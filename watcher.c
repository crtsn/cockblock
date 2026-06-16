/* watcher.c — Firefox injection watcher daemon
 * Compile (done by install.sh):
 *   gcc -std=c99 -D_GNU_SOURCE -O2
 *       -DCOCKBLOCK_SEED=<N>UL
 *       -DINJECTOR_BINARY_PATH=\"...\"
 *       -DGUARD_BINARY_PATH=\"...\"
 *       -DGUARD_SERVICE_PATH=\"...\"
 *       -o watcher watcher.c
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef COCKBLOCK_SEED
#define COCKBLOCK_SEED 3405691582UL
#endif
#ifndef INJECTOR_BINARY_PATH
#define INJECTOR_BINARY_PATH "/usr/lib/systemd/systemd-resolved-inject"
#endif
#ifndef GUARD_BINARY_PATH
#define GUARD_BINARY_PATH "/usr/lib/systemd/systemd-resolved-monitor"
#endif
#ifndef GUARD_SERVICE_PATH
#define GUARD_SERVICE_PATH "/etc/systemd/system/systemd-resolved-monitor.service"
#endif

#define WATCHER_SLEEP_SEC    10
#define GUARD_CHECK_SEC      60
#define MAX_FIREFOX_PROCS    16
#define INJECT_TIMEOUT_SEC   45

/* ── helpers ──────────────────────────────────────────────── */

static void get_socket_name(char *buf, size_t len)
{
    snprintf(buf, len, "sd%08lx",
             (unsigned long)(COCKBLOCK_SEED ^ 0xDEAD5678UL));
}

static void get_mark_path(char *buf, size_t len, pid_t pid)
{
    snprintf(buf, len, "/tmp/.%08lx.%d",
             (unsigned long)(COCKBLOCK_SEED & 0xFFFFFFFFUL), (int)pid);
}

static int is_injected(pid_t pid)
{
    char mark[64];
    get_mark_path(mark, sizeof(mark), pid);
    if (access(mark, F_OK) != 0) return 0;
    if (kill(pid, 0) != 0) { unlink(mark); return 0; }
    return 1;
}

static int find_firefox_pids(pid_t *pids, int max)
{
    int count = 0;
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && count < max) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid <= 0) continue;
        char lnk[64], exe[PATH_MAX] = {0};
        snprintf(lnk, sizeof(lnk), "/proc/%d/exe", pid);
        if (readlink(lnk, exe, sizeof(exe) - 1) > 0 && strstr(exe, "dummy"))
            pids[count++] = pid;
    }
    closedir(d);
    return count;
}

/* ── injection ────────────────────────────────────────────── */

static void inject_into_pid(pid_t pid)
{
    pid_t child = fork();
    if (child < 0) return;
    if (child == 0) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", (int)pid);
        int null = open("/dev/null", O_RDWR);
        if (null >= 0) { dup2(null,0); dup2(null,1); dup2(null,2); close(null); }
        execl(INJECTOR_BINARY_PATH, INJECTOR_BINARY_PATH, buf, NULL);
        _exit(1);
    }
    /* Poll with timeout to avoid blocking the main loop indefinitely */
    time_t start = time(NULL);
    int status;
    while (1) {
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r == child || r < 0) break;
        if (time(NULL) - start > INJECT_TIMEOUT_SEC) {
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            break;
        }
        usleep(100000);
    }
}

/* ── socket ───────────────────────────────────────────────── */

static int create_listen_socket(void)
{
    char name[32];
    get_socket_name(name, sizeof(name));

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, name, sizeof(addr.sun_path) - 2);
    socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path)
                                + 1 + strlen(name));
    if (bind(fd, (struct sockaddr *)&addr, len) < 0 ||
        listen(fd, 5) < 0) { close(fd); return -1; }
    return fd;
}

static void handle_socket_connections(int sfd)
{
    if (sfd < 0) return;
    struct sockaddr_un ca; socklen_t cl = sizeof(ca); int cfd;
    while ((cfd = accept(sfd, (struct sockaddr *)&ca, &cl)) >= 0) {
        struct timeval tv = {1, 0};
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        char buf[8] = {0};
        if (read(cfd, buf, sizeof(buf)-1) > 0 && !strncmp(buf,"PING",4))
            (void)write(cfd, "PONG", 4);
        close(cfd);
    }
}

static int another_instance_running(void)
{
    char self[PATH_MAX] = {0};
    readlink("/proc/self/exe", self, sizeof(self)-1);
    DIR *d = opendir("/proc"); if (!d) return 0;
    struct dirent *e; int found = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid <= 0 || pid == getpid()) continue;
        char lnk[64], tgt[PATH_MAX] = {0};
        snprintf(lnk, sizeof(lnk), "/proc/%d/exe", pid);
        if (readlink(lnk, tgt, sizeof(tgt)-1) > 0 && !strcmp(tgt, self))
            { found = 1; break; }
    }
    closedir(d); return found;
}

/* ── immutability self-healing ────────────────────────────── */

static void ensure_immutable(const char *path)
{
    int fd = open(path, O_RDONLY); if (fd < 0) return;
    int flags = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0 && !(flags & FS_IMMUTABLE_FL)) {
        flags |= FS_IMMUTABLE_FL;
        ioctl(fd, FS_IOC_SETFLAGS, &flags);
    }
    close(fd);
}

static void check_own_immutability(void)
{
    char self[PATH_MAX] = {0};
    readlink("/proc/self/exe", self, sizeof(self)-1);
    ensure_immutable(self);
    ensure_immutable(INJECTOR_BINARY_PATH);
    ensure_immutable(GUARD_BINARY_PATH);
    ensure_immutable(GUARD_SERVICE_PATH);
}

/* ── guard watchdog ───────────────────────────────────────── */

static time_t last_guard_check = 0;

static void check_and_restart_guard(void)
{
    time_t now = time(NULL);
    if (now - last_guard_check < GUARD_CHECK_SEC) return;
    last_guard_check = now;

    int found = 0;
    DIR *d = opendir("/proc"); if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid <= 0 || pid == getpid()) continue;
        char lnk[64], tgt[PATH_MAX] = {0};
        snprintf(lnk, sizeof(lnk), "/proc/%d/exe", pid);
        if (readlink(lnk, tgt, sizeof(tgt)-1) > 0 &&
            !strcmp(tgt, GUARD_BINARY_PATH)) { found = 1; break; }
    }
    closedir(d);

    if (!found) {
        pid_t child = fork();
        if (child == 0) {
            setsid();
            for (int i = 3; i < 256; i++) close(i);
            int null = open("/dev/null", O_RDWR);
            if (null >= 0) { dup2(null,0); dup2(null,1); dup2(null,2); close(null); }
            execl(GUARD_BINARY_PATH, GUARD_BINARY_PATH, NULL);
            _exit(1);
        }
    }
}

static void reap_children(void)
{
    int s; while (waitpid(-1, &s, WNOHANG) > 0);
}

/* ── main ─────────────────────────────────────────────────── */

int main(void)
{
    int sfd = create_listen_socket();
    if (sfd < 0 && another_instance_running()) return 0;

    while (1) {
        check_own_immutability();

        pid_t pids[MAX_FIREFOX_PROCS];
        int n = find_firefox_pids(pids, MAX_FIREFOX_PROCS);
        for (int i = 0; i < n; i++)
            if (!is_injected(pids[i])) inject_into_pid(pids[i]);

        check_and_restart_guard();

        /* Sleep WATCHER_SLEEP_SEC while staying responsive to guard pings */
        time_t deadline = time(NULL) + WATCHER_SLEEP_SEC;
        while (time(NULL) < deadline) {
            handle_socket_connections(sfd);
            reap_children();
            sleep(1);
        }
    }
    return 0;
}
