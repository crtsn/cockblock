/* guard.c — watcher guardian daemon
 * Compile (done by install.sh):
 *   gcc -std=c99 -D_GNU_SOURCE -O2
 *       -DCOCKBLOCK_SEED=<N>UL
 *       -DWATCHER_BINARY_PATH=\"...\"
 *       -o guard guard.c
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef COCKBLOCK_SEED
#define COCKBLOCK_SEED 3405691582UL
#endif
#ifndef WATCHER_BINARY_PATH
#define WATCHER_BINARY_PATH "/usr/lib/systemd/systemd-resolved-update"
#endif

#define PING_TIMEOUT_SEC    5
#define CHECK_INTERVAL_MIN  15
#define CHECK_INTERVAL_MAX  30
#define MAX_FAILURES        3

static void get_socket_name(char *buf, size_t len)
{
    snprintf(buf, len, "sd%08lx",
             (unsigned long)(COCKBLOCK_SEED ^ 0xDEAD5678UL));
}

static int try_ping_watcher(void)
{
    char name[32]; get_socket_name(name, sizeof(name));
    int fd = socket(AF_UNIX, SOCK_STREAM, 0); if (fd < 0) return 0;
    struct timeval tv = {PING_TIMEOUT_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, name, sizeof(addr.sun_path) - 2);
    socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path)
                                + 1 + strlen(name));
    if (connect(fd, (struct sockaddr *)&addr, len) < 0) { close(fd); return 0; }
    if (write(fd, "PING", 4) != 4) { close(fd); return 0; }
    char buf[8] = {0};
    ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    return (n == 4 && !strncmp(buf, "PONG", 4));
}

static void kill_existing_watcher(void)
{
    DIR *d = opendir("/proc"); if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid <= 0 || pid == getpid()) continue;
        char lnk[64], tgt[PATH_MAX] = {0};
        snprintf(lnk, sizeof(lnk), "/proc/%d/exe", pid);
        if (readlink(lnk, tgt, sizeof(tgt)-1) > 0 &&
            !strcmp(tgt, WATCHER_BINARY_PATH))
            { kill(pid, SIGTERM); break; }
    }
    closedir(d);
}

static void restart_watcher(void)
{
    kill_existing_watcher();
    sleep(2);
    pid_t child = fork(); if (child != 0) return;
    setsid();
    for (int i = 3; i < 256; i++) close(i);
    int null = open("/dev/null", O_RDWR);
    if (null >= 0) { dup2(null,0); dup2(null,1); dup2(null,2); close(null); }
    execl(WATCHER_BINARY_PATH, WATCHER_BINARY_PATH, NULL);
    _exit(1);
}

int main(void)
{
    srand((unsigned int)(time(NULL) ^ (unsigned long)getpid()));
    int failures = 0;
    sleep(20); /* let watcher start first */

    while (1) {
        if (!try_ping_watcher()) {
            if (++failures >= MAX_FAILURES) {
                restart_watcher();
                failures = 0;
                sleep(15);
            }
        } else {
            failures = 0;
        }
        sleep(CHECK_INTERVAL_MIN +
              (rand() % (CHECK_INTERVAL_MAX - CHECK_INTERVAL_MIN + 1)));
    }
    return 0;
}
