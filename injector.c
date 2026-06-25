#if 0
set -e

TMP_BIN="./injector"
cleanup() {
	rm -f "$TMP_BIN" policies_json.o userchrome_css.o
}
trap cleanup EXIT INT TERM

if [ -f /etc/machine-id ]; then
    SEED=$(cat /etc/machine-id | cksum | cut -d' ' -f1)
else
    SEED=3405691582
fi

objcopy -I binary -O elf64-x86-64 -B i386:x86-64 policies.json   policies_json.o
objcopy -I binary -O elf64-x86-64 -B i386:x86-64 userChrome.css  userchrome_css.o
gcc -std=c99 -D_GNU_SOURCE -g -O0 -z noexecstack -fno-stack-protector \
    -DCOCKBLOCK_SEED=$SEED \
    -fPIC -shared -Wl,-e,_start -o "$TMP_BIN" "$0" cJSON.c \
    policies_json.o userchrome_css.o
"$TMP_BIN" "$@"
exit 0
#endif

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/limits.h>
#include <malloc.h>
#include <sched.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>
#include <signal.h>
#include "cJSON.h"

extern const unsigned char _binary_policies_json_start[];
extern const unsigned char _binary_policies_json_end[];
extern const unsigned char _binary_userChrome_css_start[];
extern const unsigned char _binary_userChrome_css_end[];

#ifndef COCKBLOCK_SEED
#define COCKBLOCK_SEED 3405691582UL
#endif

#define KILL_SWITCH_PATH "/tmp/.xsession-kill"

typedef struct payload_params {
    long dlopen_addr;
    long dlsym_addr;
    long dlclose_addr;
    long dlerror_addr;
    char entry_fn_name[64];
    char memfd_name[128];
    long lib_buf_addr;
    long lib_buf_sz;
    char target_path[64];
    char policies_local_path[PATH_MAX];
    char chrome_local_path[PATH_MAX];
    char addon_startup_path[PATH_MAX];
} payload_params;

#define EIP(R) (R)->rip
#define EAX(R) (R)->rax
#define USER_EAX offsetof(struct user, regs.rax)
#define ADDR2INT(R) (unsigned long long)(R)

#define MAX_CODE_SIZE		128
#define STACK_SIZE		0x40000
#define CLONE_FLAGS		CLONE_THREAD | CLONE_SIGHAND | CLONE_UNTRACED | CLONE_VM
#define MMAP_PROTS		PROT_READ | PROT_WRITE | PROT_EXEC
#define MMAP_FLAGS		MAP_PRIVATE | MAP_ANONYMOUS

static void mmap_start(void);
static void mmap_end(void);

static void clone_start(void);
static void clone_end(void);

static void payload_start(void);
static void payload_end(void);

int inject_code(int pid, unsigned char *payload, size_t payload_len);

int ptrace_attach(int pid);
int ptrace_detach(int pid);
int ptrace_getregs(int pid, struct user_regs_struct *regs);
int ptrace_setregs(int pid, struct user_regs_struct *regs);
int ptrace_continue(int pid, void *stop_addr);
int ptrace_readmem(int pid, void *addr, unsigned char *buf, size_t len);
int ptrace_writemem(int pid, void *addr, unsigned char *buf, size_t len);

int wait_stopped(int pid);

#define CHECK(A,M,...) \
  do { \
    if (!(A)) { \
      fprintf(stderr, \
          "(%s:%d: error: %d [%s]) " M "\n", \
          __FILE__, \
          __LINE__, \
          errno, \
          errno == 0 ? "None" : strerror(errno), \
          ##__VA_ARGS__); \
      errno = 0; \
      goto error; \
    } \
  } while(0)

#define DEBUG_PRINTING
#ifdef DEBUG_PRINTING
#define dprintf(M,...) printf("[*] [%s] " M "\n", __FUNCTION__, ##__VA_ARGS__)
#else
#define dprintf(...)
#endif

/* ---------- New helper: find session process ---------- */
static pid_t find_session_pid(void) {
    const char *targets[] = {
        "gnome-session",
        "gnome-session-b",
        "xfce4-session",
        "lxqt-session",
        "mate-session",
        "cinnamon-sessio",
        NULL
    };
    DIR *proc = opendir("/proc");
    if (!proc) return -1;
    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (de->d_type != DT_DIR) continue;
        pid_t pid = atoi(de->d_name);
        if (pid <= 0) continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char comm[256] = {0};
        if (fgets(comm, sizeof(comm), f)) {
            comm[strcspn(comm, "\n")] = 0;
            for (int i = 0; targets[i]; i++) {
                if (strcmp(comm, targets[i]) == 0) {
                    fclose(f);
                    closedir(proc);
                    return pid;
                }
            }
        }
        fclose(f);
    }
    closedir(proc);
    return -1;
}

/* ---------- New helper: get environment variable from a user process ---------- */
static char* get_env_from_uid(uid_t uid, const char *varname) {
    DIR *proc = opendir("/proc");
    if (!proc) return NULL;
    struct dirent *de;
    while ((de = readdir(proc)) != NULL) {
        if (de->d_type != DT_DIR) continue;
        pid_t pid = atoi(de->d_name);
        if (pid <= 0) continue;

        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
        FILE *sf = fopen(status_path, "r");
        if (!sf) continue;

        uid_t proc_uid = -1;
        char line[256];
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                sscanf(line + 4, "%u", &proc_uid);
                break;
            }
        }
        fclose(sf);
        if (proc_uid != uid) continue;

        char env_path[64];
        snprintf(env_path, sizeof(env_path), "/proc/%d/environ", pid);
        int fd = open(env_path, O_RDONLY);
        if (fd < 0) continue;

        char *env_buf = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (env_buf == MAP_FAILED) continue;

        size_t varlen = strlen(varname);
        char *p = env_buf;
        while (p < env_buf + 4096 && *p) {
            if (strncmp(p, varname, varlen) == 0 && p[varlen] == '=') {
                char *val = strdup(p + varlen + 1);
                munmap(env_buf, 4096);
                closedir(proc);
                return val;
            }
            p += strlen(p) + 1;
        }
        munmap(env_buf, 4096);
    }
    closedir(proc);
    return NULL;
}

/* ---------- New helper: abstract socket name from seed ---------- */
static void make_socket_addr(struct sockaddr_un *addr, unsigned long seed) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1,
             "cb_%08lx", seed & 0xFFFFFFFFUL);
}

/* Append suffix to the original argv[0] string so that
   ps aux shows "original (suffix)". */
static void append_to_proc_title(const char *suffix) {
    extern char *program_invocation_name;
    if (!program_invocation_name || !suffix)
        return;
    size_t len = strlen(program_invocation_name);
    size_t slen = strlen(suffix);
    char *p = program_invocation_name + len;
    *p++ = ' ';
    memcpy(p, suffix, slen);
    p[slen] = '\0';
}

/* ---------- New daemons: heartbeat system ---------- */
static void manager_loop(unsigned long seed) {
    int lsock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lsock < 0) return;

    struct sockaddr_un addr;
    make_socket_addr(&addr, seed);
    if (bind(lsock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(lsock);
        return;
    }
    if (listen(lsock, 2) < 0) { close(lsock); return; }

    // Make listening socket non-blocking for kill‑switch aware accept
    int flags = fcntl(lsock, F_GETFL, 0);
    if (flags >= 0)
        fcntl(lsock, F_SETFL, flags | O_NONBLOCK);

    unlink(KILL_SWITCH_PATH);   // clear any leftover kill‑switch so we don't die immediately
    append_to_proc_title("(manager)");

    time_t last_hb = 0;

    while (1) {
        if (access(KILL_SWITCH_PATH, F_OK) == 0) {
            close(lsock);
            _exit(0);
        }
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lsock, &rfds);
        struct timeval tv = {1, 0};          // 1 second timeout

        int ret = select(lsock + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0)
            continue;                        // error, loop back (will check kill‑switch again)
        if (ret == 0)
            continue;                        // timeout -> loop back and check kill‑switch again

        // ret > 0: socket is readable
        int csock = accept(lsock, NULL, NULL);
        if (csock < 0) {
            // Non-blocking mode: EAGAIN/EWOULDBLOCK are not errors (but shouldn't happen after select)
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            // real error
            continue;
        }

        unsigned char cmd;
        if (read(csock, &cmd, 1) != 1) { close(csock); continue; }

        if (cmd == 0x01) {
            last_hb = time(NULL);
            unsigned char ack = 0x01;
            write(csock, &ack, 1);
        } else if (cmd == 0x02) {
            unsigned char resp = (time(NULL) - last_hb < 30) ? 0x01 : 0x00;
            write(csock, &resp, 1);
        }
        close(csock);
    }
}

static void main_loop(unsigned long seed) {
    struct sockaddr_un addr;
    make_socket_addr(&addr, seed);

    unlink(KILL_SWITCH_PATH);   // clear leftover kill‑switch
    append_to_proc_title("(main)");

    while (1) {
        if (access(KILL_SWITCH_PATH, F_OK) == 0) {
            _exit(0);
        }
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) { sleep(5); continue; }

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            pid_t p = fork();
            if (p == 0) {
                setsid();
                close(0); close(1); close(2);
                manager_loop(seed);
                _exit(0);
            } else if (p < 0) {
                close(sock);
                sleep(5);
                continue;
            }
            close(sock);
            sleep(2);
            continue;
        }

        unsigned char hb = 0x01;
        if (write(sock, &hb, 1) != 1) { close(sock); sleep(5); continue; }

        unsigned char ack;
        if (read(sock, &ack, 1) == 1 && ack == 0x01) {
            /* heartbeat ok */
        }
        close(sock);
        sleep(10);
    }
}

/* ---------- New: guard loop with kill‑switch and self‑repair ---------- */
static void guard_loop(unsigned long seed, const char *kill_path) {
    struct sockaddr_un addr;
    make_socket_addr(&addr, seed);

    unlink(kill_path);   // clear any leftover kill‑switch from a previous run
    append_to_proc_title("(guard)");

    while (1) {
        /* Check kill‑switch file */
        if (access(kill_path, F_OK) == 0) {
            _exit(0);
        }

        /* Now the heartbeat check */
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) { sleep(5); continue; }

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            sleep(5);
            continue;
        }

        unsigned char query = 0x02;
        write(sock, &query, 1);

        unsigned char resp;
        int n = read(sock, &resp, 1);
        close(sock);

        if (n == 1 && resp == 0x00) {
            pid_t p = fork();
            if (p == 0) {
                setsid();
                close(0); close(1); close(2);
                main_loop(seed);
                _exit(0);
            }
            sleep(rand() % 5 + 1);
        }
        sleep(10);
    }
}

static void
_print_usage(void)
{
  printf("Usage: injector <target PID>\n");
}

/* ---------- Modified main: auto‑select PID if none given ---------- */
int
main(int argc, char **argv, char **envp)
{
  pid_t pid;

  if (argc == 1) {
    printf("Waiting for a desktop session process...\n");
    while ((pid = find_session_pid()) <= 0) {
      sleep(2);
    }
    printf("Injecting into PID %d\n", pid);
  } else if (argc == 2) {
    pid = atoi(argv[1]);
  } else {
    _print_usage();
    return 1;
  }

  size_t payload_len = (size_t)payload_end - (size_t)payload_start;
  size_t payload_size_aligned = payload_len + (sizeof(void*) - (payload_len % sizeof(void*)));
  unsigned char *payload = malloc(payload_size_aligned);
  CHECK(payload, "malloc error");
  memset(payload, 0x90, payload_size_aligned);
  memcpy(payload, (void*)payload_start, payload_len);

  CHECK(inject_code(pid, payload, payload_len), "Failed to inject code into target process %d", pid);

  printf("Code injection successful\n\n");

  return 0;
error:
  return 1;
}

const char __invoke_dynamic_linker[] __attribute__((section(".interp")))
    = "/lib64/ld-linux-x86-64.so.2";

/* Standard libc initialization function */
extern int __libc_start_main(
    int (*main) (int, char **, char **),
    int argc,
    char **ubp_av,
    void (*init) (void),
    void (*fini) (void),
    void (*rtld_fini) (void),
    void (*stack_end)
);

/* The manual entry point */
__attribute__((naked))
void
_start(void) {
  __asm__ (
    "mov (%%rsp), %%rsi;"      // 2nd arg: argc (loaded from top of stack)
    "lea 8(%%rsp), %%rdx;"     // 3rd arg: ubp_av (argv, starts 8 bytes after argc)

    "mov %%rsp, %%rax;"        // Save original stack pointer to RAX
    "and $-16, %%rsp;"         /* Align stack to 16 bytes for ABI compliance */

    "sub $8, %%rsp;"           /* 8-byte alignment padding */
    "push %%rax;"              // 7th arg: stack_end (passed via stack)

    "mov main@GOTPCREL(%%rip), %%rdi;" // 1st arg: main function pointer (via GOT)
    "xor %%rcx, %%rcx;"        // 4th arg: init (NULL)
    "xor %%r8, %%r8;"          // 5th arg: fini (NULL)
    "xor %%r9, %%r9;"          // 6th arg: rtld_fini (NULL)

    "call __libc_start_main@PLT;"
    "hlt;"                     /* Safety halt if __libc_start_main returns */
    ::: "memory"
  );
}

struct pstate {
  struct user_regs_struct regs;
  size_t mem_len;
  unsigned char mem[1];
};

static struct pstate *target_state = NULL;

static int
_save_state(int pid)
{
  if (!target_state) {
    CHECK((target_state = calloc(1, sizeof(struct pstate) + MAX_CODE_SIZE - 1)),
        "Memory allocation error");
    target_state->mem_len = MAX_CODE_SIZE;
  }
  CHECK(ptrace_getregs(pid, &target_state->regs),
      "Failed to get registers of target process");

  // --- SYSCALL RESTART LOGIC ---
  long rax = (long)target_state->regs.rax;
  long orig_rax = (long)target_state->regs.orig_rax;
  // Check if thread was interrupted mid-syscall (ERESTARTSYS, ERESTARTNOHAND, etc.)
  if (orig_rax >= 0 && (rax == -512 || rax == -514 || rax == -513 || rax == -516)) {
      dprintf("Target interrupted in syscall %ld. Manually rewinding RIP.", orig_rax);

      target_state->regs.rax = orig_rax; // Restore the syscall number to execute it again
      target_state->regs.orig_rax = -1; // Prevent the kernel from executing its own restart logic

      // Immediately apply these changes to the target thread so subsequent backups
      // and injections happen at the correctly rewound RIP.
      CHECK(ptrace_setregs(pid, &target_state->regs), "Failed to apply rewound registers");
  }

  dprintf("Saved registers");
  CHECK(ptrace_readmem(pid, (void*)EIP(&target_state->regs), target_state->mem, target_state->mem_len),
      "Failed to read %ld bytes of memory at target process instruction pointer",
      target_state->mem_len);
  dprintf("Saved %ld bytes from EIP %p", target_state->mem_len, target_state->mem);
  return 1;
error:
  return 0;
}

  static int
_restore_state(int pid)
{
  if (!target_state) return 1;
  CHECK(ptrace_setregs(pid, &target_state->regs),
      "Failed to set registers of target process");
  dprintf("Restored registers");
  CHECK(ptrace_writemem(pid, (void*)EIP(&target_state->regs), target_state->mem, target_state->mem_len),
      "Failed to write %ld bytes of memory to target process instruction pointer",
      target_state->mem_len);
  dprintf("Restored %ld bytes to EIP %p", target_state->mem_len, target_state->mem);
  free(target_state);
  target_state = NULL;
  return 1;
error:
  return 0;
}

static int
_wait_trap(int pid)
{
  int status = 0;
  while(1) {
    CHECK(waitpid(pid, &status, __WALL) != -1,
        "waitpid error");

    if (WIFSTOPPED(status)) {
      dprintf("Process stopped with signal %d", WSTOPSIG(status));
    }
    if (WIFEXITED(status)) {
      dprintf("Process exited with signal %d", WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
      dprintf("Process terminated with signal %d", WTERMSIG(status));
      if (WCOREDUMP(status))
        dprintf("Process core dumped");
    }
    if (WIFCONTINUED(status)) {
      dprintf("Process was resumed by delivery of SIGCONT");
    }

    CHECK(!WIFEXITED(status), "Target process has exited");
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
      return 1;
  }
error:
  return 0;
}

static int
_mmap_data(int pid, size_t len, void *base_address, int protections, int flags, void **out)
{
  int ret = 0;
  unsigned char *shellcode = NULL;

  size_t shellcode_len = (size_t)mmap_end - (size_t)mmap_start;
  // align shellcode size to 64-bit boundary
  size_t shellcode_len_aligned = shellcode_len + (sizeof(void*) - (shellcode_len % sizeof(void*)));
  shellcode = malloc(shellcode_len_aligned);
  CHECK(shellcode, "malloc error");
  memset(shellcode, 0x90, shellcode_len_aligned);
  memcpy(shellcode, (void*)mmap_start, shellcode_len);

  // get current registers
  struct user_regs_struct orig_regs, regs = {0};
  CHECK(ptrace_getregs(pid, &regs),
      "Failed to get registers of target process");
  orig_regs = regs;

  // BACK UP THE ORIGINAL BYTES
  unsigned char *backup_bytes = malloc(shellcode_len_aligned);
  CHECK(backup_bytes, "malloc backup error");
  CHECK(ptrace_readmem(pid, (void*)EIP(&regs), backup_bytes, shellcode_len_aligned), 
        "Failed to backup original memory at RIP");

  // put our arguments in the proper registers (see mmap64.asm)
  regs.rdi = (unsigned long long)base_address;
  regs.rsi = (unsigned long long)len;
  regs.rdx = (unsigned long long)((protections) ? protections : MMAP_PROTS);
  regs.r10 = (unsigned long long)((flags) ? flags : MMAP_FLAGS);
  CHECK(ptrace_setregs(pid, &regs),
      "Failed to set registers of target process");
  dprintf("Wrote our shellcode parameters into process registers");

  // write mmap code to target process EIP
  CHECK(ptrace_writemem(pid, (void*)EIP(&regs), shellcode, shellcode_len_aligned),
      "Failed to write mmap code to target process");
  dprintf("Wrote mmap code to EIP %p", (void*)EIP(&regs));

  // run mmap code and check return value
  CHECK(ptrace_continue(pid, 0), "Failed to execute mmap code");
  CHECK(_wait_trap(pid), "Error waiting for interrupt");
  dprintf("Mmap() finished execution");

  // get return value from mmap()
  CHECK(ptrace_getregs(pid, &regs),
      "Failed to get registers of target process");
  *out = (void*)EAX(&regs);
  dprintf("Mmap() returned %p", *out);
  CHECK(*out != MAP_FAILED, "Mmap() returned error");

  // --- IMMEDIATELY RESTORE THE ORIGINAL BYTES ---
  CHECK(ptrace_writemem(pid, (void*)EIP(&orig_regs), backup_bytes, shellcode_len_aligned), 
        "Failed to restore original memory at RIP");

  // restore registers
  CHECK(ptrace_setregs(pid, &orig_regs),
      "Failed to restore registers of target process");
  dprintf("Restored registers of target process");
  dprintf("Mmap() returned %p and memory cleanly restored!", *out);

  ret = 1;
error:
  if (shellcode)
    free(shellcode);
  if (backup_bytes)
    free(backup_bytes);
  return ret;
}

__attribute__((naked, aligned(8)))
static void
memfd_write_start() {
    __asm__ (
        ".intel_syntax noprefix;"
        "mov rax, 319;"
        "syscall;"
        "test rax, rax;"
        "js error;"
        "mov r8, rax;"
        "mov rdi, r8;"
        "mov rsi, rdx;"
        "mov rdx, r10;"
    "write_loop:"
        "mov rax, 1;"
        "syscall;"
        "test rax, rax;"
        "js error;"
        "add rsi, rax;"
        "sub rdx, rax;"
        "jnz write_loop;"
        "mov rax, r8;"
        "int3;"
    "error:"
        "mov rax, -1;"
        "int3;"
        ".att_syntax;"
    );
}

void
memfd_write_end()
{
}

static int
_create_memfd(int pid,
              const char *name, size_t name_len,
              const unsigned char *data, size_t data_len,
              int *fd_out)
{
    int ret = 0;
    void *name_addr = NULL, *data_addr = NULL, *code_cave = NULL;
    unsigned char *shellcode = NULL;

    size_t shellcode_len = (size_t)memfd_write_end - (size_t)memfd_write_start;
    size_t code_sz = shellcode_len + (sizeof(void*) - (shellcode_len % sizeof(void*)));

    // 1. Allocate shellcode buffer in the target (code cave)
    CHECK(_mmap_data(pid, code_sz, NULL, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, &code_cave),
          "mmap code cave failed");
    shellcode = malloc(code_sz);
    CHECK(shellcode, "malloc shellcode");
    memset(shellcode, 0x90, code_sz);
    memcpy(shellcode, (void*)memfd_write_start, shellcode_len);
    CHECK(ptrace_writemem(pid, code_cave, shellcode, code_sz),
          "write shellcode failed");

    // 2. Allocate memory for the name string and copy it
    size_t name_aligned = name_len + (sizeof(void*) - (name_len % sizeof(void*)));
    CHECK(_mmap_data(pid, name_aligned, NULL, 0, 0, &name_addr),
          "mmap name buffer failed");
    CHECK(ptrace_writemem(pid, name_addr, (void*)name, name_aligned),
          "write name failed");

    // 3. Allocate memory for the file data and copy it
    size_t data_aligned = data_len + (sizeof(void*) - (data_len % sizeof(void*)));
    CHECK(_mmap_data(pid, data_aligned, NULL, 0, 0, &data_addr),
          "mmap data buffer failed");
    CHECK(ptrace_writemem(pid, data_addr, (void*)data, data_aligned),
          "write data failed");

    // 4. Set up registers and execute shellcode
    struct user_regs_struct regs;
    CHECK(ptrace_getregs(pid, &regs), "getregs");
    regs.rdi = (unsigned long long)name_addr;
    regs.rsi = (unsigned long long)1;   // MFD_CLOEXEC
    regs.rdx = (unsigned long long)data_addr;
    regs.r10 = (unsigned long long)data_len;
    EIP(&regs) = (unsigned long long)code_cave;
    CHECK(ptrace_setregs(pid, &regs), "setregs");

    CHECK(ptrace_continue(pid, 0), "continue");
    CHECK(_wait_trap(pid), "wait trap");

    CHECK(ptrace_getregs(pid, &regs), "getregs after");
    long res = (long)regs.rax;
    CHECK(res >= 0, "memfd_create/write failed (rax = %ld)", res);
    *fd_out = (int)res;

    ret = 1;
error:
    // free local copies; target memory remains (will be freed by munmap in child)
    free(shellcode);
    return ret;
}

static int
_launch_payload(int pid, void *code_cave, size_t code_cave_size, void *stack_address, size_t stack_size, void *payload_address, size_t payload_len, void *payload_param, int flags)
{
  int ret = 0;
  unsigned char *shellcode = NULL;
  size_t shellcode_len = (size_t)clone_end - (size_t)clone_start;
  CHECK(shellcode_len > 0, "ftell error");
  CHECK(shellcode_len <= code_cave_size, "Shellcode is too big (%ld) for allocated code cave", shellcode_len);
  shellcode = malloc(code_cave_size);
  CHECK(shellcode, "malloc error");
  memset(shellcode, 0x90, code_cave_size); // fill with NOPs
  memcpy(shellcode, (void*)clone_start, shellcode_len);

  // get current registers
  struct user_regs_struct regs = {0};
  CHECK(ptrace_getregs(pid, &regs),
      "Failed to get registers of target process");

  // put our arguments in the proper registers (see clone64.asm)
  regs.rax = (unsigned long long)code_cave_size;
  regs.rdi = (unsigned long long)((flags) ? flags : CLONE_FLAGS);
  regs.rsi = (unsigned long long)stack_address;
  regs.rdx = (unsigned long long)stack_size;
  regs.rcx = (unsigned long long)payload_address;
  regs.r8  = (unsigned long long)payload_len;
  regs.r9  = (unsigned long long)payload_param;
  // move EIP to our code cave
  EIP(&regs) = ADDR2INT(code_cave);
  CHECK(ptrace_setregs(pid, &regs),
      "Failed to set registers of target process");
  dprintf("Wrote our shellcode parameters into process registers. EIP: %p", code_cave);

  // write shellcode to target process code cave
  CHECK(ptrace_writemem(pid, code_cave, shellcode, code_cave_size),
      "Failed to write clone trampoline code to target process");
  dprintf("Wrote clone trampoline code to address %p", code_cave);

  // run shellcode and check return value
  CHECK(ptrace_continue(pid, code_cave), "Failed to execute clone trampoline code");
  CHECK(_wait_trap(pid), "Error waiting for interrupt");
  dprintf("Clone() finished execution");
  CHECK(ptrace_getregs(pid, &regs),
      "Failed to get registers of target process");
  dprintf("New thread ID: %lld", EAX(&regs));
  CHECK((int)EAX(&regs) != -1, "Clone() returned error");

  // no need to restore registers, as we're about to call _restore_state()

  dprintf("Successfully launched payload");

  ret = 1;
error:
  if (ret == 0)
    dprintf("Failed to launch payload");
  if (shellcode)
    free(shellcode);
  return ret;
}

long getlibcaddr(pid_t pid) {
    FILE *fp;
    char filename[64];
    char line[1024];
    long addr = 0;

    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if (fp == NULL) return 0;

    while (fgets(line, sizeof(line), fp)) {
        // Look for the standard libc path.
        // This checks for the file path at the end of the line.
        if (strstr(line, "/libc.so") || strstr(line, "/libc-")) {
            // We found the first occurrence (the base address)
            sscanf(line, "%lx-", &addr);
            break;
        }
    }
    fclose(fp);
    return addr;
}

long getFunctionAddress(char* funcName)
{
	void* self = dlopen("libc.so.6", RTLD_LAZY);
	void* funcAddr = dlsym(self, funcName);
	return (long)funcAddr;
}


static int get_thread_list(pid_t pid, pid_t **tids_out) {
    char task_path[64];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
    
    DIR *dir = opendir(task_path);
    if (!dir) return -1;

    int capacity = 10;
    int count = 0;
    pid_t *tids = malloc(capacity * sizeof(pid_t));

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue; // Skip "." and ".."
        
        pid_t tid = (pid_t)atoi(entry->d_name);
        if (tid <= 0) continue;

        if (count >= capacity) {
            capacity *= 2;
            tids = realloc(tids, capacity * sizeof(pid_t));
        }
        tids[count++] = tid;
    }
    closedir(dir);
    
    *tids_out = tids;
    return count; // Returns total number of threads found
}

static int freeze_all_threads(pid_t *tids, int count, pid_t main_pid) {
    for (int i = 0; i < count; i++) {
        pid_t tid = tids[i];
        
        // Use PTRACE_ATTACH on the individual TID
        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) < 0) {
            // It is common for short-lived threads to die before attachment; 
            // handle ESRCH gracefully if necessary
            if (errno == ESRCH) continue; 
            return 0; 
        }
        
        // Wait specifically for this thread to enter the stopped state
        if (!wait_stopped(tid)) {
            return 0;
        }
        
        // Note: For any thread that is NOT the main thread executing your 
        // trampoline code, you DO NOT alter its registers or instructions. 
        // Just leaving it in the PTRACE stopped state is sufficient to freeze it.
    }
    return 1;
}

void thaw_all_threads(pid_t *tids, int count) {
    for (int i = 0; i < count; i++) {
        pid_t tid = tids[i];
        // Detach leaves the thread in a running state
        ptrace(PTRACE_DETACH, tid, NULL, NULL);
    }
}

int
inject_code(int pid, unsigned char *payload, size_t payload_len)
{
  int ret = 0, status = 0;
  void *payload_addr = NULL,
       *stack = NULL,
       *code_cave = NULL,
       *payload_aligned = NULL;
  size_t payload_size;
  pid_t *thread_ids = NULL;
  int total_threads = 0;

  // 1. Enumerate all running threads in the target
  total_threads = get_thread_list(pid, &thread_ids);
  CHECK(total_threads > 0, "Failed to parse target threads");

  // 2. Freeze every thread using PTRACE_ATTACH
  CHECK(freeze_all_threads(thread_ids, total_threads, pid), "Failed to freeze target threads");
  dprintf("All %d threads frozen successfully.", total_threads);

  // align shellcode size to 64-bit boundary
  payload_size = payload_len + (sizeof(void*) - (payload_len % sizeof(void*)));
  payload_aligned = malloc(payload_size);
  CHECK(payload_aligned, "malloc() error");
  memset(payload_aligned, 0x90, payload_size); // fill with NOPs
  memcpy(payload_aligned, payload, payload_len);

  int mypid = getpid();
  long mylibcaddr = getlibcaddr(mypid);
  dprintf("Injecting from injector process %d", mypid);
  dprintf("mylibcaddr: %p", (void *) mylibcaddr);
	long dlopenAddr = getFunctionAddress("dlopen");
	long dlsymAddr = getFunctionAddress("dlsym");
	long dlcloseAddr = getFunctionAddress("dlclose");
	long dlerrorAddr = getFunctionAddress("dlerror");

  long dlopenOffset = dlopenAddr - mylibcaddr;
  long dlsymOffset = dlsymAddr - mylibcaddr;
  long dlcloseOffset = dlcloseAddr - mylibcaddr;
  long dlerrorOffset = dlerrorAddr - mylibcaddr;

  payload_params p = {0};
  long targetLibcAddr = getlibcaddr(pid);
  p.dlopen_addr = targetLibcAddr + dlopenOffset;
  p.dlsym_addr = targetLibcAddr + dlsymOffset;
  p.dlclose_addr = targetLibcAddr + dlcloseOffset;
  p.dlerror_addr = targetLibcAddr + dlerrorOffset;
  snprintf(p.memfd_name, sizeof(p.memfd_name), "ml%08lx",
           (unsigned long)(COCKBLOCK_SEED & 0xFFFFFFFFUL));
  snprintf(p.entry_fn_name, sizeof(p.entry_fn_name), "my_payload_entry");

  // Find Firefox profile path to compute addonStartup.json.lz4 path
  const char *home = getpwuid(geteuid())->pw_dir;
  if (home) {
      char profiles_ini[PATH_MAX];
      snprintf(profiles_ini, sizeof(profiles_ini),
               "%s/snap/firefox/common/.mozilla/firefox/profiles.ini", home);
      FILE *fp = fopen(profiles_ini, "r");
      if (fp) {
          char line[512];
          while (fgets(line, sizeof(line), fp)) {
              if (strncmp(line, "Path=", 5) == 0) {
                  char *path_start = line + 5;
                  char *newline = strchr(path_start, '\n');
                  if (newline) *newline = '\0';
                  snprintf(p.addon_startup_path, sizeof(p.addon_startup_path),
                           "%s/snap/firefox/common/.mozilla/firefox/%s/addonStartup.json.lz4",
                           home, path_start);
                  break;
              }
          }
          fclose(fp);
      }
  }
  if (!p.addon_startup_path[0]) {
      // Fallback: use a default path
      snprintf(p.addon_startup_path, sizeof(p.addon_startup_path),
               "/tmp/.cockblock_addon_startup_%08lx.json.lz4",
               (unsigned long)(COCKBLOCK_SEED & 0xFFFFFFFFUL));
  }

  char injector_path[PATH_MAX] = {0};
  readlink("/proc/self/exe", injector_path, PATH_MAX);
  dprintf("injector_path: %s", injector_path);
  FILE *f = fopen(injector_path, "rb");
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  rewind(f);
  char *buf = malloc(sz);
  fread(buf, 1, sz, f);
  fclose(f);
  dprintf("Size of binary: %zu", sz);

  printf("Injecting into target process %d", pid);

  // save state (which handles the syscall rollback if needed)
  // Must be done BEFORE any code execution in the target
  CHECK(_save_state(pid), "Failed to state target process state");

  // embed sizes
  size_t policies_size  = _binary_policies_json_end - _binary_policies_json_start;
  size_t chrome_size    = _binary_userChrome_css_end - _binary_userChrome_css_start;

  // create memfd for policies.json
  const char pol_name[] = "policies.json";
  int pol_fd = -1;
  CHECK(_create_memfd(pid, pol_name, sizeof(pol_name),
                      _binary_policies_json_start, policies_size, &pol_fd),
        "create memfd for policies.json");
  snprintf(p.policies_local_path, sizeof(p.policies_local_path),
           "/proc/self/fd/%d", pol_fd);

  // create memfd for userChrome.css
  const char chrome_name[] = "userChrome.css";
  int chrome_fd = -1;
  CHECK(_create_memfd(pid, chrome_name, sizeof(chrome_name),
                      _binary_userChrome_css_start, chrome_size, &chrome_fd),
        "create memfd for userChrome.css");
  snprintf(p.chrome_local_path, sizeof(p.chrome_local_path),
           "/proc/self/fd/%d", chrome_fd);
  dprintf("Saved state of target process");

  // Copy the injector's binary into the target's memory
  void *lib_buf = NULL;
  _mmap_data(pid, sz, NULL, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, &lib_buf);
  ptrace_writemem(pid, lib_buf, buf, sz);
  dprintf("Allocated space for lib_buf at location %p with size: %zu", lib_buf, sz);

  p.lib_buf_addr = (long) lib_buf;
  p.lib_buf_sz = sz;

  // allocate payload space
  CHECK(_mmap_data(pid, payload_size, NULL, 0, 0, &payload_addr),
        "Failed to allocate space for payload");
  dprintf("Allocated space for payload at location %p", payload_addr);

  // copy payload
  CHECK(ptrace_writemem(pid, payload_addr, payload_aligned, payload_size),
        "Failed to copy payload to target process");
  dprintf("Wrote payload to target process at address %p", payload_addr);

  // allocate payload args space
  void *remote_params_ptr = NULL;
  CHECK(_mmap_data(pid, sizeof(payload_params), NULL, 0, 0, &remote_params_ptr),
        "Failed to allocate space for payload args");
  dprintf("Allocated space for payload attrs at location %p", remote_params_ptr);

  // copy payload args
  CHECK(ptrace_writemem(pid, remote_params_ptr, (void *) &p, sizeof(payload_params)),
        "Failed to copy payload params to target process");
  dprintf("Wrote payload attrs to target process at address %p", remote_params_ptr);

  // allocate new stack
  CHECK(_mmap_data(pid, STACK_SIZE, NULL, 0, 0, &stack),
        "Failed to allocate space for new stack");
  stack += STACK_SIZE; // use top address as stack base, since stack grows downward
  dprintf("Allocated new stack at location %p", stack);

  // allocate space for code cave
  CHECK(_mmap_data(pid, MAX_CODE_SIZE, NULL, 0, 0, &code_cave),
        "Failed to allocate space for code cave");
  dprintf("Allocated space for code cave at location %p", code_cave);

  // launch payload via clone(2)
  dprintf("Launching payload in new thread");
  CHECK(_launch_payload(pid, code_cave, MAX_CODE_SIZE, stack, STACK_SIZE, payload_addr, payload_size, remote_params_ptr, 0),
        "Failed to launch payload");

  ret = 1;
error:
  if (payload_aligned)
    free(payload_aligned);
  _restore_state(pid);
  // detach from all secondary threads to resume the target application
  if (thread_ids) {
      thaw_all_threads(thread_ids, total_threads);
      free(thread_ids);
  }
  return ret;
}

int
ptrace_attach(int pid)
{
  CHECK(ptrace(PTRACE_ATTACH, (pid_t)pid, NULL, NULL) == 0,
        "Failed to attach to target process %d", pid);
  return 1;
error:
  return 0;
}

int
ptrace_detach(int pid)
{
  CHECK(ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL) == 0,
        "Failed to detach to target process %d", pid);
  return 1;
error:
  return 0;
}

int
ptrace_getregs(int pid, struct user_regs_struct *regs)
{
  CHECK(ptrace(PTRACE_GETREGS, (pid_t)pid, NULL, regs) == 0,
        "Failed to get registers of target process %d", pid);
  return 1;
error:
  return 0;
}

int
ptrace_setregs(int pid, struct user_regs_struct *regs)
{
  CHECK(ptrace(PTRACE_SETREGS, (pid_t)pid, NULL, regs) == 0,
        "Failed to set registers of target process %d", pid);
  return 1;
error:
  return 0;
}

int
wait_stopped(int pid)
{
  int status = 0;
  while(1) {
    dprintf("START WAITPID %d", pid);
    CHECK(waitpid(pid, &status, __WALL) != -1,
          "waitpid error");
    dprintf("STOP WAITPID %d", pid);

    if (WIFSTOPPED(status)) {
      dprintf("Process stopped with signal %d", WSTOPSIG(status));
    }
    if (WIFEXITED(status)) {
      dprintf("Process exited with signal %d", WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
      dprintf("Process terminated with signal %d", WTERMSIG(status));
      if (WCOREDUMP(status))
	dprintf("Process core dumped");
    }
    if (WIFCONTINUED(status)) {
      dprintf("Process was resumed by delivery of SIGCONT");
    }

    CHECK(!WIFEXITED(status), "Target process has exited");
    if (WIFSTOPPED(status))
      break;
  }
  return 1;
error:
  return 0;
}

int
ptrace_continue(int pid, void *stop_addr)
{
  dprintf("Continuing execution of target process %d", pid);
  CHECK(ptrace(PTRACE_CONT, (pid_t)pid, NULL, NULL) == 0,
        "Failed to continue execution of target process %d", pid);
  return 1;
error:
  return 1;
}

int
ptrace_readmem(int pid, void *addr, unsigned char *buf, size_t len)
{
  CHECK(len % sizeof(void*) == 0, "Length of memory to read must be word-aligned");

  size_t wordlen = len / sizeof(void*);
  void **wordbuf = (void**)buf;

  errno = 0;
  for (size_t i = 0; i < wordlen; i++) {
    wordbuf[i] = (void*)ptrace(PTRACE_PEEKDATA, (pid_t)pid, addr + (i * sizeof(void*)), NULL);
    CHECK(errno == 0,
          "Failed to read memory of target process %d at location %p",
    pid,
    addr + (i * sizeof(void*)));
  }
  return 1;
error:
  return 0;
}

int
ptrace_writemem(int pid, void *addr, unsigned char *buf, size_t len)
{
  CHECK(len % sizeof(void*) == 0, "Length of memory to read must be word-aligned");

  size_t wordlen = len / sizeof(void*);
  void **wordbuf = (void**)buf;

  for (size_t i = 0; i < wordlen; i++) {
    long result = ptrace(PTRACE_POKEDATA, (pid_t)pid, addr + (i * sizeof(void*)), wordbuf[i]);
    CHECK(result == 0,
          "Failed to write memory to target process %d at location %p",
      pid,
      addr + (i * sizeof(void*)));
  }
  return 1;
error:
  return 0;
}

__attribute__((naked, aligned(8)))
static void
mmap_start() {
    __asm__ (
        ".intel_syntax noprefix;"  // Switch to Intel syntax
        "xor rax, rax;"
        "mov al, 9;"               // SYS_MMAP
        "xor		r8,r8;"            // fd
        "xor		r9,r9;"            // offset
        "syscall;"
        "int3;"                    // interrupt for caller to trap
        ".att_syntax;"             // Switch back to AT&T (good practice)
    );
}

void
mmap_end()
{
}

__attribute__((naked, aligned(8)))
static void
clone_start() {
__asm__ (
        ".intel_syntax noprefix;"
        "start:"

        "mov rsp, rsi;" // start using new stack

        "push rax;"             // shellcode size
        "lea r11, [rip]; 1: sub r11, (1b - start); push r11;" // shellcode addr
        "push rdx;"             // stack size
        "push rsi;"             // stack addr
        "push r8;"              // payload size
        "push rcx;"             // payload addr
        "push rcx;"             // payload addr
        "push r9;"              // payload param
        "mov rsi, rsp;"         // update stack pointer for clone

        // 5. Execute SYS_CLONE (56)
        "mov rax, 56;"
        "xor rdx, rdx;"         // ptid = NULL
        "xor r10, r10;"         // ctid = NULL
        "xor r8, r8;"           // regs = NULL
        "syscall;"

        "test rax, rax;"
        "jz child_thread;"

        // Parent: Trap back to injector
        "int3;"

    "child_thread:"
        // 6. Child: Execute Payload
        "pop rdi;"              // Pop r9 (parameter)
        "pop rax;"              // Pop rcx (address)
        "call rax;"

    "cleanup:"
        "xor rax,rax;"
        "mov al, 11;"          // SYS_MUNMAP
        "xor rdx,rdx;"
        "mov dl,3;"
    "munmap:"
        "pop rdi;"              // Pop addr
        "pop rsi;"              // Pop size
        "syscall;"
        "dec dl;"
        "jnz munmap;"

    "child_exit:"
        "mov rax, 60;"          // SYS_EXIT
        "xor rdi, rdi;"
        "syscall;"

        ".att_syntax;"
    );
}

void
clone_end()
{
}


__attribute__((naked, aligned(8)))
static void
payload_start() {
  __asm__ (
    ".intel_syntax noprefix;"
    "push rbp;"
    "mov rbp, rsp;"

    "mov rbx, rdi;"              // rbx = payload_params
    "sub rsp, 256;"
    "and rsp, -16;"              // Stack alignment for GLIBC calls

    // --- 1. Create memfd ---
    "mov rax, 319;"              // sys_memfd_create
    "lea rdi, [rbx + 96];"       // Offset 96: memfd_name
    "mov rsi, 1;"                // MFD_CLOEXEC
    "syscall;"
    "mov r12, rax;"              // r12 = fd

    "test r12, r12;"
    "js exit_fail;"

    // --- 2. Write buffer to memfd ---
    "mov r13, [rbx + 224];"      // Offset 224: lib_buf_addr
    "mov r14, [rbx + 232];"      // Offset 232: lib_buf_sz
    "xor r15, r15;"              // Written offset

    "write_loop2:"
    "cmp r15, r14;"
    "jae write_done;"
    "mov rdi, r12;"
    "lea rsi, [r13 + r15];"
    "mov rdx, r14;"
    "sub rdx, r15;"
    "mov rax, 1;"                // sys_write
    "syscall;"
    "test rax, rax;"
    "js exit_fail;"
    "jz write_done;"
    "add r15, rax;"
    "jmp write_loop2;"
    "write_done:"

    // --- 3. Build thread-self path ---
    "lea rdi, [rbx + 240];"       // Offset 240: target_path
    "mov rax, 0x636f72702f;"       // "/proc" (little endian)
    "mov [rdi], rax;"
    "mov rax, 0x657268742f;"       // "/thre"
    "mov [rdi+5], rax;"
    "mov rax, 0x6c65732d6461;"     // "ad-sel"
    "mov [rdi+10], rax;"
    "mov rax, 0x64662f66;"         // "f/fd"
    "mov [rdi+16], rax;"
    "mov byte ptr [rdi+20], 0x2f;" // "/"

    "add rdi, 21;"                 // rdi now points right after "/proc/thread-self/fd/"

    // Determine how many digits the file descriptor needs
    "mov rax, r12;"                // rax = FD
    "mov rcx, 10;"                 // Base 10 divisor
    "mov rsi, rdi;"                // Use rsi as a lookahead tracker to find the string end

"find_end_loop:"
    "xor rdx, rdx;"
    "div rcx;"
    "inc rsi;"                     // Move end pointer forward by 1 byte per digit
    "test rax, rax;"
    "jnz find_end_loop;"

    // rsi now points exactly to where the null terminator goes
    "mov byte ptr [rsi], 0;"
    "mov r8, rsi;"                 // Save the end address to update rdi later

    // Generate the characters in reverse (from right to left)
    "mov rax, r12;"                // Reload the original FD

"convert_loop:"
    "xor rdx, rdx;"
    "div rcx;"
    "add dl, 0x30;"                // Convert remainder to ASCII digit
    "dec rsi;"                     // Move backward from the end pointer
    "mov [rsi], dl;"               // Write the digit string character
    "test rax, rax;"
    "jnz convert_loop;"

    "mov rdi, r8;"                 // Advance rdi to the null-terminator for subsequent use

    // --- 4. dlopen(target_path, RTLD_NOW) ---
    "lea rdi, [rbx + 240];"      // target_path
    "mov rsi, 2;"                // RTLD_NOW
    "mov rax, [rbx + 0];"        // dlopen_addr
    "call rax;"
    "mov r13, rax;"              // handle

    "test r13, r13;"
    "jz call_dlerror;"

    // --- 5. dlsym(handle, entry_fn_name) ---
    "mov rdi, r13;"
    "lea rsi, [rbx + 32];"       // Offset 32: entry_fn_name
    "mov rax, [rbx + 8];"        // dlsym_addr
    "call rax;"
    "mov r14, rax;"              // function pointer

    "test r14, r14;"
    "jz call_dlerror;"

    // --- 6. Print success (library loaded and symbol found) ---
    "mov rax, 0x0a4b4f5f444c;"   // "DL_OK\n"
    "mov [rsp], rax;"
    "mov rdi, 1; mov rsi, rsp; mov rdx, 6; mov rax, 1; syscall;"

    // --- 7. Execute ---
    "mov rdi, r13;"              // Arg 1 (rdi) = library handle
    "mov rsi, rbx;"              // Arg 2 (rsi) = payload_params pointer
    "call r14;"

    // --- 8. Leave library loaded (don't dlclose) ---
    // The library must remain in memory since we're executing from it
    "jmp payload_cleanup;"

    "call_dlerror:"
    "mov rax, [rbx + 24];"       // dlerror_addr
    "call rax;"
    "test rax, rax; jz exit_fail;"
    "mov rsi, rax; xor rdx, rdx;"
    "c_lp: cmp byte ptr [rsi+rdx], 0; je p_lp; inc rdx; jmp c_lp;"
    "p_lp: mov rdi, 2; mov rax, 1; syscall;"
    "jmp exit_fail;"


    "exit_fail:"
    "mov rax, 0x0a5252455f444c;" // "DL_ERR\n"
    "mov [rsp], rax;"
    "mov rdi, 1; mov rsi, rsp; mov rdx, 7; mov rax, 1; syscall;"

    "payload_cleanup:"
    "mov rdi, r12; mov rax, 3; syscall;" // sys_close(fd)
    "mov rsp, rbp;"
    "pop rbp;"
    "ret;"
    ".att_syntax;"
);
}

void
payload_end()
{
}

/* ---------- Modified restart_firefox_detached to accept env ---------- */
static void restart_firefox_detached(uid_t uid, const char *home_dir,
                                     const char *display, const char *dbus_address) {
    system("pkill firefox 2>/dev/null");
    sleep(2);
    pid_t c = fork();
    if (c == 0) {
        pid_t g = fork();
        if (g == 0) {
            setsid();
            int dn = open("/dev/null", O_RDWR);
            if (dn >= 0) { dup2(dn,0); dup2(dn,1); dup2(dn,2); close(dn); }
            if (setgid(uid) != 0 || setuid(uid) != 0) { /* silent */ }
            if (display && display[0])
                setenv("DISPLAY", display, 1);
            else
                setenv("DISPLAY", ":0", 1);
            if (dbus_address && dbus_address[0])
                setenv("DBUS_SESSION_BUS_ADDRESS", dbus_address, 1);
            else {
                char dbus[128];
                snprintf(dbus, sizeof(dbus), "unix:path=/run/user/%u/bus", (unsigned)uid);
                setenv("DBUS_SESSION_BUS_ADDRESS", dbus, 1);
            }
            if (home_dir && home_dir[0]) {
                char xauth[PATH_MAX];
                snprintf(xauth, sizeof(xauth), "%s/.Xauthority", home_dir);
                setenv("XAUTHORITY", xauth, 1);
                setenv("HOME", home_dir, 1);
            }
            char *av[] = { "/snap/bin/firefox", NULL };
            execv(av[0], av);
            _exit(1);
        }
        _exit(0);
    }
    if (c > 0) waitpid(c, NULL, 0);
}

static int clean_policies_directory(void) {
    const char *dirpath = "/etc/firefox/policies";
    DIR *d = opendir(dirpath);
    if (!d) {
        /* directory doesn't exist -> nothing to clean */
        return 1;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        /* skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        /* skip policies.json itself */
        if (strcmp(entry->d_name, "policies.json") == 0)
            continue;

        /* Build full path */
        char fullpath[PATH_MAX];
        int n = snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(fullpath))
            continue;

        /* Remove only regular files (ignore subdirectories to be safe) */
        struct stat st;
        if (lstat(fullpath, &st) == 0 && S_ISREG(st.st_mode)) {
            if (unlink(fullpath) < 0) {
                dprintf("Failed to remove %s: %s", fullpath, strerror(errno));
                /* continue anyway */
            } else {
                dprintf("Removed %s", fullpath);
            }
        }
    }
    closedir(d);
    return 1;
}

static int find_firefox_profile(char *profile_path_out, size_t len) {
    char profiles_ini[PATH_MAX];
    const char *home = NULL;

    /* 1. Try the real UID from /proc/self/status */
    FILE *st = fopen("/proc/self/status", "r");
    if (st) {
        char buf[256];
        while (fgets(buf, sizeof(buf), st)) {
            unsigned long uid;
            if (sscanf(buf, "Uid: %lu", &uid) == 1) {
                struct passwd *pw = getpwuid((uid_t)uid);
                if (pw && pw->pw_dir && pw->pw_dir[0])
                    home = pw->pw_dir;
                break;
            }
        }
        fclose(st);
    }

    /* 2. If we got root or nothing, try the effective UID */
    if (!home || strcmp(home, "/root") == 0) {
        struct passwd *pw_eff = getpwuid(geteuid());
        if (pw_eff && pw_eff->pw_dir && pw_eff->pw_dir[0] && pw_eff->pw_uid != 0)
            home = pw_eff->pw_dir;
    }

    /* 3. Still no good home? Scan all human users (UID >= 1000) for a
     *    Firefox snap profile. This handles the case when the payload runs
     *    inside a root process (sudo) but needs a normal user's profile. */
    if (!home || strcmp(home, "/root") == 0) {
        setpwent();
        struct passwd *entry;
        while ((entry = getpwent()) != NULL) {
            if (entry->pw_uid >= 1000 && entry->pw_dir && entry->pw_dir[0]) {
                snprintf(profiles_ini, sizeof(profiles_ini),
                         "%s/snap/firefox/common/.mozilla/firefox/profiles.ini",
                         entry->pw_dir);
                if (access(profiles_ini, F_OK) == 0) {
                    home = entry->pw_dir;
                    break;
                }
            }
        }
        endpwent();
    }

    if (!home) {
        printf("[payload] Could not determine user home directory\n");
        fflush(stdout);
        return 0;
    }

    snprintf(profiles_ini, sizeof(profiles_ini),
             "%s/snap/firefox/common/.mozilla/firefox/profiles.ini", home);

    printf("[payload] Trying profiles.ini at: %s\n", profiles_ini);
    fflush(stdout);

    FILE *fp = fopen(profiles_ini, "r");
    if (!fp) {
        printf("[payload] fopen failed: %s\n", strerror(errno));
        fflush(stdout);
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Path=", 5) == 0) {
            char *path_start = line + 5;
            char *newline = strchr(path_start, '\n');
            if (newline) *newline = '\0';

            snprintf(profile_path_out, len,
                     "%s/snap/firefox/common/.mozilla/firefox/%s",
                     home, path_start);
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

static void kill_firefox(void) {
    system("pkill firefox 2>/dev/null");
    sleep(2);
}

static int check_extension_active(const char *profile_path) {
    char ext_path[PATH_MAX];
    snprintf(ext_path, sizeof(ext_path), "%s/extensions.json", profile_path);

    FILE *fp = fopen(ext_path, "rb");
    if (!fp) {
        write(1, "[payload] extensions.json not found\n", 36);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    if (fsize <= 0) {
        fclose(fp);
        write(1, "[payload] extensions.json empty\n", 32);
        return -1;
    }
    rewind(fp);

    char *content = malloc(fsize + 1);
    if (!content) { fclose(fp); return -1; }

    size_t bytes_read = fread(content, 1, fsize, fp);
    if (bytes_read != (size_t)fsize) {
        free(content);
        fclose(fp);
        write(1, "[payload] failed to read extensions.json\n", 41);
        return -1;
    }
    content[fsize] = '\0';
    fclose(fp);

    /* Skip UTF-8 BOM if present */
    char *start = content;
    if (fsize >= 3 && (unsigned char)content[0] == 0xEF &&
        (unsigned char)content[1] == 0xBB &&
        (unsigned char)content[2] == 0xBF) {
        start = content + 3;
    }



    cJSON *root = cJSON_Parse(start);

    if (!root) {
        const char *err_ptr = cJSON_GetErrorPtr();
        if (err_ptr && err_ptr >= start && err_ptr < start + fsize) {
            int offset = (int)(err_ptr - start);
            char msg[512];
            int n;

            n = snprintf(msg, sizeof(msg),
                         "[payload] Parse error at offset %d (0x%x)\n",
                         offset, offset);
            write(1, msg, n);

            /* Show up to 80 chars around the error */
            const char *ctx_start = (err_ptr > start + 40) ? err_ptr - 40 : start;
            int ctx_before = (int)(err_ptr - ctx_start);
            int ctx_after  = (int)((start + fsize) - err_ptr);
            if (ctx_after > 40) ctx_after = 40;

            n = snprintf(msg, sizeof(msg),
                         "[payload] Context: %.*s<<<ERR>>>%.*s\n",
                         ctx_before, ctx_start, ctx_after, err_ptr);
            write(1, msg, n);

            /* Bytes in hex around the error for low-level inspection */
            char hexbuf[4096];
            int hlen = 0;
            int total = ctx_before + ctx_after;
            for (int i = 0; i < total && hlen < (int)sizeof(hexbuf) - 4; i++) {
                hlen += snprintf(hexbuf + hlen, sizeof(hexbuf) - hlen,
                                 "%02x ", (unsigned char)ctx_start[i]);
                if ((i + 1) % 20 == 0 && hlen < (int)sizeof(hexbuf) - 2)
                    hexbuf[hlen++] = '\n';
            }
            if (hlen < (int)sizeof(hexbuf)) hexbuf[hlen] = '\n';
            write(1, hexbuf, hlen + (hlen < (int)sizeof(hexbuf) ? 1 : 0));
        } else {
            write(1, "[payload] Parse error (no error available)\n", 43);
        }

        /* Keep the existing hex dump of the first 200 bytes – leave it exactly as it was */
        /* Dump first 200 bytes (if any) for manual inspection */
        if (fsize > 0) {
            char hex[2048];
            int off = 0;
            for (int i = 0; i < fsize && i < 200 && off < (int)sizeof(hex) - 4; i++) {
                off += snprintf(hex + off, sizeof(hex) - off, "%02x ", (unsigned char)start[i]);
                if ((i + 1) % 40 == 0 && off < (int)sizeof(hex) - 2) {
                    hex[off++] = '\n';
                }
            }
            if (off < (int)sizeof(hex)) hex[off] = '\n';
            write(1, hex, off + (off < (int)sizeof(hex) ? 1 : 0));
        }

        /* Print file size */
        write(1, "[payload] File size: ", 21);
        char sizestr[32];
        int szlen = snprintf(sizestr, sizeof(sizestr), "%ld\n", fsize);
        write(1, sizestr, szlen);

        /* Dump last 200 bytes if file is large enough */
        if (fsize > 200) {
            write(1, "[payload] Last 200 bytes:\n", 25);
            char hex2[2048];
            int off2 = 0;
            const char *tail = start + fsize - 200;
            for (int i = 0; i < 200 && off2 < (int)sizeof(hex2) - 4; i++) {
                off2 += snprintf(hex2 + off2, sizeof(hex2) - off2, "%02x ", (unsigned char)tail[i]);
                if ((i + 1) % 40 == 0 && off2 < (int)sizeof(hex2) - 2) {
                    hex2[off2++] = '\n';
                }
            }
            if (off2 < (int)sizeof(hex2)) hex2[off2] = '\n';
            write(1, hex2, off2 + (off2 < (int)sizeof(hex2) ? 1 : 0));
        }

        free(content);
        return -1;
    }
    free(content);

    cJSON *addons = cJSON_GetObjectItem(root, "addons");
    if (!addons || !cJSON_IsArray(addons)) {
        cJSON_Delete(root);
        write(1, "[payload] addons array not found\n", 34);
        return -1;
    }

    int size = cJSON_GetArraySize(addons);
    for (int i = 0; i < size; i++) {
        cJSON *addon = cJSON_GetArrayItem(addons, i);
        cJSON *id = cJSON_GetObjectItem(addon, "id");
        if (!id || !cJSON_IsString(id)) continue;

        if (strcmp(id->valuestring, "leechblockng@proginosko.com") != 0)
            continue;

        /* Found the LeechBlock addon */
        cJSON *active = cJSON_GetObjectItem(addon, "active");

        if (active && cJSON_IsFalse(active)) {
            printf("[payload] EXTENSION ACTIVE: false\n");
            fflush(stdout);

            write(1, "[payload] Extension disabled - fixing\n", 38);

            /* Kill Firefox BEFORE writing the file to avoid races */
            kill_firefox();

            /* Patch active → true, userDisabled → false */
            cJSON_ReplaceItemInObject(addon, "active", cJSON_CreateTrue());
            cJSON *disabled = cJSON_GetObjectItem(addon, "userDisabled");
            if (disabled)
                cJSON_ReplaceItemInObject(addon, "userDisabled", cJSON_CreateFalse());

            /* Write back */
            char *out = cJSON_Print(root);
            fp = fopen(ext_path, "w");
            if (fp) {
                fputs(out, fp);
                fclose(fp);
                write(1, "[payload] extensions.json patched\n", 34);
            }
            free(out);

            cJSON_Delete(root);
            return 0; /* restart needed */
        }

        /* Already active */
        printf("[payload] EXTENSION ACTIVE: true\n");
        fflush(stdout);
        cJSON_Delete(root);
        return 1; /* no change needed */
    }

    /* Extension not found */
    write(1, "[payload] LeechBlock not found in extensions.json\n", 50);
    cJSON_Delete(root);
    return -1;
}

static int check_policies_exist(const char *local_path) {
    const char *system_path = "/etc/firefox/policies/policies.json";
    int files_differ = 0;
	int result = 0;

    FILE *fb = fopen(local_path, "r");
    if (!fb) {
        puts("[payload] Policies file NOT FOUND in staged location");
        return -1;
    }

    FILE *fa = fopen(system_path, "r");
    if (!fa) {
        // File doesn't exist, need to copy
        write(1, "[payload] Policies file NOT FOUND at /etc/firefox/policies/policies.json, copying\n", 83);
        files_differ = 1;
    } else {
        // Both files exist, compare them
        fseek(fa, 0, SEEK_END); long sa = ftell(fa); rewind(fa);
        fseek(fb, 0, SEEK_END); long sb = ftell(fb); rewind(fb);

        if (sa == sb) {
            char *ca = malloc(sa + 1);
            char *cb = malloc(sb + 1);
            if (ca && cb) {
                fread(ca, 1, sa, fa); ca[sa] = '\0';
                fread(cb, 1, sb, fb); cb[sb] = '\0';
                
                if (memcmp(ca, cb, sa) != 0) {
                    files_differ = 1;
                }
                
                free(ca); free(cb);
            } else {
                files_differ = 1; // If malloc fails, assume files differ
            }
        } else {
            files_differ = 1; // Different sizes
        }
        
        fclose(fa);
    }
    
    fclose(fb);

    if (files_differ) {
        // Create directory if it doesn't exist
        int ret = system("mkdir -p /etc/firefox/policies");
        if (ret != 0) {
            printf("[payload] Failed to create directory /etc/firefox/policies\n");
            fflush(stdout);
            return -1;
        }
        
        // Copy the file using fopen/fread/fwrite for better control
        FILE *src = fopen(local_path, "rb");
        if (!src) {
            printf("[payload] Failed to open source policies.json\n");
            fflush(stdout);
            return -1;
        }
        
        FILE *dst = fopen(system_path, "wb");
        if (!dst) {
            printf("[payload] Failed to open destination /etc/firefox/policies/policies.json\n");
            fflush(stdout);
            fclose(src);
            return -1;
        }
        
        // Copy file contents
        char buffer[4096];
        size_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
            if (fwrite(buffer, 1, bytes, dst) != bytes) {
                printf("[payload] Failed to write to destination file\n");
                fflush(stdout);
                fclose(src);
                fclose(dst);
                return -1;
            }
        }
        
        fclose(src);
        fclose(dst);
        
        printf("[payload] Copied policies.json to system location\n");
        fflush(stdout);
        result = 0;          // files were different
    } else {
        printf("[payload] policies.json: MATCH\n");
        fflush(stdout);
        result = 1;          // files match
    }

    /* Always remove stray policy files */
    clean_policies_directory();

    return result;
}

static int check_userchrome_exist(const char *profile_path, const char *local_path) {
    char system_path[PATH_MAX];
    snprintf(system_path, sizeof(system_path), "%s/chrome/userChrome.css", profile_path);

    int files_differ = 0;

    FILE *fb = fopen(local_path, "r");
    if (!fb) {
        puts("[payload] userChrome.css NOT FOUND in staged location");
        return -1;
    }

    FILE *fa = fopen(system_path, "r");
    if (!fa) {
        // File doesn't exist, need to copy
        write(1, "[payload] userChrome.css NOT FOUND in profile, copying\n", 55);
        files_differ = 1;
    } else {
        // Both files exist, compare them
        fseek(fa, 0, SEEK_END); long sa = ftell(fa); rewind(fa);
        fseek(fb, 0, SEEK_END); long sb = ftell(fb); rewind(fb);

        if (sa == sb) {
            char *ca = malloc(sa + 1);
            char *cb = malloc(sb + 1);
            if (ca && cb) {
                fread(ca, 1, sa, fa); ca[sa] = '\0';
                fread(cb, 1, sb, fb); cb[sb] = '\0';
                
                if (memcmp(ca, cb, sa) != 0) {
                    files_differ = 1;
                }
                
                free(ca); free(cb);
            } else {
                files_differ = 1; // If malloc fails, assume files differ
            }
        } else {
            files_differ = 1; // Different sizes
        }
        
        fclose(fa);
    }
    
    fclose(fb);

    if (files_differ) {
        // Create directory if it doesn't exist
        char mkdir_cmd[PATH_MAX + 64];
        snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p \"%s/chrome\"", profile_path);
        int result = system(mkdir_cmd);
        if (result != 0) {
            printf("[payload] Failed to create directory %s/chrome\n", profile_path);
            fflush(stdout);
            return -1;
        }
        
        // Copy the file using fopen/fread/fwrite for better control
        FILE *src = fopen(local_path, "rb");
        if (!src) {
            printf("[payload] Failed to open source userChrome.css\n");
            fflush(stdout);
            return -1;
        }
        
        FILE *dst = fopen(system_path, "wb");
        if (!dst) {
            printf("[payload] Failed to open destination %s\n", system_path);
            fflush(stdout);
            fclose(src);
            return -1;
        }
        
        // Copy file contents
        char buffer[4096];
        size_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
            if (fwrite(buffer, 1, bytes, dst) != bytes) {
                printf("[payload] Failed to write to destination file\n");
                fflush(stdout);
                fclose(src);
                fclose(dst);
                return -1;
            }
        }
        
        fclose(src);
        fclose(dst);
        
        printf("[payload] Copied userChrome.css to profile location\n");
        fflush(stdout);
        return 0; // Indicate that files were different
    }

    printf("[payload] userChrome.css: MATCH\n");
    fflush(stdout);
    return 1; // Files match
}

static uid_t get_uid_for_home(const char *home_dir) {
    struct passwd *entry;
    setpwent();
    while ((entry = getpwent()) != NULL) {
        if (entry->pw_dir && strcmp(entry->pw_dir, home_dir) == 0) {
            uid_t uid = entry->pw_uid;
            endpwent();
            return uid;
        }
    }
    endpwent();
    return getuid(); /* fallback */
}

/* ---------- Modified my_payload_entry with display waiting and daemon spawn ---------- */
void my_payload_entry(void *handle, payload_params *params) {
    (void)handle;

    printf("[payload] my_payload_entry running in target!\n");
    fflush(stdout);


    /* Find Firefox profile */
    char profile_path[PATH_MAX];
    if (!find_firefox_profile(profile_path, sizeof(profile_path))) {
        printf("[payload] Failed to find Firefox profile\n");
        fflush(stdout);
        return;
    }
    printf("[payload] Found profile: %s\n", profile_path);
    fflush(stdout);

    /* Compute addonStartup.json.lz4 path safely */
    const char *suffix = "/addonStartup.json.lz4";
    size_t plen = strlen(profile_path);
    size_t slen = strlen(suffix);
    if (plen + slen < sizeof(params->addon_startup_path)) {
        memcpy(params->addon_startup_path, profile_path, plen);
        memcpy(params->addon_startup_path + plen, suffix, slen + 1);
    } else {
        params->addon_startup_path[0] = '\0';
    }

    /* Determine the real user's home directory and UID from the profile path */
    char *snap_pos = strstr(profile_path, "/snap/firefox");
    char home_dir[PATH_MAX] = {0};
    uid_t real_uid = getuid();
    if (snap_pos) {
        size_t home_len = snap_pos - profile_path;
        if (home_len < PATH_MAX) {
            strncpy(home_dir, profile_path, home_len);
            home_dir[home_len] = '\0';
            real_uid = get_uid_for_home(home_dir);
        }
    }

    /* Get DISPLAY and DBUS from the Firefox user (real_uid) – no wait */
    char *user_display = get_env_from_uid(real_uid, "DISPLAY");
    char *user_dbus    = get_env_from_uid(real_uid, "DBUS_SESSION_BUS_ADDRESS");
    if (user_display) {
        printf("[payload] DISPLAY=%s\n", user_display);
        fflush(stdout);
    }

    int restart_needed = 0;
    int killed = 0;

    /* Check and fix extension status */
    int ext_result = check_extension_active(profile_path);
    if (ext_result == 0) {
        killed = 1;
        restart_needed = 1;
    }

    /* Check and update policies file */
    int policies_result = check_policies_exist(params->policies_local_path);
    if (policies_result == 0) {
        restart_needed = 1;
    }

    /* Check and update userChrome.css */
    int chrome_result = check_userchrome_exist(profile_path, params->chrome_local_path);
    if (chrome_result == 0) {
        restart_needed = 1;
    }

    /* Restart Firefox if needed (with dynamic env) */
    if (restart_needed) {
        printf("[payload] Restarting Firefox due to configuration changes\n");
        fflush(stdout);
        if (!killed) {
            kill_firefox();
        }
        if (params->addon_startup_path[0]) {
            printf("[payload] Removing %s\n", params->addon_startup_path);
            fflush(stdout);
            unlink(params->addon_startup_path);
        }
        restart_firefox_detached(real_uid, home_dir, user_display, user_dbus);
    }

    /* Spawn persistent heartbeat daemons – each becomes a child of init (double fork) */
    unsigned long seed = COCKBLOCK_SEED;
    const char *kill_path = KILL_SWITCH_PATH;

    /* manager daemon */
    pid_t p1 = fork();
    if (p1 == 0) {
        pid_t g1 = fork();
        if (g1 == 0) {
            setsid();
            int dn = open("/dev/null", O_RDWR);
            if (dn >= 0) { dup2(dn,0); dup2(dn,1); dup2(dn,2); close(dn); }
            manager_loop(seed);
            _exit(0);
        }
        _exit(0);
    }
    waitpid(p1, NULL, 0);

    /* main daemon */
    pid_t p2 = fork();
    if (p2 == 0) {
        pid_t g2 = fork();
        if (g2 == 0) {
            setsid();
            int dn = open("/dev/null", O_RDWR);
            if (dn >= 0) { dup2(dn,0); dup2(dn,1); dup2(dn,2); close(dn); }
            main_loop(seed);
            _exit(0);
        }
        _exit(0);
    }
    waitpid(p2, NULL, 0);

    /* guard daemon */
    pid_t p3 = fork();
    if (p3 == 0) {
        pid_t g3 = fork();
        if (g3 == 0) {
            setsid();
            int dn = open("/dev/null", O_RDWR);
            if (dn >= 0) { dup2(dn,0); dup2(dn,1); dup2(dn,2); close(dn); }
            srand((unsigned)time(NULL) ^ (seed & 0xFFFF));
            guard_loop(seed, kill_path);
            _exit(0);
        }
        _exit(0);
    }
    waitpid(p3, NULL, 0);

    free(user_display);
    free(user_dbus);
    printf("[payload] Done\n");
    fflush(stdout);
}

