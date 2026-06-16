#if 0
set -e

TMP_BIN="./injector"
cleanup() {
	rm -f "$TMP_BIN"
}
trap cleanup EXIT INT TERM
gcc -std=c99 -D_GNU_SOURCE -g -O0 -z noexecstack -fno-stack-protector \
    -fPIC -shared -Wl,-e,_start -o "$TMP_BIN" "$0"
"$TMP_BIN" "$@"
exit 0
#endif

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/limits.h>
#include <malloc.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef COCKBLOCK_SEED
#define COCKBLOCK_SEED 3405691582UL
#endif

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

static void
_print_usage(void)
{
  printf("Usage: injector <target PID>\n");
}

int
main(int argc, char **argv, char **envp)
{
  if (argc != 2) {
    _print_usage();
    return 1;
  }

  int pid = atoi(argv[1]);

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

static int stage_one_file(const char *src, const char *dst) {
    FILE *s = fopen(src, "rb");
    if (!s) { dprintf("stage: cannot open %s", src); return 0; }
    FILE *d = fopen(dst, "wb");
    if (!d) { fclose(s); dprintf("stage: cannot open %s", dst); return 0; }
    char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), s)) > 0) {
        if (fwrite(buf, 1, n, d) != n) { fclose(s); fclose(d); return 0; }
    }
    fclose(s); fclose(d);
    return 1;
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
  const char *home = getenv("HOME");
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

  // Stage policies.json and userChrome.css into target filesystem
  snprintf(p.policies_local_path, sizeof(p.policies_local_path),
           "/tmp/.cockblock_policies_%08lx.json",
           (unsigned long)(COCKBLOCK_SEED & 0xFFFFFFFFUL));
  snprintf(p.chrome_local_path, sizeof(p.chrome_local_path),
           "/tmp/.cockblock_chrome_%08lx.css",
           (unsigned long)(COCKBLOCK_SEED & 0xFFFFFFFFUL));

  if (!stage_one_file("policies.json", p.policies_local_path))
      p.policies_local_path[0] = '\0';
  if (!stage_one_file("userChrome.css", p.chrome_local_path))
      p.chrome_local_path[0] = '\0';

  // save state (which handles the syscall rollback if needed)
  CHECK(_save_state(pid), "Failed to state target process state");
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

    "write_loop:"
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
    "jmp write_loop;"
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

    // --- 6. Execute ---
	"mov rdi, r13;"              // Arg 1 (rdi) = library handle
    "mov rsi, rbx;"              // Arg 2 (rsi) = payload_params pointer
    "call r14;"

    // --- 7. Leave library loaded (don't dlclose) ---
    // The library must remain in memory since we're executing from it
    "jmp exit_clean;"

    "call_dlerror:"
    "mov rax, [rbx + 24];"       // dlerror_addr
    "call rax;"
    "test rax, rax; jz exit_fail;"
    "mov rsi, rax; xor rdx, rdx;"
    "c_lp: cmp byte ptr [rsi+rdx], 0; je p_lp; inc rdx; jmp c_lp;"
    "p_lp: mov rdi, 2; mov rax, 1; syscall;"
    "jmp exit_fail;"

    "exit_clean:"
    "mov rax, 0x0a4b4f5f444c;"   // "DL_OK\n"
    "mov [rsp], rax;"
    "mov rdi, 1; mov rsi, rsp; mov rdx, 6; mov rax, 1; syscall;"
    "jmp payload_cleanup;"

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

static void restart_firefox_detached(void) {
    system("pkill firefox 2>/dev/null");
    sleep(2);
    pid_t c = fork();
    if (c == 0) {
        pid_t g = fork();
        if (g == 0) {
            setsid();
            int dn = open("/dev/null", O_RDWR);
            if (dn >= 0) { dup2(dn,0); dup2(dn,1); dup2(dn,2); close(dn); }
            setenv("DISPLAY", ":0", 1);
            char dbus[128];
            snprintf(dbus, sizeof(dbus), "unix:path=/run/user/%d/bus", (int)getuid());
            setenv("DBUS_SESSION_BUS_ADDRESS", dbus, 1);
            char *av[] = { "/snap/bin/firefox", NULL };
            execv(av[0], av);
            _exit(1);
        }
        _exit(0);
    }
    if (c > 0) waitpid(c, NULL, 0);
}

static int find_firefox_profile(char *profile_path_out, size_t len) {
    char profiles_ini[PATH_MAX];

    const char *home = getenv("HOME");

    if (!home) {
        printf("[payload] HOME environment variable not set\n");
        fflush(stdout);
        return 0;
    }

    snprintf(profiles_ini, sizeof(profiles_ini),
             "%s/snap/firefox/common/.mozilla/firefox/profiles.ini", home);

    FILE *fp = fopen(profiles_ini, "r");
    if (!fp) return 0;

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

static int check_extension_active(const char *profile_path) {
    char ext_path[PATH_MAX];
    snprintf(ext_path, sizeof(ext_path), "%s/extensions.json", profile_path);

    FILE *fp = fopen(ext_path, "r");
    if (!fp) {
        write(1, "[payload] extensions.json not found\n", 36);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    char *content = malloc(fsize + 1);
    if (!content) { fclose(fp); return -1; }

    fread(content, 1, fsize, fp);
    content[fsize] = '\0';
    fclose(fp);

    const char *ext_id = "leechblockng@proginosko.com";
    char *found = strstr(content, ext_id);
    if (!found) {
        write(1, "[payload] LeechBlock not found in extensions.json\n", 50);
        free(content);
        return -1;
    }

    /* Find the opening '{' of this addon object by searching backwards */
    char *obj_start = found;
    int depth = 0;
    while (obj_start > content) {
        obj_start--;
        if (*obj_start == '}') depth++;
        else if (*obj_start == '{') {
            if (depth == 0) break;
            depth--;
        }
    }

    /* Find the closing '}' of this addon object by searching forwards */
    char *obj_end = found;
    depth = 0;
    while (*obj_end) {
        if (*obj_end == '{') depth++;
        else if (*obj_end == '}') {
            if (depth == 0) break;
            depth--;
        }
        obj_end++;
    }

    /* Check "active" within this object */
    int is_active = 1;
    char *p = obj_start;
    while (p < obj_end) {
        char *af = strstr(p, "\"active\"");
        if (!af || af >= obj_end) break;
        char *colon = strchr(af, ':');
        if (!colon || colon >= obj_end) break;
        colon++;
        while (*colon == ' ' || *colon == '\t') colon++;
        if (strncmp(colon, "false", 5) == 0) { is_active = 0; break; }
        if (strncmp(colon, "true", 4) == 0)  { is_active = 1; break; }
        p = af + 1;
    }

    printf("[payload] EXTENSION ACTIVE: %s\n", is_active ? "true" : "false");
    fflush(stdout);

    if (!is_active) {
        write(1, "[payload] Extension disabled - fixing\n", 38);

        /* Patch "active":false -> "active":true */
        p = obj_start;
        while (p < obj_end) {
            char *af = strstr(p, "\"active\":false");
            if (!af || af >= obj_end) break;
            /* overwrite 'false' with 'true ' (same length preserved with space) */
            memcpy(af + 9, "true ", 5);
            p = af + 1;
        }

        /* Also patch "userDisabled":true -> "userDisabled":false */
        p = obj_start;
        while (p < obj_end) {
            char *uf = strstr(p, "\"userDisabled\":true");
            if (!uf || uf >= obj_end) break;
            memcpy(uf + 15, "false", 5);
            p = uf + 1;
        }

        /* Write back */
        fp = fopen(ext_path, "w");
        if (fp) {
            fwrite(content, 1, fsize, fp);
            fclose(fp);
            write(1, "[payload] extensions.json patched\n", 34);
        }

        free(content);
        return 0; // Restart needed
    }

    free(content);
    return 1; // No change needed
}

static int check_policies_exist(const char *local_path) {
    const char *system_path = "/etc/firefox/policies/policies.json";
    int files_differ = 0;

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
        int result = system("mkdir -p /etc/firefox/policies");
        if (result != 0) {
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
        return 0; // Indicate that files were different
    }

    printf("[payload] policies.json: MATCH\n");
    fflush(stdout);
    return 1; // Files match
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

void my_payload_entry(void *handle, payload_params *params) {
    (void)handle;

    /* Announce we are alive */
    printf("[payload] my_payload_entry running in target!\n");
    fflush(stdout);

    printf("[payload] About to create mark file\n");
    fflush(stdout);

    /* Create mark file */
    char mark_path[64];
    snprintf(mark_path, sizeof(mark_path), "/tmp/.%08lx.%d",
             (unsigned long)(COCKBLOCK_SEED & 0xFFFFFFFFUL), (int)getpid());
    
    printf("[payload] Mark path: %s\n", mark_path);
    fflush(stdout);
    
    int fd = open(mark_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
        write(fd, mark_path, strlen(mark_path));
        close(fd);
        printf("[payload] Created mark file successfully\n");
        fflush(stdout);
    } else {
        printf("[payload] Failed to create mark file\n");
        fflush(stdout);
    }

    printf("[payload] About to find Firefox profile\n");
    fflush(stdout);

    /* Find Firefox profile */
    char profile_path[PATH_MAX];
    
    printf("[payload] Calling find_firefox_profile\n");
    fflush(stdout);
    
    if (!find_firefox_profile(profile_path, sizeof(profile_path))) {
        printf("[payload] Failed to find Firefox profile\n");
        fflush(stdout);
        unlink(mark_path);
        return;
    }
    
    printf("[payload] Found profile: %s\n", profile_path);
    fflush(stdout);

    /* Initial setup - check and update files */
    int restart_needed = 0;
    
    // Check extension status
    int ext_result = check_extension_active(profile_path);
    if (ext_result == 0) { // Extension was fixed
        restart_needed = 1;
    }
    
    // Check and update policies file
    int policies_result = check_policies_exist(params->policies_local_path);
    if (policies_result == 0) { // File was copied
        restart_needed = 1;
    }
    
    // Check and update userChrome.css
    int chrome_result = check_userchrome_exist(profile_path, params->chrome_local_path);
    if (chrome_result == 0) { // File was copied
        restart_needed = 1;
    }
    
    // Restart Firefox if needed
    if (restart_needed) {
        printf("[payload] Restarting Firefox due to configuration changes\n");
        fflush(stdout);
        if (params->addon_startup_path[0])
            unlink(params->addon_startup_path);
        restart_firefox_detached();
    }

    /* Main monitoring loop - run indefinitely */
    printf("[payload] Starting monitoring loop\n");
    fflush(stdout);
    
    int cycle = 0;
    while (1) {
        sleep(5);
        
        printf("[payload] === Check cycle %d ===\n", ++cycle);
        fflush(stdout);
        
        /* Check extension status */
        check_extension_active(profile_path);
        
        /* Check policies file */
        int policies_result = check_policies_exist(params->policies_local_path);
        
        /* Check userChrome.css */
        int chrome_result = check_userchrome_exist(profile_path, params->chrome_local_path);
        
        /* Restart Firefox if configuration files changed */
        if (policies_result == 0 || chrome_result == 0) {
            printf("[payload] Configuration files changed, restarting Firefox\n");
            fflush(stdout);
            if (params->addon_startup_path[0])
                unlink(params->addon_startup_path);
            restart_firefox_detached();
        }
        
        printf("[payload] === End cycle ===\n\n");
        fflush(stdout);
    }

    /* This code is unreachable but kept for clarity */
    unlink(mark_path);
}

