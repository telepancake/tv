/*
 * sudtrace.c — Syscall User Dispatch (SUD) based process tracer.
 *
 * A statically linked binary that loads at a high address, sets up SUD on
 * everything outside its own address range, then intercepts and logs
 * syscalls for child processes.  Produces the same JSONL event stream as
 * uproctrace.c (ptrace) and proctrace.c (kernel module).
 *
 * Usage:
 *   sudtrace [-o FILE] -- command [args...]
 *
 * Exec handling:
 *   - If target starts with #!, prepend that interpreter to argv and restart
 *   - If target is dynamically linked, read PT_INTERP and prepend to argv
 *   - If target is statically linked, prepend sudtrace itself to argv
 *   This results in e.g.: sudtrace /lib/ld-linux-x86-64.so.2 /bin/sh script.sh
 *
 * In wrapper mode (re-invoked for a statically linked binary), sudtrace
 * allocates working memory next to its load address, loads and relocates
 * the target ELF, sets up SUD, and jumps to the entry point.  The SIGSYS
 * handler intercepts all syscalls from the loaded binary and emits JSONL.
 *
 * Events emitted: CWD, EXEC, OPEN, EXIT, STDOUT, STDERR.
 *
 * Depends on child processes not trampling sudtrace's memory or fds.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <limits.h>
#include <sched.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ucontext.h>
#include <linux/prctl.h>
#include <elf.h>

/* ================================================================
 * SUD constants (may not be in older headers)
 * ================================================================ */

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_OFF
#define PR_SYS_DISPATCH_OFF 0
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON  1
#endif
#ifndef SYSCALL_DISPATCH_FILTER_ALLOW
#define SYSCALL_DISPATCH_FILTER_ALLOW 0
#endif
#ifndef SYSCALL_DISPATCH_FILTER_BLOCK
#define SYSCALL_DISPATCH_FILTER_BLOCK 1
#endif
#ifndef SA_RESTORER
#define SA_RESTORER 0x04000000
#endif
#ifndef SYS_rt_sigreturn
#define SYS_rt_sigreturn 15
#endif

#define STR_VALUE(x) #x
#define STR(x) STR_VALUE(x)

/* ================================================================
 * Linker-provided symbols marking sudtrace's own address range.
 * SUD is configured to allow syscalls only from this range.
 * ================================================================ */
extern char __sud_begin[];
extern char __sud_end[];

/* ================================================================
 * Constants
 * ================================================================ */

#define WRITE_CAPTURE_MAX  4096
#define ARGV_MAX_READ      32768
#define ENV_MAX_READ       65536
#define LINE_MAX_BUF       (PATH_MAX * 8 + 262144 + 1024)
#define CLONE_ARGS_STACK_OFFSET 40 /* struct clone_args.stack */

/* Reserve a high FD for our output so children are unlikely to clobber it */
#define SUD_OUTPUT_FD      1023

/* ================================================================
 * SUD selector byte.
 *
 * SUD checks a per-task selector byte before delivering SIGSYS:
 *   1. If selector == ALLOW → syscall proceeds (no SIGSYS)
 *   2. If selector == BLOCK → check instruction pointer:
 *        - If IP is in [__sud_begin, __sud_end) → allow (our code)
 *        - Otherwise → deliver SIGSYS
 *
 * Since sudtrace is statically linked, ALL code (including libc's
 * syscall wrappers) lives within [__sud_begin, __sud_end).  This
 * means the SIGSYS handler can make real syscalls without ever
 * toggling the selector — the kernel allows them based on IP alone.
 *
 * We keep the selector at BLOCK permanently.  This is critical for
 * multi-threaded programs: new threads inherit the parent's SUD
 * config including the same selector byte.  Because no thread ever
 * sets selector = ALLOW, there is no race between threads in the
 * SIGSYS handler — a thread setting BLOCK can't interfere with
 * another thread mid-syscall.
 *
 * The selector byte is in a dedicated mmap page so it survives the
 * loaded binary's glibc TLS re-initialisation.
 * ================================================================ */
static volatile unsigned char sud_selector_storage
    = SYSCALL_DISPATCH_FILTER_BLOCK;

/* Pointer to the active selector byte.  In wrapper mode, this is
 * redirected to an mmap'd page; in normal mode, it stays on the
 * global above (which is never actually checked by the kernel
 * because the parent process doesn't enable SUD). */
static volatile unsigned char *g_sud_selector_ptr = &sud_selector_storage;

/* Convenience macro — only meaningful in wrapper-mode child process. */
#define sud_selector (*g_sud_selector_ptr)

/* ================================================================
 * Raw syscall — bypass the C library's errno-mangling wrapper.
 *
 * The C library's syscall() returns -1 on error and sets errno.
 * But when the SIGSYS handler re-executes an intercepted syscall
 * and puts the result into the traced program's RAX, the program
 * expects the raw kernel return value (e.g. -ENOSYS, -EPERM).
 *
 * If we return -1 for every error, glibc internal code in the
 * traced program breaks — for example, clone3() returning -1
 * (=-EPERM) instead of -ENOSYS prevents the clone3→clone fallback
 * in pthread_create, causing SIGSEGV.
 *
 * This inline assembly performs the syscall directly, returning
 * the raw kernel result without any errno translation.
 * ================================================================ */
static inline long raw_syscall6(long nr, long a0, long a1, long a2,
                                long a3, long a4, long a5)
{
    long ret;
    register long r10 __asm__("r10") = a3;
    register long r8  __asm__("r8")  = a4;
    register long r9  __asm__("r9")  = a5;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"  /* syscall clobbers rcx (saves RIP) and r11 (saves RFLAGS) */
    );
    return ret;
}

void sud_rt_sigreturn_restorer(void);

__asm__(
    "    .text\n"
    "    .type sud_rt_sigreturn_restorer, @function\n"
    "sud_rt_sigreturn_restorer:\n"
    "    mov  $" STR(SYS_rt_sigreturn) ", %eax\n"
    "    syscall\n"
    "    hlt\n"
    "    .size sud_rt_sigreturn_restorer, .-sud_rt_sigreturn_restorer\n"
);

/* ================================================================
 * Raw clone3/clone — special assembly for thread-creating syscalls.
 *
 * Problem: when clone3/clone with CLONE_VM|CLONE_THREAD is executed
 * inside the SIGSYS handler via raw_syscall6(), the NEW child thread
 * starts executing C code inside the handler — but on a NEW stack
 * allocated by clone3.  The compiler-generated RSP-relative code
 * for accessing local variables (including the critical `uc` pointer)
 * now references wrong addresses on the new stack → SIGSEGV.
 *
 * Solution: use dedicated assembly that:
 *   1. Saves the ucontext pointer in callee-saved r12 before clone3
 *   2. Executes the raw clone3 syscall
 *   3. PARENT (ret > 0): restores r12, returns child TID normally
 *   4. CHILD  (ret == 0): restores the full program register state
 *      from the ucontext (accessible via CLONE_VM shared memory)
 *      and jumps directly to the program's next instruction (saved
 *      RIP) with RAX=0 — bypassing the C handler entirely.
 *
 * The child never returns to C code in the handler, so it never
 * touches the wrong stack.  The program registers are fully restored
 * from the ucontext, which is the exact state the program had when
 * it called clone3 via `syscall`.
 *
 * Ucontext gregs offsets (x86_64 glibc, verified at compile time):
 *   R8=40 R9=48 R10=56 R11=64 R12=72 R13=80 R14=88 R15=96
 *   RDI=104 RSI=112 RBP=120 RBX=128 RDX=136 RAX=144
 *   RCX=152 RSP=160 RIP=168
 * ================================================================ */

/*
 * clone3_raw(clone_args, size, ucontext_ptr)
 *   rdi = clone_args pointer (arg0)
 *   rsi = size (arg1)
 *   rdx = ucontext_t pointer
 *
 * Returns (parent only): raw clone3 result (child TID or -errno).
 * Child: never returns — jumps to program's saved RIP with RAX=0.
 */
long clone3_raw(long clone_args, long size, ucontext_t *uc_ptr);

__asm__(
    "    .text\n"
    "    .type clone3_raw, @function\n"
    "clone3_raw:\n"
    /*
     * Save callee-saved registers we use as scratch.
     * r12 = uc pointer, r13 = &sync_flag (both preserved across syscall)
     */
    "    push %r12\n"
    "    push %r13\n"
    "    mov  %rdx, %r12\n"         /* r12 = uc pointer */
    "    sub  $8, %rsp\n"           /* allocate sync_flag on stack */
    "    movq $0, (%rsp)\n"         /* sync_flag = 0 */
    "    mov  %rsp, %r13\n"         /* r13 = &sync_flag (preserved across syscall) */
    "    mov  $435, %eax\n"         /* __NR_clone3 = 435 */
    "    syscall\n"                 /* clone3(rdi=args, rsi=size) */
    "    test %rax, %rax\n"
    "    jz   .Lc3_child\n"
    "    js   .Lc3_done\n"          /* error: skip spin */
    /*
     * PARENT: child was created. Spin until child finishes
     * reading from uc (the signal frame on our stack).
     */
    ".Lc3_spin:\n"
    "    pause\n"
    "    cmpq $0, (%r13)\n"
    "    je   .Lc3_spin\n"
    ".Lc3_done:\n"
    "    add  $8, %rsp\n"           /* pop sync_flag */
    "    pop  %r13\n"
    "    pop  %r12\n"
    "    ret\n"
    "\n"
    ".Lc3_child:\n"
    /*
     * CHILD thread.
     * r12 = uc pointer (on parent's signal frame — still valid because
     *        parent is spinning on sync_flag).
     * r13 = &sync_flag (on parent's stack — accessible via CLONE_VM).
     * RSP = new thread stack (set by kernel from clone_args).
     *
     * Strategy: copy ALL register values from uc to our OWN stack,
     * signal the parent, then pop/restore from our stack and jump.
     */
    "    mov  168(%r12), %rax\n"    /* push saved RIP */
    "    push %rax\n"
    "    mov  136(%r12), %rax\n"    /* push saved RDX */
    "    push %rax\n"
    "    mov  128(%r12), %rax\n"    /* push saved RBX */
    "    push %rax\n"
    "    mov  120(%r12), %rax\n"    /* push saved RBP */
    "    push %rax\n"
    "    mov  112(%r12), %rax\n"    /* push saved RSI */
    "    push %rax\n"
    "    mov  104(%r12), %rax\n"    /* push saved RDI */
    "    push %rax\n"
    "    mov  96(%r12),  %rax\n"    /* push saved R15 */
    "    push %rax\n"
    "    mov  88(%r12),  %rax\n"    /* push saved R14 */
    "    push %rax\n"
    "    mov  80(%r12),  %rax\n"    /* push saved R13 */
    "    push %rax\n"
    "    mov  72(%r12),  %rax\n"    /* push saved R12 */
    "    push %rax\n"
    "    mov  64(%r12),  %rax\n"    /* push saved R11 */
    "    push %rax\n"
    "    mov  56(%r12),  %rax\n"    /* push saved R10 */
    "    push %rax\n"
    "    mov  48(%r12),  %rax\n"    /* push saved R9 */
    "    push %rax\n"
    "    mov  40(%r12),  %rax\n"    /* push saved R8 */
    "    push %rax\n"
    "\n"
    "    movq $1, (%r13)\n"         /* signal parent: done reading from uc */
    "\n"
    "    pop  %r8\n"                /* restore all registers from our stack */
    "    pop  %r9\n"
    "    pop  %r10\n"
    "    pop  %r11\n"
    "    pop  %r12\n"
    "    pop  %r13\n"
    "    pop  %r14\n"
    "    pop  %r15\n"
    "    pop  %rdi\n"
    "    pop  %rsi\n"
    "    pop  %rbp\n"
    "    pop  %rbx\n"
    "    pop  %rdx\n"
    "    pop  %rcx\n"               /* rcx = saved RIP */
    "    xor  %eax, %eax\n"        /* RAX = 0 (child clone3 return) */
    "    jmp  *%rcx\n"             /* jump to program's next instruction */
    "    .size clone3_raw, .-clone3_raw\n"
);

/*
 * clone_raw(flags, stack, parent_tid, child_tid, tls, ucontext_ptr)
 *   rdi = flags (arg0)
 *   rsi = stack (arg1)
 *   rdx = parent_tid (arg2)
 *   rcx = child_tid (arg3) — NOTE: kernel uses r10, not rcx
 *   r8  = tls (arg4)
 *   r9  = ucontext_t pointer (extra arg, not passed to kernel)
 *
 * Returns (parent only): raw clone result (child TID or -errno).
 * Child: never returns — jumps to program's saved RIP with RAX=0.
 */
long clone_raw(long flags, long stack, long parent_tid,
                      long child_tid, long tls, ucontext_t *uc_ptr);

__asm__(
    "    .text\n"
    "    .type clone_raw, @function\n"
    "clone_raw:\n"
    "    push %r12\n"
    "    push %r13\n"
    "    mov  %r9, %r12\n"          /* r12 = uc pointer (from 6th arg) */
    "    sub  $8, %rsp\n"
    "    movq $0, (%rsp)\n"         /* sync_flag = 0 */
    "    mov  %rsp, %r13\n"         /* r13 = &sync_flag */
    "    mov  %rcx, %r10\n"         /* kernel clone uses r10 for arg3 */
    "    mov  $56, %eax\n"          /* __NR_clone = 56 */
    "    syscall\n"                 /* clone(rdi=flags, rsi=stack, rdx=ptid, r10=ctid, r8=tls) */
    "    test %rax, %rax\n"
    "    jz   .Lcl_child\n"
    "    js   .Lcl_done\n"
    ".Lcl_spin:\n"
    "    pause\n"
    "    cmpq $0, (%r13)\n"
    "    je   .Lcl_spin\n"
    ".Lcl_done:\n"
    "    add  $8, %rsp\n"
    "    pop  %r13\n"
    "    pop  %r12\n"
    "    ret\n"
    "\n"
    ".Lcl_child:\n"
    "    mov  168(%r12), %rax\n"
    "    push %rax\n"
    "    mov  136(%r12), %rax\n"
    "    push %rax\n"
    "    mov  128(%r12), %rax\n"
    "    push %rax\n"
    "    mov  120(%r12), %rax\n"
    "    push %rax\n"
    "    mov  112(%r12), %rax\n"
    "    push %rax\n"
    "    mov  104(%r12), %rax\n"
    "    push %rax\n"
    "    mov  96(%r12),  %rax\n"
    "    push %rax\n"
    "    mov  88(%r12),  %rax\n"
    "    push %rax\n"
    "    mov  80(%r12),  %rax\n"
    "    push %rax\n"
    "    mov  72(%r12),  %rax\n"
    "    push %rax\n"
    "    mov  64(%r12),  %rax\n"
    "    push %rax\n"
    "    mov  56(%r12),  %rax\n"
    "    push %rax\n"
    "    mov  48(%r12),  %rax\n"
    "    push %rax\n"
    "    mov  40(%r12),  %rax\n"
    "    push %rax\n"
    "    movq $1, (%r13)\n"
    "    pop  %r8\n"
    "    pop  %r9\n"
    "    pop  %r10\n"
    "    pop  %r11\n"
    "    pop  %r12\n"
    "    pop  %r13\n"
    "    pop  %r14\n"
    "    pop  %r15\n"
    "    pop  %rdi\n"
    "    pop  %rsi\n"
    "    pop  %rbp\n"
    "    pop  %rbx\n"
    "    pop  %rdx\n"
    "    pop  %rcx\n"
    "    xor  %eax, %eax\n"
    "    jmp  *%rcx\n"
    "    .size clone_raw, .-clone_raw\n"
);

/* Compile-time verification of ucontext_t gregs offsets used in assembly.
 * If any of these fire, the hardcoded offsets in clone3_raw/clone_raw
 * assembly above must be updated. */
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_R8])  == 40,  "R8 offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_R9])  == 48,  "R9 offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_R10]) == 56,  "R10 offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_R11]) == 64,  "R11 offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_R12]) == 72,  "R12 offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_R13]) == 80,  "R13 offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_R14]) == 88,  "R14 offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_R15]) == 96,  "R15 offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_RDI]) == 104, "RDI offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_RSI]) == 112, "RSI offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_RBP]) == 120, "RBP offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_RBX]) == 128, "RBX offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_RDX]) == 136, "RDX offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_RAX]) == 144, "RAX offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_RIP]) == 168, "RIP offset");

/* ================================================================
 * Raw syscall convenience wrappers.
 *
 * The SIGSYS handler MUST NOT call glibc syscall wrappers (open, read,
 * write, etc.) because they access thread-local storage via %fs for
 * errno, stack canaries, and internal state.  When the traced binary's
 * runtime (glibc, Go, etc.) sets its own FS base via arch_prctl, the
 * %fs register points to the traced binary's TLS, not sudtrace's.
 * Any %fs access from sudtrace's glibc then reads/writes the wrong
 * memory — causing silent corruption, wrong errno, or SIGSEGV.
 *
 * These thin wrappers use raw_syscall6() to bypass glibc entirely.
 * They return raw kernel results (negative errno on error).
 * ================================================================ */

static inline int raw_open(const char *path, int flags)
{
    return (int)raw_syscall6(SYS_openat, AT_FDCWD, (long)path, flags, 0, 0, 0);
}

static inline int raw_open3(const char *path, int flags, int mode)
{
    return (int)raw_syscall6(SYS_openat, AT_FDCWD, (long)path, flags, mode, 0, 0);
}

static inline ssize_t raw_read(int fd, void *buf, size_t count)
{
    return (ssize_t)raw_syscall6(SYS_read, fd, (long)buf, count, 0, 0, 0);
}

static inline ssize_t raw_write(int fd, const void *buf, size_t count)
{
    return (ssize_t)raw_syscall6(SYS_write, fd, (long)buf, count, 0, 0, 0);
}

static inline int raw_close(int fd)
{
    return (int)raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
}

static inline ssize_t raw_readlink(const char *path, char *buf, size_t bufsz)
{
    return (ssize_t)raw_syscall6(SYS_readlinkat, AT_FDCWD, (long)path,
                                  (long)buf, bufsz, 0, 0);
}

static inline int raw_fstatat(int dirfd, const char *path, struct stat *st,
                              int flags)
{
    return (int)raw_syscall6(SYS_newfstatat, dirfd, (long)path, (long)st,
                              flags, 0, 0);
}

static inline ssize_t raw_pread(int fd, void *buf, size_t count, off_t offset)
{
    return (ssize_t)raw_syscall6(SYS_pread64, fd, (long)buf, count,
                                  offset, 0, 0);
}

static inline pid_t raw_gettid(void)
{
    return (pid_t)raw_syscall6(SYS_gettid, 0, 0, 0, 0, 0, 0);
}

static inline int raw_clock_gettime(clockid_t clk, struct timespec *ts)
{
    return (int)raw_syscall6(SYS_clock_gettime, clk, (long)ts, 0, 0, 0, 0);
}

static inline int raw_sched_yield(void)
{
    return (int)raw_syscall6(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
}

static inline int raw_access(const char *path, int mode)
{
    return (int)raw_syscall6(SYS_faccessat, AT_FDCWD, (long)path, mode,
                              0, 0, 0);
}

static inline long raw_getdents64(int fd, void *buf, size_t count)
{
    return raw_syscall6(SYS_getdents64, fd, (long)buf, count, 0, 0, 0);
}

/* ================================================================
 * Signal-safe bump allocator for the execve path.
 *
 * malloc/calloc/realloc/free use TLS (thread-local arenas, tcache)
 * and internal locks that may be held by the interrupted code.
 * We use a simple bump allocator backed by a pre-allocated mmap page.
 * The arena is reset after each execve attempt (either exec succeeded
 * and the address space is replaced, or it failed and we reset).
 * ================================================================ */

#define ARENA_SIZE (256 * 1024)

static char  g_arena_buf[ARENA_SIZE]
    __attribute__((aligned(16)));
static size_t g_arena_pos = 0;

static void arena_reset(void)
{
    g_arena_pos = 0;
}

static void *arena_alloc(size_t size)
{
    size = (size + 15) & ~(size_t)15;  /* align to 16 bytes */
    if (g_arena_pos + size > ARENA_SIZE) return NULL;
    void *p = g_arena_buf + g_arena_pos;
    g_arena_pos += size;
    memset(p, 0, size);
    return p;
}

static char *arena_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *p = arena_alloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

static void arena_free(void *p)
{
    (void)p;  /* bump allocator: nothing to free */
}

/* ================================================================
 * TLS-free integer-to-string formatting.
 *
 * snprintf uses glibc internals that access %fs (stack canary,
 * locale data, errno).  These helpers format numbers directly
 * into a caller-supplied buffer without any TLS access.
 * ================================================================ */

/* Format a signed int. Returns number of chars written (not including NUL). */
static int fmt_int(char *buf, int buflen, int val)
{
    if (buflen < 2) return 0;
    char tmp[24];
    int neg = 0, pos = 0;
    unsigned int uv;
    if (val < 0) { neg = 1; uv = (unsigned int)(-(val + 1)) + 1u; }
    else uv = (unsigned int)val;
    do { tmp[pos++] = '0' + (uv % 10); uv /= 10; } while (uv);
    if (neg) tmp[pos++] = '-';
    int len = pos;
    if (len >= buflen) len = buflen - 1;
    for (int i = 0; i < len; i++) buf[i] = tmp[pos - 1 - i];
    buf[len] = '\0';
    return len;
}

/* Format a signed long. */
static int fmt_long(char *buf, int buflen, long val)
{
    if (buflen < 2) return 0;
    char tmp[24];
    int neg = 0, pos = 0;
    unsigned long uv;
    if (val < 0) { neg = 1; uv = (unsigned long)(-(val + 1)) + 1UL; }
    else uv = (unsigned long)val;
    do { tmp[pos++] = '0' + (uv % 10); uv /= 10; } while (uv);
    if (neg) tmp[pos++] = '-';
    int len = pos;
    if (len >= buflen) len = buflen - 1;
    for (int i = 0; i < len; i++) buf[i] = tmp[pos - 1 - i];
    buf[len] = '\0';
    return len;
}

/* Format an unsigned long. */
static int fmt_ulong(char *buf, int buflen, unsigned long val)
{
    if (buflen < 2) return 0;
    char tmp[24];
    int pos = 0;
    do { tmp[pos++] = '0' + (val % 10); val /= 10; } while (val);
    int len = pos;
    if (len >= buflen) len = buflen - 1;
    for (int i = 0; i < len; i++) buf[i] = tmp[pos - 1 - i];
    buf[len] = '\0';
    return len;
}

/* Format a size_t as unsigned. */
static int fmt_size(char *buf, int buflen, size_t val)
{
    return fmt_ulong(buf, buflen, (unsigned long)val);
}

/* Append a string, returning chars written. */
static int fmt_str(char *buf, int buflen, const char *s)
{
    int i = 0;
    while (s[i] && i < buflen - 1) { buf[i] = s[i]; i++; }
    buf[i] = '\0';
    return i;
}

/* Append char, returning 1 if written, 0 if full. */
static int fmt_ch(char *buf, int buflen, char c)
{
    if (buflen < 2) return 0;
    buf[0] = c;
    buf[1] = '\0';
    return 1;
}

/* Format "/proc/<pid>/<name>" into buf. */
static int fmt_proc_path(char *buf, int buflen, int pid, const char *name)
{
    int pos = 0;
    pos += fmt_str(buf + pos, buflen - pos, "/proc/");
    pos += fmt_int(buf + pos, buflen - pos, pid);
    pos += fmt_ch(buf + pos, buflen - pos, '/');
    pos += fmt_str(buf + pos, buflen - pos, name);
    return pos;
}

/* ================================================================
 * Global state
 * ================================================================ */

static int g_out_fd = -1;           /* fd for JSONL output */
static struct stat g_creator_stdout_st;
static int g_creator_stdout_valid;
static char g_self_exe[PATH_MAX];   /* path to sudtrace binary itself */
static int g_trace_exec_env = 1;

/* ================================================================
 * Low-level output — write(2) directly, bypassing stdio.
 *
 * The SIGSYS handler cannot safely use stdio (not async-signal-safe),
 * so all event emission uses raw write().  We also need to serialise
 * writes from multiple threads/processes via a simple spinlock.
 * ================================================================ */

static volatile int g_write_lock = 0;

static void emit_lock(void)
{
    while (__sync_lock_test_and_set(&g_write_lock, 1))
        raw_sched_yield();
}
static void emit_unlock(void)
{
    __sync_lock_release(&g_write_lock);
}

static void emit_raw(const char *buf, size_t len)
{
    emit_lock();
    size_t off = 0;
    while (off < len) {
        ssize_t n = raw_write(g_out_fd, buf + off, len - off);
        if (n <= 0) break;
        off += n;
    }
    emit_unlock();
}

/* ================================================================
 * Timestamp
 * ================================================================ */

static void get_timestamp_raw(struct timespec *ts)
{
    raw_clock_gettime(CLOCK_REALTIME, ts);
}

/* ================================================================
 * JSON helpers (identical to uproctrace.c / proctrace.c)
 * ================================================================ */

static int json_escape(char *dst, int dstsize, const char *src, int srclen)
{
    int si, di = 0;
    if (dstsize < 3) { if (dstsize > 0) dst[0] = '\0'; return 0; }
    dst[di++] = '"';
    for (si = 0; si < srclen && di + 7 < dstsize; si++) {
        unsigned char c = (unsigned char)src[si];
        switch (c) {
        case '"':  dst[di++] = '\\'; dst[di++] = '"'; break;
        case '\\': dst[di++] = '\\'; dst[di++] = '\\'; break;
        case '\n': dst[di++] = '\\'; dst[di++] = 'n'; break;
        case '\r': dst[di++] = '\\'; dst[di++] = 'r'; break;
        case '\t': dst[di++] = '\\'; dst[di++] = 't'; break;
        case '\b': dst[di++] = '\\'; dst[di++] = 'b'; break;
        case '\f': dst[di++] = '\\'; dst[di++] = 'f'; break;
        default:
            if (c < 0x20) {
                static const char hex[] = "0123456789abcdef";
                dst[di++] = '\\'; dst[di++] = 'u';
                dst[di++] = '0'; dst[di++] = '0';
                dst[di++] = hex[(c >> 4) & 0xf];
                dst[di++] = hex[c & 0xf];
            } else
                dst[di++] = c;
        }
    }
    dst[di++] = '"';
    dst[di] = '\0';
    return di;
}

static int json_argv_array(char *dst, int dstsize, const char *raw, int rawlen)
{
    int di = 0, si = 0;
    dst[di++] = '[';
    while (si < rawlen && di + 8 < dstsize) {
        const char *arg = raw + si;
        int arglen = 0;
        while (si + arglen < rawlen && raw[si + arglen] != '\0') arglen++;
        if (arglen == 0 && si + 1 >= rawlen) break;
        if (di > 1) dst[di++] = ',';
        di += json_escape(dst + di, dstsize - di, arg, arglen);
        si += arglen + 1;
    }
    if (di < dstsize) dst[di++] = ']';
    if (di < dstsize) dst[di] = '\0';
    return di;
}

static int json_env_object(char *dst, int dstsize, const char *raw, int rawlen)
{
    int di = 0, si = 0;
    dst[di++] = '{';
    while (si < rawlen && di + 16 < dstsize) {
        const char *entry = raw + si;
        int entlen = 0;
        while (si + entlen < rawlen && raw[si + entlen] != '\0') entlen++;
        if (entlen == 0 && si + 1 >= rawlen) break;
        const char *eq = memchr(entry, '=', entlen);
        int keylen, vallen;
        const char *val;
        if (eq) { keylen = eq - entry; val = eq + 1; vallen = entlen - keylen - 1; }
        else { keylen = entlen; val = ""; vallen = 0; }
        if (di > 1) dst[di++] = ',';
        di += json_escape(dst + di, dstsize - di, entry, keylen);
        dst[di++] = ':';
        di += json_escape(dst + di, dstsize - di, val, vallen);
        si += entlen + 1;
    }
    if (di < dstsize) dst[di++] = '}';
    if (di < dstsize) dst[di] = '\0';
    return di;
}

static int json_open_flags(int flags, char *buf, int buflen)
{
    int pos = 0, acc = flags & O_ACCMODE;
    buf[pos++] = '[';
    switch (acc) {
    case O_RDONLY: pos += fmt_str(buf + pos, buflen - pos, "\"O_RDONLY\""); break;
    case O_WRONLY: pos += fmt_str(buf + pos, buflen - pos, "\"O_WRONLY\""); break;
    case O_RDWR:  pos += fmt_str(buf + pos, buflen - pos, "\"O_RDWR\""); break;
    default:      pos += fmt_str(buf + pos, buflen - pos, "\"O_OTHER\""); break;
    }
#define F(f) if ((flags & (f)) && pos < buflen - 2) \
    pos += fmt_str(buf + pos, buflen - pos, ",\"" #f "\"")
    F(O_CREAT); F(O_EXCL); F(O_TRUNC); F(O_APPEND); F(O_NONBLOCK);
    F(O_DIRECTORY); F(O_NOFOLLOW); F(O_CLOEXEC);
#ifdef O_TMPFILE
    F(O_TMPFILE);
#endif
#undef F
    if (pos < buflen) buf[pos++] = ']';
    if (pos < buflen) buf[pos] = '\0';
    return pos;
}

/* ================================================================
 * JSON header — produces the common prefix for every event line.
 * ================================================================ */

static int json_header(char *buf, int buflen, const char *event,
                       pid_t pid, pid_t tgid, pid_t ppid,
                       struct timespec *ts)
{
    int pos = 0;
    pos += fmt_str(buf + pos, buflen - pos, "{\"event\":\"");
    pos += fmt_str(buf + pos, buflen - pos, event);
    pos += fmt_str(buf + pos, buflen - pos, "\",\"ts\":");
    pos += fmt_long(buf + pos, buflen - pos, (long)ts->tv_sec);
    pos += fmt_ch(buf + pos, buflen - pos, '.');
    /* Zero-pad nanoseconds to 9 digits */
    {
        char ns[16];
        int nlen = fmt_long(ns, sizeof(ns), ts->tv_nsec);
        for (int i = nlen; i < 9; i++)
            pos += fmt_ch(buf + pos, buflen - pos, '0');
        pos += fmt_str(buf + pos, buflen - pos, ns);
    }
    pos += fmt_str(buf + pos, buflen - pos, ",\"pid\":");
    pos += fmt_int(buf + pos, buflen - pos, (int)pid);
    pos += fmt_str(buf + pos, buflen - pos, ",\"tgid\":");
    pos += fmt_int(buf + pos, buflen - pos, (int)tgid);
    pos += fmt_str(buf + pos, buflen - pos, ",\"ppid\":");
    pos += fmt_int(buf + pos, buflen - pos, (int)ppid);
    pos += fmt_str(buf + pos, buflen - pos, ",\"nspid\":");
    pos += fmt_int(buf + pos, buflen - pos, (int)pid);
    pos += fmt_str(buf + pos, buflen - pos, ",\"nstgid\":");
    pos += fmt_int(buf + pos, buflen - pos, (int)tgid);
    return pos;
}

/* ================================================================
 * /proc helpers — all async-signal-safe (use raw open/read/close).
 * ================================================================ */

/*
 * Simple locale-independent integer parser.
 *
 * glibc's atoi/strtol/sscanf use locale data internally.  When called
 * from the SIGSYS handler in the context of a loaded binary, the
 * static glibc's locale pointers can be NULL or stale, causing
 * SIGSEGV in ____strtoll_l_internal (accessing address 0x8 via a
 * NULL locale struct pointer).
 *
 * This helper skips leading whitespace, handles optional sign, and
 * parses decimal digits directly — no locale lookup needed.
 */
static int parse_int(const char *s)
{
    if (!s) return 0;
    while (*s == ' ' || *s == '\t' || *s == '\n') s++;
    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') { s++; }
    int val = 0;
    while (*s >= '0' && *s <= '9')
        val = val * 10 + (*s++ - '0');
    return neg ? -val : val;
}

static long parse_long_octal(const char *s)
{
    if (!s) return 0;
    while (*s == ' ' || *s == '\t') s++;
    long val = 0;
    while (*s >= '0' && *s <= '7')
        val = val * 8 + (*s++ - '0');
    return val;
}

static ssize_t read_proc_raw(pid_t pid, const char *name,
                              char *buf, size_t bufsz)
{
    char path[256];
    fmt_proc_path(path, sizeof(path), (int)pid, name);
    int fd = raw_open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t total = 0, n;
    while ((size_t)total < bufsz &&
           (n = raw_read(fd, buf + total, bufsz - total)) > 0)
        total += n;
    raw_close(fd);
    if (total > 0 && (size_t)total < bufsz) buf[total] = '\0';
    return total;
}

static char *read_proc_file(pid_t pid, const char *name, size_t max,
                            size_t *out_len)
{
    char path[256];
    fmt_proc_path(path, sizeof(path), (int)pid, name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    char *buf = malloc(max + 1);
    if (!buf) { close(fd); return NULL; }
    size_t total = 0;
    ssize_t n;
    while (total < max && (n = read(fd, buf + total, max - total)) > 0)
        total += n;
    close(fd);
    if (total == 0) { free(buf); return NULL; }
    buf[total] = '\0';
    if (out_len) *out_len = total;
    return buf;
}

static char *read_proc_exe(pid_t pid, char *buf, size_t bufsz)
{
    char path[256];
    fmt_proc_path(path, sizeof(path), (int)pid, "exe");
    ssize_t n = raw_readlink(path, buf, bufsz - 1);
    if (n <= 0) return NULL;
    buf[n] = '\0';
    const char *del = " (deleted)";
    size_t dlen = strlen(del);
    if ((size_t)n > dlen && strcmp(buf + n - dlen, del) == 0)
        buf[n - dlen] = '\0';
    return buf;
}

static char *read_proc_cwd(pid_t pid, char *buf, size_t bufsz)
{
    char path[256];
    fmt_proc_path(path, sizeof(path), (int)pid, "cwd");
    ssize_t n = raw_readlink(path, buf, bufsz - 1);
    if (n <= 0) return NULL;
    buf[n] = '\0';
    return buf;
}

static pid_t get_ppid(pid_t pid)
{
    char buf[512];
    if (read_proc_raw(pid, "stat", buf, sizeof(buf) - 1) <= 0) return 0;
    char *cp = strrchr(buf, ')');
    if (!cp) return 0;
    /* Format after ')': " S ppid ..." — skip space, state char, space */
    cp += 2;  /* skip ") " */
    while (*cp && *cp != ' ') cp++;  /* skip state */
    return parse_int(cp);
}

static pid_t get_tgid(pid_t pid)
{
    char buf[2048];
    if (read_proc_raw(pid, "status", buf, sizeof(buf) - 1) <= 0) return pid;
    const char *p = strstr(buf, "\nTgid:");
    if (!p) return pid;
    return parse_int(p + 6);
}

static ssize_t read_proc_mem(pid_t pid, unsigned long addr, void *buf,
                             size_t len)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, len, (off_t)addr);
    close(fd);
    return n;
}

static int format_auxv_json(pid_t pid, char *buf, int buflen)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/auxv", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    unsigned char raw[4096];
    ssize_t n = read(fd, raw, sizeof(raw));
    close(fd);
    if (n <= 0) return 0;

    int pos = 0, first = 1;
    Elf64_auxv_t *av = (Elf64_auxv_t *)raw;
    int count = n / sizeof(Elf64_auxv_t);
    for (int i = 0; i < count; i++) {
        unsigned long type = av[i].a_type;
        unsigned long val  = av[i].a_un.a_val;
        if (type == AT_NULL) break;
        switch (type) {
        case AT_UID: case AT_EUID: case AT_GID: case AT_EGID: case AT_SECURE:
#ifdef AT_CLKTCK
        case AT_CLKTCK:
#endif
        {
            const char *nm =
                type == AT_UID   ? "AT_UID" :
                type == AT_EUID  ? "AT_EUID" :
                type == AT_GID   ? "AT_GID" :
                type == AT_EGID  ? "AT_EGID" :
                type == AT_SECURE? "AT_SECURE" : "AT_CLKTCK";
            if (!first) buf[pos++] = ',';
            pos += snprintf(buf + pos, buflen - pos, "\"%s\":%lu", nm, val);
            first = 0;
        } break;
#ifdef AT_EXECFN
        case AT_EXECFN: {
            char u[256];
            ssize_t r = read_proc_mem(pid, val, u, sizeof(u) - 1);
            if (r > 0) {
                u[r] = '\0';
                size_t slen = strlen(u);
                char e[520];
                json_escape(e, sizeof(e), u, slen);
                if (!first) buf[pos++] = ',';
                pos += snprintf(buf + pos, buflen - pos,
                                "\"AT_EXECFN\":%s", e);
                first = 0;
            }
        } break;
#endif
#ifdef AT_PLATFORM
        case AT_PLATFORM: {
            char u[64];
            ssize_t r = read_proc_mem(pid, val, u, sizeof(u) - 1);
            if (r > 0) {
                u[r] = '\0';
                size_t slen = strlen(u);
                char e[140];
                json_escape(e, sizeof(e), u, slen);
                if (!first) buf[pos++] = ',';
                pos += snprintf(buf + pos, buflen - pos,
                                "\"AT_PLATFORM\":%s", e);
                first = 0;
            }
        } break;
#endif
        default: break;
        }
        if (pos >= buflen - 1) break;
    }
    return pos;
}

/* ================================================================
 * Event emission (matching uproctrace.c format exactly)
 *
 * These are called from the SIGSYS handler (in the traced process)
 * and from the parent monitor.  They use raw write(), not stdio.
 * ================================================================ */

static void emit_cwd_event(pid_t pid)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    char cwd_buf[PATH_MAX];
    char *cwd = read_proc_cwd(pid, cwd_buf, sizeof(cwd_buf));
    if (!cwd) return;

    char cwd_esc[PATH_MAX * 2];
    json_escape(cwd_esc, sizeof(cwd_esc), cwd, strlen(cwd));

    char line[PATH_MAX * 2 + 256];
    int pos = json_header(line, sizeof(line), "CWD", pid, tgid, ppid, &ts);
    pos += fmt_str(line + pos, sizeof(line) - pos, ",\"path\":");
    pos += fmt_str(line + pos, sizeof(line) - pos, cwd_esc);
    pos += fmt_str(line + pos, sizeof(line) - pos, "}\n");
    if (pos > 0) emit_raw(line, pos);
}

static void emit_exec_event(pid_t pid)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    char exe_buf[PATH_MAX];
    char *exe = read_proc_exe(pid, exe_buf, sizeof(exe_buf));
    char exe_esc[PATH_MAX * 2];
    if (exe) json_escape(exe_esc, sizeof(exe_esc), exe, strlen(exe));

    size_t argv_len = 0;
    char *argv_raw = read_proc_file(pid, "cmdline", ARGV_MAX_READ, &argv_len);
    char *argv_j = NULL;
    if (argv_raw && argv_len > 0) {
        argv_j = malloc(argv_len * 6 + 64);
        if (argv_j)
            json_argv_array(argv_j, argv_len * 6 + 64, argv_raw, argv_len);
    }

    char *env_j = NULL;
    char *env_raw = NULL;
    if (g_trace_exec_env) {
        size_t env_len = 0;
        env_raw = read_proc_file(pid, "environ", ENV_MAX_READ, &env_len);
        if (env_raw && env_len > 0) {
            env_j = malloc(env_len * 6 + 64);
            if (env_j)
                json_env_object(env_j, env_len * 6 + 64, env_raw, env_len);
        }
    }

    char auxv_buf[4096];
    auxv_buf[0] = '\0';
    format_auxv_json(pid, auxv_buf, sizeof(auxv_buf));

    char *line = malloc(LINE_MAX_BUF);
    if (line) {
        int pos = json_header(line, LINE_MAX_BUF, "EXEC", pid, tgid, ppid,
                              &ts);
        if (g_trace_exec_env) {
            pos += snprintf(line + pos, LINE_MAX_BUF - pos,
                ",\"exe\":%s,\"argv\":%s,\"env\":%s,\"auxv\":{%s}}\n",
                exe ? exe_esc : "null",
                argv_j ? argv_j : "[]",
                env_j ? env_j : "{}",
                auxv_buf[0] ? auxv_buf : "");
        } else {
            pos += snprintf(line + pos, LINE_MAX_BUF - pos,
                ",\"exe\":%s,\"argv\":%s,\"auxv\":{%s}}\n",
                exe ? exe_esc : "null",
                argv_j ? argv_j : "[]",
                auxv_buf[0] ? auxv_buf : "");
        }
        if (pos > 0 && pos < LINE_MAX_BUF)
            emit_raw(line, pos);
        free(line);
    }

    free(env_j); free(env_raw);
    free(argv_j); free(argv_raw);
}

static void emit_inherited_open_for_fd(pid_t pid, pid_t tgid, pid_t ppid,
                                       struct timespec *ts, int fd_num)
{
    if (fd_num == g_out_fd) return;

    char link_path[256], link_target[PATH_MAX];
    {
        int lp = 0;
        lp += fmt_str(link_path + lp, sizeof(link_path) - lp, "/proc/");
        lp += fmt_int(link_path + lp, sizeof(link_path) - lp, (int)pid);
        lp += fmt_str(link_path + lp, sizeof(link_path) - lp, "/fd/");
        lp += fmt_int(link_path + lp, sizeof(link_path) - lp, fd_num);
    }
    ssize_t n = readlink(link_path, link_target, sizeof(link_target) - 1);
    if (n <= 0) return;
    link_target[n] = '\0';

    struct stat st;
    if (fstatat(AT_FDCWD, link_path, &st, 0) < 0)
        memset(&st, 0, sizeof(st));

    char fdinfo_path[256], fdinfo_buf[512];
    {
        int fp = 0;
        fp += fmt_str(fdinfo_path + fp, sizeof(fdinfo_path) - fp, "/proc/");
        fp += fmt_int(fdinfo_path + fp, sizeof(fdinfo_path) - fp, (int)pid);
        fp += fmt_str(fdinfo_path + fp, sizeof(fdinfo_path) - fp, "/fdinfo/");
        fp += fmt_int(fdinfo_path + fp, sizeof(fdinfo_path) - fp, fd_num);
    }
    int flags = O_RDONLY;
    int fi = open(fdinfo_path, O_RDONLY);
    if (fi >= 0) {
        ssize_t r = read(fi, fdinfo_buf, sizeof(fdinfo_buf) - 1);
        close(fi);
        if (r > 0) {
            fdinfo_buf[r] = '\0';
            const char *fptr = strstr(fdinfo_buf, "flags:");
            if (fptr) flags = (int)parse_long_octal(fptr + 6);
        }
    }

    char path_esc[PATH_MAX * 2];
    json_escape(path_esc, sizeof(path_esc), link_target, strlen(link_target));

    char flags_j[256];
    json_open_flags(flags, flags_j, sizeof(flags_j));

    char line[PATH_MAX * 2 + 512];
    int pos = json_header(line, sizeof(line), "OPEN", pid, tgid, ppid, ts);
    pos += fmt_str(line + pos, sizeof(line) - pos, ",\"path\":");
    pos += fmt_str(line + pos, sizeof(line) - pos, path_esc);
    pos += fmt_str(line + pos, sizeof(line) - pos, ",\"flags\":");
    pos += fmt_str(line + pos, sizeof(line) - pos, flags_j);
    pos += fmt_str(line + pos, sizeof(line) - pos, ",\"fd\":");
    pos += fmt_int(line + pos, sizeof(line) - pos, fd_num);
    pos += fmt_str(line + pos, sizeof(line) - pos, ",\"ino\":");
    pos += fmt_ulong(line + pos, sizeof(line) - pos, (unsigned long)st.st_ino);
    pos += fmt_str(line + pos, sizeof(line) - pos, ",\"dev\":\"");
    pos += fmt_ulong(line + pos, sizeof(line) - pos, major(st.st_dev));
    pos += fmt_ch(line + pos, sizeof(line) - pos, ':');
    pos += fmt_ulong(line + pos, sizeof(line) - pos, minor(st.st_dev));
    pos += fmt_str(line + pos, sizeof(line) - pos, "\",\"inherited\":true}\n");
    if (pos > 0) emit_raw(line, pos);
}

static void emit_inherited_open_events(pid_t pid)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    char dir_path[256];
    fmt_proc_path(dir_path, sizeof(dir_path), (int)pid, "fd");
    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        int fd_num = parse_int(ent->d_name);
        emit_inherited_open_for_fd(pid, tgid, ppid, &ts, fd_num);
    }
    closedir(d);
}

static void emit_open_event(pid_t pid, const char *path, int flags,
                            long fd_or_err)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    char path_esc[PATH_MAX * 2];
    if (path)
        json_escape(path_esc, sizeof(path_esc), path, strlen(path));

    char flags_j[256];
    json_open_flags(flags, flags_j, sizeof(flags_j));

    unsigned long ino_nr = 0;
    unsigned int dev_major = 0, dev_minor = 0;
    if (fd_or_err >= 0) {
        char fd_path[256];
        struct stat st;
        int fp = 0;
        fp += fmt_str(fd_path + fp, sizeof(fd_path) - fp, "/proc/");
        fp += fmt_int(fd_path + fp, sizeof(fd_path) - fp, (int)pid);
        fp += fmt_str(fd_path + fp, sizeof(fd_path) - fp, "/fd/");
        fp += fmt_long(fd_path + fp, sizeof(fd_path) - fp, fd_or_err);
        if (raw_fstatat(AT_FDCWD, fd_path, &st, 0) == 0) {
            ino_nr = st.st_ino;
            dev_major = major(st.st_dev);
            dev_minor = minor(st.st_dev);
        }
    }

    char line[PATH_MAX * 2 + 512];
    int pos = json_header(line, sizeof(line), "OPEN", pid, tgid, ppid, &ts);

    pos += fmt_str(line + pos, sizeof(line) - pos, ",\"path\":");
    pos += fmt_str(line + pos, sizeof(line) - pos, path ? path_esc : "null");
    pos += fmt_str(line + pos, sizeof(line) - pos, ",\"flags\":");
    pos += fmt_str(line + pos, sizeof(line) - pos, flags_j);

    if (fd_or_err >= 0) {
        pos += fmt_str(line + pos, sizeof(line) - pos, ",\"fd\":");
        pos += fmt_long(line + pos, sizeof(line) - pos, fd_or_err);
        pos += fmt_str(line + pos, sizeof(line) - pos, ",\"ino\":");
        pos += fmt_ulong(line + pos, sizeof(line) - pos, ino_nr);
        pos += fmt_str(line + pos, sizeof(line) - pos, ",\"dev\":\"");
        pos += fmt_ulong(line + pos, sizeof(line) - pos, dev_major);
        pos += fmt_ch(line + pos, sizeof(line) - pos, ':');
        pos += fmt_ulong(line + pos, sizeof(line) - pos, dev_minor);
        pos += fmt_str(line + pos, sizeof(line) - pos, "\"}\n");
    } else {
        pos += fmt_str(line + pos, sizeof(line) - pos, ",\"err\":");
        pos += fmt_long(line + pos, sizeof(line) - pos, fd_or_err);
        pos += fmt_str(line + pos, sizeof(line) - pos, "}\n");
    }

    if (pos > 0) emit_raw(line, pos);
}

/* Static buffers for emit_write_event — avoids malloc() which is not
 * async-signal-safe.  This function is called from the SIGSYS handler
 * while the traced program may hold malloc's internal lock (e.g. inside
 * fprintf → write).  The buffers are protected by the emit_lock() /
 * emit_unlock() spinlock that already serialises output. */
#define WRITE_ESCAPED_MAX  (WRITE_CAPTURE_MAX * 6 + 4)
#define WRITE_LINE_MAX     (WRITE_CAPTURE_MAX * 6 + 512)
static char g_write_escaped_buf[WRITE_ESCAPED_MAX];
static char g_write_line_buf[WRITE_LINE_MAX];

static void emit_write_event(pid_t pid, const char *stream,
                             const void *data_buf, size_t count)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    size_t to_read = count;
    if (to_read > WRITE_CAPTURE_MAX) to_read = WRITE_CAPTURE_MAX;

    /* Use static buffers under lock instead of malloc — the SIGSYS handler
     * cannot safely call malloc (the interrupted code may hold the heap lock). */
    emit_lock();

    json_escape(g_write_escaped_buf, WRITE_ESCAPED_MAX, data_buf, to_read);

    int pos = json_header(g_write_line_buf, WRITE_LINE_MAX, stream,
                          pid, tgid, ppid, &ts);
    pos += fmt_str(g_write_line_buf + pos, WRITE_LINE_MAX - pos, ",\"len\":");
    pos += fmt_size(g_write_line_buf + pos, WRITE_LINE_MAX - pos, to_read);
    pos += fmt_str(g_write_line_buf + pos, WRITE_LINE_MAX - pos, ",\"data\":");
    pos += fmt_str(g_write_line_buf + pos, WRITE_LINE_MAX - pos,
                   g_write_escaped_buf);
    pos += fmt_str(g_write_line_buf + pos, WRITE_LINE_MAX - pos, "}\n");

    if (pos > 0) {
        size_t off = 0;
        while (off < (size_t)pos) {
            ssize_t n = raw_write(g_out_fd, g_write_line_buf + off, pos - off);
            if (n <= 0) break;
            off += n;
        }
    }

    emit_unlock();
}

static void emit_exit_event(pid_t pid, int status)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    char line[384];
    int pos = json_header(line, sizeof(line), "EXIT", pid, tgid, ppid, &ts);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        pos += fmt_str(line + pos, sizeof(line) - pos,
            ",\"status\":\"exited\",\"code\":");
        pos += fmt_int(line + pos, sizeof(line) - pos, code);
        pos += fmt_str(line + pos, sizeof(line) - pos, ",\"raw\":");
        pos += fmt_int(line + pos, sizeof(line) - pos, status);
        pos += fmt_str(line + pos, sizeof(line) - pos, "}\n");
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        int core = 0;
#ifdef WCOREDUMP
        core = WCOREDUMP(status) ? 1 : 0;
#endif
        pos += fmt_str(line + pos, sizeof(line) - pos,
            ",\"status\":\"signaled\",\"signal\":");
        pos += fmt_int(line + pos, sizeof(line) - pos, sig);
        pos += fmt_str(line + pos, sizeof(line) - pos, ",\"core_dumped\":");
        pos += fmt_str(line + pos, sizeof(line) - pos,
            core ? "true" : "false");
        pos += fmt_str(line + pos, sizeof(line) - pos, ",\"raw\":");
        pos += fmt_int(line + pos, sizeof(line) - pos, status);
        pos += fmt_str(line + pos, sizeof(line) - pos, "}\n");
    } else {
        pos += fmt_str(line + pos, sizeof(line) - pos,
            ",\"status\":\"unknown\",\"raw\":");
        pos += fmt_int(line + pos, sizeof(line) - pos, status);
        pos += fmt_str(line + pos, sizeof(line) - pos, "}\n");
    }

    if (pos > 0) emit_raw(line, pos);
}

/* ================================================================
 * STDOUT filtering (same logic as uproctrace.c)
 * ================================================================ */

static int fd1_is_creator_stdout(pid_t pid)
{
    if (!g_creator_stdout_valid) return 0;
    char link_path[256];
    struct stat st;
    int pos = 0;
    pos += fmt_str(link_path + pos, sizeof(link_path) - pos, "/proc/");
    pos += fmt_int(link_path + pos, sizeof(link_path) - pos, (int)pid);
    pos += fmt_str(link_path + pos, sizeof(link_path) - pos, "/fd/1");
    int r = raw_fstatat(AT_FDCWD, link_path, &st, 0);
    if (r < 0) return 0;
    return (st.st_dev == g_creator_stdout_st.st_dev &&
            st.st_ino == g_creator_stdout_st.st_ino);
}

/* ================================================================
 * ELF inspection helpers
 * ================================================================ */

static int check_shebang(const char *path, char *interp, size_t interp_sz,
                         char *interp_arg, size_t arg_sz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 3) return 0;
    buf[n] = '\0';

    if (buf[0] != '#' || buf[1] != '!') return 0;

    char *nl = strchr(buf + 2, '\n');
    if (nl) *nl = '\0';

    char *p = buf + 2;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) return 0;

    char *end = p;
    while (*end && *end != ' ' && *end != '\t') end++;

    size_t ilen = end - p;
    if (ilen >= interp_sz) ilen = interp_sz - 1;
    memcpy(interp, p, ilen);
    interp[ilen] = '\0';

    if (interp_arg) {
        interp_arg[0] = '\0';
        while (*end == ' ' || *end == '\t') end++;
        if (*end) {
            size_t alen = strlen(end);
            if (alen >= arg_sz) alen = arg_sz - 1;
            memcpy(interp_arg, end, alen);
            interp_arg[alen] = '\0';
        }
    }

    return 1;
}

static int check_elf_dynamic(const char *path, char *interp, size_t interp_sz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        return -1;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        close(fd);
        return -1;
    }

    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        close(fd);
        return -1;
    }

    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (pread(fd, &phdr, sizeof(phdr),
                  ehdr.e_phoff + i * ehdr.e_phentsize) != sizeof(phdr))
            continue;

        if (phdr.p_type == PT_INTERP) {
            size_t sz = phdr.p_filesz;
            if (sz >= interp_sz) sz = interp_sz - 1;
            if (pread(fd, interp, sz, phdr.p_offset) != (ssize_t)sz) {
                close(fd);
                return -1;
            }
            interp[sz] = '\0';
            size_t len = strlen(interp);
            while (len > 0 &&
                   (interp[len-1] == '\n' || interp[len-1] == '\0'))
                len--;
            interp[len] = '\0';
            close(fd);
            return 1;
        }
    }

    close(fd);
    return 0;
}

/*
 * Signal-safe versions of check_shebang and check_elf_dynamic
 * using raw syscalls (no TLS access).
 */

static int check_shebang_raw(const char *path, char *interp, size_t interp_sz,
                              char *interp_arg, size_t arg_sz)
{
    int fd = raw_open(path, O_RDONLY);
    if (fd < 0) return 0;

    char buf[256];
    ssize_t n = raw_read(fd, buf, sizeof(buf) - 1);
    raw_close(fd);
    if (n < 3) return 0;
    buf[n] = '\0';

    if (buf[0] != '#' || buf[1] != '!') return 0;

    char *nl = strchr(buf + 2, '\n');
    if (nl) *nl = '\0';

    char *p = buf + 2;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) return 0;

    char *end = p;
    while (*end && *end != ' ' && *end != '\t') end++;

    size_t ilen = end - p;
    if (ilen >= interp_sz) ilen = interp_sz - 1;
    memcpy(interp, p, ilen);
    interp[ilen] = '\0';

    if (interp_arg) {
        interp_arg[0] = '\0';
        while (*end == ' ' || *end == '\t') end++;
        if (*end) {
            size_t alen = strlen(end);
            if (alen >= arg_sz) alen = arg_sz - 1;
            memcpy(interp_arg, end, alen);
            interp_arg[alen] = '\0';
        }
    }

    return 1;
}

static int check_elf_dynamic_raw(const char *path, char *interp,
                                  size_t interp_sz)
{
    int fd = raw_open(path, O_RDONLY);
    if (fd < 0) return -1;

    Elf64_Ehdr ehdr;
    if (raw_read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        raw_close(fd);
        return -1;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        raw_close(fd);
        return -1;
    }

    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        raw_close(fd);
        return -1;
    }

    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (raw_pread(fd, &phdr, sizeof(phdr),
                      ehdr.e_phoff + i * ehdr.e_phentsize) != sizeof(phdr))
            continue;

        if (phdr.p_type == PT_INTERP) {
            size_t sz = phdr.p_filesz;
            if (sz >= interp_sz) sz = interp_sz - 1;
            if (raw_pread(fd, interp, sz, phdr.p_offset) != (ssize_t)sz) {
                raw_close(fd);
                return -1;
            }
            interp[sz] = '\0';
            size_t len = strlen(interp);
            while (len > 0 &&
                   (interp[len-1] == '\n' || interp[len-1] == '\0'))
                len--;
            interp[len] = '\0';
            raw_close(fd);
            return 1;
        }
    }

    raw_close(fd);
    return 0;
}
static int resolve_path_raw(const char *cmd, char *out, size_t out_sz)
{
    if (cmd[0] == '/' || cmd[0] == '.') {
        /* Copy the path directly — no realpath resolution */
        size_t clen = strlen(cmd);
        if (clen >= out_sz) clen = out_sz - 1;
        memcpy(out, cmd, clen);
        out[clen] = '\0';
        return (raw_access(out, X_OK) == 0);
    }

    const char *path_env = getenv("PATH");
    if (!path_env) path_env = "/usr/bin:/bin";

    /* Walk PATH directories manually (strtok_r is safe but we avoid
     * snprintf; use manual string concat instead) */
    const char *p = path_env;
    while (*p) {
        const char *colon = p;
        while (*colon && *colon != ':') colon++;
        size_t dlen = colon - p;
        size_t clen = strlen(cmd);
        if (dlen + 1 + clen + 1 <= out_sz) {
            memcpy(out, p, dlen);
            out[dlen] = '/';
            memcpy(out + dlen + 1, cmd, clen);
            out[dlen + 1 + clen] = '\0';
            if (raw_access(out, X_OK) == 0)
                return 1;
        }
        p = *colon ? colon + 1 : colon;
    }

    return 0;
}

/*
 * Original resolve_path using glibc — for use in the parent process
 * (normal mode startup) where TLS is valid.
 */
static int resolve_path(const char *cmd, char *out, size_t out_sz)
{
    if (cmd[0] == '/' || cmd[0] == '.') {
        if (realpath(cmd, out) != NULL)
            return 1;
        snprintf(out, out_sz, "%s", cmd);
        return (access(out, X_OK) == 0);
    }

    const char *path_env = getenv("PATH");
    if (!path_env) path_env = "/usr/bin:/bin";

    char path_copy[4096];
    snprintf(path_copy, sizeof(path_copy), "%s", path_env);

    char *saveptr;
    for (char *dir = strtok_r(path_copy, ":", &saveptr);
         dir; dir = strtok_r(NULL, ":", &saveptr)) {
        snprintf(out, out_sz, "%s/%s", dir, cmd);
        if (access(out, X_OK) == 0)
            return 1;
    }

    return 0;
}

/*
 * Build the argv for exec.  The algorithm:
 *
 * 1. Resolve the target command to a full path
 * 2. If it starts with #!, prepend the interpreter to argv and restart
 * 3. If it is a dynamically linked ELF, prepend PT_INTERP to argv
 * 4. If it is a statically linked ELF, prepend sudtrace itself to argv
 *
 * Final result: e.g. sudtrace /lib/ld-linux-x86-64.so.2 /bin/sh script.sh
 */
static char **build_exec_argv(int orig_argc, char **orig_argv)
{
    int max_args = orig_argc + 9;
    char **args = calloc(max_args + 1, sizeof(char *));
    if (!args) return NULL;

    int nargs = 0;
    for (int i = 0; i < orig_argc; i++)
        args[nargs++] = strdup(orig_argv[i]);
    args[nargs] = NULL;

    for (int depth = 0; depth < 16; depth++) {
        char resolved[PATH_MAX];
        if (!resolve_path(args[0], resolved, sizeof(resolved))) {
            fprintf(stderr, "sudtrace: cannot find '%s'\n", args[0]);
            return args;
        }

        free(args[0]);
        args[0] = strdup(resolved);

        char interp[PATH_MAX], interp_arg[256];
        if (check_shebang(resolved, interp, sizeof(interp),
                          interp_arg, sizeof(interp_arg))) {
            int extra = interp_arg[0] ? 2 : 1;
            if (nargs + extra >= max_args) {
                max_args = nargs + extra + 8;
                args = realloc(args, (max_args + 1) * sizeof(char *));
            }
            memmove(args + extra, args, (nargs + 1) * sizeof(char *));
            args[0] = strdup(interp);
            if (interp_arg[0])
                args[1] = strdup(interp_arg);
            nargs += extra;
            continue;
        }

        char elf_interp[PATH_MAX];
        int dyn = check_elf_dynamic(resolved, elf_interp, sizeof(elf_interp));

        if (dyn == 1) {
            if (nargs + 1 >= max_args) {
                max_args = nargs + 8;
                args = realloc(args, (max_args + 1) * sizeof(char *));
            }
            memmove(args + 1, args, (nargs + 1) * sizeof(char *));
            args[0] = strdup(elf_interp);
            nargs++;
            continue;
        }

        if (dyn == 0) {
            if (nargs + 1 >= max_args) {
                max_args = nargs + 8;
                args = realloc(args, (max_args + 1) * sizeof(char *));
            }
            memmove(args + 1, args, (nargs + 1) * sizeof(char *));
            args[0] = strdup(g_self_exe);
            nargs++;
            if (!g_trace_exec_env) {
                if (nargs + 1 >= max_args) {
                    max_args = nargs + 8;
                    char **new_args = realloc(args, (max_args + 1) * sizeof(char *));
                    if (!new_args) return NULL;
                    args = new_args;
                }
                memmove(args + 2, args + 1, nargs * sizeof(char *));
                args[1] = strdup("--no-env");
                nargs++;
            }
            break;
        }

        break;
    }

    return args;
}

static void free_exec_argv(char **args)
{
    if (!args) return;
    for (int i = 0; args[i]; i++)
        free(args[i]);
    free(args);
}

/*
 * Signal-safe version of build_exec_argv using the arena allocator
 * and raw syscalls.  Called from the SIGSYS handler's execve path.
 * All allocations go to the arena; call arena_reset() when done.
 */
static char **build_exec_argv_raw(int orig_argc, char **orig_argv)
{
    int max_args = orig_argc + 17;
    char **args = arena_alloc((max_args + 1) * sizeof(char *));
    if (!args) return NULL;

    int nargs = 0;
    for (int i = 0; i < orig_argc; i++)
        args[nargs++] = arena_strdup(orig_argv[i]);
    args[nargs] = NULL;

    for (int depth = 0; depth < 16; depth++) {
        char resolved[PATH_MAX];
        if (!resolve_path_raw(args[0], resolved, sizeof(resolved)))
            return args;

        args[0] = arena_strdup(resolved);

        char interp[PATH_MAX], interp_arg[256];
        if (check_shebang_raw(resolved, interp, sizeof(interp),
                               interp_arg, sizeof(interp_arg))) {
            int extra = interp_arg[0] ? 2 : 1;
            if (nargs + extra >= max_args) {
                /* Need more space: allocate new array in arena */
                max_args = nargs + extra + 8;
                char **new_args = arena_alloc((max_args + 1) * sizeof(char *));
                if (!new_args) return args;
                memcpy(new_args, args, (nargs + 1) * sizeof(char *));
                args = new_args;
            }
            memmove(args + extra, args, (nargs + 1) * sizeof(char *));
            args[0] = arena_strdup(interp);
            if (interp_arg[0])
                args[1] = arena_strdup(interp_arg);
            nargs += extra;
            continue;
        }

        char elf_interp[PATH_MAX];
        int dyn = check_elf_dynamic_raw(resolved, elf_interp,
                                         sizeof(elf_interp));

        if (dyn == 1) {
            if (nargs + 1 >= max_args) {
                max_args = nargs + 8;
                char **new_args = arena_alloc((max_args + 1) * sizeof(char *));
                if (!new_args) return args;
                memcpy(new_args, args, (nargs + 1) * sizeof(char *));
                args = new_args;
            }
            memmove(args + 1, args, (nargs + 1) * sizeof(char *));
            args[0] = arena_strdup(elf_interp);
            nargs++;
            continue;
        }

        if (dyn == 0) {
            if (nargs + 1 >= max_args) {
                max_args = nargs + 8;
                char **new_args = arena_alloc((max_args + 1) * sizeof(char *));
                if (!new_args) return args;
                memcpy(new_args, args, (nargs + 1) * sizeof(char *));
                args = new_args;
            }
            memmove(args + 1, args, (nargs + 1) * sizeof(char *));
            args[0] = arena_strdup(g_self_exe);
            nargs++;
            if (!g_trace_exec_env) {
                if (nargs + 1 >= max_args) {
                    max_args = nargs + 8;
                    char **new_args = arena_alloc((max_args + 1) * sizeof(char *));
                    if (!new_args) return NULL;
                    memcpy(new_args, args, (nargs + 1) * sizeof(char *));
                    args = new_args;
                }
                memmove(args + 2, args + 1, nargs * sizeof(char *));
                args[1] = arena_strdup("--no-env");
                nargs++;
            }
            break;
        }

        break;
    }

    return args;
}

/* ================================================================
 * SIGSYS handler — the core of SUD tracing.
 *
 * When a process with SUD enabled makes a syscall and the instruction
 * pointer is outside [__sud_begin, __sud_end), the kernel delivers
 * SIGSYS.  This handler:
 *   1. Reads the syscall number and arguments from the ucontext
 *   2. Performs the real syscall (with selector = ALLOW)
 *   3. Logs the relevant trace event
 *   4. Stores the return value back in the ucontext
 *
 * Since the handler runs in the traced process itself, we have direct
 * access to its memory (no ptrace or /proc/mem needed for pointers).
 * ================================================================ */

static void sigsys_handler(int sig, siginfo_t *info, void *uctx_raw)
{
    ucontext_t *uc = (ucontext_t *)uctx_raw;
    (void)sig;
    (void)info;

    /* No selector toggling needed: all syscalls made from within
     * sudtrace's code are in the allowed IP range [__sud_begin,
     * __sud_end) and pass the kernel's SUD check regardless of the
     * selector byte value.  This is critical for multi-threaded
     * programs — a shared selector byte with toggling would race
     * between concurrent SIGSYS handlers on different threads. */

    pid_t tid = raw_gettid();

    /* x86_64 ABI: nr=rax, args=rdi,rsi,rdx,r10,r8,r9, ret→rax */
    long nr  = (long)uc->uc_mcontext.gregs[REG_RAX];
    long a0  = (long)uc->uc_mcontext.gregs[REG_RDI];
    long a1  = (long)uc->uc_mcontext.gregs[REG_RSI];
    long a2  = (long)uc->uc_mcontext.gregs[REG_RDX];
    long a3  = (long)uc->uc_mcontext.gregs[REG_R10];
    long a4  = (long)uc->uc_mcontext.gregs[REG_R8];
    long a5  = (long)uc->uc_mcontext.gregs[REG_R9];

    long ret;

    /*
     * ptrace(PTRACE_TRACEME) — a child process wants a ptrace-based
     * tracer (e.g. nested uproctrace, fakeroot-ng) to trace it.
     *
     * Execute the real ptrace call, then disable SUD for this process.
     * Rationale: ptrace and SUD both intercept syscalls.  If both are
     * active, ptrace sees the SIGSYS handler's internal syscalls instead
     * of the original ones, which confuses the sub-tracer.  Disabling
     * SUD lets the sub-tracer get clean syscall visibility while
     * sudtrace's parent still monitors this process via waitpid()
     * for EXEC/EXIT events.
     */
    if (nr == SYS_ptrace && a0 == 0 /* PTRACE_TRACEME */) {
        long r = raw_syscall6(SYS_ptrace, 0 /* PTRACE_TRACEME */,
                              0, 0, 0, 0, 0);
        if (r == 0) {
            /* Disable SUD: the sub-tracer now manages this process. */
            raw_syscall6(SYS_prctl, PR_SET_SYSCALL_USER_DISPATCH,
                         PR_SYS_DISPATCH_OFF, 0, 0, 0, 0);
            uc->uc_mcontext.gregs[REG_RAX] = 0;
            return;
        }
        uc->uc_mcontext.gregs[REG_RAX] = r;  /* raw kernel negative errno */
        return;
    }

    /*
     * Special handling for execve: rewrite argv to go through sudtrace.
     */
    if (nr == SYS_execve) {
        const char *fn = (const char *)a0;
        char **orig_argv = (char **)a1;
        int orig_argc = 0;
        if (orig_argv)
            while (orig_argv[orig_argc]) orig_argc++;

        arena_reset();

        int build_argc = orig_argc > 0 ? orig_argc : 1;
        char **build_argv = arena_alloc((build_argc + 1) * sizeof(char *));
        if (build_argv) {
            build_argv[0] = arena_strdup(fn);
            for (int i = 1; i < orig_argc; i++)
                build_argv[i] = arena_strdup(orig_argv[i]);
            build_argv[build_argc] = NULL;

            char **new_argv = build_exec_argv_raw(build_argc, build_argv);

            if (new_argv) {
                ret = raw_syscall6(SYS_execve, (long)new_argv[0],
                                   (long)new_argv, a2, 0, 0, 0);
                /* If exec succeeded, we never reach here.
                 * If it failed, arena will be reset on next execve. */
            } else {
                ret = -ENOMEM;
            }
        } else {
            ret = -ENOMEM;
        }

        arena_reset();
        uc->uc_mcontext.gregs[REG_RAX] = ret;
        return;
    }

#ifdef SYS_execveat
    if (nr == SYS_execveat) {
        ret = raw_syscall6(SYS_execveat, a0, a1, a2, a3, a4, 0);
        uc->uc_mcontext.gregs[REG_RAX] = ret;
        return;
    }
#endif

    /*
     * clone3/clone — thread/process creation needs special handling.
     *
     * Two cases:
     *
     * A) CLONE_VM with a separate child stack (pthread/clone3 spawn):
     *    The child starts executing inside this handler on a NEW stack.
     *    The compiler's RSP-relative code for local variables (including
     *    `uc`) references wrong addresses on the new stack → SIGSEGV.
     *    Use dedicated assembly (clone3_raw/clone_raw) that saves the uc
     *    pointer in r12, and in the child restores the full program
     *    register state from the ucontext and jumps directly to the
     *    program's saved RIP.  The child never returns to C code here.
     *
     * B) Anything else (fork/vfork without a reusable post-syscall state):
     *    The child can return through the handler normally via
     *    rt_sigreturn, or for clone3 vfork-style spawns we can force
     *    glibc's vfork fallback by reporting ENOSYS.
     */
#ifndef CLONE_VM
#define CLONE_VM 0x00000100
#endif
#ifndef CLONE_VFORK
#define CLONE_VFORK 0x00004000
#endif
#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000
#endif
#ifdef SYS_clone3
    if (nr == SYS_clone3) {
        /* clone3: flags are at offset 0, stack at CLONE_ARGS_STACK_OFFSET */
        unsigned long long c3_flags = 0;
        unsigned long long c3_stack = 0;
        if (a0) {
            c3_flags = *(unsigned long long *)a0;
            c3_stack =
                *(unsigned long long *)((char *)a0 + CLONE_ARGS_STACK_OFFSET);
        }
        if ((c3_flags & (CLONE_VM | CLONE_THREAD)) ==
            (CLONE_VM | CLONE_THREAD) && c3_stack) {
            ret = clone3_raw(a0, a1, uc);
            /* Only parent reaches here; child jumped to program's RIP */
        } else if (c3_flags & CLONE_VFORK) {
            /* glibc falls back to vfork/clone when clone3 reports ENOSYS */
            ret = -ENOSYS;
        } else {
            ret = raw_syscall6(nr, a0, a1, a2, a3, a4, a5);
            /* Both parent and child reach here */
        }
        uc->uc_mcontext.gregs[REG_RAX] = ret;
        return;
    }
#endif
    if (nr == SYS_clone) {
        /* clone: flags are in a0 (rdi) */
        unsigned long c_flags = (unsigned long)a0;
        if ((c_flags & CLONE_VM) && a1 != 0) {
            ret = clone_raw(a0, a1, a2, a3, a4, uc);
            /* Only parent reaches here */
        } else {
            ret = raw_syscall6(nr, a0, a1, a2, a3, a4, a5);
            /* Both parent and child reach here */
        }
        uc->uc_mcontext.gregs[REG_RAX] = ret;
        return;
    }

#ifdef SYS_rt_sigaction
    if (nr == SYS_rt_sigaction) {
        struct kernel_sigaction {
            void (*handler)(int);
            unsigned long flags;
            void (*restorer)(void);
            unsigned long mask;
        };
        const struct kernel_sigaction *act =
            (const struct kernel_sigaction *)a1;
        if (act) {
            struct kernel_sigaction patched = *act;
            patched.flags |= SA_RESTORER;
            patched.restorer = sud_rt_sigreturn_restorer;
            ret = raw_syscall6(nr, a0, (long)&patched, a2, a3, a4, a5);
        } else {
            ret = raw_syscall6(nr, a0, a1, a2, a3, a4, a5);
        }
        uc->uc_mcontext.gregs[REG_RAX] = ret;
        return;
    }
#endif

    /* Execute the real syscall using raw inline assembly.
     *
     * We must NOT use the C library's syscall() wrapper here because it
     * returns -1 on error (setting errno).  The traced program expects the
     * raw kernel return value in RAX (e.g. -ENOSYS, -EPERM).  Using the
     * wrapper would map every error to -1, which breaks glibc internals
     * in the traced program (e.g. clone3→clone fallback in pthread_create). */
    ret = raw_syscall6(nr, a0, a1, a2, a3, a4, a5);

    /* Post-syscall tracing */

#ifdef SYS_openat
    if (nr == SYS_openat) {
        const char *path = (const char *)a1;
        emit_open_event(tid, path, (int)a2, ret);
    }
#endif
#ifdef SYS_open
    if (nr == SYS_open) {
        const char *path = (const char *)a0;
        emit_open_event(tid, path, (int)a1, ret);
    }
#endif

    if (nr == SYS_chdir || nr == SYS_fchdir) {
        if (ret == 0)
            emit_cwd_event(tid);
    }

    if (nr == SYS_write) {
        unsigned int fd = (unsigned int)a0;
        if (ret > 0) {
            if (fd == 2) {
                emit_write_event(tid, "STDERR", (const void *)a1,
                                 (size_t)ret);
            } else if (fd == 1 && fd1_is_creator_stdout(tid)) {
                emit_write_event(tid, "STDOUT", (const void *)a1,
                                 (size_t)ret);
            }
        }
    }

    uc->uc_mcontext.gregs[REG_RAX] = ret;
}

/* ================================================================
 * ELF loader — load a statically linked ELF and jump to it.
 *
 * Called in wrapper mode (child process after fork).  Steps:
 * 1. Parse ELF program headers
 * 2. mmap each PT_LOAD segment at the specified vaddr
 * 3. Allocate a new stack near our high address
 * 4. Set up argv/envp/auxv on the new stack
 * 5. Install SIGSYS handler and enable SUD
 * 6. Jump to the entry point
 * ================================================================ */

static void load_and_run_elf(const char *path, int argc, char **argv)
    __attribute__((noreturn));

static void load_and_run_elf(const char *path, int argc, char **argv)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("sudtrace: open ELF");
        _exit(127);
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        fprintf(stderr, "sudtrace: cannot read ELF header\n");
        close(fd);
        _exit(127);
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "sudtrace: not a valid 64-bit ELF: %s\n", path);
        close(fd);
        _exit(127);
    }

    /* For PIE/ET_DYN binaries (e.g. ld.so), p_vaddr starts at 0.
     * We need to pick a base address because mmap(0, ..., MAP_FIXED) fails
     * due to vm.mmap_min_addr.  For ET_EXEC, base stays 0 (use as-is). */
    unsigned long load_base = 0;
    if (ehdr.e_type == ET_DYN) {
        /* Find total memory span of all PT_LOAD segments */
        unsigned long lo = ~0UL, hi = 0;
        for (int i = 0; i < ehdr.e_phnum; i++) {
            Elf64_Phdr phdr;
            if (pread(fd, &phdr, sizeof(phdr),
                      ehdr.e_phoff + i * ehdr.e_phentsize) != sizeof(phdr))
                continue;
            if (phdr.p_type != PT_LOAD) continue;
            unsigned long seg_lo = phdr.p_vaddr & ~0xfffUL;
            unsigned long seg_hi = (phdr.p_vaddr + phdr.p_memsz + 0xfff)
                                    & ~0xfffUL;
            if (seg_lo < lo) lo = seg_lo;
            if (seg_hi > hi) hi = seg_hi;
        }
        if (hi > lo) {
            /* Ask kernel for a suitable address range */
            void *hint = mmap(NULL, hi - lo, PROT_NONE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (hint == MAP_FAILED) {
                fprintf(stderr, "sudtrace: cannot reserve %lu bytes for PIE\n",
                        hi - lo);
                close(fd);
                _exit(127);
            }
            load_base = (unsigned long)hint - lo;
            munmap(hint, hi - lo);
        }
    }

    /* Load PT_LOAD segments */
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (pread(fd, &phdr, sizeof(phdr),
                  ehdr.e_phoff + i * ehdr.e_phentsize) != sizeof(phdr))
            continue;

        if (phdr.p_type != PT_LOAD) continue;

        unsigned long vaddr = load_base + phdr.p_vaddr;
        unsigned long page_offset = vaddr & 0xfff;
        unsigned long map_addr = vaddr - page_offset;
        unsigned long map_size = phdr.p_memsz + page_offset;
        map_size = (map_size + 0xfff) & ~0xfffUL;

        int prot = 0;
        if (phdr.p_flags & PF_R) prot |= PROT_READ;
        if (phdr.p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr.p_flags & PF_X) prot |= PROT_EXEC;

        void *mapped = mmap((void *)map_addr, map_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                           -1, 0);
        if (mapped == MAP_FAILED) {
            fprintf(stderr, "sudtrace: mmap segment at %#lx: %s\n",
                    map_addr, strerror(errno));
            close(fd);
            _exit(127);
        }

        if (phdr.p_filesz > 0) {
            if (pread(fd, (char *)mapped + page_offset, phdr.p_filesz,
                      phdr.p_offset) != (ssize_t)phdr.p_filesz) {
                fprintf(stderr, "sudtrace: failed to read segment\n");
                close(fd);
                _exit(127);
            }
        }

        mprotect(mapped, map_size, prot);
    }

    /* Install SIGSYS handler.
     *
     * We deliberately do NOT use SA_ONSTACK.  The handler runs on the
     * calling thread's own stack instead.  This is critical for multi-
     * threaded programs: sigaltstack is per-thread, and new threads
     * created by the traced binary won't have one set up.  Using
     * SA_ONSTACK would crash those threads with SIGSEGV when SIGSYS
     * is delivered.  All thread stacks (main + pthread-created) are
     * large enough (≥ 2 MB) for the handler's needs. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL) < 0) {
        perror("sudtrace: sigaction(SIGSYS)");
        _exit(127);
    }

    /* Allocate the SUD selector byte in a dedicated mmap page.
     * This survives the loaded binary's glibc TLS re-initialization,
     * which would otherwise move __thread storage to a new address
     * and leave the kernel's stored selector pointer dangling.
     *
     * The selector stays at BLOCK permanently.  The handler never
     * toggles it — sudtrace's own syscalls pass because their IP
     * is in the allowed range, not because of the selector value.
     * This eliminates races between threads sharing the selector. */
    void *sel_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (sel_page == MAP_FAILED) {
        perror("sudtrace: mmap selector");
        _exit(127);
    }
    volatile unsigned char *sel = (volatile unsigned char *)sel_page;
    *sel = SYSCALL_DISPATCH_FILTER_BLOCK;
    g_sud_selector_ptr = sel;

    /* Enable SUD */
    unsigned long off = (unsigned long)__sud_begin;
    unsigned long len = (unsigned long)__sud_end - (unsigned long)__sud_begin;

    if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON,
              off, len, (unsigned long)sel) < 0) {
        perror("sudtrace: prctl(PR_SET_SYSCALL_USER_DISPATCH)");
        fprintf(stderr, "  Requires CONFIG_SYSCALL_USER_DISPATCH=y "
                "(Linux 5.11+).\n");
        _exit(127);
    }

    /* Build the new stack */
    size_t stack_size = 8 * 1024 * 1024;
    void *stack_base = mmap(NULL, stack_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                           -1, 0);
    if (stack_base == MAP_FAILED) {
        perror("sudtrace: mmap stack");
        _exit(127);
    }

    unsigned long *sp = (unsigned long *)((char *)stack_base + stack_size);

    extern char **environ;
    int envc = 0;
    if (environ)
        while (environ[envc]) envc++;

    int total_slots = 1 + argc + 1 + envc + 1 + 128;
    sp -= total_slots;
    sp = (unsigned long *)((unsigned long)sp & ~0xfUL);

    int idx = 0;
    sp[idx++] = argc;
    for (int i = 0; i < argc; i++)
        sp[idx++] = (unsigned long)argv[i];
    sp[idx++] = 0;
    for (int i = 0; i < envc; i++)
        sp[idx++] = (unsigned long)environ[i];
    sp[idx++] = 0;

    /* Copy auxv, patching relevant entries for the loaded ELF.
     * ld.so needs AT_PHDR pointing at its own program headers in memory,
     * and AT_BASE = 0 (it IS the interpreter, there is no separate one). */
    {
        /* Find where phdr table sits in memory */
        unsigned long phdr_addr = 0;
        for (int i = 0; i < ehdr.e_phnum; i++) {
            Elf64_Phdr phdr;
            if (pread(fd, &phdr, sizeof(phdr),
                      ehdr.e_phoff + i * ehdr.e_phentsize) != sizeof(phdr))
                continue;
            if (phdr.p_type == PT_PHDR) {
                phdr_addr = load_base + phdr.p_vaddr;
                break;
            }
        }
        /* Fallback: assume phdr table is at file offset e_phoff within
         * the first PT_LOAD segment */
        if (!phdr_addr) {
            for (int i = 0; i < ehdr.e_phnum; i++) {
                Elf64_Phdr phdr;
                if (pread(fd, &phdr, sizeof(phdr),
                          ehdr.e_phoff + i * ehdr.e_phentsize) != sizeof(phdr))
                    continue;
                if (phdr.p_type == PT_LOAD &&
                    ehdr.e_phoff >= phdr.p_offset &&
                    ehdr.e_phoff < phdr.p_offset + phdr.p_filesz) {
                    phdr_addr = load_base + phdr.p_vaddr +
                                (ehdr.e_phoff - phdr.p_offset);
                    break;
                }
            }
        }
        /* Last resort: compute from vaddr of first LOAD + e_phoff */
        if (!phdr_addr)
            phdr_addr = load_base + ehdr.e_phoff;

        int aux_fd2 = open("/proc/self/auxv", O_RDONLY);
        if (aux_fd2 >= 0) {
            Elf64_auxv_t avbuf[64];
            ssize_t n = read(aux_fd2, avbuf, sizeof(avbuf));
            close(aux_fd2);
            if (n > 0) {
                int auxc = n / sizeof(Elf64_auxv_t);
                for (int i = 0; i < auxc; i++) {
                    switch (avbuf[i].a_type) {
                    case AT_ENTRY:
                        avbuf[i].a_un.a_val = load_base + ehdr.e_entry;
                        break;
                    case AT_PHDR:
                        avbuf[i].a_un.a_val = phdr_addr;
                        break;
                    case AT_PHNUM:
                        avbuf[i].a_un.a_val = ehdr.e_phnum;
                        break;
                    case AT_PHENT:
                        avbuf[i].a_un.a_val = ehdr.e_phentsize;
                        break;
                    case AT_BASE:
                        avbuf[i].a_un.a_val = 0;
                        break;
                    }

                    sp[idx++] = avbuf[i].a_type;
                    sp[idx++] = avbuf[i].a_un.a_val;

                    if (avbuf[i].a_type == AT_NULL) break;
                }
            }
        }
    }

    close(fd);

    /* Jump to the entry point (adjusted for PIE load base) */
    unsigned long entry = load_base + ehdr.e_entry;

    /*
     * Jump to the loaded ELF's entry point with a clean register state.
     *
     * We must zero all general-purpose registers before entering the loaded
     * binary (the ABI requires an unspecified initial state except rsp).
     * However, the compiler may place the 'entry' value in any register
     * (including callee-saved r12–r15 or rbx).  If we zero that register
     * before using it, we jump to address 0 → SIGSEGV.
     *
     * Fix: set rsp first, push the entry address onto the new stack,
     * zero all registers, then 'ret' pops the entry address into rip.
     */
    __asm__ volatile(
        "mov %0, %%rsp\n\t"       /* switch to the new stack */
        "push %1\n\t"             /* save entry address on stack */
        "xor %%rax, %%rax\n\t"
        "xor %%rbx, %%rbx\n\t"
        "xor %%rcx, %%rcx\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rsi, %%rsi\n\t"
        "xor %%rdi, %%rdi\n\t"
        "xor %%rbp, %%rbp\n\t"
        "xor %%r8, %%r8\n\t"
        "xor %%r9, %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11\n\t"
        "xor %%r12, %%r12\n\t"
        "xor %%r13, %%r13\n\t"
        "xor %%r14, %%r14\n\t"
        "xor %%r15, %%r15\n\t"
        "ret\n\t"                  /* pop entry address → rip */
        :
        : "r"(sp), "r"(entry)
        : "memory"
    );

    __builtin_unreachable();
}

/* ================================================================
 * Wrapper mode
 * ================================================================ */

static int is_wrapper_mode(int argc, char **argv)
{
    if (argc < 2) return 0;
    /* Wrapper mode: sudtrace was re-invoked to SUD-trace a specific
     * binary, e.g.  sudtrace /path/to/binary [args...]
     *
     * Normal mode always has a leading flag (e.g. -o) or "--" before
     * the command.  Wrapper mode has a plain path as argv[1].
     *
     * We must NOT scan the rest of argv for "--" because that "--"
     * may belong to the wrapped command (e.g.
     *   sudtrace tv --uproctrace -o x -- /bin/echo hello
     * where "--" separates uproctrace's options from its command). */
    int i = 1;
    if (i < argc && argv[i] && strcmp(argv[i], "--no-env") == 0)
        i++;
    if (i >= argc || !argv[i] || argv[i][0] == '-') return 0;
    return 1;
}

static int run_wrapper_mode(int argc, char **argv)
{
    int argi = 1;
    if (argi < argc && argv[argi] && strcmp(argv[argi], "--no-env") == 0) {
        argi++;
        g_trace_exec_env = 0;
    }
    char resolved[PATH_MAX];
    if (!resolve_path(argv[argi], resolved, sizeof(resolved))) {
        fprintf(stderr, "sudtrace: cannot find '%s'\n", argv[argi]);
        return 127;
    }

    pid_t child = fork();
    if (child < 0) { perror("sudtrace: fork"); return 127; }

    if (child == 0) {
        load_and_run_elf(resolved, argc - argi, argv + argi);
    }

    /* Parent: emit initial events, then monitor */
    usleep(50000);

    emit_cwd_event(child);
    emit_exec_event(child);
    emit_inherited_open_events(child);

    for (;;) {
        int wstatus;
        pid_t wpid = waitpid(-1, &wstatus, __WALL);
        if (wpid < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            pid_t tgid = get_tgid(wpid);
            if (wpid == tgid || wpid == child)
                emit_exit_event(wpid, wstatus);

            if (wpid == child) break;
        }
    }

    return 0;
}

/* ================================================================
 * Usage / help
 * ================================================================ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-o FILE] [--no-env] -- command [args...]\n"
        "\n"
        "Syscall User Dispatch (SUD) based process tracer.\n"
        "Produces JSONL event stream compatible with proctrace/uproctrace.\n",
        prog);
    exit(1);
}

/* ================================================================
 * Main entry point
 * ================================================================ */

int main(int argc, char **argv)
{
    /* Resolve our own path for re-exec */
    ssize_t slen = readlink("/proc/self/exe", g_self_exe,
                            sizeof(g_self_exe) - 1);
    if (slen > 0)
        g_self_exe[slen] = '\0';
    else
        snprintf(g_self_exe, sizeof(g_self_exe), "%s", argv[0]);

    /* Wrapper mode? (re-invoked for a static binary) */
    if (is_wrapper_mode(argc, argv)) {
        if (g_out_fd < 0)
            g_out_fd = STDOUT_FILENO;

        struct stat st;
        if (fstat(SUD_OUTPUT_FD, &st) == 0)
            g_out_fd = SUD_OUTPUT_FD;

        g_creator_stdout_valid =
            (fstat(STDOUT_FILENO, &g_creator_stdout_st) == 0);
        return run_wrapper_mode(argc, argv);
    }

    /* Normal mode: parse options */
    const char *outfile = NULL;
    int cmd_start = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd_start = i + 1;
            break;
        }
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outfile = argv[++i];
        } else if (strcmp(argv[i], "--no-env") == 0) {
            g_trace_exec_env = 0;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        } else {
            cmd_start = i;
            break;
        }
    }

    if (cmd_start < 0 || cmd_start >= argc)
        usage(argv[0]);

    /* Setup output */
    if (outfile) {
        int ofd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (ofd < 0) { perror("sudtrace: open output"); exit(1); }
        g_out_fd = ofd;
    } else {
        g_out_fd = STDOUT_FILENO;
    }

    /* Move output to a high fd so children don't clobber it */
    {
        int high_fd = dup2(g_out_fd, SUD_OUTPUT_FD);
        if (high_fd >= 0) {
            if (g_out_fd != STDOUT_FILENO && g_out_fd != STDERR_FILENO)
                close(g_out_fd);
            g_out_fd = high_fd;
            /* NOT FD_CLOEXEC: wrapper child inherits the fd */
        }
    }

    g_creator_stdout_valid =
        (fstat(STDOUT_FILENO, &g_creator_stdout_st) == 0);

    /* Build exec argv */
    int cmd_argc = argc - cmd_start;
    char **exec_argv = build_exec_argv(cmd_argc, argv + cmd_start);
    if (!exec_argv) {
        fprintf(stderr, "sudtrace: failed to build exec argv\n");
        exit(1);
    }

    /* Fork the child */
    pid_t child = fork();
    if (child < 0) { perror("sudtrace: fork"); exit(1); }

    if (child == 0) {
        execv(exec_argv[0], exec_argv);
        perror("sudtrace: exec");
        _exit(127);
    }

    free_exec_argv(exec_argv);

    /* Give child time to exec so /proc reflects new image */
    usleep(50000);

    emit_cwd_event(child);
    emit_exec_event(child);
    emit_inherited_open_events(child);

    /* Main wait loop */
    for (;;) {
        int wstatus;
        pid_t wpid = waitpid(-1, &wstatus, __WALL);
        if (wpid < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            pid_t tgid = get_tgid(wpid);
            if (wpid == tgid || wpid == child)
                emit_exit_event(wpid, wstatus);

            if (wpid == child) break;
        }
    }

    if (g_out_fd >= 0 && g_out_fd != STDOUT_FILENO &&
        g_out_fd != STDERR_FILENO)
        close(g_out_fd);

    return 0;
}
