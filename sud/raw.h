/*
 * sud/raw.h — Raw syscall infrastructure for signal-safe code paths.
 *
 * Provides inline assembly syscall helpers, clone trampolines, and a
 * bump allocator that bypass the C library entirely.  Used by the
 * SIGSYS handler and other code that cannot touch TLS or errno.
 *
 * Included in exactly one translation unit (the freestanding sud binary).
 */

#ifndef SUD_RAW_H
#define SUD_RAW_H

#include "sud/libc.h"

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
#if defined(__x86_64__)
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
#else
    long ret;
    __asm__ volatile(
        "push %%ebp\n\t"
        "mov %[a5], %%ebp\n\t"
        "int $0x80\n\t"
        "pop %%ebp"
        : "=a"(ret)
        : "a"(nr), "b"(a0), "c"(a1), "d"(a2), "S"(a3), "D"(a4),
          [a5] "rm"(a5)
        : "memory"
    );
    return ret;
#endif
}

/* ================================================================
 * rt_sigreturn restorer — used as sa_restorer in struct sigaction.
 * ================================================================ */
void sud_rt_sigreturn_restorer(void);

#if defined(__x86_64__)
__asm__(
    "    .text\n"
    "    .globl sud_rt_sigreturn_restorer\n"
    "    .type sud_rt_sigreturn_restorer, @function\n"
    "sud_rt_sigreturn_restorer:\n"
    "    mov  $" STR(SYS_rt_sigreturn) ", %eax\n"
    "    syscall\n"
    "    hlt\n"
    "    .size sud_rt_sigreturn_restorer, .-sud_rt_sigreturn_restorer\n"
);
#else
__asm__(
    "    .text\n"
    "    .globl sud_rt_sigreturn_restorer\n"
    "    .type sud_rt_sigreturn_restorer, @function\n"
    "sud_rt_sigreturn_restorer:\n"
    "    mov  $" STR(SYS_rt_sigreturn) ", %eax\n"
    "    int  $0x80\n"
    "    hlt\n"
    "    .size sud_rt_sigreturn_restorer, .-sud_rt_sigreturn_restorer\n"
);
#endif

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

#if defined(__x86_64__)
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
    "    call prepare_child_sud\n"
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
    "    call prepare_child_sud\n"
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
    "    xor  %eax, %eax\n"        /* RAX = 0 (child clone return) */
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
#else
volatile ucontext_t *g_clone_uc_i386;
volatile int g_clone_sync_i386;
static volatile int g_clone_lock_i386;

static long clone3_raw(long clone_args, long size, ucontext_t *uc_ptr)
{
    (void)clone_args;
    (void)size;
    (void)uc_ptr;
    return -ENOSYS;
}

long clone_raw_impl(long flags, long stack, long parent_tid,
                    long tls, long child_tid);

__asm__(
    "    .text\n"
    "    .globl clone_raw_impl\n"
    "    .type clone_raw_impl, @function\n"
    "clone_raw_impl:\n"
    "    push %ebp\n"
    "    mov  %esp, %ebp\n"
    "    push %edi\n"
    "    push %esi\n"
    "    push %ebx\n"
    "    mov  $120, %eax\n"
    "    mov  8(%ebp), %ebx\n"
    "    mov  12(%ebp), %ecx\n"
    "    mov  16(%ebp), %edx\n"
    "    mov  20(%ebp), %esi\n"
    "    mov  24(%ebp), %edi\n"
    "    int  $0x80\n"
    "    test %eax, %eax\n"
    "    jnz  .Lcl_i386_parent\n"
    "    mov  g_clone_uc_i386, %ebp\n"
    "    mov  76(%ebp), %eax\n"
    "    push %eax\n"
    "    mov  56(%ebp), %eax\n"
    "    push %eax\n"
    "    mov  52(%ebp), %eax\n"
    "    push %eax\n"
    "    mov  44(%ebp), %eax\n"
    "    push %eax\n"
    "    mov  40(%ebp), %eax\n"
    "    push %eax\n"
    "    mov  36(%ebp), %eax\n"
    "    push %eax\n"
    "    movl $1, g_clone_sync_i386\n"
    "    call prepare_child_sud\n"
    "    pop  %edi\n"
    "    pop  %esi\n"
    "    pop  %ebp\n"
    "    pop  %ebx\n"
    "    pop  %edx\n"
    "    pop  %ecx\n"
    "    xor  %eax, %eax\n"        /* EAX = 0 (child clone return) */
    "    jmp  *%ecx\n"
    ".Lcl_i386_parent:\n"
    "    pop  %ebx\n"
    "    pop  %esi\n"
    "    pop  %edi\n"
    "    pop  %ebp\n"
    "    ret\n"
    "    .size clone_raw_impl, .-clone_raw_impl\n"
);

static long clone_raw(long flags, long stack, long parent_tid,
                      long child_tid, long tls, ucontext_t *uc_ptr)
{
    while (__sync_lock_test_and_set(&g_clone_lock_i386, 1))
        __asm__ volatile("pause");
    g_clone_uc_i386 = uc_ptr;
    g_clone_sync_i386 = 0;
    long ret = clone_raw_impl(flags, stack, parent_tid, tls, child_tid);
    if (ret > 0) {
        while (!g_clone_sync_i386)
            __asm__ volatile("pause");
    }
    __sync_lock_release(&g_clone_lock_i386);
    return ret;
}

_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_EDI]) == 36, "EDI offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_ESI]) == 40, "ESI offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_EBP]) == 44, "EBP offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_ESP]) == 48, "ESP offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_EBX]) == 52, "EBX offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_EDX]) == 56, "EDX offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_ECX]) == 60, "ECX offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_EAX]) == 64, "EAX offset");
_Static_assert(__builtin_offsetof(ucontext_t, uc_mcontext.gregs[REG_EIP]) == 76, "EIP offset");
#endif

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
#ifdef SYS_newfstatat
    return (int)raw_syscall6(SYS_newfstatat, dirfd, (long)path, (long)st,
                              flags, 0, 0);
#else
    /* On i386, SYS_fstatat64 writes a kernel struct stat64 (96 bytes) which
     * is larger than userspace struct stat (88 bytes).  Using a struct stat
     * buffer directly causes an 8-byte stack overflow that can corrupt
     * adjacent data and crash the traced process (SIGSEGV at NULL after
     * library loading).  Use an oversized buffer and copy back. */
    char buf[128] __attribute__((aligned(8)));
    int ret = (int)raw_syscall6(SYS_fstatat64, dirfd, (long)path, (long)buf,
                                flags, 0, 0);
    if (ret == 0)
        __builtin_memcpy(st, buf, sizeof(*st));
    return ret;
#endif
}

static inline ssize_t raw_pread(int fd, void *buf, size_t count, off_t offset)
{
#if defined(__x86_64__)
    return (ssize_t)raw_syscall6(SYS_pread64, fd, (long)buf, count,
                                  offset, 0, 0);
#else
    unsigned long long off = (unsigned long long)offset;
    return (ssize_t)raw_syscall6(SYS_pread64, fd, (long)buf, count,
                                  (uint32_t)off, (uint32_t)(off >> 32), 0);
#endif
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
#ifdef SYS_getdents64
    return raw_syscall6(SYS_getdents64, fd, (long)buf, count, 0, 0, 0);
#else
    return raw_syscall6(SYS_getdents, fd, (long)buf, count, 0, 0, 0);
#endif
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
    __builtin_memset(p, 0, size);
    return p;
}

static char *arena_strdup(const char *s)
{
    if (!s) return NULL;
    /* Local strlen — cannot call libc strlen in the signal handler. */
    size_t len = 0;
    while (s[len]) len++;
    len++;  /* include NUL terminator */
    char *p = arena_alloc(len);
    if (p) __builtin_memcpy(p, s, len);
    return p;
}

static void arena_free(void *p)
{
    (void)p;  /* bump allocator: nothing to free */
}

#endif /* SUD_RAW_H */
