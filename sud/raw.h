/*
 * sud/raw.h — Raw syscall infrastructure for signal-safe code paths.
 *
 * Provides inline assembly syscall helpers, clone trampoline declarations,
 * and a bump allocator that bypass the C library entirely.  Used by the
 * SIGSYS handler and other code that cannot touch TLS or errno.
 *
 * Assembly definitions and global data live in sud/raw.c.
 */

#ifndef SUD_RAW_H
#define SUD_RAW_H

#include "sud/libc.h"

/* ================================================================
 * Raw syscall — bypass the C library's errno-mangling wrapper.
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
        : "rcx", "r11", "memory"
    );
    return ret;
#else
    long ret;
    /* On i386, all 6 GPRs (eax–edi) are consumed by the syscall ABI,
     * so ebp must carry arg5.  We cannot push ebp to save it because
     * that changes esp BEFORE the compiler-generated operand for a5 is
     * read — if the compiler chose an esp-relative memory operand for
     * a5, the push shifts it by 4 bytes, loading the wrong value.
     *
     * Fix (same technique as musl libc): push a5 while esp is still at
     * its original value (so any esp-relative operand is correct), then
     * push ebp, then load a5 from the known stack slot. */
    __asm__ volatile(
        "pushl %[a5]\n\t"
        "pushl %%ebp\n\t"
        "movl  4(%%esp), %%ebp\n\t"
        "int   $0x80\n\t"
        "popl  %%ebp\n\t"
        "addl  $4, %%esp"
        : "=a"(ret)
        : "a"(nr), "b"(a0), "c"(a1), "d"(a2), "S"(a3), "D"(a4),
          [a5] "g"(a5)
        : "memory"
    );
    return ret;
#endif
}

/* ================================================================
 * rt_sigreturn restorer — defined in raw.c
 * ================================================================ */
void sud_rt_sigreturn_restorer(void);

/* ================================================================
 * Clone trampolines — defined in raw.c
 * ================================================================ */
#if defined(__x86_64__)

long clone3_raw(long clone_args, long size, ucontext_t *uc_ptr);
long clone_raw(long flags, long stack, long parent_tid,
               long child_tid, long tls, ucontext_t *uc_ptr);

#else /* i386 */

extern volatile ucontext_t *g_clone_uc_i386;
extern volatile int g_clone_sync_i386;
extern volatile int g_clone_lock_i386;

static inline long clone3_raw(long clone_args, long size, ucontext_t *uc_ptr)
{
    (void)clone_args;
    (void)size;
    (void)uc_ptr;
    return -ENOSYS;
}

long clone_raw_impl(long flags, long stack, long parent_tid,
                    long tls, long child_tid);

static inline long clone_raw(long flags, long stack, long parent_tid,
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

#endif

/* ================================================================
 * Raw syscall convenience wrappers.
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
    char buf[128] __attribute__((aligned(8)));
    int ret = (int)raw_syscall6(SYS_fstatat64, dirfd, (long)path, (long)buf,
                                flags, 0, 0);
    if (ret == 0)
        __builtin_memcpy(st, buf, 88);
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

/* mmap. i386 uses mmap2 (offset in pages); x86_64 uses mmap (offset in bytes). */
static inline void *raw_mmap(void *addr, size_t length, int prot, int flags,
                             int fd, off_t offset)
{
#ifdef SYS_mmap
    long r = raw_syscall6(SYS_mmap, (long)addr, (long)length, prot, flags,
                          fd, (long)offset);
#else
    long r = raw_syscall6(SYS_mmap2, (long)addr, (long)length, prot, flags,
                          fd, (long)(offset >> 12));
#endif
    return (void *)r;
}

/* ================================================================
 * Signal-safe bump allocator — data in raw.c, inline interface here.
 * ================================================================ */
#define ARENA_SIZE (256 * 1024)

extern char  g_arena_buf[ARENA_SIZE];
extern size_t g_arena_pos;

static inline void arena_reset(void)
{
    g_arena_pos = 0;
}

static inline void *arena_alloc(size_t size)
{
    size = (size + 15) & ~(size_t)15;
    if (g_arena_pos + size > ARENA_SIZE) return NULL;
    void *p = g_arena_buf + g_arena_pos;
    g_arena_pos += size;
    __builtin_memset(p, 0, size);
    return p;
}

static inline char *arena_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = 0;
    while (s[len]) len++;
    len++;
    char *p = arena_alloc(len);
    if (p) __builtin_memcpy(p, s, len);
    return p;
}

static inline void arena_free(void *p)
{
    (void)p;
}

#endif /* SUD_RAW_H */
