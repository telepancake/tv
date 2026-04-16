/*
 * sudmini.c — Minimal freestanding libc replacement for sudtrace.
 *
 * Provides just enough libc functionality to build sudtrace as a fully
 * standalone static binary (-nostdlib -ffreestanding).  NO libc headers
 * are included; only compiler-provided freestanding headers and the
 * Linux UAPI syscall-number header are used, so there is no risk of
 * colliding with glibc macros (_Generic wrappers for memchr, etc.).
 */

/* ---- Compiler-provided freestanding headers (no libc) ---- */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/* ---- Linux UAPI header for syscall numbers ---- */
#include <asm/unistd.h>

/* ---- SYS_xxx aliases for __NR_xxx ---- */
#define SYS_read           __NR_read
#define SYS_write          __NR_write
#define SYS_openat         __NR_openat
#define SYS_close          __NR_close
#define SYS_pread64        __NR_pread64
#define SYS_readlinkat     __NR_readlinkat
#define SYS_faccessat      __NR_faccessat
#define SYS_dup3           __NR_dup3
#define SYS_getcwd         __NR_getcwd
#define SYS_munmap         __NR_munmap
#define SYS_mprotect       __NR_mprotect
#define SYS_prctl          __NR_prctl
#define SYS_rt_sigaction   __NR_rt_sigaction
#define SYS_nanosleep      __NR_nanosleep
#define SYS_clone          __NR_clone
#define SYS_execve         __NR_execve
#define SYS_wait4          __NR_wait4
#define SYS_exit           __NR_exit
#ifdef __NR_exit_group
#define SYS_exit_group     __NR_exit_group
#endif
#ifdef __NR_dup2
#define SYS_dup2           __NR_dup2
#endif
#ifdef __NR_fork
#define SYS_fork           __NR_fork
#endif
#ifdef __NR_mmap
#define SYS_mmap           __NR_mmap
#endif
#ifdef __NR_mmap2
#define SYS_mmap2          __NR_mmap2
#endif
#ifdef __NR_fstat
#define SYS_fstat          __NR_fstat
#endif
#ifdef __NR_fstat64
#define SYS_fstat64        __NR_fstat64
#endif
#ifdef __NR_newfstatat
#define SYS_newfstatat     __NR_newfstatat
#endif
#ifdef __NR_fstatat64
#define SYS_fstatat64      __NR_fstatat64
#endif
#ifdef __NR_getdents64
#define SYS_getdents64     __NR_getdents64
#endif
#ifdef __NR_getdents
#define SYS_getdents       __NR_getdents
#endif

/* ---- POSIX-like types ---- */
typedef long            ssize_t;
typedef int             pid_t;
typedef long            off_t;
typedef unsigned int    useconds_t;
typedef void            FILE;

/* ---- sigset_t (matches glibc: 1024 bits = 128 bytes) ---- */
#define _MINI_SIGSET_NWORDS (1024 / (8 * sizeof(unsigned long)))
typedef struct { unsigned long __val[_MINI_SIGSET_NWORDS]; } sigset_t;

/*
 * struct sigaction — layout must match glibc so that callers compiled
 * against <signal.h> pass compatible objects.
 */
struct sigaction {
    union {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, void *, void *);
    } __sigaction_handler;
    sigset_t sa_mask;
    int      sa_flags;
    void   (*sa_restorer)(void);
};
#define sa_handler __sigaction_handler.sa_handler

struct timespec {
    long tv_sec;
    long tv_nsec;
};

/* Forward-declare struct stat (only used as opaque pointer in syscall wrappers) */
struct stat;

struct dirent {
    unsigned long  d_ino;
    long           d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[256];
};

typedef struct __dirstream DIR;

/* ---- Error numbers ---- */
#define EPERM           1
#define ENOENT          2
#define EBADF           9
#define ENOMEM         12
#define EACCES         13
#define EINVAL         22
#define ENAMETOOLONG   36
#define ENOSYS         38

/* ---- Open/fcntl constants ---- */
#define O_RDONLY        0
#define O_WRONLY        1
#define O_RDWR          2
#define O_CREAT         0100
#define O_DIRECTORY     0200000
#define AT_FDCWD        (-100)

/* ---- Memory mapping ---- */
#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define MAP_PRIVATE     0x02
#define MAP_ANONYMOUS   0x20
#define MAP_FAILED      ((void *)-1)

/* ---- Signals ---- */
#define SIGCHLD         17
#define SA_RESTORER     0x04000000

/* ---- Limits ---- */
#define PATH_MAX        4096

#define MINI_MMAP2_SHIFT 12

#if defined(__i386__)
typedef unsigned long long mini_sigset_word_t;
#else
typedef unsigned long mini_sigset_word_t;
#endif

char **environ;
static int g_errno_value;

int *__errno_location(void)
{
    return &g_errno_value;
}

#if defined(__x86_64__)
static inline long mini_syscall6(long nr, long a0, long a1, long a2,
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
        : "rcx", "r11", "memory");
    return ret;
}
#else
static inline long mini_syscall6(long nr, long a0, long a1, long a2,
                                 long a3, long a4, long a5)
{
    long ret;
    __asm__ volatile(
        "push %%ebp\n\t"
        "mov %[a5], %%ebp\n\t"
        "int $0x80\n\t"
        "pop %%ebp"
        : "=a"(ret)
        : "a"(nr), "b"(a0), "c"(a1), "d"(a2), "S"(a3), "D"(a4),
          [a5] "rm"(a5)
        : "memory");
    return ret;
}
#endif

static inline long mini_syscall5(long nr, long a0, long a1, long a2,
                                 long a3, long a4)
{
    return mini_syscall6(nr, a0, a1, a2, a3, a4, 0);
}

static inline long mini_syscall4(long nr, long a0, long a1, long a2, long a3)
{
    return mini_syscall6(nr, a0, a1, a2, a3, 0, 0);
}

static inline long mini_syscall3(long nr, long a0, long a1, long a2)
{
    return mini_syscall6(nr, a0, a1, a2, 0, 0, 0);
}

static inline long mini_syscall2(long nr, long a0, long a1)
{
    return mini_syscall6(nr, a0, a1, 0, 0, 0, 0);
}

static inline long mini_syscall1(long nr, long a0)
{
    return mini_syscall6(nr, a0, 0, 0, 0, 0, 0);
}

static inline long mini_syscall0(long nr)
{
    return mini_syscall6(nr, 0, 0, 0, 0, 0, 0);
}

static int mini_set_errno(long ret)
{
    if ((unsigned long)ret >= (unsigned long)-4095) {
        g_errno_value = (int)-ret;
        return -1;
    }
    return (int)ret;
}

static long mini_ret_errno(long ret)
{
    if ((unsigned long)ret >= (unsigned long)-4095) {
        g_errno_value = (int)-ret;
        return -1;
    }
    return ret;
}

void _exit(int status)
{
#ifdef SYS_exit_group
    mini_syscall1(SYS_exit_group, status);
#endif
    mini_syscall1(SYS_exit, status);
    for (;;) {}
}

void exit(int status)
{
    _exit(status);
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *p = (unsigned char *)dst;
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)c;
    return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        for (size_t i = 0; i < n; i++) d[i] = s[i];
    } else {
        for (size_t i = n; i > 0; i--) d[i - 1] = s[i - 1];
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    for (size_t i = 0; i < n; i++) {
        if (pa[i] != pb[i])
            return (int)pa[i] - (int)pb[i];
    }
    return 0;
}

void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = (const unsigned char *)s;
    for (size_t i = 0; i < n; i++) {
        if (p[i] == (unsigned char)c)
            return (void *)(p + i);
    }
    return NULL;
}

size_t strlen(const char *s)
{
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca != cb || ca == '\0' || cb == '\0')
            return (int)ca - (int)cb;
    }
    return 0;
}

char *strchr(const char *s, int c)
{
    while (*s) {
        if (*s == (char)c) return (char *)s;
        s++;
    }
    return c == 0 ? (char *)s : NULL;
}

char *strrchr(const char *s, int c)
{
    char *last = NULL;
    while (*s) {
        if (*s == (char)c) last = (char *)s;
        s++;
    }
    if (c == 0) return (char *)s;
    return last;
}

char *strstr(const char *haystack, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0) return (char *)haystack;
    for (; *haystack; haystack++) {
        if (*haystack == *needle && memcmp(haystack, needle, nlen) == 0)
            return (char *)haystack;
    }
    return NULL;
}

static size_t mini_page_size(void)
{
    return 4096;
}

struct mini_alloc_hdr {
    size_t map_len;
    size_t user_len;
};

void *malloc(size_t size)
{
    if (size == 0) size = 1;
    size_t total = sizeof(struct mini_alloc_hdr) + size;
    size_t page = mini_page_size();
    size_t map_len = (total + page - 1) & ~(page - 1);
    long syscall_ret = mini_syscall6(
#if defined(__x86_64__)
        SYS_mmap,
        0, map_len, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
#else
        SYS_mmap2,
        0, map_len, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
#endif
    );
    if ((unsigned long)syscall_ret >= (unsigned long)-4095) {
        g_errno_value = (int)-syscall_ret;
        return NULL;
    }
    void *base = (void *)syscall_ret;
    struct mini_alloc_hdr *hdr = (struct mini_alloc_hdr *)base;
    hdr->map_len = map_len;
    hdr->user_len = size;
    return (void *)(hdr + 1);
}

void free(void *ptr)
{
    if (!ptr) return;
    struct mini_alloc_hdr *hdr = ((struct mini_alloc_hdr *)ptr) - 1;
#if defined(__x86_64__)
    mini_syscall2(SYS_munmap, (long)hdr, hdr->map_len);
#else
    mini_syscall2(SYS_munmap, (long)hdr, hdr->map_len);
#endif
}

void *calloc(size_t nmemb, size_t size)
{
    if (size && nmemb > (size_t)-1 / size) {
        g_errno_value = ENOMEM;
        return NULL;
    }
    size_t total = nmemb * size;
    void *p = malloc(total);
    if (p) memset(p, 0, total);
    return p;
}

void *realloc(void *ptr, size_t size)
{
    if (!ptr) return malloc(size);
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    struct mini_alloc_hdr *hdr = ((struct mini_alloc_hdr *)ptr) - 1;
    size_t old_size = hdr->user_len;
    void *np = malloc(size);
    if (!np) return NULL;
    memcpy(np, ptr, old_size < size ? old_size : size);
    free(ptr);
    return np;
}

char *strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *dup = (char *)malloc(len);
    if (!dup) return NULL;
    memcpy(dup, s, len);
    return dup;
}

static int mini_vformat(char *dst, size_t size, const char *fmt, va_list ap)
{
    size_t pos = 0;
    int total = 0;
    if (size > 0) dst[0] = '\0';

#define EMIT_CH(ch) do { \
        if (pos + 1 < size) dst[pos] = (ch); \
        pos++; total++; \
    } while (0)

    while (*fmt) {
        if (*fmt != '%') {
            EMIT_CH(*fmt++);
            continue;
        }
        fmt++;
        int alt = 0;
        int long_mod = 0;
        if (*fmt == '#') { alt = 1; fmt++; }
        while (*fmt >= '0' && *fmt <= '9') fmt++;
        if (*fmt == 'l') { long_mod = 1; fmt++; if (*fmt == 'l') { long_mod = 2; fmt++; } }
        char tmp[64];
        int len = 0;
        switch (*fmt) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s) EMIT_CH(*s++);
            break;
        }
        case 'd':
        case 'i': {
            long long v = long_mod ? va_arg(ap, long) : va_arg(ap, int);
            unsigned long long uv;
            if (v < 0) {
                EMIT_CH('-');
                uv = (unsigned long long)(-(v + 1)) + 1ULL;
            } else uv = (unsigned long long)v;
            do { tmp[len++] = (char)('0' + (uv % 10)); uv /= 10; } while (uv);
            while (len--) EMIT_CH(tmp[len]);
            break;
        }
        case 'u': {
            unsigned long long uv = long_mod ? va_arg(ap, unsigned long) : va_arg(ap, unsigned int);
            do { tmp[len++] = (char)('0' + (uv % 10)); uv /= 10; } while (uv);
            while (len--) EMIT_CH(tmp[len]);
            break;
        }
        case 'p':
            alt = 1;
            long_mod = 1;
            /* fallthrough */
        case 'x':
        case 'X': {
            unsigned long long uv = (*fmt == 'p')
                ? (uintptr_t)va_arg(ap, void *)
                : (long_mod ? va_arg(ap, unsigned long) : va_arg(ap, unsigned int));
            static const char hexd[] = "0123456789abcdef";
            if (alt) { EMIT_CH('0'); EMIT_CH('x'); }
            do { tmp[len++] = hexd[uv & 0xf]; uv >>= 4; } while (uv);
            while (len--) EMIT_CH(tmp[len]);
            break;
        }
        case 'z':
            fmt++;
            if (*fmt == 'u') {
                size_t uv = va_arg(ap, size_t);
                do { tmp[len++] = (char)('0' + (uv % 10)); uv /= 10; } while (uv);
                while (len--) EMIT_CH(tmp[len]);
            }
            break;
        case '%':
            EMIT_CH('%');
            break;
        default:
            EMIT_CH('%');
            if (*fmt) EMIT_CH(*fmt);
            break;
        }
        if (*fmt) fmt++;
    }
    if (size > 0) {
        size_t end = (pos < size) ? pos : (size - 1);
        dst[end] = '\0';
    }
    return total;
#undef EMIT_CH
}

int vsnprintf(char *dst, size_t size, const char *fmt, va_list ap)
{
    va_list apcopy;
    va_copy(apcopy, ap);
    int ret = mini_vformat(dst, size, fmt, apcopy);
    va_end(apcopy);
    return ret;
}

int snprintf(char *dst, size_t size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = mini_vformat(dst, size, fmt, ap);
    va_end(ap);
    return ret;
}

FILE *stdin = (FILE *)(intptr_t)0;
FILE *stdout = (FILE *)(intptr_t)1;
FILE *stderr = (FILE *)(intptr_t)2;

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (size == 0 || nmemb == 0) return 0;
    int fd = (int)(intptr_t)stream;
    size_t total = size * nmemb;
    long ret = mini_syscall3(SYS_write, fd, (long)ptr, total);
    if (ret < 0) {
        g_errno_value = (int)-ret;
        return 0;
    }
    return (size_t)ret / size;
}

int fprintf(FILE *stream, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int len = mini_vformat(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    int fd = (int)(intptr_t)stream;
    long ret = mini_syscall3(SYS_write, fd, (long)buf, (len < (int)sizeof(buf)) ? len : (int)sizeof(buf) - 1);
    if (ret < 0) {
        g_errno_value = (int)-ret;
        return -1;
    }
    return len;
}

char *strerror(int errnum)
{
    switch (errnum) {
    case ENOENT: return "No such file or directory";
    case EINVAL: return "Invalid argument";
    case ENOMEM: return "Out of memory";
    case EPERM: return "Operation not permitted";
    case ENOSYS: return "Function not implemented";
    case EACCES: return "Permission denied";
    default: return "Error";
    }
}

void perror(const char *s)
{
    if (s && *s)
        fprintf(stderr, "%s: %s\n", s, strerror(g_errno_value));
    else
        fprintf(stderr, "%s\n", strerror(g_errno_value));
}

int access(const char *path, int mode)
{
    return mini_set_errno(mini_syscall4(SYS_faccessat, AT_FDCWD, (long)path, mode, 0));
}

int open(const char *path, int flags, ...)
{
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return mini_set_errno(mini_syscall4(SYS_openat, AT_FDCWD, (long)path, flags, mode));
}

int close(int fd)
{
    return mini_set_errno(mini_syscall1(SYS_close, fd));
}

ssize_t read(int fd, void *buf, size_t count)
{
    return mini_ret_errno(mini_syscall3(SYS_read, fd, (long)buf, count));
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
#if defined(__x86_64__)
    return mini_ret_errno(mini_syscall4(SYS_pread64, fd, (long)buf, count, (long)offset));
#else
    uint64_t off = (uint64_t)offset;
    return mini_ret_errno(mini_syscall5(SYS_pread64, fd, (long)buf, count,
                                        (uint32_t)off, (uint32_t)(off >> 32)));
#endif
}

ssize_t write(int fd, const void *buf, size_t count)
{
    return mini_ret_errno(mini_syscall3(SYS_write, fd, (long)buf, count));
}

ssize_t readlink(const char *path, char *buf, size_t bufsz)
{
    return mini_ret_errno(mini_syscall4(SYS_readlinkat, AT_FDCWD, (long)path, (long)buf, bufsz));
}

int dup2(int oldfd, int newfd)
{
#ifdef SYS_dup2
    return mini_set_errno(mini_syscall2(SYS_dup2, oldfd, newfd));
#else
    return mini_set_errno(mini_syscall3(SYS_dup3, oldfd, newfd, 0));
#endif
}

/* On i386, SYS_fstat64 / SYS_fstatat64 write a kernel struct stat64
 * (96 bytes) which is larger than userspace struct stat (88 bytes).
 * Using a struct stat buffer directly causes an 8-byte stack overflow.
 * Use an oversized buffer and copy back the struct stat portion.
 * The fields we use (st_dev at offset 0, st_ino at offset 12) have
 * identical layout in both struct stat and struct stat64. */
#if defined(__i386__) && (defined(SYS_fstat64) || defined(SYS_fstatat64))
#define MINI_STAT64_OVERFLOW 1
#define MINI_STAT_BUF_SIZE 128
#endif

#if defined(__i386__) && defined(SYS_fstat64)
int fstat(int fd, struct stat *st)
{
    /* SYS_fstat64 writes a kernel struct stat64 (96 bytes) which is
     * larger than userspace struct stat (88 bytes) on i386.  We cannot
     * use a local buffer here because struct stat is an incomplete type
     * in this TU (forward-declared only).  Instead, callers in
     * sudtrace.c must use stat_buf_t (a padded union) so the buffer
     * passed here is always large enough for the kernel write. */
    return mini_set_errno(mini_syscall2(SYS_fstat64, fd, (long)st));
}
#else
int fstat(int fd, struct stat *st)
{
    return mini_set_errno(mini_syscall2(SYS_fstat, fd, (long)st));
}
#endif

int fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
#ifdef SYS_newfstatat
    return mini_set_errno(mini_syscall4(SYS_newfstatat, dirfd, (long)path, (long)st, flags));
#else
    /* See fstat comment above — caller must provide a padded buffer. */
    return mini_set_errno(mini_syscall4(SYS_fstatat64, dirfd, (long)path, (long)st, flags));
#endif
}

/*
 * Older glibc (< 2.33, e.g. Ubuntu 18.04) defines fstat/fstatat as inline
 * wrappers that call __fxstat/__fxstatat with a version argument.  When
 * linking with -nostdlib those symbols are missing.  Provide them so that
 * both the inline wrappers AND our own explicit definitions resolve.
 */
int __fxstat(int ver, int fd, struct stat *st)
{
    (void)ver;
#if defined(__i386__) && defined(SYS_fstat64)
    return mini_set_errno(mini_syscall2(SYS_fstat64, fd, (long)st));
#else
    return mini_set_errno(mini_syscall2(SYS_fstat, fd, (long)st));
#endif
}

int __fxstatat(int ver, int dirfd, const char *path, struct stat *st, int flags)
{
    (void)ver;
#ifdef SYS_newfstatat
    return mini_set_errno(mini_syscall4(SYS_newfstatat, dirfd, (long)path, (long)st, flags));
#else
    return mini_set_errno(mini_syscall4(SYS_fstatat64, dirfd, (long)path, (long)st, flags));
#endif
}

char *getcwd(char *buf, size_t size)
{
    long ret = mini_syscall2(SYS_getcwd, (long)buf, size);
    if ((unsigned long)ret >= (unsigned long)-4095) {
        g_errno_value = (int)-ret;
        return NULL;
    }
    return buf;
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
#if defined(__x86_64__)
    long ret = mini_syscall6(SYS_mmap, (long)addr, len, prot, flags, fd, offset);
#else
    if (((uint64_t)offset & ((1ULL << MINI_MMAP2_SHIFT) - 1)) != 0) {
        g_errno_value = EINVAL;
        return MAP_FAILED;
    }
    /* SYS_mmap2 uses offsets in 4096-byte units. */
    long ret = mini_syscall6(SYS_mmap2, (long)addr, len, prot, flags, fd,
                             (long)((uint64_t)offset >> MINI_MMAP2_SHIFT));
#endif
    if ((unsigned long)ret >= (unsigned long)-4095) {
        g_errno_value = (int)-ret;
        return MAP_FAILED;
    }
    return (void *)ret;
}

int munmap(void *addr, size_t len)
{
    return mini_set_errno(mini_syscall2(SYS_munmap, (long)addr, len));
}

int mprotect(void *addr, size_t len, int prot)
{
    return mini_set_errno(mini_syscall3(SYS_mprotect, (long)addr, len, prot));
}

int prctl(int option, unsigned long arg2, unsigned long arg3,
          unsigned long arg4, unsigned long arg5)
{
    return mini_set_errno(mini_syscall5(SYS_prctl, option, arg2, arg3, arg4, arg5));
}

extern void sud_rt_sigreturn_restorer(void);

int sigemptyset(sigset_t *set)
{
    memset(set, 0, sizeof(*set));
    return 0;
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    struct kernel_sigaction {
        void (*handler)(int);
        unsigned long flags;
        void (*restorer)(void);
        mini_sigset_word_t mask;
    } kact, kold;

    struct kernel_sigaction *pact = NULL;
    struct kernel_sigaction *pold = NULL;
    if (act) {
        memset(&kact, 0, sizeof(kact));
        kact.handler = act->sa_handler;
        kact.flags = act->sa_flags | SA_RESTORER;
        kact.restorer = sud_rt_sigreturn_restorer;
        kact.mask = 0;
        pact = &kact;
    }
    if (oldact)
        pold = &kold;
    long ret = mini_syscall4(SYS_rt_sigaction, signum, (long)pact, (long)pold,
                             sizeof(kact.mask));
    if ((unsigned long)ret >= (unsigned long)-4095) {
        g_errno_value = (int)-ret;
        return -1;
    }
    if (oldact && pold)
        memset(oldact, 0, sizeof(*oldact));
    return 0;
}

int usleep(useconds_t usec)
{
    struct timespec ts;
    ts.tv_sec = usec / 1000000U;
    ts.tv_nsec = (long)(usec % 1000000U) * 1000L;
    return mini_set_errno(mini_syscall2(SYS_nanosleep, (long)&ts, 0));
}

pid_t fork(void)
{
#ifdef SYS_fork
    return (pid_t)mini_ret_errno(mini_syscall0(SYS_fork));
#else
    return (pid_t)mini_ret_errno(mini_syscall2(SYS_clone, SIGCHLD, 0));
#endif
}

int execv(const char *path, char *const argv[])
{
    long ret = mini_syscall3(SYS_execve, (long)path, (long)argv, (long)environ);
    if ((unsigned long)ret >= (unsigned long)-4095) {
        g_errno_value = (int)-ret;
        return -1;
    }
    return (int)ret;
}

pid_t waitpid(pid_t pid, int *status, int options)
{
    return (pid_t)mini_ret_errno(mini_syscall4(SYS_wait4, pid, (long)status, options, 0));
}

char *getenv(const char *name)
{
    if (!environ || !name) return NULL;
    size_t len = strlen(name);
    for (size_t i = 0; environ[i]; i++) {
        if (strncmp(environ[i], name, len) == 0 && environ[i][len] == '=')
            return environ[i] + len + 1;
    }
    return NULL;
}

static size_t env_count(void)
{
    size_t n = 0;
    if (environ)
        while (environ[n]) n++;
    return n;
}

int setenv(const char *name, const char *value, int overwrite)
{
    if (!name || !*name || strchr(name, '=')) {
        g_errno_value = EINVAL;
        return -1;
    }
    size_t len = strlen(name);
    size_t vlen = strlen(value ? value : "");
    for (size_t i = 0; environ && environ[i]; i++) {
        if (strncmp(environ[i], name, len) == 0 && environ[i][len] == '=') {
            if (!overwrite) return 0;
            char *entry = (char *)malloc(len + 1 + vlen + 1);
            if (!entry) return -1;
            memcpy(entry, name, len);
            entry[len] = '=';
            memcpy(entry + len + 1, value ? value : "", vlen + 1);
            environ[i] = entry;
            return 0;
        }
    }
    size_t count = env_count();
    char **newenv = (char **)malloc((count + 2) * sizeof(char *));
    if (!newenv) return -1;
    for (size_t i = 0; i < count; i++) newenv[i] = environ[i];
    char *entry = (char *)malloc(len + 1 + vlen + 1);
    if (!entry) return -1;
    memcpy(entry, name, len);
    entry[len] = '=';
    memcpy(entry + len + 1, value ? value : "", vlen + 1);
    newenv[count] = entry;
    newenv[count + 1] = NULL;
    environ = newenv;
    return 0;
}

int unsetenv(const char *name)
{
    if (!name || !*name || strchr(name, '=')) {
        g_errno_value = EINVAL;
        return -1;
    }
    size_t len = strlen(name);
    if (!environ) return 0;
    for (size_t i = 0; environ[i]; ) {
        if (strncmp(environ[i], name, len) == 0 && environ[i][len] == '=') {
            size_t j = i;
            do { environ[j] = environ[j + 1]; j++; } while (environ[j - 1]);
        } else {
            i++;
        }
    }
    return 0;
}

char *realpath(const char *path, char *resolved_path)
{
    if (!path || !resolved_path) {
        g_errno_value = EINVAL;
        return NULL;
    }
    if (path[0] == '/') {
        size_t len = strlen(path);
        if (len >= PATH_MAX) {
            g_errno_value = ENAMETOOLONG;
            return NULL;
        }
        memcpy(resolved_path, path, len + 1);
        return resolved_path;
    }
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return NULL;
    size_t clen = strlen(cwd), plen = strlen(path);
    if (clen + 1 + plen >= PATH_MAX) {
        g_errno_value = ENAMETOOLONG;
        return NULL;
    }
    memcpy(resolved_path, cwd, clen);
    resolved_path[clen] = '/';
    memcpy(resolved_path + clen + 1, path, plen + 1);
    return resolved_path;
}

char *strtok_r(char *str, const char *delim, char **saveptr)
{
    char *s = str ? str : *saveptr;
    if (!s) return NULL;
    while (*s && strchr(delim, *s)) s++;
    if (!*s) {
        *saveptr = NULL;
        return NULL;
    }
    char *tok = s;
    while (*s && !strchr(delim, *s)) s++;
    if (*s) *s++ = '\0';
    *saveptr = s;
    return tok;
}

struct linux_dirent64_local {
    uint64_t        d_ino;
    int64_t         d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[];
};

struct __dirstream {
    int fd;
    int pos;
    int size;
    char buf[4096];
    struct dirent ent;
};

DIR *opendir(const char *name)
{
    int fd = open(name, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return NULL;
    DIR *dir = (DIR *)malloc(sizeof(DIR));
    if (!dir) {
        close(fd);
        return NULL;
    }
    memset(dir, 0, sizeof(*dir));
    dir->fd = fd;
    return dir;
}

struct dirent *readdir(DIR *dirp)
{
    if (!dirp) {
        g_errno_value = EBADF;
        return NULL;
    }
    for (;;) {
        if (dirp->pos >= dirp->size) {
#ifdef SYS_getdents64
            long n = mini_syscall3(SYS_getdents64, dirp->fd, (long)dirp->buf, sizeof(dirp->buf));
#else
            long n = mini_syscall3(SYS_getdents, dirp->fd, (long)dirp->buf, sizeof(dirp->buf));
#endif
            if (n <= 0) {
                if (n < 0) g_errno_value = (int)-n;
                return NULL;
            }
            dirp->pos = 0;
            dirp->size = (int)n;
        }
        struct linux_dirent64_local *ent =
            (struct linux_dirent64_local *)(dirp->buf + dirp->pos);
        dirp->pos += ent->d_reclen;
        if (ent->d_reclen == 0)
            return NULL;
        dirp->ent.d_ino = ent->d_ino;
        dirp->ent.d_off = ent->d_off;
        dirp->ent.d_reclen = sizeof(struct dirent);
        dirp->ent.d_type = ent->d_type;
        size_t nlen = strlen(ent->d_name);
        if (nlen >= sizeof(dirp->ent.d_name))
            nlen = sizeof(dirp->ent.d_name) - 1;
        memcpy(dirp->ent.d_name, ent->d_name, nlen);
        dirp->ent.d_name[nlen] = '\0';
        return &dirp->ent;
    }
}

int closedir(DIR *dirp)
{
    if (!dirp) {
        g_errno_value = EBADF;
        return -1;
    }
    int rc = close(dirp->fd);
    free(dirp);
    return rc;
}

int main(int argc, char **argv);

void sudmini_start_c(uintptr_t *sp)
{
    int argc = (int)*sp++;
    char **argv = (char **)sp;
    char **envp = argv + argc + 1;
    environ = envp;
    exit(main(argc, argv));
}

#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl _start\n"
    "_start:\n"
    "mov %rsp, %rdi\n"
    "andq $-16, %rsp\n"
    "call sudmini_start_c\n"
    "hlt\n"
);
#else
__asm__(
    ".text\n"
    ".globl _start\n"
    "_start:\n"
    "mov %esp, %eax\n"
    "andl $-16, %esp\n"
    "push %eax\n"
    "call sudmini_start_c\n"
    "hlt\n"
);
#endif
