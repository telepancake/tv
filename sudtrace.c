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

/* Reserve a high FD for our output so children are unlikely to clobber it */
#define SUD_OUTPUT_FD      1023

/* ================================================================
 * Per-thread SUD selector byte.
 *
 * SUD checks this byte before delivering SIGSYS.  When ALLOW, the
 * syscall proceeds normally; when BLOCK, the kernel sends SIGSYS.
 * Each thread in a traced process inherits this via fork().
 * ================================================================ */
static __thread volatile unsigned char sud_selector
    = SYSCALL_DISPATCH_FILTER_ALLOW;

/* ================================================================
 * Global state
 * ================================================================ */

static int g_out_fd = -1;           /* fd for JSONL output */
static struct stat g_creator_stdout_st;
static int g_creator_stdout_valid;
static char g_self_exe[PATH_MAX];   /* path to sudtrace binary itself */

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
        sched_yield();
}
static void emit_unlock(void)
{
    __sync_lock_release(&g_write_lock);
}

static void emit_raw(const char *buf, size_t len)
{
    emit_lock();
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(g_out_fd, buf + off, len - off);
        if (n <= 0) break;
        off += n;
    }
    sud_selector = saved;
    emit_unlock();
}

/* ================================================================
 * Timestamp
 * ================================================================ */

static void get_timestamp_raw(struct timespec *ts)
{
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    clock_gettime(CLOCK_REALTIME, ts);
    sud_selector = saved;
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
            if (c < 0x20)
                di += snprintf(dst + di, dstsize - di, "\\u%04x", c);
            else
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
    case O_RDONLY: pos += snprintf(buf + pos, buflen - pos, "\"O_RDONLY\""); break;
    case O_WRONLY: pos += snprintf(buf + pos, buflen - pos, "\"O_WRONLY\""); break;
    case O_RDWR:  pos += snprintf(buf + pos, buflen - pos, "\"O_RDWR\""); break;
    default:      pos += snprintf(buf + pos, buflen - pos, "\"0x%x\"", acc); break;
    }
#define F(f) if ((flags & (f)) && pos < buflen - 2) \
    pos += snprintf(buf + pos, buflen - pos, ",\"" #f "\"")
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
    return snprintf(buf, buflen,
        "{\"event\":\"%s\",\"ts\":%lld.%09ld,"
        "\"pid\":%d,\"tgid\":%d,\"ppid\":%d,"
        "\"nspid\":%d,\"nstgid\":%d",
        event,
        (long long)ts->tv_sec, ts->tv_nsec,
        (int)pid, (int)tgid, (int)ppid,
        (int)pid, (int)tgid);
}

/* ================================================================
 * /proc helpers — all async-signal-safe (use raw open/read/close).
 * ================================================================ */

static ssize_t read_proc_raw(pid_t pid, const char *name,
                              char *buf, size_t bufsz)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, name);
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    int fd = open(path, O_RDONLY);
    if (fd < 0) { sud_selector = saved; return -1; }
    ssize_t total = 0, n;
    while ((size_t)total < bufsz &&
           (n = read(fd, buf + total, bufsz - total)) > 0)
        total += n;
    close(fd);
    sud_selector = saved;
    if (total > 0 && (size_t)total < bufsz) buf[total] = '\0';
    return total;
}

static char *read_proc_file(pid_t pid, const char *name, size_t max,
                            size_t *out_len)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, name);
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    int fd = open(path, O_RDONLY);
    if (fd < 0) { sud_selector = saved; return NULL; }
    char *buf = malloc(max + 1);
    if (!buf) { close(fd); sud_selector = saved; return NULL; }
    size_t total = 0;
    ssize_t n;
    while (total < max && (n = read(fd, buf + total, max - total)) > 0)
        total += n;
    close(fd);
    sud_selector = saved;
    if (total == 0) { free(buf); return NULL; }
    buf[total] = '\0';
    if (out_len) *out_len = total;
    return buf;
}

static char *read_proc_exe(pid_t pid, char *buf, size_t bufsz)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/exe", (int)pid);
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    ssize_t n = readlink(path, buf, bufsz - 1);
    sud_selector = saved;
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
    snprintf(path, sizeof(path), "/proc/%d/cwd", (int)pid);
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    ssize_t n = readlink(path, buf, bufsz - 1);
    sud_selector = saved;
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
    int ppid = 0;
    if (sscanf(cp + 2, "%*c %d", &ppid) != 1) return 0;
    return ppid;
}

static pid_t get_tgid(pid_t pid)
{
    char buf[2048];
    if (read_proc_raw(pid, "status", buf, sizeof(buf) - 1) <= 0) return pid;
    const char *p = strstr(buf, "\nTgid:");
    if (!p) return pid;
    return atoi(p + 6);
}

static ssize_t read_proc_mem(pid_t pid, unsigned long addr, void *buf,
                             size_t len)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    int fd = open(path, O_RDONLY);
    if (fd < 0) { sud_selector = saved; return -1; }
    ssize_t n = pread(fd, buf, len, (off_t)addr);
    close(fd);
    sud_selector = saved;
    return n;
}

static int format_auxv_json(pid_t pid, char *buf, int buflen)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/auxv", (int)pid);
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    int fd = open(path, O_RDONLY);
    if (fd < 0) { sud_selector = saved; return 0; }

    unsigned char raw[4096];
    ssize_t n = read(fd, raw, sizeof(raw));
    close(fd);
    sud_selector = saved;
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
    pos += snprintf(line + pos, sizeof(line) - pos, ",\"path\":%s}\n",
                    cwd_esc);
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

    size_t env_len = 0;
    char *env_raw = read_proc_file(pid, "environ", ENV_MAX_READ, &env_len);
    char *env_j = NULL;
    if (env_raw && env_len > 0) {
        env_j = malloc(env_len * 6 + 64);
        if (env_j)
            json_env_object(env_j, env_len * 6 + 64, env_raw, env_len);
    }

    char auxv_buf[4096];
    auxv_buf[0] = '\0';
    format_auxv_json(pid, auxv_buf, sizeof(auxv_buf));

    char *line = malloc(LINE_MAX_BUF);
    if (line) {
        int pos = json_header(line, LINE_MAX_BUF, "EXEC", pid, tgid, ppid,
                              &ts);
        pos += snprintf(line + pos, LINE_MAX_BUF - pos,
            ",\"exe\":%s,\"argv\":%s,\"env\":%s,\"auxv\":{%s}}\n",
            exe ? exe_esc : "null",
            argv_j ? argv_j : "[]",
            env_j ? env_j : "{}",
            auxv_buf[0] ? auxv_buf : "");
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
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d",
             (int)pid, fd_num);
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    ssize_t n = readlink(link_path, link_target, sizeof(link_target) - 1);
    sud_selector = saved;
    if (n <= 0) return;
    link_target[n] = '\0';

    struct stat st;
    saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    if (fstatat(AT_FDCWD, link_path, &st, 0) < 0)
        memset(&st, 0, sizeof(st));
    sud_selector = saved;

    char fdinfo_path[256], fdinfo_buf[512];
    snprintf(fdinfo_path, sizeof(fdinfo_path), "/proc/%d/fdinfo/%d",
             (int)pid, fd_num);
    int flags = O_RDONLY;
    saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    int fi = open(fdinfo_path, O_RDONLY);
    if (fi >= 0) {
        ssize_t r = read(fi, fdinfo_buf, sizeof(fdinfo_buf) - 1);
        close(fi);
        if (r > 0) {
            fdinfo_buf[r] = '\0';
            const char *fp = strstr(fdinfo_buf, "flags:");
            if (fp) flags = (int)strtol(fp + 6, NULL, 8);
        }
    }
    sud_selector = saved;

    char path_esc[PATH_MAX * 2];
    json_escape(path_esc, sizeof(path_esc), link_target, strlen(link_target));

    char flags_j[256];
    json_open_flags(flags, flags_j, sizeof(flags_j));

    char line[PATH_MAX * 2 + 512];
    int pos = json_header(line, sizeof(line), "OPEN", pid, tgid, ppid, ts);
    pos += snprintf(line + pos, sizeof(line) - pos,
        ",\"path\":%s,\"flags\":%s,\"fd\":%d,\"ino\":%lu,\"dev\":\"%u:%u\","
        "\"inherited\":true}\n",
        path_esc, flags_j, fd_num,
        (unsigned long)st.st_ino,
        major(st.st_dev), minor(st.st_dev));
    if (pos > 0) emit_raw(line, pos);
}

static void emit_inherited_open_events(pid_t pid)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "/proc/%d/fd", (int)pid);
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    DIR *d = opendir(dir_path);
    sud_selector = saved;
    if (!d) return;

    struct dirent *ent;
    saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        int fd_num = atoi(ent->d_name);
        sud_selector = saved;
        emit_inherited_open_for_fd(pid, tgid, ppid, &ts, fd_num);
        saved = sud_selector;
        sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    }
    closedir(d);
    sud_selector = saved;
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
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%ld", (int)pid,
                 fd_or_err);
        unsigned char saved = sud_selector;
        sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
        if (fstatat(AT_FDCWD, fd_path, &st, 0) == 0) {
            ino_nr = st.st_ino;
            dev_major = major(st.st_dev);
            dev_minor = minor(st.st_dev);
        }
        sud_selector = saved;
    }

    char line[PATH_MAX * 2 + 512];
    int pos = json_header(line, sizeof(line), "OPEN", pid, tgid, ppid, &ts);

    if (fd_or_err >= 0)
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"path\":%s,\"flags\":%s,\"fd\":%ld,\"ino\":%lu,"
            "\"dev\":\"%u:%u\"}\n",
            path ? path_esc : "null", flags_j,
            fd_or_err, ino_nr, dev_major, dev_minor);
    else
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"path\":%s,\"flags\":%s,\"err\":%ld}\n",
            path ? path_esc : "null", flags_j, fd_or_err);

    if (pos > 0) emit_raw(line, pos);
}

static void emit_write_event(pid_t pid, const char *stream,
                             const void *data_buf, size_t count)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    size_t to_read = count;
    if (to_read > WRITE_CAPTURE_MAX) to_read = WRITE_CAPTURE_MAX;

    char *escaped = malloc(to_read * 6 + 4);
    if (!escaped) return;
    json_escape(escaped, to_read * 6 + 4, data_buf, to_read);

    char *line = malloc(to_read * 6 + 512);
    if (!line) { free(escaped); return; }

    int pos = json_header(line, to_read * 6 + 512, stream, pid, tgid, ppid,
                          &ts);
    pos += snprintf(line + pos, to_read * 6 + 512 - pos,
        ",\"len\":%zu,\"data\":%s}\n", to_read, escaped);

    if (pos > 0) emit_raw(line, pos);
    free(line); free(escaped);
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
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"status\":\"exited\",\"code\":%d,\"raw\":%d}\n",
            code, status);
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        int core = 0;
#ifdef WCOREDUMP
        core = WCOREDUMP(status) ? 1 : 0;
#endif
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"status\":\"signaled\",\"signal\":%d,\"core_dumped\":%s,"
            "\"raw\":%d}\n",
            sig, core ? "true" : "false", status);
    } else {
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"status\":\"unknown\",\"raw\":%d}\n", status);
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
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/1", (int)pid);
    unsigned char saved = sud_selector;
    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    int r = stat(link_path, &st);
    sud_selector = saved;
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
    int max_args = orig_argc + 8;
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

    sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;

    pid_t tid = (pid_t)syscall(SYS_gettid);

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
     * Special handling for execve: rewrite argv to go through sudtrace.
     */
    if (nr == SYS_execve) {
        const char *fn = (const char *)a0;
        char **orig_argv = (char **)a1;
        int orig_argc = 0;
        if (orig_argv)
            while (orig_argv[orig_argc]) orig_argc++;

        int build_argc = orig_argc > 0 ? orig_argc : 1;
        char **build_argv = calloc(build_argc + 1, sizeof(char *));
        if (build_argv) {
            build_argv[0] = strdup(fn);
            for (int i = 1; i < orig_argc; i++)
                build_argv[i] = strdup(orig_argv[i]);
            build_argv[build_argc] = NULL;

            char **new_argv = build_exec_argv(build_argc, build_argv);
            free_exec_argv(build_argv);

            if (new_argv) {
                ret = syscall(SYS_execve, new_argv[0], new_argv,
                              (char **)a2);
                free_exec_argv(new_argv);
            } else {
                ret = -ENOMEM;
            }
        } else {
            ret = -ENOMEM;
        }

        uc->uc_mcontext.gregs[REG_RAX] = ret;
        sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
        return;
    }

#ifdef SYS_execveat
    if (nr == SYS_execveat) {
        ret = syscall(SYS_execveat, a0, a1, a2, a3, a4);
        uc->uc_mcontext.gregs[REG_RAX] = ret;
        sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
        return;
    }
#endif

    /* Execute the real syscall */
    ret = syscall(nr, a0, a1, a2, a3, a4, a5);

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
    sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
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

    /* Install SIGSYS handler */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL) < 0) {
        perror("sudtrace: sigaction(SIGSYS)");
        _exit(127);
    }

    /* Set up an alternate signal stack */
    size_t altstack_sz = 64 * 1024;
    void *altstack = mmap(NULL, altstack_sz, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (altstack != MAP_FAILED) {
        stack_t ss = {
            .ss_sp = altstack,
            .ss_size = altstack_sz,
            .ss_flags = 0
        };
        sigaltstack(&ss, NULL);
    }

    /* Enable SUD */
    unsigned long off = (unsigned long)__sud_begin;
    unsigned long len = (unsigned long)__sud_end - (unsigned long)__sud_begin;

    if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON,
              off, len, (unsigned long)&sud_selector) < 0) {
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

    /* Enable interception */
    sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;

    /* Jump to the entry point (adjusted for PIE load base) */
    unsigned long entry = load_base + ehdr.e_entry;

    __asm__ volatile(
        "mov %0, %%rsp\n\t"
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
        "jmp *%1\n\t"
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
    if (argv[1][0] == '-') return 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0)
            return 0;
    }
    return 1;
}

static int run_wrapper_mode(int argc, char **argv)
{
    char resolved[PATH_MAX];
    if (!resolve_path(argv[1], resolved, sizeof(resolved))) {
        fprintf(stderr, "sudtrace: cannot find '%s'\n", argv[1]);
        return 127;
    }

    pid_t child = fork();
    if (child < 0) { perror("sudtrace: fork"); return 127; }

    if (child == 0) {
        load_and_run_elf(resolved, argc - 1, argv + 1);
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
        "Usage: %s [-o FILE] -- command [args...]\n"
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
