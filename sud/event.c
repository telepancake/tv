/*
 * sud/event.c — JSONL event formatting and emission for sudtrace.
 *
 * All event-emitting functions are async-signal-safe: they use raw
 * syscalls, static buffers, and a spinlock — no malloc, no stdio,
 * no TLS.  The inherited-open helpers (called at startup only) use
 * opendir/readdir/closedir from the mini-libc.
 */

#include "sud/libc.h"
#include "sud/raw.h"
#include "sud/fmt.h"
#include "sud/event.h"

/* ================================================================
 * Global variable definitions
 * ================================================================ */
int        g_out_fd               = -1;
stat_buf_t g_creator_stdout_stbuf;
int        g_creator_stdout_valid;
char       g_self_exe[PATH_MAX];
char       g_self_exe32[PATH_MAX];
char       g_self_exe64[PATH_MAX];
char       g_target_exe[PATH_MAX];
char      *g_path_env;
int        g_trace_exec_env       = 1;

/* ================================================================
 * Stat field extraction from raw kernel buffers.
 *
 * stat_buf_t is an opaque 256-byte union.  We call the fstatat
 * syscall directly (bypassing raw_fstatat's 88-byte truncation on
 * i386) and extract st_dev / st_ino at known kernel offsets using
 * memcpy to avoid alignment issues.
 * ================================================================ */
static int event_fstatat(const char *path, stat_buf_t *sb)
{
    __builtin_memset(sb, 0, sizeof(*sb));
#ifdef SYS_newfstatat
    return (int)raw_syscall6(SYS_newfstatat, AT_FDCWD, (long)path,
                             (long)sb, 0, 0, 0);
#else
    return (int)raw_syscall6(SYS_fstatat64, AT_FDCWD, (long)path,
                             (long)sb, 0, 0, 0);
#endif
}

static unsigned long sb_dev(const stat_buf_t *sb)
{
#if defined(__x86_64__)
    /* x86_64 struct stat: st_dev is unsigned long at offset 0 */
    unsigned long v;
    __builtin_memcpy(&v, sb->_data, sizeof(v));
    return v;
#else
    /* i386 stat64: st_dev is unsigned long long at offset 0 */
    unsigned long long v;
    __builtin_memcpy(&v, sb->_data, sizeof(v));
    return (unsigned long)v;
#endif
}

static unsigned long sb_ino(const stat_buf_t *sb)
{
#if defined(__x86_64__)
    /* x86_64 struct stat: st_ino is unsigned long at offset 8 */
    unsigned long v;
    __builtin_memcpy(&v, sb->_data + 8, sizeof(v));
    return v;
#else
    /* i386 kernel stat64 structure (96 bytes): full st_ino is
     * unsigned long long at offset 88.  We get all 96 bytes because
     * event_fstatat writes directly into the 256-byte stat_buf_t
     * (no 88-byte truncation). */
    unsigned long long v;
    __builtin_memcpy(&v, sb->_data + 88, sizeof(v));
    return (unsigned long)v;
#endif
}

static unsigned int sud_major(unsigned long dev)
{
    return (unsigned int)((dev >> 8) & 0xfff);
}

static unsigned int sud_minor(unsigned long dev)
{
    return (unsigned int)((dev & 0xff) | ((dev >> 12) & ~0xffU));
}

/* WCOREDUMP is not defined in the freestanding headers */
#ifndef WCOREDUMP
#define WCOREDUMP(s) ((s) & 0x80)
#endif

/* ================================================================
 * Low-level output — raw write(2) with spinlock serialisation.
 *
 * The SIGSYS handler cannot safely use stdio (not async-signal-safe),
 * so all event emission uses raw write().  We serialise writes from
 * multiple threads via a simple spinlock.
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
 * JSON helpers
 * ================================================================ */

int json_escape(char *dst, int dstsize, const char *src, int srclen)
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

int json_argv_array(char *dst, int dstsize, const char *raw, int rawlen)
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

int json_argv_array_vec(char *dst, int dstsize, char *const *argv, int argc)
{
    int di = 0;
    dst[di++] = '[';
    for (int i = 0; i < argc && di + 8 < dstsize; i++) {
        const char *arg = argv[i] ? argv[i] : "";
        if (di > 1) dst[di++] = ',';
        di += json_escape(dst + di, dstsize - di, arg, strlen(arg));
    }
    if (di < dstsize) dst[di++] = ']';
    if (di < dstsize) dst[di] = '\0';
    return di;
}

int json_env_object(char *dst, int dstsize, const char *raw, int rawlen)
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

int json_open_flags(int flags, char *buf, int buflen)
{
    char *p = buf;
    int acc = flags & O_ACCMODE;
    (void)buflen;

    *p++ = '[';
    switch (acc) {
    case O_RDONLY: p = fmt_str(p, "\"O_RDONLY\""); break;
    case O_WRONLY: p = fmt_str(p, "\"O_WRONLY\""); break;
    case O_RDWR:  p = fmt_str(p, "\"O_RDWR\""); break;
    default:      p = fmt_str(p, "\"O_OTHER\""); break;
    }
#define F(f) if (flags & (f)) { *p++ = ','; p = fmt_str(p, "\"" #f "\""); }
    F(O_CREAT) F(O_EXCL) F(O_TRUNC) F(O_APPEND) F(O_NONBLOCK)
    F(O_DIRECTORY) F(O_NOFOLLOW) F(O_CLOEXEC)
    F(O_TMPFILE)
#undef F
    *p++ = ']';
    *p = '\0';
    return (int)(p - buf);
}

/* ================================================================
 * JSON header — common prefix for every JSONL event line.
 * ================================================================ */
int json_header(char *buf, int buflen, const char *event,
                pid_t pid, pid_t tgid, pid_t ppid,
                struct timespec *ts)
{
    char *p = buf;
    (void)buflen;

    p = fmt_str(p, "{\"event\":\"");
    p = fmt_str(p, event);
    p = fmt_str(p, "\",\"ts\":");
    p = fmt_long(p, (long)ts->tv_sec);
    p = fmt_ch(p, '.');
    /* Zero-pad nanoseconds to 9 digits */
    {
        char ns[16];
        char *ne = fmt_long(ns, ts->tv_nsec);
        int nlen = (int)(ne - ns);
        for (int i = nlen; i < 9; i++)
            p = fmt_ch(p, '0');
        p = fmt_str(p, ns);
    }
    p = fmt_str(p, ",\"pid\":");
    p = fmt_int(p, (int)pid);
    p = fmt_str(p, ",\"tgid\":");
    p = fmt_int(p, (int)tgid);
    p = fmt_str(p, ",\"ppid\":");
    p = fmt_int(p, (int)ppid);
    p = fmt_str(p, ",\"nspid\":");
    p = fmt_int(p, (int)pid);
    p = fmt_str(p, ",\"nstgid\":");
    p = fmt_int(p, (int)tgid);
    return (int)(p - buf);
}

/* ================================================================
 * Proc helpers (raw-syscall-safe)
 * ================================================================ */

ssize_t read_proc_raw(pid_t pid, const char *name,
                      char *buf, size_t bufsz)
{
    char path[256];
    fmt_proc_path(path, pid, name);
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

char *read_proc_exe(pid_t pid, char *buf, size_t bufsz)
{
    char path[256];
    fmt_proc_path(path, pid, "exe");
    ssize_t n = raw_readlink(path, buf, bufsz - 1);
    if (n <= 0) return NULL;
    buf[n] = '\0';
    const char *del = " (deleted)";
    size_t dlen = strlen(del);
    if ((size_t)n > dlen && strcmp(buf + n - dlen, del) == 0)
        buf[n - dlen] = '\0';
    return buf;
}

char *read_proc_cwd(pid_t pid, char *buf, size_t bufsz)
{
    char path[256];
    fmt_proc_path(path, pid, "cwd");
    ssize_t n = raw_readlink(path, buf, bufsz - 1);
    if (n <= 0) return NULL;
    buf[n] = '\0';
    return buf;
}

pid_t get_ppid(pid_t pid)
{
    char buf[512];
    if (read_proc_raw(pid, "stat", buf, sizeof(buf) - 1) <= 0) return 0;
    char *cp = strrchr(buf, ')');
    if (!cp) return 0;
    /* Format after ')': " S ppid ..." — skip space, state char, space */
    cp += 2;
    while (*cp && *cp != ' ') cp++;
    return parse_int(cp);
}

pid_t get_tgid(pid_t pid)
{
    char buf[2048];
    if (read_proc_raw(pid, "status", buf, sizeof(buf) - 1) <= 0) return pid;
    const char *p = strstr(buf, "\nTgid:");
    if (!p) return pid;
    return parse_int(p + 6);
}

/* ================================================================
 * Event emission
 *
 * Called from the SIGSYS handler (in the traced process) and from
 * startup.  All paths use raw write(), not stdio.
 * ================================================================ */

void emit_cwd_event(pid_t pid)
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
    char *p = line + pos;
    p = fmt_str(p, ",\"path\":");
    p = fmt_str(p, cwd_esc);
    p = fmt_str(p, "}\n");
    emit_raw(line, (size_t)(p - line));
}

/* Static buffers for emit_exec_event, protected by emit_lock.
 * Only one exec event can be in-flight at a time. */
static char g_exec_line_buf[LINE_MAX_BUF];
static char g_exec_cmdline[ARGV_MAX_READ];
static char g_exec_env_buf[ENV_MAX_READ];

void emit_exec_event(pid_t pid, const char *fallback_exe,
                     int fallback_argc, char **fallback_argv)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    char exe_buf[PATH_MAX];
    char *exe = (fallback_exe && fallback_exe[0])
        ? (char *)fallback_exe
        : read_proc_exe(pid, exe_buf, sizeof(exe_buf));
    char exe_esc[PATH_MAX * 2];
    if (exe) json_escape(exe_esc, sizeof(exe_esc), exe, strlen(exe));

    emit_lock();

    /* Build JSONL line in static buffer */
    int hdr_len = json_header(g_exec_line_buf, LINE_MAX_BUF, "EXEC",
                              pid, tgid, ppid, &ts);
    char *p = g_exec_line_buf + hdr_len;

    p = fmt_str(p, ",\"exe\":");
    p = fmt_str(p, exe ? exe_esc : "null");
    p = fmt_str(p, ",\"argv\":");

    int avail = LINE_MAX_BUF - (int)(p - g_exec_line_buf);
    if (fallback_argv && fallback_argc > 0) {
        int n = json_argv_array_vec(p, avail, fallback_argv, fallback_argc);
        p += n;
    } else {
        ssize_t cmdline_len = read_proc_raw(pid, "cmdline",
                                            g_exec_cmdline, ARGV_MAX_READ);
        if (cmdline_len > 0) {
            int n = json_argv_array(p, avail, g_exec_cmdline, (int)cmdline_len);
            p += n;
        } else {
            p = fmt_str(p, "[]");
        }
    }

    if (g_trace_exec_env) {
        p = fmt_str(p, ",\"env\":");
        ssize_t env_len = read_proc_raw(pid, "environ",
                                        g_exec_env_buf, ENV_MAX_READ);
        avail = LINE_MAX_BUF - (int)(p - g_exec_line_buf);
        if (env_len > 0) {
            int n = json_env_object(p, avail, g_exec_env_buf, (int)env_len);
            p += n;
        } else {
            p = fmt_str(p, "{}");
        }
    }

    p = fmt_str(p, "}\n");

    int total = (int)(p - g_exec_line_buf);
    if (total > 0 && total < LINE_MAX_BUF) {
        size_t off = 0;
        while (off < (size_t)total) {
            ssize_t n = raw_write(g_out_fd, g_exec_line_buf + off, total - off);
            if (n <= 0) break;
            off += n;
        }
    }

    emit_unlock();
}

void emit_inherited_open_for_fd(pid_t pid, pid_t tgid, pid_t ppid,
                                struct timespec *ts, int fd_num)
{
    if (fd_num == g_out_fd) return;

    char link_path[256], link_target[PATH_MAX];
    {
        char *lp = link_path;
        lp = fmt_str(lp, "/proc/");
        lp = fmt_int(lp, (int)pid);
        lp = fmt_str(lp, "/fd/");
        lp = fmt_int(lp, fd_num);
    }
    ssize_t n = raw_readlink(link_path, link_target, sizeof(link_target) - 1);
    if (n <= 0) return;
    link_target[n] = '\0';

    stat_buf_t stbuf;
    event_fstatat(link_path, &stbuf);

    char fdinfo_path[256], fdinfo_buf[512];
    {
        char *fp = fdinfo_path;
        fp = fmt_str(fp, "/proc/");
        fp = fmt_int(fp, (int)pid);
        fp = fmt_str(fp, "/fdinfo/");
        fp = fmt_int(fp, fd_num);
    }
    int flags = O_RDONLY;
    int fi = raw_open(fdinfo_path, O_RDONLY);
    if (fi >= 0) {
        ssize_t r = raw_read(fi, fdinfo_buf, sizeof(fdinfo_buf) - 1);
        raw_close(fi);
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

    unsigned long dev = sb_dev(&stbuf);
    unsigned long ino = sb_ino(&stbuf);

    char line[PATH_MAX * 2 + 512];
    int pos = json_header(line, sizeof(line), "OPEN", pid, tgid, ppid, ts);
    char *p = line + pos;
    p = fmt_str(p, ",\"path\":");
    p = fmt_str(p, path_esc);
    p = fmt_str(p, ",\"flags\":");
    p = fmt_str(p, flags_j);
    p = fmt_str(p, ",\"fd\":");
    p = fmt_int(p, fd_num);
    p = fmt_str(p, ",\"ino\":");
    p = fmt_ulong(p, ino);
    p = fmt_str(p, ",\"dev\":\"");
    p = fmt_ulong(p, (unsigned long)sud_major(dev));
    p = fmt_ch(p, ':');
    p = fmt_ulong(p, (unsigned long)sud_minor(dev));
    p = fmt_str(p, "\",\"inherited\":true}\n");
    emit_raw(line, (size_t)(p - line));
}

void emit_inherited_open_events(pid_t pid)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    char dir_path[256];
    fmt_proc_path(dir_path, pid, "fd");
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

void emit_open_event(pid_t pid, const char *path, int flags,
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
        char *fp = fd_path;
        fp = fmt_str(fp, "/proc/");
        fp = fmt_int(fp, (int)pid);
        fp = fmt_str(fp, "/fd/");
        fp = fmt_long(fp, fd_or_err);

        stat_buf_t sb;
        if (event_fstatat(fd_path, &sb) >= 0) {
            ino_nr = sb_ino(&sb);
            dev_major = sud_major(sb_dev(&sb));
            dev_minor = sud_minor(sb_dev(&sb));
        }
    }

    char line[PATH_MAX * 2 + 512];
    int pos = json_header(line, sizeof(line), "OPEN", pid, tgid, ppid, &ts);
    char *p = line + pos;

    p = fmt_str(p, ",\"path\":");
    p = fmt_str(p, path ? path_esc : "null");
    p = fmt_str(p, ",\"flags\":");
    p = fmt_str(p, flags_j);

    if (fd_or_err >= 0) {
        p = fmt_str(p, ",\"fd\":");
        p = fmt_long(p, fd_or_err);
        p = fmt_str(p, ",\"ino\":");
        p = fmt_ulong(p, ino_nr);
        p = fmt_str(p, ",\"dev\":\"");
        p = fmt_ulong(p, (unsigned long)dev_major);
        p = fmt_ch(p, ':');
        p = fmt_ulong(p, (unsigned long)dev_minor);
        p = fmt_str(p, "\"}\n");
    } else {
        p = fmt_str(p, ",\"err\":");
        p = fmt_long(p, fd_or_err);
        p = fmt_str(p, "}\n");
    }

    emit_raw(line, (size_t)(p - line));
}

/* Static buffers for emit_write_event — avoids malloc() which is not
 * async-signal-safe.  Protected by the emit_lock() spinlock that
 * already serialises output. */
#define WRITE_ESCAPED_MAX  (WRITE_CAPTURE_MAX * 6 + 4)
#define WRITE_LINE_MAX     (WRITE_CAPTURE_MAX * 6 + 512)
static char g_write_escaped_buf[WRITE_ESCAPED_MAX];
static char g_write_line_buf[WRITE_LINE_MAX];

void emit_write_event(pid_t pid, const char *stream,
                      const void *data_buf, size_t count)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    size_t to_read = count;
    if (to_read > WRITE_CAPTURE_MAX) to_read = WRITE_CAPTURE_MAX;

    /* Use static buffers under lock — the SIGSYS handler cannot
     * safely call malloc (the interrupted code may hold the heap lock). */
    emit_lock();

    json_escape(g_write_escaped_buf, WRITE_ESCAPED_MAX, data_buf, to_read);

    int pos = json_header(g_write_line_buf, WRITE_LINE_MAX, stream,
                          pid, tgid, ppid, &ts);
    char *p = g_write_line_buf + pos;
    p = fmt_str(p, ",\"len\":");
    p = fmt_size(p, to_read);
    p = fmt_str(p, ",\"data\":");
    p = fmt_str(p, g_write_escaped_buf);
    p = fmt_str(p, "}\n");

    int total = (int)(p - g_write_line_buf);
    if (total > 0) {
        size_t off = 0;
        while (off < (size_t)total) {
            ssize_t n = raw_write(g_out_fd, g_write_line_buf + off, total - off);
            if (n <= 0) break;
            off += n;
        }
    }

    emit_unlock();
}

void emit_exit_event(pid_t pid, int status)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp_raw(&ts);

    char line[384];
    int pos = json_header(line, sizeof(line), "EXIT", pid, tgid, ppid, &ts);
    char *p = line + pos;

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        p = fmt_str(p, ",\"status\":\"exited\",\"code\":");
        p = fmt_int(p, code);
        p = fmt_str(p, ",\"raw\":");
        p = fmt_int(p, status);
        p = fmt_str(p, "}\n");
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        int core = 0;
        core = WCOREDUMP(status) ? 1 : 0;
        p = fmt_str(p, ",\"status\":\"signaled\",\"signal\":");
        p = fmt_int(p, sig);
        p = fmt_str(p, ",\"core_dumped\":");
        p = fmt_str(p, core ? "true" : "false");
        p = fmt_str(p, ",\"raw\":");
        p = fmt_int(p, status);
        p = fmt_str(p, "}\n");
    } else {
        p = fmt_str(p, ",\"status\":\"unknown\",\"raw\":");
        p = fmt_int(p, status);
        p = fmt_str(p, "}\n");
    }

    emit_raw(line, (size_t)(p - line));
}

/* ================================================================
 * STDOUT filtering (same logic as uproctrace.c)
 * ================================================================ */
int fd1_is_creator_stdout(pid_t pid)
{
    if (!g_creator_stdout_valid) return 0;

    char link_path[256];
    char *lp = link_path;
    lp = fmt_str(lp, "/proc/");
    lp = fmt_int(lp, (int)pid);
    lp = fmt_str(lp, "/fd/1");

    stat_buf_t sb;
    if (event_fstatat(link_path, &sb) < 0) return 0;

    return (sb_dev(&sb) == sb_dev(&g_creator_stdout_stbuf) &&
            sb_ino(&sb) == sb_ino(&g_creator_stdout_stbuf));
}
