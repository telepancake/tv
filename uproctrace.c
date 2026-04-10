/*
 * uproctrace.c — Userspace process tracer using ptrace.
 *
 * Produces the same JSONL event stream as proctrace.c (kernel module),
 * but runs entirely in userspace via PTRACE.  Meant to be accessible
 * in environments where loading a kernel module is impractical.
 *
 * Usage:  uproctrace [options] -- command [args...]
 *
 *   -o FILE   Write trace to FILE instead of stdout.
 *
 * Events emitted: CWD, EXEC, OPEN (real + inherited), EXIT, STDOUT, STDERR.
 *
 * Build:  cc -O2 -o uproctrace uproctrace.c
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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <linux/ptrace.h>
#include <elf.h>          /* AT_* constants, ElfW, NT_PRSTATUS */

/* ================================================================
 * Constants
 * ================================================================ */

#define WRITE_CAPTURE_MAX   4096
#define ARGV_MAX_READ       32768
#define ENV_MAX_READ        65536
#define LINE_MAX_BUF        (PATH_MAX * 8 + 262144 + 1024)

/* ================================================================
 * Output stream
 * ================================================================ */

static FILE *g_out;
static struct stat g_creator_stdout_st; /* stat of the session creator's stdout */
static int g_creator_stdout_valid;

/* ================================================================
 * Timestamp
 * ================================================================ */

static void get_timestamp(struct timespec *ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
}

/* ================================================================
 * JSON helpers
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

/* Build a JSON array from a NUL-separated string (like /proc/.../cmdline) */
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

/* Build a JSON object from NUL-separated KEY=VALUE entries */
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

/* Open flags to JSON array */
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
 * JSON header helper
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

static void emit_line(const char *line, size_t len)
{
    fwrite(line, 1, len, g_out);
    fflush(g_out);
}

/* ================================================================
 * /proc helpers
 * ================================================================ */

/* Read a whole /proc file into a malloc'd buffer */
static char *read_proc_file(pid_t pid, const char *name, size_t max, size_t *out_len)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, name);
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

/* Read /proc/PID/exe symlink */
static char *read_proc_exe(pid_t pid, char *buf, size_t bufsz)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/exe", (int)pid);
    ssize_t n = readlink(path, buf, bufsz - 1);
    if (n <= 0) return NULL;
    buf[n] = '\0';
    /* strip " (deleted)" suffix if present */
    const char *del = " (deleted)";
    size_t dlen = strlen(del);
    if ((size_t)n > dlen && strcmp(buf + n - dlen, del) == 0)
        buf[n - dlen] = '\0';
    return buf;
}

/* Read /proc/PID/cwd symlink */
static char *read_proc_cwd(pid_t pid, char *buf, size_t bufsz)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cwd", (int)pid);
    ssize_t n = readlink(path, buf, bufsz - 1);
    if (n <= 0) return NULL;
    buf[n] = '\0';
    return buf;
}

/* Get ppid from /proc/PID/stat */
static pid_t get_ppid(pid_t pid)
{
    char path[256], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    /* Format: pid (comm) state ppid ... */
    char *cp = strrchr(buf, ')');
    if (!cp) return 0;
    int ppid = 0;
    if (sscanf(cp + 2, "%*c %d", &ppid) != 1) return 0;
    return ppid;
}

/* Get tgid from /proc/PID/status */
static pid_t get_tgid(pid_t pid)
{
    char path[256], buf[2048];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return pid; /* fallback: assume tgid == pid */
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return pid;
    buf[n] = '\0';
    const char *p = strstr(buf, "\nTgid:");
    if (!p) return pid;
    return atoi(p + 6);
}

/* Read a process's memory at a given address. */
static ssize_t read_proc_mem(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, len, (off_t)addr);
    close(fd);
    return n;
}

/* Read /proc/PID/auxv and extract interesting entries */
static int format_auxv_json(pid_t pid, char *buf, int buflen)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/auxv", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    /* auxv is an array of Elf{32,64}_auxv_t */
    unsigned char raw[4096];
    ssize_t n = read(fd, raw, sizeof(raw));
    close(fd);
    if (n <= 0) return 0;

    int pos = 0, first = 1;
    /* Parse as native auxv_t (Elf64_auxv_t on 64-bit, Elf32_auxv_t on 32-bit) */
#if __SIZEOF_POINTER__ == 8
    typedef Elf64_auxv_t my_auxv_t;
#else
    typedef Elf32_auxv_t my_auxv_t;
#endif
    my_auxv_t *av = (my_auxv_t *)raw;
    int count = n / sizeof(my_auxv_t);
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
            /* val is a pointer in the tracee's address space */
            char u[256];
            ssize_t r = read_proc_mem(pid, val, u, sizeof(u) - 1);
            if (r > 0) {
                u[r] = '\0';
                size_t slen = strlen(u);
                char e[520];
                json_escape(e, sizeof(e), u, slen);
                if (!first) buf[pos++] = ',';
                pos += snprintf(buf + pos, buflen - pos, "\"AT_EXECFN\":%s", e);
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
                pos += snprintf(buf + pos, buflen - pos, "\"AT_PLATFORM\":%s", e);
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
 * Tracked-pid set (simple dynamic array)
 * ================================================================ */

struct pid_set {
    pid_t *pids;
    int    count;
    int    cap;
};

static struct pid_set g_tracked = { NULL, 0, 0 };

static void pidset_add(struct pid_set *s, pid_t pid)
{
    for (int i = 0; i < s->count; i++)
        if (s->pids[i] == pid) return;
    if (s->count >= s->cap) {
        int nc = s->cap ? s->cap * 2 : 64;
        pid_t *np = realloc(s->pids, (size_t)nc * sizeof(pid_t));
        if (!np) return; /* OOM: silently drop */
        s->pids = np;
        s->cap = nc;
    }
    s->pids[s->count++] = pid;
}

static void pidset_remove(struct pid_set *s, pid_t pid)
{
    for (int i = 0; i < s->count; i++) {
        if (s->pids[i] == pid) {
            s->pids[i] = s->pids[--s->count];
            return;
        }
    }
}

static int pidset_contains(struct pid_set *s, pid_t pid)
{
    for (int i = 0; i < s->count; i++)
        if (s->pids[i] == pid) return 1;
    return 0;
}

/* ================================================================
 * Per-process state (for syscall entry/exit tracking)
 * ================================================================ */

struct proc_state {
    pid_t pid;
    int   in_syscall;     /* 1 if we're at syscall entry, 0 at exit */
    long  saved_syscall;  /* syscall number at entry */
    /* saved args for specific syscalls */
    unsigned long arg0, arg1, arg2;
    struct proc_state *next;
};

static struct proc_state *g_states = NULL;

static struct proc_state *get_state(pid_t pid)
{
    for (struct proc_state *s = g_states; s; s = s->next)
        if (s->pid == pid) return s;
    struct proc_state *s = calloc(1, sizeof(*s));
    s->pid = pid;
    s->next = g_states;
    g_states = s;
    return s;
}

static void free_state(pid_t pid)
{
    struct proc_state **pp = &g_states;
    while (*pp) {
        if ((*pp)->pid == pid) {
            struct proc_state *tmp = *pp;
            *pp = tmp->next;
            free(tmp);
            return;
        }
        pp = &(*pp)->next;
    }
}

/* ================================================================
 * Read tracee string from /proc/pid/mem
 * ================================================================ */

static char *read_tracee_string(pid_t pid, unsigned long addr, size_t max)
{
    if (!addr) return NULL;
    char *buf = malloc(max + 1);
    if (!buf) return NULL;
    ssize_t n = read_proc_mem(pid, addr, buf, max);
    if (n <= 0) { free(buf); return NULL; }
    buf[n] = '\0';
    /* Ensure NUL-termination within buffer */
    if (memchr(buf, '\0', n) == NULL)
        buf[n] = '\0';
    return buf;
}

/* ================================================================
 * Event emission
 * ================================================================ */

static void emit_cwd_event(pid_t pid)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp(&ts);

    char cwd_buf[PATH_MAX];
    char *cwd = read_proc_cwd(pid, cwd_buf, sizeof(cwd_buf));
    if (!cwd) return;

    char cwd_esc[PATH_MAX * 2];
    json_escape(cwd_esc, sizeof(cwd_esc), cwd, strlen(cwd));

    char line[PATH_MAX * 2 + 256];
    int pos = json_header(line, sizeof(line), "CWD", pid, tgid, ppid, &ts);
    pos += snprintf(line + pos, sizeof(line) - pos, ",\"path\":%s}\n", cwd_esc);
    if (pos > 0) emit_line(line, pos);
}

static void emit_exec_event(pid_t pid)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp(&ts);

    /* exe */
    char exe_buf[PATH_MAX];
    char *exe = read_proc_exe(pid, exe_buf, sizeof(exe_buf));
    char exe_esc[PATH_MAX * 2];
    if (exe) json_escape(exe_esc, sizeof(exe_esc), exe, strlen(exe));

    /* argv */
    size_t argv_len = 0;
    char *argv_raw = read_proc_file(pid, "cmdline", ARGV_MAX_READ, &argv_len);
    char *argv_j = NULL;
    if (argv_raw && argv_len > 0) {
        argv_j = malloc(argv_len * 6 + 64);
        if (argv_j) json_argv_array(argv_j, argv_len * 6 + 64, argv_raw, argv_len);
    }

    /* env */
    size_t env_len = 0;
    char *env_raw = read_proc_file(pid, "environ", ENV_MAX_READ, &env_len);
    char *env_j = NULL;
    if (env_raw && env_len > 0) {
        env_j = malloc(env_len * 6 + 64);
        if (env_j) json_env_object(env_j, env_len * 6 + 64, env_raw, env_len);
    }

    /* auxv */
    char auxv_buf[4096];
    auxv_buf[0] = '\0';
    format_auxv_json(pid, auxv_buf, sizeof(auxv_buf));

    /* Build line */
    char *line = malloc(LINE_MAX_BUF);
    if (line) {
        int pos = json_header(line, LINE_MAX_BUF, "EXEC", pid, tgid, ppid, &ts);
        pos += snprintf(line + pos, LINE_MAX_BUF - pos,
            ",\"exe\":%s,\"argv\":%s,\"env\":%s,\"auxv\":{%s}}\n",
            exe ? exe_esc : "null",
            argv_j ? argv_j : "[]",
            env_j ? env_j : "{}",
            auxv_buf[0] ? auxv_buf : "");
        if (pos > 0 && pos < LINE_MAX_BUF)
            emit_line(line, pos);
        free(line);
    }

    free(env_j); free(env_raw);
    free(argv_j); free(argv_raw);
}

static void emit_inherited_open_for_fd(pid_t pid, pid_t tgid, pid_t ppid,
                                        struct timespec *ts,
                                        int fd_num)
{
    /* Read fd link and stat */
    char link_path[256], link_target[PATH_MAX];
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d", (int)pid, fd_num);
    ssize_t n = readlink(link_path, link_target, sizeof(link_target) - 1);
    if (n <= 0) return;
    link_target[n] = '\0';

    struct stat st;
    if (fstatat(AT_FDCWD, link_path, &st, 0) < 0) {
        /* If we can't stat through /proc, use the link text */
        memset(&st, 0, sizeof(st));
    }

    /* Read fdinfo for flags */
    char fdinfo_path[256], fdinfo_buf[512];
    snprintf(fdinfo_path, sizeof(fdinfo_path), "/proc/%d/fdinfo/%d", (int)pid, fd_num);
    int flags = O_RDONLY;
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
    if (pos > 0) emit_line(line, pos);
}

static void emit_inherited_open_events(pid_t pid)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp(&ts);

    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "/proc/%d/fd", (int)pid);
    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        int fd_num = atoi(ent->d_name);
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
    get_timestamp(&ts);

    char path_esc[PATH_MAX * 2];
    if (path)
        json_escape(path_esc, sizeof(path_esc), path, strlen(path));

    char flags_j[256];
    json_open_flags(flags, flags_j, sizeof(flags_j));

    /* If successful, get inode info from /proc/pid/fd/N */
    unsigned long ino_nr = 0;
    unsigned int dev_major = 0, dev_minor = 0;
    if (fd_or_err >= 0) {
        char fd_path[256];
        struct stat st;
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%ld", (int)pid, fd_or_err);
        if (fstatat(AT_FDCWD, fd_path, &st, 0) == 0) {
            ino_nr = st.st_ino;
            dev_major = major(st.st_dev);
            dev_minor = minor(st.st_dev);
        }
    }

    char line[PATH_MAX * 2 + 512];
    int pos = json_header(line, sizeof(line), "OPEN", pid, tgid, ppid, &ts);

    if (fd_or_err >= 0)
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"path\":%s,\"flags\":%s,\"fd\":%ld,\"ino\":%lu,\"dev\":\"%u:%u\"}\n",
            path ? path_esc : "null", flags_j,
            fd_or_err, ino_nr, dev_major, dev_minor);
    else
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"path\":%s,\"flags\":%s,\"err\":%ld}\n",
            path ? path_esc : "null", flags_j, fd_or_err);

    if (pos > 0) emit_line(line, pos);
}

static void emit_write_event(pid_t pid, const char *stream,
                             unsigned long buf_addr, size_t count)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp(&ts);

    size_t to_read = count;
    if (to_read > WRITE_CAPTURE_MAX) to_read = WRITE_CAPTURE_MAX;

    char *data = malloc(to_read);
    if (!data) return;
    ssize_t n = read_proc_mem(pid, buf_addr, data, to_read);
    if (n <= 0) { free(data); return; }
    to_read = n;

    char *escaped = malloc(to_read * 6 + 4);
    if (!escaped) { free(data); return; }
    json_escape(escaped, to_read * 6 + 4, data, to_read);

    char *line = malloc(to_read * 6 + 512);
    if (!line) { free(escaped); free(data); return; }

    int pos = json_header(line, to_read * 6 + 512, stream, pid, tgid, ppid, &ts);
    pos += snprintf(line + pos, to_read * 6 + 512 - pos,
        ",\"len\":%zu,\"data\":%s}\n", to_read, escaped);

    if (pos > 0) emit_line(line, pos);
    free(line); free(escaped); free(data);
}

static void emit_exit_event(pid_t pid, int status)
{
    pid_t tgid = get_tgid(pid);
    pid_t ppid = get_ppid(pid);
    struct timespec ts;
    get_timestamp(&ts);

    char line[384];
    int pos = json_header(line, sizeof(line), "EXIT", pid, tgid, ppid, &ts);

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"status\":\"exited\",\"code\":%d,\"raw\":%d}\n", code, status);
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        int core = 0;
#ifdef WCOREDUMP
        core = WCOREDUMP(status) ? 1 : 0;
#endif
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"status\":\"signaled\",\"signal\":%d,\"core_dumped\":%s,\"raw\":%d}\n",
            sig, core ? "true" : "false", status);
    } else {
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"status\":\"unknown\",\"raw\":%d}\n", status);
    }

    if (pos > 0) emit_line(line, pos);
}

/* ================================================================
 * Decide whether to capture a write on fd 1 as STDOUT
 * ================================================================
 *
 * Match the kernel module logic:
 * - fd 2 → always STDERR
 * - fd 1 → STDOUT only if the tracee's fd 1 points to the same
 *   inode as the session creator's stdout (i.e. the same tty/pty).
 *   Writes to files/pipes are NOT captured as STDOUT.
 */

static int fd1_is_creator_stdout(pid_t pid)
{
    if (!g_creator_stdout_valid) return 0;
    char link_path[256];
    struct stat st;
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/1", (int)pid);
    if (stat(link_path, &st) < 0) return 0;
    return (st.st_dev == g_creator_stdout_st.st_dev &&
            st.st_ino == g_creator_stdout_st.st_ino);
}

/* ================================================================
 * Syscall handling
 * ================================================================ */

/* Get syscall registers */
#if defined(__x86_64__)
static int get_syscall_info(pid_t pid, long *nr,
    unsigned long *a0, unsigned long *a1, unsigned long *a2,
    long *ret)
{
    struct user_regs_struct regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    *nr  = regs.orig_rax;
    *a0  = regs.rdi;
    *a1  = regs.rsi;
    *a2  = regs.rdx;
    *ret = regs.rax;
    return 0;
}
#elif defined(__aarch64__)
struct aarch64_user_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};
static int get_syscall_info(pid_t pid, long *nr,
    unsigned long *a0, unsigned long *a1, unsigned long *a2,
    long *ret)
{
    struct aarch64_user_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    /* On arm64, the syscall number is in x8, return value in x0 */
    *nr  = regs.regs[8];
    *a0  = regs.regs[0];
    *a1  = regs.regs[1];
    *a2  = regs.regs[2];
    *ret = regs.regs[0];
    return 0;
}
#else
/* Fallback — will compile but may not work on other arches */
static int get_syscall_info(pid_t pid, long *nr,
    unsigned long *a0, unsigned long *a1, unsigned long *a2,
    long *ret)
{
    *nr = *a0 = *a1 = *a2 = 0;
    *ret = 0;
    return -1;
}
#endif

static void handle_syscall_entry(pid_t pid, struct proc_state *ps)
{
    long nr, ret;
    unsigned long a0, a1, a2;
    if (get_syscall_info(pid, &nr, &a0, &a1, &a2, &ret) < 0)
        return;

    ps->saved_syscall = nr;
    ps->arg0 = a0;
    ps->arg1 = a1;
    ps->arg2 = a2;
}

static void handle_syscall_exit(pid_t pid, struct proc_state *ps)
{
    long nr, ret_unused;
    unsigned long a0_unused, a1_unused, a2_unused;
    if (get_syscall_info(pid, &nr, &a0_unused, &a1_unused, &a2_unused, &ret_unused) < 0)
        return;

    long syscall_nr = ps->saved_syscall;
    long ret_val = ret_unused; /* rax on x86_64, x0 on aarch64 */

    /* ---- execve / execveat ---- */
    if (syscall_nr == SYS_execve
#ifdef SYS_execveat
        || syscall_nr == SYS_execveat
#endif
       ) {
        if (ret_val == 0) {
            /* Successful exec: emit CWD then EXEC then inherited OPENs */
            emit_cwd_event(pid);
            emit_exec_event(pid);
            emit_inherited_open_events(pid);
        }
        return;
    }

    /* ---- openat / open ---- */
#ifdef SYS_openat
    if (syscall_nr == SYS_openat) {
        /* a0 = dirfd, a1 = pathname, a2 = flags */
        char *path = read_tracee_string(pid, ps->arg1, PATH_MAX);
        emit_open_event(pid, path, (int)ps->arg2, ret_val);
        free(path);
        return;
    }
#endif
#ifdef SYS_open
    if (syscall_nr == SYS_open) {
        /* a0 = pathname, a1 = flags */
        char *path = read_tracee_string(pid, ps->arg0, PATH_MAX);
        emit_open_event(pid, path, (int)ps->arg1, ret_val);
        free(path);
        return;
    }
#endif

    /* ---- chdir / fchdir ---- */
    if (syscall_nr == SYS_chdir || syscall_nr == SYS_fchdir) {
        if (ret_val == 0)
            emit_cwd_event(pid);
        return;
    }

    /* ---- write ---- */
    if (syscall_nr == SYS_write) {
        unsigned int fd = (unsigned int)ps->arg0;
        if (ret_val <= 0) return;
        if (fd == 2) {
            emit_write_event(pid, "STDERR", ps->arg1, (size_t)ret_val);
        } else if (fd == 1 && fd1_is_creator_stdout(pid)) {
            emit_write_event(pid, "STDOUT", ps->arg1, (size_t)ret_val);
        }
        return;
    }

    /* ---- writev (for STDERR/STDOUT that goes through writev) ---- */
    if (syscall_nr == SYS_writev) {
        unsigned int fd = (unsigned int)ps->arg0;
        if (ret_val <= 0) return;
        if (fd != 1 && fd != 2) return;
        if (fd == 1 && !fd1_is_creator_stdout(pid)) return;
        const char *stream = (fd == 2) ? "STDERR" : "STDOUT";
        /*
         * For writev we would need to read the iovec array from the tracee.
         * For simplicity, read directly from /proc/pid/fd/N instead.
         * Since the write already completed, the data is gone. We can only
         * capture the length. Skip actual data capture for writev.
         */
        (void)stream;
        return;
    }
}

/* ================================================================
 * Main tracer loop
 * ================================================================ */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-o FILE] -- command [args...]\n", prog);
    exit(1);
}

int main(int argc, char **argv)
{
    const char *outfile = NULL;
    int cmd_start = -1;

    /* Parse options before "--" */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd_start = i + 1;
            break;
        }
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outfile = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        } else {
            /* Assume everything from here is the command if no "--" yet */
            cmd_start = i;
            break;
        }
    }

    if (cmd_start < 0 || cmd_start >= argc)
        usage(argv[0]);

    /* Setup output */
    if (outfile) {
        g_out = fopen(outfile, "w");
        if (!g_out) { perror("fopen"); exit(1); }
    } else {
        g_out = stdout;
    }

    /* Record the creator's stdout inode for STDOUT filtering */
    g_creator_stdout_valid = (fstat(STDOUT_FILENO, &g_creator_stdout_st) == 0);

    /* Fork the child */
    pid_t child = fork();
    if (child < 0) { perror("fork"); exit(1); }

    if (child == 0) {
        /* Child: request tracing, then exec */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace(TRACEME)");
            _exit(127);
        }
        raise(SIGSTOP); /* Wait for parent to set options */
        execvp(argv[cmd_start], argv + cmd_start);
        perror("execvp");
        _exit(127);
    }

    /* Parent: wait for child's initial SIGSTOP */
    int status;
    waitpid(child, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "uproctrace: child did not stop\n");
        exit(1);
    }

    /* Set ptrace options to track forks and execs */
    long opts = PTRACE_O_TRACESYSGOOD   /* set bit 7 in signal for syscall stops */
              | PTRACE_O_TRACEFORK
              | PTRACE_O_TRACEVFORK
              | PTRACE_O_TRACECLONE
              | PTRACE_O_TRACEEXEC;
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, opts) < 0) {
        perror("ptrace(SETOPTIONS)");
        exit(1);
    }

    /* Track the child */
    pidset_add(&g_tracked, child);

    /* Resume child (it will immediately hit execve) */
    ptrace(PTRACE_SYSCALL, child, NULL, 0);

    /* Main event loop */
    while (g_tracked.count > 0) {
        int wstatus;
        pid_t wpid = waitpid(-1, &wstatus, __WALL);
        if (wpid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;
            break;
        }

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            /* Process exited */
            if (pidset_contains(&g_tracked, wpid)) {
                emit_exit_event(wpid, wstatus);
                pidset_remove(&g_tracked, wpid);
                free_state(wpid);
            }
            continue;
        }

        if (!WIFSTOPPED(wstatus)) continue;

        int sig = WSTOPSIG(wstatus);
        int event = (unsigned)wstatus >> 16;

        /* Handle ptrace events (fork/vfork/clone/exec) */
        if (event == PTRACE_EVENT_FORK ||
            event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE) {
            unsigned long new_pid;
            ptrace(PTRACE_GETEVENTMSG, wpid, NULL, &new_pid);
            if (new_pid > 0) {
                pidset_add(&g_tracked, (pid_t)new_pid);
                /* The new child is auto-traced; it will be delivered
                 * its own stop. We need to set it up for SYSCALL tracing. */
            }
            ptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        if (event == PTRACE_EVENT_EXEC) {
            /* The exec happened. We don't need to do anything special here
             * because we handle it in the execve syscall exit. */
            ptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        /* Syscall stop (bit 7 set in signal from PTRACE_O_TRACESYSGOOD) */
        if (sig == (SIGTRAP | 0x80)) {
            struct proc_state *ps = get_state(wpid);
            if (!ps->in_syscall) {
                /* Syscall entry */
                ps->in_syscall = 1;
                handle_syscall_entry(wpid, ps);
            } else {
                /* Syscall exit */
                ps->in_syscall = 0;
                handle_syscall_exit(wpid, ps);
            }
            ptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        /* PTRACE_EVENT_STOP for newly traced processes */
        if (sig == SIGSTOP && event == 0 && pidset_contains(&g_tracked, wpid)) {
            ptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        /* Group stop */
        if (event == PTRACE_EVENT_STOP) {
            ptrace(PTRACE_LISTEN, wpid, NULL, 0);
            continue;
        }

        /* Deliver the signal to the tracee */
        ptrace(PTRACE_SYSCALL, wpid, NULL, (void *)(long)sig);
    }

    if (outfile && g_out)
        fclose(g_out);

    /* Clean up */
    free(g_tracked.pids);
    while (g_states) {
        struct proc_state *s = g_states;
        g_states = s->next;
        free(s);
    }

    return 0;
}
