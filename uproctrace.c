/*
 * uproctrace.c — Userspace process tracer using ptrace.
 *
 * Produces the same JSONL event stream as proctrace.c (kernel module),
 * but runs entirely in userspace via PTRACE.  Meant to be accessible
 * in environments where loading a kernel module is impractical.
 *
 * Built into the tv binary.  Invoked as:
 *   tv --uproctrace [-o FILE] -- command [args...]
 *
 * Events emitted: CWD, EXEC, OPEN (real + inherited), EXIT, STDOUT, STDERR.
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
#include <sys/prctl.h>
#include <linux/ptrace.h>
#include <elf.h>          /* AT_* constants, ElfW, NT_PRSTATUS */
#include <pthread.h>

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_OFF
#define PR_SYS_DISPATCH_OFF 0
#endif

/* ================================================================
 * Constants
 * ================================================================ */

#define WRITE_CAPTURE_MAX   4096
#define ARGV_MAX_READ       32768
#define ENV_MAX_READ        65536
#define LINE_MAX_BUF        (PATH_MAX * 8 + 262144 + 1024)
#define TRACE_OUT_RING_SIZE (1 << 20)
#define TRACE_OUT_CHUNK_SIZE (1 << 16)

/* ================================================================
 * Output stream
 * ================================================================ */

struct trace_output {
    FILE *stream;
    int owns_stream;
    int error;
    int closing;
    pid_t compressor_pid;
    char *ring;
    size_t ring_size;
    size_t head;
    size_t tail;
    size_t used;
    pthread_t writer;
    pthread_mutex_t lock;
    pthread_cond_t can_read;
    pthread_cond_t can_write;
};

static struct trace_output g_out;
static struct stat g_creator_stdout_st; /* stat of the session creator's stdout */
static int g_creator_stdout_valid;
static int g_trace_exec_env = 1;

static int path_has_suffix(const char *path, const char *suffix)
{
    size_t path_len, suffix_len;
    if (!path || !suffix) return 0;
    path_len = strlen(path);
    suffix_len = strlen(suffix);
    return path_len >= suffix_len && strcmp(path + path_len - suffix_len, suffix) == 0;
}

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

static int trace_output_write_plain(struct trace_output *out, const char *buf, size_t len)
{
    return fwrite(buf, 1, len, out->stream) == len ? 0 : -1;
}

static void *trace_output_writer_main(void *arg)
{
    struct trace_output *out = arg;
    char *chunk = malloc(TRACE_OUT_CHUNK_SIZE);
    if (!chunk) {
        pthread_mutex_lock(&out->lock);
        out->error = 1;
        pthread_cond_broadcast(&out->can_read);
        pthread_cond_broadcast(&out->can_write);
        pthread_mutex_unlock(&out->lock);
        return NULL;
    }

    for (;;) {
        size_t n = 0;

        pthread_mutex_lock(&out->lock);
        while (out->used == 0 && !out->closing && !out->error)
            pthread_cond_wait(&out->can_read, &out->lock);
        if (out->error) {
            pthread_mutex_unlock(&out->lock);
            break;
        }
        if (out->used == 0 && out->closing) {
            pthread_mutex_unlock(&out->lock);
            break;
        }

        n = out->ring_size - out->tail;
        if (n > out->used) n = out->used;
        if (n > TRACE_OUT_CHUNK_SIZE) n = TRACE_OUT_CHUNK_SIZE;
        memcpy(chunk, out->ring + out->tail, n);
        out->tail = (out->tail + n) % out->ring_size;
        out->used -= n;
        pthread_cond_signal(&out->can_write);
        pthread_mutex_unlock(&out->lock);

        if (trace_output_write_plain(out, chunk, n) != 0) {
            pthread_mutex_lock(&out->lock);
            out->error = 1;
            pthread_cond_broadcast(&out->can_read);
            pthread_cond_broadcast(&out->can_write);
            pthread_mutex_unlock(&out->lock);
            break;
        }
    }

    if (!out->error)
        fflush(out->stream);
    free(chunk);
    return NULL;
}

static int trace_output_enqueue(const char *buf, size_t len)
{
    struct trace_output *out = &g_out;

    if (!out->ring || len == 0) return 0;
    if (len > out->ring_size) return -1;

    pthread_mutex_lock(&out->lock);
    while (!out->error && (out->ring_size - out->used) < len)
        pthread_cond_wait(&out->can_write, &out->lock);
    if (out->error) {
        pthread_mutex_unlock(&out->lock);
        return -1;
    }

    size_t first = out->ring_size - out->head;
    if (first > len) first = len;
    memcpy(out->ring + out->head, buf, first);
    if (len > first)
        memcpy(out->ring, buf + first, len - first);
    out->head = (out->head + len) % out->ring_size;
    out->used += len;
    pthread_cond_signal(&out->can_read);
    pthread_mutex_unlock(&out->lock);
    return 0;
}

static int trace_output_enqueue_line(const char *line, size_t len)
{
    if (g_trace_exec_env || !line || len == 0)
        return trace_output_enqueue(line, len);

    if (!memmem(line, len, "\"event\":\"EXEC\"", strlen("\"event\":\"EXEC\""))
        || !memmem(line, len, ",\"env\":", strlen(",\"env\":")))
        return trace_output_enqueue(line, len);

    char *tmp = malloc(len + 1);
    if (!tmp)
        return -1;
    memcpy(tmp, line, len);
    tmp[len] = '\0';

    char *env = strstr(tmp, ",\"env\":");
    char *auxv = env ? strstr(env, ",\"auxv\":") : NULL;
    size_t out_len = len;
    if (env && auxv) {
        memmove(env, auxv, out_len - (size_t)(auxv - tmp) + 1);
        out_len -= (size_t)(auxv - env);
    }
    int rc = trace_output_enqueue(tmp, out_len);
    free(tmp);
    return rc;
}

static void emit_line(const char *line, size_t len)
{
    (void)trace_output_enqueue_line(line, len);
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
static int ensure_proc_mem_fd(pid_t pid);

static ssize_t read_proc_mem(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    int fd = ensure_proc_mem_fd(pid);
    if (fd < 0) return -1;
    return pread(fd, buf, len, (off_t)addr);
}

/* Write to a process's memory at a given address. */
static ssize_t write_proc_mem(pid_t pid, unsigned long addr, const void *buf, size_t len)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = pwrite(fd, buf, len, (off_t)addr);
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
    pid_t tgid;           /* thread group leader — cached at first sight */
    pid_t ppid;           /* cached parent pid */
    int   is_thread;      /* 1 if pid != tgid (a non-leader thread) */
    int   mem_fd;         /* cached /proc/pid/mem fd */
    int   in_syscall;     /* 1 if we're at syscall entry, 0 at exit */
    long  saved_syscall;  /* syscall number at entry */
    /* saved args for specific syscalls */
    unsigned long arg0, arg1, arg2, arg3;
    /* ptrace emulation */
    int   emu_neutralized; /* 1 if syscall was replaced with -1 for emulation */
    int   emu_waiting;     /* 1 if blocked in emulated wait4 */
    unsigned long emu_wait_wstatus_addr; /* wstatus pointer for emulated wait */
    long  emu_wait_pid;    /* pid arg for emulated wait */
    long  emu_wait_options;/* options arg for emulated wait */
    int   emu_race_interrupt; /* 1 if we injected SIGCHLD to break real wait4 */
    struct proc_state *next;
};

static struct proc_state *g_states = NULL;

static struct proc_state *get_state(pid_t pid)
{
    for (struct proc_state *s = g_states; s; s = s->next)
        if (s->pid == pid) return s;
    struct proc_state *s = calloc(1, sizeof(*s));
    s->pid = pid;
    /* Cache tgid at creation so it's available even after /proc disappears */
    s->tgid = get_tgid(pid);
    s->ppid = get_ppid(pid);
    s->is_thread = (s->tgid != pid);
    s->mem_fd = -1;
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
            if (tmp->mem_fd >= 0) close(tmp->mem_fd);
            free(tmp);
            return;
        }
        pp = &(*pp)->next;
    }
}

static int ensure_proc_mem_fd(pid_t pid)
{
    struct proc_state *ps = get_state(pid);
    char path[256];
    if (!ps) return -1;
    if (ps->mem_fd >= 0) return ps->mem_fd;
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    ps->mem_fd = open(path, O_RDONLY);
    return ps->mem_fd;
}

static void get_cached_ids(pid_t pid, pid_t *tgid, pid_t *ppid)
{
    struct proc_state *ps = get_state(pid);
    if (!ps) {
        *tgid = pid;
        *ppid = 0;
        return;
    }
    if (ps->tgid <= 0) ps->tgid = get_tgid(pid);
    if (ps->ppid <= 0) ps->ppid = get_ppid(pid);
    *tgid = ps->tgid > 0 ? ps->tgid : pid;
    *ppid = ps->ppid;
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
    pid_t tgid, ppid;
    struct timespec ts;
    get_cached_ids(pid, &tgid, &ppid);
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
    pid_t tgid, ppid;
    struct timespec ts;
    get_cached_ids(pid, &tgid, &ppid);
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
    char *env_raw = NULL;
    char *env_j = NULL;
    if (g_trace_exec_env) {
        size_t env_len = 0;
        env_raw = read_proc_file(pid, "environ", ENV_MAX_READ, &env_len);
        if (env_raw && env_len > 0) {
            env_j = malloc(env_len * 6 + 64);
            if (env_j) json_env_object(env_j, env_len * 6 + 64, env_raw, env_len);
        }
    }

    /* auxv */
    char auxv_buf[4096];
    auxv_buf[0] = '\0';
    format_auxv_json(pid, auxv_buf, sizeof(auxv_buf));

    /* Build line */
    char *line = malloc(LINE_MAX_BUF);
    if (line) {
        int pos = json_header(line, LINE_MAX_BUF, "EXEC", pid, tgid, ppid, &ts);
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
    pid_t tgid, ppid;
    struct timespec ts;
    get_cached_ids(pid, &tgid, &ppid);
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
    pid_t tgid, ppid;
    struct timespec ts;
    get_cached_ids(pid, &tgid, &ppid);
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
    pid_t tgid, ppid;
    struct timespec ts;
    get_cached_ids(pid, &tgid, &ppid);
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
    pid_t tgid, ppid;
    struct timespec ts;
    get_cached_ids(pid, &tgid, &ppid);
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
    unsigned long *a3, long *ret)
{
    struct user_regs_struct regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    *nr  = regs.orig_rax;
    *a0  = regs.rdi;
    *a1  = regs.rsi;
    *a2  = regs.rdx;
    *a3  = regs.r10;
    *ret = regs.rax;
    return 0;
}

static int set_syscall_nr(pid_t pid, long nr)
{
    struct user_regs_struct regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    regs.orig_rax = nr;
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

static int set_syscall_ret(pid_t pid, long ret)
{
    struct user_regs_struct regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    regs.rax = ret;
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
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
    unsigned long *a3, long *ret)
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
    *a3  = regs.regs[3];
    *ret = regs.regs[0];
    return 0;
}

static int set_syscall_nr(pid_t pid, long nr)
{
    struct aarch64_user_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    regs.regs[8] = nr;
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

static int set_syscall_ret(pid_t pid, long ret)
{
    struct aarch64_user_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    regs.regs[0] = ret;
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

#else
/* Fallback — will compile but may not work on other arches */
static int get_syscall_info(pid_t pid, long *nr,
    unsigned long *a0, unsigned long *a1, unsigned long *a2,
    unsigned long *a3, long *ret)
{
    *nr = *a0 = *a1 = *a2 = *a3 = 0;
    *ret = 0;
    return -1;
}
static int set_syscall_nr(pid_t pid, long nr)
{
    (void)pid; (void)nr; return -1;
}
static int set_syscall_ret(pid_t pid, long ret)
{
    (void)pid; (void)ret; return -1;
}
#endif

/* ================================================================
 * Ptrace emulation — data structures
 * ================================================================
 *
 * When a tracee calls ptrace() (e.g. fakeroot-ng, nested uproctrace),
 * we intercept the syscall, neutralise it (replace with -1 → ENOSYS),
 * and emulate the operation ourselves.  This allows multiple layers
 * of ptrace-based tools to run under a single real tracer.
 */

struct emu_tracee {
    pid_t pid;            /* the sub-tracee */
    pid_t tracer_pid;     /* the sub-tracer that thinks it owns this tracee */
    long  options;        /* PTRACE_O_xxx set by the sub-tracer */
    int   syscall_stop;   /* 1 = sub-tracer wants syscall-stops (PTRACE_SYSCALL) */
    int   stopped;        /* 1 = sub-tracee held, awaiting sub-tracer resume */
    int   stop_reported;  /* 1 = stop was delivered to sub-tracer via wait */
    int   wstatus;        /* synthetic wait-status for sub-tracer */
    long  event_msg;      /* GETEVENTMSG value (new child pid, etc.) */
    int   pending_sig;    /* signal to deliver when sub-tracer resumes */
    struct emu_tracee *next;
};

static struct emu_tracee *g_emu_tracees = NULL;

static struct emu_tracee *find_emu_tracee(pid_t pid)
{
    for (struct emu_tracee *t = g_emu_tracees; t; t = t->next)
        if (t->pid == pid) return t;
    return NULL;
}

static struct emu_tracee *find_emu_tracee_for(pid_t tracer, pid_t tracee)
{
    for (struct emu_tracee *t = g_emu_tracees; t; t = t->next)
        if (t->tracer_pid == tracer && t->pid == tracee) return t;
    return NULL;
}

static int is_emu_tracer(pid_t pid)
{
    for (struct emu_tracee *t = g_emu_tracees; t; t = t->next)
        if (t->tracer_pid == pid) return 1;
    return 0;
}

static struct emu_tracee *add_emu_tracee(pid_t tracee_pid, pid_t tracer_pid)
{
    struct emu_tracee *t = find_emu_tracee(tracee_pid);
    if (t) { t->tracer_pid = tracer_pid; return t; }
    t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->pid = tracee_pid;
    t->tracer_pid = tracer_pid;
    t->next = g_emu_tracees;
    g_emu_tracees = t;
    return t;
}

static void remove_emu_tracee(pid_t pid)
{
    struct emu_tracee **pp = &g_emu_tracees;
    while (*pp) {
        if ((*pp)->pid == pid) {
            struct emu_tracee *tmp = *pp;
            *pp = tmp->next;
            free(tmp);
            return;
        }
        pp = &(*pp)->next;
    }
}

/* Remove all sub-tracees belonging to a given sub-tracer. */
static void remove_emu_tracees_for(pid_t tracer_pid)
{
    struct emu_tracee **pp = &g_emu_tracees;
    while (*pp) {
        if ((*pp)->tracer_pid == tracer_pid) {
            struct emu_tracee *tmp = *pp;
            *pp = tmp->next;
            free(tmp);
        } else {
            pp = &(*pp)->next;
        }
    }
}

/* Find any un-reported stopped sub-tracee for a given sub-tracer. */
static struct emu_tracee *find_stopped_for(pid_t tracer, long wait_pid)
{
    for (struct emu_tracee *t = g_emu_tracees; t; t = t->next) {
        if (t->tracer_pid != tracer) continue;
        if (!t->stopped || t->stop_reported) continue;
        if (wait_pid == -1 || wait_pid == t->pid ||
            (wait_pid == 0 /* any in same pgid – approximate */))
            return t;
    }
    return NULL;
}

/* ================================================================
 * Ptrace emulation — deliver stop to a waiting sub-tracer
 * ================================================================ */

static void try_deliver_to_tracer(pid_t tracer_pid)
{
    struct proc_state *tps = get_state(tracer_pid);
    if (!tps->emu_waiting) {
        /* Race-condition path: the sub-tracer entered wait4 before
         * any sub-tracee existed, so the syscall was NOT neutralised.
         * If it is still blocked in the kernel we must interrupt it,
         * so that it returns a syscall-exit-stop we can hijack.
         *
         * PTRACE_INTERRUPT only works for PTRACE_SEIZE-attached processes,
         * not for PTRACE_TRACEME.  Instead, inject a SIGCHLD via tgkill()
         * which will break the kernel's wait4 with -EINTR (or restart it).
         * We then get a signal-delivery-stop for SIGCHLD which we handle
         * specially (see main loop). */
#ifdef SYS_wait4
        if (tps->in_syscall && !tps->emu_neutralized &&
            tps->saved_syscall == SYS_wait4) {
            tps->emu_race_interrupt = 1;
            syscall(SYS_tgkill, tracer_pid, tracer_pid, SIGCHLD);
        }
#endif
        return;
    }

    struct emu_tracee *et = find_stopped_for(tracer_pid, tps->emu_wait_pid);
    if (!et) return;

    /* Write wstatus to the sub-tracer's address space */
    if (tps->emu_wait_wstatus_addr) {
        int wst = et->wstatus;
        write_proc_mem(tracer_pid, tps->emu_wait_wstatus_addr, &wst, sizeof(wst));
    }

    /* Set the return value to the stopped sub-tracee's pid */
    set_syscall_ret(tracer_pid, et->pid);

    et->stop_reported = 1;
    tps->emu_waiting = 0;

    /* Resume the sub-tracer */
    ptrace(PTRACE_SYSCALL, tracer_pid, NULL, 0);
}

/* ================================================================
 * Ptrace emulation — handle emulated ptrace() syscall
 * ================================================================
 *
 * Called at syscall-exit after we neutralised a SYS_ptrace.
 * Returns the value to place in the return register.
 */

static long emu_handle_ptrace(pid_t caller, unsigned long request,
                              unsigned long pid_arg, unsigned long addr,
                              unsigned long data)
{
    pid_t target = (pid_t)pid_arg;

    switch (request) {

    /* ---- PTRACE_TRACEME ---- */
    case PTRACE_TRACEME: {
        pid_t ppid = get_ppid(caller);
        if (ppid <= 0) return -ESRCH;
        add_emu_tracee(caller, ppid);
        return 0;
    }

    /* ---- PTRACE_SETOPTIONS ---- */
    case PTRACE_SETOPTIONS: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        et->options = (long)data;
        return 0;
    }

    /* ---- PTRACE_SYSCALL / PTRACE_CONT ---- */
    case PTRACE_SYSCALL:
    case PTRACE_CONT: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        et->syscall_stop = (request == PTRACE_SYSCALL) ? 1 : 0;
        int sig = (int)data;  /* signal to deliver */
        et->stopped = 0;
        et->stop_reported = 0;
        /* Actually resume the sub-tracee (we always use PTRACE_SYSCALL
         * for our own tracing; the syscall_stop flag controls whether
         * we also report stops to the sub-tracer). */
        ptrace(PTRACE_SYSCALL, target, NULL, (void *)(long)sig);
        return 0;
    }

    /* ---- PTRACE_DETACH ---- */
    case PTRACE_DETACH: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        int sig = (int)data;
        et->stopped = 0;
        et->stop_reported = 0;
        remove_emu_tracee(target);
        /* Resume normally */
        ptrace(PTRACE_SYSCALL, target, NULL, (void *)(long)sig);
        return 0;
    }

    /* ---- PTRACE_GETEVENTMSG ---- */
    case PTRACE_GETEVENTMSG: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        unsigned long msg = (unsigned long)et->event_msg;
        if (data)
            write_proc_mem(caller, data, &msg, sizeof(msg));
        return 0;
    }

    /* ---- PTRACE_GETREGS ---- */
    case PTRACE_GETREGS: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et || !et->stopped) return -ESRCH;
#if defined(__x86_64__)
        struct user_regs_struct regs;
        struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, target, NT_PRSTATUS, &iov) < 0)
            return -EIO;
        if (data)
            write_proc_mem(caller, data, &regs, sizeof(regs));
#else
        /* On non-x86_64, GETREGS may not be available; fall back. */
        return -EIO;
#endif
        return 0;
    }

    /* ---- PTRACE_SETREGS ---- */
    case PTRACE_SETREGS: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et || !et->stopped) return -ESRCH;
#if defined(__x86_64__)
        struct user_regs_struct regs;
        if (!data) return -EIO;
        if (read_proc_mem(caller, data, &regs, sizeof(regs)) < (ssize_t)sizeof(regs))
            return -EIO;
        struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
        if (ptrace(PTRACE_SETREGSET, target, NT_PRSTATUS, &iov) < 0)
            return -EIO;
#else
        return -EIO;
#endif
        return 0;
    }

    /* ---- PTRACE_GETREGSET ---- */
    case PTRACE_GETREGSET: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et || !et->stopped) return -ESRCH;
        if (!data) return -EIO;
        /* Read the iovec from the caller's address space */
        struct iovec caller_iov;
        if (read_proc_mem(caller, data, &caller_iov, sizeof(caller_iov))
                < (ssize_t)sizeof(caller_iov))
            return -EIO;
        /* Allocate a local buffer, do the real ptrace, write back */
        size_t bufsz = caller_iov.iov_len;
        if (bufsz > 4096) bufsz = 4096;
        void *buf = malloc(bufsz);
        if (!buf) return -ENOMEM;
        struct iovec local_iov = { .iov_base = buf, .iov_len = bufsz };
        if (ptrace(PTRACE_GETREGSET, target, addr, &local_iov) < 0) {
            free(buf);
            return -EIO;
        }
        write_proc_mem(caller, (unsigned long)caller_iov.iov_base, buf, local_iov.iov_len);
        /* Update iov_len in caller's iov to reflect actual size */
        caller_iov.iov_len = local_iov.iov_len;
        write_proc_mem(caller, data, &caller_iov, sizeof(caller_iov));
        free(buf);
        return 0;
    }

    /* ---- PTRACE_SETREGSET ---- */
    case PTRACE_SETREGSET: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et || !et->stopped) return -ESRCH;
        if (!data) return -EIO;
        struct iovec caller_iov;
        if (read_proc_mem(caller, data, &caller_iov, sizeof(caller_iov))
                < (ssize_t)sizeof(caller_iov))
            return -EIO;
        size_t bufsz = caller_iov.iov_len;
        if (bufsz > 4096) bufsz = 4096;
        void *buf = malloc(bufsz);
        if (!buf) return -ENOMEM;
        if (read_proc_mem(caller, (unsigned long)caller_iov.iov_base, buf, bufsz)
                < (ssize_t)bufsz) {
            free(buf);
            return -EIO;
        }
        struct iovec local_iov = { .iov_base = buf, .iov_len = bufsz };
        int rc = ptrace(PTRACE_SETREGSET, target, addr, &local_iov) < 0 ? -EIO : 0;
        free(buf);
        return rc;
    }

    /* ---- PTRACE_PEEKDATA / PTRACE_PEEKTEXT ---- */
    case PTRACE_PEEKDATA:
    case PTRACE_PEEKTEXT: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        errno = 0;
        long val = ptrace(PTRACE_PEEKDATA, target, (void *)addr, NULL);
        if (errno) return -errno;
        return val;
    }

    /* ---- PTRACE_POKEDATA / PTRACE_POKETEXT ---- */
    case PTRACE_POKEDATA:
    case PTRACE_POKETEXT: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        if (ptrace(PTRACE_POKEDATA, target, (void *)addr, (void *)data) < 0)
            return -errno;
        return 0;
    }

    /* ---- PTRACE_ATTACH ---- */
    case PTRACE_ATTACH: {
        /* Only allow attaching to processes we're already tracing */
        if (!pidset_contains(&g_tracked, target)) return -EPERM;
        add_emu_tracee(target, caller);
        /* The target will receive a SIGSTOP; we'll queue it. */
        kill(target, SIGSTOP);
        return 0;
    }

    /* ---- PTRACE_KILL ---- */
#ifdef PTRACE_KILL
    case PTRACE_KILL: {
        struct emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        kill(target, SIGKILL);
        remove_emu_tracee(target);
        return 0;
    }
#endif

    default:
        /* Unsupported request — return EINVAL so the caller can cope */
        return -EINVAL;
    }
}

/* ================================================================
 * Ptrace emulation — handle emulated wait4() syscall
 * ================================================================
 *
 * Called at syscall-exit for a sub-tracer whose wait4 was neutralised.
 * Returns 1 if the caller should be held (not resumed) until a
 * sub-tracee stop becomes available, 0 otherwise.
 */

static int emu_handle_wait4(pid_t caller, struct proc_state *ps)
{
    long wpid_arg = (long)(int)ps->arg0; /* sign-extend pid_t */
    unsigned long wstatus_addr = ps->arg1;
    int options = (int)ps->arg2;

    /* Check for an already-stopped sub-tracee */
    struct emu_tracee *et = find_stopped_for(caller, wpid_arg);
    if (et) {
        if (wstatus_addr) {
            int wst = et->wstatus;
            write_proc_mem(caller, wstatus_addr, &wst, sizeof(wst));
        }
        set_syscall_ret(caller, et->pid);
        et->stop_reported = 1;
        return 0; /* resume caller */
    }

    if (options & WNOHANG) {
        set_syscall_ret(caller, 0);
        return 0;
    }

    /* No pending stop and blocking — hold the sub-tracer */
    ps->emu_waiting = 1;
    ps->emu_wait_wstatus_addr = wstatus_addr;
    ps->emu_wait_pid = wpid_arg;
    ps->emu_wait_options = options;
    return 1; /* hold caller */
}

/* ================================================================
 * Ptrace emulation — queue a stop for a sub-tracee
 * ================================================================
 *
 * Call this when a sub-tracee hits a stop that should be visible
 * to its sub-tracer (syscall stop, signal stop, ptrace event).
 */

static void emu_queue_stop(struct emu_tracee *et, int wstatus)
{
    et->stopped = 1;
    et->stop_reported = 0;
    et->wstatus = wstatus;
    try_deliver_to_tracer(et->tracer_pid);
}

static void handle_syscall_entry(pid_t pid, struct proc_state *ps)
{
    long nr, ret;
    unsigned long a0, a1, a2, a3;
    if (get_syscall_info(pid, &nr, &a0, &a1, &a2, &a3, &ret) < 0)
        return;

    ps->saved_syscall = nr;
    ps->arg0 = a0;
    ps->arg1 = a1;
    ps->arg2 = a2;
    ps->arg3 = a3;
    ps->emu_neutralized = 0;

    /* ---- Intercept ptrace() syscall ---- */
    if (nr == SYS_ptrace) {
        set_syscall_nr(pid, -1);   /* neutralise → kernel returns -ENOSYS */
        ps->emu_neutralized = 1;
        return;
    }

    /* ---- Intercept wait4() from sub-tracers ---- */
#ifdef SYS_wait4
    if (nr == SYS_wait4 && is_emu_tracer(pid)) {
        set_syscall_nr(pid, -1);
        ps->emu_neutralized = 1;
        return;
    }
#endif
#ifdef SYS_waitid
    if (nr == SYS_waitid && is_emu_tracer(pid)) {
        set_syscall_nr(pid, -1);
        ps->emu_neutralized = 1;
        return;
    }
#endif
}

/*
 * handle_syscall_exit — returns 1 if the pid should be held (not resumed).
 */
static int handle_syscall_exit(pid_t pid, struct proc_state *ps)
{
    long nr, ret_unused;
    unsigned long a0_unused, a1_unused, a2_unused, a3_unused;
    if (get_syscall_info(pid, &nr, &a0_unused, &a1_unused, &a2_unused, &a3_unused, &ret_unused) < 0)
        return 0;

    /* ---- Handle emulated (neutralised) syscalls ---- */
    if (ps->emu_neutralized) {
        if (ps->saved_syscall == SYS_ptrace) {
            long result = emu_handle_ptrace(pid, ps->arg0, ps->arg1,
                                            ps->arg2, ps->arg3);
            set_syscall_ret(pid, result);
            return 0;
        }
#ifdef SYS_wait4
        if (ps->saved_syscall == SYS_wait4) {
            return emu_handle_wait4(pid, ps);
        }
#endif
#ifdef SYS_waitid
        if (ps->saved_syscall == SYS_waitid) {
            /* waitid has different arg layout but approximate with wait4 logic */
            return emu_handle_wait4(pid, ps);
        }
#endif
        return 0;
    }

    /* Race-condition path: wait4 was NOT neutralised (the process was not
     * yet a sub-tracer at syscall-entry) but became one before we got the
     * syscall-exit (e.g. child called TRACEME in the meantime, and we
     * interrupted this wait4 via PTRACE_INTERRUPT).  Handle it as emulated. */
#ifdef SYS_wait4
    if (ps->saved_syscall == SYS_wait4 && is_emu_tracer(pid)) {
        return emu_handle_wait4(pid, ps);
    }
#endif

    long syscall_nr = ps->saved_syscall;
    long ret_val = ret_unused; /* rax on x86_64, x0 on aarch64 */

    /* ---- execve / execveat ---- */
    if (syscall_nr == SYS_execve
#ifdef SYS_execveat
        || syscall_nr == SYS_execveat
#endif
       ) {
        if (ret_val == 0) {
            /* Successful exec: emit CWD then EXEC then inherited OPENs.
             * After exec, the thread becomes the new thread-group leader,
             * so update our cached tgid and clear is_thread. */
            ps->tgid = pid;
            ps->is_thread = 0;
            emit_cwd_event(pid);
            emit_exec_event(pid);
            emit_inherited_open_events(pid);
        }
        return 0;
    }

    /* ---- openat / open ---- */
#ifdef SYS_openat
    if (syscall_nr == SYS_openat) {
        /* a0 = dirfd, a1 = pathname, a2 = flags */
        char *path = read_tracee_string(pid, ps->arg1, PATH_MAX);
        emit_open_event(pid, path, (int)ps->arg2, ret_val);
        free(path);
        return 0;
    }
#endif
#ifdef SYS_open
    if (syscall_nr == SYS_open) {
        /* a0 = pathname, a1 = flags */
        char *path = read_tracee_string(pid, ps->arg0, PATH_MAX);
        emit_open_event(pid, path, (int)ps->arg1, ret_val);
        free(path);
        return 0;
    }
#endif

    /* ---- chdir / fchdir ---- */
    if (syscall_nr == SYS_chdir || syscall_nr == SYS_fchdir) {
        if (ret_val == 0)
            emit_cwd_event(pid);
        return 0;
    }

    /* ---- write ---- */
    if (syscall_nr == SYS_write) {
        unsigned int fd = (unsigned int)ps->arg0;
        if (ret_val <= 0) return 0;
        if (fd == 2) {
            emit_write_event(pid, "STDERR", ps->arg1, (size_t)ret_val);
        } else if (fd == 1 && fd1_is_creator_stdout(pid)) {
            emit_write_event(pid, "STDOUT", ps->arg1, (size_t)ret_val);
        }
        return 0;
    }

    /* ---- writev (for STDERR/STDOUT that goes through writev) ---- */
    if (syscall_nr == SYS_writev) {
        unsigned int fd = (unsigned int)ps->arg0;
        if (ret_val <= 0) return 0;
        if (fd != 1 && fd != 2) return 0;
        if (fd == 1 && !fd1_is_creator_stdout(pid)) return 0;
        const char *stream = (fd == 2) ? "STDERR" : "STDOUT";
        /*
         * For writev we would need to read the iovec array from the tracee.
         * For simplicity, read directly from /proc/pid/fd/N instead.
         * Since the write already completed, the data is gone. We can only
         * capture the length. Skip actual data capture for writev.
         */
        (void)stream;
        return 0;
    }

    return 0;
}

/* ================================================================
 * Main tracer loop
 * ================================================================ */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-o FILE[.zst]] [--no-env] [--backend auto|module|sud|ptrace] [--module|--sud|--ptrace] -- command [args...]\n",
            prog);
    exit(1);
}

enum trace_backend {
    TRACE_BACKEND_AUTO = 0,
    TRACE_BACKEND_MODULE,
    TRACE_BACKEND_SUD,
    TRACE_BACKEND_PTRACE,
};

static const char *trace_backend_name(enum trace_backend backend)
{
    switch (backend) {
    case TRACE_BACKEND_MODULE: return "module";
    case TRACE_BACKEND_SUD:    return "sud";
    case TRACE_BACKEND_PTRACE: return "ptrace";
    default:                   return "auto";
    }
}

static int parse_trace_backend(const char *name, enum trace_backend *backend)
{
    if (strcmp(name, "auto") == 0) *backend = TRACE_BACKEND_AUTO;
    else if (strcmp(name, "module") == 0) *backend = TRACE_BACKEND_MODULE;
    else if (strcmp(name, "sud") == 0) *backend = TRACE_BACKEND_SUD;
    else if (strcmp(name, "ptrace") == 0) *backend = TRACE_BACKEND_PTRACE;
    else return -1;
    return 0;
}

static int resolve_self_exe(char *buf, size_t bufsz)
{
    ssize_t n = readlink("/proc/self/exe", buf, bufsz - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return 0;
}

static int resolve_sudtrace_exe(char *buf, size_t bufsz)
{
    char self_exe[PATH_MAX];
    if (resolve_self_exe(self_exe, sizeof(self_exe)) == 0) {
        char *slash = strrchr(self_exe, '/');
        if (slash) {
            int len = snprintf(buf, bufsz, "%.*s/sudtrace",
                               (int)(slash - self_exe), self_exe);
            if (len > 0 && (size_t)len < bufsz && access(buf, X_OK) == 0)
                return 0;
        }
    }
    if (snprintf(buf, bufsz, "%s", "sudtrace") >= (int)bufsz)
        return -1;
    return access(buf, X_OK) == 0 ? 0 : -1;
}

static int kernel_supports_sud(void)
{
    errno = 0;
    return prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, 0, 0, 0) == 0;
}

static int kernel_supports_proctrace_module(void)
{
    int fd = open("/proc/proctrace/new", O_RDONLY);
    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

static int trace_output_uses_zstd(const char *outfile)
{
    return outfile && path_has_suffix(outfile, ".zst");
}

static int open_trace_output(const char *outfile)
{
    int want_zstd = trace_output_uses_zstd(outfile);
    memset(&g_out, 0, sizeof(g_out));
    g_out.ring_size = TRACE_OUT_RING_SIZE;
    g_out.ring = malloc(g_out.ring_size);
    if (!g_out.ring) {
        perror("malloc");
        return -1;
    }
    pthread_mutex_init(&g_out.lock, NULL);
    pthread_cond_init(&g_out.can_read, NULL);
    pthread_cond_init(&g_out.can_write, NULL);

    if (outfile && want_zstd) {
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            perror("pipe");
            free(g_out.ring);
            g_out.ring = NULL;
            return -1;
        }
        g_out.compressor_pid = fork();
        if (g_out.compressor_pid < 0) {
            perror("fork");
            close(pipefd[0]);
            close(pipefd[1]);
            free(g_out.ring);
            g_out.ring = NULL;
            return -1;
        }
        if (g_out.compressor_pid == 0) {
            if (dup2(pipefd[0], STDIN_FILENO) < 0) _exit(127);
            close(pipefd[0]);
            close(pipefd[1]);
            execlp("zstd", "zstd", "-q", "-T0", "-f", "-o", outfile, (char *)NULL);
            _exit(127);
        }
        close(pipefd[0]);
        g_out.stream = fdopen(pipefd[1], "wb");
        if (!g_out.stream) {
            perror("fdopen");
            close(pipefd[1]);
            waitpid(g_out.compressor_pid, NULL, 0);
            free(g_out.ring);
            g_out.ring = NULL;
            return -1;
        }
        g_out.owns_stream = 1;
    } else if (outfile) {
        g_out.stream = fopen(outfile, "wb");
        if (!g_out.stream) {
            perror("fopen");
            free(g_out.ring);
            g_out.ring = NULL;
            return -1;
        }
        g_out.owns_stream = 1;
    } else {
        g_out.stream = stdout;
        g_out.owns_stream = 0;
    }
    setvbuf(g_out.stream, NULL, _IOFBF, TRACE_OUT_RING_SIZE);
    if (pthread_create(&g_out.writer, NULL, trace_output_writer_main, &g_out) != 0) {
        perror("pthread_create");
        if (g_out.owns_stream) fclose(g_out.stream);
        if (g_out.compressor_pid > 0) waitpid(g_out.compressor_pid, NULL, 0);
        free(g_out.ring);
        g_out.ring = NULL;
        return -1;
    }
    return 0;
}

static int close_trace_output(const char *outfile)
{
    int rc = 0;
    if (!g_out.stream) return 0;

    pthread_mutex_lock(&g_out.lock);
    g_out.closing = 1;
    pthread_cond_broadcast(&g_out.can_read);
    pthread_mutex_unlock(&g_out.lock);
    pthread_join(g_out.writer, NULL);

    if (g_out.error) {
        fprintf(stderr, "uproctrace: trace output failed\n");
        rc = -1;
    }
    if (outfile && g_out.owns_stream && fclose(g_out.stream) != 0)
        rc = -1;
    else if (!outfile)
        fflush(g_out.stream);
    if (g_out.compressor_pid > 0) {
        int status;
        if (waitpid(g_out.compressor_pid, &status, 0) < 0
            || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            rc = -1;
    }
    pthread_cond_destroy(&g_out.can_read);
    pthread_cond_destroy(&g_out.can_write);
    pthread_mutex_destroy(&g_out.lock);
    free(g_out.ring);
    memset(&g_out, 0, sizeof(g_out));
    return rc;
}

static int copy_fd_to_output(int fd)
{
    char buf[8192];

    if (g_trace_exec_env) {
        for (;;) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n == 0) return 0;
            if (n < 0) {
                if (errno == EINTR) continue;
                perror("read");
                return -1;
            }
            if (trace_output_enqueue(buf, (size_t)n) != 0) {
                fprintf(stderr, "uproctrace: trace output queue failed\n");
                return -1;
            }
        }
    }

    char *pending = NULL;
    size_t pending_len = 0;
    size_t pending_cap = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("read");
            free(pending);
            return -1;
        }

        if (pending_len + (size_t)n + 1 > pending_cap) {
            size_t new_cap = pending_cap ? pending_cap : 8192;
            while (new_cap < pending_len + (size_t)n + 1)
                new_cap *= 2;
            char *tmp = realloc(pending, new_cap);
            if (!tmp) {
                perror("realloc");
                free(pending);
                return -1;
            }
            pending = tmp;
            pending_cap = new_cap;
        }
        memcpy(pending + pending_len, buf, (size_t)n);
        pending_len += (size_t)n;
        pending[pending_len] = '\0';

        size_t start = 0;
        while (start < pending_len) {
            char *nl = memchr(pending + start, '\n', pending_len - start);
            if (!nl) break;
            size_t line_len = (size_t)(nl - (pending + start)) + 1;
            if (trace_output_enqueue_line(pending + start, line_len) != 0) {
                fprintf(stderr, "uproctrace: trace output queue failed\n");
                free(pending);
                return -1;
            }
            start += line_len;
        }

        if (start > 0) {
            memmove(pending, pending + start, pending_len - start);
            pending_len -= start;
            pending[pending_len] = '\0';
        }
    }

    if (pending_len > 0 && trace_output_enqueue_line(pending, pending_len) != 0) {
        fprintf(stderr, "uproctrace: trace output queue failed\n");
        free(pending);
        return -1;
    }
    free(pending);
    return 0;
}

static int wait_for_child(pid_t child)
{
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            perror("waitpid");
            return 1;
        }
    }
    return 0;
}

static int run_module_trace(char **cmd, const char *outfile)
{
    int trace_fd = open("/proc/proctrace/new", O_RDONLY);
    if (trace_fd < 0)
        return -1;
    if (open_trace_output(outfile) < 0) {
        close(trace_fd);
        return 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        close(trace_fd);
        (void)close_trace_output(outfile);
        return 1;
    }
    if (child == 0) {
        execvp(cmd[0], cmd);
        perror(cmd[0]);
        _exit(127);
    }

    int rc = copy_fd_to_output(trace_fd);
    close(trace_fd);
    if (wait_for_child(child) != 0)
        rc = 1;
    if (close_trace_output(outfile) != 0)
        rc = 1;
    return rc == 0 ? 0 : 1;
}

static int build_exec_argv(char ***out_argv, const char *exe,
                           const char *outfile, int no_env, char **cmd)
{
    size_t cmdc = 0;
    while (cmd[cmdc]) cmdc++;

    size_t argc = 1 + (outfile ? 2 : 0) + (no_env ? 1 : 0) + 1 + cmdc + 1;
    char **sub_argv = calloc(argc, sizeof(*sub_argv));
    if (!sub_argv) {
        perror("calloc");
        return -1;
    }

    size_t i = 0;
    sub_argv[i++] = (char *)exe;
    if (outfile) {
        sub_argv[i++] = "-o";
        sub_argv[i++] = (char *)outfile;
    }
    if (no_env)
        sub_argv[i++] = "--no-env";
    sub_argv[i++] = "--";
    for (size_t j = 0; j < cmdc; j++)
        sub_argv[i++] = cmd[j];
    sub_argv[i] = NULL;

    *out_argv = sub_argv;
    return 0;
}

static int run_sud_trace(char **cmd, const char *outfile, const char *sudtrace_exe)
{
    if (trace_output_uses_zstd(outfile)) {
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            perror("pipe");
            return 1;
        }
        if (open_trace_output(outfile) < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            return 1;
        }
        pid_t child = fork();
        if (child < 0) {
            perror("fork");
            close(pipefd[0]);
            close(pipefd[1]);
            (void)close_trace_output(outfile);
            return 1;
        }
        if (child == 0) {
            char **sub_argv = NULL;
            close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
            close(pipefd[1]);
            if (build_exec_argv(&sub_argv, sudtrace_exe, NULL, !g_trace_exec_env, cmd) != 0)
                _exit(127);
            if (strchr(sudtrace_exe, '/'))
                execv(sudtrace_exe, sub_argv);
            else
                execvp(sudtrace_exe, sub_argv);
            perror("exec sudtrace");
            _exit(127);
        }
        close(pipefd[1]);
        int rc = copy_fd_to_output(pipefd[0]);
        close(pipefd[0]);
        if (wait_for_child(child) != 0)
            rc = 1;
        if (close_trace_output(outfile) != 0)
            rc = 1;
        return rc == 0 ? 0 : 1;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        char **sub_argv = NULL;
        if (build_exec_argv(&sub_argv, sudtrace_exe, outfile, !g_trace_exec_env, cmd) != 0)
            _exit(127);
        if (strchr(sudtrace_exe, '/'))
            execv(sudtrace_exe, sub_argv);
        else
            execvp(sudtrace_exe, sub_argv);
        perror("exec sudtrace");
        _exit(127);
    }
    return wait_for_child(child);
}

static int run_ptrace_trace(char **cmd, const char *outfile)
{
    if (open_trace_output(outfile) < 0)
        return 1;

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
        execvp(cmd[0], cmd);
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
            /* Process/thread exited */
            if (pidset_contains(&g_tracked, wpid)) {
                /* Only emit EXIT for thread-group leaders (pid == tgid),
                 * matching the kernel module's behaviour. */
                struct proc_state *eps = get_state(wpid);
                if (!eps->is_thread)
                    emit_exit_event(wpid, wstatus);
                pidset_remove(&g_tracked, wpid);
                free_state(wpid);
            }
            /* If this was a sub-tracee, queue the exit for its sub-tracer */
            struct emu_tracee *et = find_emu_tracee(wpid);
            if (et) {
                /* Synthesise an exit wstatus for the sub-tracer.
                 * The kernel's real wstatus is fine as-is. */
                emu_queue_stop(et, wstatus);
                /* Don't remove yet — sub-tracer needs to wait for it. */
            }
            /* If this was a sub-tracer, release all its sub-tracees */
            remove_emu_tracees_for(wpid);
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
            }

            /* If the forking process is a sub-tracee, check if the
             * sub-tracer wants this event and auto-attach the child. */
            struct emu_tracee *et = find_emu_tracee(wpid);
            if (et) {
                int want = 0;
                if (event == PTRACE_EVENT_FORK && (et->options & PTRACE_O_TRACEFORK)) want = 1;
                if (event == PTRACE_EVENT_VFORK && (et->options & PTRACE_O_TRACEVFORK)) want = 1;
                if (event == PTRACE_EVENT_CLONE && (et->options & PTRACE_O_TRACECLONE)) want = 1;

                if (want && new_pid > 0) {
                    /* Auto-attach new child as a sub-tracee */
                    struct emu_tracee *net = add_emu_tracee((pid_t)new_pid, et->tracer_pid);
                    if (net) {
                        net->options = et->options;
                        net->syscall_stop = et->syscall_stop;
                    }
                }

                if (want) {
                    et->event_msg = (long)new_pid;
                    int emu_wstatus = (SIGTRAP << 8) | (event << 16) | 0x7f;
                    emu_queue_stop(et, emu_wstatus);
                    /* Hold the sub-tracee */
                    continue;
                }
            }

            ptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        if (event == PTRACE_EVENT_EXEC) {
            /* If this is a sub-tracee, notify its sub-tracer */
            struct emu_tracee *et = find_emu_tracee(wpid);
            if (et && (et->options & PTRACE_O_TRACEEXEC)) {
                et->event_msg = (long)wpid;
                int emu_wstatus = (SIGTRAP << 8) | (PTRACE_EVENT_EXEC << 16) | 0x7f;
                emu_queue_stop(et, emu_wstatus);
                continue;  /* hold sub-tracee */
            }
            ptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        /* Syscall stop (bit 7 set in signal from PTRACE_O_TRACESYSGOOD) */
        if (sig == (SIGTRAP | 0x80)) {
            struct proc_state *ps = get_state(wpid);
            int hold = 0;
            if (!ps->in_syscall) {
                /* Syscall entry */
                ps->in_syscall = 1;
                handle_syscall_entry(wpid, ps);
            } else {
                /* Syscall exit */
                ps->in_syscall = 0;
                hold = handle_syscall_exit(wpid, ps);
            }

            /* After our tracing, check if this is a sub-tracee whose
             * sub-tracer wants syscall-stop reports. */
            if (!hold) {
                struct emu_tracee *et = find_emu_tracee(wpid);
                if (et && et->syscall_stop) {
                    /* Synthesise a syscall-stop for the sub-tracer */
                    int ss = (et->options & PTRACE_O_TRACESYSGOOD)
                             ? (SIGTRAP | 0x80) : SIGTRAP;
                    int emu_wstatus = (ss << 8) | 0x7f;
                    emu_queue_stop(et, emu_wstatus);
                    hold = 1;
                }
            }

            if (!hold)
                ptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        /* PTRACE_EVENT_STOP for newly traced processes */
        if (sig == SIGSTOP && event == 0 && pidset_contains(&g_tracked, wpid)) {
            /* If this process is a sub-tracee, queue the SIGSTOP for the
             * sub-tracer (the child's initial stop after TRACEME). */
            struct emu_tracee *et = find_emu_tracee(wpid);
            if (et) {
                int emu_wstatus = (SIGSTOP << 8) | 0x7f;
                emu_queue_stop(et, emu_wstatus);
                continue;  /* hold sub-tracee */
            }
            ptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        /* Group stop / PTRACE_INTERRUPT stop */
        if (event == PTRACE_EVENT_STOP) {
            /* PTRACE_INTERRUPT generates SIGTRAP; real group-stops use
             * SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU.  For interrupt stops we
             * must resume with PTRACE_SYSCALL (not PTRACE_LISTEN). */
            if (sig == SIGTRAP) {
                ptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            } else {
                ptrace(PTRACE_LISTEN, wpid, NULL, 0);
            }
            continue;
        }

        /* Signal delivery — if this is a sub-tracee, let the sub-tracer
         * decide whether to deliver the signal. */
        {
            /* Check for our injected SIGCHLD used to break a real wait4
             * (race-condition path).  Suppress it — don't deliver. */
            struct proc_state *sigps = get_state(wpid);
            if (sig == SIGCHLD && sigps->emu_race_interrupt) {
                sigps->emu_race_interrupt = 0;
                ptrace(PTRACE_SYSCALL, wpid, NULL, 0);
                continue;
            }

            struct emu_tracee *et = find_emu_tracee(wpid);
            if (et) {
                et->pending_sig = sig;
                int emu_wstatus = (sig << 8) | 0x7f;
                emu_queue_stop(et, emu_wstatus);
                continue;  /* hold sub-tracee until sub-tracer resumes */
            }
        }

        /* Deliver the signal to the tracee */
        ptrace(PTRACE_SYSCALL, wpid, NULL, (void *)(long)sig);
    }

    if (close_trace_output(outfile) != 0)
        return 1;

    /* Clean up */
    free(g_tracked.pids);
    while (g_states) {
        struct proc_state *s = g_states;
        g_states = s->next;
        if (s->mem_fd >= 0) close(s->mem_fd);
        free(s);
    }
    while (g_emu_tracees) {
        struct emu_tracee *t = g_emu_tracees;
        g_emu_tracees = t->next;
        free(t);
    }

    return 0;
}

int uproctrace_main(int argc, char **argv)
{
    const char *outfile = NULL;
    enum trace_backend requested = TRACE_BACKEND_AUTO;
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
        } else if (strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
            if (parse_trace_backend(argv[++i], &requested) != 0)
                usage(argv[0]);
        } else if (strncmp(argv[i], "--backend=", 10) == 0) {
            if (parse_trace_backend(argv[i] + 10, &requested) != 0)
                usage(argv[0]);
        } else if (strcmp(argv[i], "--module") == 0) {
            requested = TRACE_BACKEND_MODULE;
        } else if (strcmp(argv[i], "--sud") == 0) {
            requested = TRACE_BACKEND_SUD;
        } else if (strcmp(argv[i], "--ptrace") == 0) {
            requested = TRACE_BACKEND_PTRACE;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        } else {
            cmd_start = i;
            break;
        }
    }

    if (cmd_start < 0 || cmd_start >= argc)
        usage(argv[0]);

    char **cmd = argv + cmd_start;
    char sudtrace_exe[PATH_MAX];
    int have_module = kernel_supports_proctrace_module();
    int have_sud = resolve_sudtrace_exe(sudtrace_exe, sizeof(sudtrace_exe)) == 0 &&
                   kernel_supports_sud();

    enum trace_backend selected = requested;
    if (selected == TRACE_BACKEND_AUTO) {
        if (have_module) selected = TRACE_BACKEND_MODULE;
        else if (have_sud) selected = TRACE_BACKEND_SUD;
        else selected = TRACE_BACKEND_PTRACE;
    }

    switch (selected) {
    case TRACE_BACKEND_MODULE:
        if (!have_module) {
            fprintf(stderr, "uproctrace: requested backend '%s' is unavailable\n",
                    trace_backend_name(selected));
            return 1;
        }
        return run_module_trace(cmd, outfile);
    case TRACE_BACKEND_SUD:
        if (!have_sud) {
            fprintf(stderr, "uproctrace: requested backend '%s' is unavailable\n",
                    trace_backend_name(selected));
            return 1;
        }
        return run_sud_trace(cmd, outfile, sudtrace_exe);
    case TRACE_BACKEND_PTRACE:
        return run_ptrace_trace(cmd, outfile);
    case TRACE_BACKEND_AUTO:
    default:
        return run_ptrace_trace(cmd, outfile);
    }
}
