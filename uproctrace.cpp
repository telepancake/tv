/*
 * uproctrace.cpp — Userspace process tracer using ptrace (C++23 rewrite).
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <climits>
#include <cctype>
#include <cstdarg>
#include <ctime>

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <utility>
#include <algorithm>
#include <string_view>
#include <memory>
#include <new>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
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

/* C++ ptrace wrapper: glibc's C++ prototype wants __ptrace_request enum */
template <typename... Args>
static inline long xptrace(int req, Args... args) {
    return ptrace(static_cast<__ptrace_request>(req), args...);
}

/* ================================================================
 * Constants
 * ================================================================ */

static constexpr size_t WRITE_CAPTURE_MAX   = 4096;
static constexpr size_t ARGV_MAX_READ       = 32768;
static constexpr size_t ENV_MAX_READ        = 65536;
#define LINE_MAX_BUF        (PATH_MAX * 8 + 262144 + 1024)
static constexpr size_t TRACE_OUT_RING_SIZE = (1 << 20);
static constexpr size_t TRACE_OUT_CHUNK_SIZE = (1 << 16);

/* ================================================================
 * Output stream
 * ================================================================ */

struct trace_output {
    FILE *stream = nullptr;
    bool owns_stream = false;
    bool error = false;
    bool closing = false;
    pid_t compressor_pid = 0;
    std::unique_ptr<char[]> ring;
    size_t ring_size = 0;
    size_t head = 0;
    size_t tail = 0;
    size_t used = 0;
    pthread_t writer = {};
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t can_read = PTHREAD_COND_INITIALIZER;
    pthread_cond_t can_write = PTHREAD_COND_INITIALIZER;
};

static struct trace_output g_out;
static struct stat g_creator_stdout_st; /* stat of the session creator's stdout */
static int g_creator_stdout_valid;
static int g_trace_exec_env = 1;

static bool path_has_suffix(const char *path, const char *suffix)
{
    if (!path || !suffix) return false;
    std::string_view p(path);
    std::string_view s(suffix);
    return p.ends_with(s);
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
        unsigned char c = static_cast<unsigned char>(src[si]);
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
        const char *eq = static_cast<const char *>(std::memchr(entry, '=', entlen));
        int keylen, vallen;
        const char *val;
        if (eq) { keylen = static_cast<int>(eq - entry); val = eq + 1; vallen = entlen - keylen - 1; }
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
        static_cast<int>(pid), static_cast<int>(tgid), static_cast<int>(ppid),
        static_cast<int>(pid), static_cast<int>(tgid));
}

static int trace_output_write_plain(struct trace_output *out, const char *buf, size_t len)
{
    return fwrite(buf, 1, len, out->stream) == len ? 0 : -1;
}

static void *trace_output_writer_main(void *arg)
{
    struct trace_output *out = static_cast<struct trace_output *>(arg);
    std::unique_ptr<char[]> chunk(new(std::nothrow) char[TRACE_OUT_CHUNK_SIZE]);
    if (!chunk) {
        pthread_mutex_lock(&out->lock);
        out->error = true;
        pthread_cond_broadcast(&out->can_read);
        pthread_cond_broadcast(&out->can_write);
        pthread_mutex_unlock(&out->lock);
        return nullptr;
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
        std::memcpy(chunk.get(), out->ring.get() + out->tail, n);
        out->tail = (out->tail + n) % out->ring_size;
        out->used -= n;
        pthread_cond_signal(&out->can_write);
        pthread_mutex_unlock(&out->lock);

        if (trace_output_write_plain(out, chunk.get(), n) != 0) {
            pthread_mutex_lock(&out->lock);
            out->error = true;
            pthread_cond_broadcast(&out->can_read);
            pthread_cond_broadcast(&out->can_write);
            pthread_mutex_unlock(&out->lock);
            break;
        }
    }

    if (!out->error)
        fflush(out->stream);
    return nullptr;
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
    std::memcpy(out->ring.get() + out->head, buf, first);
    if (len > first)
        std::memcpy(out->ring.get(), buf + first, len - first);
    out->head = (out->head + len) % out->ring_size;
    out->used += len;
    pthread_cond_signal(&out->can_read);
    pthread_mutex_unlock(&out->lock);
    return 0;
}

static int trace_output_enqueue_line(const char *line, size_t len)
{
    static const char exec_marker[] = "\"event\":\"EXEC\"";
    static const char env_marker[] = ",\"env\":";

    if (!line || len == 0)
        return 0;
    if (g_trace_exec_env)
        return trace_output_enqueue(line, len);

    std::string tmp(line, len);

    if (tmp.find(exec_marker) == std::string::npos ||
        tmp.find(env_marker) == std::string::npos)
        return trace_output_enqueue(tmp.data(), tmp.size());

    auto env_pos = tmp.find(",\"env\":");
    auto auxv_pos = (env_pos != std::string::npos) ? tmp.find(",\"auxv\":", env_pos) : std::string::npos;
    if (env_pos != std::string::npos && auxv_pos != std::string::npos) {
        tmp.erase(env_pos, auxv_pos - env_pos);
    }
    return trace_output_enqueue(tmp.data(), tmp.size());
}

static void emit_line(const char *line, size_t len)
{
    (void)trace_output_enqueue_line(line, len);
}

/* ================================================================
 * /proc helpers
 * ================================================================ */

/* Read a whole /proc file into a std::string */
static std::string read_proc_file(pid_t pid, const char *name, size_t max)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/%s", static_cast<int>(pid), name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return {};
    std::string buf(max, '\0');
    size_t total = 0;
    ssize_t n;
    while (total < max && (n = read(fd, buf.data() + total, max - total)) > 0)
        total += static_cast<size_t>(n);
    close(fd);
    if (total == 0) return {};
    buf.resize(total);
    return buf;
}

/* Read /proc/PID/exe symlink */
static std::string read_proc_exe(pid_t pid)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/exe", static_cast<int>(pid));
    char buf[PATH_MAX];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    std::string_view sv(buf, static_cast<size_t>(n));
    if (sv.ends_with(" (deleted)"))
        sv.remove_suffix(10);
    return std::string(sv);
}

/* Read /proc/PID/cwd symlink */
static std::string read_proc_cwd(pid_t pid)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cwd", static_cast<int>(pid));
    char buf[PATH_MAX];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    return std::string(buf, static_cast<size_t>(n));
}

/* Get ppid from /proc/PID/stat */
static pid_t get_ppid(pid_t pid)
{
    char path[256], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", static_cast<int>(pid));
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    /* Format: pid (comm) state ppid ... */
    char *cp = std::strrchr(buf, ')');
    if (!cp) return 0;
    int ppid = 0;
    if (sscanf(cp + 2, "%*c %d", &ppid) != 1) return 0;
    return ppid;
}

/* Get tgid from /proc/PID/status */
static pid_t get_tgid(pid_t pid)
{
    char path[256], buf[2048];
    snprintf(path, sizeof(path), "/proc/%d/status", static_cast<int>(pid));
    int fd = open(path, O_RDONLY);
    if (fd < 0) return pid; /* fallback: assume tgid == pid */
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return pid;
    buf[n] = '\0';
    const char *p = std::strstr(buf, "\nTgid:");
    if (!p) return pid;
    return std::atoi(p + 6);
}

/* Read a process's memory at a given address. */
static int ensure_proc_mem_fd(pid_t pid);

static ssize_t read_proc_mem(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    int fd = ensure_proc_mem_fd(pid);
    if (fd < 0) return -1;
    return pread(fd, buf, len, static_cast<off_t>(addr));
}

/* Write to a process's memory at a given address. */
static ssize_t write_proc_mem(pid_t pid, unsigned long addr, const void *buf, size_t len)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", static_cast<int>(pid));
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = pwrite(fd, buf, len, static_cast<off_t>(addr));
    close(fd);
    return n;
}

/* Read /proc/PID/auxv and extract interesting entries */
static int format_auxv_json(pid_t pid, char *buf, int buflen)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/auxv", static_cast<int>(pid));
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
    my_auxv_t *av = reinterpret_cast<my_auxv_t *>(raw);
    int count = static_cast<int>(n / sizeof(my_auxv_t));
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
                size_t slen = std::strlen(u);
                char e[520];
                json_escape(e, sizeof(e), u, static_cast<int>(slen));
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
                size_t slen = std::strlen(u);
                char e[140];
                json_escape(e, sizeof(e), u, static_cast<int>(slen));
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
 * Tracked-pid set (std::vector)
 * ================================================================ */

static std::vector<pid_t> g_tracked;

static void pidset_add(pid_t pid)
{
    if (std::find(g_tracked.begin(), g_tracked.end(), pid) != g_tracked.end())
        return;
    g_tracked.push_back(pid);
}

static void pidset_remove(pid_t pid)
{
    auto it = std::find(g_tracked.begin(), g_tracked.end(), pid);
    if (it != g_tracked.end()) {
        *it = g_tracked.back();
        g_tracked.pop_back();
    }
}

static bool pidset_contains(pid_t pid)
{
    return std::find(g_tracked.begin(), g_tracked.end(), pid) != g_tracked.end();
}

/* ================================================================
 * Per-process state (for syscall entry/exit tracking)
 * ================================================================ */

struct proc_state {
    pid_t pid = 0;
    pid_t tgid = 0;           /* thread group leader — cached at first sight */
    pid_t ppid = 0;           /* cached parent pid */
    bool  is_thread = false;  /* true if pid != tgid (a non-leader thread) */
    int   mem_fd = -1;        /* cached /proc/pid/mem fd */
    bool  in_syscall = false; /* true if we're at syscall entry, false at exit */
    long  saved_syscall = 0;  /* syscall number at entry */
    /* saved args for specific syscalls */
    unsigned long arg0 = 0, arg1 = 0, arg2 = 0, arg3 = 0;
    /* ptrace emulation */
    bool  emu_neutralized = false; /* true if syscall was replaced with -1 for emulation */
    bool  emu_waiting = false;     /* true if blocked in emulated wait4 */
    unsigned long emu_wait_wstatus_addr = 0; /* wstatus pointer for emulated wait */
    long  emu_wait_pid = 0;    /* pid arg for emulated wait */
    long  emu_wait_options = 0;/* options arg for emulated wait */
    bool  emu_race_interrupt = false; /* true if we injected SIGCHLD to break real wait4 */

    ~proc_state() { if (mem_fd >= 0) ::close(mem_fd); }

    proc_state() = default;

    proc_state(proc_state&& o) noexcept
        : pid(o.pid), tgid(o.tgid), ppid(o.ppid), is_thread(o.is_thread),
          mem_fd(std::exchange(o.mem_fd, -1)), in_syscall(o.in_syscall),
          saved_syscall(o.saved_syscall),
          arg0(o.arg0), arg1(o.arg1), arg2(o.arg2), arg3(o.arg3),
          emu_neutralized(o.emu_neutralized), emu_waiting(o.emu_waiting),
          emu_wait_wstatus_addr(o.emu_wait_wstatus_addr),
          emu_wait_pid(o.emu_wait_pid), emu_wait_options(o.emu_wait_options),
          emu_race_interrupt(o.emu_race_interrupt)
    {}

    proc_state& operator=(proc_state&& o) noexcept {
        if (this != &o) {
            if (mem_fd >= 0) ::close(mem_fd);
            pid = o.pid; tgid = o.tgid; ppid = o.ppid;
            is_thread = o.is_thread;
            mem_fd = std::exchange(o.mem_fd, -1);
            in_syscall = o.in_syscall;
            saved_syscall = o.saved_syscall;
            arg0 = o.arg0; arg1 = o.arg1; arg2 = o.arg2; arg3 = o.arg3;
            emu_neutralized = o.emu_neutralized;
            emu_waiting = o.emu_waiting;
            emu_wait_wstatus_addr = o.emu_wait_wstatus_addr;
            emu_wait_pid = o.emu_wait_pid;
            emu_wait_options = o.emu_wait_options;
            emu_race_interrupt = o.emu_race_interrupt;
        }
        return *this;
    }

    proc_state(const proc_state&) = delete;
    proc_state& operator=(const proc_state&) = delete;
};

static std::unordered_map<pid_t, proc_state> g_states;

static proc_state *get_state(pid_t pid)
{
    auto [it, inserted] = g_states.try_emplace(pid);
    if (inserted) {
        it->second.pid = pid;
        it->second.tgid = get_tgid(pid);
        it->second.ppid = get_ppid(pid);
        it->second.is_thread = (it->second.tgid != pid);
    }
    return &it->second;
}

static void free_state(pid_t pid)
{
    g_states.erase(pid);
}

static int ensure_proc_mem_fd(pid_t pid)
{
    proc_state *ps = get_state(pid);
    char path[256];
    if (!ps) return -1;
    if (ps->mem_fd >= 0) return ps->mem_fd;
    snprintf(path, sizeof(path), "/proc/%d/mem", static_cast<int>(pid));
    ps->mem_fd = open(path, O_RDONLY);
    return ps->mem_fd;
}

static void get_cached_ids(pid_t pid, pid_t *tgid, pid_t *ppid)
{
    proc_state *ps = get_state(pid);
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

static std::optional<std::string> read_tracee_string(pid_t pid, unsigned long addr, size_t max)
{
    if (!addr) return std::nullopt;
    std::string buf(max, '\0');
    ssize_t n = read_proc_mem(pid, addr, buf.data(), max);
    if (n <= 0) return std::nullopt;
    /* Find actual string length within the read data */
    size_t slen = strnlen(buf.data(), static_cast<size_t>(n));
    buf.resize(slen);
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

    std::string cwd = read_proc_cwd(pid);
    if (cwd.empty()) return;

    char cwd_esc[PATH_MAX * 2];
    json_escape(cwd_esc, sizeof(cwd_esc), cwd.c_str(), static_cast<int>(cwd.size()));

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
    std::string exe = read_proc_exe(pid);
    char exe_esc[PATH_MAX * 2];
    if (!exe.empty()) json_escape(exe_esc, sizeof(exe_esc), exe.c_str(), static_cast<int>(exe.size()));

    /* argv */
    std::string argv_raw = read_proc_file(pid, "cmdline", ARGV_MAX_READ);
    std::string argv_j;
    if (!argv_raw.empty()) {
        argv_j.resize(argv_raw.size() * 6 + 64);
        json_argv_array(argv_j.data(), static_cast<int>(argv_j.size()),
                        argv_raw.data(), static_cast<int>(argv_raw.size()));
    }

    /* env */
    std::string env_raw;
    std::string env_j;
    if (g_trace_exec_env) {
        env_raw = read_proc_file(pid, "environ", ENV_MAX_READ);
        if (!env_raw.empty()) {
            env_j.resize(env_raw.size() * 6 + 64);
            json_env_object(env_j.data(), static_cast<int>(env_j.size()),
                           env_raw.data(), static_cast<int>(env_raw.size()));
        }
    }

    /* auxv */
    char auxv_buf[4096];
    auxv_buf[0] = '\0';
    format_auxv_json(pid, auxv_buf, sizeof(auxv_buf));

    /* Build line */
    std::string line(LINE_MAX_BUF, '\0');
    int pos = json_header(line.data(), LINE_MAX_BUF, "EXEC", pid, tgid, ppid, &ts);
    if (g_trace_exec_env) {
        pos += snprintf(line.data() + pos, LINE_MAX_BUF - pos,
            ",\"exe\":%s,\"argv\":%s,\"env\":%s,\"auxv\":{%s}}\n",
            !exe.empty() ? exe_esc : "null",
            !argv_j.empty() ? argv_j.c_str() : "[]",
            !env_j.empty() ? env_j.c_str() : "{}",
            auxv_buf[0] ? auxv_buf : "");
    } else {
        pos += snprintf(line.data() + pos, LINE_MAX_BUF - pos,
            ",\"exe\":%s,\"argv\":%s,\"auxv\":{%s}}\n",
            !exe.empty() ? exe_esc : "null",
            !argv_j.empty() ? argv_j.c_str() : "[]",
            auxv_buf[0] ? auxv_buf : "");
    }
    if (pos > 0 && pos < LINE_MAX_BUF)
        emit_line(line.data(), pos);
}

static void emit_inherited_open_for_fd(pid_t pid, pid_t tgid, pid_t ppid,
                                        struct timespec *ts,
                                        int fd_num)
{
    /* Read fd link and stat */
    char link_path[256], link_target[PATH_MAX];
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d", static_cast<int>(pid), fd_num);
    ssize_t n = readlink(link_path, link_target, sizeof(link_target) - 1);
    if (n <= 0) return;
    link_target[n] = '\0';

    struct stat st;
    if (fstatat(AT_FDCWD, link_path, &st, 0) < 0) {
        /* If we can't stat through /proc, use the link text */
        std::memset(&st, 0, sizeof(st));
    }

    /* Read fdinfo for flags */
    char fdinfo_path[256], fdinfo_buf[512];
    snprintf(fdinfo_path, sizeof(fdinfo_path), "/proc/%d/fdinfo/%d", static_cast<int>(pid), fd_num);
    int flags = O_RDONLY;
    int fi = open(fdinfo_path, O_RDONLY);
    if (fi >= 0) {
        ssize_t r = read(fi, fdinfo_buf, sizeof(fdinfo_buf) - 1);
        close(fi);
        if (r > 0) {
            fdinfo_buf[r] = '\0';
            const char *fp = std::strstr(fdinfo_buf, "flags:");
            if (fp) flags = static_cast<int>(strtol(fp + 6, nullptr, 8));
        }
    }

    char path_esc[PATH_MAX * 2];
    json_escape(path_esc, sizeof(path_esc), link_target, static_cast<int>(std::strlen(link_target)));

    char flags_j[256];
    json_open_flags(flags, flags_j, sizeof(flags_j));

    char line[PATH_MAX * 2 + 512];
    int pos = json_header(line, sizeof(line), "OPEN", pid, tgid, ppid, ts);
    pos += snprintf(line + pos, sizeof(line) - pos,
        ",\"path\":%s,\"flags\":%s,\"mode\":%d,\"fd\":%d,\"ino\":%lu,\"dev\":\"%u:%u\","
        "\"inherited\":true}\n",
        path_esc, flags_j, flags, fd_num,
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
    snprintf(dir_path, sizeof(dir_path), "/proc/%d/fd", static_cast<int>(pid));
    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        int fd_num = std::atoi(ent->d_name);
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
        json_escape(path_esc, sizeof(path_esc), path, static_cast<int>(std::strlen(path)));

    char flags_j[256];
    json_open_flags(flags, flags_j, sizeof(flags_j));

    /* If successful, get inode info from /proc/pid/fd/N */
    unsigned long ino_nr = 0;
    unsigned int dev_major = 0, dev_minor = 0;
    if (fd_or_err >= 0) {
        char fd_path[256];
        struct stat st;
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%ld", static_cast<int>(pid), fd_or_err);
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
            ",\"path\":%s,\"flags\":%s,\"mode\":%d,\"fd\":%ld,\"ino\":%lu,\"dev\":\"%u:%u\"}\n",
            path ? path_esc : "null", flags_j, flags,
            fd_or_err, ino_nr, dev_major, dev_minor);
    else
        pos += snprintf(line + pos, sizeof(line) - pos,
            ",\"path\":%s,\"flags\":%s,\"mode\":%d,\"err\":%ld}\n",
            path ? path_esc : "null", flags_j, flags, fd_or_err);

    if (pos > 0) emit_line(line, pos);
}

static void emit_unlink_event(pid_t pid, const char *path, long ret)
{
    pid_t tgid, ppid;
    struct timespec ts;
    get_cached_ids(pid, &tgid, &ppid);
    get_timestamp(&ts);

    char path_esc[PATH_MAX * 2];
    if (path)
        json_escape(path_esc, sizeof(path_esc), path, static_cast<int>(std::strlen(path)));

    char line[PATH_MAX * 2 + 256];
    int pos = json_header(line, sizeof(line), "UNLINK", pid, tgid, ppid, &ts);
    pos += snprintf(line + pos, sizeof(line) - pos,
        ",\"path\":%s,\"ret\":%ld}\n",
        path ? path_esc : "null", ret);

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

    std::string data(to_read, '\0');
    ssize_t n = read_proc_mem(pid, buf_addr, data.data(), to_read);
    if (n <= 0) return;
    to_read = static_cast<size_t>(n);
    data.resize(to_read);

    std::string escaped(to_read * 6 + 4, '\0');
    json_escape(escaped.data(), static_cast<int>(escaped.size()), data.data(), static_cast<int>(to_read));

    std::string line(to_read * 6 + 512, '\0');
    int pos = json_header(line.data(), static_cast<int>(line.size()), stream, pid, tgid, ppid, &ts);
    pos += snprintf(line.data() + pos, line.size() - pos,
        ",\"len\":%zu,\"data\":%s}\n", to_read, escaped.c_str());

    if (pos > 0) emit_line(line.data(), pos);
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
 * ================================================================ */

static int fd1_is_creator_stdout(pid_t pid)
{
    if (!g_creator_stdout_valid) return 0;
    char link_path[256];
    struct stat st;
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/1", static_cast<int>(pid));
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
    if (xptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
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
    if (xptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    regs.orig_rax = nr;
    return xptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

static int set_syscall_ret(pid_t pid, long ret)
{
    struct user_regs_struct regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (xptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    regs.rax = ret;
    return xptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
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
    if (xptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
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
    if (xptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    regs.regs[8] = nr;
    return xptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

static int set_syscall_ret(pid_t pid, long ret)
{
    struct aarch64_user_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (xptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -1;
    regs.regs[0] = ret;
    return xptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
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
 * ================================================================ */

struct emu_tracee {
    pid_t pid = 0;            /* the sub-tracee */
    pid_t tracer_pid = 0;     /* the sub-tracer that thinks it owns this tracee */
    long  options = 0;        /* PTRACE_O_xxx set by the sub-tracer */
    bool  syscall_stop = false;   /* sub-tracer wants syscall-stops (PTRACE_SYSCALL) */
    bool  stopped = false;        /* sub-tracee held, awaiting sub-tracer resume */
    bool  stop_reported = false;  /* stop was delivered to sub-tracer via wait */
    int   wstatus = 0;        /* synthetic wait-status for sub-tracer */
    long  event_msg = 0;      /* GETEVENTMSG value (new child pid, etc.) */
    int   pending_sig = 0;    /* signal to deliver when sub-tracer resumes */
};

static std::unordered_map<pid_t, emu_tracee> g_emu_tracees;

static emu_tracee *find_emu_tracee(pid_t pid)
{
    auto it = g_emu_tracees.find(pid);
    if (it != g_emu_tracees.end()) return &it->second;
    return nullptr;
}

static emu_tracee *find_emu_tracee_for(pid_t tracer, pid_t tracee)
{
    auto it = g_emu_tracees.find(tracee);
    if (it != g_emu_tracees.end() && it->second.tracer_pid == tracer)
        return &it->second;
    return nullptr;
}

static bool is_emu_tracer(pid_t pid)
{
    for (auto &[k, t] : g_emu_tracees)
        if (t.tracer_pid == pid) return true;
    return false;
}

static emu_tracee *add_emu_tracee(pid_t tracee_pid, pid_t tracer_pid)
{
    auto *existing = find_emu_tracee(tracee_pid);
    if (existing) { existing->tracer_pid = tracer_pid; return existing; }
    auto [it, ok] = g_emu_tracees.try_emplace(tracee_pid);
    it->second.pid = tracee_pid;
    it->second.tracer_pid = tracer_pid;
    return &it->second;
}

static void remove_emu_tracee(pid_t pid)
{
    g_emu_tracees.erase(pid);
}

/* Remove all sub-tracees belonging to a given sub-tracer. */
static void remove_emu_tracees_for(pid_t tracer_pid)
{
    std::erase_if(g_emu_tracees, [tracer_pid](const auto &pair) {
        return pair.second.tracer_pid == tracer_pid;
    });
}

/* Find any un-reported stopped sub-tracee for a given sub-tracer. */
static emu_tracee *find_stopped_for(pid_t tracer, long wait_pid)
{
    for (auto &[k, t] : g_emu_tracees) {
        if (t.tracer_pid != tracer) continue;
        if (!t.stopped || t.stop_reported) continue;
        if (wait_pid == -1 || wait_pid == t.pid ||
            (wait_pid == 0 /* any in same pgid – approximate */))
            return &t;
    }
    return nullptr;
}

/* ================================================================
 * Ptrace emulation — deliver stop to a waiting sub-tracer
 * ================================================================ */

static void try_deliver_to_tracer(pid_t tracer_pid)
{
    proc_state *tps = get_state(tracer_pid);
    if (!tps->emu_waiting) {
#ifdef SYS_wait4
        if (tps->in_syscall && !tps->emu_neutralized &&
            tps->saved_syscall == SYS_wait4) {
            tps->emu_race_interrupt = true;
            syscall(SYS_tgkill, tracer_pid, tracer_pid, SIGCHLD);
        }
#endif
        return;
    }

    emu_tracee *et = find_stopped_for(tracer_pid, tps->emu_wait_pid);
    if (!et) return;

    /* Write wstatus to the sub-tracer's address space */
    if (tps->emu_wait_wstatus_addr) {
        int wst = et->wstatus;
        write_proc_mem(tracer_pid, tps->emu_wait_wstatus_addr, &wst, sizeof(wst));
    }

    /* Set the return value to the stopped sub-tracee's pid */
    set_syscall_ret(tracer_pid, et->pid);

    et->stop_reported = true;
    tps->emu_waiting = false;

    /* Resume the sub-tracer */
    xptrace(PTRACE_SYSCALL, tracer_pid, NULL, 0);
}

/* ================================================================
 * Ptrace emulation — handle emulated xptrace() syscall
 * ================================================================ */

static long emu_handle_ptrace(pid_t caller, unsigned long request,
                              unsigned long pid_arg, unsigned long addr,
                              unsigned long data)
{
    pid_t target = static_cast<pid_t>(pid_arg);

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
        emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        et->options = static_cast<long>(data);
        return 0;
    }

    /* ---- PTRACE_SYSCALL / PTRACE_CONT ---- */
    case PTRACE_SYSCALL:
    case PTRACE_CONT: {
        emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        et->syscall_stop = (request == PTRACE_SYSCALL);
        int sig = static_cast<int>(data);  /* signal to deliver */
        et->stopped = false;
        et->stop_reported = false;
        xptrace(PTRACE_SYSCALL, target, NULL, (void *)(long)sig);
        return 0;
    }

    /* ---- PTRACE_DETACH ---- */
    case PTRACE_DETACH: {
        emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        int sig = static_cast<int>(data);
        et->stopped = false;
        et->stop_reported = false;
        remove_emu_tracee(target);
        /* Resume normally */
        xptrace(PTRACE_SYSCALL, target, NULL, (void *)(long)sig);
        return 0;
    }

    /* ---- PTRACE_GETEVENTMSG ---- */
    case PTRACE_GETEVENTMSG: {
        emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        unsigned long msg = static_cast<unsigned long>(et->event_msg);
        if (data)
            write_proc_mem(caller, data, &msg, sizeof(msg));
        return 0;
    }

    /* ---- PTRACE_GETREGS ---- */
    case PTRACE_GETREGS: {
        emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et || !et->stopped) return -ESRCH;
#if defined(__x86_64__)
        struct user_regs_struct regs;
        struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
        if (xptrace(PTRACE_GETREGSET, target, NT_PRSTATUS, &iov) < 0)
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
        emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et || !et->stopped) return -ESRCH;
#if defined(__x86_64__)
        struct user_regs_struct regs;
        if (!data) return -EIO;
        if (read_proc_mem(caller, data, &regs, sizeof(regs)) < static_cast<ssize_t>(sizeof(regs)))
            return -EIO;
        struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
        if (xptrace(PTRACE_SETREGSET, target, NT_PRSTATUS, &iov) < 0)
            return -EIO;
#else
        return -EIO;
#endif
        return 0;
    }

    /* ---- PTRACE_GETREGSET ---- */
    case PTRACE_GETREGSET: {
        emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et || !et->stopped) return -ESRCH;
        if (!data) return -EIO;
        /* Read the iovec from the caller's address space */
        struct iovec caller_iov;
        if (read_proc_mem(caller, data, &caller_iov, sizeof(caller_iov))
                < static_cast<ssize_t>(sizeof(caller_iov)))
            return -EIO;
        /* Allocate a local buffer, do the real ptrace, write back */
        size_t bufsz = caller_iov.iov_len;
        if (bufsz > 4096) bufsz = 4096;
        void *buf = malloc(bufsz);
        if (!buf) return -ENOMEM;
        struct iovec local_iov = { .iov_base = buf, .iov_len = bufsz };
        if (xptrace(PTRACE_GETREGSET, target, addr, &local_iov) < 0) {
            free(buf);
            return -EIO;
        }
        write_proc_mem(caller, reinterpret_cast<unsigned long>(caller_iov.iov_base), buf, local_iov.iov_len);
        /* Update iov_len in caller's iov to reflect actual size */
        caller_iov.iov_len = local_iov.iov_len;
        write_proc_mem(caller, data, &caller_iov, sizeof(caller_iov));
        free(buf);
        return 0;
    }

    /* ---- PTRACE_SETREGSET ---- */
    case PTRACE_SETREGSET: {
        emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et || !et->stopped) return -ESRCH;
        if (!data) return -EIO;
        struct iovec caller_iov;
        if (read_proc_mem(caller, data, &caller_iov, sizeof(caller_iov))
                < static_cast<ssize_t>(sizeof(caller_iov)))
            return -EIO;
        size_t bufsz = caller_iov.iov_len;
        if (bufsz > 4096) bufsz = 4096;
        void *buf = malloc(bufsz);
        if (!buf) return -ENOMEM;
        if (read_proc_mem(caller, reinterpret_cast<unsigned long>(caller_iov.iov_base), buf, bufsz)
                < static_cast<ssize_t>(bufsz)) {
            free(buf);
            return -EIO;
        }
        struct iovec local_iov = { .iov_base = buf, .iov_len = bufsz };
        int rc = xptrace(PTRACE_SETREGSET, target, addr, &local_iov) < 0 ? -EIO : 0;
        free(buf);
        return rc;
    }

    /* ---- PTRACE_PEEKDATA / PTRACE_PEEKTEXT ---- */
    case PTRACE_PEEKDATA:
    case PTRACE_PEEKTEXT: {
        emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        errno = 0;
        long val = xptrace(PTRACE_PEEKDATA, target, (void *)addr, NULL);
        if (errno) return -errno;
        return val;
    }

    /* ---- PTRACE_POKEDATA / PTRACE_POKETEXT ---- */
    case PTRACE_POKEDATA:
    case PTRACE_POKETEXT: {
        emu_tracee *et = find_emu_tracee_for(caller, target);
        if (!et) return -ESRCH;
        if (xptrace(PTRACE_POKEDATA, target, (void *)addr, (void *)data) < 0)
            return -errno;
        return 0;
    }

    /* ---- PTRACE_ATTACH ---- */
    case PTRACE_ATTACH: {
        /* Only allow attaching to processes we're already tracing */
        if (!pidset_contains(target)) return -EPERM;
        add_emu_tracee(target, caller);
        /* The target will receive a SIGSTOP; we'll queue it. */
        kill(target, SIGSTOP);
        return 0;
    }

    /* ---- PTRACE_KILL ---- */
#ifdef PTRACE_KILL
    case PTRACE_KILL: {
        emu_tracee *et = find_emu_tracee_for(caller, target);
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
 * ================================================================ */

static int emu_handle_wait4(pid_t caller, proc_state *ps)
{
    long wpid_arg = static_cast<long>(static_cast<int>(ps->arg0)); /* sign-extend pid_t */
    unsigned long wstatus_addr = ps->arg1;
    int options = static_cast<int>(ps->arg2);

    /* Check for an already-stopped sub-tracee */
    emu_tracee *et = find_stopped_for(caller, wpid_arg);
    if (et) {
        if (wstatus_addr) {
            int wst = et->wstatus;
            write_proc_mem(caller, wstatus_addr, &wst, sizeof(wst));
        }
        set_syscall_ret(caller, et->pid);
        et->stop_reported = true;
        return 0; /* resume caller */
    }

    if (options & WNOHANG) {
        set_syscall_ret(caller, 0);
        return 0;
    }

    /* No pending stop and blocking — hold the sub-tracer */
    ps->emu_waiting = true;
    ps->emu_wait_wstatus_addr = wstatus_addr;
    ps->emu_wait_pid = wpid_arg;
    ps->emu_wait_options = options;
    return 1; /* hold caller */
}

/* ================================================================
 * Ptrace emulation — queue a stop for a sub-tracee
 * ================================================================ */

static void emu_queue_stop(emu_tracee *et, int wstatus)
{
    et->stopped = true;
    et->stop_reported = false;
    et->wstatus = wstatus;
    try_deliver_to_tracer(et->tracer_pid);
}

static void handle_syscall_entry(pid_t pid, proc_state *ps)
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
    ps->emu_neutralized = false;

    /* ---- Intercept xptrace() syscall ---- */
    if (nr == SYS_ptrace) {
        set_syscall_nr(pid, -1);   /* neutralise → kernel returns -ENOSYS */
        ps->emu_neutralized = true;
        return;
    }

    /* ---- Intercept wait4() from sub-tracers ---- */
#ifdef SYS_wait4
    if (nr == SYS_wait4 && is_emu_tracer(pid)) {
        set_syscall_nr(pid, -1);
        ps->emu_neutralized = true;
        return;
    }
#endif
#ifdef SYS_waitid
    if (nr == SYS_waitid && is_emu_tracer(pid)) {
        set_syscall_nr(pid, -1);
        ps->emu_neutralized = true;
        return;
    }
#endif
}

/*
 * handle_syscall_exit — returns 1 if the pid should be held (not resumed).
 */
static int handle_syscall_exit(pid_t pid, proc_state *ps)
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

    /* Race-condition path */
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
            ps->tgid = pid;
            ps->is_thread = false;
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
        auto path = read_tracee_string(pid, ps->arg1, PATH_MAX);
        emit_open_event(pid, path ? path->c_str() : nullptr, static_cast<int>(ps->arg2), ret_val);
        return 0;
    }
#endif
#ifdef SYS_open
    if (syscall_nr == SYS_open) {
        /* a0 = pathname, a1 = flags */
        auto path = read_tracee_string(pid, ps->arg0, PATH_MAX);
        emit_open_event(pid, path ? path->c_str() : nullptr, static_cast<int>(ps->arg1), ret_val);
        return 0;
    }
#endif

    /* ---- chdir / fchdir ---- */
    if (syscall_nr == SYS_chdir || syscall_nr == SYS_fchdir) {
        if (ret_val == 0)
            emit_cwd_event(pid);
        return 0;
    }

    /* ---- unlinkat / unlink ---- */
#ifdef SYS_unlinkat
    if (syscall_nr == SYS_unlinkat && ret_val == 0) {
        /* a0 = dirfd, a1 = pathname, a2 = flags */
        auto path = read_tracee_string(pid, ps->arg1, PATH_MAX);
        emit_unlink_event(pid, path ? path->c_str() : nullptr, ret_val);
        return 0;
    }
#endif
#ifdef SYS_unlink
    if (syscall_nr == SYS_unlink && ret_val == 0) {
        /* a0 = pathname */
        auto path = read_tracee_string(pid, ps->arg0, PATH_MAX);
        emit_unlink_event(pid, path ? path->c_str() : nullptr, ret_val);
        return 0;
    }
#endif

    /* ---- write ---- */
    if (syscall_nr == SYS_write) {
        unsigned int fd = static_cast<unsigned int>(ps->arg0);
        if (ret_val <= 0) return 0;
        if (fd == 2) {
            emit_write_event(pid, "STDERR", ps->arg1, static_cast<size_t>(ret_val));
        } else if (fd == 1 && fd1_is_creator_stdout(pid)) {
            emit_write_event(pid, "STDOUT", ps->arg1, static_cast<size_t>(ret_val));
        }
        return 0;
    }

    /* ---- writev (for STDERR/STDOUT that goes through writev) ---- */
    if (syscall_nr == SYS_writev) {
        unsigned int fd = static_cast<unsigned int>(ps->arg0);
        if (ret_val <= 0) return 0;
        if (fd != 1 && fd != 2) return 0;
        if (fd == 1 && !fd1_is_creator_stdout(pid)) return 0;
        const char *stream = (fd == 2) ? "STDERR" : "STDOUT";
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
    std::fprintf(stderr,
            "Usage: %s [-o FILE[.zst]] [--no-env] [--backend auto|module|sud|ptrace] [--module|--sud|--ptrace] -- command [args...]\n",
            prog);
    std::exit(1);
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
    std::string_view sv(name);
    if (sv == "auto") *backend = TRACE_BACKEND_AUTO;
    else if (sv == "module") *backend = TRACE_BACKEND_MODULE;
    else if (sv == "sud") *backend = TRACE_BACKEND_SUD;
    else if (sv == "ptrace") *backend = TRACE_BACKEND_PTRACE;
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
        char *slash = std::strrchr(self_exe, '/');
        if (slash) {
            int len = snprintf(buf, bufsz, "%.*s/sudtrace",
                               static_cast<int>(slash - self_exe), self_exe);
            if (len > 0 && static_cast<size_t>(len) < bufsz && access(buf, X_OK) == 0)
                return 0;
        }
    }
    if (snprintf(buf, bufsz, "%s", "sudtrace") >= static_cast<int>(bufsz))
        return -1;
    return access(buf, X_OK) == 0 ? 0 : -1;
}

static int resolve_exec_path(const char *cmd, char *out, size_t out_sz)
{
    if (!cmd || !cmd[0] || out_sz == 0)
        return -1;
    if (cmd[0] == '/' || std::strchr(cmd, '/')) {
        if (realpath(cmd, out) != nullptr)
            return 0;
        if (snprintf(out, out_sz, "%s", cmd) >= static_cast<int>(out_sz))
            return -1;
        return access(out, X_OK) == 0 ? 0 : -1;
    }

    const char *path_env = getenv("PATH");
    if (!path_env || !path_env[0])
        path_env = "/usr/bin:/bin";

    char path_copy[4096];
    if (snprintf(path_copy, sizeof(path_copy), "%s", path_env) >= static_cast<int>(sizeof(path_copy)))
        return -1;

    char *saveptr = nullptr;
    for (char *dir = strtok_r(path_copy, ":", &saveptr);
         dir; dir = strtok_r(nullptr, ":", &saveptr)) {
        if (snprintf(out, out_sz, "%s/%s", dir, cmd) >= static_cast<int>(out_sz))
            continue;
        if (access(out, X_OK) == 0)
            return 0;
    }

    return -1;
}

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

    if (buf[0] != '#' || buf[1] != '!')
        return 0;

    char *nl = std::strchr(buf + 2, '\n');
    if (nl) *nl = '\0';

    char *p = buf + 2;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) return 0;

    char *end = p;
    while (*end && *end != ' ' && *end != '\t') end++;

    size_t ilen = static_cast<size_t>(end - p);
    if (ilen >= interp_sz) ilen = interp_sz - 1;
    std::memcpy(interp, p, ilen);
    interp[ilen] = '\0';

    if (interp_arg && arg_sz > 0) {
        interp_arg[0] = '\0';
        while (*end == ' ' || *end == '\t') end++;
        if (*end) {
            size_t alen = std::strlen(end);
            if (alen >= arg_sz) alen = arg_sz - 1;
            std::memcpy(interp_arg, end, alen);
            interp_arg[alen] = '\0';
        }
    }

    return 1;
}

static int read_elf_class(const char *path, int *elf_class)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    unsigned char ident[EI_NIDENT];
    ssize_t n = read(fd, ident, sizeof(ident));
    close(fd);
    if (n != static_cast<ssize_t>(sizeof(ident)))
        return -1;
    if (std::memcmp(ident, ELFMAG, SELFMAG) != 0)
        return -1;
    if (ident[EI_CLASS] != ELFCLASS32 && ident[EI_CLASS] != ELFCLASS64)
        return -1;
    if (elf_class)
        *elf_class = ident[EI_CLASS];
    return 0;
}

static int resolve_command_elf_class(const char *cmd, int *elf_class)
{
    char current[PATH_MAX];
    if (resolve_exec_path(cmd, current, sizeof(current)) != 0)
        return -1;

    for (int depth = 0; depth < 16; depth++) {
        char interp[PATH_MAX], interp_arg[256];
        if (check_shebang(current, interp, sizeof(interp), interp_arg, sizeof(interp_arg))) {
            (void)interp_arg;
            if (resolve_exec_path(interp, current, sizeof(current)) != 0)
                return -1;
            continue;
        }
        return read_elf_class(current, elf_class);
    }

    return -1;
}

static int resolve_sud_launcher_exe(char *buf, size_t bufsz,
                                    const char *sudtrace_exe, char **cmd)
{
    int elf_class = 0;
    if (resolve_command_elf_class(cmd[0], &elf_class) != 0) {
        if (snprintf(buf, bufsz, "%s", sudtrace_exe) >= static_cast<int>(bufsz))
            return -1;
        return 0;
    }
    if (elf_class != ELFCLASS32 && elf_class != ELFCLASS64) {
        if (snprintf(buf, bufsz, "%s", sudtrace_exe) >= static_cast<int>(bufsz))
            return -1;
        return 0;
    }

    char launcher[PATH_MAX];
    if (std::strchr(sudtrace_exe, '/')) {
        char base[PATH_MAX];
        if (snprintf(base, sizeof(base), "%s", sudtrace_exe) >= static_cast<int>(sizeof(base)))
            return -1;
        char *slash = std::strrchr(base, '/');
        if (slash) {
            *slash = '\0';
            if (snprintf(launcher, sizeof(launcher), "%s/%s", base,
                         elf_class == ELFCLASS32 ? "sud32" : "sud64")
                < static_cast<int>(sizeof(launcher)) && access(launcher, X_OK) == 0) {
                if (snprintf(buf, bufsz, "%s", launcher) >= static_cast<int>(bufsz))
                    return -1;
                return 0;
            }
        }
    }

    if (snprintf(buf, bufsz, "%s", sudtrace_exe) >= static_cast<int>(bufsz))
        return -1;
    return 0;
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

    /* Field-by-field reset (cannot memset because of unique_ptr member) */
    g_out.stream = nullptr;
    g_out.owns_stream = false;
    g_out.error = false;
    g_out.closing = false;
    g_out.compressor_pid = 0;
    g_out.ring.reset();
    g_out.ring_size = TRACE_OUT_RING_SIZE;
    g_out.head = 0;
    g_out.tail = 0;
    g_out.used = 0;
    g_out.writer = {};
    g_out.lock = PTHREAD_MUTEX_INITIALIZER;
    g_out.can_read = PTHREAD_COND_INITIALIZER;
    g_out.can_write = PTHREAD_COND_INITIALIZER;

    g_out.ring = std::make_unique<char[]>(g_out.ring_size);
    if (!g_out.ring) {
        perror("malloc");
        return -1;
    }
    pthread_mutex_init(&g_out.lock, nullptr);
    pthread_cond_init(&g_out.can_read, nullptr);
    pthread_cond_init(&g_out.can_write, nullptr);

    if (outfile && want_zstd) {
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            perror("pipe");
            g_out.ring.reset();
            return -1;
        }
        g_out.compressor_pid = fork();
        if (g_out.compressor_pid < 0) {
            perror("fork");
            close(pipefd[0]);
            close(pipefd[1]);
            g_out.ring.reset();
            return -1;
        }
        if (g_out.compressor_pid == 0) {
            if (dup2(pipefd[0], STDIN_FILENO) < 0) _exit(127);
            close(pipefd[0]);
            close(pipefd[1]);
            execlp("zstd", "zstd", "-q", "-T0", "-f", "-o", outfile, static_cast<char *>(nullptr));
            _exit(127);
        }
        close(pipefd[0]);
        g_out.stream = fdopen(pipefd[1], "wb");
        if (!g_out.stream) {
            perror("fdopen");
            close(pipefd[1]);
            waitpid(g_out.compressor_pid, nullptr, 0);
            g_out.ring.reset();
            return -1;
        }
        g_out.owns_stream = true;
    } else if (outfile) {
        g_out.stream = std::fopen(outfile, "wb");
        if (!g_out.stream) {
            perror("fopen");
            g_out.ring.reset();
            return -1;
        }
        g_out.owns_stream = true;
    } else {
        g_out.stream = stdout;
        g_out.owns_stream = false;
    }
    setvbuf(g_out.stream, nullptr, _IOFBF, TRACE_OUT_RING_SIZE);
    if (pthread_create(&g_out.writer, nullptr, trace_output_writer_main, &g_out) != 0) {
        perror("pthread_create");
        if (g_out.owns_stream) std::fclose(g_out.stream);
        if (g_out.compressor_pid > 0) waitpid(g_out.compressor_pid, nullptr, 0);
        g_out.ring.reset();
        return -1;
    }
    return 0;
}

static int close_trace_output(const char *outfile)
{
    int rc = 0;
    if (!g_out.stream) return 0;

    pthread_mutex_lock(&g_out.lock);
    g_out.closing = true;
    pthread_cond_broadcast(&g_out.can_read);
    pthread_mutex_unlock(&g_out.lock);
    pthread_join(g_out.writer, nullptr);

    if (g_out.error) {
        std::fprintf(stderr, "uproctrace: trace output failed\n");
        rc = -1;
    }
    if (outfile && g_out.owns_stream && std::fclose(g_out.stream) != 0)
        rc = -1;
    else if (!outfile)
        std::fflush(g_out.stream);
    if (g_out.compressor_pid > 0) {
        int status;
        if (waitpid(g_out.compressor_pid, &status, 0) < 0
            || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            rc = -1;
    }
    pthread_cond_destroy(&g_out.can_read);
    pthread_cond_destroy(&g_out.can_write);
    pthread_mutex_destroy(&g_out.lock);

    /* Field-by-field reset */
    g_out.ring.reset();
    g_out.stream = nullptr;
    g_out.owns_stream = false;
    g_out.error = false;
    g_out.closing = false;
    g_out.compressor_pid = 0;
    g_out.ring_size = 0;
    g_out.head = 0;
    g_out.tail = 0;
    g_out.used = 0;
    g_out.writer = {};

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
            if (trace_output_enqueue(buf, static_cast<size_t>(n)) != 0) {
                std::fprintf(stderr, "uproctrace: trace output queue failed\n");
                return -1;
            }
        }
    }

    std::string pending;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("read");
            return -1;
        }

        pending.append(buf, static_cast<size_t>(n));

        size_t start = 0;
        while (start < pending.size()) {
            auto nl_pos = pending.find('\n', start);
            if (nl_pos == std::string::npos) break;
            size_t line_len = nl_pos - start + 1;
            if (trace_output_enqueue_line(pending.data() + start, line_len) != 0) {
                std::fprintf(stderr, "uproctrace: trace output queue failed\n");
                return -1;
            }
            start += line_len;
        }

        if (start > 0) {
            pending.erase(0, start);
        }
    }

    if (!pending.empty() && trace_output_enqueue_line(pending.data(), pending.size()) != 0) {
        std::fprintf(stderr, "uproctrace: trace output queue failed\n");
        return -1;
    }
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
    char **sub_argv = static_cast<char **>(calloc(argc, sizeof(*sub_argv)));
    if (!sub_argv) {
        perror("calloc");
        return -1;
    }

    size_t i = 0;
    sub_argv[i++] = const_cast<char *>(exe);
    if (outfile) {
        sub_argv[i++] = const_cast<char *>("-o");
        sub_argv[i++] = const_cast<char *>(outfile);
    }
    if (no_env)
        sub_argv[i++] = const_cast<char *>("--no-env");
    sub_argv[i++] = const_cast<char *>("--");
    for (size_t j = 0; j < cmdc; j++)
        sub_argv[i++] = cmd[j];
    sub_argv[i] = nullptr;

    *out_argv = sub_argv;
    return 0;
}

static int run_sud_trace(char **cmd, const char *outfile, const char *sudtrace_exe)
{
    char sud_launcher_exe[PATH_MAX];
    if (resolve_sud_launcher_exe(sud_launcher_exe, sizeof(sud_launcher_exe),
                                 sudtrace_exe, cmd) != 0) {
        std::fprintf(stderr, "uproctrace: cannot resolve sud launcher\n");
        return 1;
    }

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
            char **sub_argv = nullptr;
            close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
            close(pipefd[1]);
            if (build_exec_argv(&sub_argv, sud_launcher_exe, nullptr, !g_trace_exec_env, cmd) != 0)
                _exit(127);
            if (std::strchr(sud_launcher_exe, '/'))
                execv(sud_launcher_exe, sub_argv);
            else
                execvp(sud_launcher_exe, sub_argv);
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
        char **sub_argv = nullptr;
        if (build_exec_argv(&sub_argv, sud_launcher_exe, outfile, !g_trace_exec_env, cmd) != 0)
            _exit(127);
        if (std::strchr(sud_launcher_exe, '/'))
            execv(sud_launcher_exe, sub_argv);
        else
            execvp(sud_launcher_exe, sub_argv);
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
    if (child < 0) { perror("fork"); std::exit(1); }

    if (child == 0) {
        /* Child: request tracing, then exec */
        if (xptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("xptrace(TRACEME)");
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
        std::fprintf(stderr, "uproctrace: child did not stop\n");
        std::exit(1);
    }

    /* Set ptrace options to track forks and execs */
    long opts = PTRACE_O_TRACESYSGOOD   /* set bit 7 in signal for syscall stops */
              | PTRACE_O_TRACEFORK
              | PTRACE_O_TRACEVFORK
              | PTRACE_O_TRACECLONE
              | PTRACE_O_TRACEEXEC;
    if (xptrace(PTRACE_SETOPTIONS, child, NULL, opts) < 0) {
        perror("xptrace(SETOPTIONS)");
        std::exit(1);
    }

    /* Track the child */
    pidset_add(child);

    /* Resume child (it will immediately hit execve) */
    xptrace(PTRACE_SYSCALL, child, NULL, 0);

    /* Main event loop */
    while (!g_tracked.empty()) {
        int wstatus;
        pid_t wpid = waitpid(-1, &wstatus, __WALL);
        if (wpid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;
            break;
        }

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            /* Process/thread exited */
            if (pidset_contains(wpid)) {
                proc_state *eps = get_state(wpid);
                if (!eps->is_thread)
                    emit_exit_event(wpid, wstatus);
                pidset_remove(wpid);
                free_state(wpid);
            }
            /* If this was a sub-tracee, queue the exit for its sub-tracer */
            emu_tracee *et = find_emu_tracee(wpid);
            if (et) {
                emu_queue_stop(et, wstatus);
            }
            /* If this was a sub-tracer, release all its sub-tracees */
            remove_emu_tracees_for(wpid);
            continue;
        }

        if (!WIFSTOPPED(wstatus)) continue;

        int sig = WSTOPSIG(wstatus);
        int event = static_cast<unsigned>(wstatus) >> 16;

        /* Handle ptrace events (fork/vfork/clone/exec) */
        if (event == PTRACE_EVENT_FORK ||
            event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE) {
            unsigned long new_pid;
            xptrace(PTRACE_GETEVENTMSG, wpid, NULL, &new_pid);
            if (new_pid > 0) {
                pidset_add(static_cast<pid_t>(new_pid));
            }

            emu_tracee *et = find_emu_tracee(wpid);
            if (et) {
                int want = 0;
                if (event == PTRACE_EVENT_FORK && (et->options & PTRACE_O_TRACEFORK)) want = 1;
                if (event == PTRACE_EVENT_VFORK && (et->options & PTRACE_O_TRACEVFORK)) want = 1;
                if (event == PTRACE_EVENT_CLONE && (et->options & PTRACE_O_TRACECLONE)) want = 1;

                if (want && new_pid > 0) {
                    emu_tracee *net = add_emu_tracee(static_cast<pid_t>(new_pid), et->tracer_pid);
                    if (net) {
                        net->options = et->options;
                        net->syscall_stop = et->syscall_stop;
                    }
                }

                if (want) {
                    et->event_msg = static_cast<long>(new_pid);
                    int emu_wstatus = (SIGTRAP << 8) | (event << 16) | 0x7f;
                    emu_queue_stop(et, emu_wstatus);
                    continue;
                }
            }

            xptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        if (event == PTRACE_EVENT_EXEC) {
            emu_tracee *et = find_emu_tracee(wpid);
            if (et && (et->options & PTRACE_O_TRACEEXEC)) {
                et->event_msg = static_cast<long>(wpid);
                int emu_wstatus = (SIGTRAP << 8) | (PTRACE_EVENT_EXEC << 16) | 0x7f;
                emu_queue_stop(et, emu_wstatus);
                continue;  /* hold sub-tracee */
            }
            xptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        /* Syscall stop (bit 7 set in signal from PTRACE_O_TRACESYSGOOD) */
        if (sig == (SIGTRAP | 0x80)) {
            proc_state *ps = get_state(wpid);
            int hold = 0;
            if (!ps->in_syscall) {
                /* Syscall entry */
                ps->in_syscall = true;
                handle_syscall_entry(wpid, ps);
            } else {
                /* Syscall exit */
                ps->in_syscall = false;
                hold = handle_syscall_exit(wpid, ps);
            }

            if (!hold) {
                emu_tracee *et = find_emu_tracee(wpid);
                if (et && et->syscall_stop) {
                    int ss = (et->options & PTRACE_O_TRACESYSGOOD)
                             ? (SIGTRAP | 0x80) : SIGTRAP;
                    int emu_wstatus = (ss << 8) | 0x7f;
                    emu_queue_stop(et, emu_wstatus);
                    hold = 1;
                }
            }

            if (!hold)
                xptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        /* PTRACE_EVENT_STOP for newly traced processes */
        if (sig == SIGSTOP && event == 0 && pidset_contains(wpid)) {
            emu_tracee *et = find_emu_tracee(wpid);
            if (et) {
                int emu_wstatus = (SIGSTOP << 8) | 0x7f;
                emu_queue_stop(et, emu_wstatus);
                continue;  /* hold sub-tracee */
            }
            xptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            continue;
        }

        /* Group stop / PTRACE_INTERRUPT stop */
        if (event == PTRACE_EVENT_STOP) {
            if (sig == SIGTRAP) {
                xptrace(PTRACE_SYSCALL, wpid, NULL, 0);
            } else {
                xptrace(PTRACE_LISTEN, wpid, NULL, 0);
            }
            continue;
        }

        /* Signal delivery */
        {
            proc_state *sigps = get_state(wpid);
            if (sig == SIGCHLD && sigps->emu_race_interrupt) {
                sigps->emu_race_interrupt = false;
                xptrace(PTRACE_SYSCALL, wpid, NULL, 0);
                continue;
            }

            emu_tracee *et = find_emu_tracee(wpid);
            if (et) {
                et->pending_sig = sig;
                int emu_wstatus = (sig << 8) | 0x7f;
                emu_queue_stop(et, emu_wstatus);
                continue;  /* hold sub-tracee until sub-tracer resumes */
            }
        }

        /* Deliver the signal to the tracee */
        xptrace(PTRACE_SYSCALL, wpid, NULL, (void *)(long)sig);
    }

    if (close_trace_output(outfile) != 0)
        return 1;

    /* Clean up */
    g_tracked.clear();
    g_states.clear();
    g_emu_tracees.clear();

    return 0;
}

int uproctrace_main(int argc, char **argv)
{
    const char *outfile = nullptr;
    enum trace_backend requested = TRACE_BACKEND_AUTO;
    int cmd_start = -1;

    for (int i = 1; i < argc; i++) {
        std::string_view arg(argv[i]);
        if (arg == "--") {
            cmd_start = i + 1;
            break;
        }
        if (arg == "-o" && i + 1 < argc) {
            outfile = argv[++i];
        } else if (arg == "--no-env") {
            g_trace_exec_env = 0;
        } else if (arg == "--backend" && i + 1 < argc) {
            if (parse_trace_backend(argv[++i], &requested) != 0)
                usage(argv[0]);
        } else if (arg.starts_with("--backend=")) {
            if (parse_trace_backend(argv[i] + 10, &requested) != 0)
                usage(argv[0]);
        } else if (arg == "--module") {
            requested = TRACE_BACKEND_MODULE;
        } else if (arg == "--sud") {
            requested = TRACE_BACKEND_SUD;
        } else if (arg == "--ptrace") {
            requested = TRACE_BACKEND_PTRACE;
        } else if (arg == "-h" || arg == "--help") {
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
            std::fprintf(stderr, "uproctrace: requested backend '%s' is unavailable\n",
                    trace_backend_name(selected));
            return 1;
        }
        return run_module_trace(cmd, outfile);
    case TRACE_BACKEND_SUD:
        if (!have_sud) {
            std::fprintf(stderr, "uproctrace: requested backend '%s' is unavailable\n",
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
