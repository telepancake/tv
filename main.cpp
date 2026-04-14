#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <ctime>

#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <memory>

#include <zstd.h>

#include "engine.h"

extern int uproctrace_main(int argc, char **argv);

static constexpr int MAX_JSON_LINE = 1 << 20;

__attribute__((format(printf, 1, 2)))
static std::string sfmt(const char *f, ...) {
    va_list ap, ap2;
    va_start(ap, f);
    va_copy(ap2, ap);
    int n = std::vsnprintf(nullptr, 0, f, ap);
    va_end(ap);
    if (n < 0) { va_end(ap2); return {}; }
    std::string s(static_cast<size_t>(n), '\0');
    std::vsnprintf(s.data(), static_cast<size_t>(n) + 1, f, ap2);
    va_end(ap2);
    return s;
}

/* ── Types ─────────────────────────────────────────────────────────── */

enum event_kind_t {
    EV_CWD,
    EV_EXEC,
    EV_OPEN,
    EV_EXIT,
    EV_STDOUT,
    EV_STDERR
};

struct trace_event_t {
    int id = 0;
    event_kind_t kind = EV_CWD;
    double ts = 0;
    int pid = 0, tgid = 0, ppid = 0, nspid = 0, nstgid = 0;
    std::string path;
    std::string resolved_path;
    std::string exe;
    std::vector<std::string> argv;
    std::string flags_text;
    int fd = -1;
    int err = 0;
    int inherited = 0;
    std::string data;
    int len = 0;
    std::string status;
    int code = 0;
    int signal = 0;
    int core_dumped = 0;
    int raw = 0;
};

struct process_t {
    int tgid = 0, pid = 0, ppid = 0, nspid = 0, nstgid = 0;
    int parent_index = -1;
    std::vector<int> children;
    int descendant_count = 0;
    double start_ts = 0, end_ts = 0;
    int has_start = 0, has_end = 0;
    std::string exe;
    std::vector<std::string> argv;
    std::string cwd;
    std::string exit_status;
    int exit_code = 0;
    int exit_signal = 0;
    int core_dumped = 0;
    int exit_raw = 0;
    int has_write_open = 0;
    int has_stdout = 0;
    int has_stderr = 0;
    std::vector<std::string> read_paths;
    std::vector<std::string> write_paths;

    /* short display name: basename of exe or argv[0] */
    std::string display_name() const {
        std::string_view s;
        if (!exe.empty()) s = exe;
        else if (!argv.empty()) s = argv[0];
        if (s.empty()) return {};
        auto pos = s.rfind('/');
        return std::string(pos != std::string_view::npos ? s.substr(pos + 1) : s);
    }
};

struct input_cmd_t {
    int kind = 0;
    int key = 0;
    int rows = 0, cols = 0;
    std::string text;
};

struct ViewRow {
    std::string id;
    std::string style;
    std::string text;
    std::string parent_id;
    int link_mode = 0;
    std::string link_id;
    int has_children = 0;
};

struct app_state_t {
    int mode = 0;
    int grouped = 1;
    int ts_mode = 0;
    int sort_key = 0;
    int lp_filter = 0;
    int dep_filter = 0;
    int rows = 24, cols = 80;
    std::string cursor_id;
    std::string dcursor_id;
    std::string search;
    std::string evfilt;
};

struct output_group_t {
    int tgid = 0;
    std::string name;
    std::vector<int> event_indices;
};

struct file_stat_t {
    std::string path;
    int opens = 0;
    int procs = 0;
    int errs = 0;
};

struct dir_stat_t {
    std::string path;
    std::string parent;
    std::string name;
    int opens = 0;
    int procs = 0;
    int errs = 0;
    int has_children = 0;
};

struct file_edge_t {
    std::string src;
    std::string dst;
};

enum {
    INPUT_KEY,
    INPUT_RESIZE,
    INPUT_SELECT,
    INPUT_SEARCH,
    INPUT_EVFILT,
    INPUT_PRINT
};

enum {
    LIVE_TRACE_BATCH_ROWS = 256,
    LIVE_TRACE_BATCH_MS = 50,
    DETAIL_UPDATE_DELAY_MS = 120,
};

/* ── Global state ──────────────────────────────────────────────────── */

static std::vector<trace_event_t> g_events;
static int g_next_event_id = 1;
static std::vector<process_t> g_processes;
static std::vector<std::string> g_raw_trace_lines;
static std::vector<input_cmd_t> g_inputs;
static std::vector<ViewRow> g_lpane, g_rpane;
static app_state_t g_state;
static std::unique_ptr<Tui> g_tui;
static int g_headless;
static double g_base_ts;
static std::unordered_set<std::string> g_proc_collapsed, g_file_collapsed,
                                       g_output_collapsed, g_dep_collapsed;

static char t_rbuf[MAX_JSON_LINE];
static int t_rbuf_len = 0;
static int t_trace_fd = -1;
static pid_t t_child_pid = 0;
static int t_pending_live_rows = 0;
static long long t_live_batch_start_ms = 0;
static int g_detail_timer_id = -1;
static int g_detail_update_pending = 0;

static void update_status();

static const char *HELP[] = {
    "", "  Process Trace Viewer", "  ════════════════════", "",
    "  ↑↓ jk  Navigate    PgUp/PgDn  Page    g  First    Tab  Switch pane",
    "  ← h  Collapse/back    → l  Expand/detail    Enter  Follow link", "",
    "  1 Process  2 File  3 Output    G  Toggle tree/flat    s  Sort    t  Timestamps",
    "  4 Deps  5 Reverse-deps  6 Dep-cmds  7 Reverse-dep-cmds    d  Toggle dep filter",
    "  /  Search    n/N  Next/prev    f/F  Filter events/clear    e/E  Expand/collapse all",
    "  v  Cycle proc filter (none→failed→running)    V  Clear proc filter",
    "  W  Save trace to file    x  SQL removed    q  Quit    ?  Help", "", "  Press any key.", nullptr
};

/* ── Utility ───────────────────────────────────────────────────────── */

static long long monotonic_millis() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return static_cast<long long>(ts.tv_sec) * 1000LL + ts.tv_nsec / 1000000LL;
}

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

static const char *json_skip_string(const char *p, const char *end) {
    if (p >= end || *p != '"') return nullptr;
    p++;
    while (p < end) {
        if (*p == '\\') { p += 2; continue; }
        if (*p == '"') return p + 1;
        p++;
    }
    return nullptr;
}

static const char *json_skip_value(const char *p, const char *end) {
    p = skip_ws(p, end);
    if (p >= end) return nullptr;
    if (*p == '"') return json_skip_string(p, end);
    if (*p == '{') {
        int depth = 1; p++;
        while (p < end && depth > 0) {
            if (*p == '"') { p = json_skip_string(p, end); if (!p) return nullptr; continue; }
            if (*p == '{') depth++; else if (*p == '}') depth--;
            p++;
        }
        return depth == 0 ? p : nullptr;
    }
    if (*p == '[') {
        int depth = 1; p++;
        while (p < end && depth > 0) {
            if (*p == '"') { p = json_skip_string(p, end); if (!p) return nullptr; continue; }
            if (*p == '[') depth++; else if (*p == ']') depth--;
            p++;
        }
        return depth == 0 ? p : nullptr;
    }
    while (p < end && *p != ',' && *p != '}' && *p != ']') p++;
    return p;
}

static std::string json_decode_string(std::string_view sp) {
    if (sp.empty() || sp[0] != '"') return {};
    const char *p = sp.data() + 1, *end = sp.data() + sp.size() - 1;
    std::string out;
    out.reserve(static_cast<size_t>(end - p));
    while (p < end) {
        if (*p == '\\' && p + 1 < end) {
            p++;
            switch (*p) {
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'u':
                if (p + 4 < end) {
                    unsigned v = 0;
                    for (int i = 0; i < 4; i++) {
                        char c = p[1 + i];
                        v <<= 4;
                        if (c >= '0' && c <= '9') v |= static_cast<unsigned>(c - '0');
                        else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned>(c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned>(c - 'A' + 10);
                    }
                    out += (v >= 32 && v < 127) ? static_cast<char>(v) : '?';
                    p += 4;
                }
                break;
            default: out += *p; break;
            }
            p++;
            continue;
        }
        out += *p++;
    }
    return out;
}

static bool json_get(const char *json, const char *key, std::string_view &out) {
    char pat[128];
    std::snprintf(pat, sizeof pat, "\"%s\":", key);
    const char *p = std::strstr(json, pat);
    if (!p) return false;
    p += std::strlen(pat);
    const char *end = json + std::strlen(json);
    p = skip_ws(p, end);
    const char *ve = json_skip_value(p, end);
    if (!ve) return false;
    out = std::string_view(p, static_cast<size_t>(ve - p));
    return true;
}

static int span_to_int(std::string_view sp, int def) {
    std::string tmp(sp);
    char *ep = nullptr;
    long v = std::strtol(tmp.c_str(), &ep, 10);
    return (ep && *ep == '\0') ? static_cast<int>(v) : def;
}

static double span_to_double(std::string_view sp, double def) {
    std::string tmp(sp);
    char *ep = nullptr;
    double v = std::strtod(tmp.c_str(), &ep);
    return (ep && *ep == '\0') ? v : def;
}

static int span_to_bool(std::string_view sp, int def) {
    if (sp == "true") return 1;
    if (sp == "false") return 0;
    return def;
}

static std::vector<std::string> json_array_of_strings(std::string_view sp) {
    std::vector<std::string> arr;
    const char *p = skip_ws(sp.data(), sp.data() + sp.size());
    const char *end = sp.data() + sp.size();
    if (p >= end || *p != '[') return arr;
    p++;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == ']') break;
        const char *is = p;
        p = json_skip_string(p, end);
        if (!p) break;
        arr.push_back(json_decode_string(std::string_view(is, static_cast<size_t>(p - is))));
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
    return arr;
}

static std::string canon_path(std::string_view path) {
    if (path.empty()) return {};
    bool absolute = (path[0] == '/');
    std::vector<std::string_view> parts;
    size_t i = absolute ? 1 : 0;
    while (i < path.size()) {
        auto sl = path.find('/', i);
        auto seg = path.substr(i, (sl == std::string_view::npos) ? std::string_view::npos : sl - i);
        i = (sl == std::string_view::npos) ? path.size() : sl + 1;
        if (seg == ".." ) { if (!parts.empty()) parts.pop_back(); }
        else if (seg != "." && !seg.empty()) parts.push_back(seg);
    }
    std::string out;
    if (absolute) out += '/';
    for (size_t j = 0; j < parts.size(); j++) {
        if (j > 0) out += '/';
        out += parts[j];
    }
    return out;
}

static std::string resolve_path_dup(const std::string &raw, const std::string &cwd) {
    if (raw.empty()) return {};
    if (raw[0] != '/' && raw[0] != '.' && raw.find(':') != std::string::npos) return raw;
    std::string out;
    if (raw[0] == '/') out = raw;
    else if (!cwd.empty()) out = cwd + "/" + raw;
    else out = raw;
    if (!out.empty() && out[0] == '/') out = canon_path(out);
    return out;
}

/* ── View helpers ──────────────────────────────────────────────────── */

static ViewRow &view_add_row(std::vector<ViewRow> &v, const std::string &id,
                             const char *style, const std::string &parent_id,
                             const std::string &text, int link_mode,
                             const std::string &link_id, int has_children) {
    v.push_back({id, style ? style : "normal", text, parent_id, link_mode, link_id, has_children});
    return v.back();
}

static ViewRow *view_find_row(std::vector<ViewRow> &v, const std::string &id) {
    for (auto &r : v) if (r.id == id) return &r;
    return nullptr;
}

static int view_find_index(const std::vector<ViewRow> &v, const std::string &id) {
    if (id.empty()) return -1;
    for (int i = 0; i < static_cast<int>(v.size()); i++)
        if (v[i].id == id) return i;
    return -1;
}

/* ── Process model ─────────────────────────────────────────────────── */

static process_t *find_process(int tgid) {
    for (auto &p : g_processes) if (p.tgid == tgid) return &p;
    return nullptr;
}

static int process_index(int tgid) {
    for (int i = 0; i < static_cast<int>(g_processes.size()); i++)
        if (g_processes[i].tgid == tgid) return i;
    return -1;
}

static process_t &get_process(int tgid) {
    for (auto &p : g_processes) if (p.tgid == tgid) return p;
    auto &p = g_processes.emplace_back();
    p.tgid = tgid;
    return p;
}

static void proc_add_path(std::vector<std::string> &arr, const std::string &path) {
    if (path.empty()) return;
    for (const auto &s : arr) if (s == path) return;
    arr.push_back(path);
}

/* ── Trace ingestion ───────────────────────────────────────────────── */

static void append_raw_trace(const char *line) {
    g_raw_trace_lines.emplace_back(line);
}

static trace_event_t &append_event() {
    auto &ev = g_events.emplace_back();
    return ev;
}

static int parse_key_name(const char *n) {
    if (std::strcmp(n, "up") == 0) return TUI_K_UP;
    if (std::strcmp(n, "down") == 0) return TUI_K_DOWN;
    if (std::strcmp(n, "left") == 0) return TUI_K_LEFT;
    if (std::strcmp(n, "right") == 0) return TUI_K_RIGHT;
    if (std::strcmp(n, "pgup") == 0) return TUI_K_PGUP;
    if (std::strcmp(n, "pgdn") == 0) return TUI_K_PGDN;
    if (std::strcmp(n, "home") == 0) return TUI_K_HOME;
    if (std::strcmp(n, "end") == 0) return TUI_K_END;
    if (std::strcmp(n, "tab") == 0) return TUI_K_TAB;
    if (std::strcmp(n, "enter") == 0) return TUI_K_ENTER;
    if (std::strcmp(n, "esc") == 0) return TUI_K_ESC;
    if (std::strlen(n) == 1) return static_cast<unsigned char>(n[0]);
    return TUI_K_NONE;
}

static bool has_flag(const std::string &flags, const char *flag) {
    return !flags.empty() && flags.find(flag) != std::string::npos;
}

static bool is_write_open(const trace_event_t &ev) {
    return ev.kind == EV_OPEN &&
        (has_flag(ev.flags_text, "O_WRONLY") || has_flag(ev.flags_text, "O_RDWR") ||
         has_flag(ev.flags_text, "O_CREAT") || has_flag(ev.flags_text, "O_TRUNC"));
}

static bool is_read_open(const trace_event_t &ev) {
    return ev.kind == EV_OPEN &&
        (has_flag(ev.flags_text, "O_RDONLY") || has_flag(ev.flags_text, "O_RDWR"));
}

static std::string join_with_pipe(const std::vector<std::string> &arr) {
    std::string out;
    for (size_t i = 0; i < arr.size(); i++) {
        if (i) out += '|';
        out += arr[i];
    }
    return out;
}

static void ingest_input_line(const char *line) {
    std::string_view sp;
    if (!json_get(line, "input", sp)) return;
    std::string kind = json_decode_string(sp);
    if (kind.empty()) return;
    input_cmd_t cmd;
    if (kind == "key") {
        cmd.kind = INPUT_KEY;
        std::string name;
        if (json_get(line, "key", sp)) name = json_decode_string(sp);
        cmd.key = !name.empty() ? parse_key_name(name.c_str()) : TUI_K_NONE;
    } else if (kind == "resize") {
        cmd.kind = INPUT_RESIZE;
        if (json_get(line, "rows", sp)) cmd.rows = span_to_int(sp, 0);
        if (json_get(line, "cols", sp)) cmd.cols = span_to_int(sp, 0);
    } else if (kind == "select") {
        cmd.kind = INPUT_SELECT;
        if (json_get(line, "id", sp)) cmd.text = json_decode_string(sp);
    } else if (kind == "search") {
        cmd.kind = INPUT_SEARCH;
        if (json_get(line, "q", sp)) cmd.text = json_decode_string(sp);
    } else if (kind == "evfilt") {
        cmd.kind = INPUT_EVFILT;
        if (json_get(line, "q", sp)) cmd.text = json_decode_string(sp);
    } else if (kind == "print") {
        cmd.kind = INPUT_PRINT;
        if (json_get(line, "what", sp)) cmd.text = json_decode_string(sp);
    } else {
        return;
    }
    g_inputs.push_back(std::move(cmd));
}

static void ingest_trace_line(const char *line) {
    std::string_view sp;
    if (!json_get(line, "event", sp)) return;
    std::string kind = json_decode_string(sp);
    if (kind.empty()) return;
    append_raw_trace(line);
    auto &ev = append_event();
    if (kind == "CWD") ev.kind = EV_CWD;
    else if (kind == "EXEC") ev.kind = EV_EXEC;
    else if (kind == "OPEN") ev.kind = EV_OPEN;
    else if (kind == "EXIT") ev.kind = EV_EXIT;
    else if (kind == "STDOUT") ev.kind = EV_STDOUT;
    else if (kind == "STDERR") ev.kind = EV_STDERR;
    else { g_events.pop_back(); return; }
    ev.id = (ev.kind == EV_CWD) ? 0 : g_next_event_id++;

    if (json_get(line, "ts", sp)) ev.ts = span_to_double(sp, 0.0);
    if (json_get(line, "pid", sp)) ev.pid = span_to_int(sp, 0);
    if (json_get(line, "tgid", sp)) ev.tgid = span_to_int(sp, 0);
    if (json_get(line, "ppid", sp)) ev.ppid = span_to_int(sp, 0);
    if (json_get(line, "nspid", sp)) ev.nspid = span_to_int(sp, 0);
    if (json_get(line, "nstgid", sp)) ev.nstgid = span_to_int(sp, 0);
    if (g_base_ts == 0.0 || ev.ts < g_base_ts) g_base_ts = ev.ts;

    auto &proc = get_process(ev.tgid);
    if (!proc.has_start || ev.ts < proc.start_ts) { proc.start_ts = ev.ts; proc.has_start = 1; }
    if (!proc.has_end || ev.ts > proc.end_ts) { proc.end_ts = ev.ts; proc.has_end = 1; }
    if (ev.pid > 0 || proc.pid == 0) proc.pid = ev.pid;
    if (ev.ppid > 0 || proc.ppid == 0) proc.ppid = ev.ppid;
    if (ev.nspid > 0 || proc.nspid == 0) proc.nspid = ev.nspid;
    if (ev.nstgid > 0 || proc.nstgid == 0) proc.nstgid = ev.nstgid;

    switch (ev.kind) {
    case EV_CWD:
        if (json_get(line, "path", sp)) ev.path = json_decode_string(sp);
        proc.cwd = ev.path;
        break;
    case EV_EXEC:
        if (json_get(line, "exe", sp)) ev.exe = json_decode_string(sp);
        if (json_get(line, "argv", sp)) ev.argv = json_array_of_strings(sp);
        proc.exe = ev.exe;
        proc.argv = ev.argv;
        break;
    case EV_OPEN: {
        if (json_get(line, "path", sp) && !sp.empty() && sp[0] != 'n')
            ev.path = json_decode_string(sp);
        std::vector<std::string> flags;
        if (json_get(line, "flags", sp)) flags = json_array_of_strings(sp);
        ev.flags_text = join_with_pipe(flags);
        if (json_get(line, "fd", sp)) ev.fd = span_to_int(sp, -1);
        if (json_get(line, "err", sp)) ev.err = span_to_int(sp, 0);
        if (json_get(line, "inherited", sp)) ev.inherited = span_to_bool(sp, 0);
        ev.resolved_path = resolve_path_dup(ev.path, proc.cwd);
        if (is_write_open(ev)) proc.has_write_open = 1;
        if (!ev.resolved_path.empty()) {
            if (is_read_open(ev)) proc_add_path(proc.read_paths, ev.resolved_path);
            if (is_write_open(ev)) proc_add_path(proc.write_paths, ev.resolved_path);
        }
        break;
    }
    case EV_EXIT:
        if (json_get(line, "status", sp)) ev.status = json_decode_string(sp);
        if (json_get(line, "code", sp)) ev.code = span_to_int(sp, 0);
        if (json_get(line, "signal", sp)) ev.signal = span_to_int(sp, 0);
        if (json_get(line, "core_dumped", sp)) ev.core_dumped = span_to_bool(sp, 0);
        if (json_get(line, "raw", sp)) ev.raw = span_to_int(sp, 0);
        proc.exit_status = ev.status;
        proc.exit_code = ev.code;
        proc.exit_signal = ev.signal;
        proc.core_dumped = ev.core_dumped;
        proc.exit_raw = ev.raw;
        proc.end_ts = ev.ts;
        proc.has_end = 1;
        break;
    case EV_STDOUT:
    case EV_STDERR:
        if (json_get(line, "data", sp)) ev.data = json_decode_string(sp);
        if (json_get(line, "len", sp)) ev.len = span_to_int(sp, 0);
        if (ev.kind == EV_STDOUT) proc.has_stdout = 1;
        else proc.has_stderr = 1;
        break;
    }
}

static void ingest_line(const char *line) {
    std::string_view sp;
    if (!line || !line[0] || line[0] != '{') return;
    if (json_get(line, "input", sp)) ingest_input_line(line);
    else ingest_trace_line(line);
}

static bool path_has_suffix(const char *path, const char *suffix) {
    size_t n = std::strlen(path), m = std::strlen(suffix);
    return n >= m && std::strcmp(path + n - m, suffix) == 0;
}

static void ingest_zstd_file(const char *path) {
    FILE *f = std::fopen(path, "rb");
    if (!f) { std::fprintf(stderr, "tv: cannot open %s\n", path); std::exit(1); }
    size_t in_cap = ZSTD_DStreamInSize(), out_cap = ZSTD_DStreamOutSize();
    std::vector<unsigned char> in_buf(in_cap), out_buf(out_cap);
    std::string line;
    line.reserve(MAX_JSON_LINE);
    ZSTD_DStream *stream = ZSTD_createDStream();
    if (ZSTD_isError(ZSTD_initDStream(stream))) {
        std::fprintf(stderr, "tv: zstd init failed for %s\n", path); std::exit(1);
    }
    for (;;) {
        size_t nread = std::fread(in_buf.data(), 1, in_cap, f);
        ZSTD_inBuffer input = { in_buf.data(), nread, 0 };
        while (input.pos < input.size) {
            ZSTD_outBuffer output = { out_buf.data(), out_cap, 0 };
            size_t rc = ZSTD_decompressStream(stream, &output, &input);
            if (ZSTD_isError(rc)) {
                std::fprintf(stderr, "tv: zstd decompress failed for %s: %s\n", path, ZSTD_getErrorName(rc));
                std::exit(1);
            }
            size_t pos = 0;
            while (pos < output.pos) {
                auto *nl = static_cast<unsigned char*>(
                    std::memchr(out_buf.data() + pos, '\n', output.pos - pos));
                size_t chunk = nl ? static_cast<size_t>(nl - (out_buf.data() + pos)) : (output.pos - pos);
                line.append(reinterpret_cast<char*>(out_buf.data() + pos), chunk);
                pos += chunk;
                if (nl) {
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    ingest_line(line.c_str());
                    line.clear();
                    pos++;
                }
            }
        }
        if (nread == 0) break;
    }
    if (!line.empty()) {
        if (line.back() == '\r') line.pop_back();
        ingest_line(line.c_str());
    }
    ZSTD_freeDStream(stream);
    std::fclose(f);
}

static void ingest_file(const char *path) {
    if (path_has_suffix(path, ".zst")) { ingest_zstd_file(path); return; }
    FILE *f = std::fopen(path, "r");
    if (!f) { std::fprintf(stderr, "tv: cannot open %s\n", path); std::exit(1); }
    char line[MAX_JSON_LINE];
    while (std::fgets(line, sizeof line, f)) {
        char *nl = std::strchr(line, '\n');
        if (nl) *nl = 0;
        if (nl && nl > line && nl[-1] == '\r') nl[-1] = 0;
        ingest_line(line);
    }
    std::fclose(f);
}

/* ── Process tree ──────────────────────────────────────────────────── */

static bool cmp_child_index(int ia, int ib) {
    const auto &pa = g_processes[ia], &pb = g_processes[ib];
    if (g_state.sort_key == 1) {
        if (pa.start_ts < pb.start_ts) return true;
        if (pa.start_ts > pb.start_ts) return false;
    } else if (g_state.sort_key == 2) {
        if (pa.end_ts < pb.end_ts) return true;
        if (pa.end_ts > pb.end_ts) return false;
    }
    return pa.tgid < pb.tgid;
}

static int compute_descendants(int idx) {
    auto &p = g_processes[idx];
    int total = 0;
    for (int ci : p.children) total += 1 + compute_descendants(ci);
    p.descendant_count = total;
    return total;
}

static void finalize_process_tree() {
    for (int i = 0; i < static_cast<int>(g_processes.size()); i++)
        g_processes[i].parent_index = process_index(g_processes[i].ppid);
    for (int i = 0; i < static_cast<int>(g_processes.size()); i++) {
        auto &p = g_processes[i];
        if (p.parent_index >= 0)
            g_processes[p.parent_index].children.push_back(i);
    }
    for (auto &p : g_processes)
        if (p.children.size() > 1)
            std::sort(p.children.begin(), p.children.end(), cmp_child_index);
    for (int i = 0; i < static_cast<int>(g_processes.size()); i++)
        if (g_processes[i].parent_index < 0) compute_descendants(i);
}

/* ── View building ─────────────────────────────────────────────────── */

static bool proc_matches_search(const process_t &p) {
    if (g_state.search.empty()) return false;
    if (std::to_string(p.tgid).find(g_state.search) != std::string::npos) return true;
    if (!p.exe.empty() && p.exe.find(g_state.search) != std::string::npos) return true;
    for (const auto &a : p.argv)
        if (a.find(g_state.search) != std::string::npos) return true;
    for (const auto &ev : g_events) {
        if (ev.tgid != p.tgid) continue;
        if ((ev.kind == EV_STDOUT || ev.kind == EV_STDERR) &&
            !ev.data.empty() && ev.data.find(g_state.search) != std::string::npos) return true;
    }
    return false;
}

static bool proc_is_interesting_failure(const process_t &p) {
    if (p.exit_status.empty()) return false;
    if (p.exit_status == "signaled") return true;
    if (p.exit_status == "exited" && p.exit_code != 0)
        return p.has_write_open || !p.children.empty() || p.has_stdout;
    return false;
}

static bool proc_matches_filter(const process_t &p) {
    if (g_state.lp_filter == 1) return proc_is_interesting_failure(p);
    if (g_state.lp_filter == 2) return p.exit_status.empty();
    return true;
}

static bool proc_should_show(int idx) {
    auto &p = g_processes[idx];
    if (g_state.lp_filter == 0) return true;
    if (proc_matches_filter(p)) return true;
    for (int ci : p.children) if (proc_should_show(ci)) return true;
    return false;
}

static std::string format_duration(double s, double e, int running) {
    (void)running;
    double d = e - s;
    if (d < 0.0) d = 0.0;
    if (d >= 1.0) return sfmt("%.2fs", d);
    return sfmt("%.1fms", d * 1000.0);
}

static const char *proc_style(const process_t &p) {
    if (proc_matches_search(p)) return "search";
    if (proc_is_interesting_failure(p)) return "error";
    return "normal";
}

static void build_proc_rows_rec(int idx, int depth) {
    auto &p = g_processes[idx];
    std::string id_str = std::to_string(p.tgid);
    bool collapsed = g_proc_collapsed.contains(id_str);
    auto name = p.display_name();
    std::string marker;
    if (p.exit_status == "exited")
        marker = p.exit_code == 0 ? " ✓" : " ✗";
    else if (p.exit_status == "signaled")
        marker = sfmt(" ⚡%d", p.exit_signal);
    std::string dur = format_duration(p.start_ts, p.end_ts, p.exit_status.empty());
    std::string prefix = g_state.grouped
        ? sfmt("%*s%s", depth * 4, "", p.children.empty() ? "  " : (collapsed ? "▶ " : "▼ "))
        : std::string();
    std::string extra = p.descendant_count > 0 ? sfmt(" (%d)", p.descendant_count) : std::string();
    std::string text = sfmt("%s[%d] %s%s%s%s%s", prefix.c_str(), p.tgid, name.c_str(),
                            marker.c_str(), extra.c_str(), dur.empty() ? "" : "  ", dur.c_str());
    std::string parent_id = p.parent_index >= 0 ? std::to_string(g_processes[p.parent_index].tgid) : std::string();
    view_add_row(g_lpane, id_str, proc_style(p), parent_id, text, 0, id_str, !p.children.empty());
    if (g_state.grouped && collapsed) return;
    for (int ci : p.children)
        if (proc_should_show(ci))
            build_proc_rows_rec(ci, g_state.grouped ? depth + 1 : 0);
}

static void build_lpane_process() {
    std::vector<int> roots;
    for (int i = 0; i < static_cast<int>(g_processes.size()); i++)
        if (g_processes[i].parent_index < 0 && proc_should_show(i)) roots.push_back(i);
    if (roots.size() > 1) std::sort(roots.begin(), roots.end(), cmp_child_index);
    if (g_state.grouped) {
        for (int ri : roots) build_proc_rows_rec(ri, 0);
    } else {
        std::vector<int> all;
        for (int i = 0; i < static_cast<int>(g_processes.size()); i++)
            if (proc_should_show(i)) all.push_back(i);
        if (all.size() > 1) std::sort(all.begin(), all.end(), cmp_child_index);
        for (int ai : all) {
            auto &p = g_processes[ai];
            std::string id_str = std::to_string(p.tgid);
            auto name = p.display_name();
            std::string marker;
            if (p.exit_status == "exited")
                marker = p.exit_code == 0 ? " ✓" : " ✗";
            else if (p.exit_status == "signaled")
                marker = sfmt(" ⚡%d", p.exit_signal);
            std::string dur = format_duration(p.start_ts, p.end_ts, p.exit_status.empty());
            std::string text = sfmt("[%d] %s%s%s%s", p.tgid, name.c_str(), marker.c_str(), dur.empty() ? "" : "  ", dur.c_str());
            view_add_row(g_lpane, id_str, proc_style(p), "", text, 0, id_str, false);
        }
    }
}

/* ── File view ─────────────────────────────────────────────────────── */

static std::vector<file_stat_t> build_file_stats() {
    std::vector<file_stat_t> fs;
    for (const auto &ev : g_events) {
        if (ev.kind != EV_OPEN || ev.resolved_path.empty()) continue;
        auto it = std::find_if(fs.begin(), fs.end(),
            [&](const file_stat_t &f) { return f.path == ev.resolved_path; });
        if (it == fs.end()) {
            fs.push_back({ev.resolved_path, 0, 0, 0});
            it = fs.end() - 1;
        }
        it->opens++;
        if (ev.err) it->errs++;
    }
    for (auto &f : fs) {
        std::vector<int> tgids;
        for (const auto &ev : g_events) {
            if (ev.kind != EV_OPEN || ev.resolved_path != f.path) continue;
            if (std::find(tgids.begin(), tgids.end(), ev.tgid) == tgids.end())
                tgids.push_back(ev.tgid);
        }
        f.procs = static_cast<int>(tgids.size());
    }
    return fs;
}

static const char *path_leaf(const char *path) {
    const char *s = std::strrchr(path, '/');
    return s ? s + 1 : path;
}

static bool file_matches_search(const std::string &path) {
    return !g_state.search.empty() && path.find(g_state.search) != std::string::npos;
}

static std::vector<dir_stat_t> build_dir_stats(const std::vector<file_stat_t> &fs) {
    std::vector<dir_stat_t> dirs;
    for (const auto &f : fs) {
        if (f.path.empty() || f.path[0] != '/') continue;
        size_t pos = 0;
        while ((pos = f.path.find('/', pos + 1)) != std::string::npos) {
            std::string dirpath = f.path.substr(0, pos);
            bool found = false;
            for (const auto &d : dirs) if (d.path == dirpath) { found = true; break; }
            if (!found) {
                dir_stat_t nd;
                nd.path = dirpath;
                auto slash = dirpath.rfind('/');
                nd.parent = (slash == 0) ? "/" : dirpath.substr(0, slash);
                if (nd.path == "/") nd.parent.clear();
                nd.name = path_leaf(dirpath.c_str());
                dirs.push_back(std::move(nd));
            }
        }
    }
    for (auto &d : dirs) {
        for (const auto &f : fs) {
            size_t m = d.path.size();
            if (f.path.compare(0, m, d.path) == 0 && ((f.path.size() > m && f.path[m] == '/') || (m == 1 && f.path[0] == '/'))) {
                d.opens += f.opens;
                d.procs += f.procs;
                d.errs += f.errs;
            }
        }
        for (const auto &d2 : dirs) if (d2.parent == d.path) d.has_children = 1;
        for (const auto &f : fs) {
            auto slash = f.path.rfind('/');
            if (slash == std::string::npos) continue;
            std::string parent = (slash == 0) ? "/" : f.path.substr(0, slash);
            if (parent == d.path) d.has_children = 1;
        }
    }
    return dirs;
}

static void add_file_tree_rec(const std::string &dir, std::vector<dir_stat_t> &dirs,
                              std::vector<file_stat_t> &fs, int depth) {
    std::vector<std::string> children_dirs, children_files;
    for (const auto &d : dirs) if (d.parent == dir) children_dirs.push_back(d.path);
    for (const auto &f : fs) {
        auto slash = f.path.rfind('/');
        if (slash == std::string::npos) continue;
        std::string parent = (slash == 0) ? "/" : f.path.substr(0, slash);
        if (parent == dir) children_files.push_back(f.path);
    }
    std::sort(children_dirs.begin(), children_dirs.end());
    std::sort(children_files.begin(), children_files.end());

    for (const auto &cd : children_dirs) {
        dir_stat_t *d = nullptr;
        for (auto &dd : dirs) if (dd.path == cd) { d = &dd; break; }
        if (!d) continue;
        bool collapsed = g_file_collapsed.contains(d->path);
        std::string errs_text = d->errs ? sfmt(", %d errs", d->errs) : std::string();
        std::string text = sfmt("%*s%s%s/  [%d opens, %d procs%s]", depth * 2, "",
                                collapsed ? "▶ " : "▼ ", d->name.c_str(),
                                d->opens, d->procs, errs_text.c_str());
        view_add_row(g_lpane, d->path,
                     file_matches_search(d->path) ? "search" : (d->errs ? "error" : "normal"),
                     d->parent, text, 1, d->path, 1);
        if (!collapsed) add_file_tree_rec(d->path, dirs, fs, depth + 1);
    }
    for (const auto &cf : children_files) {
        file_stat_t *fp = nullptr;
        for (auto &ff : fs) if (ff.path == cf) { fp = &ff; break; }
        if (!fp) continue;
        std::string errs_text = fp->errs ? sfmt(", %d errs", fp->errs) : std::string();
        std::string text = sfmt("%*s%s  [%d opens, %d procs%s]", depth * 2, "",
                                fp->path[0] == '/' ? path_leaf(fp->path.c_str()) : fp->path.c_str(),
                                fp->opens, fp->procs, errs_text.c_str());
        auto slash = fp->path.rfind('/');
        std::string parent;
        if (slash != std::string::npos)
            parent = (slash == 0) ? "/" : fp->path.substr(0, slash);
        view_add_row(g_lpane, fp->path,
                     file_matches_search(fp->path) ? "search" : (fp->errs ? "error" : "normal"),
                     parent, text, 1, fp->path, 0);
    }
}

static void build_lpane_files() {
    auto fs = build_file_stats();
    if (!g_state.grouped) {
        std::vector<std::string> paths;
        for (const auto &f : fs) paths.push_back(f.path);
        std::sort(paths.begin(), paths.end());
        for (const auto &path : paths) {
            file_stat_t *fp = nullptr;
            for (auto &f : fs) if (f.path == path) { fp = &f; break; }
            if (!fp) continue;
            std::string errs_text = fp->errs ? sfmt(", %d errs", fp->errs) : std::string();
            std::string text = sfmt("%s  [%d opens, %d procs%s]", fp->path.c_str(),
                                    fp->opens, fp->procs, errs_text.c_str());
            view_add_row(g_lpane, fp->path,
                         file_matches_search(fp->path) ? "search" : (fp->errs ? "error" : "normal"),
                         "", text, 1, fp->path, 0);
        }
    } else {
        auto dirs = build_dir_stats(fs);
        add_file_tree_rec("/", dirs, fs, 0);
        for (auto &f : fs) {
            if (!f.path.empty() && f.path[0] == '/') continue;
            std::string errs_text = f.errs ? sfmt(", %d errs", f.errs) : std::string();
            std::string text = sfmt("  %s  [%d opens, %d procs%s]", f.path.c_str(),
                                    f.opens, f.procs, errs_text.c_str());
            view_add_row(g_lpane, f.path,
                         file_matches_search(f.path) ? "search" : (f.errs ? "error" : "normal"),
                         "", text, 1, f.path, 0);
        }
    }
}

/* ── Output view ───────────────────────────────────────────────────── */

static std::vector<output_group_t> build_output_groups() {
    std::vector<output_group_t> groups;
    for (int i = 0; i < static_cast<int>(g_events.size()); i++) {
        auto &ev = g_events[i];
        if (ev.kind != EV_STDOUT && ev.kind != EV_STDERR) continue;
        auto it = std::find_if(groups.begin(), groups.end(),
            [&](const output_group_t &g) { return g.tgid == ev.tgid; });
        if (it == groups.end()) {
            output_group_t og;
            og.tgid = ev.tgid;
            auto *p = find_process(ev.tgid);
            og.name = p ? p->display_name() : "";
            groups.push_back(std::move(og));
            it = groups.end() - 1;
        }
        it->event_indices.push_back(i);
    }
    return groups;
}

static void build_lpane_output() {
    auto groups = build_output_groups();
    if (!g_state.grouped) {
        for (int i = 0; i < static_cast<int>(g_events.size()); i++) {
            auto &ev = g_events[i];
            if (ev.kind != EV_STDOUT && ev.kind != EV_STDERR) continue;
            auto *p = find_process(ev.tgid);
            std::string id_str = std::to_string(ev.id);
            std::string text = sfmt("[%s] PID %d %s: %s",
                ev.kind == EV_STDOUT ? "STDOUT" : "STDERR", ev.tgid,
                p ? p->display_name().c_str() : "",
                ev.data.c_str());
            view_add_row(g_lpane, id_str, ev.kind == EV_STDERR ? "error" : "normal", "", text, 2, id_str, 0);
        }
    } else {
        for (auto &og : groups) {
            std::string gid = sfmt("io_%d", og.tgid);
            bool collapsed = g_output_collapsed.contains(gid);
            std::string text = sfmt("%sPID %d %s", collapsed ? "▶ " : "▼ ", og.tgid, og.name.c_str());
            view_add_row(g_lpane, gid, "heading", "", text, 2, gid, 1);
            if (!collapsed) {
                for (int ei : og.event_indices) {
                    auto &ev = g_events[ei];
                    std::string id_str = std::to_string(ev.id);
                    std::string row = sfmt("  [%s] %s", ev.kind == EV_STDOUT ? "STDOUT" : "STDERR", ev.data.c_str());
                    view_add_row(g_lpane, id_str, ev.kind == EV_STDERR ? "error" : "normal", gid, row, 2, id_str, 0);
                }
            }
        }
    }
}

/* ── Deps view ─────────────────────────────────────────────────────── */

static std::vector<file_edge_t> build_file_edges() {
    std::vector<file_edge_t> edges;
    for (auto &p : g_processes) {
        for (const auto &rp : p.read_paths) {
            for (const auto &wp : p.write_paths) {
                bool seen = false;
                for (const auto &e : edges)
                    if (e.src == rp && e.dst == wp) { seen = true; break; }
                if (!seen) edges.push_back({rp, wp});
            }
        }
    }
    return edges;
}

static void build_lpane_deps(int reverse) {
    const std::string &start = g_state.cursor_id;
    if (start.empty()) return;
    auto edges = build_file_edges();
    std::vector<std::string> queue, seen;
    int qh = 0;
    queue.push_back(start);
    while (qh < static_cast<int>(queue.size())) {
        std::string cur = queue[qh++];
        if (std::find(seen.begin(), seen.end(), cur) != seen.end()) continue;
        seen.push_back(cur);
        for (const auto &e : edges) {
            std::string next;
            if (reverse && e.dst == cur) next = e.src;
            else if (!reverse && e.src == cur) next = e.dst;
            if (!next.empty() && std::find(seen.begin(), seen.end(), next) == seen.end())
                queue.push_back(next);
        }
    }
    std::sort(seen.begin(), seen.end());
    for (const auto &s : seen) {
        int mode = reverse ? 4 : 3;
        view_add_row(g_lpane, s, file_matches_search(s) ? "search" : "normal", "", s, mode, s, 0);
    }
}

/* ── Right pane ────────────────────────────────────────────────────── */

static int format_ts(char *buf, size_t bufsz, double ts, double prev) {
    if (g_state.ts_mode == 1) std::snprintf(buf, bufsz, "+%.3fs", ts - g_base_ts);
    else if (g_state.ts_mode == 2) std::snprintf(buf, bufsz, "Δ%.3fs", prev < 0 ? 0.0 : ts - prev);
    else std::snprintf(buf, bufsz, "%.3f", ts);
    return 1;
}

static bool event_allowed(const trace_event_t &ev) {
    if (g_state.evfilt.empty()) return true;
    const char *kind = "";
    switch (ev.kind) {
    case EV_CWD: kind = "CWD"; break;
    case EV_EXEC: kind = "EXEC"; break;
    case EV_OPEN: kind = "OPEN"; break;
    case EV_EXIT: kind = "EXIT"; break;
    case EV_STDOUT: kind = "STDOUT"; break;
    case EV_STDERR: kind = "STDERR"; break;
    }
    return std::strstr(kind, g_state.evfilt.c_str()) != nullptr;
}

static void build_rpane_process(const std::string &id) {
    auto *p = find_process(id.empty() ? 0 : std::atoi(id.c_str()));
    if (!p) return;
    view_add_row(g_rpane, "hdr", "heading", "", "─── Process ───", -1, "", 0);
    view_add_row(g_rpane, "tgid", "normal", "", sfmt("TGID:  %d", p->tgid), -1, "", 0);
    view_add_row(g_rpane, "ppid", "normal", "", sfmt("PPID:  %d", p->ppid), -1, "", 0);
    view_add_row(g_rpane, "exe", "normal", "", sfmt("EXE:   %s", p->exe.c_str()), -1, "", 0);
    if (!p->exit_status.empty()) {
        std::string text = p->exit_status == "signaled"
            ? sfmt("Exit: signal %d%s", p->exit_signal, p->core_dumped ? " (core)" : "")
            : sfmt("Exit: exited code=%d", p->exit_code);
        view_add_row(g_rpane, "exit",
                     (p->exit_status == "exited" && p->exit_code == 0) ? "green" : "error",
                     "", text, -1, "", 0);
    }
    if (p->descendant_count > 0) {
        view_add_row(g_rpane, "kids_hdr", "heading", "", sfmt("Children (%d)", p->descendant_count), -1, "", 0);
        for (int ci : p->children) {
            auto &c = g_processes[ci];
            std::string cid = sfmt("child_%d", c.tgid);
            std::string text = sfmt("[%d] %s", c.tgid, c.display_name().c_str());
            view_add_row(g_rpane, cid, "normal", "", text, 0, std::to_string(c.tgid), 0);
        }
    }
    if (!p->argv.empty()) {
        view_add_row(g_rpane, "argv_hdr", "heading", "", "─── Argv ───", -1, "", 0);
        for (int i = 0; i < static_cast<int>(p->argv.size()); i++)
            view_add_row(g_rpane, sfmt("argv_%d", i), "normal", "", sfmt("[%d] %s", i, p->argv[i].c_str()), -1, "", 0);
    }
    view_add_row(g_rpane, "evt_hdr", "heading", "", "─── Events ───", -1, "", 0);
    double prev_ts = -1;
    for (auto &ev : g_events) {
        if (ev.tgid != p->tgid || !event_allowed(ev)) continue;
        char tsbuf[64];
        format_ts(tsbuf, sizeof tsbuf, ev.ts, prev_ts);
        prev_ts = ev.ts;
        std::string text;
        switch (ev.kind) {
        case EV_CWD: text = sfmt("%s [CWD] %s", tsbuf, ev.path.c_str()); break;
        case EV_EXEC: text = sfmt("%s [EXEC] %s", tsbuf, ev.exe.c_str()); break;
        case EV_OPEN: {
            std::string err_text = ev.err ? sfmt(" err=%d", ev.err) : std::string();
            text = sfmt("%s [OPEN] %s [%s]%s", tsbuf, ev.resolved_path.c_str(),
                        ev.flags_text.c_str(), err_text.c_str());
            break;
        }
        case EV_EXIT:
            text = (ev.status == "signaled")
                ? sfmt("%s [EXIT] signal %d%s", tsbuf, ev.signal, ev.core_dumped ? " (core)" : "")
                : sfmt("%s [EXIT] exited code=%d", tsbuf, ev.code);
            break;
        case EV_STDOUT: text = sfmt("%s [STDOUT] %s", tsbuf, ev.data.c_str()); break;
        case EV_STDERR: text = sfmt("%s [STDERR] %s", tsbuf, ev.data.c_str()); break;
        }
        view_add_row(g_rpane, sfmt("ev_%d", ev.id), ev.kind == EV_STDERR ? "error" : "normal", "", text, -1, "", 0);
    }
}

static void build_rpane_file(const std::string &id) {
    if (id.empty()) return;
    int opens = 0, errs = 0;
    std::vector<int> ptgids;
    view_add_row(g_rpane, "hdr", "heading", "", "─── File ───", -1, "", 0);
    view_add_row(g_rpane, "path", "normal", "", id, -1, "", 0);
    for (const auto &ev : g_events) {
        if (ev.kind != EV_OPEN || ev.resolved_path != id) continue;
        opens++;
        if (ev.err) errs++;
        if (std::find(ptgids.begin(), ptgids.end(), ev.tgid) == ptgids.end())
            ptgids.push_back(ev.tgid);
    }
    view_add_row(g_rpane, "opens", "normal", "", sfmt("Opens: %d", opens), -1, "", 0);
    view_add_row(g_rpane, "procs", "normal", "", sfmt("Procs: %d", static_cast<int>(ptgids.size())), -1, "", 0);
    view_add_row(g_rpane, "errs", errs ? "error" : "normal", "", sfmt("Errors: %d", errs), -1, "", 0);
    for (const auto &ev : g_events) {
        if (ev.kind != EV_OPEN || ev.resolved_path != id) continue;
        auto *p = find_process(ev.tgid);
        std::string err_text = ev.err ? sfmt(" err=%d", ev.err) : std::string();
        std::string text = sfmt("PID %d %s [%s]%s", ev.tgid,
            p ? p->display_name().c_str() : "",
            ev.flags_text.c_str(), err_text.c_str());
        view_add_row(g_rpane, sfmt("open_%d", ev.id),
                     ev.err ? "error" : (ev.kind == EV_STDERR ? "error" : "normal"),
                     "", text, 0, std::to_string(ev.tgid), 0);
    }
}

static void build_rpane_output(const std::string &id) {
    int eid = id.empty() ? 0 : std::atoi(id.c_str());
    trace_event_t *ev = nullptr;
    for (auto &e : g_events) if (e.id == eid) { ev = &e; break; }
    if (!ev) return;
    auto *p = find_process(ev->tgid);
    view_add_row(g_rpane, "hdr", "heading", "", "─── Output ───", -1, "", 0);
    view_add_row(g_rpane, "stream", ev->kind == EV_STDERR ? "error" : "normal", "",
                 sfmt("Stream: %s", ev->kind == EV_STDOUT ? "STDOUT" : "STDERR"), -1, "", 0);
    view_add_row(g_rpane, "pid", "normal", "", sfmt("PID: %d", ev->tgid), -1, "", 0);
    view_add_row(g_rpane, "proc", "normal", "",
                 sfmt("Proc: %s", p ? p->display_name().c_str() : ""),
                 -1, "", 0);
    view_add_row(g_rpane, "content_hdr", "heading", "", "─── Content ───", -1, "", 0);
    view_add_row(g_rpane, "content", ev->kind == EV_STDERR ? "error" : "normal", "", ev->data, -1, "", 0);
}

static void build_rpane() {
    const auto &id = g_state.cursor_id;
    if (id.empty()) return;
    if (g_state.mode == 0) build_rpane_process(id);
    else if (g_state.mode == 1 || g_state.mode >= 3) build_rpane_file(id);
    else build_rpane_output(id);
}

/* ── State management ──────────────────────────────────────────────── */

static void ensure_selection(const std::vector<ViewRow> &v, std::string &id) {
    if (view_find_index(v, id) < 0)
        id = v.empty() ? std::string() : v[0].id;
}

static void cancel_detail_update() {
    g_detail_update_pending = 0;
    if (g_tui && g_detail_timer_id >= 0)
        g_tui->remove_timer(g_detail_timer_id);
    g_detail_timer_id = -1;
}

static void rebuild_rpane_only() {
    g_rpane.clear();
    build_rpane();
    ensure_selection(g_rpane, g_state.dcursor_id);
    if (!g_tui) return;
    g_tui->set_cursor("rpane", g_state.dcursor_id.empty() ? nullptr : g_state.dcursor_id.c_str());
    g_tui->dirty("rpane");
}

static int on_detail_update_timer(Tui &tui) {
    (void)tui;
    g_detail_timer_id = -1;
    if (!g_detail_update_pending) return 0;
    g_detail_update_pending = 0;
    rebuild_rpane_only();
    update_status();
    return 0;
}

static void schedule_detail_update() {
    if (!g_tui || g_headless) {
        rebuild_rpane_only();
        update_status();
        return;
    }
    g_detail_update_pending = 1;
    if (g_detail_timer_id >= 0)
        g_tui->remove_timer(g_detail_timer_id);
    g_detail_timer_id = g_tui->add_timer(DETAIL_UPDATE_DELAY_MS, on_detail_update_timer);
}

static void rebuild_views() {
    g_lpane.clear();
    g_rpane.clear();
    switch (g_state.mode) {
    case 0: build_lpane_process(); break;
    case 1: build_lpane_files(); break;
    case 2: build_lpane_output(); break;
    case 3: case 5: build_lpane_deps(0); break;
    case 4: case 6: build_lpane_deps(1); break;
    default: build_lpane_process(); break;
    }
    ensure_selection(g_lpane, g_state.cursor_id);
    build_rpane();
    ensure_selection(g_rpane, g_state.dcursor_id);
}

static void push_cursors() {
    if (!g_tui) return;
    g_tui->set_cursor("lpane", g_state.cursor_id.empty() ? nullptr : g_state.cursor_id.c_str());
    g_tui->set_cursor("rpane", g_state.dcursor_id.empty() ? nullptr : g_state.dcursor_id.c_str());
    g_tui->dirty(nullptr);
}

static int search_hit_count() {
    int n = 0;
    for (const auto &r : g_lpane) if (r.style == "search") n++;
    return n;
}

static void update_status() {
    static const char *mn[] = {"PROCS","FILES","OUTPUT","DEPS","RDEPS","DEP-CMDS","RDEP-CMDS"};
    static const char *tsl[] = {"abs","rel","Δ"};
    int cur = g_tui ? g_tui->get_cursor("lpane") : 0;
    std::string s = sfmt(" %s%s | %d/%d | TS:%s", mn[g_state.mode], g_state.grouped ? " tree" : "",
                         cur + 1, static_cast<int>(g_lpane.size()), tsl[g_state.ts_mode]);
    if (!g_state.evfilt.empty()) s += sfmt(" | F:%s", g_state.evfilt.c_str());
    if (!g_state.search.empty()) s += sfmt(" | /%s[%d]", g_state.search.c_str(), search_hit_count());
    if (g_state.lp_filter == 1) s += " | V:failed";
    else if (g_state.lp_filter == 2) s += " | V:running";
    if (g_state.mode >= 3 && g_state.mode <= 6) s += sfmt(" | D:%s", g_state.dep_filter ? "written" : "all");
    s += " | 1:proc 2:file 3:out 4:dep 5:rdep 6:dcmd 7:rcmd ?:help";
    if (g_tui) g_tui->set_status(s.c_str());
}

/* ── Layout ────────────────────────────────────────────────────────── */

static const ColDef g_text_col[] = {{"text", -1, TUI_ALIGN_LEFT, TUI_OVERFLOW_TRUNCATE}};
static const PanelDef g_lpane_def = {"lpane", nullptr, g_text_col, 1, TUI_PANEL_CURSOR};
static const PanelDef g_rpane_def = {"rpane", nullptr, g_text_col, 1, TUI_PANEL_CURSOR | TUI_PANEL_BORDER};

/* ── Navigation ────────────────────────────────────────────────────── */

static void reset_mode_selection() {
    g_state.cursor_id.clear();
    g_state.dcursor_id.clear();
    if (g_tui) g_tui->focus("lpane");
}

static std::unordered_set<std::string> &collapsed_set_for_mode() {
    if (g_state.mode == 0) return g_proc_collapsed;
    if (g_state.mode == 1) return g_file_collapsed;
    if (g_state.mode == 2) return g_output_collapsed;
    return g_dep_collapsed;
}

static void set_cursor_to_search_hit(int dir) {
    if (g_lpane.empty()) return;
    int start = g_tui ? g_tui->get_cursor("lpane") : 0;
    int count = static_cast<int>(g_lpane.size());
    for (int step = 1; step <= count; step++) {
        int idx = (start + dir * step + count) % count;
        if (g_lpane[idx].style == "search") {
            g_state.cursor_id = g_lpane[idx].id;
            return;
        }
    }
}

static void apply_search(const std::string &q) {
    g_state.search = q;
    rebuild_views();
    for (const auto &r : g_lpane) {
        if (r.style == "search") {
            g_state.cursor_id = r.id;
            break;
        }
    }
}

static void collapse_or_back() {
    auto *row = view_find_row(g_lpane, g_state.cursor_id);
    auto &set = collapsed_set_for_mode();
    if (!row) return;
    if (g_tui && std::strcmp(g_tui->get_focus(), "rpane") == 0) { g_tui->focus("lpane"); return; }
    if (row->has_children && !set.contains(row->id)) set.insert(row->id);
    else if (!row->parent_id.empty()) g_state.cursor_id = row->parent_id;
}

static void expand_or_detail() {
    bool in_rpane = g_tui && std::strcmp(g_tui->get_focus(), "rpane") == 0;
    auto *row = in_rpane ? view_find_row(g_rpane, g_state.dcursor_id) : view_find_row(g_lpane, g_state.cursor_id);
    auto &set = collapsed_set_for_mode();
    if (!row) return;
    if (in_rpane) {
        if (row->link_mode >= 0 && !row->link_id.empty()) {
            g_state.mode = row->link_mode;
            reset_mode_selection();
            g_state.cursor_id = row->link_id;
        }
        return;
    }
    if (row->has_children && set.contains(row->id)) set.erase(row->id);
    else if (g_tui) g_tui->focus("rpane");
}

static void expand_subtree(int expand) {
    auto *row = view_find_row(g_lpane, g_state.cursor_id);
    auto &set = collapsed_set_for_mode();
    if (!row) return;
    for (auto &r : g_lpane) {
        std::string p = r.parent_id;
        while (!p.empty()) {
            if (p == row->id) {
                if (expand) set.erase(r.id);
                else if (r.has_children) set.insert(r.id);
                break;
            }
            auto *pr = view_find_row(g_lpane, p);
            p = pr ? pr->parent_id : std::string();
        }
    }
    if (!expand && row->has_children) set.insert(row->id);
    if (expand) set.erase(row->id);
}

/* ── Diagnostics ───────────────────────────────────────────────────── */

static void dump_lpane(FILE *out) {
    std::fprintf(out, "=== LPANE ===\n");
    for (int i = 0; i < static_cast<int>(g_lpane.size()); i++)
        std::fprintf(out, "%d|%s|%s|%s|%s\n", i, g_lpane[i].style.c_str(), g_lpane[i].id.c_str(),
                     g_lpane[i].parent_id.c_str(), g_lpane[i].text.c_str());
    std::fprintf(out, "=== END LPANE ===\n");
}

static void dump_rpane(FILE *out) {
    std::fprintf(out, "=== RPANE ===\n");
    for (int i = 0; i < static_cast<int>(g_rpane.size()); i++)
        std::fprintf(out, "%d|%s|%s|%d|%s\n", i, g_rpane[i].style.c_str(), g_rpane[i].text.c_str(),
                     g_rpane[i].link_mode, g_rpane[i].link_id.c_str());
    std::fprintf(out, "=== END RPANE ===\n");
}

static void dump_state(FILE *out) {
    int cursor = g_tui ? g_tui->get_cursor("lpane") : 0;
    int scroll = g_tui ? g_tui->get_scroll("lpane") : 0;
    int focus_r = g_tui && std::strcmp(g_tui->get_focus(), "rpane") == 0 ? 1 : 0;
    int dcursor = g_tui ? g_tui->get_cursor("rpane") : 0;
    int dscroll = g_tui ? g_tui->get_scroll("rpane") : 0;
    std::fprintf(out, "=== STATE ===\n");
    std::fprintf(out, "cursor=%d scroll=%d focus=%d dcursor=%d dscroll=%d ts_mode=%d sort_key=%d grouped=%d mode=%d lp_filter=%d search=%s evfilt=%s rows=%d cols=%d dep_filter=%d\n",
            cursor, scroll, focus_r, dcursor, dscroll,
            g_state.ts_mode, g_state.sort_key, g_state.grouped, g_state.mode, g_state.lp_filter,
            g_state.search.c_str(), g_state.evfilt.c_str(), g_state.rows, g_state.cols, g_state.dep_filter);
    std::fprintf(out, "=== END STATE ===\n");
}

static void process_print(const std::string &what) {
    if (what.empty()) return;
    if (what == "lpane") dump_lpane(stdout);
    else if (what == "rpane") dump_rpane(stdout);
    else if (what == "state") dump_state(stdout);
    g_headless = 1;
}

/* ── Key handler ───────────────────────────────────────────────────── */

static void apply_state_change() {
    cancel_detail_update();
    rebuild_views();
    push_cursors();
    update_status();
}

static int on_key_cb(Tui &tui, int key, const char *panel, int cursor, const char *row_id) {
    (void)cursor;
    if (key == TUI_K_NONE) {
        if (std::strcmp(panel ? panel : "", "lpane") == 0) {
            g_state.cursor_id = row_id ? row_id : "";
            schedule_detail_update();
        } else {
            g_state.dcursor_id = row_id ? row_id : "";
        }
        update_status();
        return TUI_HANDLED;
    }
    switch (key) {
    case 'q': return TUI_QUIT;
    case '?': tui.show_help(HELP); break;
    case '1': g_state.mode = 0; reset_mode_selection(); break;
    case '2': g_state.mode = 1; reset_mode_selection(); break;
    case '3': g_state.mode = 2; reset_mode_selection(); break;
    case '4': {
        std::string keep = g_state.cursor_id;
        g_state.mode = 3; reset_mode_selection();
        if (!keep.empty()) g_state.cursor_id = keep;
        break;
    }
    case '5': {
        std::string keep = g_state.cursor_id;
        g_state.mode = 4; reset_mode_selection();
        if (!keep.empty()) g_state.cursor_id = keep;
        break;
    }
    case '6': {
        std::string keep = g_state.cursor_id;
        g_state.mode = 5; reset_mode_selection();
        if (!keep.empty()) g_state.cursor_id = keep;
        break;
    }
    case '7': {
        std::string keep = g_state.cursor_id;
        g_state.mode = 6; reset_mode_selection();
        if (!keep.empty()) g_state.cursor_id = keep;
        break;
    }
    case 'G': g_state.grouped = !g_state.grouped; reset_mode_selection(); break;
    case 's': g_state.sort_key = (g_state.sort_key + 1) % 3; break;
    case 't': g_state.ts_mode = (g_state.ts_mode + 1) % 3; break;
    case 'v': g_state.lp_filter = (g_state.lp_filter + 1) % 3; reset_mode_selection(); break;
    case 'V': g_state.lp_filter = 0; break;
    case 'd': g_state.dep_filter ^= 1; break;
    case 'F': g_state.evfilt.clear(); break;
    case '/': {
        char buf[256] = "";
        if (tui.line_edit("/", buf, sizeof buf)) apply_search(buf);
        break;
    }
    case 'f': {
        char buf[64] = "";
        if (tui.line_edit("Filter: ", buf, sizeof buf)) {
            for (char *p = buf; *p; p++) *p = static_cast<char>(std::toupper(static_cast<unsigned char>(*p)));
            g_state.evfilt = buf;
        }
        break;
    }
    case 'n': set_cursor_to_search_hit(1); break;
    case 'N': set_cursor_to_search_hit(-1); break;
    case 'e': expand_subtree(1); break;
    case 'E': expand_subtree(0); break;
    case TUI_K_LEFT: case 'h': collapse_or_back(); break;
    case TUI_K_RIGHT: case 'l': case TUI_K_ENTER: expand_or_detail(); break;
    case 'W': {
        char fname[256] = "trace.db";
        if (tui.line_edit("Save to: ", fname, sizeof fname) && fname[0]) {
            FILE *f = std::fopen(fname, "w");
            if (f) {
                for (const auto &line : g_raw_trace_lines) std::fprintf(f, "%s\n", line.c_str());
                std::fclose(f);
            }
        }
        break;
    }
    case 'x': tui.set_status(" SQL prompt removed with SQLite"); break;
    default: return TUI_HANDLED;
    }
    apply_state_change();
    return TUI_HANDLED;
}

/* ── Input processing ──────────────────────────────────────────────── */

static void process_input_cmd(const input_cmd_t &cmd) {
    switch (cmd.kind) {
    case INPUT_KEY:
        if (cmd.key != TUI_K_NONE) g_tui->input_key(cmd.key);
        break;
    case INPUT_RESIZE:
        g_tui->resize(cmd.rows, cmd.cols);
        update_status();
        break;
    case INPUT_SELECT:
        reset_mode_selection();
        g_state.cursor_id = cmd.text;
        apply_state_change();
        break;
    case INPUT_SEARCH:
        apply_search(cmd.text);
        push_cursors();
        update_status();
        break;
    case INPUT_EVFILT:
        g_state.evfilt = cmd.text;
        for (auto &c : g_state.evfilt) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        apply_state_change();
        break;
    case INPUT_PRINT:
        process_print(cmd.text);
        break;
    }
}

static void save_to_file(const char *path) {
    FILE *f = std::fopen(path, "w");
    if (!f) { std::fprintf(stderr, "tv: cannot create %s\n", path); return; }
    for (const auto &line : g_raw_trace_lines) std::fprintf(f, "%s\n", line.c_str());
    std::fclose(f);
}

/* ── Live trace ────────────────────────────────────────────────────── */

static void on_live_batch() {
    finalize_process_tree();
    apply_state_change();
}

static void on_trace_fd_cb(Tui &tui, int fd) {
    int n = static_cast<int>(read(fd, t_rbuf + t_rbuf_len, sizeof(t_rbuf) - static_cast<size_t>(t_rbuf_len) - 1));
    if (n <= 0) {
        if (t_rbuf_len > 0) {
            t_rbuf[t_rbuf_len] = 0;
            ingest_line(t_rbuf);
            t_rbuf_len = 0;
        }
        t_pending_live_rows = 0;
        t_live_batch_start_ms = 0;
        on_live_batch();
        tui.unwatch_fd(fd);
        if (t_trace_fd >= 0) { close(t_trace_fd); t_trace_fd = -1; }
        return;
    }
    t_rbuf_len += n;
    int did = 0;
    while (true) {
        char *nl = static_cast<char*>(std::memchr(t_rbuf, '\n', static_cast<size_t>(t_rbuf_len)));
        if (!nl) break;
        if (nl > t_rbuf && nl[-1] == '\r') nl[-1] = 0;
        *nl = 0;
        ingest_line(t_rbuf);
        did++;
        int used = static_cast<int>(nl - t_rbuf) + 1;
        std::memmove(t_rbuf, nl + 1, static_cast<size_t>(t_rbuf_len - used));
        t_rbuf_len -= used;
    }
    if (did) {
        long long now = monotonic_millis();
        if (t_pending_live_rows == 0 && now >= 0) t_live_batch_start_ms = now;
        t_pending_live_rows += did;
        if (t_pending_live_rows >= LIVE_TRACE_BATCH_ROWS || now < 0 ||
            (t_live_batch_start_ms > 0 && now - t_live_batch_start_ms >= LIVE_TRACE_BATCH_MS)) {
            finalize_process_tree();
            apply_state_change();
            t_pending_live_rows = 0;
            t_live_batch_start_ms = 0;
        }
    }
    update_status();
}

/* ── Cleanup ───────────────────────────────────────────────────────── */

static void free_all() {
    g_lpane.clear();
    g_rpane.clear();
    g_events.clear();
    g_processes.clear();
    g_raw_trace_lines.clear();
    g_inputs.clear();
    g_proc_collapsed.clear();
    g_file_collapsed.clear();
    g_output_collapsed.clear();
    g_dep_collapsed.clear();
}

/* ── Main ──────────────────────────────────────────────────────────── */

enum live_trace_backend {
    LIVE_TRACE_BACKEND_AUTO = 0,
    LIVE_TRACE_BACKEND_MODULE,
    LIVE_TRACE_BACKEND_SUD,
    LIVE_TRACE_BACKEND_PTRACE,
};

int main(int argc, char **argv) {
    int load_mode = 0;
    live_trace_backend live_backend = LIVE_TRACE_BACKEND_AUTO;
    int no_env = 0;
    char load_file[256] = "", trace_file[256] = "", save_file[256] = "";
    char **cmd = nullptr;
    if (argc >= 2 && std::strcmp(argv[1], "--uproctrace") == 0) return uproctrace_main(argc - 1, argv + 1);
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--load") == 0 && i + 1 < argc) { load_mode = 1; std::snprintf(load_file, sizeof load_file, "%s", argv[++i]); }
        else if (std::strcmp(argv[i], "--trace") == 0 && i + 1 < argc) std::snprintf(trace_file, sizeof trace_file, "%s", argv[++i]);
        else if (std::strcmp(argv[i], "--save") == 0 && i + 1 < argc) std::snprintf(save_file, sizeof save_file, "%s", argv[++i]);
        else if (std::strcmp(argv[i], "--no-env") == 0) no_env = 1;
        else if (std::strcmp(argv[i], "--module") == 0) live_backend = LIVE_TRACE_BACKEND_MODULE;
        else if (std::strcmp(argv[i], "--sud") == 0) live_backend = LIVE_TRACE_BACKEND_SUD;
        else if (std::strcmp(argv[i], "--ptrace") == 0) live_backend = LIVE_TRACE_BACKEND_PTRACE;
        else if (std::strcmp(argv[i], "--") == 0 && i + 1 < argc) { cmd = argv + i + 1; break; }
    }
    if (!load_mode && !trace_file[0] && !cmd) {
        std::fprintf(stderr,
            "Usage: tv [--module|--sud|--ptrace] -- <command> [args...]\n"
            "       tv --load <file.db>\n"
            "       tv --trace <file.jsonl[.zst]> [--save <file.db>]\n"
            "       tv --load <file.db> --trace <input.jsonl[.zst]>\n"
            "       tv --uproctrace [-o FILE[.zst]] [--module|--sud|--ptrace] -- <command> [args...]\n");
        return 1;
    }

    if (load_mode) ingest_file(load_file);
    if (trace_file[0]) ingest_file(trace_file);
    finalize_process_tree();
    if (save_file[0]) save_to_file(save_file);

    if (cmd) {
        int pipefd[2];
        if (pipe(pipefd) < 0) { perror("pipe"); free_all(); return 1; }
        t_child_pid = fork();
        if (t_child_pid < 0) { perror("fork"); free_all(); return 1; }
        if (t_child_pid == 0) {
            close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
            close(pipefd[1]);
            size_t cmdc = 0; while (cmd[cmdc]) cmdc++;
            size_t extra = 2 + cmdc + 1;
            if (no_env) extra++;
            if (live_backend != LIVE_TRACE_BACKEND_AUTO) extra++;
            char **uargv = static_cast<char**>(std::calloc(extra, sizeof(char*)));
            size_t ui = 0;
            uargv[ui++] = const_cast<char*>("--uproctrace");
            if (no_env) uargv[ui++] = const_cast<char*>("--no-env");
            if (live_backend == LIVE_TRACE_BACKEND_MODULE) uargv[ui++] = const_cast<char*>("--module");
            else if (live_backend == LIVE_TRACE_BACKEND_SUD) uargv[ui++] = const_cast<char*>("--sud");
            else if (live_backend == LIVE_TRACE_BACKEND_PTRACE) uargv[ui++] = const_cast<char*>("--ptrace");
            uargv[ui++] = const_cast<char*>("--");
            for (size_t j = 0; j < cmdc; j++) uargv[ui++] = cmd[j];
            uargv[ui] = nullptr;
            _exit(uproctrace_main(static_cast<int>(ui), uargv));
        }
        close(pipefd[1]);
        t_trace_fd = pipefd[0];
        g_state.lp_filter = 2;
    }

    rebuild_views();
    int headless_mode = (!g_inputs.empty()) ||
                        (trace_file[0] && !cmd && !isatty(STDIN_FILENO)) ||
                        (save_file[0] && !cmd);

    DataSource src{
        .row_count = [](const char *panel) -> int {
            return std::strcmp(panel, "lpane") == 0 ? static_cast<int>(g_lpane.size()) : static_cast<int>(g_rpane.size());
        },
        .row_get = [](const char *panel, int rownum, RowRef *row) -> int {
            auto &v = (std::strcmp(panel, "lpane") == 0) ? g_lpane : g_rpane;
            if (rownum < 0 || rownum >= static_cast<int>(v.size())) return 0;
            row->id = v[rownum].id.c_str();
            row->style = v[rownum].style.c_str();
            row->cols[0] = v[rownum].text.c_str();
            return 1;
        },
        .row_find = [](const char *panel, const char *id) -> int {
            return view_find_index(std::strcmp(panel, "lpane") == 0 ? g_lpane : g_rpane, id ? id : "");
        },
        .size_changed = [](int rows, int cols) {
            g_state.rows = rows;
            g_state.cols = cols;
        },
    };

    if (headless_mode) g_tui = Tui::open_headless(std::move(src), g_state.rows, g_state.cols);
    else g_tui = Tui::open(std::move(src));
    if (!g_tui) {
        if (!headless_mode) std::fprintf(stderr, "tv: cannot open terminal\n");
        free_all();
        return headless_mode ? 0 : 1;
    }

    {
        static Box lbox = {TUI_BOX_PANEL, 1, 0, 0, &g_lpane_def, nullptr, 0};
        static Box rbox = {TUI_BOX_PANEL, 1, 0, 0, &g_rpane_def, nullptr, 0};
        static Box *hch[] = {&lbox, &rbox};
        static Box hbox = {TUI_BOX_HBOX, 1, 0, 0, nullptr, hch, 2};
        g_tui->set_layout(&hbox);
    }
    g_tui->on_key(on_key_cb);
    push_cursors();
    update_status();

    for (const auto &cmd_i : g_inputs) process_input_cmd(cmd_i);
    if (g_headless || (save_file[0] && !cmd)) {
        g_tui.reset();
        free_all();
        return 0;
    }

    if (t_trace_fd >= 0) g_tui->watch_fd(t_trace_fd, on_trace_fd_cb);
    g_tui->run();

    g_tui.reset();
    if (t_trace_fd >= 0) close(t_trace_fd);
    if (t_child_pid > 0) { kill(t_child_pid, SIGTERM); waitpid(t_child_pid, nullptr, 0); }
    free_all();
    return 0;
}
