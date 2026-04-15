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
#include <unordered_map>
#include <algorithm>
#include <memory>

#include <zstd.h>

#include "engine.h"
#include "sorted_vec_set.h"
#include "json.h"

/* ── Item — abstract base for hierarchical items ───────────────────── */

struct Item {
    std::vector<Item*>        children;
    bool                      collapsed = false;
    sorted_vec_set<Item*>     deps;
    sorted_vec_set<Item*>     rdeps;
    sorted_vec_set<int>       events;     /* indices into g_events */

    virtual ~Item() = default;
    virtual std::string_view getKey() const = 0;
    virtual std::string printLine(int depth) const = 0;
    virtual const char *style() const { return "normal"; }
    virtual bool hasChildren() const { return !children.empty(); }

    /* Set collapsed flag recursively on this subtree. */
    void setCollapsedRecursive(bool c) {
        if (!children.empty()) collapsed = c;
        for (auto *ch : children) ch->setCollapsedRecursive(c);
    }
};

/* ── PathItem — hierarchical filesystem path node ──────────────────── */

struct PathItem : Item {
    std::string         name;       /* single path component (e.g. "foo.c") */
    PathItem           *parent = nullptr;
    bool                is_dir = false;

    /* file stats, aggregated incrementally */
    int opens = 0;
    int errs  = 0;
    std::unordered_set<int> proc_tgids;
    std::vector<int> open_event_indices;    /* OPEN events into g_events */
    sorted_vec_set<int> read_procs;         /* processes that read this path */
    sorted_vec_set<int> write_procs;        /* processes that wrote this path */

    /* Build full path by traversing parent chain. */
    std::string fullPath() const {
        if (!parent) return "/";
        std::string p = parent->fullPath();
        if (p != "/") p += '/';
        p += name;
        return p;
    }

    std::string_view getKey() const override {
        /* For engine row IDs — use full path.  Cached on first call. */
        if (cached_key_.empty()) cached_key_ = fullPath();
        return cached_key_;
    }

    std::string printLine(int /*depth*/) const override {
        /* Placeholder — actual line formatting is done by view builders. */
        return name;
    }

    /* Find or create a child directory/file by name. */
    PathItem *getOrCreateChild(const std::string &child_name, bool dir) {
        for (auto *c : children) {
            auto *pc = static_cast<PathItem*>(c);
            if (pc->name == child_name) return pc;
        }
        auto *nc = new PathItem();
        nc->name = child_name;
        nc->parent = this;
        nc->is_dir = dir;
        children.push_back(nc);
        return nc;
    }

private:
    mutable std::string cached_key_;
};

/* Root of the file tree — represents "/" */
static PathItem g_path_root;
static std::vector<PathItem*> g_nonabs_paths;   /* paths like "pipe:[12345]" that don't start with "/" */

/* Intern a path into the PathItem hierarchy.  Returns the leaf node. */
static PathItem *intern_path_item(const std::string &path) {
    if (path.empty()) return nullptr;
    if (path[0] != '/') {
        /* Non-absolute path (pipe, etc.) — keep as flat item */
        for (auto *p : g_nonabs_paths)
            if (p->name == path) return p;
        auto *np = new PathItem();
        np->name = path;
        np->is_dir = false;
        g_nonabs_paths.push_back(np);
        return np;
    }
    /* Traverse/create hierarchy for absolute path. */
    PathItem *cur = &g_path_root;
    cur->is_dir = true;
    size_t i = 1; /* skip leading '/' */
    while (i < path.size()) {
        auto sl = path.find('/', i);
        std::string seg = (sl == std::string::npos) ? path.substr(i) : path.substr(i, sl - i);
        if (seg.empty()) { i = (sl == std::string::npos) ? path.size() : sl + 1; continue; }
        bool is_last = (sl == std::string::npos);
        cur = cur->getOrCreateChild(seg, !is_last);
        i = is_last ? path.size() : sl + 1;
    }
    return cur;
}

/* Lookup without creating. */
static PathItem *find_path_item(const std::string &path) {
    if (path.empty()) return nullptr;
    if (path[0] != '/') {
        for (auto *p : g_nonabs_paths)
            if (p->name == path) return p;
        return nullptr;
    }
    PathItem *cur = &g_path_root;
    size_t i = 1;
    while (i < path.size()) {
        auto sl = path.find('/', i);
        std::string seg = (sl == std::string::npos) ? path.substr(i) : path.substr(i, sl - i);
        if (seg.empty()) { i = (sl == std::string::npos) ? path.size() : sl + 1; continue; }
        PathItem *found = nullptr;
        for (auto *c : cur->children) {
            auto *pc = static_cast<PathItem*>(c);
            if (pc->name == seg) { found = pc; break; }
        }
        if (!found) return nullptr;
        cur = found;
        i = (sl == std::string::npos) ? path.size() : sl + 1;
    }
    return cur;
}

/* Free all PathItems allocated with new. */
static void free_path_tree(PathItem *node) {
    for (auto *c : node->children) free_path_tree(static_cast<PathItem*>(c));
    if (node != &g_path_root) delete node;
    else { node->children.clear(); node->collapsed = false; node->opens = 0; node->errs = 0;
           node->proc_tgids.clear(); node->open_event_indices.clear();
           node->read_procs.clear(); node->write_procs.clear(); node->events.clear();
           node->deps.clear(); node->rdeps.clear(); }
}

static void free_nonabs_paths() {
    for (auto *p : g_nonabs_paths) delete p;
    g_nonabs_paths.clear();
}

/* ── Backward-compatible abs_path_t — now wraps PathItem* ─────────── */

struct abs_path_t {
    PathItem *ptr = nullptr;
    abs_path_t() = default;
    explicit abs_path_t(PathItem *p) : ptr(p) {}
    bool operator==(const abs_path_t &o) const { return ptr == o.ptr; }
    bool operator!=(const abs_path_t &o) const { return ptr != o.ptr; }
    bool operator< (const abs_path_t &o) const { return ptr < o.ptr; }
    bool empty() const { return !ptr; }
    std::string str() const { return ptr ? ptr->fullPath() : std::string(); }
    const char *c_str() const { return ptr ? ptr->fullPath().c_str() : ""; }
    explicit operator bool() const { return ptr != nullptr; }
};

static abs_path_t get_abs_path(const std::string &path) {
    return abs_path_t(intern_path_item(path));
}

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

struct process_t : Item {
    int tgid = 0, pid = 0, ppid = 0, nspid = 0, nstgid = 0;
    bool parent_set = false;
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
    sorted_vec_set<abs_path_t> read_paths;
    sorted_vec_set<abs_path_t> write_paths;
    std::vector<int> event_indices;     /* indices into g_events */
    std::string cached_display_name;    /* pre-computed basename */
    mutable std::string cached_key_;

    void update_display_name() {
        std::string_view s;
        if (!exe.empty()) s = exe;
        else if (!argv.empty()) s = argv[0];
        if (s.empty()) { cached_display_name.clear(); return; }
        auto pos = s.rfind('/');
        cached_display_name = std::string(pos != std::string_view::npos ? s.substr(pos + 1) : s);
    }
    const std::string &display_name() const { return cached_display_name; }

    std::string_view getKey() const override {
        if (cached_key_.empty()) cached_key_ = std::to_string(tgid);
        return cached_key_;
    }
    std::string printLine(int /*depth*/) const override { return cached_display_name; }
};

struct app_state_t {
    int mode = 0;
    int grouped = 1;
    int ts_mode = 0;
    int sort_key = 0;
    int lp_filter = 0;
    int dep_filter = 0;
    std::string cursor_id;
    std::string dcursor_id;
    std::string search;
    std::string evfilt;
};

struct output_group_t {
    int tgid = 0;
    std::string name;
    std::vector<int> event_indices;
    bool collapsed = false;
};

enum {
    LIVE_TRACE_BATCH_ROWS = 256,
    LIVE_TRACE_BATCH_MS = 50,
    DETAIL_UPDATE_DELAY_MS = 120,
};

/* ── Global state ──────────────────────────────────────────────────── */

static std::vector<trace_event_t> g_events;
static int g_next_event_id = 1;
static std::unordered_map<int, std::unique_ptr<process_t>> g_proc_map;
static FILE *g_save_fp = nullptr;       /* temp file for raw trace lines */
static std::vector<std::string> g_input_lines;  /* buffered input commands (raw JSON) */
static app_state_t g_state;
static std::unique_ptr<Tui> g_tui;
static int g_headless;
static int g_lpane = -1, g_rpane = -1;
static double g_base_ts;

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

/* Forward declare for is_collapsed/set_collapsed. */
static process_t *find_process(int tgid);

/* Output group collapsed state — stored in a persistent map since output groups
   are rebuilt each time. */
static std::unordered_map<std::string, bool> g_output_collapsed;

static bool is_collapsed(const std::string &id) {
    /* Process? */
    if (!id.empty() && id[0] >= '0' && id[0] <= '9') {
        auto *p = find_process(std::atoi(id.c_str()));
        if (p) return p->collapsed;
    }
    /* Path? */
    PathItem *pi = find_path_item(id);
    if (pi) return pi->collapsed;
    /* Output group? */
    auto it = g_output_collapsed.find(id);
    if (it != g_output_collapsed.end()) return it->second;
    return false;
}

static void set_collapsed(const std::string &id, bool c) {
    /* Process? */
    if (!id.empty() && id[0] >= '0' && id[0] <= '9') {
        auto *p = find_process(std::atoi(id.c_str()));
        if (p) { p->collapsed = c; return; }
    }
    /* Path? */
    PathItem *pi = find_path_item(id);
    if (pi) { pi->collapsed = c; return; }
    /* Output group */
    g_output_collapsed[id] = c;
}

/* Emit one row into a RowData vector. */
static void emit_row(std::vector<RowData> &v, const std::string &id,
                     const char *style, const std::string &parent_id,
                     const std::string &text, int link_mode,
                     const std::string &link_id, bool has_children) {
    RowData d;
    d.id = id;
    d.style = style ? style : "normal";
    d.cols = {text};
    d.parent_id = parent_id;
    d.link_mode = link_mode;
    d.link_id = link_id;
    d.has_children = has_children;
    v.push_back(std::move(d));
}

/* ── Process model ─────────────────────────────────────────────────── */

static process_t *find_process(int tgid) {
    auto it = g_proc_map.find(tgid);
    return it != g_proc_map.end() ? it->second.get() : nullptr;
}

static process_t &get_process(int tgid) {
    auto [it, inserted] = g_proc_map.try_emplace(tgid);
    if (inserted) { it->second = std::make_unique<process_t>(); it->second->tgid = tgid; }
    return *it->second;
}

/* ── Trace ingestion ───────────────────────────────────────────────── */

static void append_raw_trace(const char *line) {
    if (!g_save_fp) g_save_fp = std::tmpfile();
    if (g_save_fp) { std::fputs(line, g_save_fp); std::fputc('\n', g_save_fp); }
}

static trace_event_t &append_event() {
    auto &ev = g_events.emplace_back();
    return ev;
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

static int key_name_to_code(const std::string &name) {
    if (name.size() == 1) return static_cast<unsigned char>(name[0]);
    if (name == "up") return TUI_K_UP;
    if (name == "down") return TUI_K_DOWN;
    if (name == "left") return TUI_K_LEFT;
    if (name == "right") return TUI_K_RIGHT;
    if (name == "pgup") return TUI_K_PGUP;
    if (name == "pgdn") return TUI_K_PGDN;
    if (name == "home") return TUI_K_HOME;
    if (name == "end") return TUI_K_END;
    if (name == "tab") return TUI_K_TAB;
    if (name == "enter") return TUI_K_ENTER;
    if (name == "esc") return TUI_K_ESC;
    if (name == "bs") return TUI_K_BS;
    return TUI_K_NONE;
}

static void ingest_trace_line(const char *line) {
    std::string_view sp;
    if (!json_get(line, "event", sp)) return;
    std::string kind = json_decode_string(sp);
    if (kind.empty()) return;
    append_raw_trace(line);
    auto &ev = g_events.emplace_back();
    if (kind == "CWD") ev.kind = EV_CWD;
    else if (kind == "EXEC") ev.kind = EV_EXEC;
    else if (kind == "OPEN") ev.kind = EV_OPEN;
    else if (kind == "EXIT") ev.kind = EV_EXIT;
    else if (kind == "STDOUT") ev.kind = EV_STDOUT;
    else if (kind == "STDERR") ev.kind = EV_STDERR;
    else { g_events.pop_back(); return; }
    ev.id = (ev.kind == EV_CWD) ? 0 : g_next_event_id++;
    int event_idx = static_cast<int>(g_events.size()) - 1;

    if (json_get(line, "ts", sp)) ev.ts = span_to_double(sp, 0.0);
    if (json_get(line, "pid", sp)) ev.pid = span_to_int(sp, 0);
    if (json_get(line, "tgid", sp)) ev.tgid = span_to_int(sp, 0);
    if (json_get(line, "ppid", sp)) ev.ppid = span_to_int(sp, 0);
    if (json_get(line, "nspid", sp)) ev.nspid = span_to_int(sp, 0);
    if (json_get(line, "nstgid", sp)) ev.nstgid = span_to_int(sp, 0);
    if (g_base_ts == 0.0 || ev.ts < g_base_ts) g_base_ts = ev.ts;

    auto &proc = get_process(ev.tgid);
    proc.event_indices.push_back(event_idx);
    if (!proc.has_start || ev.ts < proc.start_ts) { proc.start_ts = ev.ts; proc.has_start = 1; }
    if (!proc.has_end || ev.ts > proc.end_ts) { proc.end_ts = ev.ts; proc.has_end = 1; }
    if (ev.pid > 0 || proc.pid == 0) proc.pid = ev.pid;
    if (ev.nspid > 0 || proc.nspid == 0) proc.nspid = ev.nspid;
    if (ev.nstgid > 0 || proc.nstgid == 0) proc.nstgid = ev.nstgid;

    /* Parent-child linking: set parent exactly once; subsequent events
       with a different ppid are ignored to maintain tree consistency. */
    if (!proc.parent_set && ev.ppid > 0 && ev.ppid != proc.tgid) {
        proc.ppid = ev.ppid;
        proc.parent_set = true;
        auto pit = g_proc_map.find(proc.ppid);
        if (pit != g_proc_map.end())
            pit->second->children.push_back(&proc);
    }

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
        proc.update_display_name();
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
            abs_path_t ap = get_abs_path(ev.resolved_path);
            if (is_read_open(ev)) { proc.read_paths.insert(ap); ap.ptr->read_procs.insert(ev.tgid); }
            if (is_write_open(ev)) { proc.write_paths.insert(ap); ap.ptr->write_procs.insert(ev.tgid); }
            /* Incremental file stats stored in PathItem */
            PathItem *fs = ap.ptr;
            fs->opens++;
            if (ev.err) fs->errs++;
            fs->proc_tgids.insert(ev.tgid);
            fs->open_event_indices.push_back(event_idx);
            fs->events.insert(event_idx);
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
    if (json_get(line, "input", sp)) g_input_lines.emplace_back(line);
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

static bool cmp_proc_tgid(int a, int b) {
    auto *pa = find_process(a), *pb = find_process(b);
    if (!pa || !pb) return a < b;
    if (g_state.sort_key == 1) {
        if (pa->start_ts < pb->start_ts) return true;
        if (pa->start_ts > pb->start_ts) return false;
    } else if (g_state.sort_key == 2) {
        if (pa->end_ts < pb->end_ts) return true;
        if (pa->end_ts > pb->end_ts) return false;
    }
    return a < b;
}


/* ── View building ─────────────────────────────────────────────────── */

static bool proc_matches_search(const process_t &p) {
    if (g_state.search.empty()) return false;
    if (std::to_string(p.tgid).find(g_state.search) != std::string::npos) return true;
    if (!p.exe.empty() && p.exe.find(g_state.search) != std::string::npos) return true;
    for (const auto &a : p.argv)
        if (a.find(g_state.search) != std::string::npos) return true;
    for (int ei : p.event_indices) {
        auto &ev = g_events[ei];
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

static bool proc_should_show(int tgid) {
    auto *p = find_process(tgid);
    if (!p) return false;
    if (g_state.lp_filter == 0) return true;
    if (proc_matches_filter(*p)) return true;
    for (auto *ch : p->children)
        if (proc_should_show(static_cast<process_t*>(ch)->tgid)) return true;
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

/* Build a single RowData for a process in tree mode. */
static RowData make_proc_tree_row(process_t *p, int depth) {
    int tgid = p->tgid;
    std::string id_str = std::to_string(tgid);
    bool has_kids = !p->children.empty();
    bool collapsed = has_kids && p->collapsed;
    const auto &name = p->display_name();
    std::string marker;
    if (p->exit_status == "exited")
        marker = p->exit_code == 0 ? " \xe2\x9c\x93" : " \xe2\x9c\x97";
    else if (p->exit_status == "signaled")
        marker = sfmt(" \xe2\x9a\xa1%d", p->exit_signal);
    std::string dur = format_duration(p->start_ts, p->end_ts, p->exit_status.empty());
    int nchildren = static_cast<int>(p->children.size());
    std::string prefix = sfmt("%*s%s", depth * 4, "",
        !has_kids ? "  " : (collapsed ? "\xe2\x96\xb6 " : "\xe2\x96\xbc "));
    std::string extra = nchildren > 0 ? sfmt(" (%d)", nchildren) : std::string();
    std::string text = sfmt("%s[%d] %s%s%s%s%s", prefix.c_str(), tgid, name.c_str(),
                            marker.c_str(), extra.c_str(), dur.empty() ? "" : "  ", dur.c_str());
    std::string parent_id = (p->ppid > 0 && find_process(p->ppid)) ? std::to_string(p->ppid) : std::string();
    RowData d;
    d.id = id_str;
    d.style = proc_style(*p);
    d.cols = {text};
    d.parent_id = parent_id;
    d.link_mode = 0;
    d.link_id = id_str;
    d.has_children = has_kids;
    return d;
}

/* Build a single RowData for a process in flat mode. */
static RowData make_proc_flat_row(process_t *p) {
    int tgid = p->tgid;
    std::string id_str = std::to_string(tgid);
    const auto &name = p->display_name();
    std::string marker;
    if (p->exit_status == "exited")
        marker = p->exit_code == 0 ? " \xe2\x9c\x93" : " \xe2\x9c\x97";
    else if (p->exit_status == "signaled")
        marker = sfmt(" \xe2\x9a\xa1%d", p->exit_signal);
    std::string dur = format_duration(p->start_ts, p->end_ts, p->exit_status.empty());
    std::string text = sfmt("[%d] %s%s%s%s", tgid, name.c_str(), marker.c_str(),
                            dur.empty() ? "" : "  ", dur.c_str());
    RowData d;
    d.id = id_str;
    d.style = proc_style(*p);
    d.cols = {text};
    d.link_mode = 0;
    d.link_id = id_str;
    d.has_children = false;
    return d;
}

/* ── File view ─────────────────────────────────────────────────────── */

static bool file_matches_search(const std::string &path) {
    return !g_state.search.empty() && path.find(g_state.search) != std::string::npos;
}

/* Recursive DFS on PathItem tree → emit rows for file tree view. */
static void add_file_tree_rec(std::vector<RowData> &rows, PathItem *node, int depth) {
    /* Separate dirs and files among children. */
    std::vector<PathItem*> dirs, files;
    for (auto *c : node->children) {
        auto *pc = static_cast<PathItem*>(c);
        if (pc->opens == 0 && pc->children.empty()) continue;
        if (pc->is_dir || !pc->children.empty()) dirs.push_back(pc);
        else files.push_back(pc);
    }
    std::sort(dirs.begin(), dirs.end(), [](PathItem *a, PathItem *b) { return a->name < b->name; });
    std::sort(files.begin(), files.end(), [](PathItem *a, PathItem *b) { return a->name < b->name; });

    for (auto *d : dirs) {
        std::string fullp = d->fullPath();
        std::string parent_fullp = d->parent ? d->parent->fullPath() : std::string();
        int nprocs = static_cast<int>(d->proc_tgids.size());
        std::string errs_text = d->errs ? sfmt(", %d errs", d->errs) : std::string();
        std::string text = sfmt("%*s%s%s/  [%d opens, %d procs%s]", depth * 2, "",
                                d->collapsed ? "\xe2\x96\xb6 " : "\xe2\x96\xbc ",
                                d->name.c_str(), d->opens, nprocs, errs_text.c_str());
        bool has_kids = !d->children.empty();
        emit_row(rows, fullp,
                 file_matches_search(fullp) ? "search" : (d->errs ? "error" : "normal"),
                 parent_fullp, text, 1, fullp, has_kids);
        if (!d->collapsed) add_file_tree_rec(rows, d, depth + 1);
    }
    for (auto *f : files) {
        if (f->opens == 0) continue;
        std::string fullp = f->fullPath();
        std::string parent_fullp = f->parent ? f->parent->fullPath() : std::string();
        int nprocs = static_cast<int>(f->proc_tgids.size());
        std::string errs_text = f->errs ? sfmt(", %d errs", f->errs) : std::string();
        std::string text = sfmt("%*s%s  [%d opens, %d procs%s]", depth * 2, "",
                                f->name.c_str(), f->opens, nprocs, errs_text.c_str());
        emit_row(rows, fullp,
                 file_matches_search(fullp) ? "search" : (f->errs ? "error" : "normal"),
                 parent_fullp, text, 1, fullp, false);
    }
}

/* Collect all leaf PathItems (files with opens > 0) recursively. */
static void collect_file_leaves(PathItem *node, std::vector<PathItem*> &out) {
    if (node->opens > 0 && node->children.empty())
        out.push_back(node);
    for (auto *c : node->children)
        collect_file_leaves(static_cast<PathItem*>(c), out);
}

static void build_lpane_files(std::vector<RowData> &rows) {
    if (!g_state.grouped) {
        /* Flat mode: collect all leaf files, sort by full path. */
        std::vector<PathItem*> leaves;
        collect_file_leaves(&g_path_root, leaves);
        for (auto *np : g_nonabs_paths)
            if (np->opens > 0) leaves.push_back(np);
        std::sort(leaves.begin(), leaves.end(), [](PathItem *a, PathItem *b) {
            return a->fullPath() < b->fullPath();
        });
        for (auto *fp : leaves) {
            std::string path = fp->fullPath();
            int nprocs = static_cast<int>(fp->proc_tgids.size());
            std::string errs_text = fp->errs ? sfmt(", %d errs", fp->errs) : std::string();
            std::string text = sfmt("%s  [%d opens, %d procs%s]", path.c_str(),
                                    fp->opens, nprocs, errs_text.c_str());
            emit_row(rows, path,
                     file_matches_search(path) ? "search" : (fp->errs ? "error" : "normal"),
                     "", text, 1, path, false);
        }
    } else {
        /* Tree mode: DFS on PathItem hierarchy starting from root children. */
        add_file_tree_rec(rows, &g_path_root, 0);
        /* Non-absolute paths (pipes etc.) at the end. */
        for (auto *np : g_nonabs_paths) {
            if (np->opens == 0) continue;
            std::string path = np->name;
            int nprocs = static_cast<int>(np->proc_tgids.size());
            std::string errs_text = np->errs ? sfmt(", %d errs", np->errs) : std::string();
            std::string text = sfmt("  %s  [%d opens, %d procs%s]", path.c_str(),
                                    np->opens, nprocs, errs_text.c_str());
            emit_row(rows, path,
                     file_matches_search(path) ? "search" : (np->errs ? "error" : "normal"),
                     "", text, 1, path, false);
        }
    }
}

/* ── Output view ───────────────────────────────────────────────────── */

static std::vector<output_group_t> build_output_groups() {
    std::unordered_map<int, output_group_t> gmap;
    std::vector<int> order;
    for (int i = 0; i < static_cast<int>(g_events.size()); i++) {
        auto &ev = g_events[i];
        if (ev.kind != EV_STDOUT && ev.kind != EV_STDERR) continue;
        auto [it, inserted] = gmap.try_emplace(ev.tgid);
        if (inserted) {
            it->second.tgid = ev.tgid;
            auto *p = find_process(ev.tgid);
            it->second.name = p ? p->display_name() : "";
            order.push_back(ev.tgid);
        }
        it->second.event_indices.push_back(i);
    }
    std::vector<output_group_t> groups;
    groups.reserve(order.size());
    for (int tgid : order) groups.push_back(std::move(gmap[tgid]));
    return groups;
}

static void build_lpane_output(std::vector<RowData> &rows) {
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
            emit_row(rows, id_str, ev.kind == EV_STDERR ? "error" : "normal", "", text, 2, id_str, false);
        }
    } else {
        for (auto &og : groups) {
            std::string gid = sfmt("io_%d", og.tgid);
            bool collapsed_flag = is_collapsed(gid);
            std::string text = sfmt("%sPID %d %s", collapsed_flag ? "▶ " : "▼ ", og.tgid, og.name.c_str());
            emit_row(rows, gid, "heading", "", text, 2, gid, true);
            if (!collapsed_flag) {
                for (int ei : og.event_indices) {
                    auto &ev = g_events[ei];
                    std::string id_str = std::to_string(ev.id);
                    std::string row = sfmt("  [%s] %s", ev.kind == EV_STDOUT ? "STDOUT" : "STDERR", ev.data.c_str());
                    emit_row(rows, id_str, ev.kind == EV_STDERR ? "error" : "normal", gid, row, 2, id_str, false);
                }
            }
        }
    }
}

/* ── Deps view ─────────────────────────────────────────────────────── */

/* BFS traversal of file dependency graph using bidirectional proc↔file edges.
 *
 * Edge definition: (read_file → write_file) exists when some proc reads R and writes W.
 *
 * reverse=1 (DEPS):  from file X, find dependencies (what was read to produce X).
 *   X.write_procs → for each proc P, P.read_paths → queue those.
 *
 * reverse=0 (RDEPS): from file X, find dependents (what was produced from X).
 *   X.read_procs  → for each proc P, P.write_paths → queue those.
 */
static void collect_dep_files(const std::string &start, int reverse,
                              sorted_vec_set<std::string> &seen) {
    std::vector<std::string> queue;
    int qh = 0;
    queue.push_back(start);
    while (qh < static_cast<int>(queue.size())) {
        std::string cur = queue[qh++];
        if (!seen.emplace(cur).second) continue;
        PathItem *pd = find_path_item(cur);
        if (!pd) continue;
        if (reverse) {
            /* deps: procs that wrote cur → files they read */
            for (int tgid : pd->write_procs) {
                auto *p = find_process(tgid);
                if (!p) continue;
                for (const auto &rp : p->read_paths)
                    if (!seen.contains(rp.str())) queue.push_back(rp.str());
            }
        } else {
            /* rdeps: procs that read cur → files they wrote */
            for (int tgid : pd->read_procs) {
                auto *p = find_process(tgid);
                if (!p) continue;
                for (const auto &wp : p->write_paths)
                    if (!seen.contains(wp.str())) queue.push_back(wp.str());
            }
        }
    }
}

static void build_lpane_deps(std::vector<RowData> &rows, int reverse) {
    const std::string &start = g_state.cursor_id;
    if (start.empty()) return;
    sorted_vec_set<std::string> seen;
    collect_dep_files(start, reverse, seen);
    for (const auto &s : seen) {
        int mode = reverse ? 4 : 3;
        emit_row(rows, s, file_matches_search(s) ? "search" : "normal", "", s, mode, s, false);
    }
}

static void build_lpane_dep_cmds(std::vector<RowData> &rows, int reverse) {
    const std::string &start = g_state.cursor_id;
    if (start.empty()) return;
    sorted_vec_set<std::string> seen;
    collect_dep_files(start, reverse, seen);
    /* Collect processes that touched any file in the chain */
    sorted_vec_set<int> ptgids;
    for (const auto &s : seen) {
        PathItem *pd = find_path_item(s);
        if (!pd) continue;
        for (int t : pd->read_procs) ptgids.insert(t);
        for (int t : pd->write_procs) ptgids.insert(t);
    }
    std::vector<int> sorted_ptgids(ptgids.begin(), ptgids.end());
    std::sort(sorted_ptgids.begin(), sorted_ptgids.end(), [](int a, int b) {
        auto *pa = find_process(a), *pb = find_process(b);
        if (!pa || !pb) return a < b;
        return pa->end_ts > pb->end_ts;
    });
    for (int pt : sorted_ptgids) {
        auto *p = find_process(pt);
        if (!p) continue;
        std::string id_str = std::to_string(pt);
        const auto &name = p->display_name();
        std::string marker;
        if (p->exit_status == "exited")
            marker = p->exit_code == 0 ? " \xe2\x9c\x93" : " \xe2\x9c\x97";
        else if (p->exit_status == "signaled")
            marker = sfmt(" \xe2\x9a\xa1%d", p->exit_signal);
        std::string dur = format_duration(p->start_ts, p->end_ts, p->exit_status.empty());
        std::string text = sfmt("[%d] %s%s%s%s", pt, name.c_str(), marker.c_str(),
                                dur.empty() ? "" : "  ", dur.c_str());
        emit_row(rows, id_str, proc_style(*p), "", text, 0, id_str, false);
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

static void build_rpane_process(std::vector<RowData> &rows, const std::string &id) {
    auto *p = find_process(id.empty() ? 0 : std::atoi(id.c_str()));
    if (!p) return;
    emit_row(rows, "hdr", "heading", "", "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Process \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", -1, "", false);
    emit_row(rows, "tgid", "normal", "", sfmt("TGID:  %d", p->tgid), -1, "", false);
    emit_row(rows, "ppid", "normal", "", sfmt("PPID:  %d", p->ppid), -1, "", false);
    emit_row(rows, "exe", "normal", "", sfmt("EXE:   %s", p->exe.c_str()), -1, "", false);
    if (!p->exit_status.empty()) {
        std::string text = p->exit_status == "signaled"
            ? sfmt("Exit: signal %d%s", p->exit_signal, p->core_dumped ? " (core)" : "")
            : sfmt("Exit: exited code=%d", p->exit_code);
        emit_row(rows, "exit",
                 (p->exit_status == "exited" && p->exit_code == 0) ? "green" : "error",
                 "", text, -1, "", false);
    }
    int nchildren = static_cast<int>(p->children.size());
    if (nchildren > 0) {
        emit_row(rows, "kids_hdr", "heading", "", sfmt("Children (%d)", nchildren), -1, "", false);
        auto sorted_ch = p->children;
        if (sorted_ch.size() > 1)
            std::sort(sorted_ch.begin(), sorted_ch.end(),
                [](Item *a, Item *b) { return static_cast<process_t*>(a)->tgid < static_cast<process_t*>(b)->tgid; });
        for (auto *item : sorted_ch) {
            auto *c = static_cast<process_t*>(item);
            int ct = c->tgid;
            std::string cid = sfmt("child_%d", ct);
            std::string text = sfmt("[%d] %s", ct, c->display_name().c_str());
            emit_row(rows, cid, "normal", "", text, 0, std::to_string(ct), false);
        }
    }
    if (!p->argv.empty()) {
        emit_row(rows, "argv_hdr", "heading", "", "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Argv \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", -1, "", false);
        for (int i = 0; i < static_cast<int>(p->argv.size()); i++)
            emit_row(rows, sfmt("argv_%d", i), "normal", "", sfmt("[%d] %s", i, p->argv[i].c_str()), -1, "", false);
    }
    emit_row(rows, "evt_hdr", "heading", "", "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Events \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", -1, "", false);
    double prev_ts = -1;
    for (int ei : p->event_indices) {
        auto &ev = g_events[ei];
        if (!event_allowed(ev)) continue;
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
        emit_row(rows, sfmt("ev_%d", ev.id), ev.kind == EV_STDERR ? "error" : "normal", "", text, -1, "", false);
    }
}

static void build_rpane_file(std::vector<RowData> &rows, const std::string &id) {
    if (id.empty()) return;
    emit_row(rows, "hdr", "heading", "", "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 File \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", -1, "", false);
    emit_row(rows, "path", "normal", "", id, -1, "", false);
    PathItem *pd = find_path_item(id);
    int opens = pd ? pd->opens : 0;
    int errs  = pd ? pd->errs  : 0;
    int nprocs = pd ? static_cast<int>(pd->proc_tgids.size()) : 0;
    emit_row(rows, "opens", "normal", "", sfmt("Opens: %d", opens), -1, "", false);
    emit_row(rows, "procs", "normal", "", sfmt("Procs: %d", nprocs), -1, "", false);
    emit_row(rows, "errs", errs ? "error" : "normal", "", sfmt("Errors: %d", errs), -1, "", false);
    if (pd) {
        for (int ei : pd->open_event_indices) {
            auto &ev = g_events[ei];
            auto *p = find_process(ev.tgid);
            std::string err_text = ev.err ? sfmt(" err=%d", ev.err) : std::string();
            std::string text = sfmt("PID %d %s [%s]%s", ev.tgid,
                p ? p->display_name().c_str() : "",
                ev.flags_text.c_str(), err_text.c_str());
            emit_row(rows, sfmt("open_%d", ev.id),
                     ev.err ? "error" : (ev.kind == EV_STDERR ? "error" : "normal"),
                     "", text, 0, std::to_string(ev.tgid), false);
        }
    }
}

static void build_rpane_output(std::vector<RowData> &rows, const std::string &id) {
    int eid = id.empty() ? 0 : std::atoi(id.c_str());
    trace_event_t *ev = nullptr;
    for (auto &e : g_events) if (e.id == eid) { ev = &e; break; }
    if (!ev) return;
    auto *p = find_process(ev->tgid);
    emit_row(rows, "hdr", "heading", "", "─── Output ───", -1, "", false);
    emit_row(rows, "stream", ev->kind == EV_STDERR ? "error" : "normal", "",
             sfmt("Stream: %s", ev->kind == EV_STDOUT ? "STDOUT" : "STDERR"), -1, "", false);
    emit_row(rows, "pid", "normal", "", sfmt("PID: %d", ev->tgid), -1, "", false);
    emit_row(rows, "proc", "normal", "",
             sfmt("Proc: %s", p ? p->display_name().c_str() : ""),
             -1, "", false);
    emit_row(rows, "content_hdr", "heading", "", "─── Content ───", -1, "", false);
    emit_row(rows, "content", ev->kind == EV_STDERR ? "error" : "normal", "", ev->data, -1, "", false);
}

static void build_rpane(std::vector<RowData> &rows) {
    const auto &id = g_state.cursor_id;
    if (id.empty()) return;
    if (g_state.mode == 0 || g_state.mode == 5 || g_state.mode == 6)
        build_rpane_process(rows, id);
    else if (g_state.mode == 1 || g_state.mode >= 3) build_rpane_file(rows, id);
    else build_rpane_output(rows, id);
}

/* ── State management ──────────────────────────────────────────────── */

static void cancel_detail_update() {
    g_detail_update_pending = 0;
    if (g_tui && g_detail_timer_id >= 0)
        g_tui->remove_timer(g_detail_timer_id);
    g_detail_timer_id = -1;
}

static int on_detail_update_timer(Tui &tui) {
    (void)tui;
    g_detail_timer_id = -1;
    if (!g_detail_update_pending) return 0;
    g_detail_update_pending = 0;
    if (g_tui) g_tui->dirty(g_rpane);
    return 0;
}

static void schedule_detail_update() {
    if (!g_tui || g_headless) {
        if (g_tui) g_tui->dirty(g_rpane);
        update_status();
        return;
    }
    g_detail_update_pending = 1;
    if (g_detail_timer_id >= 0)
        g_tui->remove_timer(g_detail_timer_id);
    g_detail_timer_id = g_tui->add_timer(DETAIL_UPDATE_DELAY_MS, on_detail_update_timer);
}

/* ── Lazy DataSource ────────────────────────────────────────────────── */

/* Process tree DFS iterator (mode 0, grouped) — yields one row at a time. */
static struct {
    std::vector<std::pair<process_t*,int>> dfs; /* (process, depth) stack */
} g_proc_tree_iter;

/* Process flat iterator (mode 0, not grouped). */
static struct {
    std::vector<int> tgids;
    size_t idx = 0;
} g_proc_flat_iter;

/* Prebuilt rows for non-process modes (file, output, deps, rpane). */
static struct {
    std::vector<RowData> rows;
    size_t idx = 0;
} g_prebuilt_iter, g_rp_iter;

static int g_lp_mode = -1; /* which lpane sub-iterator is active: 0=proc_tree 1=proc_flat 2=prebuilt */

static void lpane_begin_proc_tree() {
    g_lp_mode = 0;
    g_proc_tree_iter.dfs.clear();
    std::vector<process_t*> roots;
    for (auto &[tgid, p] : g_proc_map)
        if ((p->ppid == 0 || !find_process(p->ppid)) && proc_should_show(tgid))
            roots.push_back(p.get());
    if (roots.size() > 1)
        std::sort(roots.begin(), roots.end(),
            [](process_t *a, process_t *b) { return a->tgid < b->tgid; });
    for (int i = static_cast<int>(roots.size()) - 1; i >= 0; i--)
        g_proc_tree_iter.dfs.push_back({roots[i], 0});
}

static void lpane_begin_proc_flat() {
    g_lp_mode = 1;
    g_proc_flat_iter.tgids.clear();
    g_proc_flat_iter.idx = 0;
    for (auto &[tgid, p] : g_proc_map)
        if (proc_should_show(tgid)) g_proc_flat_iter.tgids.push_back(tgid);
    if (g_proc_flat_iter.tgids.size() > 1)
        std::sort(g_proc_flat_iter.tgids.begin(), g_proc_flat_iter.tgids.end(), cmp_proc_tgid);
}

static void build_lpane_nonprocess(std::vector<RowData> &rows) {
    switch (g_state.mode) {
    case 1: build_lpane_files(rows); break;
    case 2: build_lpane_output(rows); break;
    case 3: build_lpane_deps(rows, 1); break;
    case 4: build_lpane_deps(rows, 0); break;
    case 5: build_lpane_dep_cmds(rows, 1); break;
    case 6: build_lpane_dep_cmds(rows, 0); break;
    default: break;
    }
}

static void ds_row_begin(int panel) {
    if (panel == g_lpane) {
        if (g_state.mode == 0) {
            if (g_state.grouped)
                lpane_begin_proc_tree();
            else
                lpane_begin_proc_flat();
        } else {
            g_lp_mode = 2;
            g_prebuilt_iter.rows.clear();
            g_prebuilt_iter.idx = 0;
            build_lpane_nonprocess(g_prebuilt_iter.rows);
        }
    } else {
        g_rp_iter.rows.clear();
        g_rp_iter.idx = 0;
        build_rpane(g_rp_iter.rows);
    }
}

static bool ds_row_has_more(int panel) {
    if (panel == g_lpane) {
        switch (g_lp_mode) {
        case 0: return !g_proc_tree_iter.dfs.empty();
        case 1: return g_proc_flat_iter.idx < g_proc_flat_iter.tgids.size();
        case 2: return g_prebuilt_iter.idx < g_prebuilt_iter.rows.size();
        }
        return false;
    }
    return g_rp_iter.idx < g_rp_iter.rows.size();
}

static RowData ds_row_next(int panel) {
    if (panel == g_lpane) {
        switch (g_lp_mode) {
        case 0: { /* proc tree DFS */
            auto &dfs = g_proc_tree_iter.dfs;
            auto [p, depth] = dfs.back();
            dfs.pop_back();
            bool has_kids = !p->children.empty();
            bool collapsed_flag = has_kids && p->collapsed;
            /* Push children in reverse-sorted order (lowest tgid comes out first). */
            if (!collapsed_flag && has_kids) {
                auto sorted_ch = p->children;
                if (sorted_ch.size() > 1)
                    std::sort(sorted_ch.begin(), sorted_ch.end(),
                        [](Item *a, Item *b) { return static_cast<process_t*>(a)->tgid < static_cast<process_t*>(b)->tgid; });
                for (int i = static_cast<int>(sorted_ch.size()) - 1; i >= 0; i--) {
                    auto *cp = static_cast<process_t*>(sorted_ch[i]);
                    if (proc_should_show(cp->tgid))
                        dfs.push_back({cp, depth + 1});
                }
            }
            return make_proc_tree_row(p, depth);
        }
        case 1: { /* proc flat */
            int tgid = g_proc_flat_iter.tgids[g_proc_flat_iter.idx++];
            auto *p = find_process(tgid);
            if (!p) return {};
            return make_proc_flat_row(p);
        }
        case 2: /* prebuilt */
            return std::move(g_prebuilt_iter.rows[g_prebuilt_iter.idx++]);
        }
        return {};
    }
    return std::move(g_rp_iter.rows[g_rp_iter.idx++]);
}

static void update_status() {
    static const char *mn[] = {"PROCS","FILES","OUTPUT","DEPS","RDEPS","DEP-CMDS","RDEP-CMDS"};
    static const char *tsl[] = {"abs","rel","Δ"};
    int cur = g_tui ? g_tui->get_cursor(g_lpane) : 0;
    std::string s = sfmt(" %s%s | row %d | TS:%s", mn[g_state.mode], g_state.grouped ? " tree" : "",
                         cur + 1, tsl[g_state.ts_mode]);
    if (!g_state.evfilt.empty()) s += sfmt(" | F:%s", g_state.evfilt.c_str());
    if (!g_state.search.empty()) s += sfmt(" | /%s", g_state.search.c_str());
    if (g_state.lp_filter == 1) s += " | V:failed";
    else if (g_state.lp_filter == 2) s += " | V:running";
    if (g_state.mode >= 3 && g_state.mode <= 6) s += sfmt(" | D:%s", g_state.dep_filter ? "written" : "all");
    s += " | 1:proc 2:file 3:out 4:dep 5:rdep 6:dcmd 7:rcmd ?:help";
    if (g_tui) g_tui->set_status(s.c_str());
}

/* ── Layout ────────────────────────────────────────────────────────── */

static const ColDef g_text_col[] = {{-1, TUI_ALIGN_LEFT, TUI_OVERFLOW_TRUNCATE}};
static const PanelDef g_lpane_def = {nullptr, g_text_col, 1, TUI_PANEL_CURSOR};
static const PanelDef g_rpane_def = {nullptr, g_text_col, 1, TUI_PANEL_CURSOR | TUI_PANEL_BORDER};

/* ── Navigation ────────────────────────────────────────────────────── */

static void reset_mode_selection() {
    g_state.cursor_id.clear();
    g_state.dcursor_id.clear();
    if (g_tui) g_tui->focus(g_lpane);
}

static void set_cursor_to_search_hit(int dir) {
    if (!g_tui) return;
    int start = g_tui->get_cursor(g_lpane);
    if (dir > 0) {
        /* Forward: scan from start+1 to end, then wrap from 0 to start-1. */
        for (int i = start + 1; ; i++) {
            auto *r = g_tui->get_cached_row(g_lpane, i);
            if (!r) break;
            if (r->style == "search") { g_state.cursor_id = r->id; return; }
        }
        for (int i = 0; i < start; i++) {
            auto *r = g_tui->get_cached_row(g_lpane, i);
            if (!r) break;
            if (r->style == "search") { g_state.cursor_id = r->id; return; }
        }
    } else {
        /* Backward: scan from start-1 down to 0, then wrap from end to start+1. */
        for (int i = start - 1; i >= 0; i--) {
            auto *r = g_tui->get_cached_row(g_lpane, i);
            if (!r) break;
            if (r->style == "search") { g_state.cursor_id = r->id; return; }
        }
        /* Find the end by scanning forward, then scan backward from there. */
        int last = start;
        while (g_tui->get_cached_row(g_lpane, last + 1)) last++;
        for (int i = last; i > start; i--) {
            auto *r = g_tui->get_cached_row(g_lpane, i);
            if (!r) break;
            if (r->style == "search") { g_state.cursor_id = r->id; return; }
        }
    }
}

static void apply_search(const std::string &q) {
    g_state.search = q;
    /* Dirty lpane so the engine re-reads with search highlighting. */
    if (g_tui) g_tui->dirty(g_lpane);
    /* Scan lazily to find the first hit. */
    for (int i = 0; ; i++) {
        auto *r = g_tui ? g_tui->get_cached_row(g_lpane, i) : nullptr;
        if (!r) break;
        if (r->style == "search") {
            g_state.cursor_id = r->id;
            break;
        }
    }
}

static void collapse_or_back() {
    if (g_tui && g_tui->get_focus() == g_rpane) { g_tui->focus(g_lpane); return; }
    int cur = g_tui ? g_tui->get_cursor(g_lpane) : -1;
    auto *row = g_tui ? g_tui->get_cached_row(g_lpane, cur) : nullptr;
    if (!row) return;
    if (row->has_children && !is_collapsed(row->id)) {
        set_collapsed(row->id, true);
    }
    else if (!row->parent_id.empty()) g_state.cursor_id = row->parent_id;
}

static void expand_or_detail() {
    bool in_rpane = g_tui && g_tui->get_focus() == g_rpane;
    int cur = g_tui ? g_tui->get_cursor(in_rpane ? g_rpane : g_lpane) : -1;
    auto *row = g_tui ? g_tui->get_cached_row(in_rpane ? g_rpane : g_lpane, cur) : nullptr;
    if (!row) return;
    if (in_rpane) {
        if (row->link_mode >= 0 && !row->link_id.empty()) {
            g_state.mode = row->link_mode;
            reset_mode_selection();
            g_state.cursor_id = row->link_id;
        }
        return;
    }
    if (row->has_children && is_collapsed(row->id)) {
        set_collapsed(row->id, false);
    }
    else if (g_tui) g_tui->focus(g_rpane);
}

static void expand_subtree(int expand) {
    int cur = g_tui ? g_tui->get_cursor(g_lpane) : -1;
    auto *row = g_tui ? g_tui->get_cached_row(g_lpane, cur) : nullptr;
    if (!row || !row->has_children) return;
    if (g_state.mode == 0) {
        auto *p = find_process(std::atoi(row->id.c_str()));
        if (p) p->setCollapsedRecursive(!expand);
    } else if (g_state.mode == 1) {
        PathItem *pi = find_path_item(row->id);
        if (pi) pi->setCollapsedRecursive(!expand);
    } else {
        set_collapsed(row->id, !expand);
    }
}

/* ── Diagnostics ───────────────────────────────────────────────────── */

static void dump_lpane(FILE *out) {
    if (!g_tui) return;
    std::fprintf(out, "=== LPANE ===\n");
    g_tui->dump_panel(g_lpane, out, [](FILE *f, int i, const RowData &r) {
        std::fprintf(f, "%d|%s|%s|%s|%s\n", i, r.style.c_str(), r.id.c_str(),
                     r.parent_id.c_str(), r.cols.empty() ? "" : r.cols[0].c_str());
    });
    std::fprintf(out, "=== END LPANE ===\n");
}

static void dump_rpane(FILE *out) {
    if (!g_tui) return;
    std::fprintf(out, "=== RPANE ===\n");
    g_tui->dump_panel(g_rpane, out, [](FILE *f, int i, const RowData &r) {
        std::fprintf(f, "%d|%s|%s|%d|%s\n", i, r.style.c_str(),
                     r.cols.empty() ? "" : r.cols[0].c_str(),
                     r.link_mode, r.link_id.c_str());
    });
    std::fprintf(out, "=== END RPANE ===\n");
}

static void dump_state(FILE *out) {
    int cursor = g_tui ? g_tui->get_cursor(g_lpane) : 0;
    int scroll = g_tui ? g_tui->get_scroll(g_lpane) : 0;
    int focus_r = g_tui && g_tui->get_focus() == g_rpane ? 1 : 0;
    int dcursor = g_tui ? g_tui->get_cursor(g_rpane) : 0;
    int dscroll = g_tui ? g_tui->get_scroll(g_rpane) : 0;
    int rows = g_tui ? g_tui->rows() : 24;
    int cols = g_tui ? g_tui->cols() : 80;
    std::fprintf(out, "=== STATE ===\n");
    std::fprintf(out, "cursor=%d scroll=%d focus=%d dcursor=%d dscroll=%d ts_mode=%d sort_key=%d grouped=%d mode=%d lp_filter=%d search=%s evfilt=%s rows=%d cols=%d dep_filter=%d\n",
            cursor, scroll, focus_r, dcursor, dscroll,
            g_state.ts_mode, g_state.sort_key, g_state.grouped, g_state.mode, g_state.lp_filter,
            g_state.search.c_str(), g_state.evfilt.c_str(), rows, cols, g_state.dep_filter);
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
    if (g_tui) {
        g_tui->dirty();
        if (!g_state.cursor_id.empty())
            g_tui->set_cursor(g_lpane, g_state.cursor_id.c_str());
        if (!g_state.dcursor_id.empty())
            g_tui->set_cursor(g_rpane, g_state.dcursor_id.c_str());
    }
    update_status();
}

static int on_key_cb(Tui &tui, int key, int panel, int cursor, const char *row_id) {
    (void)cursor;
    if (key == TUI_K_NONE) {
        if (panel == g_lpane) {
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
                if (g_save_fp) {
                    std::rewind(g_save_fp);
                    char cbuf[4096]; size_t nr;
                    while ((nr = std::fread(cbuf, 1, sizeof cbuf, g_save_fp)) > 0)
                        std::fwrite(cbuf, 1, nr, f);
                }
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

static void process_input_line(const char *line) {
    std::string_view sp;
    if (!json_get(line, "input", sp)) return;
    std::string kind = json_decode_string(sp);
    if (kind == "key") {
        int key = TUI_K_NONE;
        if (json_get(line, "name", sp)) key = key_name_to_code(json_decode_string(sp));
        else if (json_get(line, "key", sp)) key = span_to_int(sp, TUI_K_NONE);
        if (key != TUI_K_NONE) g_tui->input_key(key);
    } else if (kind == "resize") {
        int r = 0, c = 0;
        if (json_get(line, "rows", sp)) r = span_to_int(sp, 0);
        if (json_get(line, "cols", sp)) c = span_to_int(sp, 0);
        g_tui->resize(r, c);
        update_status();
    } else if (kind == "select") {
        reset_mode_selection();
        if (json_get(line, "id", sp)) g_state.cursor_id = json_decode_string(sp);
        apply_state_change();
    } else if (kind == "search") {
        std::string q;
        if (json_get(line, "q", sp)) q = json_decode_string(sp);
        apply_search(q);
        apply_state_change();
    } else if (kind == "evfilt") {
        if (json_get(line, "q", sp)) g_state.evfilt = json_decode_string(sp);
        for (auto &c : g_state.evfilt) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        apply_state_change();
    } else if (kind == "print") {
        std::string what;
        if (json_get(line, "what", sp)) what = json_decode_string(sp);
        process_print(what);
    }
}

static void save_to_file(const char *path) {
    if (!g_save_fp) return;
    FILE *out = std::fopen(path, "w");
    if (!out) { std::fprintf(stderr, "tv: cannot create %s\n", path); return; }
    std::rewind(g_save_fp);
    char buf[4096]; size_t nr;
    while ((nr = std::fread(buf, 1, sizeof buf, g_save_fp)) > 0)
        std::fwrite(buf, 1, nr, out);
    std::fclose(out);
}

/* ── Live trace ────────────────────────────────────────────────────── */

static void on_live_batch() {
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
            apply_state_change();
            t_pending_live_rows = 0;
            t_live_batch_start_ms = 0;
        }
    }
    update_status();
}

/* ── Cleanup ───────────────────────────────────────────────────────── */

static void free_all() {
    g_events.clear();
    g_proc_map.clear();
    free_path_tree(&g_path_root);
    free_nonabs_paths();
    if (g_save_fp) { std::fclose(g_save_fp); g_save_fp = nullptr; }
    g_input_lines.clear();
    g_output_collapsed.clear();
}

/* ── Test API (non-static, called from tests.cpp) ─────────────────── */

extern int run_tests();  /* defined in tests.cpp */

void tv_test_reset() {
    g_tui.reset();
    free_all();
    g_state = {};
    g_next_event_id = 1;
    g_base_ts = 0.0;
    g_lpane = -1;
    g_rpane = -1;
    g_headless = 0;
}

void tv_test_load(const char *path) { ingest_file(path); }

void tv_test_load_string(const char *data) {
    char tmp[] = "/tmp/tv_test_XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) return;
    (void)write(fd, data, std::strlen(data));
    close(fd);
    ingest_file(tmp);
    unlink(tmp);
}

void tv_test_create(int rows, int cols) {
    DataSource src{ds_row_begin, ds_row_has_more, ds_row_next};
    g_tui = Tui::open_headless(std::move(src), rows, cols);
    if (!g_tui) return;
    g_lpane = g_tui->add_panel(g_lpane_def);
    g_rpane = g_tui->add_panel(g_rpane_def);
    static Box lbox, rbox, hbox;
    lbox = {TUI_BOX_PANEL, 1, 0, 0, g_lpane, {}};
    rbox = {TUI_BOX_PANEL, 1, 0, 0, g_rpane, {}};
    hbox = {TUI_BOX_HBOX, 1, 0, 0, -1, {&lbox, &rbox}};
    g_tui->set_layout(&hbox);
    g_tui->on_key(on_key_cb);
    g_tui->dirty();
    g_headless = 1;
    update_status();
}

void tv_test_input(const char *line) { process_input_line(line); }
int  tv_test_lpane() { return g_lpane; }
int  tv_test_rpane() { return g_rpane; }
Tui *tv_test_tui()   { return g_tui.get(); }
int  tv_test_mode()       { return g_state.mode; }
int  tv_test_grouped()    { return g_state.grouped; }
int  tv_test_sort_key()   { return g_state.sort_key; }
int  tv_test_ts_mode()    { return g_state.ts_mode; }
int  tv_test_lp_filter()  { return g_state.lp_filter; }
int  tv_test_dep_filter() { return g_state.dep_filter; }
const char *tv_test_search() { return g_state.search.c_str(); }
const char *tv_test_evfilt() { return g_state.evfilt.c_str(); }

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
    if (argc >= 2 && std::strcmp(argv[1], "--test") == 0) return run_tests();
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

    int headless_mode = (!g_input_lines.empty()) ||
                        (trace_file[0] && !cmd && !isatty(STDIN_FILENO)) ||
                        (save_file[0] && !cmd);

    DataSource src{ds_row_begin, ds_row_has_more, ds_row_next};

    if (headless_mode) g_tui = Tui::open_headless(std::move(src), 24, 80);
    else g_tui = Tui::open(std::move(src));
    if (!g_tui) {
        if (!headless_mode) std::fprintf(stderr, "tv: cannot open terminal\n");
        free_all();
        return headless_mode ? 0 : 1;
    }

    {
        g_lpane = g_tui->add_panel(g_lpane_def);
        g_rpane = g_tui->add_panel(g_rpane_def);
        static Box lbox = {TUI_BOX_PANEL, 1, 0, 0, g_lpane, {}};
        static Box rbox = {TUI_BOX_PANEL, 1, 0, 0, g_rpane, {}};
        static Box hbox = {TUI_BOX_HBOX, 1, 0, 0, -1, {&lbox, &rbox}};
        g_tui->set_layout(&hbox);
    }
    g_tui->on_key(on_key_cb);
    g_tui->dirty();
    update_status();

    for (const auto &line : g_input_lines) process_input_line(line.c_str());
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
