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
#include <sys/wait.h>
#include <fcntl.h>

#include <fnmatch.h>

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
#include "intern.h"
#include "wire_in.h"

/* ── Global intern pool ────────────────────────────────────────────── */
/* Single unified pool for all interned data (strings, argv, output). */
static Intern g_pool;

/* ── Item — abstract base for hierarchical items ───────────────────── */

struct Item {
    std::vector<Item*>        children;
    bool                      collapsed = false;
    sorted_vec_set<Item*>     deps;
    sorted_vec_set<Item*>     rdeps;
    sorted_vec_set<int>       events;     /* indices into g_events */

    virtual ~Item() = default;
    virtual std::string_view getKey() const = 0;
    virtual RowStyle  style()         const { return RowStyle::Normal; }
    virtual bool      hasChildren()   const { return !children.empty(); }
    virtual bool      shouldShow()    const { return true; }
    virtual int       sortKey()       const { return 0; }
    virtual std::string getParentKey()const { return {}; }
    virtual RowData   makeRow(int depth) const = 0;
};

/* ── PathItem — hierarchical filesystem path node ──────────────────── */

struct PathItem : Item {
    InlineIID           name_id{};   /* interned single path component */
    PathItem           *parent = nullptr;
    bool                is_dir = false;

    /* file stats, aggregated incrementally */
    int opens = 0;
    int errs  = 0;
    int unlinks = 0;
    int aggregated_mode = 0;        /* bitwise OR of all open mode values */
    double last_open_write_ts = 0;  /* ts of last write-mode OPEN */
    double last_unlink_ts = 0;      /* ts of last UNLINK */
    std::unordered_set<int> proc_tgids;
    std::vector<int> open_event_indices;    /* OPEN events into g_events */
    std::vector<int> unlink_event_indices;  /* UNLINK events into g_events */
    sorted_vec_set<int> read_procs;         /* processes that read this path */
    sorted_vec_set<int> write_procs;        /* processes that wrote this path */
    sorted_vec_set<int> unlink_procs;       /* processes that unlinked this path */

    bool was_ever_read() const { return (aggregated_mode & O_ACCMODE) == O_RDONLY || (aggregated_mode & O_ACCMODE) == O_RDWR || !read_procs.empty(); }
    bool was_ever_written() const { return !write_procs.empty(); }
    bool was_ever_unlinked() const { return unlinks > 0; }
    bool unlinked_at_end() const { return last_unlink_ts > 0 && last_unlink_ts > last_open_write_ts; }

    /* Name as string_view — total because name_id is in the inline pool. */
    std::string_view nameView() const { return g_pool.view(name_id); }

    /* Build full path, lazily cached.  Single allocation total per node. */
    std::string_view fullPathView() const {
        if (full_path_cached_) return full_path_;
        if (!parent) {
            full_path_ = "/";
        } else {
            /* Compute total length first to avoid reallocs. */
            size_t total = 0;
            for (const PathItem *n = this; n->parent; n = n->parent)
                total += 1 + g_pool.view(n->name_id).size();
            full_path_.clear();
            full_path_.reserve(total);
            /* Build by collecting the chain then emitting in reverse. */
            std::vector<std::string_view> segs;
            for (const PathItem *n = this; n->parent; n = n->parent)
                segs.push_back(g_pool.view(n->name_id));
            for (auto it = segs.rbegin(); it != segs.rend(); ++it) {
                full_path_ += '/';
                full_path_.append(it->data(), it->size());
            }
        }
        full_path_cached_ = true;
        return full_path_;
    }
    std::string fullPath() const { return std::string(fullPathView()); }

    std::string_view getKey() const override { return fullPathView(); }

    RowStyle    style()          const override;
    std::string getParentKey()   const override;
    RowData     makeRow(int depth) const override;

    /* O(1) average child lookup via unordered_map keyed by name IID. */
    PathItem *getOrCreateChild(InlineIID child_name_id, bool dir) {
        auto it = children_set_.find(child_name_id.v);
        if (it != children_set_.end()) return it->second;
        auto *nc = new PathItem();
        nc->name_id = child_name_id;
        nc->parent = this;
        nc->is_dir = dir;
        children.push_back(nc);
        children_set_.emplace(child_name_id.v, nc);
        return nc;
    }

    PathItem *findChild(InlineIID child_name_id) const {
        auto it = children_set_.find(child_name_id.v);
        return it != children_set_.end() ? it->second : nullptr;
    }

    void clearChildSet() { children_set_.clear(); }
    void invalidateFullPathCache() { full_path_cached_ = false; full_path_.clear(); }

private:
    mutable std::string full_path_;        /* cached full path */
    mutable bool        full_path_cached_ = false;

    mutable std::unordered_map<uint32_t, PathItem*> children_set_;
};

/* Deterministic ordering of PathItem* — by name IID up the parent chain.
   Pointer compares are non-deterministic (ASLR); name-id chain is stable. */
struct PathItemPtrLess {
    bool operator()(const PathItem *a, const PathItem *b) const {
        if (a == b) return false;
        if (!a) return true;
        if (!b) return false;
        /* Walk both up to root, build chains, compare lexicographically. */
        std::vector<uint32_t> ca, cb;
        for (const PathItem *p = a; p->parent; p = p->parent) ca.push_back(p->name_id.v);
        for (const PathItem *p = b; p->parent; p = p->parent) cb.push_back(p->name_id.v);
        std::reverse(ca.begin(), ca.end());
        std::reverse(cb.begin(), cb.end());
        return ca < cb;
    }
};

/* Recursively delete all PathItems below node (excluding node itself). */
static void free_path_tree_children(PathItem *node) {
    for (auto *c : node->children) {
        free_path_tree_children(static_cast<PathItem*>(c));
        delete static_cast<PathItem*>(c);
    }
    node->children.clear();
    node->clearChildSet();
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

/* 7 event kinds — fits in uint8_t (max 255). */
enum event_kind_t : uint8_t {
    EV_CWD,
    EV_EXEC,
    EV_OPEN,
    EV_UNLINK,
    EV_EXIT,
    EV_STDOUT,
    EV_STDERR
};

/* Compact trace event — no std::string members.
   All strings go through g_pool (interned/compressed).
   Paths use PathItem* from the interned file tree. */
struct trace_event_t {
    int id = 0;
    event_kind_t kind = EV_CWD;
    uint8_t core_dumped = 0;
    double ts = 0;
    int tgid = 0, ppid = 0;

    PathItem *path_item = nullptr;     /* resolved path (CWD/OPEN/UNLINK) */

    BlobIID   exe_id{};               /* EXEC: interned exe path */
    BlobIID   argv_blob{};            /* EXEC: interned argv */

    InlineIID flags_id{};             /* OPEN: interned flag string */
    int mode = 0;                     /* OPEN: raw open flags integer */
    int err = 0;                      /* OPEN: errno if failed */

    BlobIID   data_blob{};            /* STDOUT/STDERR: interned output */

    InlineIID status_id{};            /* EXIT: interned status string */
    int code = 0;                     /* EXIT: exit code */
    int signal = 0;                   /* EXIT: signal number */

    std::string get_path() const { return path_item ? path_item->fullPath() : std::string(); }
    std::string get_exe() const { return g_pool.str(exe_id); }
    std::string get_flags_text() const { return g_pool.str(flags_id); }
    std::string get_data() const { return g_pool.str(data_blob); }
};

struct process_t : Item {
    int tgid = 0, ppid = 0;
    bool parent_set = false;
    double start_ts = 0, end_ts = 0;
    int has_start = 0, has_end = 0;
    BlobIID   exe_id{};
    BlobIID   argv_blob{};
    PathItem *cwd_item = nullptr;
    InlineIID exit_status_id{};
    int exit_code = 0;
    int exit_signal = 0;
    int core_dumped = 0;
    int has_write_open = 0;
    int has_stdout = 0;
    /* Sets of paths this process touched.  Sorted by name-id chain
       (PathItemPtrLess) so iteration order is deterministic across runs. */
    sorted_vec_set<PathItem*, PathItemPtrLess> read_paths;
    sorted_vec_set<PathItem*, PathItemPtrLess> write_paths;
    std::vector<int> event_indices;
    std::string cached_display_name;

    /* CWD as a PathItem* (was: separately interned IID).  Kills the
       extra g_pool.put on every CWD/OPEN. */
    std::string get_exe() const { return g_pool.str(exe_id); }
    std::vector<std::string> get_argv() const { return g_pool.get_argv(argv_blob); }
    std::string get_cwd() const { return cwd_item ? cwd_item->fullPath() : std::string(); }
    std::string_view cwd_view() const { return cwd_item ? cwd_item->fullPathView() : std::string_view(); }
    void set_cwd(PathItem *item) { cwd_item = item; }

    void update_display_name() {
        std::string s = get_exe();
        if (s.empty()) {
            auto argv = get_argv();
            if (!argv.empty()) s = std::move(argv[0]);
        }
        if (s.empty()) { cached_display_name.clear(); return; }
        auto pos = s.rfind('/');
        cached_display_name = (pos != std::string::npos) ? s.substr(pos + 1) : std::move(s);
    }
    const std::string &display_name() const { return cached_display_name; }

    std::string_view getKey() const override {
        /* tgid is the key — intern once for stable string_view. */
        if (!key_id_) key_id_ = g_pool.put_inline(std::to_string(tgid));
        return g_pool.view(key_id_);
    }
    int         sortKey()        const override { return tgid; }
    RowStyle    style()          const override;
    bool        shouldShow()     const override;
    std::string getParentKey()   const override;
    RowData     makeRow(int depth) const override;

private:
    mutable InlineIID key_id_{};
};

struct app_state_t {
    int mode = 0;
    int grouped = 1;
    int ts_mode = 0;
    int sort_key = 0;
    int lp_filter = 0;
    int dep_filter = 0;
    int file_refinement = 0;        /* 0=all, 1=hide sys, 2=+hide deleted, 3=+hide non-fail */
    int file_mode_filter = 0x0F;    /* bit0=R, bit1=W, bit2=unlinked-ever, bit3=unlinked-at-end */
    std::string subtree_root;       /* when non-empty, only show descendants of this path */
    std::string file_glob;          /* glob pattern for file path filtering */
    std::string cursor_id;
    std::string dcursor_id;

    /* search / event filter — short user input strings, kept inline. */
    InlineIID search_id{};
    InlineIID evfilt_id{};

    std::string_view search_sv() const { return g_pool.view(search_id); }
    std::string_view evfilt_sv() const { return g_pool.view(evfilt_id); }

    void set_search(std::string_view q) {
        search_id = q.empty() ? InlineIID{} : g_pool.put_inline(q);
    }
    void set_evfilt(std::string_view q) {
        evfilt_id = q.empty() ? InlineIID{} : g_pool.put_inline(q);
    }
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
/* trace_db_t is defined below (after helper types/functions it depends on).
   Other global state that doesn't depend on those types lives here. */

static app_state_t g_state;
static std::unique_ptr<Tui> g_tui;
static int g_headless;
static int g_lpane = -1, g_rpane = -1;

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
    "  v  Cycle proc filter (none→failed→running)    V  Clear proc filter", "",
    "  File filters (mode 2):  r  Cycle refinement (all→hide-sys→hide-deleted→hide-non-fail)",
    "    R  Toggle show Read files    D  Toggle show Write files",
    "    U  Toggle show Unlinked files    S/C  Set/Clear subtree root    p/P  Glob/Clear glob",
    "  x  SQL removed    q  Quit    ?  Help", "", "  Press any key.", nullptr
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

/* Path classification.  Done once at parse time, never re-sniffed. */
enum path_kind_t : uint8_t {
    PK_NONE = 0,
    PK_ABS = 1,
    PK_ABSTRACT = 2,
    PK_RELATIVE = 3,
};

static path_kind_t classify_path(std::string_view raw) {
    if (raw.empty()) return PK_NONE;
    if (raw[0] == '/') return PK_ABS;
    if (raw[0] != '.' && raw.find(':') != std::string_view::npos)
        return PK_ABSTRACT;
    return PK_RELATIVE;
}

/* Resolve a relative path against a CWD and canonicalise.  Returns the
   resolved absolute path, or an empty string if cwd is unknown. */
static std::string resolve_relative(std::string_view raw, std::string_view cwd) {
    if (raw.empty()) return {};
    std::string out;
    if (!cwd.empty()) { out.reserve(cwd.size() + 1 + raw.size()); out = cwd; out += '/'; out += raw; }
    else { out.assign(raw); }
    if (!out.empty() && out[0] == '/') out = canon_path(out);
    return out;
}



/* ── View helpers ──────────────────────────────────────────────────── */

/* Thin wrappers that delegate to g_db — defined after trace_db_t. */
static process_t *find_process(int tgid);
static PathItem  *find_path_item(std::string_view path);

/* Output group collapsed state — stored in a persistent map since output groups
   are rebuilt each time. */
static std::unordered_map<std::string, bool> g_output_collapsed;

static bool is_collapsed(const std::string &id) {
    if (!id.empty() && id[0] >= '0' && id[0] <= '9') {
        auto *p = find_process(std::atoi(id.c_str()));
        if (p) return p->collapsed;
    }
    PathItem *pi = find_path_item(id);
    if (pi) return pi->collapsed;
    auto it = g_output_collapsed.find(id);
    if (it != g_output_collapsed.end()) return it->second;
    return false;
}

static void set_collapsed(const std::string &id, bool c) {
    if (!id.empty() && id[0] >= '0' && id[0] <= '9') {
        auto *p = find_process(std::atoi(id.c_str()));
        if (p) { p->collapsed = c; return; }
    }
    PathItem *pi = find_path_item(id);
    if (pi) { pi->collapsed = c; return; }
    g_output_collapsed[id] = c;
}

/* Emit one row into a RowData vector. */
static void emit_row(std::vector<RowData> &v, const std::string &id,
                     RowStyle style, const std::string &parent_id,
                     const std::string &text, int link_mode,
                     const std::string &link_id, bool has_children) {
    RowData d;
    d.id = id;
    d.style = style;
    d.cols = {text};
    d.parent_id = parent_id;
    d.link_mode = link_mode;
    d.link_id = link_id;
    d.has_children = has_children;
    v.push_back(std::move(d));
}

/* ── Trace ingestion ───────────────────────────────────────────────── */

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

/* ── Pre-parsed event for parallel ingestion ──────────────────────── */
/* Phase 1 (parallel): extract JSON fields into this struct.
   Phase 2 (sequential): apply to global state.

   Path resolution semantics (Step C):
   - The decoded raw path is carried as `raw_path` (a std::string moved
     out of the JSON decoder; never interned for transient use).
   - The kind (ABS / ABSTRACT / RELATIVE) is classified once at parse
     time so the ':' sniff isn't redone per event.
   - In phase 2, RELATIVE paths are resolved against proc.get_cwd();
     ABS paths are canonicalised; ABSTRACT paths are stored as-is. */

struct preparsed_event_t {
    event_kind_t kind = EV_CWD;
    bool valid = false;
    bool is_input = false;
    double ts = 0;
    int tgid = 0, ppid = 0;

    /* CWD/OPEN/UNLINK: decoded raw path + classification. */
    std::string raw_path;
    path_kind_t path_kind = PK_NONE;

    BlobIID   exe_id{};            /* EXEC */
    BlobIID   argv_blob{};         /* EXEC */

    InlineIID flags_id{};          /* OPEN */
    int mode = 0;                  /* OPEN */
    int err = 0;                   /* OPEN */

    InlineIID status_id{};         /* EXIT */
    int code = 0;                  /* EXIT */
    int signal_ = 0;               /* EXIT */
    uint8_t core_dumped = 0;       /* EXIT */

    BlobIID   data_blob{};         /* STDOUT/STDERR */

    BlobIID   input_line_id{};     /* "input" JSON line — interned blob */
};

/* Phase 1: Parse a single JSON line into a preparsed_event_t.
   Thread-safe: only uses g_pool (which is sharded / lock-per-shard). */
static preparsed_event_t preparse_line(const char *line) {
    preparsed_event_t pe;
    std::string_view sp;
    if (!line || !line[0] || line[0] != '{') return pe;
    if (json_get(line, "input", sp)) {
        pe.is_input = true;
        pe.input_line_id = g_pool.put_blob(std::string_view(line, std::strlen(line)));
        pe.valid = true;
        return pe;
    }
    if (!json_get(line, "event", sp)) return pe;
    std::string kind = json_decode_string(sp);
    if (kind.empty()) return pe;

    if (kind == "CWD") pe.kind = EV_CWD;
    else if (kind == "EXEC") pe.kind = EV_EXEC;
    else if (kind == "OPEN") pe.kind = EV_OPEN;
    else if (kind == "UNLINK") pe.kind = EV_UNLINK;
    else if (kind == "EXIT") pe.kind = EV_EXIT;
    else if (kind == "STDOUT") pe.kind = EV_STDOUT;
    else if (kind == "STDERR") pe.kind = EV_STDERR;
    else return pe;

    pe.valid = true;
    if (json_get(line, "ts", sp)) pe.ts = span_to_double(sp, 0.0);
    if (json_get(line, "tgid", sp)) pe.tgid = span_to_int(sp, 0);
    if (json_get(line, "ppid", sp)) pe.ppid = span_to_int(sp, 0);

    auto take_path = [&](const char *jkey) {
        if (json_get(line, jkey, sp) && !sp.empty() && sp[0] != 'n') {
            pe.raw_path = json_decode_string(sp);
            pe.path_kind = classify_path(pe.raw_path);
        }
    };

    switch (pe.kind) {
    case EV_CWD:
        take_path("path");
        break;
    case EV_EXEC:
        if (json_get(line, "exe", sp)) pe.exe_id = g_pool.put_blob(json_decode_string(sp));
        if (json_get(line, "argv", sp)) pe.argv_blob = g_pool.put_blob_argv(json_array_of_strings(sp));
        break;
    case EV_OPEN:
        take_path("path");
        { std::vector<std::string> flags;
          if (json_get(line, "flags", sp)) flags = json_array_of_strings(sp);
          pe.flags_id = g_pool.put_inline(join_with_pipe(flags)); }
        if (json_get(line, "mode", sp)) pe.mode = span_to_int(sp, 0);
        if (json_get(line, "err", sp)) pe.err = span_to_int(sp, 0);
        break;
    case EV_UNLINK:
        take_path("path");
        break;
    case EV_EXIT:
        if (json_get(line, "status", sp)) pe.status_id = g_pool.put_inline(json_decode_string(sp));
        if (json_get(line, "code", sp)) pe.code = span_to_int(sp, 0);
        if (json_get(line, "signal", sp)) pe.signal_ = span_to_int(sp, 0);
        if (json_get(line, "core_dumped", sp)) pe.core_dumped = static_cast<uint8_t>(span_to_bool(sp, 0));
        break;
    case EV_STDOUT:
    case EV_STDERR:
        if (json_get(line, "data", sp)) pe.data_blob = g_pool.put_blob(json_decode_string(sp));
        break;
    }
    return pe;
}

/* ── Wire-format ingestion ────────────────────────────────────────── */
/* The producers (sud, proctrace, uproctrace) emit binary wire events
 * defined in wire/wire.h. wire_in.{h,cpp} is the streaming decoder.
 * Here we adapt each WireRawEvent into the same preparsed_event_t the
 * JSON path produces, so apply_preparsed() (and the parallel pipeline)
 * stays unchanged.
 *
 * Note: we don't use parallel_ingest for wire input. The wire stream is
 * delta-encoded, so it must be decoded in order — the decoder owns
 * shared `ev_state`. After decoding, `apply_preparsed` is the only hot
 * path and is fast enough sequentially for interactive viewing. (If
 * profile shows otherwise, the post-decode preparsed_event_t buffer can
 * be tgid-bucketed exactly like the JSON path.) */

static std::string format_open_flags(int flags) {
    /* Format an open(2) flags integer into the same `O_RDONLY|O_CLOEXEC`
     * pipe-separated string that the JSON ingester used to receive. The
     * access mode goes first; everything else is appended in fixed
     * order. Unknown bits are emitted as 0xNNNN so they round-trip. */
    std::string out;
    int acc = flags & O_ACCMODE;
    if      (acc == O_RDONLY) out = "O_RDONLY";
    else if (acc == O_WRONLY) out = "O_WRONLY";
    else if (acc == O_RDWR)   out = "O_RDWR";
    else                       out = "O_RDONLY";  /* fallback */
    int rest = flags & ~O_ACCMODE;
    auto add = [&](int bit, const char *name) {
        if (rest & bit) { out += '|'; out += name; rest &= ~bit; }
    };
#ifdef O_CREAT
    add(O_CREAT, "O_CREAT");
#endif
#ifdef O_EXCL
    add(O_EXCL, "O_EXCL");
#endif
#ifdef O_NOCTTY
    add(O_NOCTTY, "O_NOCTTY");
#endif
#ifdef O_TRUNC
    add(O_TRUNC, "O_TRUNC");
#endif
#ifdef O_APPEND
    add(O_APPEND, "O_APPEND");
#endif
#ifdef O_NONBLOCK
    add(O_NONBLOCK, "O_NONBLOCK");
#endif
#ifdef O_DSYNC
    add(O_DSYNC, "O_DSYNC");
#endif
#ifdef O_SYNC
    add(O_SYNC, "O_SYNC");
#endif
#ifdef O_TMPFILE
    /* O_TMPFILE includes O_DIRECTORY bits — test (and consume) it
     * before the bare O_DIRECTORY check below so the output reads
     * `O_TMPFILE` rather than the redundant `O_DIRECTORY|O_TMPFILE`. */
    if ((flags & O_TMPFILE) == O_TMPFILE) {
        out += "|O_TMPFILE";
        rest &= ~O_TMPFILE;
    }
#endif
#ifdef O_DIRECTORY
    add(O_DIRECTORY, "O_DIRECTORY");
#endif
#ifdef O_NOFOLLOW
    add(O_NOFOLLOW, "O_NOFOLLOW");
#endif
#ifdef O_CLOEXEC
    add(O_CLOEXEC, "O_CLOEXEC");
#endif
#ifdef O_PATH
    add(O_PATH, "O_PATH");
#endif
    if (rest) {
        char buf[24];
        std::snprintf(buf, sizeof buf, "|0x%x", rest);
        out += buf;
    }
    return out;
}

/* Build a preparsed_event_t from one decoded wire event. Returns
 * pe.valid=false for events tv doesn't surface (none, currently). */
static preparsed_event_t preparse_wire(const WireRawEvent &w) {
    preparsed_event_t pe;
    pe.valid = true;
    pe.ts    = (double)w.ts_ns / 1e9;
    pe.tgid  = w.tgid;
    pe.ppid  = w.ppid;

    switch (w.kind) {
    case WIRE_EV_CWD:
        pe.kind = EV_CWD;
        if (w.path_len) {
            pe.raw_path.assign(w.path, w.path_len);
            pe.path_kind = classify_path(pe.raw_path);
        }
        break;
    case WIRE_EV_EXEC:
        pe.kind = EV_EXEC;
        if (w.exe_len) pe.exe_id = g_pool.put_blob(std::string_view(w.exe, w.exe_len));
        if (w.argv_len) {
            /* Wire's argv is raw NUL-separated bytes — split into the
             * vector<string> shape put_blob_argv expects. Trim a single
             * trailing NUL if present (kernel /proc/cmdline terminates). */
            std::vector<std::string> argv;
            size_t i = 0;
            while (i < w.argv_len) {
                size_t j = i;
                while (j < w.argv_len && w.argv[j] != '\0') j++;
                argv.emplace_back(w.argv + i, j - i);
                if (j == w.argv_len) break;
                i = j + 1;
            }
            /* Drop a trailing empty arg from a final NUL terminator. */
            if (!argv.empty() && argv.back().empty()) argv.pop_back();
            pe.argv_blob = g_pool.put_blob_argv(argv);
        }
        break;
    case WIRE_EV_OPEN:
        pe.kind = EV_OPEN;
        if (w.path_len) {
            pe.raw_path.assign(w.path, w.path_len);
            pe.path_kind = classify_path(pe.raw_path);
        }
        pe.mode     = w.open_flags;     /* numeric flags carry O_ACCMODE bits */
        pe.flags_id = g_pool.put_inline(format_open_flags(w.open_flags));
        pe.err      = w.open_err;
        break;
    case WIRE_EV_EXIT: {
        pe.kind = EV_EXIT;
        /* Wire exit_status_kind: 0 = EXITED, 1 = SIGNALED (see
         * wire/wire.h's EV_EXIT_EXITED / EV_EXIT_SIGNALED). */
        const char *status = "exited";
        if (w.exit_status_kind == 1) status = "signaled";
        else if (w.exit_status_kind != 0) status = "unknown";
        pe.status_id   = g_pool.put_inline(status);
        if (w.exit_status_kind == 1) {
            pe.signal_ = w.exit_code_or_sig;
        } else {
            pe.code    = w.exit_code_or_sig;
        }
        pe.core_dumped = w.exit_core_dumped ? 1 : 0;
        break;
    }
    case WIRE_EV_STDOUT:
        pe.kind = EV_STDOUT;
        if (w.data_len) pe.data_blob = g_pool.put_blob(std::string_view(w.data, w.data_len));
        break;
    case WIRE_EV_STDERR:
        pe.kind = EV_STDERR;
        if (w.data_len) pe.data_blob = g_pool.put_blob(std::string_view(w.data, w.data_len));
        break;
    default:
        pe.valid = false;
        break;
    }
    return pe;
}

/* Helpers shared by ingest fast paths (predicate inspection of an event
   that has not yet had its .path_item set).  Use mode + flags_id only;
   no string ops on the hot path. */
static bool open_is_write(int mode, InlineIID flags_id) {
    if (mode != 0) {
        int acc = mode & O_ACCMODE;
        return acc == O_WRONLY || acc == O_RDWR ||
               (mode & O_CREAT) || (mode & O_TRUNC);
    }
    if (!flags_id) return false;
    auto sv = g_pool.view(flags_id);
    return sv.find("O_WRONLY") != std::string_view::npos ||
           sv.find("O_RDWR")   != std::string_view::npos ||
           sv.find("O_CREAT")  != std::string_view::npos ||
           sv.find("O_TRUNC")  != std::string_view::npos;
}
static bool open_is_read(int mode, InlineIID flags_id) {
    if (mode != 0) {
        int acc = mode & O_ACCMODE;
        return acc == O_RDONLY || acc == O_RDWR;
    }
    if (!flags_id) return false;
    auto sv = g_pool.view(flags_id);
    return sv.find("O_RDONLY") != std::string_view::npos ||
           sv.find("O_RDWR")   != std::string_view::npos;
}

static bool is_write_open(const trace_event_t &ev) {
    return ev.kind == EV_OPEN && open_is_write(ev.mode, ev.flags_id);
}
static bool is_read_open(const trace_event_t &ev) {
    return ev.kind == EV_OPEN && open_is_read(ev.mode, ev.flags_id);
}

/* ── trace_db_t — encapsulates all mutable ingest state ───────────── */
/* A single global instance `g_db` replaces the old static globals.
   Per-worker instances of the same type are used for parallel ingest,
   eliminating code duplication: the same apply_preparsed() method runs
   on both the global and worker-local databases. */

struct trace_db_t {
    std::vector<trace_event_t>    events;
    int                           next_event_id = 1;
    /* Maps event id -> index into `events`.  Event ids are assigned
       sequentially starting at 1 (CWD events get id 0 — the unused
       slot 0 of this vector — and aren't recorded here), so a flat
       vector is dense and uses ~4 B/entry instead of the ~30–40 B/entry
       an unordered_map node would cost.  This matters during ingestion
       of large traces (10^8 events ⇒ several GB saved).  Unfilled
       slots (e.g. for skipped/CWD ids) hold the sentinel -1. */
    std::vector<int>              event_id_to_index;
    std::unordered_map<int, std::unique_ptr<process_t>> proc_map;
    std::vector<BlobIID>          input_lines;
    double                        base_ts = 0;

    std::unique_ptr<PathItem>     path_root_owner;
    PathItem                     *path_root = nullptr;
    std::unordered_map<uint32_t, PathItem*> nonabs_paths;

    /* ── Path tree helpers ─────────────────────────────────────────── */

    void ensure_path_root() {
        if (!path_root_owner) {
            path_root_owner = std::make_unique<PathItem>();
            path_root_owner->is_dir = true;
            path_root = path_root_owner.get();
        }
    }

    PathItem *intern_path_item(std::string_view path) {
        if (path.empty()) return nullptr;
        ensure_path_root();
        if (path[0] != '/') {
            InlineIID nid = g_pool.put_inline(path);
            auto it = nonabs_paths.find(nid.v);
            if (it != nonabs_paths.end()) return it->second;
            auto *np = new PathItem();
            np->name_id = nid;
            np->is_dir = false;
            nonabs_paths.emplace(nid.v, np);
            return np;
        }
        PathItem *cur = path_root;
        size_t i = 1;
        while (i < path.size()) {
            auto sl = path.find('/', i);
            size_t seg_len = (sl == std::string_view::npos) ? path.size() - i : sl - i;
            std::string_view seg(path.data() + i, seg_len);
            if (seg.empty()) { i = (sl == std::string_view::npos) ? path.size() : sl + 1; continue; }
            bool is_last = (sl == std::string_view::npos);
            InlineIID seg_id = g_pool.put_inline(seg);
            cur = cur->getOrCreateChild(seg_id, !is_last);
            i = is_last ? path.size() : sl + 1;
        }
        return cur;
    }

    PathItem *find_path_item(std::string_view path) const {
        if (path.empty() || !path_root) return nullptr;
        if (path[0] != '/') {
            InlineIID nid = g_pool.find_inline(path);
            if (!nid) return nullptr;
            auto it = nonabs_paths.find(nid.v);
            return it != nonabs_paths.end() ? it->second : nullptr;
        }
        PathItem *cur = path_root;
        size_t i = 1;
        while (i < path.size()) {
            auto sl = path.find('/', i);
            size_t seg_len = (sl == std::string_view::npos) ? path.size() - i : sl - i;
            std::string_view seg(path.data() + i, seg_len);
            if (seg.empty()) { i = (sl == std::string_view::npos) ? path.size() : sl + 1; continue; }
            InlineIID seg_id = g_pool.find_inline(seg);
            if (!seg_id) return nullptr;
            PathItem *found = cur->findChild(seg_id);
            if (!found) return nullptr;
            cur = found;
            i = (sl == std::string_view::npos) ? path.size() : sl + 1;
        }
        return cur;
    }

    PathItem *intern_classified(path_kind_t kind, std::string_view raw,
                                std::string_view cwd) {
        switch (kind) {
        case PK_NONE: return nullptr;
        case PK_ABS:  return intern_path_item(canon_path(raw));
        case PK_ABSTRACT: return intern_path_item(raw);
        case PK_RELATIVE: {
            std::string resolved = resolve_relative(raw, cwd);
            if (resolved.empty()) return nullptr;
            return intern_path_item(resolved);
        }
        }
        return nullptr;
    }

    void free_path_tree_all() {
        if (path_root) free_path_tree_children(path_root);
        path_root_owner.reset();
        path_root = nullptr;
        for (auto &kv : nonabs_paths) delete kv.second;
        nonabs_paths.clear();
    }

    /* ── Process access ────────────────────────────────────────────── */

    process_t *find_process(int tgid) const {
        auto it = proc_map.find(tgid);
        return it != proc_map.end() ? it->second.get() : nullptr;
    }

    process_t &get_process(int tgid) {
        auto [it, inserted] = proc_map.try_emplace(tgid);
        if (inserted) { it->second = std::make_unique<process_t>(); it->second->tgid = tgid; }
        return *it->second;
    }

    /* ── Apply one preparsed event ─────────────────────────────────── */

    void apply_path_event(trace_event_t &ev, process_t &proc, int event_idx,
                          path_kind_t pk, std::string_view raw_path) {
        PathItem *pi = intern_classified(pk, raw_path, proc.cwd_view());
        if (!pi) return;
        ev.path_item = pi;
        if (ev.kind == EV_CWD) { proc.set_cwd(pi); return; }
        if (ev.kind == EV_OPEN) {
            bool wr = open_is_write(ev.mode, ev.flags_id);
            bool rd = open_is_read (ev.mode, ev.flags_id);
            if (wr) proc.has_write_open = 1;
            if (rd) { proc.read_paths.insert(pi);  pi->read_procs.insert(ev.tgid); }
            if (wr) { proc.write_paths.insert(pi); pi->write_procs.insert(ev.tgid); }
            pi->opens++;
            if (ev.err) pi->errs++;
            pi->aggregated_mode |= ev.mode;
            if (wr && ev.ts > pi->last_open_write_ts) pi->last_open_write_ts = ev.ts;
            pi->proc_tgids.insert(ev.tgid);
            pi->open_event_indices.push_back(event_idx);
            pi->events.insert(event_idx);
        } else if (ev.kind == EV_UNLINK) {
            pi->unlinks++;
            if (ev.ts > pi->last_unlink_ts) pi->last_unlink_ts = ev.ts;
            pi->unlink_procs.insert(ev.tgid);
            pi->proc_tgids.insert(ev.tgid);
            pi->unlink_event_indices.push_back(event_idx);
            pi->events.insert(event_idx);
        }
    }

    void apply_preparsed(preparsed_event_t &pe) {
        if (pe.is_input) { input_lines.push_back(pe.input_line_id); return; }
        auto &ev = events.emplace_back();
        ev.kind = pe.kind;
        ev.ts = pe.ts;
        ev.tgid = pe.tgid;
        ev.ppid = pe.ppid;
        ev.id = (ev.kind == EV_CWD) ? 0 : next_event_id++;
        int event_idx = static_cast<int>(events.size()) - 1;
        if (ev.id) {
            if (static_cast<size_t>(ev.id) >= event_id_to_index.size())
                event_id_to_index.resize(static_cast<size_t>(ev.id) + 1, -1);
            event_id_to_index[ev.id] = event_idx;
        }
        if (base_ts == 0.0 || ev.ts < base_ts) base_ts = ev.ts;

        auto &proc = get_process(ev.tgid);
        proc.event_indices.push_back(event_idx);
        if (!proc.has_start || ev.ts < proc.start_ts) { proc.start_ts = ev.ts; proc.has_start = 1; }
        if (!proc.has_end   || ev.ts > proc.end_ts)   { proc.end_ts   = ev.ts; proc.has_end   = 1; }

        if (!proc.parent_set && ev.ppid > 0 && ev.ppid != proc.tgid) {
            proc.ppid = ev.ppid;
            proc.parent_set = true;
            auto pit = proc_map.find(proc.ppid);
            if (pit != proc_map.end())
                pit->second->children.push_back(&proc);
        }

        switch (ev.kind) {
        case EV_CWD:
        case EV_OPEN:
        case EV_UNLINK:
            if (ev.kind == EV_OPEN) {
                ev.flags_id = pe.flags_id;
                ev.mode = pe.mode;
                ev.err = pe.err;
            }
            apply_path_event(ev, proc, event_idx, pe.path_kind, pe.raw_path);
            break;
        case EV_EXEC:
            ev.exe_id = pe.exe_id;
            ev.argv_blob = pe.argv_blob;
            proc.exe_id = ev.exe_id;
            proc.argv_blob = ev.argv_blob;
            proc.update_display_name();
            break;
        case EV_EXIT:
            ev.status_id = pe.status_id;
            ev.code = pe.code;
            ev.signal = pe.signal_;
            ev.core_dumped = pe.core_dumped;
            proc.exit_status_id = ev.status_id;
            proc.exit_code = ev.code;
            proc.exit_signal = ev.signal;
            proc.core_dumped = ev.core_dumped;
            proc.end_ts = ev.ts;
            proc.has_end = 1;
            break;
        case EV_STDOUT:
        case EV_STDERR:
            ev.data_blob = pe.data_blob;
            if (ev.kind == EV_STDOUT) proc.has_stdout = 1;
            break;
        }
    }

    /* ── Merge helpers (public static for use by parallel_ingest) ─── */

    static void merge_trie_rec_ex(PathItem *local, PathItem *global,
                                  std::unordered_map<PathItem*, PathItem*> &mapping,
                                  const std::vector<int> &remap) {
        if (!local) return;
        for (auto *child_item : local->children) {
            auto *lc = static_cast<PathItem*>(child_item);
            PathItem *gc = global->getOrCreateChild(lc->name_id, lc->is_dir);
            mapping[lc] = gc;
            merge_path_counters_ex(lc, gc, remap);
            merge_trie_rec_ex(lc, gc, mapping, remap);
        }
    }

    static void merge_path_counters_ex(PathItem *src, PathItem *dst,
                                       const std::vector<int> &remap) {
        dst->opens   += src->opens;
        dst->errs    += src->errs;
        dst->unlinks += src->unlinks;
        dst->aggregated_mode |= src->aggregated_mode;
        if (src->last_open_write_ts > dst->last_open_write_ts)
            dst->last_open_write_ts = src->last_open_write_ts;
        if (src->last_unlink_ts > dst->last_unlink_ts)
            dst->last_unlink_ts = src->last_unlink_ts;
        for (auto t : src->proc_tgids)    dst->proc_tgids.insert(t);
        for (auto &v : src->read_procs)   dst->read_procs.insert(v);
        for (auto &v : src->write_procs)  dst->write_procs.insert(v);
        for (auto &v : src->unlink_procs) dst->unlink_procs.insert(v);
        for (auto li : src->open_event_indices)
            dst->open_event_indices.push_back(remap[li]);
        for (auto li : src->unlink_event_indices)
            dst->unlink_event_indices.push_back(remap[li]);
        for (auto &li : src->events)
            dst->events.insert(remap[li]);
    }

    static void remap_proc_paths_ex(
        process_t &proc,
        const std::unordered_map<PathItem*, PathItem*> &mapping) {
        if (proc.cwd_item) {
            auto it = mapping.find(proc.cwd_item);
            proc.cwd_item = (it != mapping.end()) ? it->second : nullptr;
        }
        auto remap_set = [&](sorted_vec_set<PathItem*, PathItemPtrLess> &s) {
            sorted_vec_set<PathItem*, PathItemPtrLess> tmp;
            for (auto *pi : s) {
                auto it = mapping.find(pi);
                if (it != mapping.end()) tmp.insert(it->second);
            }
            s = std::move(tmp);
        };
        remap_set(proc.read_paths);
        remap_set(proc.write_paths);
    }

    void clear() {
        events.clear();
        event_id_to_index.clear();
        event_id_to_index.shrink_to_fit();
        proc_map.clear();
        free_path_tree_all();
        input_lines.clear();
        next_event_id = 1;
        base_ts = 0;
    }
};

static trace_db_t g_db;

/* Thin wrappers that delegate to g_db (used throughout the view layer). */
static process_t *find_process(int tgid) { return g_db.find_process(tgid); }
static PathItem  *find_path_item(std::string_view path) { return g_db.find_path_item(path); }

static void ingest_trace_line(const char *line) {
    auto pe = preparse_line(line);
    if (pe.valid && !pe.is_input) g_db.apply_preparsed(pe);
}

static void ingest_line(const char *line) {
    if (!line || !line[0] || line[0] != '{') return;
    std::string_view sp;
    if (json_get(line, "input", sp))
        g_db.input_lines.push_back(g_pool.put_blob(std::string_view(line, std::strlen(line))));
    else
        ingest_trace_line(line);
}

static bool path_has_suffix(const char *path, const char *suffix) {
    size_t n = std::strlen(path), m = std::strlen(suffix);
    return n >= m && std::strcmp(path + n - m, suffix) == 0;
}

static void parallel_ingest(std::vector<std::string> &lines);
static void ingest_zstd_file(const char *path);

/* ── Parallel batch ingestion — pipelined ─────────────────────────── */
/* Phase 1 (parallel): parse JSON lines + intern strings via g_pool.
   Phase 2 (parallel): bucket by tgid; each worker owns a trace_db_t
     and calls the same apply_preparsed() method — zero code duplication.
   Merge (sequential): fold each worker's trace_db_t into g_db via
     the generic trace_db_t::merge_from() method.
   Pipeline: parse and apply stages overlap — parse threads push to a
     shared preparsed buffer, apply workers start as soon as their tgid
     buckets are ready (chunked pipeline, not fork-join).               */

#include <thread>

static constexpr int MAX_PARSE_THREADS = 8;
static constexpr int MIN_LINES_PER_THREAD = 64;
static constexpr int MIN_EVENTS_PER_P2_THREAD = 16;
static constexpr int INGEST_BATCH_SIZE = 128 * 1024;

static void parallel_ingest(std::vector<std::string> &lines) {
    if (lines.empty()) return;
    int nlines = static_cast<int>(lines.size());

    /* ── Phase 1: Parse JSON in parallel. ────────────────────────── */
    std::vector<preparsed_event_t> parsed(nlines);
    int hw = std::max(1, static_cast<int>(std::thread::hardware_concurrency()));
    int nthreads_p1 = std::min(hw, MAX_PARSE_THREADS);
    if (nlines < nthreads_p1 * MIN_LINES_PER_THREAD) nthreads_p1 = 1;

    auto p1_worker = [&](int tid) {
        int chunk = (nlines + nthreads_p1 - 1) / nthreads_p1;
        int lo = tid * chunk;
        int hi = std::min(lo + chunk, nlines);
        for (int i = lo; i < hi; i++)
            parsed[i] = preparse_line(lines[i].c_str());
    };
    if (nthreads_p1 > 1) {
        std::vector<std::thread> threads;
        threads.reserve(nthreads_p1);
        for (int t = 0; t < nthreads_p1; t++)
            threads.emplace_back(p1_worker, t);
        for (auto &t : threads) t.join();
    } else {
        p1_worker(0);
    }
    lines.clear();
    lines.shrink_to_fit();

    /* ── Collect input lines (not tgid-bucketed). ────────────────── */
    for (int i = 0; i < nlines; i++) {
        if (parsed[i].valid && parsed[i].is_input)
            g_db.input_lines.push_back(parsed[i].input_line_id);
    }

    /* ── Count valid trace events — decide parallel vs sequential. ── */
    int n_trace = 0;
    for (int i = 0; i < nlines; i++)
        if (parsed[i].valid && !parsed[i].is_input) n_trace++;
    if (n_trace == 0) return;

    int nthreads_p2 = std::min(hw, MAX_PARSE_THREADS);
    if (n_trace < nthreads_p2 * MIN_EVENTS_PER_P2_THREAD) nthreads_p2 = 1;

    /* ── Sequential fallback. ────────────────────────────────────── */
    if (nthreads_p2 <= 1) {
        g_db.events.reserve(g_db.events.size() + n_trace);
        for (int i = 0; i < nlines; i++) {
            if (parsed[i].valid && !parsed[i].is_input)
                g_db.apply_preparsed(parsed[i]);
        }
        return;
    }

    /* ── Phase 2: Bucket by tgid, assign to workers. ─────────────── */
    std::unordered_map<int, std::vector<int>> tgid_buckets;
    tgid_buckets.reserve(256);
    for (int i = 0; i < nlines; i++) {
        auto &pe = parsed[i];
        if (pe.valid && !pe.is_input)
            tgid_buckets[pe.tgid].push_back(i);
    }

    /* Sort buckets largest-first for greedy load balancing. */
    std::vector<std::pair<int, int>> tgid_list;
    tgid_list.reserve(tgid_buckets.size());
    for (auto &[tgid, bkt] : tgid_buckets)
        tgid_list.push_back({tgid, static_cast<int>(bkt.size())});
    std::sort(tgid_list.begin(), tgid_list.end(),
              [](auto &a, auto &b){ return a.second > b.second; });

    std::vector<std::vector<int>> worker_tgids(nthreads_p2);
    std::vector<int> worker_load(nthreads_p2, 0);
    for (auto &[tgid, sz] : tgid_list) {
        int best = 0;
        for (int w = 1; w < nthreads_p2; w++)
            if (worker_load[w] < worker_load[best]) best = w;
        worker_tgids[best].push_back(tgid);
        worker_load[best] += sz;
    }

    /* ── Phase 2: Each worker owns a trace_db_t — same code path. ── */
    std::vector<std::unique_ptr<trace_db_t>> workers(nthreads_p2);
    for (int w = 0; w < nthreads_p2; w++)
        workers[w] = std::make_unique<trace_db_t>();

    auto p2_worker = [&](int wid) {
        auto &db = *workers[wid];
        for (int tgid : worker_tgids[wid]) {
            for (int orig_idx : tgid_buckets[tgid])
                db.apply_preparsed(parsed[orig_idx]);
        }
    };

    {
        std::vector<std::thread> threads;
        threads.reserve(nthreads_p2);
        for (int w = 0; w < nthreads_p2; w++)
            threads.emplace_back(p2_worker, w);
        for (auto &t : threads) t.join();
    }

    /* ── Merge: fold worker trace_db_t's into g_db, preserving order. ─ */

    /* To preserve original event order across workers, we need to know
       which events came from which original line indices and stitch them.
       Each worker processed events in tgid-bucket order; we need to
       merge them back in original line order.

       Strategy: build a mapping of (orig_line_idx → worker, local_event_idx),
       then iterate orig indices 0..nlines-1. For each valid trace event,
       find which worker has it and its local index. Emit events to g_db
       in that order, remapping local→global indices. */

    /* Build orig_idx → (worker, local_event_idx) mapping.
       Each worker's events are in the order they were applied:
       for worker w, the events correspond to tgid_buckets[tgid] indices
       in the order of worker_tgids[w]. */
    struct event_loc { int16_t worker; int local_idx; };
    std::vector<event_loc> loc_map(nlines, {-1, -1});
    for (int w = 0; w < nthreads_p2; w++) {
        int li = 0;
        for (int tgid : worker_tgids[w]) {
            for (int orig_idx : tgid_buckets[tgid]) {
                /* Skip input events — they don't produce trace events. */
                if (parsed[orig_idx].is_input) continue;
                loc_map[orig_idx] = {static_cast<int16_t>(w), li++};
            }
        }
    }

    /* Stitch events into g_db in original order, building per-worker
       local→global index remap tables for the merge. */
    int total_events = 0;
    for (int w = 0; w < nthreads_p2; w++)
        total_events += static_cast<int>(workers[w]->events.size());

    g_db.events.reserve(g_db.events.size() + total_events);
    std::vector<std::vector<int>> idx_remap(nthreads_p2);
    for (int w = 0; w < nthreads_p2; w++)
        idx_remap[w].resize(workers[w]->events.size(), -1);

    int global_base = static_cast<int>(g_db.events.size());
    /* Pre-size the id-index vector once: we'll assign at most one new id per
       non-CWD event added in this batch.  A single resize avoids repeated
       reallocations during the per-event tight loop below. */
    {
        int cwd_count = 0;
        for (int i = 0; i < nlines; i++)
            if (loc_map[i].worker >= 0 && parsed[i].kind == EV_CWD) cwd_count++;
        int new_ids = total_events - cwd_count;
        if (new_ids > 0) {
            size_t need = static_cast<size_t>(g_db.next_event_id) +
                          static_cast<size_t>(new_ids);
            if (g_db.event_id_to_index.size() < need)
                g_db.event_id_to_index.resize(need, -1);
        }
    }
    for (int i = 0; i < nlines; i++) {
        if (loc_map[i].worker < 0) continue;
        int w  = loc_map[i].worker;
        int li = loc_map[i].local_idx;
        auto &gev = g_db.events.emplace_back(std::move(workers[w]->events[li]));
        int gi = static_cast<int>(g_db.events.size()) - 1;
        gev.id = (gev.kind == EV_CWD) ? 0 : g_db.next_event_id++;
        if (gev.id) g_db.event_id_to_index[gev.id] = gi;
        idx_remap[w][li] = gi;
    }

    /* Merge base_ts from workers. */
    for (int w = 0; w < nthreads_p2; w++) {
        if (workers[w]->base_ts != 0.0 &&
            (g_db.base_ts == 0.0 || workers[w]->base_ts < g_db.base_ts))
            g_db.base_ts = workers[w]->base_ts;
    }

    /* Fold each worker's path trie into g_db. */
    g_db.ensure_path_root();
    std::unordered_map<PathItem*, PathItem*> pi_mapping;
    for (int w = 0; w < nthreads_p2; w++) {
        if (workers[w]->path_root)
            pi_mapping[workers[w]->path_root] = g_db.path_root;
        trace_db_t::merge_trie_rec_ex(workers[w]->path_root, g_db.path_root,
                                      pi_mapping, idx_remap[w]);
        for (auto &[nid_v, lp] : workers[w]->nonabs_paths) {
            auto it = g_db.nonabs_paths.find(nid_v);
            PathItem *gp;
            if (it != g_db.nonabs_paths.end()) { gp = it->second; }
            else {
                gp = new PathItem();
                gp->name_id = lp->name_id;
                gp->is_dir = lp->is_dir;
                g_db.nonabs_paths.emplace(nid_v, gp);
            }
            pi_mapping[lp] = gp;
            trace_db_t::merge_path_counters_ex(lp, gp, idx_remap[w]);
        }
    }

    /* Remap ev.path_item pointers in newly appended events. */
    for (int i = global_base; i < static_cast<int>(g_db.events.size()); i++) {
        if (g_db.events[i].path_item) {
            auto it = pi_mapping.find(g_db.events[i].path_item);
            if (it != pi_mapping.end())
                g_db.events[i].path_item = it->second;
        }
    }

    /* Merge processes from each worker into g_db. */
    for (int w = 0; w < nthreads_p2; w++) {
        auto &remap = idx_remap[w];
        for (auto &[tgid, lp] : workers[w]->proc_map) {
            trace_db_t::remap_proc_paths_ex(*lp, pi_mapping);
            for (auto &li : lp->event_indices) li = remap[li];
            auto [it, inserted] = g_db.proc_map.try_emplace(tgid);
            if (inserted) {
                it->second = std::move(lp);
            } else {
                auto &gp = *it->second;
                if (lp->has_start && (!gp.has_start || lp->start_ts < gp.start_ts))
                    { gp.start_ts = lp->start_ts; gp.has_start = 1; }
                if (lp->has_end && (!gp.has_end || lp->end_ts > gp.end_ts))
                    { gp.end_ts = lp->end_ts; gp.has_end = 1; }
                if (!gp.parent_set && lp->parent_set)
                    { gp.ppid = lp->ppid; gp.parent_set = true; }
                if (lp->exe_id)
                    { gp.exe_id = lp->exe_id; gp.argv_blob = lp->argv_blob;
                      gp.update_display_name(); }
                if (lp->cwd_item) gp.cwd_item = lp->cwd_item;
                if (lp->exit_status_id) {
                    gp.exit_status_id = lp->exit_status_id;
                    gp.exit_code = lp->exit_code;
                    gp.exit_signal = lp->exit_signal;
                    gp.core_dumped = lp->core_dumped;
                }
                gp.has_write_open |= lp->has_write_open;
                gp.has_stdout     |= lp->has_stdout;
                gp.event_indices.insert(gp.event_indices.end(),
                    lp->event_indices.begin(), lp->event_indices.end());
                for (auto *pi : lp->read_paths)  gp.read_paths.insert(pi);
                for (auto *pi : lp->write_paths) gp.write_paths.insert(pi);
            }
        }
    }

    /* Establish parent-child links. */
    for (int w = 0; w < nthreads_p2; w++) {
        for (auto &[tgid, _lp] : workers[w]->proc_map) {
            auto pit = g_db.proc_map.find(tgid);
            if (pit == g_db.proc_map.end()) continue;
            auto &proc = *pit->second;
            if (!proc.parent_set || proc.ppid <= 0 || proc.ppid == proc.tgid) continue;
            auto parent_it = g_db.proc_map.find(proc.ppid);
            if (parent_it == g_db.proc_map.end()) continue;
            auto &parent = *parent_it->second;
            bool already = false;
            for (auto *c : parent.children)
                if (static_cast<process_t*>(c)->tgid == tgid) { already = true; break; }
            if (!already) parent.children.push_back(&proc);
        }
    }
}

/* ── wire-format file ingest helpers ──────────────────────────────── */
/* For wire input we drive a single WireDecoder; the sink converts each
 * decoded WireRawEvent into a preparsed_event_t and applies it directly
 * to g_db. Sequential by design — see preparse_wire commentary. */
static void ingest_wire_bytes_via(WireDecoder &dec, const void *data, size_t n) {
    if (!dec.feed(data, n)) {
        std::fprintf(stderr, "tv: wire decode error\n");
        std::exit(1);
    }
}

static WireDecoder make_db_wire_decoder() {
    return WireDecoder([](const WireRawEvent &w) {
        auto pe = preparse_wire(w);
        if (pe.valid) g_db.apply_preparsed(pe);
    });
}

static void ingest_wire_file_plain(FILE *f, const char *path) {
    auto dec = make_db_wire_decoder();
    unsigned char buf[64 * 1024];
    while (true) {
        size_t n = std::fread(buf, 1, sizeof buf, f);
        if (n == 0) break;
        ingest_wire_bytes_via(dec, buf, n);
    }
    if (std::ferror(f)) {
        std::fprintf(stderr, "tv: read error in %s\n", path);
        std::exit(1);
    }
    dec.flush();
}

static void ingest_wire_file_zstd(FILE *f, const char *path,
                                   const unsigned char *carry,
                                   size_t carry_n) {
    auto dec = make_db_wire_decoder();
    if (carry_n) ingest_wire_bytes_via(dec, carry, carry_n);
    size_t in_cap = ZSTD_DStreamInSize(), out_cap = ZSTD_DStreamOutSize();
    std::vector<unsigned char> in_buf(in_cap), out_buf(out_cap);
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
                std::fprintf(stderr, "tv: zstd decompress failed for %s: %s\n",
                             path, ZSTD_getErrorName(rc));
                std::exit(1);
            }
            if (output.pos) ingest_wire_bytes_via(dec, out_buf.data(), output.pos);
        }
        if (nread == 0) break;
    }
    ZSTD_freeDStream(stream);
    dec.flush();
}

static void ingest_zstd_file(const char *path) {
    FILE *f = std::fopen(path, "rb");
    if (!f) { std::fprintf(stderr, "tv: cannot open %s\n", path); std::exit(1); }
    /* Decode the first frame's first byte to sniff format. */
    size_t in_cap = ZSTD_DStreamInSize(), out_cap = ZSTD_DStreamOutSize();
    std::vector<unsigned char> in_buf(in_cap), out_buf(out_cap);
    ZSTD_DStream *stream = ZSTD_createDStream();
    if (ZSTD_isError(ZSTD_initDStream(stream))) {
        std::fprintf(stderr, "tv: zstd init failed for %s\n", path); std::exit(1);
    }
    /* Pull just enough to peek one decoded byte. */
    unsigned char first = 0;
    bool got_first = false;
    std::vector<unsigned char> early_decoded;
    while (!got_first) {
        size_t nread = std::fread(in_buf.data(), 1, in_cap, f);
        if (nread == 0) break;
        ZSTD_inBuffer input = { in_buf.data(), nread, 0 };
        while (input.pos < input.size && !got_first) {
            ZSTD_outBuffer output = { out_buf.data(), out_cap, 0 };
            size_t rc = ZSTD_decompressStream(stream, &output, &input);
            if (ZSTD_isError(rc)) {
                std::fprintf(stderr, "tv: zstd decompress failed for %s: %s\n",
                             path, ZSTD_getErrorName(rc));
                std::exit(1);
            }
            if (output.pos) {
                first = out_buf.data()[0];
                got_first = true;
                early_decoded.assign(out_buf.data(), out_buf.data() + output.pos);
            }
        }
        /* If we got a first byte, also retain any unconsumed compressed
         * input so the chosen path can finish reading the file. */
        if (got_first) {
            /* push back unconsumed compressed bytes for the chosen path */
            if (input.pos < input.size) {
                std::fseek(f, -(long)(input.size - input.pos), SEEK_CUR);
            }
        }
    }
    if (!got_first) { ZSTD_freeDStream(stream); std::fclose(f); return; }

    if (wire_looks_like_wire(first)) {
        /* Restart zstd stream — we need a fresh one to feed the carry */
        ZSTD_freeDStream(stream);
        std::rewind(f);
        ingest_wire_file_zstd(f, path, nullptr, 0);
        std::fclose(f);
        return;
    }
    /* JSONL path: line-buffered ingest as before. */
    ZSTD_freeDStream(stream);
    std::rewind(f);
    /* Fresh stream for the JSONL decoder. */
    std::string line;
    line.reserve(MAX_JSON_LINE);
    ZSTD_DStream *jstream = ZSTD_createDStream();
    ZSTD_initDStream(jstream);
    std::vector<std::string> lines;
    for (;;) {
        size_t nread = std::fread(in_buf.data(), 1, in_cap, f);
        ZSTD_inBuffer input = { in_buf.data(), nread, 0 };
        while (input.pos < input.size) {
            ZSTD_outBuffer output = { out_buf.data(), out_cap, 0 };
            size_t rc = ZSTD_decompressStream(jstream, &output, &input);
            if (ZSTD_isError(rc)) {
                std::fprintf(stderr, "tv: zstd decompress failed for %s: %s\n",
                             path, ZSTD_getErrorName(rc));
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
                    if (!line.empty() && line[0] == '{') lines.emplace_back(std::move(line));
                    line.clear();
                    pos++;
                    if (static_cast<int>(lines.size()) >= INGEST_BATCH_SIZE) {
                        parallel_ingest(lines);
                        lines.clear();
                    }
                }
            }
        }
        if (nread == 0) break;
    }
    if (!line.empty()) {
        if (line.back() == '\r') line.pop_back();
        if (!line.empty() && line[0] == '{') lines.emplace_back(std::move(line));
    }
    if (!lines.empty()) parallel_ingest(lines);
    ZSTD_freeDStream(jstream);
    std::fclose(f);
}

static void ingest_file(const char *path) {
    if (path_has_suffix(path, ".zst")) { ingest_zstd_file(path); return; }
    FILE *f = std::fopen(path, "rb");
    if (!f) { std::fprintf(stderr, "tv: cannot open %s\n", path); std::exit(1); }

    /* Sniff first non-empty byte to choose format. */
    int fb = std::fgetc(f);
    if (fb == EOF) { std::fclose(f); return; }
    std::ungetc(fb, f);

    if (wire_looks_like_wire(static_cast<unsigned char>(fb))) {
        ingest_wire_file_plain(f, path);
        std::fclose(f);
        return;
    }

    std::vector<std::string> lines;
    char *buf = nullptr;
    size_t cap = 0;
    ssize_t nread;
    while ((nread = getline(&buf, &cap, f)) > 0) {
        size_t len = static_cast<size_t>(nread);
        if (len > 0 && buf[len - 1] == '\n') len--;
        if (len > 0 && buf[len - 1] == '\r') len--;
        if (len > 0 && buf[0] == '{') lines.emplace_back(buf, len);
        if (static_cast<int>(lines.size()) >= INGEST_BATCH_SIZE) {
            parallel_ingest(lines);
            lines.clear();
        }
    }
    if (std::ferror(f)) {
        std::free(buf);
        std::fclose(f);
        std::fprintf(stderr, "tv: read error in %s\n", path);
        std::exit(1);
    }
    std::free(buf);
    std::fclose(f);
    if (!lines.empty()) parallel_ingest(lines);
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
    if (!g_state.search_id) return false;
    auto q = g_state.search_sv();
    /* Check tgid key via its string_view (already backed by intern pool). */
    auto key = p.getKey();
    if (!key.empty() && key.find(q) != std::string_view::npos) return true;
    if (g_pool.contains(p.exe_id, q)) return true;
    if (g_pool.contains(p.argv_blob, q)) return true;
    for (int ei : p.event_indices) {
        auto &ev = g_db.events[ei];
        if ((ev.kind == EV_STDOUT || ev.kind == EV_STDERR) && ev.data_blob) {
            if (g_pool.contains(ev.data_blob, q)) return true;
        }
    }
    return false;
}

static bool proc_is_interesting_failure(const process_t &p) {
    if (g_pool.empty(p.exit_status_id)) return false;
    if (g_pool.eq(p.exit_status_id, "signaled")) return true;
    if (g_pool.eq(p.exit_status_id, "exited") && p.exit_code != 0)
        return p.has_write_open || !p.children.empty() || p.has_stdout;
    return false;
}

static bool proc_matches_filter(const process_t &p) {
    if (g_state.lp_filter == 1) return proc_is_interesting_failure(p);
    if (g_state.lp_filter == 2) return g_pool.empty(p.exit_status_id);
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

/* ── process_t virtual method implementations ──────────────────────── */

RowStyle process_t::style() const {
    if (proc_matches_search(*this)) return RowStyle::Search;
    if (proc_is_interesting_failure(*this)) return RowStyle::Error;
    return RowStyle::Normal;
}

bool process_t::shouldShow() const { return proc_should_show(tgid); }

std::string process_t::getParentKey() const {
    return (ppid > 0 && find_process(ppid)) ? std::to_string(ppid) : std::string();
}

RowData process_t::makeRow(int depth) const {
    std::string id_str(getKey());
    bool has_kids = !children.empty();
    bool collapsed_flag = has_kids && collapsed;
    std::string marker;
    if (g_pool.eq(exit_status_id, "exited"))
        marker = exit_code == 0 ? " \xe2\x9c\x93" : " \xe2\x9c\x97";
    else if (g_pool.eq(exit_status_id, "signaled"))
        marker = sfmt(" \xe2\x9a\xa1%d", exit_signal);
    std::string dur = format_duration(start_ts, end_ts, g_pool.empty(exit_status_id));
    int nch = static_cast<int>(children.size());
    std::string prefix = sfmt("%*s%s", depth * 4, "",
        !has_kids ? "  " : (collapsed_flag ? "\xe2\x96\xb6 " : "\xe2\x96\xbc "));
    std::string extra = nch > 0 ? sfmt(" (%d)", nch) : std::string();
    std::string text = sfmt("%s[%d] %s%s%s%s%s", prefix.c_str(), tgid,
                            display_name().c_str(), marker.c_str(), extra.c_str(),
                            dur.empty() ? "" : "  ", dur.c_str());
    RowData d;
    d.id = id_str;
    d.style = style();
    d.cols = {text};
    d.parent_id = getParentKey();
    d.link_mode = 0;
    d.link_id = id_str;
    d.has_children = has_kids;
    return d;
}

/* Build a single RowData for a process in flat mode (no tree indent). */
static RowData make_proc_flat_row(process_t *p) {
    std::string id_str(p->getKey());
    std::string marker;
    if (g_pool.eq(p->exit_status_id, "exited"))
        marker = p->exit_code == 0 ? " \xe2\x9c\x93" : " \xe2\x9c\x97";
    else if (g_pool.eq(p->exit_status_id, "signaled"))
        marker = sfmt(" \xe2\x9a\xa1%d", p->exit_signal);
    std::string dur = format_duration(p->start_ts, p->end_ts, g_pool.empty(p->exit_status_id));
    std::string text = sfmt("[%d] %s%s%s%s", p->tgid, p->display_name().c_str(),
                            marker.c_str(), dur.empty() ? "" : "  ", dur.c_str());
    RowData d;
    d.id = id_str;
    d.style = p->style();
    d.cols = {text};
    d.link_mode = 0;
    d.link_id = id_str;
    d.has_children = false;
    return d;
}

/* ── File view ─────────────────────────────────────────────────────── */

static bool file_matches_search(const std::string &path) {
    if (!g_state.search_id) return false;
    auto q = g_state.search_sv();
    return path.find(q) != std::string::npos;
}

/* Build fixed-width RWUE flags string for a PathItem. */
static std::string path_flags_str(const PathItem *f) {
    char buf[5];
    buf[0] = !f->read_procs.empty() ? 'R' : ' ';
    buf[1] = !f->write_procs.empty() ? 'W' : ' ';
    buf[2] = f->unlinks > 0 ? 'U' : ' ';
    buf[3] = f->errs > 0 ? 'E' : ' ';
    buf[4] = '\0';
    return std::string(buf, 4);
}

/* Check whether a path is a well-known system path. */
static bool is_sys_path(const std::string &path) {
    static const char *prefixes[] = {
        "/lib", "/lib64", "/opt", "/usr", "/etc", "/proc", "/sys", "/dev",
        "/run", "/snap", "/var/lib", nullptr
    };
    for (const char **p = prefixes; *p; p++)
        if (path.compare(0, std::strlen(*p), *p) == 0 &&
            (path.size() == std::strlen(*p) || path[std::strlen(*p)] == '/'))
            return true;
    return false;
}

/* Check whether a PathItem (leaf file) passes the current file filters. */
static bool file_passes_filters(const PathItem *f, const std::string &fullpath) {
    /* Subtree filter */
    if (!g_state.subtree_root.empty()) {
        if (fullpath.compare(0, g_state.subtree_root.size(), g_state.subtree_root) != 0)
            return false;
        if (fullpath.size() > g_state.subtree_root.size() &&
            fullpath[g_state.subtree_root.size()] != '/')
            return false;
    }

    /* Progressive refinement */
    if (g_state.file_refinement >= 1 && is_sys_path(fullpath))
        return false;
    if (g_state.file_refinement >= 2 && f->unlinked_at_end())
        return false;
    if (g_state.file_refinement >= 3) {
        /* Hide files from processes that did not fail interestingly */
        bool any_interesting = false;
        for (int tgid : f->proc_tgids) {
            auto *p = find_process(tgid);
            if (p && proc_is_interesting_failure(*p)) { any_interesting = true; break; }
        }
        if (!any_interesting) return false;
    }

    /* Mode toggles (bit0=R, bit1=W, bit2=unlinked-ever, bit3=unlinked-at-end) */
    bool has_read = !f->read_procs.empty();
    bool has_write = !f->write_procs.empty();
    bool has_unlink = f->unlinks > 0;
    bool is_unlinked_end = f->unlinked_at_end();
    /* File must match at least one enabled access type */
    bool any_mode_match = false;
    if ((g_state.file_mode_filter & 0x01) && has_read) any_mode_match = true;
    if ((g_state.file_mode_filter & 0x02) && has_write) any_mode_match = true;
    if ((g_state.file_mode_filter & 0x04) && has_unlink) any_mode_match = true;
    if ((g_state.file_mode_filter & 0x08) && is_unlinked_end) any_mode_match = true;
    /* If file doesn't have unlink or write, it's read-only; show if R bit set */
    if (!has_write && !has_unlink && !is_unlinked_end && (g_state.file_mode_filter & 0x01))
        any_mode_match = true;
    if (!any_mode_match) return false;

    /* Glob filter */
    if (!g_state.file_glob.empty()) {
        if (fnmatch(g_state.file_glob.c_str(), fullpath.c_str(), FNM_PATHNAME) != 0)
            return false;
    }

    return true;
}

/* ── PathItem virtual method implementations ────────────────────────── */

RowStyle PathItem::style() const {
    if (file_matches_search(fullPath())) return RowStyle::Search;
    if (errs) return RowStyle::Error;
    if (unlinked_at_end()) return RowStyle::Yellow;
    if (!write_procs.empty()) return RowStyle::Bold;
    return RowStyle::Normal;
}

std::string PathItem::getParentKey() const {
    return (parent && parent->parent) ? std::string(parent->getKey()) : std::string();
}

RowData PathItem::makeRow(int depth) const {
    std::string fullp(getKey());
    int nprocs = static_cast<int>(proc_tgids.size());
    std::string errs_text = errs ? sfmt(", %d errs", errs) : std::string();
    std::string unlinks_text = unlinks ? sfmt(", %d unlinks", unlinks) : std::string();
    bool has_kids = hasChildren();
    std::string flags = path_flags_str(this);
    auto nv = nameView();
    std::string text;
    if (has_kids) {
        text = sfmt("%s %*s%s%.*s/  [%d opens, %d procs%s%s]", flags.c_str(), depth * 2, "",
                    collapsed ? "\xe2\x96\xb6 " : "\xe2\x96\xbc ",
                    (int)nv.size(), nv.data(), opens, nprocs, errs_text.c_str(), unlinks_text.c_str());
    } else {
        text = sfmt("%s %*s%.*s  [%d opens, %d procs%s%s]", flags.c_str(), depth * 2, "",
                    (int)nv.size(), nv.data(), opens, nprocs, errs_text.c_str(), unlinks_text.c_str());
    }
    RowData d;
    d.id = fullp;
    d.style = style();
    d.cols = {text};
    d.parent_id = getParentKey();
    d.link_mode = 1;
    d.link_id = fullp;
    d.has_children = has_kids;
    return d;
}

/* Recursive DFS on PathItem tree → emit rows for file tree view. */
static void add_file_tree_rec(std::vector<RowData> &rows, PathItem *node, int depth) {
    /* Separate dirs and files among children, skipping empty dirs. */
    std::vector<PathItem*> dirs, files;
    for (auto *c : node->children) {
        auto *pc = static_cast<PathItem*>(c);
        if (pc->opens == 0 && pc->unlinks == 0 && pc->children.empty()) continue;
        if (pc->is_dir || !pc->children.empty()) dirs.push_back(pc);
        else files.push_back(pc);
    }
    std::sort(dirs.begin(), dirs.end(), [](PathItem *a, PathItem *b) { return a->name_id < b->name_id; });
    std::sort(files.begin(), files.end(), [](PathItem *a, PathItem *b) { return a->name_id < b->name_id; });

    for (auto *d : dirs) {
        std::string dfp = d->fullPath();
        if (!file_passes_filters(d, dfp)) {
            /* Still recurse — child files may pass */
            if (!d->collapsed) add_file_tree_rec(rows, d, depth);
            continue;
        }
        rows.push_back(d->makeRow(depth));
        if (!d->collapsed) add_file_tree_rec(rows, d, depth + 1);
    }
    for (auto *f : files) {
        if (f->opens == 0 && f->unlinks == 0) continue;
        std::string fp = f->fullPath();
        if (!file_passes_filters(f, fp)) continue;
        rows.push_back(f->makeRow(depth));
    }
}

/* Collect all leaf PathItems (files with opens > 0 or unlinks > 0) recursively. */
static void collect_file_leaves(PathItem *node, std::vector<PathItem*> &out) {
    if ((node->opens > 0 || node->unlinks > 0) && node->children.empty())
        out.push_back(node);
    for (auto *c : node->children)
        collect_file_leaves(static_cast<PathItem*>(c), out);
}

static void build_lpane_files(std::vector<RowData> &rows) {
    if (!g_state.grouped) {
        /* Flat mode: collect all leaf files, sort by full path. */
        std::vector<PathItem*> leaves;
        if (g_db.path_root) collect_file_leaves(g_db.path_root, leaves);
        for (auto &kv : g_db.nonabs_paths)
            if (kv.second->opens > 0 || kv.second->unlinks > 0) leaves.push_back(kv.second);
        std::sort(leaves.begin(), leaves.end(), [](PathItem *a, PathItem *b) {
            return a->fullPath() < b->fullPath();
        });
        for (auto *fp : leaves) {
            std::string path = fp->fullPath();
            if (!file_passes_filters(fp, path)) continue;
            int nprocs = static_cast<int>(fp->proc_tgids.size());
            std::string errs_text = fp->errs ? sfmt(", %d errs", fp->errs) : std::string();
            std::string unlinks_text = fp->unlinks ? sfmt(", %d unlinks", fp->unlinks) : std::string();
            std::string flags = path_flags_str(fp);
            std::string text = sfmt("%s %s  [%d opens, %d procs%s%s]", flags.c_str(), path.c_str(),
                                    fp->opens, nprocs, errs_text.c_str(), unlinks_text.c_str());
            emit_row(rows, path, fp->style(),
                     "", text, 1, path, false);
        }
    } else {
        /* Tree mode: DFS on PathItem hierarchy starting from root children. */
        if (g_db.path_root) add_file_tree_rec(rows, g_db.path_root, 0);
        /* Non-absolute paths (pipes etc.) at the end. */
        for (auto &kv : g_db.nonabs_paths) {
            PathItem *np = kv.second;
            if (np->opens == 0 && np->unlinks == 0) continue;
            std::string path = g_pool.str(np->name_id);
            if (!file_passes_filters(np, path)) continue;
            int nprocs = static_cast<int>(np->proc_tgids.size());
            std::string errs_text = np->errs ? sfmt(", %d errs", np->errs) : std::string();
            std::string unlinks_text = np->unlinks ? sfmt(", %d unlinks", np->unlinks) : std::string();
            std::string flags = path_flags_str(np);
            std::string text = sfmt("%s   %s  [%d opens, %d procs%s%s]", flags.c_str(), path.c_str(),
                                    np->opens, nprocs, errs_text.c_str(), unlinks_text.c_str());
            emit_row(rows, path, np->style(),
                     "", text, 1, path, false);
        }
    }
}

/* ── Output view ───────────────────────────────────────────────────── */

static std::vector<output_group_t> build_output_groups() {
    std::unordered_map<int, output_group_t> gmap;
    std::vector<int> order;
    for (int i = 0; i < static_cast<int>(g_db.events.size()); i++) {
        auto &ev = g_db.events[i];
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
        for (int i = 0; i < static_cast<int>(g_db.events.size()); i++) {
            auto &ev = g_db.events[i];
            if (ev.kind != EV_STDOUT && ev.kind != EV_STDERR) continue;
            auto *p = find_process(ev.tgid);
            std::string id_str = std::to_string(ev.id);
            std::string data = ev.get_data();
            std::string text = sfmt("[%s] PID %d %s: %s",
                ev.kind == EV_STDOUT ? "STDOUT" : "STDERR", ev.tgid,
                p ? p->display_name().c_str() : "",
                data.c_str());
            emit_row(rows, id_str, ev.kind == EV_STDERR ? RowStyle::Error : RowStyle::Normal, "", text, 2, id_str, false);
        }
    } else {
        for (auto &og : groups) {
            std::string gid = sfmt("io_%d", og.tgid);
            bool collapsed_flag = is_collapsed(gid);
            std::string text = sfmt("%sPID %d %s", collapsed_flag ? "▶ " : "▼ ", og.tgid, og.name.c_str());
            emit_row(rows, gid, RowStyle::Heading, "", text, 2, gid, true);
            if (!collapsed_flag) {
                for (int ei : og.event_indices) {
                    auto &ev = g_db.events[ei];
                    std::string id_str = std::to_string(ev.id);
                    std::string data = ev.get_data();
                    std::string row = sfmt("  [%s] %s", ev.kind == EV_STDOUT ? "STDOUT" : "STDERR", data.c_str());
                    emit_row(rows, id_str, ev.kind == EV_STDERR ? RowStyle::Error : RowStyle::Normal, gid, row, 2, id_str, false);
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
                for (PathItem *rp : p->read_paths) {
                    std::string s = rp ? rp->fullPath() : std::string();
                    if (!s.empty() && !seen.contains(s)) queue.push_back(std::move(s));
                }
            }
        } else {
            /* rdeps: procs that read cur → files they wrote */
            for (int tgid : pd->read_procs) {
                auto *p = find_process(tgid);
                if (!p) continue;
                for (PathItem *wp : p->write_paths) {
                    std::string s = wp ? wp->fullPath() : std::string();
                    if (!s.empty() && !seen.contains(s)) queue.push_back(std::move(s));
                }
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
        emit_row(rows, s, file_matches_search(s) ? RowStyle::Search : RowStyle::Normal, "", s, mode, s, false);
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
        if (g_pool.eq(p->exit_status_id, "exited"))
            marker = p->exit_code == 0 ? " \xe2\x9c\x93" : " \xe2\x9c\x97";
        else if (g_pool.eq(p->exit_status_id, "signaled"))
            marker = sfmt(" \xe2\x9a\xa1%d", p->exit_signal);
        std::string dur = format_duration(p->start_ts, p->end_ts, g_pool.empty(p->exit_status_id));
        std::string text = sfmt("[%d] %s%s%s%s", pt, name.c_str(), marker.c_str(),
                                dur.empty() ? "" : "  ", dur.c_str());
        emit_row(rows, id_str, p->style(), "", text, 0, id_str, false);
    }
}

/* ── Right pane ────────────────────────────────────────────────────── */

static int format_ts(char *buf, size_t bufsz, double ts, double prev) {
    if (g_state.ts_mode == 1) std::snprintf(buf, bufsz, "+%.3fs", ts - g_db.base_ts);
    else if (g_state.ts_mode == 2) std::snprintf(buf, bufsz, "Δ%.3fs", prev < 0 ? 0.0 : ts - prev);
    else std::snprintf(buf, bufsz, "%.3f", ts);
    return 1;
}

static bool event_allowed(const trace_event_t &ev) {
    if (!g_state.evfilt_id) return true;
    const char *kind = "";
    switch (ev.kind) {
    case EV_CWD: kind = "CWD"; break;
    case EV_EXEC: kind = "EXEC"; break;
    case EV_OPEN: kind = "OPEN"; break;
    case EV_UNLINK: kind = "UNLINK"; break;
    case EV_EXIT: kind = "EXIT"; break;
    case EV_STDOUT: kind = "STDOUT"; break;
    case EV_STDERR: kind = "STDERR"; break;
    }
    auto q = g_state.evfilt_sv();
    return std::string_view(kind).find(q) != std::string_view::npos;
}

static void build_rpane_process(std::vector<RowData> &rows, const std::string &id) {
    auto *p = find_process(id.empty() ? 0 : std::atoi(id.c_str()));
    if (!p) return;
    emit_row(rows, "hdr", RowStyle::Heading, "", "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Process \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", -1, "", false);
    emit_row(rows, "tgid", RowStyle::Normal, "", sfmt("TGID:  %d", p->tgid), -1, "", false);
    emit_row(rows, "ppid", RowStyle::Normal, "", sfmt("PPID:  %d", p->ppid), -1, "", false);
    emit_row(rows, "exe", RowStyle::Normal, "", sfmt("EXE:   %s", p->get_exe().c_str()), -1, "", false);
    if (!g_pool.empty(p->exit_status_id)) {
        std::string text = g_pool.eq(p->exit_status_id, "signaled")
            ? sfmt("Exit: signal %d%s", p->exit_signal, p->core_dumped ? " (core)" : "")
            : sfmt("Exit: exited code=%d", p->exit_code);
        emit_row(rows, "exit",
                 (g_pool.eq(p->exit_status_id, "exited") && p->exit_code == 0) ? RowStyle::Green : RowStyle::Error,
                 "", text, -1, "", false);
    }
    int nchildren = static_cast<int>(p->children.size());
    if (nchildren > 0) {
        emit_row(rows, "kids_hdr", RowStyle::Heading, "", sfmt("Children (%d)", nchildren), -1, "", false);
        auto sorted_ch = p->children;
        if (sorted_ch.size() > 1)
            std::sort(sorted_ch.begin(), sorted_ch.end(),
                [](Item *a, Item *b) { return static_cast<process_t*>(a)->tgid < static_cast<process_t*>(b)->tgid; });
        for (auto *item : sorted_ch) {
            auto *c = static_cast<process_t*>(item);
            int ct = c->tgid;
            std::string cid = sfmt("child_%d", ct);
            std::string text = sfmt("[%d] %s", ct, c->display_name().c_str());
            emit_row(rows, cid, RowStyle::Normal, "", text, 0, std::to_string(ct), false);
        }
    }
    auto argv = p->get_argv();
    if (!argv.empty()) {
        emit_row(rows, "argv_hdr", RowStyle::Heading, "", "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Argv \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", -1, "", false);
        for (int i = 0; i < static_cast<int>(argv.size()); i++)
            emit_row(rows, sfmt("argv_%d", i), RowStyle::Normal, "", sfmt("[%d] %s", i, argv[i].c_str()), -1, "", false);
    }
    emit_row(rows, "evt_hdr", RowStyle::Heading, "", "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Events \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", -1, "", false);
    double prev_ts = -1;
    for (int ei : p->event_indices) {
        auto &ev = g_db.events[ei];
        if (!event_allowed(ev)) continue;
        char tsbuf[64];
        format_ts(tsbuf, sizeof tsbuf, ev.ts, prev_ts);
        prev_ts = ev.ts;
        std::string text;
        switch (ev.kind) {
        case EV_CWD: text = sfmt("%s [CWD] %s", tsbuf, ev.get_path().c_str()); break;
        case EV_EXEC: text = sfmt("%s [EXEC] %s", tsbuf, ev.get_exe().c_str()); break;
        case EV_OPEN: {
            std::string err_text = ev.err ? sfmt(" err=%d", ev.err) : std::string();
            text = sfmt("%s [OPEN] %s [%s]%s", tsbuf, ev.get_path().c_str(),
                        ev.get_flags_text().c_str(), err_text.c_str());
            break;
        }
        case EV_UNLINK:
            text = sfmt("%s [UNLINK] %s", tsbuf, ev.get_path().c_str());
            break;
        case EV_EXIT:
            text = g_pool.eq(ev.status_id, "signaled")
                ? sfmt("%s [EXIT] signal %d%s", tsbuf, ev.signal, ev.core_dumped ? " (core)" : "")
                : sfmt("%s [EXIT] exited code=%d", tsbuf, ev.code);
            break;
        case EV_STDOUT: text = sfmt("%s [STDOUT] %s", tsbuf, ev.get_data().c_str()); break;
        case EV_STDERR: text = sfmt("%s [STDERR] %s", tsbuf, ev.get_data().c_str()); break;
        }
        emit_row(rows, sfmt("ev_%d", ev.id), ev.kind == EV_STDERR ? RowStyle::Error : RowStyle::Normal, "", text, -1, "", false);
    }
}

static void build_rpane_file(std::vector<RowData> &rows, const std::string &id) {
    if (id.empty()) return;
    emit_row(rows, "hdr", RowStyle::Heading, "", "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 File \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80", -1, "", false);
    emit_row(rows, "path", RowStyle::Normal, "", id, -1, "", false);
    PathItem *pd = find_path_item(id);
    int opens = pd ? pd->opens : 0;
    int errs  = pd ? pd->errs  : 0;
    int unlinks = pd ? pd->unlinks : 0;
    int nprocs = pd ? static_cast<int>(pd->proc_tgids.size()) : 0;
    if (pd) {
        std::string flags = path_flags_str(pd);
        emit_row(rows, "flags", RowStyle::Normal, "", sfmt("Flags: %s", flags.c_str()), -1, "", false);
    }
    emit_row(rows, "opens", RowStyle::Normal, "", sfmt("Opens: %d", opens), -1, "", false);
    emit_row(rows, "procs", RowStyle::Normal, "", sfmt("Procs: %d", nprocs), -1, "", false);
    emit_row(rows, "errs", errs ? RowStyle::Error : RowStyle::Normal, "", sfmt("Errors: %d", errs), -1, "", false);
    emit_row(rows, "unlinks", unlinks ? RowStyle::Yellow : RowStyle::Normal, "",
             sfmt("Unlinks: %d%s", unlinks,
                  (pd && pd->unlinked_at_end()) ? " (deleted at trace end)" : ""), -1, "", false);
    if (pd) {
        for (int ei : pd->open_event_indices) {
            auto &ev = g_db.events[ei];
            auto *p = find_process(ev.tgid);
            std::string err_text = ev.err ? sfmt(" err=%d", ev.err) : std::string();
            std::string text = sfmt("PID %d %s [OPEN] [%s]%s", ev.tgid,
                p ? p->display_name().c_str() : "",
                ev.get_flags_text().c_str(), err_text.c_str());
            emit_row(rows, sfmt("open_%d", ev.id),
                     ev.err ? RowStyle::Error : (ev.kind == EV_STDERR ? RowStyle::Error : RowStyle::Normal),
                     "", text, 0, std::to_string(ev.tgid), false);
        }
        for (int ei : pd->unlink_event_indices) {
            auto &ev = g_db.events[ei];
            auto *p = find_process(ev.tgid);
            std::string text = sfmt("PID %d %s [UNLINK]", ev.tgid,
                p ? p->display_name().c_str() : "");
            emit_row(rows, sfmt("unlink_%d", ev.id), RowStyle::Yellow,
                     "", text, 0, std::to_string(ev.tgid), false);
        }
    }
}

static void build_rpane_output(std::vector<RowData> &rows, const std::string &id) {
    int eid = id.empty() ? 0 : std::atoi(id.c_str());
    if (eid <= 0 || static_cast<size_t>(eid) >= g_db.event_id_to_index.size()) return;
    int idx = g_db.event_id_to_index[eid];
    if (idx < 0 || idx >= static_cast<int>(g_db.events.size())) return;
    trace_event_t *ev = &g_db.events[idx];
    auto *p = find_process(ev->tgid);
    emit_row(rows, "hdr", RowStyle::Heading, "", "─── Output ───", -1, "", false);
    emit_row(rows, "stream", ev->kind == EV_STDERR ? RowStyle::Error : RowStyle::Normal, "",
             sfmt("Stream: %s", ev->kind == EV_STDOUT ? "STDOUT" : "STDERR"), -1, "", false);
    emit_row(rows, "pid", RowStyle::Normal, "", sfmt("PID: %d", ev->tgid), -1, "", false);
    emit_row(rows, "proc", RowStyle::Normal, "",
             sfmt("Proc: %s", p ? p->display_name().c_str() : ""),
             -1, "", false);
    emit_row(rows, "content_hdr", RowStyle::Heading, "", "─── Content ───", -1, "", false);
    emit_row(rows, "content", ev->kind == EV_STDERR ? RowStyle::Error : RowStyle::Normal, "", ev->get_data(), -1, "", false);
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
    std::vector<std::pair<Item*,int>> dfs; /* (item, depth) stack */
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
    std::vector<Item*> roots;
    for (auto &[tgid, p] : g_db.proc_map)
        if ((p->ppid == 0 || !find_process(p->ppid)) && p->shouldShow())
            roots.push_back(p.get());
    if (roots.size() > 1)
        std::sort(roots.begin(), roots.end(),
            [](Item *a, Item *b) { return a->sortKey() < b->sortKey(); });
    for (int i = static_cast<int>(roots.size()) - 1; i >= 0; i--)
        g_proc_tree_iter.dfs.push_back({roots[i], 0});
}

static void lpane_begin_proc_flat() {
    g_lp_mode = 1;
    g_proc_flat_iter.tgids.clear();
    g_proc_flat_iter.idx = 0;
    for (auto &[tgid, p] : g_db.proc_map)
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
            auto [item, depth] = dfs.back();
            dfs.pop_back();
            bool has_kids = item->hasChildren();
            /* Push children in reverse-sorted order (lowest sortKey comes out first). */
            if (has_kids && !item->collapsed) {
                auto sorted_ch = item->children;
                if (sorted_ch.size() > 1)
                    std::sort(sorted_ch.begin(), sorted_ch.end(),
                        [](Item *a, Item *b) { return a->sortKey() < b->sortKey(); });
                for (int i = static_cast<int>(sorted_ch.size()) - 1; i >= 0; i--) {
                    if (sorted_ch[i]->shouldShow())
                        dfs.push_back({sorted_ch[i], depth + 1});
                }
            }
            return item->makeRow(depth);
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
    if (g_state.evfilt_id) { auto q = g_state.evfilt_sv(); s += sfmt(" | F:%.*s", (int)q.size(), q.data()); }
    if (g_state.search_id) { auto q = g_state.search_sv(); s += sfmt(" | /%.*s", (int)q.size(), q.data()); }
    if (g_state.lp_filter == 1) s += " | V:failed";
    else if (g_state.lp_filter == 2) s += " | V:running";
    if (g_state.mode >= 3 && g_state.mode <= 6) s += sfmt(" | D:%s", g_state.dep_filter ? "written" : "all");
    if (g_state.mode == 1) {
        static const char *ref_labels[] = {"all","no-sys","no-del","fail-only"};
        if (g_state.file_refinement > 0)
            s += sfmt(" | ref:%s", ref_labels[g_state.file_refinement]);
        if (g_state.file_mode_filter != 0x0F) {
            s += " | mode:";
            if (g_state.file_mode_filter & 0x01) s += "R";
            if (g_state.file_mode_filter & 0x02) s += "W";
            if (g_state.file_mode_filter & 0x04) s += "U";
            if (g_state.file_mode_filter & 0x08) s += "D";
        }
        if (!g_state.subtree_root.empty()) s += " | sub:" + g_state.subtree_root;
        if (!g_state.file_glob.empty()) s += " | glob:" + g_state.file_glob;
    }
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
            if (r->style == RowStyle::Search) { g_state.cursor_id = r->id; return; }
        }
        for (int i = 0; i < start; i++) {
            auto *r = g_tui->get_cached_row(g_lpane, i);
            if (!r) break;
            if (r->style == RowStyle::Search) { g_state.cursor_id = r->id; return; }
        }
    } else {
        /* Backward: scan from start-1 down to 0, then wrap from end to start+1. */
        for (int i = start - 1; i >= 0; i--) {
            auto *r = g_tui->get_cached_row(g_lpane, i);
            if (!r) break;
            if (r->style == RowStyle::Search) { g_state.cursor_id = r->id; return; }
        }
        /* Find the end by scanning forward, then scan backward from there. */
        int last = start;
        while (g_tui->get_cached_row(g_lpane, last + 1)) last++;
        for (int i = last; i > start; i--) {
            auto *r = g_tui->get_cached_row(g_lpane, i);
            if (!r) break;
            if (r->style == RowStyle::Search) { g_state.cursor_id = r->id; return; }
        }
    }
}

static void apply_search(const std::string &q) {
    g_state.set_search(q);
    /* Dirty lpane so the engine re-reads with search highlighting. */
    if (g_tui) g_tui->dirty(g_lpane);
    /* Scan lazily to find the first hit. */
    for (int i = 0; ; i++) {
        auto *r = g_tui ? g_tui->get_cached_row(g_lpane, i) : nullptr;
        if (!r) break;
        if (r->style == RowStyle::Search) {
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
    set_collapsed(row->id, !expand);
}

/* ── Diagnostics ───────────────────────────────────────────────────── */

static const char *row_style_name(RowStyle s) {
    switch (s) {
    case RowStyle::Error:   return "error";
    case RowStyle::Search:  return "search";
    case RowStyle::Heading: return "heading";
    case RowStyle::Green:   return "green";
    case RowStyle::Dim:     return "dim";
    case RowStyle::Bold:    return "bold";
    case RowStyle::Cyan:    return "cyan";
    case RowStyle::CyanBold:return "cyan_bold";
    case RowStyle::Yellow:  return "yellow";
    default:                return "normal";
    }
}

static void dump_lpane(FILE *out) {
    if (!g_tui) return;
    std::fprintf(out, "=== LPANE ===\n");
    g_tui->dump_panel(g_lpane, out, [](FILE *f, int i, const RowData &r) {
        std::fprintf(f, "%d|%s|%s|%s|%s\n", i, row_style_name(r.style), r.id.c_str(),
                     r.parent_id.c_str(), r.cols.empty() ? "" : r.cols[0].c_str());
    });
    std::fprintf(out, "=== END LPANE ===\n");
}

static void dump_rpane(FILE *out) {
    if (!g_tui) return;
    std::fprintf(out, "=== RPANE ===\n");
    g_tui->dump_panel(g_rpane, out, [](FILE *f, int i, const RowData &r) {
        std::fprintf(f, "%d|%s|%s|%d|%s\n", i, row_style_name(r.style),
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
    std::string search_s = g_pool.str(g_state.search_id);
    std::string evfilt_s = g_pool.str(g_state.evfilt_id);
    std::fprintf(out, "cursor=%d scroll=%d focus=%d dcursor=%d dscroll=%d ts_mode=%d sort_key=%d grouped=%d mode=%d lp_filter=%d search=%s evfilt=%s rows=%d cols=%d dep_filter=%d\n",
            cursor, scroll, focus_r, dcursor, dscroll,
            g_state.ts_mode, g_state.sort_key, g_state.grouped, g_state.mode, g_state.lp_filter,
            search_s.c_str(), evfilt_s.c_str(), rows, cols, g_state.dep_filter);
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
    case 'F': g_state.set_evfilt(""); break;
    case '/': {
        char buf[256] = "";
        if (tui.line_edit("/", buf, sizeof buf)) apply_search(buf);
        break;
    }
    case 'f': {
        char buf[64] = "";
        if (tui.line_edit("Filter: ", buf, sizeof buf)) {
            for (char *p = buf; *p; p++) *p = static_cast<char>(std::toupper(static_cast<unsigned char>(*p)));
            g_state.set_evfilt(buf);
        }
        break;
    }
    case 'n': set_cursor_to_search_hit(1); break;
    case 'N': set_cursor_to_search_hit(-1); break;
    case 'e': expand_subtree(1); break;
    case 'E': expand_subtree(0); break;
    case 'r': if (g_state.mode == 1) { g_state.file_refinement = (g_state.file_refinement + 1) % 4; reset_mode_selection(); } break;
    case 'R': if (g_state.mode == 1) { g_state.file_mode_filter ^= 0x01; reset_mode_selection(); } break;
    case 'D': if (g_state.mode == 1) { g_state.file_mode_filter ^= 0x02; reset_mode_selection(); } break;
    case 'U': if (g_state.mode == 1) { g_state.file_mode_filter ^= 0x04; reset_mode_selection(); } break;
    case 'S': if (g_state.mode == 1) { g_state.subtree_root = g_state.cursor_id; reset_mode_selection(); } break;
    case 'C': if (g_state.mode == 1) { g_state.subtree_root.clear(); g_state.file_glob.clear();
                                        g_state.file_refinement = 0; g_state.file_mode_filter = 0x0F;
                                        reset_mode_selection(); } break;
    case 'p': if (g_state.mode == 1) {
        char buf[256] = "";
        if (tui.line_edit("Glob: ", buf, sizeof buf)) g_state.file_glob = buf;
        reset_mode_selection();
        break;
    }
    case 'P': if (g_state.mode == 1) { g_state.file_glob.clear(); reset_mode_selection(); } break;
    case TUI_K_LEFT: case 'h': collapse_or_back(); break;
    case TUI_K_RIGHT: case 'l': case TUI_K_ENTER: expand_or_detail(); break;
    case 'W': tui.set_status(" Save removed — use uproctrace/sudtrace to save traces"); break;
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
        std::string q;
        if (json_get(line, "q", sp)) q = json_decode_string(sp);
        for (auto &c : q) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        g_state.set_evfilt(q);
        apply_state_change();
    } else if (kind == "print") {
        std::string what;
        if (json_get(line, "what", sp)) what = json_decode_string(sp);
        process_print(what);
    }
}

/* ── Live trace ────────────────────────────────────────────────────── */

static void on_live_batch() {
    apply_state_change();
}

/* Live trace fd is always wire-format — uproctrace, the only live
 * producer tv ever spawns, emits binary wire. We keep a persistent
 * decoder across reads and count delivered events for live-batch
 * coalescing. */
static std::unique_ptr<WireDecoder> t_live_dec;
static int t_live_did = 0;

static WireDecoder &get_live_decoder() {
    if (!t_live_dec) {
        t_live_dec = std::make_unique<WireDecoder>([](const WireRawEvent &w) {
            auto pe = preparse_wire(w);
            if (pe.valid) { g_db.apply_preparsed(pe); t_live_did++; }
        });
    }
    return *t_live_dec;
}

static void on_trace_fd_cb(Tui &tui, int fd) {
    unsigned char buf[64 * 1024];
    int n = static_cast<int>(read(fd, buf, sizeof buf));
    if (n <= 0) {
        if (t_live_dec) t_live_dec->flush();
        t_pending_live_rows = 0;
        t_live_batch_start_ms = 0;
        on_live_batch();
        tui.unwatch_fd(fd);
        if (t_trace_fd >= 0) { close(t_trace_fd); t_trace_fd = -1; }
        return;
    }
    t_live_did = 0;
    auto &dec = get_live_decoder();
    if (!dec.feed(buf, static_cast<size_t>(n))) {
        std::fprintf(stderr, "tv: live wire decode error\n");
        tui.unwatch_fd(fd);
        if (t_trace_fd >= 0) { close(t_trace_fd); t_trace_fd = -1; }
        return;
    }
    int did = t_live_did;
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
    g_db.clear();
    g_output_collapsed.clear();
    g_pool.clear();
}

/* ── Test API (non-static, called from tests.cpp) ─────────────────── */

extern int run_tests();  /* defined in tests.cpp */

void tv_test_reset() {
    g_tui.reset();
    free_all();
    g_state = {};
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
int  tv_test_file_refinement() { return g_state.file_refinement; }
int  tv_test_file_mode_filter() { return g_state.file_mode_filter; }
/* test helpers need null-terminated strings; use static buffers. */
const char *tv_test_search() {
    static std::string buf;
    buf = g_pool.str(g_state.search_id);
    return buf.c_str();
}
const char *tv_test_evfilt() {
    static std::string buf;
    buf = g_pool.str(g_state.evfilt_id);
    return buf.c_str();
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
    char load_file[256] = "", trace_file[256] = "";
    char **cmd = nullptr;
    if (argc >= 2 && std::strcmp(argv[1], "--uproctrace") == 0) return uproctrace_main(argc - 1, argv + 1);
    if (argc >= 2 && std::strcmp(argv[1], "--test") == 0) return run_tests();
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--load") == 0 && i + 1 < argc) { load_mode = 1; std::snprintf(load_file, sizeof load_file, "%s", argv[++i]); }
        else if (std::strcmp(argv[i], "--trace") == 0 && i + 1 < argc) std::snprintf(trace_file, sizeof trace_file, "%s", argv[++i]);
        else if (std::strcmp(argv[i], "--no-env") == 0) no_env = 1;
        else if (std::strcmp(argv[i], "--module") == 0) live_backend = LIVE_TRACE_BACKEND_MODULE;
        else if (std::strcmp(argv[i], "--sud") == 0) live_backend = LIVE_TRACE_BACKEND_SUD;
        else if (std::strcmp(argv[i], "--ptrace") == 0) live_backend = LIVE_TRACE_BACKEND_PTRACE;
        else if (std::strcmp(argv[i], "--") == 0 && i + 1 < argc) { cmd = argv + i + 1; break; }
    }
    if (!load_mode && !trace_file[0] && !cmd) {
        std::fprintf(stderr,
            "Usage: tv [--module|--sud|--ptrace] -- <command> [args...]\n"
            "       tv --trace <file.wire[.zst] | file.jsonl[.zst]>\n"
            "       tv --uproctrace [-o FILE[.wire[.zst]]] [--module|--sud|--ptrace] -- <command> [args...]\n");
        return 1;
    }

    if (load_mode) ingest_file(load_file);
    if (trace_file[0]) ingest_file(trace_file);

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

    int headless_mode = (!g_db.input_lines.empty()) ||
                        (trace_file[0] && !cmd && !isatty(STDIN_FILENO));

    DataSource src{ds_row_begin, ds_row_has_more, ds_row_next};

    if (headless_mode) g_tui = Tui::open_headless(std::move(src), 24, 80);
    else g_tui = Tui::open(std::move(src));
    if (!g_tui) {
        if (!headless_mode) std::fprintf(stderr, "tv: cannot open terminal\n");
        free_all();
        return headless_mode ? 0 : 1;
    }
    if (headless_mode) g_headless = 1;

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

    for (BlobIID lid : g_db.input_lines) { std::string s = g_pool.str(lid); process_input_line(s.c_str()); }
    if (g_headless) {
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
