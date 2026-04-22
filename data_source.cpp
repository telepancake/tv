/* data_source.cpp — implements data_source.h.
 *
 * Each mode rebuilds its panel from a SQL query. Heavy aggregations
 * are kept in tv_idx_* tables (built lazily via TvDb::ensure_*()).
 *
 * Tree views (process hierarchy, file path tree) build a small
 * adjacency map from the result set and DFS in C++ — no recursive CTE
 * needed at the row-emit layer (recursive CTEs are reserved for
 * dep/rdep closure traversal in modes 4..7).
 */

#include "data_source.h"
#include "tv_db.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace {

/* ── tiny formatting helpers ──────────────────────────────────────── */

std::string sfmt(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    return buf;
}

std::string format_duration_ns(int64_t start_ns, int64_t end_ns) {
    if (end_ns < start_ns) return "";
    double s = (end_ns - start_ns) / 1e9;
    char buf[32];
    if (s < 0.001)      std::snprintf(buf, sizeof buf, "%.0f us", s * 1e6);
    else if (s < 1.0)   std::snprintf(buf, sizeof buf, "%.0f ms", s * 1000);
    else if (s < 60.0)  std::snprintf(buf, sizeof buf, "%.2f s", s);
    else if (s < 3600)  std::snprintf(buf, sizeof buf, "%.1f m", s / 60);
    else                std::snprintf(buf, sizeof buf, "%.1f h", s / 3600);
    return buf;
}

std::string format_exit(const std::string &kind, const std::string &code,
                        const std::string &core, bool ended) {
    if (!ended) return "running";
    if (kind.empty()) return "—";
    int k = std::atoi(kind.c_str());
    int c = std::atoi(code.c_str());
    if (k == 1) {
        std::string s = sfmt("sig %d", c);
        if (core == "true" || core == "1") s += " (core)";
        return s;
    }
    return c == 0 ? "ok" : sfmt("exit %d", c);
}

std::string sql_escape(const std::string &s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "''";
        else out += c;
    }
    out += "'";
    return out;
}

std::string basename_of(const std::string &p) {
    auto pos = p.find_last_of('/');
    return pos == std::string::npos ? p : p.substr(pos + 1);
}

const char *style_for_exit(const std::string &kind, const std::string &code,
                           bool ended) {
    if (!ended) return "green";
    if (kind.empty()) return "dim";
    if (kind == "1") return "err";
    return code == "0" ? "ok" : "err";
}

RowStyle to_style(const char *s) {
    if (!s) return RowStyle::Normal;
    if (!std::strcmp(s, "err"))     return RowStyle::Error;
    if (!std::strcmp(s, "ok"))      return RowStyle::Normal;
    if (!std::strcmp(s, "green"))   return RowStyle::Green;
    if (!std::strcmp(s, "dim"))     return RowStyle::Dim;
    if (!std::strcmp(s, "head"))    return RowStyle::Heading;
    if (!std::strcmp(s, "yellow"))  return RowStyle::Yellow;
    return RowStyle::Normal;
}

RowData mk_row(const std::string &id, const std::string &text,
               RowStyle style = RowStyle::Normal) {
    RowData r;
    r.id = id;
    r.style = style;
    r.cols.push_back(text);
    return r;
}

RowData mk_kv(const std::string &id, const std::string &key,
              const std::string &val, RowStyle style = RowStyle::Normal) {
    /* The right pane is rendered as a single-column panel (the
     * engine truncates extra columns), so we pre-format key+value
     * into one cell with a fixed-width left part for alignment.
     * Long values overflow the panel width and get ellipsised by
     * the engine, which is what we want — at least the first chunk
     * of the value is visible. */
    RowData r;
    r.id = id;
    r.style = style;
    char prefix[24];
    std::snprintf(prefix, sizeof prefix, "%-18s ", key.c_str());
    r.cols.push_back(std::string(prefix) + val);
    /* Carry the raw fields for app-level navigation (Enter on a row,
     * value-based searches, etc.). */
    r.link_id = val;
    return r;
}

/* OPEN flags → human flags string (R/W/RW + O_CREAT/O_TRUNC hints). */
std::string flags_text(int flags) {
    std::string s;
    int acc = flags & 3;
    if      (acc == 0) s = "R";
    else if (acc == 1) s = "W";
    else if (acc == 2) s = "RW";
    else               s = "?";
    if (flags & 0x40)    s += "+create";
    if (flags & 0x200)   s += "+trunc";
    if (flags & 0x400)   s += "+append";
    if (flags & 0x80000) s += "+cloexec";
    return s;
}

} // namespace

/* ── ctor / DataSource wiring ─────────────────────────────────────── */

TvDataSource::TvDataSource(TvDb &db, AppState &state)
    : db_(db), state_(state) {}

DataSource TvDataSource::make_data_source() {
    DataSource s;
    s.row_begin    = [this](int p) { row_begin(p); };
    s.row_has_more = [this](int p) { return row_has_more(p); };
    s.row_next     = [this](int p) { return row_next(p); };
    return s;
}

void TvDataSource::invalidate() {
    built_lpane_ = false;
    built_rpane_ = false;
}

bool dirty_for_lpane(const AppState &s,
                     int prev_mode, const std::string &prev_search,
                     const std::string &prev_flag_filter,
                     bool prev_grouped, bool prev_subtree_only,
                     const std::string &prev_subtree_root,
                     const std::string &prev_subject,
                     bool prev_show_pids) {
    return s.mode != prev_mode || s.search != prev_search ||
           s.flag_filter != prev_flag_filter ||
           s.grouped != prev_grouped || s.subtree_only != prev_subtree_only ||
           s.subtree_root != prev_subtree_root ||
           s.subject_file != prev_subject ||
           s.show_pids != prev_show_pids;
}

void TvDataSource::row_begin(int panel) {
    if (panel == 0) {
        bool stale = !built_lpane_ ||
            dirty_for_lpane(state_, built_for_mode_, built_for_search_,
                            built_for_flag_filter_,
                            built_for_grouped_, built_for_subtree_only_,
                            built_for_subtree_root_, built_for_subject_,
                            built_for_show_pids_);
        if (stale) {
            rebuild_lpane();
            built_for_mode_ = state_.mode;
            built_for_search_ = state_.search;
            built_for_flag_filter_ = state_.flag_filter;
            built_for_grouped_ = state_.grouped;
            built_for_subtree_only_ = state_.subtree_only;
            built_for_subtree_root_ = state_.subtree_root;
            built_for_subject_ = state_.subject_file;
            built_for_show_pids_ = state_.show_pids;
            built_lpane_ = true;
        }
        lpane_idx_ = 0;
    } else {
        if (!built_rpane_ || built_for_cursor_ != state_.cursor_id ||
            built_for_mode_ != state_.mode ||
            built_for_collapsed_ != state_.collapsed_sections) {
            rebuild_rpane();
            built_for_cursor_ = state_.cursor_id;
            built_for_collapsed_ = state_.collapsed_sections;
            built_rpane_ = true;
        }
        rpane_idx_ = 0;
    }
}

bool TvDataSource::row_has_more(int panel) {
    if (panel == 0) return lpane_idx_ < lpane_.size();
    return rpane_idx_ < rpane_.size();
}

RowData TvDataSource::row_next(int panel) {
    if (panel == 0) return lpane_.at(lpane_idx_++);
    return rpane_.at(rpane_idx_++);
}

/* ── lpane dispatch ───────────────────────────────────────────────── */

void TvDataSource::rebuild_lpane() {
    lpane_.clear();
    switch (state_.mode) {
        case 1: lpane_processes(); break;
        case 2: lpane_files(); break;
        case 3: lpane_events(); break;
        case 4: lpane_deps(0); break;
        case 5: lpane_deps(1); break;
        case 6: lpane_dep_cmds(0); break;
        case 7: lpane_dep_cmds(1); break;
        default:
            lpane_.push_back(mk_row("__bad",
                "(unknown mode " + std::to_string(state_.mode) + ")",
                RowStyle::Dim));
    }
    if (lpane_.empty()) {
        lpane_.push_back(mk_row("__empty", "(no rows)", RowStyle::Dim));
    }
}

/* ── Mode 1: process tree ─────────────────────────────────────────── */

namespace {
struct ProcRow {
    int         tgid = 0;
    int         ppid = 0;
    std::string exe;
    std::string name;
    int64_t     start_ns = 0;
    int64_t     end_ns   = 0;
    std::string exit_kind, exit_code, core_dumped;
    bool        ended = false;
    /* for tree */
    std::vector<int> children;
    bool             matches_search = true;
};

std::string proc_label(const ProcRow &p, bool show_basename_only,
                       bool show_pid) {
    std::string label;
    if (show_pid) label = sfmt("[%d] ", p.tgid);
    label += show_basename_only ? p.name : p.exe;
    if (label.size() > 0 && p.exe.empty() && p.name.empty())
        label += "(no exec)";
    std::string dur = format_duration_ns(p.start_ns, p.end_ns);
    if (!dur.empty()) label += "  " + dur;
    label += "  " + format_exit(p.exit_kind, p.exit_code, p.core_dumped, p.ended);
    return label;
}
} // namespace

void TvDataSource::lpane_processes() {
    std::string err;
    if (!db_.ensure_proc_index(&err)) {
        lpane_.push_back(mk_row("__err", "(index: " + err + ")", RowStyle::Error));
        return;
    }

    std::string sql =
        "SELECT tgid, ppid, "
        "       CAST(exe AS VARCHAR), "
        "       start_ns, end_ns, "
        "       exit_kind, exit_code, core_dumped "
        "FROM tv_idx_proc";
    auto rows = db_.query_strings(sql, &err);
    if (!err.empty()) {
        lpane_.push_back(mk_row("__err", err, RowStyle::Error));
        return;
    }
    if (rows.empty()) {
        lpane_.push_back(mk_row("__empty", "(no processes)", RowStyle::Dim));
        return;
    }

    std::unordered_map<int, ProcRow> procs;
    procs.reserve(rows.size());
    for (auto &r : rows) {
        ProcRow p;
        p.tgid     = std::atoi(r[0].c_str());
        p.ppid     = std::atoi(r[1].c_str());
        p.exe      = r[2];
        p.name     = basename_of(p.exe);
        p.start_ns = r[3].empty() ? 0 : std::stoll(r[3]);
        p.end_ns   = r[4].empty() ? p.start_ns : std::stoll(r[4]);
        p.exit_kind = r[5];
        p.exit_code = r[6];
        p.core_dumped = r[7];
        p.ended = !r[5].empty();
        if (!state_.search.empty()) {
            p.matches_search = (p.exe.find(state_.search) != std::string::npos) ||
                               (p.name.find(state_.search) != std::string::npos);
        }
        procs.emplace(p.tgid, std::move(p));
    }

    /* Build adjacency: child list for each ppid. */
    std::vector<int> roots;
    if (state_.grouped) {
        for (auto &kv : procs) {
            ProcRow &p = kv.second;
            auto pit = procs.find(p.ppid);
            if (pit == procs.end()) {
                roots.push_back(p.tgid);
            } else {
                pit->second.children.push_back(p.tgid);
            }
        }
        /* If subtree_only and a root tgid is set, restrict to that subtree. */
        if (state_.subtree_only && !state_.subtree_root.empty()) {
            int rt = std::atoi(state_.subtree_root.c_str());
            if (procs.count(rt)) roots = { rt };
        }
        std::sort(roots.begin(), roots.end(),
                  [&](int a, int b) { return procs[a].start_ns < procs[b].start_ns; });
        for (auto &kv : procs) {
            auto &c = kv.second.children;
            std::sort(c.begin(), c.end(),
                [&](int a, int b) { return procs[a].start_ns < procs[b].start_ns; });
        }
    } else {
        for (auto &kv : procs) roots.push_back(kv.first);
        std::sort(roots.begin(), roots.end(),
                  [&](int a, int b) { return procs[a].start_ns < procs[b].start_ns; });
    }

    /* Search-aware pruning: in tree mode, drop subtrees whose own row
     * and all descendants don't match. */
    std::function<bool(int)> any_match = [&](int t) -> bool {
        ProcRow &p = procs[t];
        if (state_.search.empty() || p.matches_search) return true;
        for (int c : p.children) if (any_match(c)) return true;
        return false;
    };

    /* DFS emit. */
    std::function<void(int, const std::string &, bool)> emit =
        [&](int t, const std::string &prefix, bool is_last) {
            ProcRow &p = procs[t];
            if (state_.grouped && !state_.search.empty() && !any_match(t)) return;
            std::string indent;
            if (state_.grouped) {
                indent = prefix;
                if (!prefix.empty() || prefix == "")
                    indent += is_last ? "└─ " : "├─ ";
                /* Note: roots are emitted with empty prefix and no glyph. */
            }
            std::string text = state_.grouped ? indent : "";
            text += proc_label(p, /*basename_only=*/true,
                               state_.show_pids);
            RowStyle style = RowStyle::Normal;
            if (!p.ended)             style = RowStyle::Green;
            else if (p.exit_kind == "1") style = RowStyle::Error;
            else if (p.exit_code != "0" && !p.exit_code.empty())
                style = RowStyle::Error;
            if (!state_.search.empty() && p.matches_search)
                style = RowStyle::Search;
            RowData row;
            row.id = std::to_string(p.tgid);
            row.parent_id = std::to_string(p.ppid);
            row.has_children = !p.children.empty();
            row.cols.push_back(std::move(text));
            row.style = style;
            lpane_.push_back(std::move(row));
            if (!state_.grouped) return;
            std::string child_prefix = prefix + (is_last ? "   " : "│  ");
            for (size_t i = 0; i < p.children.size(); i++)
                emit(p.children[i], child_prefix, i + 1 == p.children.size());
        };

    if (state_.grouped) {
        for (size_t i = 0; i < roots.size(); i++)
            emit(roots[i], "", i + 1 == roots.size());
    } else {
        for (int t : roots) emit(t, "", true);
    }
}

/* ── Mode 2: file tree ────────────────────────────────────────────── */

void TvDataSource::lpane_files() {
    std::string err;
    if (!db_.ensure_path_index(&err)) {
        lpane_.push_back(mk_row("__err", "(index: " + err + ")", RowStyle::Error));
        return;
    }
    std::string sql =
        "SELECT path, opens, errors, procs, reads, writes "
        "FROM tv_idx_path";
    std::string where;
    if (!state_.search.empty())
        where += "path LIKE '%' || " + sql_escape(state_.search) + " || '%'";
    /* Flag filter: an arbitrary subset of {R,W,E}; row must have ALL of
     * the requested categories.  E.g. "WE" = files written AND with
     * errors; "R" = files read.  Matches the visible "RWE" badge. */
    auto add_clause = [&](const std::string &c) {
        if (where.empty()) where = c;
        else where = "(" + where + ") AND " + c;
    };
    for (char ch : state_.flag_filter) {
        switch (ch) {
            case 'R': case 'r': add_clause("reads  > 0");  break;
            case 'W': case 'w': add_clause("writes > 0");  break;
            case 'E': case 'e': add_clause("errors > 0");  break;
            default: break;
        }
    }
    if (!where.empty()) sql += " WHERE " + where;
    sql += " ORDER BY path LIMIT 5000";
    auto rows = db_.query_strings(sql, &err);
    if (!err.empty()) {
        lpane_.push_back(mk_row("__err", err, RowStyle::Error));
        return;
    }

    auto fmt_row = [&](const std::vector<std::string> &r,
                       const std::string &display_text) -> RowData {
        const std::string &path = r[0];
        int opens  = std::atoi(r[1].c_str());
        int errors = std::atoi(r[2].c_str());
        int procs  = std::atoi(r[3].c_str());
        int reads  = std::atoi(r[4].c_str());
        int writes = std::atoi(r[5].c_str());
        std::string flags;
        flags += reads  ? 'R' : '-';
        flags += writes ? 'W' : '-';
        flags += errors ? 'E' : '-';
        std::string text = sfmt("%s  %s  [%d opens, %d procs%s]",
            flags.c_str(), display_text.c_str(), opens, procs,
            errors ? sfmt(", %d errs", errors).c_str() : "");
        RowStyle st = errors ? RowStyle::Error :
                      writes ? RowStyle::Yellow : RowStyle::Normal;
        if (!state_.search.empty() &&
            path.find(state_.search) != std::string::npos)
            st = RowStyle::Search;
        RowData row;
        row.id = path;
        row.cols.push_back(std::move(text));
        row.style = st;
        return row;
    };

    if (!state_.grouped) {
        for (auto &r : rows) lpane_.push_back(fmt_row(r, r[0]));
        return;
    }

    /* Tree mode: build a directory tree from the path list. Each
     * directory node is a synthetic heading; leaf nodes are real
     * files with their stats. */
    struct Node {
        std::string component;          /* "" for root */
        std::string full_path;          /* absolute or partial */
        bool        is_file = false;
        int         row_idx = -1;       /* index into `rows` if is_file */
        std::map<std::string, std::unique_ptr<Node>> children;
    };
    Node root;
    for (size_t i = 0; i < rows.size(); i++) {
        const std::string &p = rows[i][0];
        if (p.empty()) continue;
        Node *cur = &root;
        size_t pos = 0;
        if (p[0] == '/') pos = 1;
        std::string acc = (p[0] == '/') ? "/" : "";
        while (pos <= p.size()) {
            size_t nx = p.find('/', pos);
            std::string comp = p.substr(pos, nx == std::string::npos
                                            ? p.size() - pos : nx - pos);
            if (comp.empty() && nx == std::string::npos) break;
            acc += (acc.empty() || acc.back() == '/') ? comp : "/" + comp;
            auto it = cur->children.find(comp);
            if (it == cur->children.end()) {
                auto n = std::make_unique<Node>();
                n->component = comp;
                n->full_path = acc;
                Node *raw = n.get();
                cur->children.emplace(comp, std::move(n));
                cur = raw;
            } else {
                cur = it->second.get();
            }
            if (nx == std::string::npos) break;
            pos = nx + 1;
        }
        cur->is_file = true;
        cur->row_idx = (int)i;
    }

    std::function<void(Node *, int)> emit = [&](Node *n, int depth) {
        for (auto &kv : n->children) {
            Node *c = kv.second.get();
            std::string indent(depth * 2, ' ');
            if (c->is_file) {
                RowData rw = fmt_row(rows[c->row_idx], indent + c->component);
                lpane_.push_back(std::move(rw));
            } else {
                RowData rw;
                rw.id = c->full_path + "/";
                rw.cols.push_back(indent + c->component + "/");
                rw.style = RowStyle::CyanBold;
                rw.has_children = true;
                lpane_.push_back(std::move(rw));
            }
            emit(c, depth + 1);
        }
    };
    emit(&root, 0);
}

/* ── Mode 3: event log ────────────────────────────────────────────── */

void TvDataSource::lpane_events() {
    /* UNION ALL across event tables. We omit ARGV/ENV/AUXV; those are
     * shown in the right-pane process detail. */
    std::string err;
    std::string sql =
        "SELECT 'EXEC'   AS kind, ts_ns, tgid, CAST(exe AS VARCHAR) AS info "
        "FROM exec UNION ALL "
        "SELECT 'CWD'    AS kind, ts_ns, tgid, CAST(cwd AS VARCHAR) "
        "FROM cwd UNION ALL "
        "SELECT 'OPEN'   AS kind, ts_ns, tgid, CAST(path AS VARCHAR) "
        "FROM open_ UNION ALL "
        "SELECT 'EXIT'   AS kind, ts_ns, tgid, "
        "       CASE WHEN status_kind=1 THEN 'sig ' || code_or_sig "
        "            ELSE 'code ' || code_or_sig END "
        "FROM exit_ UNION ALL "
        "SELECT 'STDOUT' AS kind, ts_ns, tgid, CAST(data AS VARCHAR) "
        "FROM stdout_ UNION ALL "
        "SELECT 'STDERR' AS kind, ts_ns, tgid, CAST(data AS VARCHAR) "
        "FROM stderr_";
    if (!state_.search.empty())
        sql = "SELECT * FROM (" + sql + ") WHERE info LIKE '%' || " +
              sql_escape(state_.search) + " || '%'";
    sql = "SELECT * FROM (" + sql + ") ORDER BY ts_ns LIMIT 5000";

    auto rows = db_.query_strings(sql, &err);
    if (!err.empty()) {
        lpane_.push_back(mk_row("__err", err, RowStyle::Error));
        return;
    }
    int64_t base_ns = 0;
    if (!rows.empty() && !rows[0][1].empty()) base_ns = std::stoll(rows[0][1]);
    for (auto &r : rows) {
        const std::string &kind = r[0];
        int64_t ts_ns = r[1].empty() ? 0 : std::stoll(r[1]);
        const std::string &tgid = r[2];
        std::string info = r[3];
        /* Strip control chars in stdout/stderr previews. */
        if (kind == "STDOUT" || kind == "STDERR") {
            for (auto &c : info) if (c == '\n' || c == '\r' || c == '\t') c = ' ';
            if (info.size() > 120) info = info.substr(0, 117) + "...";
        }
        double rel = (ts_ns - base_ns) / 1e9;
        std::string text = sfmt("+%6.3fs  %-6s  [%s]  %s",
            rel, kind.c_str(), tgid.c_str(), info.c_str());
        RowStyle st = RowStyle::Normal;
        if      (kind == "STDERR" || kind == "EXIT") st = RowStyle::Error;
        else if (kind == "EXEC")                     st = RowStyle::CyanBold;
        else if (kind == "CWD")                      st = RowStyle::Cyan;
        if (!state_.search.empty() &&
            info.find(state_.search) != std::string::npos)
            st = RowStyle::Search;
        RowData row;
        row.id = tgid + ":" + std::to_string(ts_ns);
        row.cols.push_back(std::move(text));
        row.style = st;
        lpane_.push_back(std::move(row));
    }
}

/* ── Modes 4 & 5: dep / rdep file closure ─────────────────────────── */

void TvDataSource::lpane_deps(int reverse) {
    if (state_.subject_file.empty()) {
        lpane_.push_back(mk_row("__hint",
            "(no subject file: navigate to a file in mode 2 and press 4-7)",
            RowStyle::Dim));
        return;
    }
    std::string err;
    if (!db_.ensure_edge_index(&err)) {
        lpane_.push_back(mk_row("__err", err, RowStyle::Error));
        return;
    }
    /* Recursive closure on (path) edges:
     *  reverse=0 (deps): from start, find all paths that fed into it.
     *    edge: P writes A and reads B  ⇒  A depends on B.
     *  reverse=1 (rdeps): from start, find all paths derived from it.
     *    edge: P reads A and writes B  ⇒  B is derived from A.
     */
    const char *src_mode = reverse ? "0" : "1";   // edge mode of start side
    const char *dst_mode = reverse ? "1" : "0";   // edge mode of "next" side
    std::string sql =
        "WITH RECURSIVE closure(path, depth) AS ("
        "  SELECT " + sql_escape(state_.subject_file) + " AS path, 0"
        "  UNION "
        "  SELECT e2.path, c.depth + 1 "
        "  FROM closure c "
        "  JOIN tv_idx_edge e1 ON e1.path = c.path AND e1.mode = " + src_mode +
        "  JOIN tv_idx_edge e2 ON e2.tgid = e1.tgid AND e2.mode = " + dst_mode +
        "                    AND e2.path <> c.path "
        "  WHERE c.depth < 8 "
        ") "
        "SELECT path, MIN(depth) AS d FROM closure "
        "GROUP BY path ORDER BY d, path LIMIT 5000";
    auto rows = db_.query_strings(sql, &err);
    if (!err.empty()) {
        lpane_.push_back(mk_row("__err", err, RowStyle::Error));
        return;
    }
    for (auto &r : rows) {
        const std::string &path = r[0];
        int d = std::atoi(r[1].c_str());
        std::string text = sfmt("%*s%s", d * 2, "", path.c_str());
        RowStyle st = (d == 0) ? RowStyle::Heading : RowStyle::Normal;
        if (!state_.search.empty() &&
            path.find(state_.search) != std::string::npos)
            st = RowStyle::Search;
        RowData row;
        row.id = path;
        row.cols.push_back(std::move(text));
        row.style = st;
        lpane_.push_back(std::move(row));
    }
}

/* ── Modes 6 & 7: dep / rdep cmds (processes in closure) ──────────── */

void TvDataSource::lpane_dep_cmds(int reverse) {
    if (state_.subject_file.empty()) {
        lpane_.push_back(mk_row("__hint",
            "(no subject file: navigate to a file in mode 2 and press 4-7)",
            RowStyle::Dim));
        return;
    }
    std::string err;
    if (!db_.ensure_edge_index(&err)) {
        lpane_.push_back(mk_row("__err", err, RowStyle::Error));
        return;
    }
    if (!db_.ensure_proc_index(&err)) {
        lpane_.push_back(mk_row("__err", err, RowStyle::Error));
        return;
    }
    const char *src_mode = reverse ? "0" : "1";
    const char *dst_mode = reverse ? "1" : "0";
    std::string sql =
        "WITH RECURSIVE closure(path) AS ("
        "  SELECT " + sql_escape(state_.subject_file) +
        "  UNION "
        "  SELECT e2.path "
        "  FROM closure c "
        "  JOIN tv_idx_edge e1 ON e1.path = c.path AND e1.mode = " + src_mode +
        "  JOIN tv_idx_edge e2 ON e2.tgid = e1.tgid AND e2.mode = " + dst_mode +
        "                    AND e2.path <> c.path "
        "), "
        "procs AS ("
        "  SELECT DISTINCT e.tgid FROM tv_idx_edge e JOIN closure c ON e.path = c.path"
        ") "
        "SELECT p.tgid, CAST(p.exe AS VARCHAR), "
        "       p.start_ns, p.end_ns, p.exit_kind, p.exit_code, p.core_dumped "
        "FROM tv_idx_proc p JOIN procs USING (tgid) "
        "ORDER BY p.start_ns LIMIT 5000";
    auto rows = db_.query_strings(sql, &err);
    if (!err.empty()) {
        lpane_.push_back(mk_row("__err", err, RowStyle::Error));
        return;
    }
    for (auto &r : rows) {
        ProcRow p;
        p.tgid = std::atoi(r[0].c_str());
        p.exe  = r[1];
        p.name = basename_of(p.exe);
        p.start_ns = r[2].empty() ? 0 : std::stoll(r[2]);
        p.end_ns   = r[3].empty() ? p.start_ns : std::stoll(r[3]);
        p.exit_kind = r[4];
        p.exit_code = r[5];
        p.core_dumped = r[6];
        p.ended = !r[4].empty();
        std::string text = proc_label(p, true, /*show_pid=*/true);
        RowStyle st = RowStyle::Normal;
        if (!p.ended) st = RowStyle::Green;
        else if (p.exit_kind == "1" || (p.exit_code != "0" && !p.exit_code.empty()))
            st = RowStyle::Error;
        if (!state_.search.empty() &&
            (p.name.find(state_.search) != std::string::npos ||
             p.exe.find(state_.search)  != std::string::npos))
            st = RowStyle::Search;
        RowData row;
        row.id = std::to_string(p.tgid);
        row.cols.push_back(std::move(text));
        row.style = st;
        lpane_.push_back(std::move(row));
    }
}

/* ── rpane dispatch ───────────────────────────────────────────────── */

namespace {
bool is_heading_id(const std::string &id) {
    return id.size() >= 2 && id[0] == '_' && id[1] == '_';
}
} // namespace

void TvDataSource::rebuild_rpane() {
    rpane_.clear();
    const std::string &cid = state_.cursor_id;
    if (cid.empty()) {
        rpane_.push_back(mk_row("__empty", "(select a row)", RowStyle::Dim));
        return;
    }
    switch (state_.mode) {
        case 1:
        case 6:
        case 7:
            rpane_process_detail(cid);
            break;
        case 2:
        case 4:
        case 5:
            rpane_file_detail(cid);
            break;
        case 3:
            rpane_event_detail(cid);
            break;
        default:
            rpane_.push_back(mk_row("__stub",
                "(no detail for mode " + std::to_string(state_.mode) + ")",
                RowStyle::Dim));
    }
    if (rpane_.empty())
        rpane_.push_back(mk_row("__empty", "(no detail)", RowStyle::Dim));

    /* Apply section collapsing: remove rows that fall under a heading
     * whose id appears in collapsed_sections, until the next heading.
     * Collapsed headings get a "[+]" indicator; expanded ones get
     * "[-]" so the user can see what's collapsed. */
    if (!state_.collapsed_sections.empty()) {
        std::vector<RowData> out;
        out.reserve(rpane_.size());
        bool skip = false;
        for (auto &r : rpane_) {
            if (is_heading_id(r.id)) {
                bool col = std::find(state_.collapsed_sections.begin(),
                                     state_.collapsed_sections.end(),
                                     r.id) != state_.collapsed_sections.end();
                skip = col;
                if (col && !r.cols.empty()) {
                    /* annotate so the user sees the section is collapsed */
                    r.cols[0] = "▶ " + r.cols[0];
                } else if (!r.cols.empty() && r.style == RowStyle::Heading) {
                    r.cols[0] = "▼ " + r.cols[0];
                }
                out.push_back(std::move(r));
                continue;
            }
            if (!skip) out.push_back(std::move(r));
        }
        rpane_ = std::move(out);
    } else {
        for (auto &r : rpane_) {
            if (is_heading_id(r.id) && r.style == RowStyle::Heading &&
                !r.cols.empty())
                r.cols[0] = "▼ " + r.cols[0];
        }
    }
}

/* ── rpane: process detail ────────────────────────────────────────── */

void TvDataSource::rpane_process_detail(const std::string &tgid_s) {
    /* Validate tgid is numeric. */
    for (char c : tgid_s) if (c < '0' || c > '9') return;
    std::string err;
    if (!db_.ensure_proc_index(&err)) {
        rpane_.push_back(mk_row("__err", err, RowStyle::Error));
        return;
    }

    auto pr = db_.query_strings(
        "SELECT tgid, ppid, CAST(exe AS VARCHAR), "
        "       start_ns, end_ns, exit_kind, exit_code, core_dumped "
        "FROM tv_idx_proc WHERE tgid = " + tgid_s, &err);
    if (!err.empty()) { rpane_.push_back(mk_row("__err", err, RowStyle::Error)); return; }
    if (pr.empty()) {
        rpane_.push_back(mk_row("__none", "(no process " + tgid_s + ")",
                                RowStyle::Dim));
        return;
    }
    auto &p = pr.front();
    int64_t start_ns = p[3].empty() ? 0 : std::stoll(p[3]);
    int64_t end_ns   = p[4].empty() ? start_ns : std::stoll(p[4]);
    bool ended = !p[5].empty();

    rpane_.push_back(mk_row("__hp", "── Process ──", RowStyle::Heading));
    rpane_.push_back(mk_kv("tgid", "tgid", p[0]));
    rpane_.push_back(mk_kv("ppid", "ppid", p[1]));
    rpane_.push_back(mk_kv("exe",  "exe",  p[2]));
    rpane_.push_back(mk_kv("name", "name", basename_of(p[2])));
    rpane_.push_back(mk_kv("dur",  "duration", format_duration_ns(start_ns, end_ns)));
    rpane_.push_back(mk_kv("status", "status",
        format_exit(p[5], p[6], p[7], ended),
        ended ? (p[5] == "1" || (p[6] != "0" && !p[6].empty())
                 ? RowStyle::Error : RowStyle::Normal)
              : RowStyle::Green));

    /* argv */
    auto argv = db_.query_strings(
        "SELECT idx, CAST(arg AS VARCHAR) FROM argv WHERE tgid = " + tgid_s +
        " ORDER BY ts_ns DESC, idx ASC LIMIT 5000", &err);
    if (!argv.empty()) {
        rpane_.push_back(mk_row("__ha", "── argv ──", RowStyle::Heading));
        for (auto &a : argv) {
            rpane_.push_back(mk_kv("argv_" + a[0], "[" + a[0] + "]", a[1]));
        }
    }

    /* children */
    auto kids = db_.query_strings(
        "SELECT tgid, CAST(exe AS VARCHAR) FROM tv_idx_proc "
        "WHERE ppid = " + tgid_s + " ORDER BY start_ns LIMIT 5000", &err);
    if (!kids.empty()) {
        rpane_.push_back(mk_row("__hc",
            sfmt("── children (%zu) ──", kids.size()),
            RowStyle::Heading));
        for (auto &k : kids) {
            RowData rw = mk_kv("child_" + k[0], "[" + k[0] + "]",
                               basename_of(k[1]));
            rw.link_mode = 1;       /* mode 1: process tree */
            rw.link_id   = k[0];    /* tgid */
            rpane_.push_back(std::move(rw));
        }
    }

    /* opens — first 5000 with flags + err — using canonicalised paths
     * so the user sees the same path string the file view shows. */
    auto opens = db_.query_strings(
        "SELECT ts_ns, fd, err, flags, path "
        "FROM tv_idx_open_canon WHERE tgid = " + tgid_s +
        " ORDER BY ts_ns LIMIT 5000", &err);
    if (!opens.empty()) {
        rpane_.push_back(mk_row("__ho", sfmt("── opens (%zu) ──", opens.size()),
            RowStyle::Heading));
        size_t i = 0;
        for (auto &o : opens) {
            int err_ = std::atoi(o[2].c_str());
            int flags = std::atoi(o[3].c_str());
            std::string lhs = sfmt("fd %s [%s]%s", o[1].c_str(),
                                   flags_text(flags).c_str(),
                                   err_ ? sfmt(" err %d", err_).c_str() : "");
            RowData rw = mk_kv("open_" + std::to_string(i++), lhs, o[4],
                err_ ? RowStyle::Error : RowStyle::Normal);
            rw.link_mode = 2;       /* mode 2: file tree */
            rw.link_id   = o[4];    /* path */
            rpane_.push_back(std::move(rw));
        }
    }

    /* env (first 64) */
    auto env = db_.query_strings(
        "SELECT idx, CAST(key AS VARCHAR), CAST(val AS VARCHAR) "
        "FROM env WHERE tgid = " + tgid_s + " ORDER BY idx LIMIT 5000", &err);
    if (!env.empty()) {
        rpane_.push_back(mk_row("__he", sfmt("── env (%zu) ──", env.size()),
            RowStyle::Heading));
        for (auto &e : env)
            rpane_.push_back(mk_kv("env_" + e[0], e[1], e[2]));
    }
}

/* ── rpane: file detail ───────────────────────────────────────────── */

void TvDataSource::rpane_file_detail(const std::string &path) {
    std::string err;
    if (!db_.ensure_path_index(&err)) {
        rpane_.push_back(mk_row("__err", err, RowStyle::Error));
        return;
    }
    /* Synthetic directory rows from mode 2's tree view end with '/'.
     * Show an aggregate over everything under that prefix instead of
     * "(no path)". */
    bool is_dir = !path.empty() && path.back() == '/';
    std::string display_path = path;
    std::string where_clause;
    if (is_dir) {
        where_clause = "WHERE path LIKE " +
            sql_escape(path + "%");
    } else {
        where_clause = "WHERE path = " + sql_escape(path);
    }
    auto pr = db_.query_strings(
        "SELECT SUM(opens), SUM(errors), SUM(procs), "
        "       SUM(reads), SUM(writes), "
        "       MIN(first_ns), MAX(last_ns), COUNT(*) "
        "FROM tv_idx_path " + where_clause, &err);
    if (pr.empty() || pr.front()[7] == "0" || pr.front()[7].empty()) {
        rpane_.push_back(mk_row("__none", "(no path " + path + ")", RowStyle::Dim));
        return;
    }
    auto &r = pr.front();
    rpane_.push_back(mk_row("__hf",
        is_dir ? "── Directory ──" : "── File ──", RowStyle::Heading));
    rpane_.push_back(mk_kv("path", "path", display_path));
    if (is_dir)
        rpane_.push_back(mk_kv("count", "files", r[7]));
    rpane_.push_back(mk_kv("opens",  "opens",  r[0]));
    rpane_.push_back(mk_kv("errors", "errors", r[1],
        std::atoi(r[1].c_str()) ? RowStyle::Error : RowStyle::Normal));
    rpane_.push_back(mk_kv("procs",  "procs",  r[2]));
    rpane_.push_back(mk_kv("reads",  "reads",  r[3]));
    rpane_.push_back(mk_kv("writes", "writes", r[4],
        std::atoi(r[4].c_str()) ? RowStyle::Yellow : RowStyle::Normal));

    /* opens log: who, flags, err, using the canonicalised view. */
    std::string opens_where = is_dir
        ? "WHERE o.path LIKE " + sql_escape(path + "%")
        : "WHERE o.path = " + sql_escape(path);
    auto opens = db_.query_strings(
        "SELECT o.ts_ns, o.tgid, o.fd, o.err, o.flags, "
        "       CAST(p.exe AS VARCHAR), o.path "
        "FROM tv_idx_open_canon o "
        "LEFT JOIN tv_idx_proc p ON p.tgid = o.tgid "
        + opens_where +
        " ORDER BY o.ts_ns LIMIT 5000", &err);
    if (!opens.empty()) {
        rpane_.push_back(mk_row("__ho", sfmt("── opens (%zu) ──", opens.size()),
            RowStyle::Heading));
        size_t i = 0;
        for (auto &o : opens) {
            int err_ = std::atoi(o[3].c_str());
            int flags = std::atoi(o[4].c_str());
            std::string lhs = sfmt("[%s] %s", o[1].c_str(),
                                   basename_of(o[5]).c_str());
            std::string rhs = sfmt("fd %s [%s]%s%s%s", o[2].c_str(),
                                   flags_text(flags).c_str(),
                                   err_ ? sfmt(" err %d", err_).c_str() : "",
                                   is_dir ? "  " : "",
                                   is_dir ? o[6].c_str() : "");
            RowData rw = mk_kv("open_" + std::to_string(i++), lhs, rhs,
                               err_ ? RowStyle::Error : RowStyle::Normal);
            rw.link_mode = 1;       /* mode 1: process tree */
            rw.link_id   = o[1];    /* tgid */
            rpane_.push_back(std::move(rw));
        }
    }
}

/* ── rpane: event detail ──────────────────────────────────────────── */

void TvDataSource::rpane_event_detail(const std::string &id) {
    /* id format: "tgid:ts_ns" */
    auto colon = id.find(':');
    if (colon == std::string::npos) return;
    std::string tgid_s = id.substr(0, colon);
    std::string ts_s   = id.substr(colon + 1);
    for (char c : tgid_s) if (c < '0' || c > '9') return;
    for (char c : ts_s)   if (c < '0' || c > '9') return;

    rpane_.push_back(mk_row("__he", "── Event ──", RowStyle::Heading));
    rpane_.push_back(mk_kv("tgid", "tgid", tgid_s));
    rpane_.push_back(mk_kv("ts_ns", "ts_ns", ts_s));

    std::string err;
    /* Find which table it belongs to. */
    struct EvSrc { const char *kind; const char *table; const char *expr; };
    EvSrc srcs[] = {
        {"EXEC",   "exec",    "CAST(exe AS VARCHAR)"},
        {"CWD",    "cwd",     "CAST(cwd AS VARCHAR)"},
        {"OPEN",   "open_",   "CAST(path AS VARCHAR) || ' [fd ' || fd || ']'"},
        {"EXIT",   "exit_",   "CASE WHEN status_kind=1 THEN 'sig ' || code_or_sig ELSE 'code ' || code_or_sig END"},
        {"STDOUT", "stdout_", "CAST(data AS VARCHAR)"},
        {"STDERR", "stderr_", "CAST(data AS VARCHAR)"},
    };
    for (auto &s : srcs) {
        std::string sql = std::string("SELECT ") + s.expr +
            " FROM " + s.table + " WHERE tgid = " + tgid_s +
            " AND ts_ns = " + ts_s + " LIMIT 1";
        auto rs = db_.query_strings(sql, &err);
        if (!rs.empty()) {
            rpane_.push_back(mk_kv("kind", "kind", s.kind));
            rpane_.push_back(mk_kv("info", "info", rs.front()[0],
                (std::strcmp(s.kind, "STDERR") == 0 ||
                 std::strcmp(s.kind, "EXIT")   == 0)
                    ? RowStyle::Error : RowStyle::Normal));
            break;
        }
    }
    /* Always show the process this event belongs to. */
    auto pr = db_.query_strings(
        "SELECT CAST(exe AS VARCHAR) "
        "FROM tv_idx_proc WHERE tgid = " + tgid_s, &err);
    if (!pr.empty()) {
        rpane_.push_back(mk_row("__hp", "── Process ──", RowStyle::Heading));
        rpane_.push_back(mk_kv("name", "name", basename_of(pr.front()[0])));
        rpane_.push_back(mk_kv("exe",  "exe",  pr.front()[0]));
    }
}
