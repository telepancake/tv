/* tv_db.cpp - DuckDB-backed storage and query layer. */

#include "tv_db.h"
#include "wire_in.h"

#include "duckdb.h"

extern "C" {
#include "wire/wire.h"
}

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unordered_map>

namespace {

const char *const kSchemaSQL =
    "CREATE TABLE IF NOT EXISTS exec("
    "  ts_ns UBIGINT, pid INTEGER, tgid INTEGER, ppid INTEGER,"
    "  nspid INTEGER, nstgid INTEGER,"
    "  exe BLOB);"

    "CREATE TABLE IF NOT EXISTS argv("
    "  ts_ns UBIGINT, pid INTEGER, tgid INTEGER, ppid INTEGER,"
    "  nspid INTEGER, nstgid INTEGER,"
    "  idx UINTEGER, arg BLOB);"

    "CREATE TABLE IF NOT EXISTS env("
    "  ts_ns UBIGINT, pid INTEGER, tgid INTEGER, ppid INTEGER,"
    "  nspid INTEGER, nstgid INTEGER,"
    "  idx UINTEGER, key BLOB, val BLOB);"

    "CREATE TABLE IF NOT EXISTS auxv("
    "  ts_ns UBIGINT, pid INTEGER, tgid INTEGER, ppid INTEGER,"
    "  nspid INTEGER, nstgid INTEGER,"
    "  a_type UBIGINT, a_val UBIGINT);"

    "CREATE TABLE IF NOT EXISTS exit_("
    "  ts_ns UBIGINT, pid INTEGER, tgid INTEGER, ppid INTEGER,"
    "  nspid INTEGER, nstgid INTEGER,"
    "  status_kind TINYINT, code_or_sig INTEGER,"
    "  core_dumped BOOLEAN, raw INTEGER);"

    "CREATE TABLE IF NOT EXISTS open_("
    "  ts_ns UBIGINT, pid INTEGER, tgid INTEGER, ppid INTEGER,"
    "  nspid INTEGER, nstgid INTEGER,"
    "  flags INTEGER, fd INTEGER, ino UBIGINT,"
    "  dev_major UINTEGER, dev_minor UINTEGER, err INTEGER,"
    "  inherited BOOLEAN, path BLOB);"

    "CREATE TABLE IF NOT EXISTS cwd("
    "  ts_ns UBIGINT, pid INTEGER, tgid INTEGER, ppid INTEGER,"
    "  nspid INTEGER, nstgid INTEGER,"
    "  cwd BLOB);"

    "CREATE TABLE IF NOT EXISTS stdout_("
    "  ts_ns UBIGINT, pid INTEGER, tgid INTEGER, ppid INTEGER,"
    "  nspid INTEGER, nstgid INTEGER,"
    "  data BLOB);"

    "CREATE TABLE IF NOT EXISTS stderr_("
    "  ts_ns UBIGINT, pid INTEGER, tgid INTEGER, ppid INTEGER,"
    "  nspid INTEGER, nstgid INTEGER,"
    "  data BLOB);"

    /* Lazy index metadata. tv_meta records which derived tables have
     * been materialised for this .tvdb so subsequent opens reuse them. */
    "CREATE TABLE IF NOT EXISTS tv_meta("
    "  key VARCHAR PRIMARY KEY, value VARCHAR);";

/* exit/open/stdout/stderr collide with SQL keywords; tables use trailing
 * underscore. The data_source layer aliases them in queries. */
const char *table_for(int32_t type) {
    switch (type) {
        case EV_EXEC:   return "exec";
        case EV_ARGV:   return "argv";
        case EV_ENV:    return "env";
        case EV_AUXV:   return "auxv";
        case EV_EXIT:   return "exit_";
        case EV_OPEN:   return "open_";
        case EV_CWD:    return "cwd";
        case EV_STDOUT: return "stdout_";
        case EV_STDERR: return "stderr_";
        default:        return nullptr;
    }
}

void append_header(duckdb_appender ap, const WireEvent &ev) {
    duckdb_append_uint64(ap, ev.ts_ns);
    duckdb_append_int32(ap, ev.pid);
    duckdb_append_int32(ap, ev.tgid);
    duckdb_append_int32(ap, ev.ppid);
    duckdb_append_int32(ap, ev.nspid);
    duckdb_append_int32(ap, ev.nstgid);
}

/* Split NUL-separated blob into entries. A trailing NUL produces a
 * trailing empty entry which we drop (matches the kernel's terminating
 * NUL convention). Genuine empty entries in the middle are kept. */
std::vector<std::pair<const char*, size_t>>
split_nul(const char *data, size_t len) {
    std::vector<std::pair<const char*, size_t>> out;
    if (!data || len == 0) return out;
    const char *start = data;
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\0') {
            out.emplace_back(start, (size_t)(data + i - start));
            start = data + i + 1;
        }
    }
    if (start < data + len) {
        out.emplace_back(start, (size_t)(data + len - start));
    }
    if (!out.empty() && out.back().second == 0 && data[len - 1] == '\0') {
        out.pop_back();
    }
    return out;
}

} // namespace

struct TvDb::Impl {
    duckdb_database db = nullptr;
    duckdb_connection con = nullptr;
    std::string path_;
    /* One appender per table, lazily created on first append. */
    std::unordered_map<std::string, duckdb_appender> appenders;
    bool dirty = false;

    duckdb_appender get_appender(const char *table, std::string *err) {
        std::string key(table);
        auto it = appenders.find(key);
        if (it != appenders.end()) return it->second;
        duckdb_appender ap = nullptr;
        if (duckdb_appender_create(con, nullptr, table, &ap) != DuckDBSuccess) {
            if (err) {
                const char *e = duckdb_appender_error(ap);
                *err = std::string("appender create ") + table + ": " + (e ? e : "?");
            }
            if (ap) duckdb_appender_destroy(&ap);
            return nullptr;
        }
        appenders.emplace(key, ap);
        return ap;
    }

    bool flush(std::string *err) {
        for (auto &kv : appenders) {
            if (duckdb_appender_flush(kv.second) != DuckDBSuccess) {
                if (err) {
                    const char *e = duckdb_appender_error(kv.second);
                    *err = "appender flush " + kv.first + ": " + (e ? e : "?");
                }
                return false;
            }
        }
        if (dirty) {
            duckdb_result r;
            duckdb_state s = duckdb_query(con, "CHECKPOINT", &r);
            if (s != DuckDBSuccess) {
                if (err) {
                    const char *e = duckdb_result_error(&r);
                    *err = std::string("checkpoint: ") + (e ? e : "?");
                }
                duckdb_destroy_result(&r);
                return false;
            }
            duckdb_destroy_result(&r);
            dirty = false;
        }
        return true;
    }

    ~Impl() {
        for (auto &kv : appenders) {
            duckdb_appender_destroy(&kv.second);
        }
        if (con) duckdb_disconnect(&con);
        if (db) duckdb_close(&db);
    }
};

TvDb::TvDb() : impl_(std::make_unique<Impl>()) {}
TvDb::~TvDb() = default;

std::unique_ptr<TvDb> TvDb::open_with_path(const char *path,
                                           const std::string &display,
                                           std::string *err) {
    auto db = std::unique_ptr<TvDb>(new TvDb());
    if (duckdb_open(path, &db->impl_->db) != DuckDBSuccess) {
        if (err) *err = "duckdb_open(" + display + ") failed";
        return nullptr;
    }
    if (duckdb_connect(db->impl_->db, &db->impl_->con) != DuckDBSuccess) {
        if (err) *err = "duckdb_connect failed";
        return nullptr;
    }
    /* Memory-friendly defaults - let DuckDB spill to disk freely
     * instead of clinging to multi-GB result sets. preserve_insertion_order
     * lets the query planner stream large windowed/grouped queries
     * (the path-canonicalisation builder benefits a lot). */
    duckdb_result r0;
    (void)duckdb_query(db->impl_->con,
        "PRAGMA preserve_insertion_order=false;",
        &r0);
    duckdb_destroy_result(&r0);

    db->impl_->path_ = display;
    duckdb_result r;
    duckdb_state s = duckdb_query(db->impl_->con, kSchemaSQL, &r);
    if (s != DuckDBSuccess) {
        if (err) {
            const char *e = duckdb_result_error(&r);
            *err = std::string("schema: ") + (e ? e : "?");
        }
        duckdb_destroy_result(&r);
        return nullptr;
    }
    duckdb_destroy_result(&r);
    return db;
}

std::unique_ptr<TvDb> TvDb::open_file(const std::string &path,
                                      std::string *err) {
    return TvDb::open_with_path(path.c_str(), path, err);
}

std::unique_ptr<TvDb> TvDb::open_memory(std::string *err) {
    return TvDb::open_with_path(nullptr, ":memory:", err);
}

bool TvDb::append(const WireEvent &ev, std::string *err) {
    const char *t = table_for(ev.type);
    if (!t) {
        if (err) *err = "unknown event type " + std::to_string(ev.type);
        return false;
    }
    duckdb_appender ap = impl_->get_appender(t, err);
    if (!ap) return false;

    impl_->dirty = true;

    auto end_row = [&](duckdb_appender a) -> bool {
        if (duckdb_appender_end_row(a) != DuckDBSuccess) {
            if (err) {
                const char *e = duckdb_appender_error(a);
                *err = std::string("end_row ") + t + ": " + (e ? e : "?");
            }
            return false;
        }
        return true;
    };

    switch (ev.type) {
    case EV_EXEC:
        append_header(ap, ev);
        duckdb_append_blob(ap, ev.blob, ev.blen);
        return end_row(ap);

    case EV_ARGV: {
        auto parts = split_nul(ev.blob, ev.blen);
        if (parts.empty()) {
            /* Emit a single zero-arg row so the EXEC has a join key. */
            append_header(ap, ev);
            duckdb_append_uint32(ap, 0);
            duckdb_append_blob(ap, "", 0);
            return end_row(ap);
        }
        for (size_t i = 0; i < parts.size(); i++) {
            append_header(ap, ev);
            duckdb_append_uint32(ap, (uint32_t)i);
            duckdb_append_blob(ap, parts[i].first, parts[i].second);
            if (!end_row(ap)) return false;
        }
        return true;
    }

    case EV_ENV: {
        auto parts = split_nul(ev.blob, ev.blen);
        for (size_t i = 0; i < parts.size(); i++) {
            const char *p = parts[i].first;
            size_t n = parts[i].second;
            const char *eq = (const char *)std::memchr(p, '=', n);
            const char *key = p;
            size_t klen = eq ? (size_t)(eq - p) : n;
            const char *val = eq ? (eq + 1) : "";
            size_t vlen = eq ? (size_t)(p + n - (eq + 1)) : 0;
            append_header(ap, ev);
            duckdb_append_uint32(ap, (uint32_t)i);
            duckdb_append_blob(ap, key, klen);
            duckdb_append_blob(ap, val, vlen);
            if (!end_row(ap)) return false;
        }
        return true;
    }

    case EV_AUXV: {
        size_t pair_sz = sizeof(uint64_t) * 2;
        size_t n = ev.blen - (ev.blen % pair_sz);
        for (size_t off = 0; off < n; off += pair_sz) {
            uint64_t a_type, a_val;
            std::memcpy(&a_type, ev.blob + off, sizeof a_type);
            std::memcpy(&a_val, ev.blob + off + sizeof(uint64_t), sizeof a_val);
            if (a_type == 0) break;
            append_header(ap, ev);
            duckdb_append_uint64(ap, a_type);
            duckdb_append_uint64(ap, a_val);
            if (!end_row(ap)) return false;
        }
        return true;
    }

    case EV_EXIT:
        if (ev.n_extras < 4) { if (err) *err = "EV_EXIT extras"; return false; }
        append_header(ap, ev);
        duckdb_append_int8(ap, (int8_t)ev.extras[0]);
        duckdb_append_int32(ap, (int32_t)ev.extras[1]);
        duckdb_append_bool(ap, ev.extras[2] != 0);
        duckdb_append_int32(ap, (int32_t)ev.extras[3]);
        return end_row(ap);

    case EV_OPEN:
        if (ev.n_extras < 7) { if (err) *err = "EV_OPEN extras"; return false; }
        append_header(ap, ev);
        duckdb_append_int32(ap, (int32_t)ev.extras[0]);
        duckdb_append_int32(ap, (int32_t)ev.extras[1]);
        duckdb_append_uint64(ap, (uint64_t)ev.extras[2]);
        duckdb_append_uint32(ap, (uint32_t)ev.extras[3]);
        duckdb_append_uint32(ap, (uint32_t)ev.extras[4]);
        duckdb_append_int32(ap, (int32_t)ev.extras[5]);
        duckdb_append_bool(ap, ev.extras[6] != 0);
        duckdb_append_blob(ap, ev.blob, ev.blen);
        return end_row(ap);

    case EV_CWD:
    case EV_STDOUT:
    case EV_STDERR:
        append_header(ap, ev);
        duckdb_append_blob(ap, ev.blob, ev.blen);
        return end_row(ap);
    }
    if (err) *err = "unhandled event type " + std::to_string(ev.type);
    return false;
}

bool TvDb::flush(std::string *err) {
    return impl_->flush(err);
}

std::vector<int64_t> TvDb::query_int64(const std::string &sql,
                                       std::string *err) {
    std::vector<int64_t> out;
    /* Make sure pending appends are visible before querying. */
    if (!impl_->flush(err)) return out;
    duckdb_result r;
    if (duckdb_query(impl_->con, sql.c_str(), &r) != DuckDBSuccess) {
        if (err) {
            const char *e = duckdb_result_error(&r);
            *err = std::string("query: ") + (e ? e : "?") + " :: " + sql;
        }
        duckdb_destroy_result(&r);
        return out;
    }
    idx_t rows = duckdb_row_count(&r);
    out.reserve(rows);
    for (idx_t i = 0; i < rows; i++) {
        out.push_back(duckdb_value_int64(&r, 0, i));
    }
    duckdb_destroy_result(&r);
    return out;
}

std::vector<std::vector<std::string>>
TvDb::query_strings(const std::string &sql, std::string *err) {
    std::vector<std::vector<std::string>> out;
    if (!impl_->flush(err)) return out;
    duckdb_result r;
    if (duckdb_query(impl_->con, sql.c_str(), &r) != DuckDBSuccess) {
        if (err) {
            const char *e = duckdb_result_error(&r);
            *err = std::string("query: ") + (e ? e : "?") + " :: " + sql;
        }
        duckdb_destroy_result(&r);
        return out;
    }
    idx_t rows = duckdb_row_count(&r);
    idx_t cols = duckdb_column_count(&r);
    out.reserve(rows);
    for (idx_t i = 0; i < rows; i++) {
        std::vector<std::string> row;
        row.reserve(cols);
        for (idx_t c = 0; c < cols; c++) {
            char *v = duckdb_value_varchar(&r, c, i);
            row.emplace_back(v ? v : "");
            if (v) duckdb_free(v);
        }
        out.push_back(std::move(row));
    }
    duckdb_destroy_result(&r);
    return out;
}

int64_t TvDb::total_event_count() {
    std::string err;
    auto v = query_int64(
        "SELECT (SELECT COUNT(*) FROM exec) + (SELECT COUNT(*) FROM argv)"
        " + (SELECT COUNT(*) FROM env) + (SELECT COUNT(*) FROM auxv)"
        " + (SELECT COUNT(*) FROM exit_) + (SELECT COUNT(*) FROM open_)"
        " + (SELECT COUNT(*) FROM cwd) + (SELECT COUNT(*) FROM stdout_)"
        " + (SELECT COUNT(*) FROM stderr_)", &err);
    return v.empty() ? -1 : v[0];
}

/* -- Lazy index materialisation ---------------------------------------
 * Each ensure_*() runs CREATE TABLE AS SELECT once, then records its
 * existence in tv_meta. The check-and-build is gated by tv_meta so
 * subsequent opens of the same .tvdb reuse the materialised table. */

namespace {
bool meta_get(duckdb_connection con, const char *key, std::string &out) {
    std::string sql = std::string("SELECT value FROM tv_meta WHERE key='") +
                      key + "'";
    duckdb_result r;
    if (duckdb_query(con, sql.c_str(), &r) != DuckDBSuccess) {
        duckdb_destroy_result(&r);
        return false;
    }
    bool found = duckdb_row_count(&r) > 0;
    if (found) {
        char *v = duckdb_value_varchar(&r, 0, 0);
        out = v ? v : "";
        if (v) duckdb_free(v);
    }
    duckdb_destroy_result(&r);
    return found;
}

bool meta_set(duckdb_connection con, const char *key, const char *value,
              std::string *err) {
    std::string sql = std::string("INSERT OR REPLACE INTO tv_meta VALUES('") +
                      key + "','" + value + "')";
    duckdb_result r;
    if (duckdb_query(con, sql.c_str(), &r) != DuckDBSuccess) {
        if (err) {
            const char *e = duckdb_result_error(&r);
            *err = std::string("meta_set: ") + (e ? e : "?");
        }
        duckdb_destroy_result(&r);
        return false;
    }
    duckdb_destroy_result(&r);
    return true;
}

bool run_query(duckdb_connection con, const char *sql, std::string *err) {
    duckdb_result r;
    if (duckdb_query(con, sql, &r) != DuckDBSuccess) {
        if (err) {
            const char *e = duckdb_result_error(&r);
            *err = std::string("query: ") + (e ? e : "?") + " :: " + sql;
        }
        duckdb_destroy_result(&r);
        return false;
    }
    duckdb_destroy_result(&r);
    return true;
}
} // namespace

bool TvDb::ensure_proc_index(std::string *err) {
    if (!impl_->flush(err)) return false;
    std::string val;
    if (meta_get(impl_->con, "idx_proc", val)) return true;

    /* One row per tgid: ppid (last exec), exe (last exec), start_ns,
     * end_ns (exit if recorded, else last exec ts), exit info.
     * Avoid FIRST(... ORDER BY ...) and regex - neither is in the
     * vendored DuckDB amalgamation; use window functions and assume
     * one EXIT per tgid (true in practice). Basename of exe is computed
     * in C++ at view time. */
    const char *sql =
        "CREATE TABLE IF NOT EXISTS tv_idx_proc AS "
        "WITH e_ranked AS ("
        "  SELECT tgid, ppid, exe, ts_ns, "
        "         ROW_NUMBER() OVER (PARTITION BY tgid ORDER BY ts_ns DESC) AS rn"
        "  FROM exec"
        "), e_last AS ("
        "  SELECT tgid, ppid, exe FROM e_ranked WHERE rn = 1"
        "), p_span AS ("
        "  SELECT tgid, MIN(ts_ns) AS start_ns, MAX(ts_ns) AS exec_end_ns"
        "  FROM exec GROUP BY tgid"
        "), x_dedup AS ("
        "  SELECT tgid, status_kind AS exit_kind, code_or_sig AS exit_code,"
        "         core_dumped, ts_ns AS exit_ns,"
        "         ROW_NUMBER() OVER (PARTITION BY tgid ORDER BY ts_ns) AS rn"
        "  FROM exit_"
        "), x_first AS ("
        "  SELECT tgid, exit_kind, exit_code, core_dumped, exit_ns"
        "  FROM x_dedup WHERE rn = 1"
        ") "
        "SELECT e.tgid, e.ppid, e.exe, "
        "       p.start_ns AS start_ns, "
        "       COALESCE(x.exit_ns, p.exec_end_ns) AS end_ns, "
        "       x.exit_kind, x.exit_code, x.core_dumped "
        "FROM e_last e "
        "JOIN p_span p USING (tgid) "
        "LEFT JOIN x_first x USING (tgid)";
    if (!run_query(impl_->con, sql, err)) return false;
    if (!run_query(impl_->con,
                   "CREATE INDEX IF NOT EXISTS tv_idx_proc_tgid "
                   "ON tv_idx_proc(tgid)", err)) return false;
    if (!run_query(impl_->con,
                   "CREATE INDEX IF NOT EXISTS tv_idx_proc_ppid "
                   "ON tv_idx_proc(ppid)", err)) return false;
    if (!meta_set(impl_->con, "idx_proc", "1", err)) return false;
    impl_->dirty = true;
    return true;
}

bool TvDb::ensure_path_index(std::string *err) {
    if (!impl_->flush(err)) return false;
    std::string val;
    if (meta_get(impl_->con, "idx_path", val)) return true;

    /* Canonicalise relative open paths against the latest CWD for the
     * tgid that precedes the open's ts_ns. We *only* keep the
     * canonicalised path column (no raw_path duplicate); on large
     * traces (10^8 opens) raw_path was a 3-5 GB redundant copy of the
     * data already in `open_`. */
    const char *canon_sql =
        "CREATE TABLE IF NOT EXISTS tv_idx_open_canon AS "
        "WITH ranked AS ("
        "  SELECT o.ts_ns, o.tgid, o.fd, o.flags, o.err, "
        "         CAST(o.path AS VARCHAR) AS raw_path, "
        "         CAST(c.cwd AS VARCHAR)  AS cwd, "
        "         ROW_NUMBER() OVER ( "
        "           PARTITION BY o.ts_ns, o.tgid, o.fd, o.path "
        "           ORDER BY c.ts_ns DESC) AS rn "
        "  FROM open_ o "
        "  LEFT JOIN cwd c ON c.tgid = o.tgid AND c.ts_ns <= o.ts_ns "
        ") "
        "SELECT ts_ns, tgid, fd, flags, err, "
        "       CASE "
        "         WHEN raw_path LIKE '/%' THEN raw_path "
        "         WHEN cwd IS NULL OR raw_path LIKE 'pipe:%' "
        "              OR raw_path LIKE 'socket:%' OR raw_path LIKE 'anon_inode:%' "
        "           THEN raw_path "
        "         WHEN cwd = '/' THEN '/' || raw_path "
        "         ELSE cwd || '/' || raw_path "
        "       END AS path "
        "FROM ranked WHERE rn = 1";
    if (!run_query(impl_->con, canon_sql, err)) return false;
    if (!run_query(impl_->con,
                   "CREATE INDEX IF NOT EXISTS tv_idx_open_canon_path "
                   "ON tv_idx_open_canon(path)", err)) return false;
    if (!run_query(impl_->con,
                   "CREATE INDEX IF NOT EXISTS tv_idx_open_canon_tgid "
                   "ON tv_idx_open_canon(tgid)", err)) return false;

    /* Per-canonical-path stats; flags & 3 == 0  -> read-only open. */
    const char *sql =
        "CREATE TABLE IF NOT EXISTS tv_idx_path AS "
        "SELECT path, "
        "       COUNT(*) AS opens, "
        "       SUM(CASE WHEN err <> 0 THEN 1 ELSE 0 END) AS errors, "
        "       COUNT(DISTINCT tgid) AS procs, "
        "       SUM(CASE WHEN (flags & 3) = 0 THEN 1 ELSE 0 END) AS reads, "
        "       SUM(CASE WHEN (flags & 3) <> 0 THEN 1 ELSE 0 END) AS writes, "
        "       MIN(ts_ns) AS first_ns, MAX(ts_ns) AS last_ns "
        "FROM tv_idx_open_canon GROUP BY path";
    if (!run_query(impl_->con, sql, err)) return false;
    if (!run_query(impl_->con,
                   "CREATE INDEX IF NOT EXISTS tv_idx_path_path "
                   "ON tv_idx_path(path)", err)) return false;
    if (!meta_set(impl_->con, "idx_path", "1", err)) return false;
    impl_->dirty = true;
    return true;
}

bool TvDb::ensure_edge_index(std::string *err) {
    if (!impl_->flush(err)) return false;
    std::string val;
    if (meta_get(impl_->con, "idx_edge", val)) return true;

    /* The path index canonicalises relative paths against cwd; we
     * depend on it so that dep/rdep traversal doesn't get fragmented
     * by the same file appearing under multiple aliases. */
    if (!ensure_path_index(err)) return false;

    /* (tgid, path, mode) where mode = 0 read, 1 write. Successful opens
     * only - failures (err != 0) don't create dependencies. */
    const char *sql =
        "CREATE TABLE IF NOT EXISTS tv_idx_edge AS "
        "SELECT DISTINCT tgid, path, "
        "       CASE WHEN (flags % 4) = 0 THEN 0 ELSE 1 END AS mode "
        "FROM tv_idx_open_canon WHERE err = 0";
    if (!run_query(impl_->con, sql, err)) return false;
    if (!run_query(impl_->con,
                   "CREATE INDEX IF NOT EXISTS tv_idx_edge_path "
                   "ON tv_idx_edge(path)", err)) return false;
    if (!run_query(impl_->con,
                   "CREATE INDEX IF NOT EXISTS tv_idx_edge_tgid "
                   "ON tv_idx_edge(tgid)", err)) return false;
    if (!meta_set(impl_->con, "idx_edge", "1", err)) return false;
    impl_->dirty = true;
    return true;
}

const std::string &TvDb::path() const { return impl_->path_; }
void *TvDb::raw_conn() { return impl_->con; }
