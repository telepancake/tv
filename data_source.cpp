/* data_source.cpp — implements data_source.h. */

#include "data_source.h"
#include "tv_db.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace {

std::string sfmt_dur(int64_t start_ns, int64_t end_ns) {
    double s = (end_ns >= start_ns ? (end_ns - start_ns) : 0) / 1e9;
    char buf[32];
    if (s < 1.0)        std::snprintf(buf, sizeof buf, "%4.0f ms", s * 1000);
    else if (s < 60.0)  std::snprintf(buf, sizeof buf, "%5.2f s", s);
    else if (s < 3600)  std::snprintf(buf, sizeof buf, "%4.1f m", s / 60);
    else                std::snprintf(buf, sizeof buf, "%4.1f h", s / 3600);
    return buf;
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

RowData make_stub_row(const char *id, const std::string &text, RowStyle style) {
    RowData r;
    r.id = id;
    r.style = style;
    r.cols.push_back(text);
    return r;
}

RowData make_error_row(const std::string &msg) {
    return make_stub_row("__err", "(error) " + msg, RowStyle::Error);
}

} // namespace

TvDataSource::TvDataSource(TvDb &db, AppState &state)
    : db_(db), state_(state) {}

DataSource TvDataSource::make_data_source() {
    DataSource s;
    s.row_begin    = [this](int p)         { row_begin(p); };
    s.row_has_more = [this](int p)         { return row_has_more(p); };
    s.row_next     = [this](int p)         { return row_next(p); };
    return s;
}

void TvDataSource::invalidate() {
    built_lpane_ = false;
    built_rpane_ = false;
}

void TvDataSource::row_begin(int panel) {
    if (panel == 0) {
        if (!built_lpane_ || built_for_mode_ != state_.mode) {
            rebuild_lpane();
            built_for_mode_ = state_.mode;
            built_lpane_ = true;
        }
        lpane_idx_ = 0;
    } else {
        if (!built_rpane_ || built_for_cursor_ != state_.cursor_id) {
            rebuild_rpane();
            built_for_cursor_ = state_.cursor_id;
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

/* ── lpane: process tree (flat order by start_ns) ─────────────────── */

void TvDataSource::rebuild_lpane() {
    lpane_.clear();
    if (state_.mode != 1) {
        lpane_.push_back(make_stub_row(
            "__stub",
            std::string("(mode ") + std::to_string(state_.mode) +
                ": not yet ported to SQL backend; press 1 for processes)",
            RowStyle::Dim));
        return;
    }

    std::string err;

    /* One row per process. exit_ may be missing (still running);
     * end_ns falls back to MAX(exec.ts_ns) for that case. */
    std::string sql =
        "SELECT p.tgid, ANY_VALUE(p.ppid) AS ppid, "
        "       MIN(p.ts_ns) AS start_ns, "
        "       COALESCE((SELECT MIN(x.ts_ns) FROM exit_ x WHERE x.tgid = p.tgid), "
        "                MAX(p.ts_ns)) AS end_ns, "
        "       (SELECT exe FROM exec e WHERE e.tgid = p.tgid "
        "         ORDER BY ts_ns DESC LIMIT 1) AS exe, "
        "       (SELECT status_kind FROM exit_ x WHERE x.tgid = p.tgid LIMIT 1) AS sk, "
        "       (SELECT code_or_sig FROM exit_ x WHERE x.tgid = p.tgid LIMIT 1) AS code "
        "FROM exec p ";
    if (!state_.search.empty()) {
        sql +=
            "WHERE EXISTS ("
            "  SELECT 1 FROM exec e2 WHERE e2.tgid = p.tgid AND e2.exe LIKE '%' || "
            + sql_escape(state_.search) + " || '%') ";
    }
    sql += "GROUP BY p.tgid ORDER BY start_ns";

    auto rows = db_.query_strings(sql, &err);
    if (!err.empty()) { lpane_.push_back(make_error_row(err)); return; }

    if (rows.empty()) {
        lpane_.push_back(make_stub_row("__empty",
            "(no processes recorded)", RowStyle::Dim));
        return;
    }

    for (auto &r : rows) {
        const std::string &tgid_s = r[0];
        const std::string &ppid_s = r[1];
        int64_t start_ns = r[2].empty() ? 0 : std::stoll(r[2]);
        int64_t end_ns   = r[3].empty() ? start_ns : std::stoll(r[3]);
        const std::string &exe = r[4];
        const std::string &sk = r[5];
        const std::string &code = r[6];

        RowData row;
        row.id = tgid_s;
        row.parent_id = ppid_s;
        row.has_children = false;
        row.cols.push_back(tgid_s);
        row.cols.push_back(sfmt_dur(start_ns, end_ns));
        row.cols.push_back(exe);

        std::string st;
        if (!sk.empty()) {
            int kind = std::atoi(sk.c_str());
            int c = std::atoi(code.c_str());
            if (kind == 1) {
                char b[32]; std::snprintf(b, sizeof b, "sig %d", c);
                st = b;
                row.style = RowStyle::Error;
            } else if (c != 0) {
                char b[32]; std::snprintf(b, sizeof b, "exit %d", c);
                st = b;
                row.style = RowStyle::Error;
            } else {
                st = "ok";
            }
        } else {
            st = "running";
            row.style = RowStyle::Green;
        }
        row.cols.push_back(st);
        lpane_.push_back(std::move(row));
    }
}

/* ── rpane: process detail ─────────────────────────────────────────── */

std::vector<std::vector<std::string>>
TvDataSource::rpane_process(const std::string &cursor_id, std::string *err) {
    if (cursor_id.empty()) return {};
    /* Validate cursor_id is a number (it's a tgid). */
    for (char c : cursor_id) if (c < '0' || c > '9') return {};
    std::string base =
        "SELECT p.tgid, p.ppid, p.exe, p.ts_ns, "
        "       (SELECT status_kind FROM exit_ x WHERE x.tgid = p.tgid LIMIT 1), "
        "       (SELECT code_or_sig FROM exit_ x WHERE x.tgid = p.tgid LIMIT 1), "
        "       (SELECT ts_ns FROM exit_ x WHERE x.tgid = p.tgid ORDER BY ts_ns LIMIT 1) "
        "FROM exec p WHERE p.tgid = " + cursor_id +
        " ORDER BY ts_ns DESC LIMIT 1";
    return db_.query_strings(base, err);
}

void TvDataSource::rebuild_rpane() {
    rpane_.clear();
    const std::string &cid = state_.cursor_id;
    if (cid.empty()) {
        rpane_.push_back(make_stub_row("__empty",
            "(select a process)", RowStyle::Dim));
        return;
    }
    if (state_.mode != 1) {
        rpane_.push_back(make_stub_row("__stub",
            "(detail not yet ported for this mode)", RowStyle::Dim));
        return;
    }
    std::string err;
    auto pr = rpane_process(cid, &err);
    if (!err.empty()) { rpane_.push_back(make_error_row(err)); return; }
    if (pr.empty()) {
        rpane_.push_back(make_stub_row("__none",
            "(no process " + cid + ")", RowStyle::Dim));
        return;
    }
    auto &p = pr.front();

    auto add = [&](const char *id, const std::string &k, const std::string &v,
                   RowStyle s = RowStyle::Normal) {
        RowData r;
        r.id = id;
        r.style = s;
        r.cols.push_back(k);
        r.cols.push_back(v);
        rpane_.push_back(std::move(r));
    };

    add("tgid", "tgid", p[0]);
    add("ppid", "ppid", p[1]);
    add("exe",  "exe",  p[2]);
    add("start_ns", "start_ns", p[3]);
    add("exit_kind", "exit_kind", p[4]);
    add("exit_code", "exit_code", p[5]);
    add("exit_ns", "exit_ns", p[6]);

    /* argv as sub-rows. */
    auto argv = db_.query_strings(
        "SELECT idx, arg FROM argv WHERE tgid = " + cid +
        " ORDER BY ts_ns DESC, idx ASC LIMIT 256", &err);
    if (!err.empty()) {
        rpane_.push_back(make_error_row(err));
    } else if (!argv.empty()) {
        rpane_.push_back(make_stub_row("__argv_h", "── argv ──", RowStyle::Heading));
        for (auto &a : argv) {
            char id[32]; std::snprintf(id, sizeof id, "argv_%s", a[0].c_str());
            add(id, "[" + a[0] + "]", a[1]);
        }
    }

    /* opens — first 50, ordered by ts. */
    auto opens = db_.query_strings(
        "SELECT ts_ns, fd, err, path FROM open_ WHERE tgid = " + cid +
        " ORDER BY ts_ns LIMIT 50", &err);
    if (!err.empty()) {
        rpane_.push_back(make_error_row(err));
    } else if (!opens.empty()) {
        rpane_.push_back(make_stub_row("__open_h", "── opens (first 50) ──",
                                       RowStyle::Heading));
        size_t i = 0;
        for (auto &o : opens) {
            char id[32]; std::snprintf(id, sizeof id, "open_%zu", i++);
            std::string lhs = "fd " + o[1] + (o[2] == "0" ? "" : (" err " + o[2]));
            add(id, lhs, o[3], o[2] != "0" ? RowStyle::Error : RowStyle::Normal);
        }
    }
}
