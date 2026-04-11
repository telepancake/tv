/*
 * main.c — Process trace viewer: business logic + entry point.
 *
 * This file contains:
 *   • SQLite database management (open, schema, queries)
 *   • SQL custom functions (regexp, canon_path, dir_part, depth)
 *   • Trace event processing (JSONL → DB)
 *   • UI rebuild logic (lpane/rpane population)
 *   • Key dispatch (all application-specific key bindings)
 *   • Event loop (poll on tty_fd + optional trace_fd)
 *   • Headless dump functions
 *   • argv parsing and uproctrace integration
 *
 * The generic TUI engine (engine.c) provides only terminal management,
 * rendering, key reading, and line editing.  This file drives everything.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>

#include "engine.h"
#include "tv_sql.h"

/* ── DB helper functions (app-side) ────────────────────────────────── */
static sqlite3 *g_db;

static void xexec(const char *sql) {
    char *e;
    if (sqlite3_exec(g_db, sql, 0, 0, &e) != SQLITE_OK) {
        fprintf(stderr, "sql: %s\n%.300s\n", e, sql);
        sqlite3_free(e);
        exit(1);
    }
}

static void xexecf(const char *fmt, ...) {
    char b[16384];
    va_list a;
    va_start(a, fmt);
    vsnprintf(b, sizeof b, fmt, a);
    va_end(a);
    xexec(b);
}

static int qint(const char *sql, int def) {
    sqlite3_stmt *s;
    int r = def;
    if (sqlite3_prepare_v2(g_db, sql, -1, &s, 0) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) r = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
    }
    return r;
}

static int qintf(int def, const char *fmt, ...) {
    va_list a;
    va_start(a, fmt);
    char *sql = sqlite3_vmprintf(fmt, a);
    va_end(a);
    if (!sql) return def;
    int r = qint(sql, def);
    sqlite3_free(sql);
    return r;
}

static double qdbl(const char *sql, double def) {
    sqlite3_stmt *s;
    double r = def;
    if (sqlite3_prepare_v2(g_db, sql, -1, &s, 0) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) r = sqlite3_column_double(s, 0);
        sqlite3_finalize(s);
    }
    return r;
}

/* ── SQL custom functions ──────────────────────────────────────────── */

static void sql_regexp(sqlite3_context *ctx, int n, sqlite3_value **v) {
    (void)n;
    const char *pat = (const char *)sqlite3_value_text(v[0]);
    const char *str = (const char *)sqlite3_value_text(v[1]);
    if (!pat || !str) { sqlite3_result_int(ctx, 0); return; }
    sqlite3_result_int(ctx, strstr(str, pat) != NULL);
}

static void canon_path_c(char *path, int maxlen) {
    if (!path || !path[0]) return;
    char *parts[256]; int np = 0;
    char tmp[4096]; snprintf(tmp, sizeof tmp, "%s", path);
    int ab = (tmp[0] == '/'); char *s = tmp; if (ab) s++;
    while (*s && np < 256) {
        char *sl = strchr(s, '/'); if (sl) *sl = 0;
        if (strcmp(s, "..") == 0) { if (np > 0) np--; }
        else if (strcmp(s, ".") != 0 && *s) parts[np++] = s;
        if (sl) s = sl + 1; else break;
    }
    char out[4096]; int p = 0;
    if (ab && p < (int)sizeof(out) - 1) out[p++] = '/';
    for (int i = 0; i < np; i++) {
        if (i > 0 && p < (int)sizeof(out) - 1) out[p++] = '/';
        int l = strlen(parts[i]);
        if (p + l >= (int)sizeof(out)) l = (int)sizeof(out) - p - 1;
        memcpy(out + p, parts[i], l); p += l;
    }
    out[p] = 0;
    snprintf(path, maxlen, "%s", out);
}

static void sql_canon_path(sqlite3_context *ctx, int n, sqlite3_value **v) {
    (void)n;
    const char *in = (const char *)sqlite3_value_text(v[0]);
    if (!in) { sqlite3_result_null(ctx); return; }
    char out[4096]; snprintf(out, sizeof out, "%s", in);
    canon_path_c(out, sizeof out);
    sqlite3_result_text(ctx, out, -1, SQLITE_TRANSIENT);
}

static void sql_dir_part(sqlite3_context *ctx, int n, sqlite3_value **v) {
    (void)n;
    const char *in = (const char *)sqlite3_value_text(v[0]);
    if (!in) { sqlite3_result_null(ctx); return; }
    const char *last = strrchr(in, '/');
    if (!last || last == in) { sqlite3_result_text(ctx, last ? "/" : "", last ? 1 : 0, SQLITE_TRANSIENT); return; }
    sqlite3_result_text(ctx, in, (int)(last - in), SQLITE_TRANSIENT);
}

static void sql_depth(sqlite3_context *ctx, int n, sqlite3_value **v) {
    (void)n;
    const char *in = (const char *)sqlite3_value_text(v[0]);
    if (!in) { sqlite3_result_int(ctx, 0); return; }
    int d = 0; for (const char *p = in; *p; p++) if (*p == '/') d++;
    sqlite3_result_int(ctx, d);
}

static void register_sql_funcs(sqlite3 *db) {
    sqlite3_create_function(db, "regexp",     2, SQLITE_UTF8, 0, sql_regexp,     0, 0);
    sqlite3_create_function(db, "canon_path", 1, SQLITE_UTF8, 0, sql_canon_path, 0, 0);
    sqlite3_create_function(db, "dir_part",   1, SQLITE_UTF8, 0, sql_dir_part,   0, 0);
    sqlite3_create_function(db, "depth",      1, SQLITE_UTF8, 0, sql_depth,      0, 0);
}

/* ── Macros for SQL building ───────────────────────────────────────── */
#define BNAME(c) "REPLACE("c",RTRIM("c",REPLACE("c",'/','')),'') "
#define DUR(d) "CASE WHEN "d">=1 THEN printf('%%.2fs',"d") WHEN "d">=.001 THEN printf('%%.1fms',("d")*1e3) WHEN "d">0 THEN printf('%%.0fµs',("d")*1e6) ELSE '' END"

/* ── Forward declarations ──────────────────────────────────────────── */
static int handle_key(tui_t *tui, int k);
static void do_search(const char *q);
static void build_file_tree(void);
static void jump_hit(int dir);
static void follow_link(tui_t *tui);

/* ── Global TUI handle (set after tui_open) ────────────────────────── */
static tui_t *g_tui;

/* ── Sync engine cursor ↔ state table ──────────────────────────────── */
static void sync_cursor_to_state(void) {
    if (!g_tui) return;
    int lc = tui_get_cursor(g_tui, "lpane");
    const char *lcid = tui_get_cursor_id(g_tui, "lpane");
    int rc = tui_get_cursor(g_tui, "rpane");
    if (lc < 0) lc = 0;
    if (rc < 0) rc = 0;
    if (lcid && lcid[0]) {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(g_db, "UPDATE state SET cursor=?, cursor_id=?, dcursor=?",
                           -1, &st, 0);
        sqlite3_bind_int(st, 1, lc);
        sqlite3_bind_text(st, 2, lcid, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, rc);
        sqlite3_step(st); sqlite3_finalize(st);
    } else {
        xexecf("UPDATE state SET cursor=%d, dcursor=%d", lc, rc);
    }
}

static void sync_cursor_from_state(void) {
    if (!g_tui) return;
    int lc = qint("SELECT cursor FROM state", 0);
    int rc = qint("SELECT dcursor FROM state", 0);
    tui_set_cursor_idx(g_tui, "lpane", lc);
    tui_set_cursor_idx(g_tui, "rpane", rc);
}

static void sync_focus_to_state(void) {
    if (!g_tui) return;
    const char *f = tui_get_focus(g_tui);
    xexecf("UPDATE state SET focus=%d", (f && strcmp(f, "rpane") == 0) ? 1 : 0);
}

static void sync_focus_from_state(void) {
    if (!g_tui) return;
    int f = qint("SELECT focus FROM state", 0);
    tui_focus(g_tui, f ? "rpane" : "lpane");
}

/* ── Status bar update ─────────────────────────────────────────────── */
static void update_status(void) {
    int mode = qint("SELECT mode FROM state", 0);
    int nf = qint("SELECT COUNT(*) FROM lpane", 0);
    int cursor = g_tui ? tui_get_cursor(g_tui, "lpane") : qint("SELECT cursor FROM state", 0);
    if (cursor < 0) cursor = 0;
    const char *mn[] = {"PROCS","FILES","OUTPUT","DEPS","RDEPS","DEP-CMDS","RDEP-CMDS"};
    const char *tsl[] = {"abs","rel","Δ"};
    int tsm = qint("SELECT ts_mode FROM state", 0);
    int gr = qint("SELECT grouped FROM state", 1);
    int lpf = qint("SELECT lp_filter FROM state", 0);

    char s[512]; int p = 0;
    p += snprintf(s + p, sizeof s - p, " %s%s | %d/%d",
                  mode < 7 ? mn[mode] : "?", gr ? " tree" : "", cursor + 1, nf);
    p += snprintf(s + p, sizeof s - p, " | TS:%s", tsm < 3 ? tsl[tsm] : "?");

    {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(g_db, "SELECT evfilt,search FROM state", -1, &st, 0);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *ef = (const char *)sqlite3_column_text(st, 0);
            const char *sq = (const char *)sqlite3_column_text(st, 1);
            if (ef && ef[0]) p += snprintf(s + p, sizeof s - p, " | F:%s", ef);
            if (sq && sq[0]) p += snprintf(s + p, sizeof s - p, " | /%s[%d]",
                sq, qint("SELECT COUNT(*) FROM search_hits", 0));
        }
        sqlite3_finalize(st);
    }
    if (lpf == 1) p += snprintf(s + p, sizeof s - p, " | V:failed");
    else if (lpf == 2) p += snprintf(s + p, sizeof s - p, " | V:running");

    { int df = qint("SELECT dep_filter FROM state", 0);
      if (mode >= 3 && mode <= 6) p += snprintf(s + p, sizeof s - p, " | D:%s", df ? "written" : "all"); }

    p += snprintf(s + p, sizeof s - p, " | 1:proc 2:file 3:out 4:dep 5:rdep 6:dcmd 7:rcmd ?:help");
    (void)p;

    if (g_tui)
        tui_set_status(g_tui, s);
}

/* ── FTS setup ─────────────────────────────────────────────────────── */
static void setup_fts(void) {
    char *e = 0;
    if (sqlite3_exec(g_db, tv_sql_fts, 0, 0, &e) == SQLITE_OK) {
        /* OK */
    } else {
        sqlite3_free(e);
    }
}

/* ── Ingest helpers ────────────────────────────────────────────────── */
static void ingest_line(const char *ln) {
    if (!ln || !ln[0] || ln[0] != '{') return;
    const char *kind = strstr(ln, "\"input\"") ? "input" : "trace";
    sqlite3_stmt *st;
    sqlite3_prepare_v2(g_db, "INSERT INTO inbox(kind,data) VALUES(?,?)", -1, &st, 0);
    sqlite3_bind_text(st, 1, kind, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, ln, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

static void ingest_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "tv: cannot open %s\n", path); exit(1); }
    char line[1 << 20];
    xexec("BEGIN");
    while (fgets(line, sizeof line, f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        if (nl > line && *(nl - 1) == '\r') *(nl - 1) = 0;
        ingest_line(line);
    }
    xexec("COMMIT");
    fclose(f);
}

/* ── Process one JSONL line from the trace ─────────────────────────── */
static int g_own_tgid;

static void process_trace_event(const char *ln) {
    if (!ln || ln[0] != '{') return;

    char ev[32] = ""; int tgid = 0;
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db,
          "SELECT COALESCE(json_extract(?1,'$.event'),''),"
          " COALESCE(CAST(json_extract(?1,'$.tgid')AS INT),0)",
          -1, &st, 0);
      sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
      if (sqlite3_step(st) == SQLITE_ROW) {
          const char *e = (const char *)sqlite3_column_text(st, 0);
          if (e) snprintf(ev, sizeof ev, "%s", e);
          tgid = sqlite3_column_int(st, 1);
      }
      sqlite3_finalize(st);
    }
    if (!ev[0] || !tgid || tgid == g_own_tgid) return;

    /* Ensure process stub */
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db,
          "INSERT OR IGNORE INTO processes(tgid,pid,ppid,nspid,nstgid,first_ts,last_ts)"
          " VALUES(json_extract(?1,'$.tgid'),json_extract(?1,'$.pid'),json_extract(?1,'$.ppid'),"
          "  json_extract(?1,'$.nspid'),json_extract(?1,'$.nstgid'),"
          "  json_extract(?1,'$.ts'),json_extract(?1,'$.ts'))",
          -1, &st, 0);
      sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
      sqlite3_step(st); sqlite3_finalize(st);
    }
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db,
          "INSERT OR IGNORE INTO expanded(id,ex) VALUES(CAST(json_extract(?1,'$.tgid')AS TEXT),1)",
          -1, &st, 0);
      sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
      sqlite3_step(st); sqlite3_finalize(st);
    }

    if (strcmp(ev, "CWD") == 0) {
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "INSERT OR REPLACE INTO cwd_cache(tgid,cwd)"
              " VALUES(CAST(json_extract(?1,'$.tgid')AS INT),json_extract(?1,'$.path'))",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "UPDATE processes SET cwd=json_extract(?1,'$.path')"
              " WHERE tgid=CAST(json_extract(?1,'$.tgid')AS INT)",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        return;
    }

    if (strcmp(ev, "EXEC") == 0) {
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "UPDATE processes SET"
              " exe=json_extract(?1,'$.exe'),"
              " argv=CASE WHEN json_type(?1,'$.argv')='array' THEN"
              "  (SELECT GROUP_CONCAT(value,char(10)) FROM json_each(json_extract(?1,'$.argv')))"
              "  ELSE NULL END,"
              " env=CASE WHEN json_type(?1,'$.env')='object' THEN"
              "  (SELECT GROUP_CONCAT(key||'='||value,char(10)) FROM json_each(json_extract(?1,'$.env')))"
              "  ELSE NULL END,"
              " auxv=CASE WHEN json_type(?1,'$.auxv')='object' THEN"
              "  (SELECT GROUP_CONCAT(key||'='||value,char(10)) FROM json_each(json_extract(?1,'$.auxv')))"
              "  ELSE NULL END,"
              " first_ts=MIN(first_ts,json_extract(?1,'$.ts')),"
              " last_ts=MAX(last_ts,json_extract(?1,'$.ts'))"
              " WHERE tgid=CAST(json_extract(?1,'$.tgid')AS INT)",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "INSERT INTO events(tgid,ts,event)"
              " VALUES(json_extract(?1,'$.tgid'),json_extract(?1,'$.ts'),'EXEC')",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        return;
    }

    if (strcmp(ev, "OPEN") == 0) {
        char path[8192] = ""; char flag0[32] = "O_RDONLY";
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "SELECT COALESCE(json_extract(?1,'$.path'),''),"
              " COALESCE(json_extract(?1,'$.flags[0]'),'O_RDONLY')",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          if (sqlite3_step(st) == SQLITE_ROW) {
              const char *p = (const char *)sqlite3_column_text(st, 0);
              if (p) snprintf(path, sizeof path, "%s", p);
              const char *f = (const char *)sqlite3_column_text(st, 1);
              if (f) snprintf(flag0, sizeof flag0, "%s", f);
          }
          sqlite3_finalize(st);
        }

        { int is_pseudo = (path[0] && !strchr("/.", path[0]) && strchr(path, ':') != NULL);
          if (!is_pseudo && path[0] && path[0] != '/') {
              char cwd[4096] = "";
              { sqlite3_stmt *st;
                sqlite3_prepare_v2(g_db, "SELECT COALESCE(cwd,'') FROM cwd_cache WHERE tgid=?", -1, &st, 0);
                sqlite3_bind_int(st, 1, tgid);
                if (sqlite3_step(st) == SQLITE_ROW) {
                    const char *c = (const char *)sqlite3_column_text(st, 0);
                    if (c && c[0]) snprintf(cwd, sizeof cwd, "%s", c);
                }
                sqlite3_finalize(st);
              }
              if (cwd[0]) { char abs[8192]; snprintf(abs, sizeof abs, "%s/%s", cwd, path); snprintf(path, 8192, "%s", abs); }
          }
          if (!is_pseudo && path[0] == '/') canon_path_c(path, sizeof path);
        }

        if (strcmp(flag0, "O_RDONLY") == 0 && path[0] == '/') {
            static const char *sys[] = {"/usr/","/lib/","/lib64/","/bin/","/sbin/","/opt/","/srv/",NULL};
            for (int i = 0; sys[i]; i++) if (strncmp(path, sys[i], strlen(sys[i])) == 0) return;
        }

        long long eid;
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "INSERT INTO events(tgid,ts,event)"
              " VALUES(json_extract(?1,'$.tgid'),json_extract(?1,'$.ts'),'OPEN')",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        eid = sqlite3_last_insert_rowid(g_db);

        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "INSERT INTO open_events(eid,path,flags,fd,err) VALUES(?1,?2,"
              " CASE WHEN json_type(?3,'$.flags')='array' THEN"
              "  (SELECT GROUP_CONCAT(value,'|') FROM json_each(json_extract(?3,'$.flags')))"
              "  ELSE NULL END,"
              " json_extract(?3,'$.fd'),json_extract(?3,'$.err'))",
              -1, &st, 0);
          sqlite3_bind_int64(st, 1, eid);
          sqlite3_bind_text(st, 2, path, -1, SQLITE_TRANSIENT);
          sqlite3_bind_text(st, 3, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }

        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "UPDATE processes SET"
              " last_ts=MAX(last_ts,json_extract(?1,'$.ts')),"
              " first_ts=MIN(first_ts,json_extract(?1,'$.ts'))"
              " WHERE tgid=CAST(json_extract(?1,'$.tgid')AS INT)",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        return;
    }

    if (strcmp(ev, "EXIT") == 0) {
        long long eid;
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "INSERT INTO events(tgid,ts,event)"
              " VALUES(json_extract(?1,'$.tgid'),json_extract(?1,'$.ts'),'EXIT')",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        eid = sqlite3_last_insert_rowid(g_db);
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "INSERT INTO exit_events(eid,status,code,signal,core_dumped,raw)"
              " VALUES(?1,json_extract(?2,'$.status'),json_extract(?2,'$.code'),"
              "  json_extract(?2,'$.signal'),json_extract(?2,'$.core_dumped'),json_extract(?2,'$.raw'))",
              -1, &st, 0);
          sqlite3_bind_int64(st, 1, eid);
          sqlite3_bind_text(st, 2, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "UPDATE processes SET last_ts=MAX(last_ts,json_extract(?1,'$.ts'))"
              " WHERE tgid=CAST(json_extract(?1,'$.tgid')AS INT)",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        return;
    }

    if (strcmp(ev, "STDOUT") == 0 || strcmp(ev, "STDERR") == 0) {
        long long eid;
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "INSERT INTO events(tgid,ts,event)"
              " VALUES(json_extract(?1,'$.tgid'),json_extract(?1,'$.ts'),?2)",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          sqlite3_bind_text(st, 2, ev, -1, SQLITE_STATIC);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        eid = sqlite3_last_insert_rowid(g_db);
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "INSERT INTO io_events(eid,stream,len,data)"
              " VALUES(?1,?2,json_extract(?3,'$.len'),json_extract(?3,'$.data'))",
              -1, &st, 0);
          sqlite3_bind_int64(st, 1, eid);
          sqlite3_bind_text(st, 2, ev, -1, SQLITE_STATIC);
          sqlite3_bind_text(st, 3, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "UPDATE processes SET last_ts=MAX(last_ts,json_extract(?1,'$.ts'))"
              " WHERE tgid=CAST(json_extract(?1,'$.tgid')AS INT)",
              -1, &st, 0);
          sqlite3_bind_text(st, 1, ln, -1, SQLITE_TRANSIENT);
          sqlite3_step(st); sqlite3_finalize(st);
        }
        return;
    }
}

/* ── Process inbox ─────────────────────────────────────────────────── */
static void process_inbox_trace(void) {
    static char buf[1 << 20];
    xexec("BEGIN");
    for (;;) {
        long long id = -1; buf[0] = 0;
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db, "SELECT id,data FROM inbox WHERE kind='trace' ORDER BY id LIMIT 1", -1, &st, 0);
          if (sqlite3_step(st) == SQLITE_ROW) {
              id = sqlite3_column_int64(st, 0);
              const char *d = (const char *)sqlite3_column_text(st, 1);
              if (d) snprintf(buf, sizeof buf - 1, "%s", d);
          }
          sqlite3_finalize(st);
        }
        if (id < 0) break;
        xexecf("DELETE FROM inbox WHERE id=%lld", id);
        process_trace_event(buf);
    }
    xexec("COMMIT");
}

static int g_headless;

static void process_inbox_input(tui_t *tui);

static void process_inbox(tui_t *tui, int trace_only) {
    process_inbox_trace();
    if (!trace_only) process_inbox_input(tui);
}

/* ── Input dispatch ────────────────────────────────────────────────── */
static int parse_key_name(const char *n) {
    if (strcmp(n, "up") == 0) return TUI_K_UP;
    if (strcmp(n, "down") == 0) return TUI_K_DOWN;
    if (strcmp(n, "left") == 0) return TUI_K_LEFT;
    if (strcmp(n, "right") == 0) return TUI_K_RIGHT;
    if (strcmp(n, "pgup") == 0) return TUI_K_PGUP;
    if (strcmp(n, "pgdn") == 0) return TUI_K_PGDN;
    if (strcmp(n, "home") == 0) return TUI_K_HOME;
    if (strcmp(n, "end") == 0) return TUI_K_END;
    if (strcmp(n, "tab") == 0) return TUI_K_TAB;
    if (strcmp(n, "enter") == 0) return TUI_K_ENTER;
    if (strcmp(n, "esc") == 0) return TUI_K_ESC;
    if (strlen(n) == 1) return (unsigned char)n[0];
    return TUI_K_NONE;
}

/* ── Headless dump functions ───────────────────────────────────────── */
static void dump_lpane(void) {
    printf("=== LPANE ===\n");
    sqlite3_stmt *st;
    sqlite3_prepare_v2(g_db,
        "SELECT rownum,style,id,COALESCE(parent_id,''),text FROM lpane ORDER BY rownum",
        -1, &st, 0);
    while (sqlite3_step(st) == SQLITE_ROW)
        printf("%d|%s|%s|%s|%s\n",
            sqlite3_column_int(st, 0),
            (const char *)sqlite3_column_text(st, 1),
            (const char *)sqlite3_column_text(st, 2),
            (const char *)sqlite3_column_text(st, 3),
            (const char *)sqlite3_column_text(st, 4));
    sqlite3_finalize(st);
    printf("=== END LPANE ===\n");
}

static void dump_rpane(void) {
    printf("=== RPANE ===\n");
    sqlite3_stmt *st;
    int rc = sqlite3_prepare_v2(g_db,
        "SELECT rownum,style,text,link_mode,COALESCE(link_id,'') FROM rpane ORDER BY rownum",
        -1, &st, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "dump_rpane prepare error: %s\n", sqlite3_errmsg(g_db));
        printf("=== END RPANE ===\n");
        return;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW)
        printf("%d|%s|%s|%d|%s\n",
            sqlite3_column_int(st, 0),
            (const char *)sqlite3_column_text(st, 1),
            (const char *)sqlite3_column_text(st, 2),
            sqlite3_column_int(st, 3),
            (const char *)sqlite3_column_text(st, 4));
    if (rc != SQLITE_DONE)
        fprintf(stderr, "dump_rpane step error: %s\n", sqlite3_errmsg(g_db));
    sqlite3_finalize(st);
    printf("=== END RPANE ===\n");
}

static void dump_state(void) {
    printf("=== STATE ===\n");
    sqlite3_stmt *st;
    sqlite3_prepare_v2(g_db,
        "SELECT cursor,scroll,focus,dcursor,dscroll,ts_mode,sort_key,grouped,mode,lp_filter,"
        "COALESCE(search,''),COALESCE(evfilt,''),rows,cols,dep_filter FROM state",
        -1, &st, 0);
    if (sqlite3_step(st) == SQLITE_ROW)
        printf("cursor=%d scroll=%d focus=%d dcursor=%d dscroll=%d ts_mode=%d sort_key=%d"
            " grouped=%d mode=%d lp_filter=%d search=%s evfilt=%s rows=%d cols=%d dep_filter=%d\n",
            sqlite3_column_int(st, 0), sqlite3_column_int(st, 1), sqlite3_column_int(st, 2),
            sqlite3_column_int(st, 3), sqlite3_column_int(st, 4), sqlite3_column_int(st, 5),
            sqlite3_column_int(st, 6), sqlite3_column_int(st, 7), sqlite3_column_int(st, 8),
            sqlite3_column_int(st, 9),
            (const char *)sqlite3_column_text(st, 10),
            (const char *)sqlite3_column_text(st, 11),
            sqlite3_column_int(st, 12), sqlite3_column_int(st, 13),
            sqlite3_column_int(st, 14));
    sqlite3_finalize(st);
    printf("=== END STATE ===\n");
}

static void sync_cursor_id_from_pos(void) {
    /* Sync cursor_id in state to match current state.cursor position in lpane view. */
    xexec("UPDATE state SET cursor_id=COALESCE("
          "(SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),'')");
}

static void dispatch_input(tui_t *tui, const char *data) {
    char inp[32] = "", arg1[4096] = "", arg2[64] = "";
    int n1 = 0, n2 = 0;
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db,
          "SELECT COALESCE(json_extract(?1,'$.input'),''),"
          " COALESCE(json_extract(?1,'$.key'),json_extract(?1,'$.id'),json_extract(?1,'$.q'),json_extract(?1,'$.what'),''),"
          " COALESCE(json_extract(?1,'$.q'),''),"
          " CAST(COALESCE(json_extract(?1,'$.rows'),0)AS INT),"
          " CAST(COALESCE(json_extract(?1,'$.cols'),0)AS INT)", -1, &st, 0);
      sqlite3_bind_text(st, 1, data, -1, SQLITE_TRANSIENT);
      if (sqlite3_step(st) == SQLITE_ROW) {
          const char *v;
          v = (const char *)sqlite3_column_text(st, 0); if (v) snprintf(inp, sizeof inp, "%s", v);
          v = (const char *)sqlite3_column_text(st, 1); if (v) snprintf(arg1, sizeof arg1, "%s", v);
          v = (const char *)sqlite3_column_text(st, 2); if (v) snprintf(arg2, sizeof arg2, "%s", v);
          n1 = sqlite3_column_int(st, 3);
          n2 = sqlite3_column_int(st, 4);
      }
      sqlite3_finalize(st);
    }
    if (!inp[0]) return;

    if (strcmp(inp, "key") == 0) {
        int k = parse_key_name(arg1);
        if (k != TUI_K_NONE) {
            int res = handle_key(tui, k);
            /* In headless mode, apply default navigation via state table */
            if (res == TUI_DEFAULT && !tui) {
                int focus = qint("SELECT focus FROM state", 0);
                int nf = qint("SELECT COUNT(*) FROM lpane", 0);
                int nrp = qint("SELECT COUNT(*) FROM rpane", 0);
                int rows = qint("SELECT rows FROM state", 24);
                int pg = rows - 3;
                switch (k) {
                case TUI_K_UP: case 'k':
                    if (!focus) xexec("UPDATE state SET cursor=MAX(cursor-1,0),dscroll=0,dcursor=0");
                    else xexec("UPDATE state SET dcursor=MAX(dcursor-1,0)");
                    break;
                case TUI_K_DOWN: case 'j':
                    if (!focus) xexecf("UPDATE state SET cursor=MIN(cursor+1,%d),dscroll=0,dcursor=0", nf-1);
                    else xexecf("UPDATE state SET dcursor=MIN(dcursor+1,%d)", nrp-1);
                    break;
                case TUI_K_PGUP:
                    if (!focus) xexecf("UPDATE state SET cursor=MAX(cursor-%d,0),dscroll=0,dcursor=0", pg);
                    else xexecf("UPDATE state SET dcursor=MAX(dcursor-%d,0)", pg);
                    break;
                case TUI_K_PGDN:
                    if (!focus) xexecf("UPDATE state SET cursor=MIN(cursor+%d,%d),dscroll=0,dcursor=0", pg, nf-1);
                    else xexecf("UPDATE state SET dcursor=MIN(dcursor+%d,%d)", pg, nrp-1);
                    break;
                case TUI_K_HOME: case 'g':
                    if (!focus) xexec("UPDATE state SET cursor=0,dscroll=0,dcursor=0");
                    else xexec("UPDATE state SET dcursor=0");
                    break;
                case TUI_K_END:
                    if (!focus) xexecf("UPDATE state SET cursor=%d,dscroll=0,dcursor=0", nf>0?nf-1:0);
                    else xexecf("UPDATE state SET dcursor=%d", nrp>0?nrp-1:0);
                    break;
                }
                if (!focus) sync_cursor_id_from_pos();
            }
        }
    } else if (strcmp(inp, "print") == 0) {
        if (strcmp(arg1, "lpane") == 0) dump_lpane();
        else if (strcmp(arg1, "rpane") == 0) dump_rpane();
        else if (strcmp(arg1, "state") == 0) dump_state();
        g_headless = 1;
    } else if (strcmp(inp, "resize") == 0) {
        if (n1 > 0 && n2 > 0) {
            xexecf("UPDATE state SET rows=%d,cols=%d", n1, n2);
            tui_dirty(g_tui, NULL);
        }
    } else if (strcmp(inp, "select") == 0) {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(g_db,
            "UPDATE state SET cursor=COALESCE((SELECT rownum FROM lpane WHERE id=?),(SELECT cursor FROM state)),"
            "cursor_id=?,dscroll=0,dcursor=0", -1, &st, 0);
        sqlite3_bind_text(st, 1, arg1, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, arg1, -1, SQLITE_TRANSIENT);
        sqlite3_step(st); sqlite3_finalize(st);
        tui_dirty(g_tui, "rpane");
    } else if (strcmp(inp, "search") == 0) {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(g_db, "UPDATE state SET search=?", -1, &st, 0);
        sqlite3_bind_text(st, 1, arg1, -1, SQLITE_TRANSIENT);
        sqlite3_step(st); sqlite3_finalize(st);
        do_search(arg1);
        if (qint("SELECT mode FROM state", 0) == 1) build_file_tree();
        tui_dirty(g_tui, NULL);
    } else if (strcmp(inp, "evfilt") == 0) {
        char q[64] = "";
        for (int i = 0; arg2[i] && i < 63; i++) q[i] = toupper(arg2[i]);
        q[63] = 0;
        sqlite3_stmt *st;
        sqlite3_prepare_v2(g_db, "UPDATE state SET evfilt=?", -1, &st, 0);
        sqlite3_bind_text(st, 1, q, -1, SQLITE_TRANSIENT);
        sqlite3_step(st); sqlite3_finalize(st);
        tui_dirty(g_tui, "rpane");
    }
}

static void process_inbox_input(tui_t *tui) {
    static char buf[1 << 20];
    for (;;) {
        long long id = -1; buf[0] = 0;
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db, "SELECT id,data FROM inbox WHERE kind='input' ORDER BY id LIMIT 1", -1, &st, 0);
          if (sqlite3_step(st) == SQLITE_ROW) {
              id = sqlite3_column_int64(st, 0);
              const char *d = (const char *)sqlite3_column_text(st, 1);
              if (d) snprintf(buf, sizeof buf - 1, "%s", d);
          }
          sqlite3_finalize(st);
        }
        if (id < 0) break;
        xexecf("DELETE FROM inbox WHERE id=%lld", id);
        dispatch_input(tui, buf);
    }
}



/* ── Save DB ───────────────────────────────────────────────────────── */
static void save_to_file(const char *path) {
    sqlite3 *dst;
    if (sqlite3_open(path, &dst) != SQLITE_OK) {
        fprintf(stderr, "tv: cannot create %s\n", path);
        return;
    }
    sqlite3_backup *bk = sqlite3_backup_init(dst, "main", g_db, "main");
    if (bk) { sqlite3_backup_step(bk, -1); sqlite3_backup_finish(bk); }
    sqlite3_close(dst);
}

static void save_db(tui_t *tui) {
    char fname[256] = "trace.db";
    if (!tui_line_edit(tui, "Save to: ", fname, sizeof fname) || !fname[0]) return;
    save_to_file(fname);
}

/* ── Load DB ───────────────────────────────────────────────────────── */
static void load_db(const char *path) {
    sqlite3 *src;
    if (sqlite3_open(path, &src) != SQLITE_OK) {
        fprintf(stderr, "tv: cannot open %s\n", path);
        exit(1);
    }
    sqlite3_backup *bk = sqlite3_backup_init(g_db, "main", src, "main");
    if (!bk) { fprintf(stderr, "tv: backup init failed\n"); exit(1); }
    sqlite3_backup_step(bk, -1);
    sqlite3_backup_finish(bk);
    sqlite3_close(src);
}

/* ── build_file_tree: populate _ftree for mode=1 ──────────────────── */
static void build_file_tree(void) {
    int gr = qint( "SELECT grouped FROM state", 1);
    int sk = qint( "SELECT sort_key FROM state", 0);

    xexec("DELETE FROM _ftree;");

    if (!gr) {
        const char *ob;
        switch (sk) { case 1: ob = "MIN(e.ts)"; break; case 2: ob = "MAX(e.ts)"; break; default: ob = "o.path"; }
        xexecf(
            "INSERT INTO _ftree(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER(ORDER BY %s)-1,o.path,NULL,"
            "  CASE WHEN o.path IN(SELECT id FROM search_hits) THEN 'search'"
            "       WHEN SUM(CASE WHEN o.err IS NOT NULL THEN 1 ELSE 0 END)>0 THEN 'error'"
            "       ELSE 'normal' END,"
            "  printf('%%s  [%%d opens, %%d procs%%s]',"
            "   o.path,"
            "   COUNT(*),COUNT(DISTINCT e.tgid),"
            "   CASE WHEN SUM(o.err IS NOT NULL)>0 THEN printf(', %%d errs',SUM(o.err IS NOT NULL)) ELSE '' END)"
            " FROM open_events o JOIN events e ON e.id=o.eid WHERE o.path IS NOT NULL GROUP BY o.path", ob);
        return;
    }

    /* Tree mode: build file_stats, dir_nodes, compress chains, then ftree */
    xexec(
        "CREATE TEMP TABLE IF NOT EXISTS file_stats("
        " path TEXT NOT NULL, canon TEXT NOT NULL,"
        " opens INT, procs INT, errs INT);"
        "DELETE FROM file_stats;"
        "INSERT INTO file_stats(path,canon,opens,procs,errs)"
        " SELECT o.path,canon_path(o.path),COUNT(*),COUNT(DISTINCT e.tgid),SUM(o.err IS NOT NULL)"
        " FROM open_events o JOIN events e ON e.id=o.eid WHERE o.path IS NOT NULL GROUP BY o.path;");

    xexec(
        "CREATE TEMP TABLE IF NOT EXISTS dir_nodes("
        " id INTEGER PRIMARY KEY, path TEXT NOT NULL, parent_path TEXT, name TEXT,"
        " opens INT DEFAULT 0, procs INT DEFAULT 0, errs INT DEFAULT 0, dead INT DEFAULT 0);"
        "DELETE FROM dir_nodes;"
        "WITH RECURSIVE dirs(d) AS("
        "  SELECT DISTINCT dir_part(canon) FROM file_stats WHERE INSTR(canon,'/')>0"
        "  UNION"
        "  SELECT dir_part(d) FROM dirs WHERE LENGTH(d)>1 AND INSTR(d,'/')>0"
        ")"
        "INSERT INTO dir_nodes(path,parent_path,name)"
        " SELECT d,"
        "  CASE WHEN d='/' THEN NULL"
        "   WHEN INSTR(SUBSTR(d,2),'/')=0 THEN '/'"
        "   ELSE dir_part(d) END,"
        "  " BNAME("d")
        " FROM dirs WHERE d IS NOT NULL AND LENGTH(d)>0;"
        "CREATE INDEX IF NOT EXISTS ix_dn_path ON dir_nodes(path);"
        "CREATE INDEX IF NOT EXISTS ix_dn_par ON dir_nodes(parent_path);"
        "UPDATE dir_nodes SET"
        " opens=(SELECT COALESCE(SUM(f.opens),0) FROM file_stats f WHERE f.canon LIKE dir_nodes.path||'/%'),"
        " procs=(SELECT COALESCE(SUM(f.procs),0) FROM file_stats f WHERE f.canon LIKE dir_nodes.path||'/%'),"
        " errs =(SELECT COALESCE(SUM(f.errs),0)  FROM file_stats f WHERE f.canon LIKE dir_nodes.path||'/%');");

    for (int pass = 0; pass < 20; pass++) {
        int merged = qint(
            "SELECT COUNT(*) FROM dir_nodes p"
            " WHERE p.dead=0 AND p.parent_path IS NOT NULL"
            " AND (SELECT COUNT(*) FROM dir_nodes c WHERE c.parent_path=p.path AND c.dead=0)=1"
            " AND (SELECT COUNT(*) FROM file_stats f WHERE dir_part(f.canon)=p.path)=0"
            " AND NOT EXISTS(SELECT 1 FROM dir_nodes ch"
            "  WHERE ch.parent_path=p.path AND ch.dead=0"
            "  AND (SELECT COUNT(*) FROM dir_nodes gc WHERE gc.parent_path=ch.path AND gc.dead=0)=1"
            "  AND (SELECT COUNT(*) FROM file_stats f2 WHERE dir_part(f2.canon)=ch.path)=0)", 0);
        if (!merged) break;
        xexec(
            "UPDATE dir_nodes SET"
            " name=name||'/'||(SELECT c.name FROM dir_nodes c WHERE c.parent_path=dir_nodes.path AND c.dead=0),"
            " opens=(SELECT c.opens FROM dir_nodes c WHERE c.parent_path=dir_nodes.path AND c.dead=0),"
            " procs=(SELECT c.procs FROM dir_nodes c WHERE c.parent_path=dir_nodes.path AND c.dead=0),"
            " errs=(SELECT c.errs FROM dir_nodes c WHERE c.parent_path=dir_nodes.path AND c.dead=0)"
            " WHERE dead=0 AND parent_path IS NOT NULL"
            " AND (SELECT COUNT(*) FROM dir_nodes c WHERE c.parent_path=dir_nodes.path AND c.dead=0)=1"
            " AND (SELECT COUNT(*) FROM file_stats f WHERE dir_part(f.canon)=dir_nodes.path)=0"
            " AND NOT EXISTS(SELECT 1 FROM dir_nodes ch"
            "  WHERE ch.parent_path=dir_nodes.path AND ch.dead=0"
            "  AND (SELECT COUNT(*) FROM dir_nodes gc WHERE gc.parent_path=ch.path AND gc.dead=0)=1"
            "  AND (SELECT COUNT(*) FROM file_stats f2 WHERE dir_part(f2.canon)=ch.path)=0);");
        xexec(
            "CREATE TEMP TABLE IF NOT EXISTS _merge(pid INT, old_path TEXT, child_path TEXT);"
            "DELETE FROM _merge;"
            "INSERT INTO _merge SELECT p.id, p.path,"
            " (SELECT c.path FROM dir_nodes c WHERE c.parent_path=p.path AND c.dead=0 LIMIT 1)"
            " FROM dir_nodes p WHERE p.dead=0 AND p.parent_path IS NOT NULL"
            " AND (SELECT COUNT(*) FROM dir_nodes c WHERE c.parent_path=p.path AND c.dead=0)=1"
            " AND (SELECT COUNT(*) FROM file_stats f WHERE dir_part(f.canon)=p.path)=0"
            " AND NOT EXISTS(SELECT 1 FROM dir_nodes ch"
            "  WHERE ch.parent_path=p.path AND ch.dead=0"
            "  AND (SELECT COUNT(*) FROM dir_nodes gc WHERE gc.parent_path=ch.path AND gc.dead=0)=1"
            "  AND (SELECT COUNT(*) FROM file_stats f2 WHERE dir_part(f2.canon)=ch.path)=0);");
        xexec(
            "UPDATE dir_nodes SET dead=1 WHERE path IN(SELECT child_path FROM _merge) AND dead=0;");
        xexec(
            "UPDATE dir_nodes SET path="
            " (SELECT m.child_path FROM _merge m WHERE m.pid=dir_nodes.id)"
            " WHERE id IN(SELECT pid FROM _merge);");
        xexec( "DROP TABLE IF EXISTS _merge;");
    }

    xexec( "INSERT OR IGNORE INTO expanded(id,ex) SELECT path,1 FROM dir_nodes WHERE dead=0;");

    xexec(
        "CREATE TEMP TABLE IF NOT EXISTS ftree("
        " id INTEGER PRIMARY KEY, sort_key TEXT, path TEXT, parent_path TEXT, name TEXT,"
        " opens INT, procs INT, errs INT, is_dir INT, depth INT);"
        "DELETE FROM ftree;");

    xexec(
        "INSERT INTO ftree(sort_key,path,parent_path,name,opens,procs,errs,is_dir,depth)"
        " SELECT printf('0/%s',name),"
        "  path,parent_path,name,opens,procs,errs,1,0"
        " FROM dir_nodes"
        " WHERE dead=0 AND (parent_path IS NULL OR parent_path NOT IN(SELECT path FROM dir_nodes WHERE dead=0));");
    xexec(
        "INSERT INTO ftree(sort_key,path,parent_path,name,opens,procs,errs,is_dir,depth)"
        " SELECT printf('1/%s'," BNAME("canon") "),"
        "  path,NULL," BNAME("canon") ",opens,procs,errs,0,0"
        " FROM file_stats"
        " WHERE INSTR(canon,'/')=0"
        "  OR dir_part(canon) NOT IN(SELECT path FROM dir_nodes WHERE dead=0);");

    for (int depth = 0; depth < 50; depth++) {
        int has_more = qintf( 0,
            "SELECT COUNT(*) FROM ftree t"
            " WHERE t.depth=%d AND t.is_dir=1"
            " AND COALESCE((SELECT ex FROM expanded WHERE id=t.path),1)=1"
            " AND (EXISTS(SELECT 1 FROM dir_nodes d WHERE d.parent_path=t.path AND d.dead=0)"
            "  OR EXISTS(SELECT 1 FROM file_stats f WHERE dir_part(f.canon)=t.path))",
            depth);
        if (!has_more) break;
        xexecf(
            "INSERT INTO ftree(sort_key,path,parent_path,name,opens,procs,errs,is_dir,depth)"
            " SELECT t.sort_key||'/0/'||d.name,"
            "  d.path,d.parent_path,d.name,d.opens,d.procs,d.errs,1,%d"
            " FROM ftree t JOIN dir_nodes d ON d.parent_path=t.path"
            " WHERE t.depth=%d AND t.is_dir=1 AND d.dead=0"
            "  AND COALESCE((SELECT ex FROM expanded WHERE id=t.path),1)=1",
            depth + 1, depth);
        xexecf(
            "INSERT INTO ftree(sort_key,path,parent_path,name,opens,procs,errs,is_dir,depth)"
            " SELECT t.sort_key||'/1/'||" BNAME("f.canon") ","
            "  f.path,dir_part(f.canon)," BNAME("f.canon") ",f.opens,f.procs,f.errs,0,%d"
            " FROM ftree t JOIN file_stats f ON dir_part(f.canon)=t.path"
            " WHERE t.depth=%d AND t.is_dir=1"
            "  AND COALESCE((SELECT ex FROM expanded WHERE id=t.path),1)=1",
            depth + 1, depth);
    }

    xexec(
        "INSERT INTO _ftree(rownum,id,parent_id,style,text)"
        " SELECT ROW_NUMBER()OVER(ORDER BY sort_key)-1,"
        "  path,parent_path,"
        "  CASE WHEN path IN(SELECT id FROM search_hits) THEN 'search'"
        "       WHEN errs>0 THEN 'error' ELSE 'normal' END,"
        "  printf('%*s%s%s  [%d opens, %d procs%s]',"
        "   depth*2,'',"
        "   CASE WHEN is_dir AND COALESCE((SELECT ex FROM expanded WHERE id=path),1)=1"
        "    THEN '▼ ' WHEN is_dir THEN '▶ ' ELSE '  ' END,"
        "   name||CASE WHEN is_dir THEN '/' ELSE '' END,"
        "   opens,procs,"
        "   CASE WHEN errs>0 THEN printf(', %d errs',errs) ELSE '' END)"
        " FROM ftree;");

    xexec( "DROP TABLE IF EXISTS ftree;DROP TABLE IF EXISTS file_stats;DROP TABLE IF EXISTS dir_nodes;");
}

/* ── Search & navigation ───────────────────────────────────────────── */
static void do_search(const char *q) {
    sqlite3 *db = g_db;
    xexec( "DELETE FROM search_hits;");
    if (!q || !q[0]) return;
    int mode = qint( "SELECT mode FROM state", 0);
    char lk[512]; snprintf(lk, sizeof lk, "%%%s%%", q);
    sqlite3_stmt *st;
    if (mode == 0 || mode == 5 || mode == 6) {
        if (qint( "SELECT has_fts FROM state", 0)) {
            char fq[512]; snprintf(fq, sizeof fq, "\"%s\"*", q);
            sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO search_hits(id) SELECT DISTINCT CAST(pid AS TEXT) FROM fts WHERE fts MATCH ?", -1, &st, 0);
            sqlite3_bind_text(st, 1, fq, -1, SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st);
        }
        sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO search_hits(id) SELECT CAST(tgid AS TEXT) FROM processes"
            " WHERE CAST(tgid AS TEXT) LIKE ?1 OR exe LIKE ?1 OR argv LIKE ?1", -1, &st, 0);
        sqlite3_bind_text(st, 1, lk, -1, SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st);
    } else if (mode == 1 || mode == 3 || mode == 4) {
        sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO search_hits(id) SELECT DISTINCT path FROM open_events WHERE path LIKE ?", -1, &st, 0);
        sqlite3_bind_text(st, 1, lk, -1, SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st);
    } else {
        sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO search_hits(id) SELECT CAST(e.id AS TEXT) FROM io_events i"
            " JOIN events e ON e.id=i.eid WHERE i.data LIKE ?", -1, &st, 0);
        sqlite3_bind_text(st, 1, lk, -1, SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st);
    }
}

static void jump_hit(int dir) {
    sqlite3 *db = g_db;
    int c = g_tui ? tui_get_cursor(g_tui, "lpane") : qint( "SELECT cursor FROM state", 0);
    if (c < 0) c = 0;
    sqlite3_stmt *st;
    const char *sql = dir > 0
        ? "SELECT MIN(rownum) FROM lpane WHERE id IN(SELECT id FROM search_hits)AND rownum>?"
        : "SELECT MAX(rownum) FROM lpane WHERE id IN(SELECT id FROM search_hits)AND rownum<?";
    sqlite3_prepare_v2(db, sql, -1, &st, 0);
    sqlite3_bind_int(st, 1, c);
    int f = -1;
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL)
        f = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    if (f < 0) {
        sql = dir > 0
            ? "SELECT MIN(rownum) FROM lpane WHERE id IN(SELECT id FROM search_hits)"
            : "SELECT MAX(rownum) FROM lpane WHERE id IN(SELECT id FROM search_hits)";
        f = qint( sql, -1);
    }
    if (f >= 0) {
        if (g_tui) tui_set_cursor_idx(g_tui, "lpane", f);
        xexecf( "UPDATE state SET cursor=%d,dscroll=0,dcursor=0", f);
        sync_cursor_id_from_pos();
        tui_dirty(g_tui, "rpane");
    }
}

static void follow_link(tui_t *tui) {
    sqlite3 *db = g_db;
    int dc = tui ? tui_get_cursor(tui, "rpane") : qint( "SELECT dcursor FROM state", 0);
    if (dc < 0) dc = 0;
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT link_mode,link_id FROM rpane WHERE rownum=? AND link_mode>=0", -1, &st, 0);
    sqlite3_bind_int(st, 1, dc);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int tm = sqlite3_column_int(st, 0);
        const char *ti = (const char *)sqlite3_column_text(st, 1);
        if (ti && ti[0]) {
            char tid[4096]; snprintf(tid, sizeof tid, "%s", ti);
            sqlite3_finalize(st);
            xexecf( "UPDATE state SET mode=%d,cursor=0,cursor_id='',scroll=0,dscroll=0,dcursor=0,focus=0", tm);
            if (tm == 0) {
                int tg = atoi(tid);
                xexecf(
                    "WITH RECURSIVE a(p) AS(SELECT ppid FROM processes WHERE tgid=%d"
                    " UNION ALL SELECT ppid FROM processes JOIN a ON tgid=a.p WHERE ppid IS NOT NULL"
                    ")UPDATE expanded SET ex=1 WHERE id IN(SELECT CAST(p AS TEXT) FROM a)", tg);
            } else if (tm == 1) {
                build_file_tree();
            }
            /* Find rownum of target in (now-current-mode) lpane view */
            sqlite3_prepare_v2(db, "SELECT rownum FROM lpane WHERE id=?", -1, &st, 0);
            sqlite3_bind_text(st, 1, tid, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) {
                int r = sqlite3_column_int(st, 0);
                xexecf( "UPDATE state SET cursor=%d,cursor_id=?", r);
                sqlite3_stmt *s2;
                sqlite3_prepare_v2(db, "UPDATE state SET cursor_id=?", -1, &s2, 0);
                sqlite3_bind_text(s2, 1, tid, -1, SQLITE_TRANSIENT);
                sqlite3_step(s2); sqlite3_finalize(s2);
                if (tui) tui_set_cursor_idx(tui, "lpane", r);
            }
            sqlite3_finalize(st);
            sync_focus_from_state();
            tui_dirty(tui, NULL);
            return;
        }
    }
    sqlite3_finalize(st);
}

/* ── Helper: get rpane section name for collapse ──────────────────── */
static void rpane_section_at( int rownum, char *buf, int bsz) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(g_db,
        "SELECT COALESCE(section,'') FROM rpane WHERE rownum=?", -1, &st, 0);
    sqlite3_bind_int(st, 1, rownum);
    buf[0] = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        if (t) snprintf(buf, bsz, "%s", t);
    }
    sqlite3_finalize(st);
}

/* ── Help text ─────────────────────────────────────────────────────── */
static const char *HELP[] = {
    "", "  Process Trace Viewer", "  ════════════════════", "",
    "  ↑↓ jk  Navigate    PgUp/PgDn  Page    g  First    Tab  Switch pane",
    "  ← h  Collapse/back    → l  Expand/detail    Enter  Follow link", "",
    "  1 Process  2 File  3 Output    G  Toggle tree/flat    s  Sort    t  Timestamps",
    "  4 Deps  5 Reverse-deps  6 Dep-cmds  7 Reverse-dep-cmds    d  Toggle dep filter",
    "  /  Search    n/N  Next/prev    f/F  Filter events/clear    e/E  Expand/collapse all",
    "  v  Cycle proc filter (none→failed→running)    V  Clear proc filter",
    "  W  Save DB to file    x  SQL query    q  Quit    ?  Help", "", "  Press any key.", 0
};

/* ── Key dispatch ──────────────────────────────────────────────────── */
/*
 * handle_key() processes application-specific key bindings.
 * Navigation keys (up/down/pgup/pgdn/home/end) are delegated to the
 * engine's default_nav when the app doesn't handle them.
 * Returns: TUI_HANDLED, TUI_DEFAULT, or TUI_QUIT.
 */
static int handle_key(tui_t *tui, int k) {
    int focus = qint( "SELECT focus FROM state", 0);
    int mode = qint( "SELECT mode FROM state", 0);

    switch (k) {
    /* ── cursor / scroll — let engine handle, then rebuild rpane ── */
    case TUI_K_UP: case 'k':
    case TUI_K_DOWN: case 'j':
    case TUI_K_PGUP:
    case TUI_K_PGDN:
    case TUI_K_HOME: case 'g':
    case TUI_K_END:
        /* Engine will move cursor; post-nav TUI_K_NONE callback updates cursor_id + rpane */
        return TUI_DEFAULT;

    case TUI_K_TAB:
        { int nf = qint("SELECT focus FROM state", 0);
          xexecf("UPDATE state SET focus=%d", nf ? 0 : 1);
          sync_focus_from_state();
          tui_set_cursor_idx(tui, "rpane", 0);
        }
        return TUI_HANDLED;

    case TUI_K_ENTER: case '\n':
        if (focus) follow_link(tui);
        else {
            xexec("UPDATE state SET focus=1");
            sync_focus_from_state();
            tui_set_cursor_idx(tui, "rpane", 0);
        }
        return TUI_HANDLED;
    /* ── business logic ──────────────────────────────────────────── */
    case 'G':
        tui_set_cursor_idx(tui, "lpane", 0);
        tui_set_cursor_idx(tui, "rpane", 0);
        xexec( "UPDATE state SET grouped=1-grouped,cursor=0,scroll=0,dscroll=0,dcursor=0");
        if (qint("SELECT mode FROM state", 0) == 1) build_file_tree();
        tui_dirty(tui, NULL);
        return TUI_HANDLED;
    case TUI_K_RIGHT: case 'l':
        if (focus) {
            int dc = tui_get_cursor(tui, "rpane");
            if (dc < 0) dc = 0;
            char rsty[32] = "";
            { sqlite3_stmt *st2;
              sqlite3_prepare_v2(g_db, "SELECT COALESCE(style,'') FROM rpane WHERE rownum=?", -1, &st2, 0);
              sqlite3_bind_int(st2, 1, dc);
              if (sqlite3_step(st2) == SQLITE_ROW) {
                  const char *t = (const char *)sqlite3_column_text(st2, 0);
                  if (t) snprintf(rsty, sizeof rsty, "%s", t);
              }
              sqlite3_finalize(st2);
            }
            if (strcmp(rsty, "heading") == 0) {
                char sec[128] = "";
                rpane_section_at(dc, sec, sizeof sec);
                if (sec[0]) {
                    int is_ex = qintf( 1, "SELECT COALESCE((SELECT ex FROM expanded WHERE id='rp_%s'),1)", sec);
                    xexecf( "INSERT OR REPLACE INTO expanded(id,ex) VALUES('rp_%s',%d)", sec, is_ex ? 0 : 1);
                    tui_dirty(tui, "rpane");
                }
                return TUI_HANDLED;
            }
            follow_link(tui);
            return TUI_HANDLED;
        }
        { char id[256] = "";
          int cur = tui_get_cursor(tui, "lpane"); if (cur < 0) cur = 0;
          sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db, "SELECT id FROM lpane WHERE rownum=?", -1, &st, 0);
          sqlite3_bind_int(st, 1, cur);
          if (sqlite3_step(st) == SQLITE_ROW) {
              const char *t = (const char *)sqlite3_column_text(st, 0);
              if (t) snprintf(id, sizeof id, "%s", t);
          }
          sqlite3_finalize(st);
          if ((mode == 0 || mode == 1 || mode == 2) && id[0]) {
              int is_ex = qintf( 1, "SELECT COALESCE((SELECT ex FROM expanded WHERE id='%s'),1)", id);
              int has_ch = 0;
              if (mode == 0) has_ch = qintf( 0, "SELECT COUNT(*)>0 FROM processes WHERE ppid=%d", atoi(id));
              else if (mode == 1) has_ch = qintf( 0, "SELECT COUNT(*)>0 FROM _ftree WHERE parent_id='%s'", id);
              else if (!strncmp(id, "io_", 3)) has_ch = 1;
              if (has_ch && !is_ex) {
                  xexecf( "INSERT OR REPLACE INTO expanded(id,ex) VALUES('%s',1)", id);
                  if (mode == 1) build_file_tree();
                  tui_dirty(tui, NULL);
                  return TUI_HANDLED;
              }
          }
        }
        return TUI_HANDLED;
    case TUI_K_LEFT: case 'h':
        if (focus) {
            int dc = tui_get_cursor(tui, "rpane");
            if (dc < 0) dc = 0;
            char rsty[32] = "";
            { sqlite3_stmt *st2;
              sqlite3_prepare_v2(g_db, "SELECT COALESCE(style,'') FROM rpane WHERE rownum=?", -1, &st2, 0);
              sqlite3_bind_int(st2, 1, dc);
              if (sqlite3_step(st2) == SQLITE_ROW) {
                  const char *t = (const char *)sqlite3_column_text(st2, 0);
                  if (t) snprintf(rsty, sizeof rsty, "%s", t);
              }
              sqlite3_finalize(st2);
            }
            if (strcmp(rsty, "heading") == 0) {
                char sec[128] = "";
                rpane_section_at(dc, sec, sizeof sec);
                if (sec[0]) {
                    int is_ex = qintf( 1, "SELECT COALESCE((SELECT ex FROM expanded WHERE id='rp_%s'),1)", sec);
                    xexecf( "INSERT OR REPLACE INTO expanded(id,ex) VALUES('rp_%s',%d)", sec, is_ex ? 0 : 1);
                    tui_dirty(tui, "rpane");
                }
                return TUI_HANDLED;
            }
            return TUI_HANDLED;
        }
        { char id[256] = "";
          int cur = tui_get_cursor(tui, "lpane"); if (cur < 0) cur = 0;
          sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db, "SELECT id FROM lpane WHERE rownum=?", -1, &st, 0);
          sqlite3_bind_int(st, 1, cur);
          if (sqlite3_step(st) == SQLITE_ROW) {
              const char *t = (const char *)sqlite3_column_text(st, 0);
              if (t) snprintf(id, sizeof id, "%s", t);
          }
          sqlite3_finalize(st);
          if (mode == 0 && id[0]) {
              int tgid = atoi(id);
              int has_ch = qintf( 0, "SELECT COUNT(*)>0 FROM processes WHERE ppid=%d", tgid);
              int is_ex = qintf( 1, "SELECT COALESCE((SELECT ex FROM expanded WHERE id='%s'),1)", id);
              if (has_ch && is_ex) { xexecf( "UPDATE expanded SET ex=0 WHERE id='%s'", id); tui_dirty(tui, NULL); return TUI_HANDLED; }
              int ppid = qintf( -1, "SELECT ppid FROM processes WHERE tgid=%d", tgid);
              if (ppid >= 0) {
                  int r = qintf( -1, "SELECT rownum FROM lpane WHERE id='%d'", ppid);
                  if (r >= 0) tui_set_cursor_idx(tui, "lpane", r);
              }
          } else if (mode == 1 && id[0]) {
              int is_ex = qintf( 1, "SELECT COALESCE((SELECT ex FROM expanded WHERE id='%s'),1)", id);
              int has_ch = qintf( 0, "SELECT COUNT(*)>0 FROM _ftree WHERE parent_id='%s'", id);
              if (has_ch && is_ex) {
                  xexecf( "INSERT OR REPLACE INTO expanded(id,ex) VALUES('%s',0)", id);
                  build_file_tree();
                  tui_dirty(tui, NULL);
                  return TUI_HANDLED;
              }
              { sqlite3_stmt *s2;
                sqlite3_prepare_v2(g_db, "SELECT parent_id FROM _ftree WHERE id=? LIMIT 1", -1, &s2, 0);
                sqlite3_bind_text(s2, 1, id, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(s2) == SQLITE_ROW) {
                    const char *pi = (const char *)sqlite3_column_text(s2, 0);
                    if (pi && pi[0]) {
                        int r = qintf( -1, "SELECT rownum FROM lpane WHERE id='%s'", pi);
                        if (r >= 0) tui_set_cursor_idx(tui, "lpane", r);
                    }
                }
                sqlite3_finalize(s2);
              }
          } else if (mode == 2 && id[0]) {
              if (!strncmp(id, "io_", 3)) {
                  xexecf( "INSERT OR REPLACE INTO expanded(id,ex) VALUES('%s',0)", id);
                  tui_dirty(tui, NULL);
              } else {
                  char pid[256] = "";
                  sqlite3_stmt *s2;
                  sqlite3_prepare_v2(g_db, "SELECT parent_id FROM lpane WHERE rownum=?", -1, &s2, 0);
                  sqlite3_bind_int(s2, 1, cur);
                  if (sqlite3_step(s2) == SQLITE_ROW) {
                      const char *pi = (const char *)sqlite3_column_text(s2, 0);
                      if (pi) snprintf(pid, sizeof pid, "%s", pi);
                  }
                  sqlite3_finalize(s2);
                  if (pid[0]) {
                      int r = qintf( -1, "SELECT rownum FROM lpane WHERE id='%s'", pid);
                      if (r >= 0) tui_set_cursor_idx(tui, "lpane", r);
                  }
              }
          }
        }
        return TUI_HANDLED;
    case 'e': case 'E':
        if (mode == 0) {
            char id[64] = "";
            int cur = tui_get_cursor(tui, "lpane"); if (cur < 0) cur = 0;
            sqlite3_stmt *st;
            sqlite3_prepare_v2(g_db, "SELECT id FROM lpane WHERE rownum=?", -1, &st, 0);
            sqlite3_bind_int(st, 1, cur);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *t = (const char *)sqlite3_column_text(st, 0);
                if (t) snprintf(id, sizeof id, "%s", t);
            }
            sqlite3_finalize(st);
            int tg = atoi(id);
            xexecf( "WITH RECURSIVE d(t) AS(SELECT %d UNION ALL SELECT c.tgid FROM processes c JOIN d ON c.ppid=d.t)"
                " UPDATE expanded SET ex=%d WHERE id IN(SELECT CAST(t AS TEXT) FROM d)", tg, k == 'e' ? 1 : 0);
            tui_dirty(tui, NULL);
        }
        return TUI_HANDLED;
    case '1': tui_set_cursor_idx(tui, "lpane", 0); tui_set_cursor_idx(tui, "rpane", 0); xexec( "UPDATE state SET mode=0,cursor=0,cursor_id='',scroll=0,dscroll=0,dcursor=0,focus=0,sort_key=0"); sync_focus_from_state(); tui_dirty(tui, NULL); return TUI_HANDLED;
    case '2': tui_set_cursor_idx(tui, "lpane", 0); tui_set_cursor_idx(tui, "rpane", 0); xexec( "UPDATE state SET mode=1,cursor=0,cursor_id='',scroll=0,dscroll=0,dcursor=0,focus=0,sort_key=0"); sync_focus_from_state(); build_file_tree(); tui_dirty(tui, NULL); return TUI_HANDLED;
    case '3': tui_set_cursor_idx(tui, "lpane", 0); tui_set_cursor_idx(tui, "rpane", 0); xexec( "UPDATE state SET mode=2,cursor=0,cursor_id='',scroll=0,dscroll=0,dcursor=0,focus=0,sort_key=0"); sync_focus_from_state(); tui_dirty(tui, NULL); return TUI_HANDLED;
    case '4': { sync_cursor_to_state();
                xexec( "UPDATE state SET dep_root=COALESCE((SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),''),mode=3,cursor=0,cursor_id='',scroll=0,dscroll=0,dcursor=0,focus=0");
                tui_set_cursor_idx(tui, "lpane", 0); tui_set_cursor_idx(tui, "rpane", 0); sync_focus_from_state(); tui_dirty(tui, NULL); } return TUI_HANDLED;
    case '5': { sync_cursor_to_state();
                xexec( "UPDATE state SET dep_root=COALESCE((SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),''),mode=4,cursor=0,cursor_id='',scroll=0,dscroll=0,dcursor=0,focus=0");
                tui_set_cursor_idx(tui, "lpane", 0); tui_set_cursor_idx(tui, "rpane", 0); sync_focus_from_state(); tui_dirty(tui, NULL); } return TUI_HANDLED;
    case '6': { sync_cursor_to_state();
                xexec( "UPDATE state SET dep_root=COALESCE((SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),''),mode=5,cursor=0,cursor_id='',scroll=0,dscroll=0,dcursor=0,focus=0");
                tui_set_cursor_idx(tui, "lpane", 0); tui_set_cursor_idx(tui, "rpane", 0); sync_focus_from_state(); tui_dirty(tui, NULL); } return TUI_HANDLED;
    case '7': { sync_cursor_to_state();
                xexec( "UPDATE state SET dep_root=COALESCE((SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),''),mode=6,cursor=0,cursor_id='',scroll=0,dscroll=0,dcursor=0,focus=0");
                tui_set_cursor_idx(tui, "lpane", 0); tui_set_cursor_idx(tui, "rpane", 0); sync_focus_from_state(); tui_dirty(tui, NULL); } return TUI_HANDLED;
    case 'd': tui_set_cursor_idx(tui, "lpane", 0); xexec( "UPDATE state SET dep_filter=1-dep_filter,cursor=0,scroll=0"); tui_dirty(tui, NULL); return TUI_HANDLED;
    case 's': tui_set_cursor_idx(tui, "lpane", 0); xexec( "UPDATE state SET sort_key=(sort_key+1)%3,cursor=0,scroll=0"); tui_dirty(tui, NULL); return TUI_HANDLED;
    case 't': xexec( "UPDATE state SET ts_mode=(ts_mode+1)%3"); tui_dirty(tui, "rpane"); return TUI_HANDLED;

    /* ── interactive terminal actions ─────────────────────────────── */
    case '/': {
        char buf[256] = "";
        if (tui_line_edit(tui, "/", buf, sizeof buf) && buf[0]) {
            sqlite3_stmt *st;
            sqlite3_prepare_v2(g_db, "UPDATE state SET search=?", -1, &st, 0);
            sqlite3_bind_text(st, 1, buf, -1, SQLITE_TRANSIENT);
            sqlite3_step(st); sqlite3_finalize(st);
            do_search(buf);
            tui_dirty(tui, NULL);
            jump_hit(1);
        }
    } return TUI_HANDLED;
    case 'n': jump_hit(1); return TUI_HANDLED;
    case 'N': jump_hit(-1); return TUI_HANDLED;
    case 'f': {
        char buf[32] = "";
        if (tui_line_edit(tui, "Filter: ", buf, sizeof buf) && buf[0]) {
            for (char *p = buf; *p; p++) *p = toupper(*p);
            sqlite3_stmt *st;
            sqlite3_prepare_v2(g_db, "UPDATE state SET evfilt=?", -1, &st, 0);
            sqlite3_bind_text(st, 1, buf, -1, SQLITE_TRANSIENT);
            sqlite3_step(st); sqlite3_finalize(st);
            tui_dirty(tui, "rpane");
        }
    } return TUI_HANDLED;
    case 'F': xexec( "UPDATE state SET evfilt=''"); tui_dirty(tui, "rpane"); return TUI_HANDLED;
    case 'v': tui_set_cursor_idx(tui, "lpane", 0); xexecf( "UPDATE state SET lp_filter=(lp_filter+1)%%3,cursor=0,scroll=0"); tui_dirty(tui, NULL); return TUI_HANDLED;
    case 'V': tui_set_cursor_idx(tui, "lpane", 0); xexec( "UPDATE state SET lp_filter=0,cursor=0,scroll=0"); tui_dirty(tui, NULL); return TUI_HANDLED;
    case 'W': save_db(tui); return TUI_HANDLED;
    case 'x': tui_sql_prompt(tui); return TUI_HANDLED;
    case '?': tui_show_help(tui, HELP); return TUI_HANDLED;
    default: return TUI_DEFAULT;
    }
}

/* ── on_key callback for engine event loop ─────────────────────────── */
static int on_key_cb(tui_t *tui, int key, const char *panel,
                     int cursor, const char *row_id, void *ctx) {
    (void)ctx;
    /* TUI_K_NONE: post-navigation notification — engine has moved cursor */
    if (key == TUI_K_NONE) {
        if (panel && strcmp(panel, "lpane") == 0 && row_id && row_id[0]) {
            sqlite3_stmt *st;
            sqlite3_prepare_v2(g_db,
                "UPDATE state SET cursor=?, cursor_id=?", -1, &st, 0);
            sqlite3_bind_int(st, 1, cursor);
            sqlite3_bind_text(st, 2, row_id, -1, SQLITE_TRANSIENT);
            sqlite3_step(st); sqlite3_finalize(st);
            tui_dirty(tui, "rpane");
        }
        update_status();
        return TUI_HANDLED;
    }
    if (key == 'q' || key == 'Q') return TUI_QUIT;
    int result = handle_key(tui, key);
    /* After any key, sync engine cursor back to state table and update status */
    sync_cursor_to_state();
    update_status();
    return result;
}

/* ── on_stream_end callback ────────────────────────────────────────── */
static void on_stream_end(void) {
    setup_fts();
    xexec( "UPDATE state SET lp_filter=0");
}

/* ── Trace FD state (shared with on_trace_fd_cb) ───────────────────── */
static char t_rbuf[1<<20];
static int t_rbuf_len = 0;
static FILE *t_trace_pipe = NULL;
static int t_trace_fd = -1;
static pid_t t_child_pid = 0;

/* ── Trace FD callback for engine event loop ───────────────────────── */
static void on_trace_fd_cb(tui_t *tui, int fd, void *ctx) {
    (void)ctx;
    int n = read(fd, t_rbuf + t_rbuf_len, (int)(sizeof(t_rbuf) - t_rbuf_len - 1));
    if (n <= 0) {
        if (t_rbuf_len > 0) {
            t_rbuf[t_rbuf_len] = 0;
            xexec("BEGIN"); ingest_line(t_rbuf); xexec("COMMIT");
            t_rbuf_len = 0;
            process_inbox(tui, 1);
        }
        on_stream_end();
        tui_unwatch_fd(tui, fd);
        if (t_trace_pipe) { pclose(t_trace_pipe); t_trace_pipe = NULL; t_trace_fd = -1; }
        else { close(fd); t_trace_fd = -1; }
        tui_dirty(tui, NULL);
    } else {
        t_rbuf_len += n;
        int did = 0;
        xexec("BEGIN");
        while (1) {
            char *nl = (char *)memchr(t_rbuf, '\n', t_rbuf_len);
            if (!nl) break;
            if (nl > t_rbuf && *(nl-1) == '\r') *(nl-1) = 0;
            *nl = 0;
            ingest_line(t_rbuf);
            did++;
            int used = (int)(nl - t_rbuf) + 1;
            memmove(t_rbuf, nl + 1, t_rbuf_len - used);
            t_rbuf_len -= used;
        }
        if (t_rbuf_len >= (int)(sizeof(t_rbuf) - 1)) {
            t_rbuf[t_rbuf_len] = 0;
            ingest_line(t_rbuf);
            did++;
            t_rbuf_len = 0;
        }
        xexec("COMMIT");
        if (did) {
            process_inbox(tui, 1);
            xexec("UPDATE state SET base_ts=(SELECT COALESCE(MIN(ts),0) FROM events) WHERE base_ts=0");
            tui_dirty(tui, NULL);
            /* Reap child */
            if (t_child_pid > 0) {
                int ws;
                if (waitpid(t_child_pid, &ws, WNOHANG) == t_child_pid)
                    t_child_pid = 0;
            }
        }
    }
    update_status();
}

/* ═══════════════════════════════════════════════════════════════════ */
extern int uproctrace_main(int argc, char **argv);

int main(int argc, char **argv) {
    /* --uproctrace: delegate entirely to uproctrace_main() */
    if (argc >= 2 && strcmp(argv[1], "--uproctrace") == 0)
        return uproctrace_main(argc - 1, argv + 1);

    int load_mode = 0, force_ptrace = 0;
    char load_file[256] = "", trace_file[256] = "", save_file[256] = "";
    char **cmd = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--load") == 0 && i + 1 < argc) { load_mode = 1; snprintf(load_file, sizeof load_file, "%s", argv[++i]); }
        else if (strcmp(argv[i], "--trace") == 0 && i + 1 < argc) snprintf(trace_file, sizeof trace_file, "%s", argv[++i]);
        else if (strcmp(argv[i], "--save") == 0 && i + 1 < argc) snprintf(save_file, sizeof save_file, "%s", argv[++i]);
        else if (strcmp(argv[i], "--ptrace") == 0) force_ptrace = 1;
        else if (strcmp(argv[i], "--") == 0 && i + 1 < argc) { cmd = argv + i + 1; break; }
    }
    if (!load_mode && !trace_file[0] && !cmd) {
        fprintf(stderr, "Usage: tv [--ptrace] -- <command> [args...]\n"
            "       tv --load <file.db>\n"
            "       tv --trace <file.jsonl> [--save <file.db>]\n"
            "       tv --load <file.db> --trace <input.jsonl>\n"
            "       tv --uproctrace [-o FILE] -- <command> [args...]\n"
            "\n  --ptrace   Force ptrace backend (default: use proctrace kernel module if available)\n"
            "  --uproctrace  Run as trace-only tool (write JSONL to stdout, no TUI)\n"
            "\n  Input events in trace streams: {\"input\":\"key\",\"key\":\"j\"}\n"
            "  {\"input\":\"resize\",\"rows\":50,\"cols\":120}\n"
            "  {\"input\":\"select\",\"id\":\"1003\"}\n"
            "  {\"input\":\"search\",\"q\":\"term\"}\n"
            "  {\"input\":\"evfilt\",\"q\":\"OPEN\"}\n"
            "  {\"input\":\"print\",\"what\":\"lpane|rpane|state\"}\n");
        return 1;
    }

    /* Open in-memory DB */
    if (sqlite3_open(":memory:", &g_db) != SQLITE_OK) {
        fprintf(stderr, "tv: sqlite3_open failed\n");
        return 1;
    }
    register_sql_funcs(g_db);

    int trace_fd = -1;
    pid_t child_pid = 0;
    FILE *trace_pipe = NULL;

    if (load_mode) {
        load_db(load_file);
        xexec(tv_sql_setup);
        if (!qint("SELECT has_fts FROM state", 0))
            setup_fts();
        if (trace_file[0])
            ingest_file(trace_file);
    } else if (trace_file[0]) {
        xexec(tv_sql_schema);
        ingest_file(trace_file);
        process_inbox(NULL, 1);
        xexec(tv_sql_setup);
        setup_fts();
    } else {
        xexec(tv_sql_schema);
        xexec(tv_sql_setup);
        g_own_tgid = (int)getpid();
        if (!force_ptrace)
            trace_fd = open("/proc/proctrace/new", O_RDONLY);
        if (trace_fd >= 0) {
            child_pid = fork();
            if (child_pid < 0) { close(trace_fd); fprintf(stderr, "tv: fork\n"); exit(1); }
            if (child_pid == 0) { execvp(cmd[0], cmd); perror(cmd[0]); _exit(127); }
        } else {
            char self_exe[4096];
            ssize_t slen = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
            if (slen <= 0) { fprintf(stderr, "tv: cannot resolve /proc/self/exe\n"); exit(1); }
            self_exe[slen] = '\0';

            size_t cmdlen = strlen(self_exe) + strlen(" --uproctrace --") + 1;
            for (char **p = cmd; *p; p++) cmdlen += strlen(*p) * 4 + 3;
            char *popen_cmd = malloc(cmdlen);
            if (!popen_cmd) { fprintf(stderr, "tv: malloc\n"); exit(1); }
            char *w = popen_cmd;
            w += sprintf(w, "%s --uproctrace --", self_exe);
            for (char **p = cmd; *p; p++) {
                *w++ = ' '; *w++ = '\'';
                for (const char *c = *p; *c; c++) {
                    if (*c == '\'') { *w++ = '\''; *w++ = '\\'; *w++ = '\''; *w++ = '\''; }
                    else *w++ = *c;
                }
                *w++ = '\'';
            }
            *w = '\0';

            FILE *pp = popen(popen_cmd, "r");
            free(popen_cmd);
            if (!pp) { fprintf(stderr, "tv: popen uproctrace failed\n"); exit(1); }
            trace_pipe = pp;
            trace_fd = fileno(pp);
        }
        xexec("UPDATE state SET lp_filter=2");
    }

    /* Initial setup: populate _ftree if starting in file mode, then sync cursor_id */
    if (qint("SELECT mode FROM state", 0) == 1) build_file_tree();
    sync_cursor_id_from_pos();

    if (save_file[0]) save_to_file(save_file);
    process_inbox(NULL, 0);

    if (g_headless) { sqlite3_close(g_db); return 0; }
    if (save_file[0] && !cmd) { sqlite3_close(g_db); return 0; }

    /* ── Engine-driven event loop ──────────────────────────────── */
    tui_t *tui = tui_open(g_db);
    if (!tui) { fprintf(stderr, "tv: cannot open terminal\n"); sqlite3_close(g_db); return 1; }
    g_tui = tui;

    /* Define panels — lpane (left), rpane (right) */
    static tui_col_def lp_cols[] = {{"text", -1, TUI_ALIGN_LEFT, TUI_OVERFLOW_ELLIPSIS}};
    static tui_panel_def lp_def = {"lpane", NULL, "rownum", lp_cols, 1, TUI_PANEL_CURSOR};
    tui_add_panel(tui, &lp_def, 0, 0, 50, 100);

    static tui_col_def rp_cols[] = {{"text", -1, TUI_ALIGN_LEFT, TUI_OVERFLOW_ELLIPSIS}};
    static tui_panel_def rp_def = {"rpane", NULL, "rownum", rp_cols, 1, TUI_PANEL_CURSOR | TUI_PANEL_BORDER};
    tui_add_panel(tui, &rp_def, 50, 0, 50, 100);

    /* Focus starts on lpane */
    tui_focus(tui, "lpane");

    /* Register key handler */
    tui_on_key(tui, on_key_cb, NULL);

    /* Set up trace fd state for callback */
    t_trace_pipe = trace_pipe;
    t_trace_fd = trace_fd;
    t_child_pid = child_pid;

    /* Register trace fd if active */
    if (trace_fd >= 0)
        tui_watch_fd(tui, trace_fd, on_trace_fd_cb, NULL);

    /* Initial status + dirty all */
    update_status();
    tui_dirty(tui, NULL);

    /* Run the event loop */
    tui_run(tui);

    g_tui = NULL;
    tui_close(tui);
    if (t_trace_pipe) { pclose(t_trace_pipe); t_trace_pipe = NULL; }
    else if (t_trace_fd >= 0) { close(t_trace_fd); t_trace_fd = -1; }
    if (t_child_pid > 0) { kill(t_child_pid, SIGTERM); waitpid(t_child_pid, NULL, 0); }
    sqlite3_close(g_db);
    return 0;
}
