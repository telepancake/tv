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
static void handle_key(tui_t *tui, int k);
static void do_search(const char *q);
static void rebuild_lpane(void);
static void rebuild_rpane(void);
static void jump_hit(int dir);
static void follow_link(tui_t *tui);

/* ── Dirty flags (outbox) ──────────────────────────────────────────── */
static void dirty_lp(void)   { xexec("UPDATE outbox SET rl=1"); }
static void dirty_rp(void)   { xexec("UPDATE outbox SET rr=1"); }
static void dirty_both(void) { xexec("UPDATE outbox SET rl=1,rr=1"); }

static void sync_panes(void) {
    int rl = qint("SELECT rl FROM outbox", 0);
    int rr = qint("SELECT rr FROM outbox", 0);
    if (rl || rr) xexec("UPDATE outbox SET rl=0,rr=0");
    if (rl) rebuild_lpane();
    if (rr) rebuild_rpane();
}

/* ── Status bar update ─────────────────────────────────────────────── */
static void update_status(void) {
    int mode = qint("SELECT mode FROM state", 0);
    int nf = qint("SELECT COUNT(*) FROM lpane", 0);
    int cursor = qint("SELECT cursor FROM state", 0);
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

    /* Write to state.status for engine to render */
    sqlite3_stmt *st;
    sqlite3_prepare_v2(g_db, "UPDATE state SET status=?", -1, &st, 0);
    sqlite3_bind_text(st, 1, s, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
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
    sqlite3_prepare_v2(g_db,
        "SELECT rownum,style,text,link_mode,COALESCE(link_id,'') FROM rpane ORDER BY rownum",
        -1, &st, 0);
    while (sqlite3_step(st) == SQLITE_ROW)
        printf("%d|%s|%s|%d|%s\n",
            sqlite3_column_int(st, 0),
            (const char *)sqlite3_column_text(st, 1),
            (const char *)sqlite3_column_text(st, 2),
            sqlite3_column_int(st, 3),
            (const char *)sqlite3_column_text(st, 4));
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
        if (k != TUI_K_NONE) handle_key(tui, k);
    } else if (strcmp(inp, "print") == 0) {
        sync_panes();
        if (strcmp(arg1, "lpane") == 0) dump_lpane();
        else if (strcmp(arg1, "rpane") == 0) dump_rpane();
        else if (strcmp(arg1, "state") == 0) dump_state();
        g_headless = 1;
    } else if (strcmp(inp, "resize") == 0) {
        if (n1 > 0 && n2 > 0) { xexecf("UPDATE state SET rows=%d,cols=%d", n1, n2); dirty_both(); }
    } else if (strcmp(inp, "select") == 0) {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(g_db,
            "UPDATE state SET cursor=COALESCE((SELECT rownum FROM lpane WHERE id=?),(SELECT cursor FROM state)),"
            "dscroll=0,dcursor=0", -1, &st, 0);
        sqlite3_bind_text(st, 1, arg1, -1, SQLITE_TRANSIENT);
        sqlite3_step(st); sqlite3_finalize(st);
        dirty_rp();
    } else if (strcmp(inp, "search") == 0) {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(g_db, "UPDATE state SET search=?", -1, &st, 0);
        sqlite3_bind_text(st, 1, arg1, -1, SQLITE_TRANSIENT);
        sqlite3_step(st); sqlite3_finalize(st);
        do_search(arg1);
        dirty_both();
    } else if (strcmp(inp, "evfilt") == 0) {
        char q[64] = "";
        for (int i = 0; arg2[i] && i < 63; i++) q[i] = toupper(arg2[i]);
        q[63] = 0;
        sqlite3_stmt *st;
        sqlite3_prepare_v2(g_db, "UPDATE state SET evfilt=?", -1, &st, 0);
        sqlite3_bind_text(st, 1, q, -1, SQLITE_TRANSIENT);
        sqlite3_step(st); sqlite3_finalize(st);
        dirty_rp();
    }
    sync_panes();
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

static void apply_lp_filter(void) {
    int filt = qint( "SELECT lp_filter FROM state", 0);
    if (!filt) return;

    if (filt == 1) {
        xexec(
            "WITH RECURSIVE"
            " failed(tgid) AS("
            "  SELECT p.tgid FROM processes p"
            "  JOIN events ev ON ev.tgid=p.tgid AND ev.event='EXIT'"
            "  JOIN exit_events x ON x.eid=ev.id"
            "  WHERE x.signal IS NOT NULL"
            "   OR(x.code IS NOT NULL AND x.code!=0"
            "      AND EXISTS(SELECT 1 FROM open_events o JOIN events e ON e.id=o.eid"
            "       WHERE e.tgid=p.tgid"
            "        AND(o.flags LIKE 'O_WRONLY%' OR o.flags LIKE 'O_RDWR%')))"
            " ),"
            " visible(tgid) AS("
            "  SELECT tgid FROM failed"
            "  UNION SELECT p2.ppid FROM processes p2 JOIN visible v ON p2.tgid=v.tgid"
            "   WHERE p2.ppid IS NOT NULL AND p2.ppid IN(SELECT tgid FROM processes)"
            " )"
            " UPDATE lpane SET visible=0"
            "  WHERE CAST(id AS INT) NOT IN(SELECT tgid FROM visible)");
    } else if (filt == 2) {
        xexec(
            "WITH RECURSIVE"
            " running(tgid) AS("
            "  SELECT tgid FROM processes"
            "  WHERE NOT EXISTS("
            "   SELECT 1 FROM events WHERE events.tgid=processes.tgid AND events.event='EXIT')"
            " ),"
            " visible(tgid) AS("
            "  SELECT tgid FROM running"
            "  UNION SELECT p2.ppid FROM processes p2 JOIN visible v ON p2.tgid=v.tgid"
            "   WHERE p2.ppid IS NOT NULL AND p2.ppid IN(SELECT tgid FROM processes)"
            " )"
            " UPDATE lpane SET visible=0"
            "  WHERE CAST(id AS INT) NOT IN(SELECT tgid FROM visible)");
    }

    xexec(
        "CREATE TEMP TABLE _lp AS"
        " SELECT ROW_NUMBER()OVER(ORDER BY rownum)-1 AS rn,id,parent_id,style,text,1 AS visible FROM lpane WHERE visible=1;"
        "DELETE FROM lpane;"
        "INSERT INTO lpane(rownum,id,parent_id,style,text,visible) SELECT*FROM _lp;"
        "DROP TABLE _lp;");
}

/* ── Rebuild lpane: processes ──────────────────────────────────────── */
static void rebuild_procs(void) {
    int gr = qint( "SELECT grouped FROM state", 1);
    int sk = qint( "SELECT sort_key FROM state", 0);
    const char *bo, *co, *fo;
    switch (sk) {
        case 1: bo = "p2.first_ts"; co = "c.first_ts"; fo = "p.first_ts"; break;
        case 2: bo = "p2.last_ts";  co = "c.last_ts";  fo = "p.last_ts";  break;
        default: bo = "p2.tgid";    co = "c.tgid";     fo = "p.tgid";     break;
    }
    if (gr) {
        xexec( "INSERT OR IGNORE INTO expanded(id,ex) SELECT CAST(tgid AS TEXT),1 FROM processes;");
        char sql[8192]; snprintf(sql, sizeof sql,
            "INSERT INTO lpane(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER()-1,CAST(f.tgid AS TEXT),CAST(p.ppid AS TEXT),"
            "  CASE WHEN f.tgid IN(SELECT CAST(id AS INT) FROM search_hits) THEN 'search'"
            "       WHEN x.code IS NOT NULL AND x.code!=0 THEN 'error'"
            "       WHEN x.signal IS NOT NULL THEN 'error' ELSE 'normal' END,"
            "  printf('%%*s%%s[%%d] %%s%%s%%s %%s',f.depth*2,'',"
            "   CASE WHEN NOT EXISTS(SELECT 1 FROM processes WHERE ppid=f.tgid) THEN '  '"
            "        WHEN COALESCE((SELECT ex FROM expanded WHERE id=CAST(f.tgid AS TEXT)),1) THEN '▼ ' ELSE '▶ ' END,"
            "   f.tgid,COALESCE(" BNAME("p.exe") ",'?'),"
            "   CASE WHEN x.code IS NOT NULL AND x.code!=0 THEN ' ✗'"
            "        WHEN x.signal IS NOT NULL THEN printf(' ⚡%%d',x.signal)"
            "        WHEN x.code IS NOT NULL THEN ' ✓' ELSE '' END,"
            "   CASE WHEN(SELECT COUNT(*)FROM processes WHERE ppid=f.tgid)>0"
            "    THEN printf(' (%%d)',(WITH RECURSIVE d(t) AS(SELECT tgid FROM processes WHERE ppid=f.tgid"
            "     UNION ALL SELECT c2.tgid FROM processes c2 JOIN d ON c2.ppid=d.t)SELECT COUNT(*)FROM d))ELSE'' END,"
            "   " DUR("p.last_ts-p.first_ts") ")"
            " FROM(WITH RECURSIVE flat(tgid,depth,sk) AS("
            "  SELECT p2.tgid,0,%s FROM processes p2"
            "   WHERE p2.ppid IS NULL OR p2.ppid NOT IN(SELECT tgid FROM processes)"
            "  UNION ALL SELECT c.tgid,flat.depth+1,%s FROM processes c"
            "   JOIN flat ON c.ppid=flat.tgid"
            "   JOIN expanded ex ON ex.id=CAST(flat.tgid AS TEXT) WHERE ex.ex=1 ORDER BY 3"
            " )SELECT tgid,depth FROM flat)f"
            " JOIN processes p ON p.tgid=f.tgid"
            " LEFT JOIN events ev ON ev.tgid=f.tgid AND ev.event='EXIT'"
            " LEFT JOIN exit_events x ON x.eid=ev.id", bo, co);
        xexec( sql);
    } else {
        xexecf(
            "INSERT INTO lpane(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER(ORDER BY %s)-1,CAST(p.tgid AS TEXT),CAST(p.ppid AS TEXT),"
            "  CASE WHEN p.tgid IN(SELECT CAST(id AS INT) FROM search_hits) THEN 'search'"
            "       WHEN x.code IS NOT NULL AND x.code!=0 THEN 'error'"
            "       WHEN x.signal IS NOT NULL THEN 'error' ELSE 'normal' END,"
            "  printf('[%%d] %%s%%s %%s',p.tgid,COALESCE(" BNAME("p.exe") ",'?'),"
            "   CASE WHEN x.code IS NOT NULL AND x.code!=0 THEN ' ✗'"
            "        WHEN x.signal IS NOT NULL THEN printf(' ⚡%%d',x.signal)"
            "        WHEN x.code IS NOT NULL THEN ' ✓' ELSE '' END," DUR("p.last_ts-p.first_ts") ")"
            " FROM processes p LEFT JOIN events ev ON ev.tgid=p.tgid AND ev.event='EXIT'"
            " LEFT JOIN exit_events x ON x.eid=ev.id", fo);
    }
}

/* ── Rebuild lpane: files ──────────────────────────────────────────── */
static void rebuild_files(void) {
    int gr = qint( "SELECT grouped FROM state", 1);
    int sk = qint( "SELECT sort_key FROM state", 0);

    if (!gr) {
        const char *ob;
        switch (sk) { case 1: ob = "MIN(e.ts)"; break; case 2: ob = "MAX(e.ts)"; break; default: ob = "o.path"; }
        xexecf(
            "INSERT INTO lpane(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER(ORDER BY %s)-1,o.path,NULL,"
            "  CASE WHEN o.path IN(SELECT id FROM search_hits) THEN 'search'"
            "       WHEN SUM(CASE WHEN o.err IS NOT NULL THEN 1 ELSE 0 END)>0 THEN 'error'"
            "       ELSE 'normal' END,"
            "  printf('%%s  \x1b[36m[%%d opens, %%d procs%%s]\x1b[0m',"
            "   o.path,"
            "   COUNT(*),COUNT(DISTINCT e.tgid),"
            "   CASE WHEN SUM(o.err IS NOT NULL)>0 THEN printf(', %%d errs',SUM(o.err IS NOT NULL)) ELSE '' END)"
            " FROM open_events o JOIN events e ON e.id=o.eid WHERE o.path IS NOT NULL GROUP BY o.path", ob);
        return;
    }

    /* Tree mode */
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

    /* Collapse single-child directory chains */
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
        "INSERT INTO lpane(rownum,id,parent_id,style,text)"
        " SELECT ROW_NUMBER()OVER(ORDER BY sort_key)-1,"
        "  path,parent_path,"
        "  CASE WHEN path IN(SELECT id FROM search_hits) THEN 'search'"
        "       WHEN errs>0 THEN 'error' ELSE 'normal' END,"
        "  printf('%*s%s%s%s  \x1b[36m[%d opens, %d procs%s]\x1b[0m',"
        "   depth*2,'',"
        "   CASE WHEN is_dir AND COALESCE((SELECT ex FROM expanded WHERE id=path),1)=1"
        "    THEN '▼ ' WHEN is_dir THEN '▶ ' ELSE '  ' END,"
        "   CASE WHEN is_dir THEN '\x1b[1m' ELSE '\x1b[32m' END,"
        "   name||CASE WHEN is_dir THEN '/\x1b[0m' ELSE '\x1b[0m' END,"
        "   opens,procs,"
        "   CASE WHEN errs>0 THEN printf(', %d errs',errs) ELSE '' END)"
        " FROM ftree;");

    xexec( "DROP TABLE IF EXISTS ftree;DROP TABLE IF EXISTS file_stats;DROP TABLE IF EXISTS dir_nodes;");
}

/* ── Rebuild lpane: outputs ────────────────────────────────────────── */
static void rebuild_outputs(void) {
    int gr = qint( "SELECT grouped FROM state", 1);
    if (gr) {
        xexec( "INSERT OR IGNORE INTO expanded(id,ex)"
            " SELECT DISTINCT 'io_'||CAST(e.tgid AS TEXT),1 FROM io_events i JOIN events e ON e.id=i.eid;");
        xexec(
            "INSERT INTO lpane(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER(ORDER BY sub.g_ts,sub.s_ts)-1,sub.id,sub.par,sub.sty,sub.txt FROM("
            "  SELECT 'io_'||CAST(e.tgid AS TEXT) AS id,NULL AS par,'cyan_bold' AS sty,"
            "   printf('── PID %d %s (%d lines) ──',e.tgid,COALESCE(" BNAME("p.exe") ",'?'),COUNT(*)) AS txt,"
            "   MIN(e.ts) AS g_ts,0.0 AS s_ts"
            "  FROM io_events i JOIN events e ON e.id=i.eid JOIN processes p ON p.tgid=e.tgid GROUP BY e.tgid"
            "  UNION ALL"
            "  SELECT CAST(e.id AS TEXT),'io_'||CAST(e.tgid AS TEXT),"
            "   CASE WHEN i.stream='STDERR' THEN 'error' ELSE 'normal' END,"
            "   printf('  %s %s',i.stream,SUBSTR(REPLACE(COALESCE(i.data,''),char(10),'↵'),1,200)),"
            "   (SELECT MIN(e2.ts) FROM events e2 JOIN io_events i2 ON i2.eid=e2.id WHERE e2.tgid=e.tgid),e.ts"
            "  FROM io_events i JOIN events e ON e.id=i.eid"
            "  WHERE EXISTS(SELECT 1 FROM expanded WHERE id='io_'||CAST(e.tgid AS TEXT) AND ex=1)"
            " )sub;");
    } else {
        xexec(
            "INSERT INTO lpane(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER(ORDER BY e.ts)-1,CAST(e.id AS TEXT),NULL,"
            "  CASE WHEN i.stream='STDERR' THEN 'error' ELSE 'normal' END,"
            "  printf('[%d] %s %s',e.tgid,i.stream,SUBSTR(REPLACE(COALESCE(i.data,''),char(10),'↵'),1,200))"
            " FROM io_events i JOIN events e ON e.id=i.eid ORDER BY e.ts;");
    }
}

/* ── Dependency views ──────────────────────────────────────────────── */
static void build_dep_edges(void) {
    xexec(
        "CREATE TEMP TABLE IF NOT EXISTS dep_edges("
        " src TEXT NOT NULL, dst TEXT NOT NULL, tgid INT NOT NULL);"
        "DELETE FROM dep_edges;"
        "INSERT INTO dep_edges(src,dst,tgid)"
        " SELECT DISTINCT r.path, w.path, er.tgid"
        " FROM open_events r"
        " JOIN events er ON er.id=r.eid"
        " JOIN open_events w"
        " JOIN events ew ON ew.id=w.eid"
        " WHERE er.tgid=ew.tgid"
        "  AND r.path IS NOT NULL AND w.path IS NOT NULL"
        "  AND r.path!=w.path"
        "  AND (r.flags LIKE 'O_RDONLY%' OR r.flags LIKE 'O_RDWR%')"
        "  AND (w.flags LIKE 'O_WRONLY%' OR w.flags LIKE 'O_RDWR%' OR w.flags LIKE 'O_WRONLY,%' OR w.flags LIKE 'O_RDWR,%');"
        "CREATE INDEX IF NOT EXISTS ix_de_dst ON dep_edges(dst);"
        "CREATE INDEX IF NOT EXISTS ix_de_src ON dep_edges(src);");
}

static void rebuild_deps(void) {
    build_dep_edges();
    int df = qint( "SELECT dep_filter FROM state", 0);
    char root[4096] = "";
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db, "SELECT dep_root FROM state", -1, &st, 0);
      if (sqlite3_step(st) == SQLITE_ROW) {
          const char *t = (const char *)sqlite3_column_text(st, 0);
          if (t) snprintf(root, sizeof root, "%s", t);
      }
      sqlite3_finalize(st);
    }
    if (!root[0]) { xexec( "DROP TABLE IF EXISTS dep_edges;"); return; }

    xexec(
        "CREATE TEMP TABLE IF NOT EXISTS dep_closure(path TEXT PRIMARY KEY,depth INT);"
        "DELETE FROM dep_closure;");
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db,
          "INSERT OR IGNORE INTO dep_closure(path,depth) VALUES(?1,0)", -1, &st, 0);
      sqlite3_bind_text(st, 1, root, -1, SQLITE_TRANSIENT);
      sqlite3_step(st); sqlite3_finalize(st);
    }
    for (int d = 0; d < 100; d++) {
        int added = qintf( 0,
            "SELECT COUNT(*) FROM dep_edges e"
            " JOIN dep_closure c ON c.path=e.dst AND c.depth=%d"
            " WHERE e.src NOT IN(SELECT path FROM dep_closure)", d);
        if (!added) break;
        xexecf(
            "INSERT OR IGNORE INTO dep_closure(path,depth)"
            " SELECT DISTINCT e.src,%d"
            " FROM dep_edges e JOIN dep_closure c ON c.path=e.dst AND c.depth=%d"
            " WHERE e.src NOT IN(SELECT path FROM dep_closure)", d + 1, d);
    }

    const char *filt = df ? "AND EXISTS(SELECT 1 FROM open_events o2 JOIN events e2 ON e2.id=o2.eid"
        " WHERE o2.path=dc.path AND (o2.flags LIKE 'O_WRONLY%%' OR o2.flags LIKE 'O_RDWR%%'"
        " OR o2.flags LIKE 'O_WRONLY,%%' OR o2.flags LIKE 'O_RDWR,%%'))" : "";

    xexecf(
        "INSERT INTO lpane(rownum,id,parent_id,style,text)"
        " SELECT ROW_NUMBER()OVER(ORDER BY dc.depth,dc.path)-1,dc.path,NULL,"
        "  CASE WHEN dc.depth=0 THEN 'cyan_bold'"
        "       WHEN dc.path IN(SELECT id FROM search_hits) THEN 'search'"
        "       ELSE 'normal' END,"
        "  printf('%%*s%%s',dc.depth*2,''," BNAME("dc.path") ")"
        " FROM dep_closure dc WHERE 1=1 %s ORDER BY dc.depth,dc.path", filt);

    xexec( "DROP TABLE IF EXISTS dep_closure;DROP TABLE IF EXISTS dep_edges;");
}

static void rebuild_rdeps(void) {
    build_dep_edges();
    int df = qint( "SELECT dep_filter FROM state", 0);
    char root[4096] = "";
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db, "SELECT dep_root FROM state", -1, &st, 0);
      if (sqlite3_step(st) == SQLITE_ROW) {
          const char *t = (const char *)sqlite3_column_text(st, 0);
          if (t) snprintf(root, sizeof root, "%s", t);
      }
      sqlite3_finalize(st);
    }
    if (!root[0]) { xexec( "DROP TABLE IF EXISTS dep_edges;"); return; }

    xexec(
        "CREATE TEMP TABLE IF NOT EXISTS dep_closure(path TEXT PRIMARY KEY,depth INT);"
        "DELETE FROM dep_closure;");
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db,
          "INSERT OR IGNORE INTO dep_closure(path,depth) VALUES(?1,0)", -1, &st, 0);
      sqlite3_bind_text(st, 1, root, -1, SQLITE_TRANSIENT);
      sqlite3_step(st); sqlite3_finalize(st);
    }
    for (int d = 0; d < 100; d++) {
        int added = qintf( 0,
            "SELECT COUNT(*) FROM dep_edges e"
            " JOIN dep_closure c ON c.path=e.src AND c.depth=%d"
            " WHERE e.dst NOT IN(SELECT path FROM dep_closure)", d);
        if (!added) break;
        xexecf(
            "INSERT OR IGNORE INTO dep_closure(path,depth)"
            " SELECT DISTINCT e.dst,%d"
            " FROM dep_edges e JOIN dep_closure c ON c.path=e.src AND c.depth=%d"
            " WHERE e.dst NOT IN(SELECT path FROM dep_closure)", d + 1, d);
    }

    const char *filt = df ? "AND EXISTS(SELECT 1 FROM open_events o2 JOIN events e2 ON e2.id=o2.eid"
        " WHERE o2.path=dc.path AND (o2.flags LIKE 'O_WRONLY%%' OR o2.flags LIKE 'O_RDWR%%'"
        " OR o2.flags LIKE 'O_WRONLY,%%' OR o2.flags LIKE 'O_RDWR,%%'))" : "";

    xexecf(
        "INSERT INTO lpane(rownum,id,parent_id,style,text)"
        " SELECT ROW_NUMBER()OVER(ORDER BY dc.depth,dc.path)-1,dc.path,NULL,"
        "  CASE WHEN dc.depth=0 THEN 'cyan_bold'"
        "       WHEN dc.path IN(SELECT id FROM search_hits) THEN 'search'"
        "       ELSE 'normal' END,"
        "  printf('%%*s%%s',dc.depth*2,''," BNAME("dc.path") ")"
        " FROM dep_closure dc WHERE 1=1 %s ORDER BY dc.depth,dc.path", filt);

    xexec( "DROP TABLE IF EXISTS dep_closure;DROP TABLE IF EXISTS dep_edges;");
}

static void rebuild_dep_cmds(void) {
    build_dep_edges();
    char root[4096] = "";
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db, "SELECT dep_root FROM state", -1, &st, 0);
      if (sqlite3_step(st) == SQLITE_ROW) {
          const char *t = (const char *)sqlite3_column_text(st, 0);
          if (t) snprintf(root, sizeof root, "%s", t);
      }
      sqlite3_finalize(st);
    }
    if (!root[0]) { xexec( "DROP TABLE IF EXISTS dep_edges;"); return; }

    xexec(
        "CREATE TEMP TABLE IF NOT EXISTS dep_closure(path TEXT PRIMARY KEY,depth INT);"
        "DELETE FROM dep_closure;");
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db,
          "INSERT OR IGNORE INTO dep_closure(path,depth) VALUES(?1,0)", -1, &st, 0);
      sqlite3_bind_text(st, 1, root, -1, SQLITE_TRANSIENT);
      sqlite3_step(st); sqlite3_finalize(st);
    }
    for (int d = 0; d < 100; d++) {
        int added = qintf( 0,
            "SELECT COUNT(*) FROM dep_edges e"
            " JOIN dep_closure c ON c.path=e.dst AND c.depth=%d"
            " WHERE e.src NOT IN(SELECT path FROM dep_closure)", d);
        if (!added) break;
        xexecf(
            "INSERT OR IGNORE INTO dep_closure(path,depth)"
            " SELECT DISTINCT e.src,%d"
            " FROM dep_edges e JOIN dep_closure c ON c.path=e.dst AND c.depth=%d"
            " WHERE e.src NOT IN(SELECT path FROM dep_closure)", d + 1, d);
    }

    xexecf(
        "INSERT INTO lpane(rownum,id,parent_id,style,text)"
        " SELECT ROW_NUMBER()OVER(ORDER BY p.last_ts DESC)-1,"
        "  CAST(p.tgid AS TEXT),NULL,"
        "  CASE WHEN p.tgid IN(SELECT CAST(id AS INT) FROM search_hits) THEN 'search'"
        "       WHEN x.code IS NOT NULL AND x.code!=0 THEN 'error'"
        "       WHEN x.signal IS NOT NULL THEN 'error' ELSE 'normal' END,"
        "  printf('[%%d] %%s%%s %%s',p.tgid,COALESCE(" BNAME("p.exe") ",'?'),"
        "   CASE WHEN x.code IS NOT NULL AND x.code!=0 THEN ' ✗'"
        "        WHEN x.signal IS NOT NULL THEN printf(' ⚡%%d',x.signal)"
        "        WHEN x.code IS NOT NULL THEN ' ✓' ELSE '' END," DUR("p.last_ts-p.first_ts") ")"
        " FROM processes p"
        " LEFT JOIN events ev ON ev.tgid=p.tgid AND ev.event='EXIT'"
        " LEFT JOIN exit_events x ON x.eid=ev.id"
        " WHERE p.tgid IN("
        "  SELECT DISTINCT e.tgid FROM dep_edges e"
        "  JOIN dep_closure dc ON (e.dst=dc.path OR e.src=dc.path)"
        " )"
        " ORDER BY p.last_ts DESC");

    xexec( "DROP TABLE IF EXISTS dep_closure;DROP TABLE IF EXISTS dep_edges;");
}

static void rebuild_rdep_cmds(void) {
    build_dep_edges();
    char root[4096] = "";
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db, "SELECT dep_root FROM state", -1, &st, 0);
      if (sqlite3_step(st) == SQLITE_ROW) {
          const char *t = (const char *)sqlite3_column_text(st, 0);
          if (t) snprintf(root, sizeof root, "%s", t);
      }
      sqlite3_finalize(st);
    }
    if (!root[0]) { xexec( "DROP TABLE IF EXISTS dep_edges;"); return; }

    xexec(
        "CREATE TEMP TABLE IF NOT EXISTS dep_closure(path TEXT PRIMARY KEY,depth INT);"
        "DELETE FROM dep_closure;");
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db,
          "INSERT OR IGNORE INTO dep_closure(path,depth) VALUES(?1,0)", -1, &st, 0);
      sqlite3_bind_text(st, 1, root, -1, SQLITE_TRANSIENT);
      sqlite3_step(st); sqlite3_finalize(st);
    }
    for (int d = 0; d < 100; d++) {
        int added = qintf( 0,
            "SELECT COUNT(*) FROM dep_edges e"
            " JOIN dep_closure c ON c.path=e.src AND c.depth=%d"
            " WHERE e.dst NOT IN(SELECT path FROM dep_closure)", d);
        if (!added) break;
        xexecf(
            "INSERT OR IGNORE INTO dep_closure(path,depth)"
            " SELECT DISTINCT e.dst,%d"
            " FROM dep_edges e JOIN dep_closure c ON c.path=e.src AND c.depth=%d"
            " WHERE e.dst NOT IN(SELECT path FROM dep_closure)", d + 1, d);
    }

    xexecf(
        "INSERT INTO lpane(rownum,id,parent_id,style,text)"
        " SELECT ROW_NUMBER()OVER(ORDER BY p.last_ts DESC)-1,"
        "  CAST(p.tgid AS TEXT),NULL,"
        "  CASE WHEN p.tgid IN(SELECT CAST(id AS INT) FROM search_hits) THEN 'search'"
        "       WHEN x.code IS NOT NULL AND x.code!=0 THEN 'error'"
        "       WHEN x.signal IS NOT NULL THEN 'error' ELSE 'normal' END,"
        "  printf('[%%d] %%s%%s %%s',p.tgid,COALESCE(" BNAME("p.exe") ",'?'),"
        "   CASE WHEN x.code IS NOT NULL AND x.code!=0 THEN ' ✗'"
        "        WHEN x.signal IS NOT NULL THEN printf(' ⚡%%d',x.signal)"
        "        WHEN x.code IS NOT NULL THEN ' ✓' ELSE '' END," DUR("p.last_ts-p.first_ts") ")"
        " FROM processes p"
        " LEFT JOIN events ev ON ev.tgid=p.tgid AND ev.event='EXIT'"
        " LEFT JOIN exit_events x ON x.eid=ev.id"
        " WHERE p.tgid IN("
        "  SELECT DISTINCT e.tgid FROM dep_edges e"
        "  JOIN dep_closure dc ON (e.dst=dc.path OR e.src=dc.path)"
        " )"
        " ORDER BY p.last_ts DESC");

    xexec( "DROP TABLE IF EXISTS dep_closure;DROP TABLE IF EXISTS dep_edges;");
}

/* ── Main rebuild_lpane callback ───────────────────────────────────── */
static void rebuild_lpane(void) {
    xexec( "DELETE FROM lpane;");
    int mode = qint( "SELECT mode FROM state", 0);
    switch (mode) {
        case 0: rebuild_procs(); break;
        case 1: rebuild_files(); break;
        case 2: rebuild_outputs(); break;
        case 3: rebuild_deps(); break;
        case 4: rebuild_rdeps(); break;
        case 5: rebuild_dep_cmds(); break;
        case 6: rebuild_rdep_cmds(); break;
    }
    if (mode == 0) apply_lp_filter();
    xexec( "UPDATE state SET cursor=MIN(cursor,MAX((SELECT COUNT(*)-1 FROM lpane),0));");
}

/* ── Rebuild rpane: process detail ─────────────────────────────────── */
static void rpane_proc( int tgid) {
    int tsm = qint( "SELECT ts_mode FROM state", 0);
    double bts = qdbl( "SELECT base_ts FROM state", 0);
    char ef[64] = "";
    { sqlite3_stmt *s;
      sqlite3_prepare_v2(g_db, "SELECT evfilt FROM state", -1, &s, 0);
      if (sqlite3_step(s) == SQLITE_ROW) {
          const char *t = (const char *)sqlite3_column_text(s, 0);
          if (t && t[0]) snprintf(ef, sizeof ef, "%s", t);
      }
      sqlite3_finalize(s);
    }

    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) VALUES(0,'heading','─── Process ───',-1,'','process')");
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 1,'cyan',printf('TGID:  %%d',tgid),-1,'','process' FROM processes WHERE tgid=%d", tgid);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 2,'cyan',printf('PPID:  %%d',ppid),0,CAST(ppid AS TEXT),'process' FROM processes WHERE tgid=%d AND ppid IS NOT NULL", tgid);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 3,'green',printf('EXE:   %%s',COALESCE(exe,'?')),-1,'','process' FROM processes WHERE tgid=%d", tgid);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 4,'green',printf('CWD:   %%s',COALESCE(cwd,'?')),-1,'','process' FROM processes WHERE tgid=%d", tgid);
    /* Argv */
    xexecf( "WITH RECURSIVE sp(i,rest,line) AS("
        " SELECT 0,SUBSTR(argv,INSTR(argv,char(10))+1),"
        "  CASE WHEN INSTR(argv,char(10))>0 THEN SUBSTR(argv,1,INSTR(argv,char(10))-1) ELSE argv END"
        "  FROM processes WHERE tgid=%d AND argv IS NOT NULL"
        " UNION ALL SELECT i+1,"
        "  CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,INSTR(rest,char(10))+1) ELSE '' END,"
        "  CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,1,INSTR(rest,char(10))-1) ELSE rest END"
        "  FROM sp WHERE LENGTH(rest)>0"
        ")INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 10+i,'normal',printf('  [%%d] %%s',i,line),-1,'','process' FROM sp", tgid);
    /* Exit */
    xexecf(
        "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 200,"
        " CASE WHEN x.signal IS NOT NULL THEN 'error' WHEN x.code!=0 THEN 'error' ELSE 'green' END,"
        " CASE WHEN x.signal IS NOT NULL THEN printf('Exit: signal %%d%%s',x.signal,"
        "   CASE WHEN x.core_dumped THEN ' (core)' ELSE '' END)"
        "  ELSE printf('Exit: %%s code=%%d',COALESCE(x.status,'?'),COALESCE(x.code,-1)) END,"
        " -1,'','process' FROM events ev JOIN exit_events x ON x.eid=ev.id WHERE ev.tgid=%d AND ev.event='EXIT'", tgid);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 201,'cyan','Duration: '||" DUR("last_ts-first_ts") ",-1,'','process' FROM processes WHERE tgid=%d", tgid);
    /* Children */
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) VALUES(300,'heading',printf('─── Children (%%d) ───',"
        "(SELECT COUNT(*) FROM processes WHERE ppid=%d)),-1,'','children')", tgid);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 300+ROW_NUMBER()OVER(ORDER BY first_ts),'normal',"
        " printf('  [%%d] %%s',tgid,COALESCE(" BNAME("exe") ",'?')),0,CAST(tgid AS TEXT),'children'"
        " FROM processes WHERE ppid=%d ORDER BY first_ts LIMIT 50", tgid);
    /* Events */
    char fc[128] = "";
    if (ef[0]) snprintf(fc, sizeof fc, " AND e.event='%s'", ef);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) VALUES(500,'heading',printf('─── Events (%%d)%%s ───',"
        "(SELECT COUNT(*) FROM events WHERE tgid=%d),"
        "CASE WHEN '%s'!='' THEN printf(' [%%s]','%s') ELSE '' END),-1,'','events')", tgid, ef, ef);
    xexecf(
        "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 501+ROW_NUMBER()OVER(ORDER BY e.ts),"
        " CASE WHEN e.event='EXEC' THEN 'cyan_bold'"
        "      WHEN e.event='EXIT' AND(COALESCE(x.code,0)!=0 OR x.signal IS NOT NULL) THEN 'error'"
        "      WHEN e.event='EXIT' THEN 'green'"
        "      WHEN e.event='OPEN' AND o.err IS NOT NULL THEN 'error'"
        "      WHEN e.event='OPEN' THEN 'green'"
        "      WHEN e.event IN('STDERR','STDOUT') THEN 'yellow' ELSE 'normal' END,"
        " printf('%%s %%-6s %%s',"
        "  CASE %d WHEN 0 THEN printf('%%.6f',e.ts)"
        "   WHEN 1 THEN printf('+%%.6f',e.ts-%f)"
        "   ELSE printf('Δ%%.6f',e.ts-COALESCE(LAG(e.ts)OVER(ORDER BY e.ts),e.ts)) END,"
        "  e.event,"
        "  CASE WHEN e.event='OPEN' THEN printf('%%s [%%s]%%s%%s',COALESCE(o.path,'?'),COALESCE(o.flags,'?'),"
        "    CASE WHEN o.fd IS NOT NULL THEN printf(' fd=%%d',o.fd) ELSE '' END,"
        "    CASE WHEN o.err IS NOT NULL THEN printf(' err=%%d',o.err) ELSE '' END)"
        "   WHEN e.event IN('STDERR','STDOUT') THEN SUBSTR(REPLACE(COALESCE(i.data,''),char(10),'↵'),1,200)"
        "   WHEN e.event='EXIT' THEN CASE WHEN x.signal IS NOT NULL THEN printf('signal=%%d',x.signal)"
        "    ELSE printf('%%s code=%%d',COALESCE(x.status,'?'),COALESCE(x.code,-1)) END"
        "   ELSE '' END),"
        " CASE WHEN e.event='OPEN' THEN 1 WHEN e.event IN('STDERR','STDOUT') THEN 2 ELSE -1 END,"
        " CASE WHEN e.event='OPEN' THEN COALESCE(o.path,'') WHEN e.event IN('STDERR','STDOUT') THEN CAST(e.id AS TEXT) ELSE '' END,"
        " 'events'"
        " FROM events e LEFT JOIN open_events o ON o.eid=e.id LEFT JOIN io_events i ON i.eid=e.id"
        " LEFT JOIN exit_events x ON x.eid=e.id WHERE e.tgid=%d%s ORDER BY e.ts LIMIT 5000",
        tsm, bts, tgid, fc);
}

static void rpane_file( const char *path) {
    sqlite3 *db = g_db;
    int tsm = qint( "SELECT ts_mode FROM state", 0);
    double bts = qdbl( "SELECT base_ts FROM state", 0);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) VALUES(0,'heading','─── File ───',-1,'','file')");
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) VALUES(1,'green',printf('Path: %s',?),-1,'','file')", -1, &st, 0);
    sqlite3_bind_text(st, 1, path, -1, SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st);
    sqlite3_prepare_v2(db,
        "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 2,'cyan',printf('Opens: %d  Errors: %d  Procs: %d',"
        " COUNT(*),SUM(o.err IS NOT NULL),COUNT(DISTINCT e.tgid)),-1,'','file'"
        " FROM open_events o JOIN events e ON e.id=o.eid WHERE o.path=?", -1, &st, 0);
    sqlite3_bind_text(st, 1, path, -1, SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) VALUES(10,'heading','─── Accesses ───',-1,'','accesses')");
    sqlite3_prepare_v2(db,
        "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 11+ROW_NUMBER()OVER(ORDER BY e.ts),"
        " CASE WHEN o.err IS NOT NULL THEN 'error' ELSE 'green' END,"
        " printf('%s  PID %d (%s)  [%s]%s%s',"
        "  CASE ?2 WHEN 0 THEN printf('%.6f',e.ts) WHEN 1 THEN printf('+%.6f',e.ts-?3)"
        "   ELSE printf('Δ%.6f',e.ts-COALESCE(LAG(e.ts)OVER(ORDER BY e.ts),e.ts)) END,"
        "  e.tgid,COALESCE(" BNAME("p.exe") ",'?'),COALESCE(o.flags,'?'),"
        "  CASE WHEN o.fd IS NOT NULL THEN printf(' fd=%d',o.fd) ELSE '' END,"
        "  CASE WHEN o.err IS NOT NULL THEN printf(' err=%d',o.err) ELSE '' END),"
        " 0,CAST(e.tgid AS TEXT),'accesses'"
        " FROM open_events o JOIN events e ON e.id=o.eid JOIN processes p ON p.tgid=e.tgid"
        " WHERE o.path=?1 ORDER BY e.ts LIMIT 5000", -1, &st, 0);
    sqlite3_bind_text(st, 1, path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, tsm);
    sqlite3_bind_double(st, 3, bts);
    sqlite3_step(st); sqlite3_finalize(st);
}

static void rpane_output( const char *id) {
    if (!strncmp(id, "io_", 3)) { rpane_proc(atoi(id + 3)); return; }
    int eid = atoi(id);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) VALUES(0,'heading','─── Output ───',-1,'','output')");
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 1,'cyan',printf('Stream: %%s  PID: %%d',i.stream,e.tgid),"
        "0,CAST(e.tgid AS TEXT),'output' FROM io_events i JOIN events e ON e.id=i.eid WHERE e.id=%d", eid);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 2,'green',printf('Process: %%s',COALESCE(p.exe,'?')),"
        "0,CAST(p.tgid AS TEXT),'output' FROM events e JOIN processes p ON p.tgid=e.tgid WHERE e.id=%d", eid);
    xexecf( "INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) VALUES(5,'heading','─── Content ───',-1,'','content')");
    xexecf( "WITH RECURSIVE sp(i,rest,line) AS("
        " SELECT 0,SUBSTR(data,INSTR(data,char(10))+1),"
        "  CASE WHEN INSTR(data,char(10))>0 THEN SUBSTR(data,1,INSTR(data,char(10))-1) ELSE data END"
        "  FROM io_events WHERE eid=%d"
        " UNION ALL SELECT i+1,"
        "  CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,INSTR(rest,char(10))+1) ELSE '' END,"
        "  CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,1,INSTR(rest,char(10))-1) ELSE rest END"
        "  FROM sp WHERE LENGTH(rest)>0"
        ")INSERT INTO rpane(rownum,style,text,link_mode,link_id,section) SELECT 10+i,'normal',line,-1,'','content' FROM sp", eid);
}

/* ── Main rebuild_rpane callback ───────────────────────────────────── */
static void rebuild_rpane(void) {
    sqlite3 *db = g_db;
    xexec( "DELETE FROM rpane;");
    int mode = qint( "SELECT mode FROM state", 0);
    int cursor = qint( "SELECT cursor FROM state", 0);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT id FROM lpane WHERE rownum=?", -1, &st, 0);
    sqlite3_bind_int(st, 1, cursor);
    char id[4096] = "";
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        if (t) snprintf(id, sizeof id, "%s", t);
    }
    sqlite3_finalize(st);
    if (!id[0]) return;
    switch (mode) {
        case 0: rpane_proc(atoi(id)); break;
        case 1: rpane_file(id); break;
        case 2: rpane_output(id); break;
        case 3: case 4: rpane_file(id); break;
        case 5: case 6: rpane_proc(atoi(id)); break;
    }

    /* Section collapse */
    xexec(
        "UPDATE rpane SET visible=0"
        " WHERE style!='heading'"
        "  AND section IN("
        "   SELECT section FROM rpane WHERE style='heading'"
        "    AND COALESCE((SELECT ex FROM expanded WHERE id='rp_'||section),1)=0);"
        "UPDATE rpane SET text=REPLACE(text,'───','▶──')"
        " WHERE style='heading'"
        "  AND COALESCE((SELECT ex FROM expanded WHERE id='rp_'||section),1)=0;"
        "UPDATE rpane SET text=REPLACE(text,'▶──','───')"
        " WHERE style='heading'"
        "  AND COALESCE((SELECT ex FROM expanded WHERE id='rp_'||section),1)=1;");

    xexec( "CREATE TEMP TABLE _rp AS SELECT ROW_NUMBER()OVER(ORDER BY rownum)-1 AS rn,"
        "style,text,link_mode,link_id,section,visible FROM rpane WHERE visible=1;"
        "DELETE FROM rpane;INSERT INTO rpane(rownum,style,text,link_mode,link_id,section,visible) SELECT*FROM _rp;DROP TABLE _rp;");

    /* Highlight search matches */
    { char sq[256] = "";
      { sqlite3_stmt *st2;
        sqlite3_prepare_v2(db, "SELECT search FROM state", -1, &st2, 0);
        if (sqlite3_step(st2) == SQLITE_ROW) {
            const char *t = (const char *)sqlite3_column_text(st2, 0);
            if (t && t[0]) snprintf(sq, sizeof sq, "%s", t);
        }
        sqlite3_finalize(st2);
      }
      if (sq[0]) {
          char lk[260]; snprintf(lk, sizeof lk, "%%%s%%", sq);
          sqlite3_stmt *st2;
          sqlite3_prepare_v2(db, "UPDATE rpane SET style='search' WHERE style='normal' AND text LIKE ?", -1, &st2, 0);
          sqlite3_bind_text(st2, 1, lk, -1, SQLITE_TRANSIENT);
          sqlite3_step(st2); sqlite3_finalize(st2);
      }
    }
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
    int c = qint( "SELECT cursor FROM state", 0);
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
    if (f >= 0) { xexecf( "UPDATE state SET cursor=%d,dscroll=0,dcursor=0", f); dirty_rp(); }
}

static void follow_link(tui_t *tui) {
    sqlite3 *db = g_db;
    int dc = qint( "SELECT dcursor FROM state", 0);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT link_mode,link_id FROM rpane WHERE rownum=? AND link_mode>=0", -1, &st, 0);
    sqlite3_bind_int(st, 1, dc);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int tm = sqlite3_column_int(st, 0);
        const char *ti = (const char *)sqlite3_column_text(st, 1);
        if (ti && ti[0]) {
            char tid[4096]; snprintf(tid, sizeof tid, "%s", ti);
            sqlite3_finalize(st);
            xexecf( "UPDATE state SET mode=%d,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0", tm);
            if (tm == 0) {
                int tg = atoi(tid);
                xexecf(
                    "WITH RECURSIVE a(p) AS(SELECT ppid FROM processes WHERE tgid=%d"
                    " UNION ALL SELECT ppid FROM processes JOIN a ON tgid=a.p WHERE ppid IS NOT NULL"
                    ")UPDATE expanded SET ex=1 WHERE id IN(SELECT CAST(p AS TEXT) FROM a)", tg);
            }
            rebuild_lpane();
            sqlite3_prepare_v2(db, "SELECT rownum FROM lpane WHERE id=?", -1, &st, 0);
            sqlite3_bind_text(st, 1, tid, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW)
                xexecf( "UPDATE state SET cursor=%d", sqlite3_column_int(st, 0));
            sqlite3_finalize(st);
            dirty_rp();
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
static void handle_key(tui_t *tui, int k) {
    int focus = qint( "SELECT focus FROM state", 0);
    int nf = qint( "SELECT COUNT(*) FROM lpane", 0);
    int nrp = qint( "SELECT COUNT(*) FROM rpane", 0);
    int rows = qint( "SELECT rows FROM state", 24);
    int pg = rows - 3;
    int mode = qint( "SELECT mode FROM state", 0);

    switch (k) {
    /* ── cursor / scroll ─────────────────────────────────────────── */
    case TUI_K_UP: case 'k':
        if (!focus) { xexec( "UPDATE state SET cursor=MAX(cursor-1,0),dscroll=0,dcursor=0"); dirty_rp(); }
        else xexec( "UPDATE state SET dcursor=MAX(dcursor-1,0)");
        break;
    case TUI_K_DOWN: case 'j':
        if (!focus) { xexecf( "UPDATE state SET cursor=MIN(cursor+1,%d),dscroll=0,dcursor=0", nf - 1); dirty_rp(); }
        else xexecf( "UPDATE state SET dcursor=MIN(dcursor+1,%d)", nrp - 1);
        break;
    case TUI_K_PGUP:
        if (!focus) { xexecf( "UPDATE state SET cursor=MAX(cursor-%d,0),dscroll=0,dcursor=0", pg); dirty_rp(); }
        else xexecf( "UPDATE state SET dcursor=MAX(dcursor-%d,0)", pg);
        break;
    case TUI_K_PGDN:
        if (!focus) { xexecf( "UPDATE state SET cursor=MIN(cursor+%d,%d),dscroll=0,dcursor=0", pg, nf - 1); dirty_rp(); }
        else xexecf( "UPDATE state SET dcursor=MIN(dcursor+%d,%d)", pg, nrp - 1);
        break;
    case TUI_K_HOME: case 'g':
        if (!focus) { xexec( "UPDATE state SET cursor=0,dscroll=0,dcursor=0"); dirty_rp(); }
        else xexec( "UPDATE state SET dcursor=0");
        break;
    case TUI_K_END:
        if (!focus) { xexecf( "UPDATE state SET cursor=%d,dscroll=0,dcursor=0", nf > 0 ? nf - 1 : 0); dirty_rp(); }
        else xexecf( "UPDATE state SET dcursor=%d", nrp > 0 ? nrp - 1 : 0);
        break;
    case TUI_K_TAB:
        xexec( "UPDATE state SET focus=1-focus,dcursor=0,dscroll=0");
        break;
    case TUI_K_ENTER: case '\n':
        if (focus) follow_link(tui);
        else xexec( "UPDATE state SET focus=1,dcursor=0,dscroll=0");
        break;

    /* ── business logic ──────────────────────────────────────────── */
    case 'G':
        xexec( "UPDATE state SET grouped=1-grouped,cursor=0,scroll=0,dscroll=0,dcursor=0");
        dirty_both();
        break;
    case TUI_K_RIGHT: case 'l':
        if (focus) {
            int dc = qint( "SELECT dcursor FROM state", 0);
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
                    dirty_rp();
                }
                break;
            }
            follow_link(tui);
            break;
        }
        { char id[256] = "";
          sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db, "SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)", -1, &st, 0);
          if (sqlite3_step(st) == SQLITE_ROW) {
              const char *t = (const char *)sqlite3_column_text(st, 0);
              if (t) snprintf(id, sizeof id, "%s", t);
          }
          sqlite3_finalize(st);
          if ((mode == 0 || mode == 1 || mode == 2) && id[0]) {
              int is_ex = qintf( 1, "SELECT COALESCE((SELECT ex FROM expanded WHERE id='%s'),1)", id);
              int has_ch = 0;
              if (mode == 0) has_ch = qintf( 0, "SELECT COUNT(*)>0 FROM processes WHERE ppid=%d", atoi(id));
              else if (mode == 1) has_ch = qintf( 0, "SELECT COUNT(*)>0 FROM lpane WHERE parent_id='%s'", id);
              else if (!strncmp(id, "io_", 3)) has_ch = 1;
              if (has_ch && !is_ex) { xexecf( "INSERT OR REPLACE INTO expanded(id,ex) VALUES('%s',1)", id); dirty_both(); break; }
          }
        }
        break;
    case TUI_K_LEFT: case 'h':
        if (focus) {
            int dc = qint( "SELECT dcursor FROM state", 0);
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
                    dirty_rp();
                }
                break;
            }
            break;
        }
        { char id[256] = "";
          sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db, "SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)", -1, &st, 0);
          if (sqlite3_step(st) == SQLITE_ROW) {
              const char *t = (const char *)sqlite3_column_text(st, 0);
              if (t) snprintf(id, sizeof id, "%s", t);
          }
          sqlite3_finalize(st);
          if (mode == 0 && id[0]) {
              int tgid = atoi(id);
              int has_ch = qintf( 0, "SELECT COUNT(*)>0 FROM processes WHERE ppid=%d", tgid);
              int is_ex = qintf( 1, "SELECT COALESCE((SELECT ex FROM expanded WHERE id='%s'),1)", id);
              if (has_ch && is_ex) { xexecf( "UPDATE expanded SET ex=0 WHERE id='%s'", id); dirty_both(); break; }
              int ppid = qintf( -1, "SELECT ppid FROM processes WHERE tgid=%d", tgid);
              if (ppid >= 0) {
                  int r = qintf( -1, "SELECT rownum FROM lpane WHERE id='%d'", ppid);
                  if (r >= 0) { xexecf( "UPDATE state SET cursor=%d,dscroll=0,dcursor=0", r); dirty_rp(); }
              }
          } else if (mode == 1 && id[0]) {
              int is_ex = qintf( 1, "SELECT COALESCE((SELECT ex FROM expanded WHERE id='%s'),1)", id);
              int has_ch = qintf( 0, "SELECT COUNT(*)>0 FROM lpane WHERE parent_id='%s'", id);
              if (has_ch && is_ex) { xexecf( "INSERT OR REPLACE INTO expanded(id,ex) VALUES('%s',0)", id); dirty_both(); break; }
              { sqlite3_stmt *s2;
                sqlite3_prepare_v2(g_db, "SELECT parent_id FROM lpane WHERE id=? LIMIT 1", -1, &s2, 0);
                sqlite3_bind_text(s2, 1, id, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(s2) == SQLITE_ROW) {
                    const char *pi = (const char *)sqlite3_column_text(s2, 0);
                    if (pi && pi[0]) {
                        int r = qintf( -1, "SELECT rownum FROM lpane WHERE id='%s'", pi);
                        if (r >= 0) { xexecf( "UPDATE state SET cursor=%d,dscroll=0,dcursor=0", r); dirty_rp(); }
                    }
                }
                sqlite3_finalize(s2);
              }
          } else if (mode == 2 && id[0]) {
              if (!strncmp(id, "io_", 3)) {
                  xexecf( "UPDATE expanded SET ex=0 WHERE id='%s'", id);
                  dirty_both();
              } else {
                  sqlite3_stmt *s2;
                  sqlite3_prepare_v2(g_db, "SELECT parent_id FROM lpane WHERE rownum=(SELECT cursor FROM state)", -1, &s2, 0);
                  if (sqlite3_step(s2) == SQLITE_ROW) {
                      const char *pi = (const char *)sqlite3_column_text(s2, 0);
                      if (pi) {
                          int r = qintf( -1, "SELECT rownum FROM lpane WHERE id='%s'", pi);
                          if (r >= 0) { xexecf( "UPDATE state SET cursor=%d,dscroll=0,dcursor=0", r); dirty_rp(); }
                      }
                  }
                  sqlite3_finalize(s2);
              }
          }
        }
        break;
    case 'e': case 'E':
        if (mode == 0) {
            char id[64] = "";
            sqlite3_stmt *st;
            sqlite3_prepare_v2(g_db, "SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)", -1, &st, 0);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *t = (const char *)sqlite3_column_text(st, 0);
                if (t) snprintf(id, sizeof id, "%s", t);
            }
            sqlite3_finalize(st);
            int tg = atoi(id);
            xexecf( "WITH RECURSIVE d(t) AS(SELECT %d UNION ALL SELECT c.tgid FROM processes c JOIN d ON c.ppid=d.t)"
                " UPDATE expanded SET ex=%d WHERE id IN(SELECT CAST(t AS TEXT) FROM d)", tg, k == 'e' ? 1 : 0);
            dirty_both();
        }
        break;
    case '1': xexec( "UPDATE state SET mode=0,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0,sort_key=0"); dirty_both(); break;
    case '2': xexec( "UPDATE state SET mode=1,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0,sort_key=0"); dirty_both(); break;
    case '3': xexec( "UPDATE state SET mode=2,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0,sort_key=0"); dirty_both(); break;
    case '4': xexec( "UPDATE state SET dep_root=COALESCE((SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),''),mode=3,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0"); dirty_both(); break;
    case '5': xexec( "UPDATE state SET dep_root=COALESCE((SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),''),mode=4,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0"); dirty_both(); break;
    case '6': xexec( "UPDATE state SET dep_root=COALESCE((SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),''),mode=5,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0"); dirty_both(); break;
    case '7': xexec( "UPDATE state SET dep_root=COALESCE((SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),''),mode=6,cursor=0,scroll=0,dscroll=0,dcursor=0,focus=0"); dirty_both(); break;
    case 'd': xexec( "UPDATE state SET dep_filter=1-dep_filter,cursor=0,scroll=0"); dirty_both(); break;
    case 's': xexec( "UPDATE state SET sort_key=(sort_key+1)%3,cursor=0,scroll=0"); dirty_both(); break;
    case 't': xexec( "UPDATE state SET ts_mode=(ts_mode+1)%3"); dirty_rp(); break;

    /* ── interactive terminal actions ─────────────────────────────── */
    case '/': {
        char buf[256] = "";
        if (tui_line_edit(tui, "/", buf, sizeof buf) && buf[0]) {
            sqlite3_stmt *st;
            sqlite3_prepare_v2(g_db, "UPDATE state SET search=?", -1, &st, 0);
            sqlite3_bind_text(st, 1, buf, -1, SQLITE_TRANSIENT);
            sqlite3_step(st); sqlite3_finalize(st);
            do_search(buf);
            dirty_both();
            sync_panes();
            jump_hit(1);
        }
    } break;
    case 'n': jump_hit(1); break;
    case 'N': jump_hit(-1); break;
    case 'f': {
        char buf[32] = "";
        if (tui_line_edit(tui, "Filter: ", buf, sizeof buf) && buf[0]) {
            for (char *p = buf; *p; p++) *p = toupper(*p);
            sqlite3_stmt *st;
            sqlite3_prepare_v2(g_db, "UPDATE state SET evfilt=?", -1, &st, 0);
            sqlite3_bind_text(st, 1, buf, -1, SQLITE_TRANSIENT);
            sqlite3_step(st); sqlite3_finalize(st);
            dirty_rp();
        }
    } break;
    case 'F': xexec( "UPDATE state SET evfilt=''"); dirty_rp(); break;
    case 'v': xexecf( "UPDATE state SET lp_filter=(lp_filter+1)%%3,cursor=0,scroll=0"); dirty_both(); break;
    case 'V': xexec( "UPDATE state SET lp_filter=0,cursor=0,scroll=0"); dirty_both(); break;
    case 'W': save_db(tui); break;
    case 'x': tui_sql_prompt(tui); break;
    case '?': tui_show_help(tui, HELP); break;
    }
    sync_panes();
}

/* ── on_key callback (returns non-zero to quit) ────────────────────── */
static int on_key_handler(tui_t *tui, int k) {
    if (k == 'q' || k == 'Q') return 1;
    handle_key(tui, k);
    return 0;
}

/* ── on_stream_end callback ────────────────────────────────────────── */
static void on_stream_end(void) {
    setup_fts();
    xexec( "UPDATE state SET lp_filter=0");
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

    /* Initial rebuild + process inbox */
    rebuild_lpane();
    rebuild_rpane();

    if (save_file[0]) save_to_file(save_file);
    process_inbox(NULL, 0);

    if (g_headless) { sqlite3_close(g_db); return 0; }
    if (save_file[0] && !cmd) { sqlite3_close(g_db); return 0; }

    /* ── App-driven event loop ─────────────────────────────────── */
    tui_t *tui = tui_open(g_db);
    if (!tui) { fprintf(stderr, "tv: cannot open terminal\n"); sqlite3_close(g_db); return 1; }

    /* Install SIGWINCH handler */
    struct sigaction sa = {0};
    sa.sa_handler = tui_sigwinch_handler;
    sigaction(SIGWINCH, &sa, 0);

    /* Stream read buffer */
    char rbuf[1<<20];
    int rbuf_len = 0;

    for (;;) {
        /* Check for terminal resize */
        if (tui_check_resize(tui)) {
            rebuild_lpane();
            rebuild_rpane();
        }

        /* Update status bar and render */
        update_status();
        tui_render(tui);

        /* Poll on tty_fd + optional trace_fd */
        fd_set rfds; FD_ZERO(&rfds);
        int tfd = tui_fd(tui);
        FD_SET(tfd, &rfds);
        int mfd = tfd;
        if (trace_fd >= 0) { FD_SET(trace_fd, &rfds); if (trace_fd > mfd) mfd = trace_fd; }
        int sel = select(mfd + 1, &rfds, NULL, NULL, NULL);
        if (sel < 0 && errno == EINTR) continue;

        /* Trace data */
        if (trace_fd >= 0 && sel > 0 && FD_ISSET(trace_fd, &rfds)) {
            int n = read(trace_fd, rbuf + rbuf_len,
                         (int)(sizeof(rbuf) - rbuf_len - 1));
            if (n <= 0) {
                if (rbuf_len > 0) {
                    rbuf[rbuf_len] = 0;
                    xexec("BEGIN");
                    ingest_line(rbuf);
                    xexec("COMMIT");
                    rbuf_len = 0;
                    process_inbox(tui, 1);
                }
                on_stream_end();
                if (trace_pipe) { pclose(trace_pipe); trace_pipe = NULL; trace_fd = -1; }
                else { close(trace_fd); trace_fd = -1; }
                rebuild_lpane();
                rebuild_rpane();
            } else {
                rbuf_len += n;
                int did = 0;
                xexec("BEGIN");
                while (1) {
                    char *nl = (char *)memchr(rbuf, '\n', rbuf_len);
                    if (!nl) break;
                    if (nl > rbuf && *(nl - 1) == '\r') *(nl - 1) = 0;
                    *nl = 0;
                    ingest_line(rbuf);
                    did++;
                    int used = (int)(nl - rbuf) + 1;
                    memmove(rbuf, nl + 1, rbuf_len - used);
                    rbuf_len -= used;
                }
                if (rbuf_len >= (int)(sizeof(rbuf) - 1)) {
                    rbuf[rbuf_len] = 0;
                    ingest_line(rbuf);
                    did++;
                    rbuf_len = 0;
                }
                xexec("COMMIT");
                if (did) {
                    process_inbox(tui, 1);
                    xexec("UPDATE state SET base_ts="
                        "(SELECT COALESCE(MIN(ts),0) FROM events) WHERE base_ts=0");
                    rebuild_lpane();
                    rebuild_rpane();
                }
            }
        }

        /* Reap child */
        if (child_pid > 0) {
            int ws;
            if (waitpid(child_pid, &ws, WNOHANG) == child_pid)
                child_pid = 0;
        }

        /* Keyboard */
        if (sel > 0 && FD_ISSET(tfd, &rfds)) {
            int k = tui_read_key(tui);
            if (k != TUI_K_NONE) {
                if (on_key_handler(tui, k)) break;
            }
        }
    }

    tui_close(tui);
    if (trace_pipe) { pclose(trace_pipe); trace_pipe = NULL; trace_fd = -1; }
    else if (trace_fd >= 0) { close(trace_fd); trace_fd = -1; }
    if (child_pid > 0) { kill(child_pid, SIGTERM); waitpid(child_pid, NULL, 0); }
    sqlite3_close(g_db);
    return 0;
}
