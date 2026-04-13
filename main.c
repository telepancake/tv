/*
 * main.c — Process trace viewer: business logic + entry point.
 *
 * This file contains:
 *   • SQLite database management (open, schema, queries)
 *   • SQL custom functions (regexp, canon_path, dir_part, depth)
 *   • Trace event processing (JSONL → DB)
 *   • Key dispatch (all application-specific key bindings)
 *   • Headless dump functions
 *   • argv parsing and uproctrace integration
 *
 * The generic TUI engine (engine.c) owns terminal I/O, the event loop,
 * rendering, navigation, and layout.  This file drives the application.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* resolve_path(raw_path, cwd) → canonical absolute path.
 * Handles pseudo-paths (no leading / or ., contains :), relative paths, and absolute paths. */
static void sql_resolve_path(sqlite3_context *ctx, int n, sqlite3_value **v) {
    (void)n;
    const char *raw = (const char *)sqlite3_value_text(v[0]);
    const char *cwd = (const char *)sqlite3_value_text(v[1]);
    if (!raw || !raw[0]) { sqlite3_result_null(ctx); return; }
    /* Pseudo paths (no leading / or ., contains :) → keep as-is */
    if (raw[0] != '/' && raw[0] != '.' && strchr(raw, ':')) {
        sqlite3_result_text(ctx, raw, -1, SQLITE_TRANSIENT); return;
    }
    char out[8192];
    if (raw[0] != '/') {
        if (cwd && cwd[0]) snprintf(out, sizeof out, "%s/%s", cwd, raw);
        else snprintf(out, sizeof out, "%s", raw);
    } else {
        snprintf(out, sizeof out, "%s", raw);
    }
    if (out[0] == '/') canon_path_c(out, sizeof out);
    sqlite3_result_text(ctx, out, -1, SQLITE_TRANSIENT);
}

/* is_sys_path(resolved_path, flag0) → 1 if this is an O_RDONLY open of a system path. */
static void sql_is_sys_path(sqlite3_context *ctx, int n, sqlite3_value **v) {
    (void)n;
    const char *path = (const char *)sqlite3_value_text(v[0]);
    const char *flag = (const char *)sqlite3_value_text(v[1]);
    if (!path || !flag || path[0] != '/' || strcmp(flag, "O_RDONLY") != 0) {
        sqlite3_result_int(ctx, 0); return;
    }
    static const char *sys[] = {"/usr/","/lib/","/lib64/","/bin/","/sbin/","/opt/","/srv/",NULL};
    for (int i = 0; sys[i]; i++)
        if (strncmp(path, sys[i], strlen(sys[i])) == 0) { sqlite3_result_int(ctx, 1); return; }
    sqlite3_result_int(ctx, 0);
}

static void sql_build_ftree(sqlite3_context *ctx, int n, sqlite3_value **v);

static void register_sql_funcs(sqlite3 *db) {
    sqlite3_create_function(db, "regexp",       2, SQLITE_UTF8, 0, sql_regexp,       0, 0);
    sqlite3_create_function(db, "canon_path",   1, SQLITE_UTF8, 0, sql_canon_path,   0, 0);
    sqlite3_create_function(db, "dir_part",     1, SQLITE_UTF8, 0, sql_dir_part,     0, 0);
    sqlite3_create_function(db, "depth",        1, SQLITE_UTF8, 0, sql_depth,        0, 0);
    sqlite3_create_function(db, "resolve_path", 2, SQLITE_UTF8, 0, sql_resolve_path, 0, 0);
    sqlite3_create_function(db, "is_sys_path",  2, SQLITE_UTF8, 0, sql_is_sys_path,  0, 0);
    sqlite3_create_function(db, "build_ftree",  0, SQLITE_UTF8, 0, sql_build_ftree,  0, 0);
}

/* ── Global TUI handle ──────────────────────────────────────────────── */
static tui_t *g_tui;

/* ── Sync engine cursor from state table ───────────────────────────── */
static void sync_engine_from_state(void) {
    if (!g_tui) return;
    sqlite3_stmt *st;
    sqlite3_prepare_v2(g_db,
        "SELECT cursor, cursor_id, dcursor, focus FROM state", -1, &st, 0);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int c  = sqlite3_column_int(st, 0);
        const char *cid = (const char *)sqlite3_column_text(st, 1);
        int dc = sqlite3_column_int(st, 2);
        int f  = sqlite3_column_int(st, 3);
        tui_set_cursor_idx(g_tui, "lpane", c);
        if (cid && cid[0]) tui_set_cursor(g_tui, "lpane", cid);
        tui_set_cursor_idx(g_tui, "rpane", dc);
        tui_focus(g_tui, f ? "rpane" : "lpane");
    }
    sqlite3_finalize(st);
}

/* ── Status bar update ─────────────────────────────────────────────── */
static void update_status(void) {
    static const char *mn[] = {"PROCS","FILES","OUTPUT","DEPS","RDEPS","DEP-CMDS","RDEP-CMDS"};
    static const char *tsl[] = {"abs","rel","Δ"};
    int mode = qint("SELECT mode FROM state", 0);
    int nf = qint("SELECT COUNT(*) FROM lpane", 0);
    int cursor = qint("SELECT cursor FROM state", 0);
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
/* Trace events are now processed by the _ingest_trace trigger in tv.sql.
 * The trigger fires on INSERT INTO inbox WHERE kind='trace'.
 * No C-side trace processing needed — ingest_line() does the INSERT. */

static int g_headless;

/* ── Key name → integer constant ───────────────────────────────────── */
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

/* ── build_ftree SQL function ─────────────────────────────────────── */
static void ftree_xr(sqlite3 *db, const char *sql) {
    char *e = 0; sqlite3_exec(db, sql, 0, 0, &e); if (e) sqlite3_free(e);
}
static void sql_build_ftree(sqlite3_context *ctx, int n, sqlite3_value **v) {
    (void)n; (void)v;
    sqlite3 *db = sqlite3_context_db_handle(ctx);

    int gr, sk;
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(db, "SELECT grouped,sort_key FROM state", -1, &st, 0);
      gr = 1; sk = 0;
      if (sqlite3_step(st) == SQLITE_ROW) {
          gr = sqlite3_column_int(st, 0);
          sk = sqlite3_column_int(st, 1);
      }
      sqlite3_finalize(st);
    }

    ftree_xr(db,"DELETE FROM _ftree");

    if (!gr) {
        const char *order;
        switch (sk) {
        case 1: order = "ORDER BY MIN(e.ts)"; break;
        case 2: order = "ORDER BY MAX(e.ts)"; break;
        default: order = "ORDER BY o.path"; break;
        }
        char sql[2048];
        snprintf(sql, sizeof sql,
            "INSERT INTO _ftree(rownum,id,parent_id,style,text)"
            " SELECT ROW_NUMBER()OVER(%s)-1,o.path,NULL,"
            "  CASE WHEN o.path IN(SELECT id FROM search_hits) THEN 'search'"
            "       WHEN SUM(CASE WHEN o.err IS NOT NULL THEN 1 ELSE 0 END)>0 THEN 'error'"
            "       ELSE 'normal' END,"
            "  printf('%%s  [%%d opens, %%d procs%%s]',o.path,COUNT(*),COUNT(DISTINCT e.tgid),"
            "   CASE WHEN SUM(o.err IS NOT NULL)>0 THEN printf(', %%d errs',SUM(o.err IS NOT NULL)) ELSE '' END)"
            " FROM open_events o JOIN events e ON e.id=o.eid WHERE o.path IS NOT NULL GROUP BY o.path",
            order);
        ftree_xr(db, sql);
        sqlite3_result_int(ctx, 1); return;
    }

    ftree_xr(db,
       "CREATE TEMP TABLE IF NOT EXISTS _fs(path TEXT NOT NULL, canon TEXT NOT NULL,"
       " opens INT, procs INT, errs INT);"
       "DELETE FROM _fs;"
       "INSERT INTO _fs SELECT o.path,canon_path(o.path),COUNT(*),"
       " COUNT(DISTINCT e.tgid),SUM(o.err IS NOT NULL)"
       " FROM open_events o JOIN events e ON e.id=o.eid"
       " WHERE o.path IS NOT NULL GROUP BY o.path");

    ftree_xr(db,
       "CREATE TEMP TABLE IF NOT EXISTS _dn(id INTEGER PRIMARY KEY,"
       " path TEXT NOT NULL, parent_path TEXT, name TEXT,"
       " opens INT DEFAULT 0, procs INT DEFAULT 0, errs INT DEFAULT 0);"
       "DELETE FROM _dn;"
       "WITH RECURSIVE dirs(d) AS("
       "  SELECT DISTINCT dir_part(canon) FROM _fs WHERE INSTR(canon,'/')>0"
       "  UNION SELECT dir_part(d) FROM dirs WHERE LENGTH(d)>1 AND INSTR(d,'/')>0)"
       "INSERT INTO _dn(path,parent_path,name)"
       " SELECT d,"
       "  CASE WHEN d='/' THEN NULL WHEN INSTR(SUBSTR(d,2),'/')=0 THEN '/'"
       "   ELSE dir_part(d) END,"
       "  REPLACE(d,RTRIM(d,REPLACE(d,'/','')),'') FROM dirs WHERE d IS NOT NULL AND LENGTH(d)>0;"
       "CREATE INDEX IF NOT EXISTS ix_dn_p ON _dn(path);"
       "CREATE INDEX IF NOT EXISTS ix_dn_pp ON _dn(parent_path);"
       "UPDATE _dn SET"
       " opens=(SELECT COALESCE(SUM(f.opens),0) FROM _fs f WHERE f.canon LIKE _dn.path||'/%'),"
       " procs=(SELECT COALESCE(SUM(f.procs),0) FROM _fs f WHERE f.canon LIKE _dn.path||'/%'),"
       " errs =(SELECT COALESCE(SUM(f.errs),0)  FROM _fs f WHERE f.canon LIKE _dn.path||'/%');"
       "INSERT OR IGNORE INTO expanded(id,ex) SELECT path,1 FROM _dn");

    ftree_xr(db,
       "INSERT INTO _ftree(rownum,id,parent_id,style,text)"
       " WITH RECURSIVE"
       "  roots(sort_key,path,parent_path,name,opens,procs,errs,is_dir,depth) AS("
       "   SELECT printf('0/%s',name),path,parent_path,name,opens,procs,errs,1,0"
       "    FROM _dn WHERE parent_path IS NULL OR parent_path NOT IN(SELECT path FROM _dn)"
       "   UNION ALL"
       "   SELECT printf('1/%s',REPLACE(canon,RTRIM(canon,REPLACE(canon,'/','')),'')),"
       "    path,NULL,REPLACE(canon,RTRIM(canon,REPLACE(canon,'/','')),''),opens,procs,errs,0,0"
       "    FROM _fs WHERE INSTR(canon,'/')=0"
       "     OR dir_part(canon) NOT IN(SELECT path FROM _dn)),"
       "  tree(sort_key,path,parent_path,name,opens,procs,errs,is_dir,depth) AS("
       "   SELECT * FROM roots"
       "   UNION ALL"
       "   SELECT t.sort_key||'/0/'||d.name,d.path,d.parent_path,d.name,"
       "    d.opens,d.procs,d.errs,1,t.depth+1"
       "    FROM tree t JOIN _dn d ON d.parent_path=t.path"
       "    WHERE t.is_dir=1 AND COALESCE((SELECT ex FROM expanded WHERE id=t.path),1)=1"
       "   UNION ALL"
       "   SELECT t.sort_key||'/1/'||REPLACE(f.canon,RTRIM(f.canon,REPLACE(f.canon,'/','')),''),"
       "    f.path,dir_part(f.canon),"
       "    REPLACE(f.canon,RTRIM(f.canon,REPLACE(f.canon,'/','')),''),"
       "    f.opens,f.procs,f.errs,0,t.depth+1"
       "    FROM tree t JOIN _fs f ON dir_part(f.canon)=t.path"
       "    WHERE t.is_dir=1 AND COALESCE((SELECT ex FROM expanded WHERE id=t.path),1)=1)"
       " SELECT ROW_NUMBER()OVER(ORDER BY sort_key)-1,path,parent_path,"
       "  CASE WHEN path IN(SELECT id FROM search_hits) THEN 'search'"
       "       WHEN errs>0 THEN 'error' ELSE 'normal' END,"
       "  printf('%*s%s%s  [%d opens, %d procs%s]',depth*2,'',"
       "   CASE WHEN is_dir AND COALESCE((SELECT ex FROM expanded WHERE id=path),1)=1"
       "    THEN '▼ ' WHEN is_dir THEN '▶ ' ELSE '  ' END,"
       "   name||CASE WHEN is_dir THEN '/' ELSE '' END,"
       "   opens,procs,"
       "   CASE WHEN errs>0 THEN printf(', %d errs',errs) ELSE '' END)"
       " FROM tree");

    ftree_xr(db,"DROP TABLE IF EXISTS _fs;DROP TABLE IF EXISTS _dn");
    sqlite3_result_int(ctx, 1);
}

/* ── Search ────────────────────────────────────────────────────────── */
static void do_search(const char *q) {
    xexec("DELETE FROM search_hits");
    if (!q || !q[0]) return;
    int mode = qint("SELECT mode FROM state", 0);
    char lk[512]; snprintf(lk, sizeof lk, "%%%s%%", q);
    sqlite3_stmt *st;
    if (mode == 0 || mode == 5 || mode == 6) {
        if (qint("SELECT has_fts FROM state", 0)) {
            char fq[512]; snprintf(fq, sizeof fq, "\"%s\"*", q);
            sqlite3_prepare_v2(g_db,
                "INSERT OR IGNORE INTO search_hits(id)"
                " SELECT DISTINCT CAST(pid AS TEXT) FROM fts WHERE fts MATCH ?",
                -1, &st, 0);
            sqlite3_bind_text(st, 1, fq, -1, SQLITE_TRANSIENT);
            sqlite3_step(st); sqlite3_finalize(st);
        }
        sqlite3_prepare_v2(g_db,
            "INSERT OR IGNORE INTO search_hits(id)"
            " SELECT CAST(tgid AS TEXT) FROM processes"
            " WHERE CAST(tgid AS TEXT) LIKE ?1 OR exe LIKE ?1 OR argv LIKE ?1",
            -1, &st, 0);
        sqlite3_bind_text(st, 1, lk, -1, SQLITE_TRANSIENT);
        sqlite3_step(st); sqlite3_finalize(st);
    } else if (mode == 1 || mode == 3 || mode == 4) {
        sqlite3_prepare_v2(g_db,
            "INSERT OR IGNORE INTO search_hits(id)"
            " SELECT DISTINCT path FROM open_events WHERE path LIKE ?",
            -1, &st, 0);
        sqlite3_bind_text(st, 1, lk, -1, SQLITE_TRANSIENT);
        sqlite3_step(st); sqlite3_finalize(st);
    } else {
        sqlite3_prepare_v2(g_db,
            "INSERT OR IGNORE INTO search_hits(id)"
            " SELECT CAST(e.id AS TEXT) FROM io_events i"
            " JOIN events e ON e.id=i.eid WHERE i.data LIKE ?",
            -1, &st, 0);
        sqlite3_bind_text(st, 1, lk, -1, SQLITE_TRANSIENT);
        sqlite3_step(st); sqlite3_finalize(st);
    }
}

/* ── Follow rpane link ─────────────────────────────────────────────── */
static void follow_link(int rpane_row) {
    sqlite3_stmt *st;
    sqlite3_prepare_v2(g_db,
        "SELECT link_mode,link_id FROM rpane WHERE rownum=? AND link_mode>=0",
        -1, &st, 0);
    sqlite3_bind_int(st, 1, rpane_row);
    if (sqlite3_step(st) == SQLITE_ROW) {
        int tm = sqlite3_column_int(st, 0);
        const char *ti = (const char *)sqlite3_column_text(st, 1);
        if (ti && ti[0]) {
            char tid[4096]; snprintf(tid, sizeof tid, "%s", ti);
            sqlite3_finalize(st);
            xexecf("UPDATE state SET mode=%d,cursor=0,cursor_id='',scroll=0,"
                   "dscroll=0,dcursor=0,focus=0", tm);
            if (tm == 0) {
                int tg = atoi(tid);
                xexecf(
                    "WITH RECURSIVE a(p) AS(SELECT ppid FROM processes WHERE tgid=%d"
                    " UNION ALL SELECT ppid FROM processes JOIN a ON tgid=a.p"
                    " WHERE ppid IS NOT NULL"
                    ")UPDATE expanded SET ex=1 WHERE id IN(SELECT CAST(p AS TEXT) FROM a)", tg);
            } else if (tm == 1) {
                xexec("SELECT build_ftree()");
            }
            sqlite3_prepare_v2(g_db, "SELECT rownum FROM lpane WHERE id=?", -1, &st, 0);
            sqlite3_bind_text(st, 1, tid, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) {
                int r = sqlite3_column_int(st, 0);
                sqlite3_stmt *s2;
                sqlite3_prepare_v2(g_db, "UPDATE state SET cursor=?,cursor_id=?", -1, &s2, 0);
                sqlite3_bind_int(s2, 1, r);
                sqlite3_bind_text(s2, 2, tid, -1, SQLITE_TRANSIENT);
                sqlite3_step(s2); sqlite3_finalize(s2);
            }
            sqlite3_finalize(st);
            return;
        }
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

/* ── Process _outbox after trigger fires ───────────────────────────── */
/* Returns TUI_QUIT if quit was requested, TUI_HANDLED otherwise. */
static int process_outbox(tui_t *tui) {
    int result = TUI_HANDLED;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(g_db,
        "SELECT id,cmd,COALESCE(arg,'') FROM _outbox ORDER BY id", -1, &st, 0) != SQLITE_OK)
        return result;
    struct { long long id; char cmd[32]; char arg[4096]; } buf[16];
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW && n < 16) {
        buf[n].id = sqlite3_column_int64(st, 0);
        const char *c = (const char *)sqlite3_column_text(st, 1);
        const char *a = (const char *)sqlite3_column_text(st, 2);
        snprintf(buf[n].cmd, sizeof buf[n].cmd, "%s", c ? c : "");
        snprintf(buf[n].arg, sizeof buf[n].arg, "%s", a ? a : "");
        n++;
    }
    sqlite3_finalize(st);
    sqlite3_exec(g_db, "DELETE FROM _outbox", 0, 0, 0);

    for (int i = 0; i < n; i++) {
        const char *cmd = buf[i].cmd;
        const char *arg = buf[i].arg;

        if (strcmp(cmd, "quit") == 0) {
            result = TUI_QUIT;
        } else if (strcmp(cmd, "follow_link") == 0) {
            follow_link(atoi(arg));
            sync_engine_from_state();
            tui_dirty(tui, NULL);
        } else if (strcmp(cmd, "build_ftree") == 0) {
            xexec("SELECT build_ftree()");
            tui_dirty(tui, NULL);
        } else if (strcmp(cmd, "prompt_search") == 0) {
            char buf2[256] = "";
            if (tui_line_edit(tui, "/", buf2, sizeof buf2) && buf2[0]) {
                sqlite3_stmt *s2;
                sqlite3_prepare_v2(g_db, "UPDATE state SET search=?", -1, &s2, 0);
                sqlite3_bind_text(s2, 1, buf2, -1, SQLITE_TRANSIENT);
                sqlite3_step(s2); sqlite3_finalize(s2);
                do_search(buf2);
                if (qint("SELECT mode FROM state", 0) == 1) xexec("SELECT build_ftree()");
                /* Jump to first hit */
                xexec("UPDATE state SET cursor=COALESCE("
                      "(SELECT MIN(rownum) FROM lpane WHERE id IN (SELECT id FROM search_hits)),"
                      "cursor), dscroll=0, dcursor=0");
                xexec("UPDATE state SET cursor_id=COALESCE("
                      "(SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),'')");
                tui_dirty(tui, NULL);
            }
        } else if (strcmp(cmd, "prompt_filter") == 0) {
            char buf2[32] = "";
            if (tui_line_edit(tui, "Filter: ", buf2, sizeof buf2) && buf2[0]) {
                for (char *p = buf2; *p; p++) *p = toupper(*p);
                sqlite3_stmt *s2;
                sqlite3_prepare_v2(g_db, "UPDATE state SET evfilt=?", -1, &s2, 0);
                sqlite3_bind_text(s2, 1, buf2, -1, SQLITE_TRANSIENT);
                sqlite3_step(s2); sqlite3_finalize(s2);
                tui_dirty(tui, "rpane");
            }
        } else if (strcmp(cmd, "prompt_save") == 0) {
            char fname[256] = "trace.db";
            if (tui_line_edit(tui, "Save to: ", fname, sizeof fname) && fname[0])
                save_to_file(fname);
        } else if (strcmp(cmd, "prompt_sql") == 0) {
            tui_sql_prompt(tui);
        } else if (strcmp(cmd, "show_help") == 0) {
            tui_show_help(tui, HELP);
        } else if (strcmp(cmd, "print") == 0) {
            sync_engine_from_state();
            tui_dump(tui, arg, stdout);
            g_headless = 1;
        }
    }
    return result;
}

/* ── Insert key event into inbox (trigger handles it) ──────────────── */
static void submit_key(int key) {
    int focus = qint("SELECT focus FROM state", 0);
    int cursor = qint("SELECT cursor FROM state", 0);
    char row_id[4096] = "";
    { sqlite3_stmt *st;
      sqlite3_prepare_v2(g_db,
          "SELECT COALESCE(cursor_id,'') FROM state", -1, &st, 0);
      if (sqlite3_step(st) == SQLITE_ROW) {
          const char *v = (const char *)sqlite3_column_text(st, 0);
          if (v) snprintf(row_id, sizeof row_id, "%s", v);
      }
      sqlite3_finalize(st);
    }
    int rows = qint("SELECT rows FROM state", 24);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(g_db,
        "INSERT INTO inbox(kind,data) VALUES('key',"
        "json_object('key',?1,'panel',?2,'cursor',?3,'row_id',?4,'focus',?5,'rows',?6))",
        -1, &st, 0);
    sqlite3_bind_int(st, 1, key);
    sqlite3_bind_text(st, 2, focus ? "rpane" : "lpane", -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, cursor);
    sqlite3_bind_text(st, 4, row_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, focus);
    sqlite3_bind_int(st, 6, rows);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

/* ── Process pending input rows from inbox ─────────────────────────── */
static void process_inbox(tui_t *tui) {
    /* Input events may have been handled by triggers already (if triggers
     * existed during ingest_file).  We also handle stale input rows
     * that were inserted before triggers existed (--trace mode). */
    static char data[1 << 20];
    for (;;) {
        long long id = -1; data[0] = 0;
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "SELECT id,data FROM inbox WHERE kind='input' ORDER BY id LIMIT 1",
              -1, &st, 0);
          if (sqlite3_step(st) == SQLITE_ROW) {
              id = sqlite3_column_int64(st, 0);
              const char *d = (const char *)sqlite3_column_text(st, 1);
              if (d) snprintf(data, sizeof data - 1, "%s", d);
          }
          sqlite3_finalize(st);
        }
        if (id < 0) break;

        /* Parse the input type */
        char inp[32] = "";
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(g_db,
              "SELECT COALESCE(json_extract(?1,'$.input'),'')", -1, &st, 0);
          sqlite3_bind_text(st, 1, data, -1, SQLITE_TRANSIENT);
          if (sqlite3_step(st) == SQLITE_ROW) {
              const char *v = (const char *)sqlite3_column_text(st, 0);
              if (v) snprintf(inp, sizeof inp, "%s", v);
          }
          sqlite3_finalize(st);
        }

        if (strcmp(inp, "key") == 0) {
            xexecf("DELETE FROM inbox WHERE id=%lld", id);
            char keyname[64] = "";
            { sqlite3_stmt *st;
              sqlite3_prepare_v2(g_db,
                  "SELECT COALESCE(json_extract(?1,'$.key'),'')", -1, &st, 0);
              sqlite3_bind_text(st, 1, data, -1, SQLITE_TRANSIENT);
              if (sqlite3_step(st) == SQLITE_ROW) {
                  const char *v = (const char *)sqlite3_column_text(st, 0);
                  if (v) snprintf(keyname, sizeof keyname, "%s", v);
              }
              sqlite3_finalize(st);
            }
            int k = parse_key_name(keyname);
            if (k != TUI_K_NONE) {
                submit_key(k);
                sync_engine_from_state();
                tui_dirty(tui, NULL);
                process_outbox(tui);
            }
        } else {
            /* Delete and re-insert to fire the trigger (row may have been
             * inserted before triggers existed in --trace mode) */
            xexecf("DELETE FROM inbox WHERE id=%lld", id);
            { sqlite3_stmt *st;
              sqlite3_prepare_v2(g_db,
                  "INSERT INTO inbox(kind,data) VALUES('input',?)", -1, &st, 0);
              sqlite3_bind_text(st, 1, data, -1, SQLITE_TRANSIENT);
              sqlite3_step(st); sqlite3_finalize(st);
            }
            sync_engine_from_state();
            tui_dirty(tui, NULL);
            process_outbox(tui);
        }
    }
    /* Always drain outbox (triggers may have fired during ingest_file
     * when triggers already existed, e.g. --load + --trace) */
    sync_engine_from_state();
    process_outbox(tui);
}

/* ── on_key callback ───────────────────────────────────────────────── */
static int on_key_cb(tui_t *tui, int key, const char *panel,
                     int cursor, const char *row_id, void *ctx) {
    (void)ctx; (void)panel; (void)cursor; (void)row_id;
    if (key == TUI_K_NONE) {
        /* Post-navigation: engine already moved cursor.
         * This is only called in interactive mode for default_nav.
         * We don't use default_nav anymore — trigger handles nav. */
        return TUI_HANDLED;
    }
    /* Insert into inbox; trigger handles all state updates */
    submit_key(key);
    int result = process_outbox(tui);
    /* build_ftree after mode changes to file mode */
    if (qint("SELECT mode FROM state", 0) == 1) {
        /* ftree may need rebuild */
    }
    sync_engine_from_state();
    tui_dirty(tui, NULL);
    update_status();
    return result == TUI_QUIT ? TUI_QUIT : TUI_HANDLED;
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

enum live_trace_backend {
    LIVE_TRACE_BACKEND_AUTO = 0,
    LIVE_TRACE_BACKEND_MODULE,
    LIVE_TRACE_BACKEND_SUD,
    LIVE_TRACE_BACKEND_PTRACE,
};

int main(int argc, char **argv) {
    /* --uproctrace: delegate entirely to uproctrace_main() */
    if (argc >= 2 && strcmp(argv[1], "--uproctrace") == 0)
        return uproctrace_main(argc - 1, argv + 1);

    int load_mode = 0;
    enum live_trace_backend live_backend = LIVE_TRACE_BACKEND_AUTO;
    char load_file[256] = "", trace_file[256] = "", save_file[256] = "";
    char **cmd = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--load") == 0 && i + 1 < argc) { load_mode = 1; snprintf(load_file, sizeof load_file, "%s", argv[++i]); }
        else if (strcmp(argv[i], "--trace") == 0 && i + 1 < argc) snprintf(trace_file, sizeof trace_file, "%s", argv[++i]);
        else if (strcmp(argv[i], "--save") == 0 && i + 1 < argc) snprintf(save_file, sizeof save_file, "%s", argv[++i]);
        else if (strcmp(argv[i], "--module") == 0) live_backend = LIVE_TRACE_BACKEND_MODULE;
        else if (strcmp(argv[i], "--sud") == 0) live_backend = LIVE_TRACE_BACKEND_SUD;
        else if (strcmp(argv[i], "--ptrace") == 0) live_backend = LIVE_TRACE_BACKEND_PTRACE;
        else if (strcmp(argv[i], "--") == 0 && i + 1 < argc) { cmd = argv + i + 1; break; }
    }
    if (!load_mode && !trace_file[0] && !cmd) {
        fprintf(stderr, "Usage: tv [--module|--sud|--ptrace] -- <command> [args...]\n"
            "       tv --load <file.db>\n"
            "       tv --trace <file.jsonl> [--save <file.db>]\n"
            "       tv --load <file.db> --trace <input.jsonl>\n"
            "       tv --uproctrace [-o FILE] [--module|--sud|--ptrace|--backend auto|module|sud|ptrace] -- <command> [args...]\n"
            "\n  --ptrace   Force ptrace backend (default: use proctrace kernel module if available)\n"
            "  --sud      Force sudtrace backend\n"
            "  --module   Force proctrace kernel module backend\n"
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
        xexec(tv_sql_setup);
        setup_fts();
    } else {
        xexec(tv_sql_schema);
        xexec(tv_sql_setup);
        xexecf("INSERT OR REPLACE INTO _config(key,val) VALUES('own_tgid','%d')", (int)getpid());
        int pipefd[2];
        if (pipe(pipefd) < 0) { fprintf(stderr, "tv: pipe\n"); exit(1); }
        child_pid = fork();
        if (child_pid < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            fprintf(stderr, "tv: fork\n");
            exit(1);
        }
        if (child_pid == 0) {
            close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0) {
                perror("dup2");
                _exit(127);
            }
            close(pipefd[1]);

            size_t cmdc = 0;
            while (cmd[cmdc]) cmdc++;
            size_t extra = 2 + cmdc + 1;
            if (live_backend != LIVE_TRACE_BACKEND_AUTO) extra++;
            char **uargv = calloc(extra, sizeof(*uargv));
            if (!uargv) {
                perror("calloc");
                _exit(127);
            }
            size_t ui = 0;
            uargv[ui++] = "--uproctrace";
            if (live_backend == LIVE_TRACE_BACKEND_MODULE) uargv[ui++] = "--module";
            else if (live_backend == LIVE_TRACE_BACKEND_SUD) uargv[ui++] = "--sud";
            else if (live_backend == LIVE_TRACE_BACKEND_PTRACE) uargv[ui++] = "--ptrace";
            uargv[ui++] = "--";
            for (size_t j = 0; j < cmdc; j++) uargv[ui++] = cmd[j];
            uargv[ui] = NULL;
            _exit(uproctrace_main((int)ui, uargv));
        }
        close(pipefd[1]);
        trace_fd = pipefd[0];
        xexec("UPDATE state SET lp_filter=2");
    }

    /* Initial setup: populate _ftree if starting in file mode */
    if (qint("SELECT mode FROM state", 0) == 1) xexec("SELECT build_ftree()");
    xexec("UPDATE state SET cursor_id=COALESCE("
          "(SELECT id FROM lpane WHERE rownum=(SELECT cursor FROM state)),'')");

    if (save_file[0]) save_to_file(save_file);

    /* Create engine — headless for test mode, terminal for interactive */
    tui_t *tui;
    int headless_mode = 0;
    {   /* Check if there are pending input commands → headless mode */
        int pending = qint("SELECT COUNT(*) FROM inbox WHERE kind='input'", 0);
        if (pending > 0 || (trace_file[0] && !cmd)) headless_mode = 1;
    }

    if (headless_mode) {
        tui = tui_open_headless(g_db);
    } else {
        tui = tui_open(g_db);
    }
    if (!tui) {
        if (!headless_mode) fprintf(stderr, "tv: cannot open terminal\n");
        sqlite3_close(g_db);
        return headless_mode ? 0 : 1;
    }
    g_tui = tui;

    /* Layout from _layout table in DB */
    tui_load_layout(tui);

    /* Focus starts on lpane */
    tui_focus(tui, "lpane");

    /* Register key handler */
    tui_on_key(tui, on_key_cb, NULL);

    /* Process any pending input commands (headless test mode) */
    process_inbox(tui);

    if (g_headless || (save_file[0] && !cmd)) {
        g_tui = NULL;
        tui_close(tui);
        sqlite3_close(g_db);
        return 0;
    }

    /* ── Engine-driven event loop ──────────────────────────────── */
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
