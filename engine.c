/*
 * engine.c — Generic TUI engine for a two-pane SQLite-driven viewer.
 *
 * See engine.h for the public API.  This file contains:
 *   • SQLite DB helpers (xexec, qint, etc.)
 *   • Terminal management (raw mode, screen buffer, key reading)
 *   • Two-pane rendering from lpane/rpane tables
 *   • Main event loop (keyboard + streaming fd)
 *   • Inbox processing (dispatch to callbacks)
 *   • Utility screens (help, SQL prompt, save)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>

#include "engine.h"

/* ── Engine state ──────────────────────────────────────────────────── */
struct tv_engine {
    sqlite3       *db;
    tv_callbacks   cb;

    /* Streaming ingest */
    int            own_tgid;
    char           rbuf[1<<20];
    int            rbuf_len;

    /* TUI state */
    int            headless;
    int            need_render;
    struct termios orig_tios;
    int            tty_fd;
    int            tty_raw;

    /* Screen buffer */
    char          *scr;
    int            scr_len;
    int            scr_cap;
};

/* Global flag for SIGWINCH (must be file-scope for signal handler) */
static volatile int g_resized = 1;

/* ── Helpers ───────────────────────────────────────────────────────── */
static void die(const char *m) {
    fprintf(stderr, "tv: %s\n", m);
    exit(1);
}

/* ── DB helpers ────────────────────────────────────────────────────── */
sqlite3 *tv_db(tv_engine *eng) { return eng->db; }

void tv_xexec(tv_engine *eng, const char *sql) {
    char *e;
    if (sqlite3_exec(eng->db, sql, 0, 0, &e) != SQLITE_OK) {
        fprintf(stderr, "sql: %s\n%.300s\n", e, sql);
        sqlite3_free(e);
        exit(1);
    }
}

void tv_xexecf(tv_engine *eng, const char *fmt, ...) {
    char b[16384];
    va_list a;
    va_start(a, fmt);
    vsnprintf(b, sizeof b, fmt, a);
    va_end(a);
    tv_xexec(eng, b);
}

int tv_qint(tv_engine *eng, const char *sql, int def) {
    sqlite3_stmt *s;
    int r = def;
    if (sqlite3_prepare_v2(eng->db, sql, -1, &s, 0) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) r = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
    }
    return r;
}

int tv_qintf(tv_engine *eng, int def, const char *fmt, ...) {
    va_list a;
    va_start(a, fmt);
    char *sql = sqlite3_vmprintf(fmt, a);
    va_end(a);
    if (!sql) return def;
    int r = tv_qint(eng, sql, def);
    sqlite3_free(sql);
    return r;
}

double tv_qdbl(tv_engine *eng, const char *sql, double def) {
    sqlite3_stmt *s;
    double r = def;
    if (sqlite3_prepare_v2(eng->db, sql, -1, &s, 0) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) r = sqlite3_column_double(s, 0);
        sqlite3_finalize(s);
    }
    return r;
}

/* ── Pane dirty flags ──────────────────────────────────────────────── */
void tv_dirty_rp(tv_engine *eng)   { tv_xexec(eng, "UPDATE outbox SET rr=1"); eng->need_render = 1; }
void tv_dirty_lp(tv_engine *eng)   { tv_xexec(eng, "UPDATE outbox SET rl=1"); eng->need_render = 1; }
void tv_dirty_both(tv_engine *eng)  { tv_xexec(eng, "UPDATE outbox SET rl=1,rr=1"); eng->need_render = 1; }

void tv_sync_panes(tv_engine *eng) {
    int rl = tv_qint(eng, "SELECT rl FROM outbox", 0);
    int rr = tv_qint(eng, "SELECT rr FROM outbox", 0);
    if (rl || rr) tv_xexec(eng, "UPDATE outbox SET rl=0,rr=0");
    if (rl && eng->cb.rebuild_lpane) eng->cb.rebuild_lpane(eng, eng->cb.app_data);
    if (rr && eng->cb.rebuild_rpane) eng->cb.rebuild_rpane(eng, eng->cb.app_data);
}

/* ── State accessors ───────────────────────────────────────────────── */
void tv_set_headless(tv_engine *eng, int h)  { eng->headless = h; }
int  tv_is_headless(tv_engine *eng)          { return eng->headless; }
void tv_set_own_tgid(tv_engine *eng, int t)  { eng->own_tgid = t; }
int  tv_own_tgid(tv_engine *eng)             { return eng->own_tgid; }
void tv_need_render(tv_engine *eng)          { eng->need_render = 1; }

/* ── Screen buffer ─────────────────────────────────────────────────── */
static void sa(tv_engine *eng, const char *s, int n) {
    if (eng->scr_len + n + 1 > eng->scr_cap) {
        eng->scr_cap = (eng->scr_len + n + 1) * 2;
        if (eng->scr_cap < 8192) eng->scr_cap = 8192;
        eng->scr = realloc(eng->scr, eng->scr_cap);
    }
    memcpy(eng->scr + eng->scr_len, s, n);
    eng->scr_len += n;
}
static void sp(tv_engine *eng, const char *s) { sa(eng, s, strlen(s)); }
static void sf(tv_engine *eng, const char *fmt, ...) {
    char t[4096];
    va_list a;
    va_start(a, fmt);
    int n = vsnprintf(t, sizeof t, fmt, a);
    va_end(a);
    if (n > 0) sa(eng, t, n < (int)sizeof t ? n : (int)sizeof t - 1);
}
static void sflush(tv_engine *eng) {
    if (eng->scr_len > 0 && eng->tty_fd >= 0)
        (void)write(eng->tty_fd, eng->scr, eng->scr_len);
    eng->scr_len = 0;
}
static void sputw(tv_engine *eng, const char *s, int w) {
    int p = 0;
    while (*s && p < w) {
        if (*s == '\x1b') { while (*s && *s != 'm') { sa(eng, s, 1); s++; }
            if (*s == 'm') { sa(eng, s, 1); s++; } continue; }
        sa(eng, s, 1);
        if ((*s & 0xC0) != 0x80) p++;
        s++;
    }
    while (p < w) { sp(eng, " "); p++; }
}

/* ── Terminal ──────────────────────────────────────────────────────── */
static void tty_restore(tv_engine *eng) {
    if (eng->tty_raw && eng->tty_fd >= 0) {
        tcsetattr(eng->tty_fd, TCSAFLUSH, &eng->orig_tios);
        (void)write(eng->tty_fd, "\x1b[?25h\x1b[?1049l", 14);
        eng->tty_raw = 0;
    }
    if (eng->tty_fd >= 0) { close(eng->tty_fd); eng->tty_fd = -1; }
}

/* atexit needs a file-scope engine pointer */
static tv_engine *g_atexit_eng = NULL;
static void atexit_tty_restore(void) {
    if (g_atexit_eng) tty_restore(g_atexit_eng);
}

static void tty_size(tv_engine *eng) {
    struct winsize ws;
    if (eng->tty_fd >= 0 && ioctl(eng->tty_fd, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
        tv_xexecf(eng, "UPDATE state SET rows=%d,cols=%d", ws.ws_row, ws.ws_col);
}

static void tty_init(tv_engine *eng) {
    eng->tty_fd = open("/dev/tty", O_RDWR);
    if (eng->tty_fd < 0) die("cannot open /dev/tty");
    tcgetattr(eng->tty_fd, &eng->orig_tios);
    g_atexit_eng = eng;
    atexit(atexit_tty_restore);
    struct termios r = eng->orig_tios;
    r.c_iflag &= ~(unsigned)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    r.c_oflag &= ~(unsigned)(OPOST);
    r.c_cflag |= CS8;
    r.c_lflag &= ~(unsigned)(ECHO | ICANON | IEXTEN | ISIG);
    r.c_cc[VMIN] = 0; r.c_cc[VTIME] = 1;
    tcsetattr(eng->tty_fd, TCSAFLUSH, &r);
    eng->tty_raw = 1;
    (void)write(eng->tty_fd, "\x1b[?1049h\x1b[?25l", 14);
    tty_size(eng);
}

static void on_winch(int s) { (void)s; g_resized = 1; }

static int readkey(tv_engine *eng) {
    char c;
    if (read(eng->tty_fd, &c, 1) <= 0) return K_NONE;
    if (c == '\x1b') {
        char s[3];
        if (read(eng->tty_fd, &s[0], 1) != 1) return K_ESC;
        if (read(eng->tty_fd, &s[1], 1) != 1) return K_ESC;
        if (s[0] == '[') {
            if (s[1] >= '0' && s[1] <= '9') {
                if (read(eng->tty_fd, &s[2], 1) != 1) return K_ESC;
                if (s[2] == '~') switch (s[1]) {
                    case '1': case '7': return K_HOME;
                    case '4': case '8': return K_END;
                    case '5': return K_PGUP;
                    case '6': return K_PGDN;
                }
            } else switch (s[1]) {
                case 'A': return K_UP;   case 'B': return K_DOWN;
                case 'C': return K_RIGHT; case 'D': return K_LEFT;
                case 'H': return K_HOME; case 'F': return K_END;
            }
        } else if (s[0] == 'O') switch (s[1]) {
            case 'H': return K_HOME; case 'F': return K_END;
        }
        return K_ESC;
    }
    return (unsigned char)c;
}

/* ── Line editor ───────────────────────────────────────────────────── */
int tv_line_edit(tv_engine *eng, const char *prompt, char *buf, int bsz) {
    int len = strlen(buf), pos = len;
    int rows = tv_qint(eng, "SELECT rows FROM state", 24);
    int cols = tv_qint(eng, "SELECT cols FROM state", 80);
    for (;;) {
        eng->scr_len = 0;
        sf(eng, "\x1b[%d;1H\x1b[7m%s%s", rows, prompt, buf);
        for (int i = (int)strlen(prompt) + len; i < cols; i++) sp(eng, " ");
        sf(eng, "\x1b[0m\x1b[%d;%dH\x1b[?25h", rows, (int)strlen(prompt) + pos + 1);
        sflush(eng);
        int k = readkey(eng);
        if (k == K_NONE) continue;
        if (k == K_ENTER || k == '\n') { sp(eng, "\x1b[?25l"); sflush(eng); return 1; }
        if (k == K_ESC) { sp(eng, "\x1b[?25l"); sflush(eng); return 0; }
        if ((k == K_BS || k == 8) && pos > 0) { memmove(buf + pos - 1, buf + pos, len - pos + 1); pos--; len--; }
        else if (k >= 32 && k < 127 && len < bsz - 1) { memmove(buf + pos + 1, buf + pos, len - pos + 1); buf[pos++] = k; len++; }
    }
}

/* ── Style helper ──────────────────────────────────────────────────── */
static const char *S(const char *s) {
    if (!s) return "\x1b[0m";
    switch (s[0]) {
        case 'c': return s[4] == '_' ? "\x1b[36;1m" : "\x1b[36m";
        case 'e': return "\x1b[31m";
        case 'g': return "\x1b[32m";
        case 'h': return "\x1b[33;1m";
        case 'n': return "\x1b[0m";
        case 's': return "\x1b[1;35m";
        case 'y': return "\x1b[33m";
        case 'd': return "\x1b[2m";
    }
    return "\x1b[0m";
}

/* ── Render ────────────────────────────────────────────────────────── */
void tv_render(tv_engine *eng) {
    sqlite3 *db = eng->db;
    int rows = tv_qint(eng, "SELECT rows FROM state", 24);
    int cols = tv_qint(eng, "SELECT cols FROM state", 80);
    int uh = rows - 1, focus = tv_qint(eng, "SELECT focus FROM state", 0);
    int tw = cols / 2, dw = cols - tw;
    if (dw < 20) { tw = cols; dw = 0; }
    int cursor = tv_qint(eng, "SELECT cursor FROM state", 0);
    int sv = tv_qint(eng, "SELECT scroll FROM state", 0);
    if (cursor < sv) sv = cursor;
    if (cursor >= sv + uh) sv = cursor - uh + 1;
    if (sv < 0) sv = 0;
    tv_xexecf(eng, "UPDATE state SET scroll=%d", sv);
    eng->scr_len = 0;
    sp(eng, "\x1b[H");

    /* Left pane */
    {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db, "SELECT style,text FROM lpane WHERE rownum>=? AND rownum<? ORDER BY rownum", -1, &st, 0);
        sqlite3_bind_int(st, 1, sv);
        sqlite3_bind_int(st, 2, sv + uh);
        int row = 0;
        while (sqlite3_step(st) == SQLITE_ROW && row < uh) {
            int idx = sv + row;
            sf(eng, "\x1b[%d;1H", row + 1);
            if (idx == cursor && !focus) sp(eng, "\x1b[1;7m");
            else if (idx == cursor) sp(eng, "\x1b[7m");
            else sp(eng, S((const char *)sqlite3_column_text(st, 0)));
            sputw(eng, (const char *)sqlite3_column_text(st, 1), tw);
            sp(eng, "\x1b[0m");
            row++;
        }
        while (row < uh) { sf(eng, "\x1b[%d;1H\x1b[K", row + 1); row++; }
        sqlite3_finalize(st);
    }

    /* Right pane */
    if (dw > 0) {
        int dc = tv_qint(eng, "SELECT dcursor FROM state", 0);
        int ds = tv_qint(eng, "SELECT dscroll FROM state", 0);
        int nrp = tv_qint(eng, "SELECT COUNT(*) FROM rpane", 0);
        if (dc < ds) ds = dc;
        if (dc >= ds + uh - 1) ds = dc - uh + 2;
        { int mx = nrp > (uh - 1) ? nrp - (uh - 1) : 0; if (ds > mx) ds = mx; }
        if (ds < 0) ds = 0;
        tv_xexecf(eng, "UPDATE state SET dscroll=%d", ds);

        sf(eng, "\x1b[1;%dH", tw + 1);
        sp(eng, focus ? "\x1b[1;45;37m" : "\x1b[7m");
        {
            char h[256] = "";
            int mode = tv_qint(eng, "SELECT mode FROM state", 0);
            sqlite3_stmt *st;
            sqlite3_prepare_v2(db, "SELECT id FROM lpane WHERE rownum=?", -1, &st, 0);
            sqlite3_bind_int(st, 1, cursor);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *id = (const char *)sqlite3_column_text(st, 0);
                if (id) {
                    if (mode == 0) snprintf(h, sizeof h, " PID %s ", id);
                    else snprintf(h, sizeof h, " %.60s ", id);
                }
            }
            sqlite3_finalize(st);
            sputw(eng, h, dw);
        }
        sp(eng, "\x1b[0m");

        sqlite3_stmt *st;
        sqlite3_prepare_v2(db, "SELECT rownum,style,text,link_mode FROM rpane WHERE rownum>=? AND rownum<? ORDER BY rownum", -1, &st, 0);
        sqlite3_bind_int(st, 1, ds);
        sqlite3_bind_int(st, 2, ds + uh - 1);
        int row = 0;
        while (sqlite3_step(st) == SQLITE_ROW && row < uh - 1) {
            int rn = sqlite3_column_int(st, 0);
            sf(eng, "\x1b[%d;%dH", row + 2, tw + 1);
            int idc = (rn == dc && focus);
            int hl = (sqlite3_column_type(st, 3) != SQLITE_NULL && sqlite3_column_int(st, 3) >= 0);
            if (idc) sp(eng, "\x1b[7m");
            else sp(eng, S((const char *)sqlite3_column_text(st, 1)));
            if (idc && hl) sp(eng, "\x1b[4m");
            sp(eng, " ");
            sputw(eng, (const char *)sqlite3_column_text(st, 2), dw - 2);
            sp(eng, " \x1b[0m");
            row++;
        }
        while (row < uh - 1) { sf(eng, "\x1b[%d;%dH\x1b[0m\x1b[K", row + 2, tw + 1); row++; }
        sqlite3_finalize(st);
    }

    /* Status bar — generic fields from state */
    {
        int mode = tv_qint(eng, "SELECT mode FROM state", 0);
        int nf = tv_qint(eng, "SELECT COUNT(*) FROM lpane", 0);
        const char *mn[] = {"PROCS","FILES","OUTPUT","DEPS","RDEPS","DEP-CMDS","RDEP-CMDS"};
        const char *tsl[] = {"abs","rel","Δ"};
        int tsm = tv_qint(eng, "SELECT ts_mode FROM state", 0);
        int gr = tv_qint(eng, "SELECT grouped FROM state", 1);
        int lpf = tv_qint(eng, "SELECT lp_filter FROM state", 0);

        char s[512]; int p = 0;
        p += snprintf(s + p, sizeof s - p, " %s%s | %d/%d",
                      mode < 7 ? mn[mode] : "?", gr ? " tree" : "", cursor + 1, nf);
        p += snprintf(s + p, sizeof s - p, " | TS:%s", tsm < 3 ? tsl[tsm] : "?");

        /* "LIVE" indicator — check if trace fd is still open via inbox heuristic:
         * we check whether the engine was given a trace fd (stored as need_render > -2 hack — but simpler:
         * we just let the app store a flag in the DB or we check a sentinel). For simplicity,
         * let's query a custom table if present, but fall back to nothing.  Instead, we use
         * a simple convention: if state has base_ts=0, data may still be streaming. */
        /* Actually, let's just check an engine field set by the main loop. */
        /* The status bar is rendered from engine.c but needs app-specific info.
         * We solve this by having the app put whatever it wants into an 'extra_status' TEXT column,
         * but to avoid schema changes, we'll just directly read existing state fields here. */

        {
            sqlite3_stmt *st;
            sqlite3_prepare_v2(db, "SELECT evfilt,search FROM state", -1, &st, 0);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *ef = (const char *)sqlite3_column_text(st, 0);
                const char *sq = (const char *)sqlite3_column_text(st, 1);
                if (ef && ef[0]) p += snprintf(s + p, sizeof s - p, " | F:%s", ef);
                if (sq && sq[0]) p += snprintf(s + p, sizeof s - p, " | /%s[%d]",
                    sq, tv_qint(eng, "SELECT COUNT(*) FROM search_hits", 0));
            }
            sqlite3_finalize(st);
        }
        if (lpf == 1) p += snprintf(s + p, sizeof s - p, " | V:failed");
        else if (lpf == 2) p += snprintf(s + p, sizeof s - p, " | V:running");

        { int df = tv_qint(eng, "SELECT dep_filter FROM state", 0);
          if (mode >= 3 && mode <= 6) p += snprintf(s + p, sizeof s - p, " | D:%s", df ? "written" : "all"); }

        p += snprintf(s + p, sizeof s - p, " | 1:proc 2:file 3:out 4:dep 5:rdep 6:dcmd 7:rcmd ?:help");
        (void)p;

        sf(eng, "\x1b[%d;1H\x1b[7;1m", rows);
        sputw(eng, s, cols);
        sp(eng, "\x1b[0m");
    }
    sflush(eng);
}

/* ── Help screen ───────────────────────────────────────────────────── */
void tv_show_help(tv_engine *eng, const char **lines) {
    eng->scr_len = 0;
    sp(eng, "\x1b[H\x1b[2J");
    for (int i = 0; lines[i]; i++)
        sf(eng, "\x1b[%d;1H\x1b[36m%s\x1b[0m", i + 1, lines[i]);
    sflush(eng);
    while (readkey(eng) == K_NONE)
        ;
}

/* ── SQL prompt ────────────────────────────────────────────────────── */
void tv_run_sql(tv_engine *eng) {
    sqlite3 *db = eng->db;
    char sql[1024] = "";
    if (!tv_line_edit(eng, "SQL> ", sql, sizeof sql) || !sql[0]) return;
    eng->scr_len = 0;
    sp(eng, "\x1b[H\x1b[2J");
    sf(eng, "\x1b[1;1H\x1b[33;1mSQL: %s\x1b[0m", sql);
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, sql, -1, &st, 0) != SQLITE_OK) {
        sf(eng, "\x1b[3;1H\x1b[31m%s\x1b[0m", sqlite3_errmsg(db));
        sflush(eng);
        while (readkey(eng) == K_NONE);
        return;
    }
    int nc = sqlite3_column_count(st), row = 3;
    int rows = tv_qint(eng, "SELECT rows FROM state", 24);
    sf(eng, "\x1b[%d;1H\x1b[36;1m", row++);
    for (int c = 0; c < nc && c < 10; c++) sf(eng, "%-20s", sqlite3_column_name(st, c));
    sp(eng, "\x1b[0m");
    sf(eng, "\x1b[%d;1H", row++);
    for (int c = 0; c < nc && c < 10; c++) sp(eng, "──────────────────── ");
    int nr = 0;
    while (sqlite3_step(st) == SQLITE_ROW && row < rows - 2) {
        sf(eng, "\x1b[%d;1H", row++);
        for (int c = 0; c < nc && c < 10; c++) {
            const char *v = (const char *)sqlite3_column_text(st, c);
            char t[21]; snprintf(t, sizeof t, "%.20s", v ? v : "NULL");
            sf(eng, "%-20s", t);
        }
        nr++;
    }
    sqlite3_finalize(st);
    sf(eng, "\x1b[%d;1H\x1b[2m%d rows.\x1b[0m", row + 1, nr);
    sflush(eng);
    while (readkey(eng) == K_NONE);
}

/* ── Save DB ───────────────────────────────────────────────────────── */
void tv_save_db(tv_engine *eng) {
    char fname[256] = "trace.db";
    if (!tv_line_edit(eng, "Save to: ", fname, sizeof fname) || !fname[0]) return;
    tv_save_to_file(eng, fname);
}

void tv_save_to_file(tv_engine *eng, const char *path) {
    sqlite3 *dst;
    if (sqlite3_open(path, &dst) != SQLITE_OK) {
        fprintf(stderr, "tv: cannot create %s\n", path);
        return;
    }
    sqlite3_backup *bk = sqlite3_backup_init(dst, "main", eng->db, "main");
    if (bk) { sqlite3_backup_step(bk, -1); sqlite3_backup_finish(bk); }
    sqlite3_close(dst);
}

/* ── Load DB ───────────────────────────────────────────────────────── */
void tv_load_db(tv_engine *eng, const char *path) {
    sqlite3 *src;
    if (sqlite3_open(path, &src) != SQLITE_OK) die("cannot open file");
    sqlite3_backup *bk = sqlite3_backup_init(eng->db, "main", src, "main");
    if (!bk) die("backup init failed");
    sqlite3_backup_step(bk, -1);
    sqlite3_backup_finish(bk);
    sqlite3_close(src);
}

/* ── Headless output ───────────────────────────────────────────────── */
void tv_dump_lpane(tv_engine *eng) {
    printf("=== LPANE ===\n");
    sqlite3_stmt *st;
    sqlite3_prepare_v2(eng->db,
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

void tv_dump_rpane(tv_engine *eng) {
    printf("=== RPANE ===\n");
    sqlite3_stmt *st;
    sqlite3_prepare_v2(eng->db,
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

void tv_dump_state(tv_engine *eng) {
    printf("=== STATE ===\n");
    sqlite3_stmt *st;
    sqlite3_prepare_v2(eng->db,
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

/* ── Ingest ────────────────────────────────────────────────────────── */
void tv_ingest_line(tv_engine *eng, const char *ln) {
    if (!ln || !ln[0] || ln[0] != '{') return;
    const char *kind = strstr(ln, "\"input\"") ? "input" : "trace";
    sqlite3_stmt *st;
    sqlite3_prepare_v2(eng->db, "INSERT INTO inbox(kind,data) VALUES(?,?)", -1, &st, 0);
    sqlite3_bind_text(st, 1, kind, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, ln, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void tv_ingest_file(tv_engine *eng, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "tv: cannot open %s\n", path); exit(1); }
    char line[1 << 20];
    tv_xexec(eng, "BEGIN");
    while (fgets(line, sizeof line, f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        if (nl > line && *(nl - 1) == '\r') *(nl - 1) = 0;
        tv_ingest_line(eng, line);
    }
    tv_xexec(eng, "COMMIT");
    fclose(f);
}

void tv_process_inbox(tv_engine *eng, int trace_only) {
    static char buf[1 << 20];

    /* Trace events: batch in a transaction */
    tv_xexec(eng, "BEGIN");
    for (;;) {
        long long id = -1; buf[0] = 0;
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(eng->db, "SELECT id,data FROM inbox WHERE kind='trace' ORDER BY id LIMIT 1", -1, &st, 0);
          if (sqlite3_step(st) == SQLITE_ROW) {
              id = sqlite3_column_int64(st, 0);
              const char *d = (const char *)sqlite3_column_text(st, 1);
              if (d) snprintf(buf, sizeof buf - 1, "%s", d);
          }
          sqlite3_finalize(st);
        }
        if (id < 0) break;
        tv_xexecf(eng, "DELETE FROM inbox WHERE id=%lld", id);
        if (eng->cb.on_trace_line) eng->cb.on_trace_line(eng, eng->cb.app_data, buf);
    }
    tv_xexec(eng, "COMMIT");

    if (trace_only) return;

    /* Input events: one at a time */
    for (;;) {
        long long id = -1; buf[0] = 0;
        { sqlite3_stmt *st;
          sqlite3_prepare_v2(eng->db, "SELECT id,data FROM inbox WHERE kind='input' ORDER BY id LIMIT 1", -1, &st, 0);
          if (sqlite3_step(st) == SQLITE_ROW) {
              id = sqlite3_column_int64(st, 0);
              const char *d = (const char *)sqlite3_column_text(st, 1);
              if (d) snprintf(buf, sizeof buf - 1, "%s", d);
          }
          sqlite3_finalize(st);
        }
        if (id < 0) break;
        tv_xexecf(eng, "DELETE FROM inbox WHERE id=%lld", id);
        if (eng->cb.on_input) eng->cb.on_input(eng, eng->cb.app_data, buf);
    }
}

/* ── Lifecycle ─────────────────────────────────────────────────────── */
tv_engine *tv_engine_new(const tv_callbacks *cb,
                         const tv_sql_func *funcs, int nfuncs) {
    tv_engine *eng = calloc(1, sizeof *eng);
    if (!eng) die("calloc");
    eng->cb = *cb;
    eng->tty_fd = -1;
    eng->need_render = 1;

    if (sqlite3_open(":memory:", &eng->db) != SQLITE_OK)
        die("sqlite3_open");

    for (int i = 0; i < nfuncs; i++)
        sqlite3_create_function(eng->db, funcs[i].name, funcs[i].nargs,
                                SQLITE_UTF8, 0, funcs[i].xFunc, 0, 0);

    return eng;
}

void tv_engine_destroy(tv_engine *eng) {
    if (!eng) return;
    tty_restore(eng);
    if (eng->db) sqlite3_close(eng->db);
    free(eng->scr);
    free(eng);
}

/* ── Main loop ─────────────────────────────────────────────────────── */
int tv_engine_run(tv_engine *eng,
                  int trace_fd, FILE *trace_pipe, pid_t child_pid,
                  int headless) {
    eng->headless = headless;

    /* Initial rebuild */
    if (eng->cb.rebuild_lpane) eng->cb.rebuild_lpane(eng, eng->cb.app_data);
    if (eng->cb.rebuild_rpane) eng->cb.rebuild_rpane(eng, eng->cb.app_data);

    /* Process any queued input events */
    tv_process_inbox(eng, 0);

    if (eng->headless) return 0;
    if (trace_fd < 0 && !child_pid) {
        /* Non-interactive, no trace — just return after processing */
        return 0;
    }

    tty_init(eng);
    struct sigaction sa2 = {0};
    sa2.sa_handler = on_winch;
    sigaction(SIGWINCH, &sa2, 0);

    for (;;) {
        if (g_resized) {
            g_resized = 0;
            tty_size(eng);
            if (eng->cb.rebuild_lpane) eng->cb.rebuild_lpane(eng, eng->cb.app_data);
            if (eng->cb.rebuild_rpane) eng->cb.rebuild_rpane(eng, eng->cb.app_data);
            eng->need_render = 1;
        }
        if (eng->need_render) { tv_render(eng); eng->need_render = 0; }

        /* Block until input arrives */
        fd_set rfds; FD_ZERO(&rfds); FD_SET(eng->tty_fd, &rfds);
        int mfd = eng->tty_fd;
        if (trace_fd >= 0) { FD_SET(trace_fd, &rfds); if (trace_fd > mfd) mfd = trace_fd; }
        int sel = select(mfd + 1, &rfds, NULL, NULL, NULL);
        if (sel < 0 && errno == EINTR) continue;

        /* Trace data */
        if (trace_fd >= 0 && sel > 0 && FD_ISSET(trace_fd, &rfds)) {
            int n = read(trace_fd, eng->rbuf + eng->rbuf_len,
                         (int)(sizeof(eng->rbuf) - eng->rbuf_len - 1));
            if (n <= 0) {
                if (eng->rbuf_len > 0) {
                    eng->rbuf[eng->rbuf_len] = 0;
                    tv_xexec(eng, "BEGIN");
                    tv_ingest_line(eng, eng->rbuf);
                    tv_xexec(eng, "COMMIT");
                    eng->rbuf_len = 0;
                    tv_process_inbox(eng, 1);
                }
                if (eng->cb.on_stream_end)
                    eng->cb.on_stream_end(eng, eng->cb.app_data);
                if (trace_pipe) { pclose(trace_pipe); trace_pipe = NULL; trace_fd = -1; }
                else { close(trace_fd); trace_fd = -1; }
                if (eng->cb.rebuild_lpane) eng->cb.rebuild_lpane(eng, eng->cb.app_data);
                if (eng->cb.rebuild_rpane) eng->cb.rebuild_rpane(eng, eng->cb.app_data);
                eng->need_render = 1;
            } else {
                eng->rbuf_len += n;
                int did = 0;
                tv_xexec(eng, "BEGIN");
                while (1) {
                    char *nl = (char *)memchr(eng->rbuf, '\n', eng->rbuf_len);
                    if (!nl) break;
                    if (nl > eng->rbuf && *(nl - 1) == '\r') *(nl - 1) = 0;
                    *nl = 0;
                    tv_ingest_line(eng, eng->rbuf);
                    did++;
                    int used = (int)(nl - eng->rbuf) + 1;
                    memmove(eng->rbuf, nl + 1, eng->rbuf_len - used);
                    eng->rbuf_len -= used;
                }
                if (eng->rbuf_len >= (int)(sizeof(eng->rbuf) - 1)) {
                    eng->rbuf[eng->rbuf_len] = 0;
                    tv_ingest_line(eng, eng->rbuf);
                    did++;
                    eng->rbuf_len = 0;
                }
                tv_xexec(eng, "COMMIT");
                if (did) {
                    tv_process_inbox(eng, 1);
                    tv_xexec(eng, "UPDATE state SET base_ts="
                        "(SELECT COALESCE(MIN(ts),0) FROM events) WHERE base_ts=0");
                    if (eng->cb.rebuild_lpane) eng->cb.rebuild_lpane(eng, eng->cb.app_data);
                    if (eng->cb.rebuild_rpane) eng->cb.rebuild_rpane(eng, eng->cb.app_data);
                    eng->need_render = 1;
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
        if (sel > 0 && FD_ISSET(eng->tty_fd, &rfds)) {
            int k = readkey(eng);
            if (k == K_NONE) {}
            else {
                int quit = 0;
                if (eng->cb.on_key) quit = eng->cb.on_key(eng, eng->cb.app_data, k);
                if (quit) break;
                eng->need_render = 1;
            }
        }
    }

    tty_restore(eng);
    if (trace_pipe) { pclose(trace_pipe); trace_pipe = NULL; trace_fd = -1; }
    else if (trace_fd >= 0) { close(trace_fd); trace_fd = -1; }
    if (child_pid > 0) { kill(child_pid, SIGTERM); waitpid(child_pid, NULL, 0); }

    return 0;
}
