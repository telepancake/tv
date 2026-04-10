/*
 * engine.c — Generic two-pane TUI engine.
 *
 * See engine.h for the full API contract and display table formats.
 *
 * This file contains:
 *   • Terminal management (raw mode, alternate screen, cleanup)
 *   • Key reading and ANSI escape sequence decoding
 *   • Two-pane rendering from lpane/rpane/state tables
 *   • Screen buffer for batched terminal output
 *   • Line editor
 *   • Help screen
 *   • SQL prompt
 *   • Headless table dump
 *
 * Nothing in this file knows about processes, traces, files, or any
 * application-specific concept.  It only knows how to render styled
 * text from database tables into a two-pane terminal layout.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>

#include "engine.h"

/* ── Internal state ────────────────────────────────────────────────── */
struct tui {
    sqlite3       *db;

    /* Terminal */
    int            tty_fd;
    struct termios orig_tios;
    int            tty_raw;

    /* Remembered terminal size for change detection */
    int            last_rows;
    int            last_cols;

    /* Screen buffer for batched writes */
    char          *scr;
    int            scr_len;
    int            scr_cap;
};

/* ── Global state for signal handler ───────────────────────────────── */
static volatile int g_resized = 0;
static tui_t *g_atexit_tui = NULL;

/* ── Helpers ───────────────────────────────────────────────────────── */
static void die(const char *m) {
    fprintf(stderr, "tui: %s\n", m);
    exit(1);
}

static int qint(sqlite3 *db, const char *sql, int def) {
    sqlite3_stmt *s;
    int r = def;
    if (sqlite3_prepare_v2(db, sql, -1, &s, 0) == SQLITE_OK) {
        if (sqlite3_step(s) == SQLITE_ROW) r = sqlite3_column_int(s, 0);
        sqlite3_finalize(s);
    }
    return r;
}

static void xexec(sqlite3 *db, const char *sql) {
    char *e;
    if (sqlite3_exec(db, sql, 0, 0, &e) != SQLITE_OK) {
        fprintf(stderr, "sql: %s\n%.300s\n", e, sql);
        sqlite3_free(e);
        exit(1);
    }
}

static void xexecf(sqlite3 *db, const char *fmt, ...) {
    char b[16384];
    va_list a;
    va_start(a, fmt);
    vsnprintf(b, sizeof b, fmt, a);
    va_end(a);
    xexec(db, b);
}

/* ── Screen buffer ─────────────────────────────────────────────────── */
static void sa(tui_t *t, const char *s, int n) {
    if (t->scr_len + n + 1 > t->scr_cap) {
        t->scr_cap = (t->scr_len + n + 1) * 2;
        if (t->scr_cap < 8192) t->scr_cap = 8192;
        t->scr = realloc(t->scr, t->scr_cap);
    }
    memcpy(t->scr + t->scr_len, s, n);
    t->scr_len += n;
}
static void sp(tui_t *t, const char *s) { sa(t, s, strlen(s)); }
static void sf(tui_t *t, const char *fmt, ...) {
    char buf[4096];
    va_list a;
    va_start(a, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, a);
    va_end(a);
    if (n > 0) sa(t, buf, n < (int)sizeof buf ? n : (int)sizeof buf - 1);
}
static void sflush(tui_t *t) {
    if (t->scr_len > 0 && t->tty_fd >= 0)
        (void)write(t->tty_fd, t->scr, t->scr_len);
    t->scr_len = 0;
}

/* Write a string, padding or truncating to exactly w visible columns.
 * ANSI escape sequences are passed through without counting as width. */
static void sputw(tui_t *t, const char *s, int w) {
    int p = 0;
    while (*s && p < w) {
        if (*s == '\x1b') {
            while (*s && *s != 'm') { sa(t, s, 1); s++; }
            if (*s == 'm') { sa(t, s, 1); s++; }
            continue;
        }
        sa(t, s, 1);
        if ((*s & 0xC0) != 0x80) p++;
        s++;
    }
    while (p < w) { sp(t, " "); p++; }
}

/* ── Style mapping ─────────────────────────────────────────────────── */
static const char *style_ansi(const char *s) {
    if (!s) return "\x1b[0m";
    switch (s[0]) {
        case 'c': return s[4] == '_' ? "\x1b[36;1m" : "\x1b[36m";  /* cyan / cyan_bold */
        case 'e': return "\x1b[31m";      /* error */
        case 'g': return "\x1b[32m";      /* green */
        case 'h': return "\x1b[33;1m";    /* heading */
        case 'n': return "\x1b[0m";       /* normal */
        case 's': return "\x1b[1;35m";    /* search */
        case 'y': return "\x1b[33m";      /* yellow */
        case 'd': return "\x1b[2m";       /* dim */
    }
    return "\x1b[0m";
}

/* ── Terminal management ───────────────────────────────────────────── */

static void tty_restore(tui_t *t) {
    if (t->tty_raw && t->tty_fd >= 0) {
        tcsetattr(t->tty_fd, TCSAFLUSH, &t->orig_tios);
        (void)write(t->tty_fd, "\x1b[?25h\x1b[?1049l", 14);
        t->tty_raw = 0;
    }
    if (t->tty_fd >= 0) { close(t->tty_fd); t->tty_fd = -1; }
}

static void atexit_restore(void) {
    if (g_atexit_tui) tty_restore(g_atexit_tui);
}

/* Query terminal size via ioctl and update state.rows/cols. */
static void tty_size(tui_t *t) {
    struct winsize ws;
    if (t->tty_fd >= 0 && ioctl(t->tty_fd, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) {
        t->last_rows = ws.ws_row;
        t->last_cols = ws.ws_col;
        xexecf(t->db, "UPDATE state SET rows=%d,cols=%d", ws.ws_row, ws.ws_col);
    }
}

/* ── Public: signal handler ────────────────────────────────────────── */
void tui_sigwinch_handler(int sig) {
    (void)sig;
    g_resized = 1;
}

/* ── Public: lifecycle ─────────────────────────────────────────────── */

tui_t *tui_open(sqlite3 *db) {
    tui_t *t = calloc(1, sizeof *t);
    if (!t) die("calloc");
    t->db = db;
    t->tty_fd = -1;

    t->tty_fd = open("/dev/tty", O_RDWR);
    if (t->tty_fd < 0) { free(t); return NULL; }

    tcgetattr(t->tty_fd, &t->orig_tios);
    g_atexit_tui = t;
    atexit(atexit_restore);

    struct termios r = t->orig_tios;
    r.c_iflag &= ~(unsigned)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    r.c_oflag &= ~(unsigned)(OPOST);
    r.c_cflag |= CS8;
    r.c_lflag &= ~(unsigned)(ECHO | ICANON | IEXTEN | ISIG);
    r.c_cc[VMIN] = 0;
    r.c_cc[VTIME] = 1;
    tcsetattr(t->tty_fd, TCSAFLUSH, &r);
    t->tty_raw = 1;

    (void)write(t->tty_fd, "\x1b[?1049h\x1b[?25l", 14);
    tty_size(t);
    g_resized = 0;

    return t;
}

void tui_close(tui_t *t) {
    if (!t) return;
    tty_restore(t);
    if (t == g_atexit_tui) g_atexit_tui = NULL;
    free(t->scr);
    free(t);
}

/* ── Public: terminal fd ───────────────────────────────────────────── */
int tui_fd(tui_t *t) {
    return t ? t->tty_fd : -1;
}

/* ── Public: resize check ──────────────────────────────────────────── */
int tui_check_resize(tui_t *t) {
    if (!t) return 0;
    if (!g_resized) return 0;
    g_resized = 0;
    int old_rows = t->last_rows, old_cols = t->last_cols;
    tty_size(t);
    return (t->last_rows != old_rows || t->last_cols != old_cols);
}

/* ── Public: key reading ───────────────────────────────────────────── */
int tui_read_key(tui_t *t) {
    if (!t || t->tty_fd < 0) return TUI_K_NONE;
    char c;
    if (read(t->tty_fd, &c, 1) <= 0) return TUI_K_NONE;
    if (c == '\x1b') {
        char s[3];
        if (read(t->tty_fd, &s[0], 1) != 1) return TUI_K_ESC;
        if (read(t->tty_fd, &s[1], 1) != 1) return TUI_K_ESC;
        if (s[0] == '[') {
            if (s[1] >= '0' && s[1] <= '9') {
                if (read(t->tty_fd, &s[2], 1) != 1) return TUI_K_ESC;
                if (s[2] == '~') switch (s[1]) {
                    case '1': case '7': return TUI_K_HOME;
                    case '4': case '8': return TUI_K_END;
                    case '5': return TUI_K_PGUP;
                    case '6': return TUI_K_PGDN;
                }
            } else switch (s[1]) {
                case 'A': return TUI_K_UP;    case 'B': return TUI_K_DOWN;
                case 'C': return TUI_K_RIGHT; case 'D': return TUI_K_LEFT;
                case 'H': return TUI_K_HOME;  case 'F': return TUI_K_END;
            }
        } else if (s[0] == 'O') switch (s[1]) {
            case 'H': return TUI_K_HOME; case 'F': return TUI_K_END;
        }
        return TUI_K_ESC;
    }
    return (unsigned char)c;
}

/* ── Public: render ────────────────────────────────────────────────── */
void tui_render(tui_t *t) {
    if (!t || t->tty_fd < 0) return;
    sqlite3 *db = t->db;
    int rows = qint(db, "SELECT rows FROM state", 24);
    int cols = qint(db, "SELECT cols FROM state", 80);
    int uh = rows - 1;  /* usable height (status bar takes 1 row) */
    int focus = qint(db, "SELECT focus FROM state", 0);
    int tw = cols / 2, dw = cols - tw;
    if (dw < 20) { tw = cols; dw = 0; }

    /* Adjust left-pane scroll to keep cursor visible */
    int cursor = qint(db, "SELECT cursor FROM state", 0);
    int sv = qint(db, "SELECT scroll FROM state", 0);
    if (cursor < sv) sv = cursor;
    if (cursor >= sv + uh) sv = cursor - uh + 1;
    if (sv < 0) sv = 0;
    xexecf(db, "UPDATE state SET scroll=%d", sv);

    t->scr_len = 0;
    sp(t, "\x1b[H");

    /* ── Left pane ─────────────────────────────────────────────── */
    {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
            "SELECT style,text FROM lpane WHERE rownum>=? AND rownum<? ORDER BY rownum",
            -1, &st, 0);
        sqlite3_bind_int(st, 1, sv);
        sqlite3_bind_int(st, 2, sv + uh);
        int row = 0;
        while (sqlite3_step(st) == SQLITE_ROW && row < uh) {
            int idx = sv + row;
            sf(t, "\x1b[%d;1H", row + 1);
            if (idx == cursor && !focus) sp(t, "\x1b[1;7m");
            else if (idx == cursor) sp(t, "\x1b[7m");
            else sp(t, style_ansi((const char *)sqlite3_column_text(st, 0)));
            sputw(t, (const char *)sqlite3_column_text(st, 1), tw);
            sp(t, "\x1b[0m");
            row++;
        }
        while (row < uh) { sf(t, "\x1b[%d;1H\x1b[K", row + 1); row++; }
        sqlite3_finalize(st);
    }

    /* ── Right pane ────────────────────────────────────────────── */
    if (dw > 0) {
        int dc = qint(db, "SELECT dcursor FROM state", 0);
        int ds = qint(db, "SELECT dscroll FROM state", 0);
        int nrp = qint(db, "SELECT COUNT(*) FROM rpane", 0);

        /* Adjust right-pane scroll */
        if (dc < ds) ds = dc;
        if (dc >= ds + uh - 1) ds = dc - uh + 2;
        { int mx = nrp > (uh - 1) ? nrp - (uh - 1) : 0; if (ds > mx) ds = mx; }
        if (ds < 0) ds = 0;
        xexecf(db, "UPDATE state SET dscroll=%d", ds);

        /* Header row — show lpane.id at cursor */
        sf(t, "\x1b[1;%dH", tw + 1);
        sp(t, focus ? "\x1b[1;45;37m" : "\x1b[7m");
        {
            char h[256] = "";
            sqlite3_stmt *st;
            sqlite3_prepare_v2(db, "SELECT id FROM lpane WHERE rownum=?", -1, &st, 0);
            sqlite3_bind_int(st, 1, cursor);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *id = (const char *)sqlite3_column_text(st, 0);
                if (id) snprintf(h, sizeof h, " %.*s ", (int)sizeof(h) - 4, id);
            }
            sqlite3_finalize(st);
            sputw(t, h, dw);
        }
        sp(t, "\x1b[0m");

        /* Content rows */
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
            "SELECT rownum,style,text FROM rpane WHERE rownum>=? AND rownum<? ORDER BY rownum",
            -1, &st, 0);
        sqlite3_bind_int(st, 1, ds);
        sqlite3_bind_int(st, 2, ds + uh - 1);
        int row = 0;
        while (sqlite3_step(st) == SQLITE_ROW && row < uh - 1) {
            int rn = sqlite3_column_int(st, 0);
            sf(t, "\x1b[%d;%dH", row + 2, tw + 1);
            int idc = (rn == dc && focus);
            if (idc) sp(t, "\x1b[7m");
            else sp(t, style_ansi((const char *)sqlite3_column_text(st, 1)));
            sp(t, " ");
            sputw(t, (const char *)sqlite3_column_text(st, 2), dw - 2);
            sp(t, " \x1b[0m");
            row++;
        }
        while (row < uh - 1) {
            sf(t, "\x1b[%d;%dH\x1b[0m\x1b[K", row + 2, tw + 1);
            row++;
        }
        sqlite3_finalize(st);
    }

    /* ── Status bar ────────────────────────────────────────────── */
    {
        char s[512] = "";
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db, "SELECT COALESCE(status,'') FROM state", -1, &st, 0);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *v = (const char *)sqlite3_column_text(st, 0);
            if (v) snprintf(s, sizeof s, "%s", v);
        }
        sqlite3_finalize(st);

        sf(t, "\x1b[%d;1H\x1b[7;1m", rows);
        sputw(t, s, cols);
        sp(t, "\x1b[0m");
    }

    sflush(t);
}

/* ── Public: line editor ───────────────────────────────────────────── */
int tui_line_edit(tui_t *t, const char *prompt, char *buf, int bsz) {
    if (!t || t->tty_fd < 0) return 0;
    int len = strlen(buf), pos = len;
    int rows = qint(t->db, "SELECT rows FROM state", 24);
    int cols = qint(t->db, "SELECT cols FROM state", 80);
    for (;;) {
        t->scr_len = 0;
        sf(t, "\x1b[%d;1H\x1b[7m%s%s", rows, prompt, buf);
        for (int i = (int)strlen(prompt) + len; i < cols; i++) sp(t, " ");
        sf(t, "\x1b[0m\x1b[%d;%dH\x1b[?25h", rows, (int)strlen(prompt) + pos + 1);
        sflush(t);
        int k = tui_read_key(t);
        if (k == TUI_K_NONE) continue;
        if (k == TUI_K_ENTER || k == '\n') {
            sp(t, "\x1b[?25l"); sflush(t); return 1;
        }
        if (k == TUI_K_ESC) {
            sp(t, "\x1b[?25l"); sflush(t); return 0;
        }
        if ((k == TUI_K_BS || k == 8) && pos > 0) {
            memmove(buf + pos - 1, buf + pos, len - pos + 1);
            pos--; len--;
        } else if (k >= 32 && k < 127 && len < bsz - 1) {
            memmove(buf + pos + 1, buf + pos, len - pos + 1);
            buf[pos++] = k; len++;
        }
    }
}

/* ── Public: help screen ───────────────────────────────────────────── */
void tui_show_help(tui_t *t, const char **lines) {
    if (!t || t->tty_fd < 0) return;
    t->scr_len = 0;
    sp(t, "\x1b[H\x1b[2J");
    for (int i = 0; lines[i]; i++)
        sf(t, "\x1b[%d;1H\x1b[36m%s\x1b[0m", i + 1, lines[i]);
    sflush(t);
    while (tui_read_key(t) == TUI_K_NONE)
        ;
}

/* ── Public: SQL prompt ────────────────────────────────────────────── */
void tui_sql_prompt(tui_t *t) {
    if (!t || t->tty_fd < 0) return;
    sqlite3 *db = t->db;
    char sql[1024] = "";
    if (!tui_line_edit(t, "SQL> ", sql, sizeof sql) || !sql[0]) return;
    t->scr_len = 0;
    sp(t, "\x1b[H\x1b[2J");
    sf(t, "\x1b[1;1H\x1b[33;1mSQL: %s\x1b[0m", sql);
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, sql, -1, &st, 0) != SQLITE_OK) {
        sf(t, "\x1b[3;1H\x1b[31m%s\x1b[0m", sqlite3_errmsg(db));
        sflush(t);
        while (tui_read_key(t) == TUI_K_NONE) ;
        return;
    }
    int nc = sqlite3_column_count(st), row = 3;
    int rows = qint(db, "SELECT rows FROM state", 24);
    sf(t, "\x1b[%d;1H\x1b[36;1m", row++);
    for (int c = 0; c < nc && c < 10; c++) sf(t, "%-20s", sqlite3_column_name(st, c));
    sp(t, "\x1b[0m");
    sf(t, "\x1b[%d;1H", row++);
    for (int c = 0; c < nc && c < 10; c++) sp(t, "──────────────────── ");
    int nr = 0;
    while (sqlite3_step(st) == SQLITE_ROW && row < rows - 2) {
        sf(t, "\x1b[%d;1H", row++);
        for (int c = 0; c < nc && c < 10; c++) {
            const char *v = (const char *)sqlite3_column_text(st, c);
            char tmp[21]; snprintf(tmp, sizeof tmp, "%.20s", v ? v : "NULL");
            sf(t, "%-20s", tmp);
        }
        nr++;
    }
    sqlite3_finalize(st);
    sf(t, "\x1b[%d;1H\x1b[2m%d rows.\x1b[0m", row + 1, nr);
    sflush(t);
    while (tui_read_key(t) == TUI_K_NONE) ;
}

/* ── Public: headless dump ─────────────────────────────────────────── */
void tui_dump_table(sqlite3 *db, const char *table) {
    if (!table) return;

    if (strcmp(table, "lpane") == 0) {
        printf("=== LPANE ===\n");
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
            "SELECT rownum,style,id,text FROM lpane ORDER BY rownum",
            -1, &st, 0);
        while (sqlite3_step(st) == SQLITE_ROW)
            printf("%d|%s|%s|%s\n",
                sqlite3_column_int(st, 0),
                (const char *)sqlite3_column_text(st, 1),
                (const char *)sqlite3_column_text(st, 2),
                (const char *)sqlite3_column_text(st, 3));
        sqlite3_finalize(st);
        printf("=== END LPANE ===\n");
    } else if (strcmp(table, "rpane") == 0) {
        printf("=== RPANE ===\n");
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
            "SELECT rownum,style,text FROM rpane ORDER BY rownum",
            -1, &st, 0);
        while (sqlite3_step(st) == SQLITE_ROW)
            printf("%d|%s|%s\n",
                sqlite3_column_int(st, 0),
                (const char *)sqlite3_column_text(st, 1),
                (const char *)sqlite3_column_text(st, 2));
        sqlite3_finalize(st);
        printf("=== END RPANE ===\n");
    } else if (strcmp(table, "state") == 0) {
        printf("=== STATE ===\n");
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db,
            "SELECT cursor,scroll,focus,dcursor,dscroll,rows,cols,"
            "COALESCE(status,'') FROM state",
            -1, &st, 0);
        if (sqlite3_step(st) == SQLITE_ROW)
            printf("cursor=%d scroll=%d focus=%d dcursor=%d dscroll=%d"
                " rows=%d cols=%d status=%s\n",
                sqlite3_column_int(st, 0), sqlite3_column_int(st, 1),
                sqlite3_column_int(st, 2), sqlite3_column_int(st, 3),
                sqlite3_column_int(st, 4), sqlite3_column_int(st, 5),
                sqlite3_column_int(st, 6),
                (const char *)sqlite3_column_text(st, 7));
        sqlite3_finalize(st);
        printf("=== END STATE ===\n");
    }
}
