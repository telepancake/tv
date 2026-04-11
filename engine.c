/*
 * engine.c — Generic panel-based TUI engine.
 * See engine.h for the API contract.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>

#include "engine.h"

#define MAX_PANELS  8
#define MAX_WATCHES 16
#define MAX_TIMERS  16

/* ── Panel state ───────────────────────────────────────────────────── */
typedef struct {
    tui_panel_def def;
    int x_pct, y_pct, w_pct, h_pct;
    int x, y, w, h;         /* resolved char positions */
    int cursor, scroll;
    int row_count;
    int dirty;
    char cursor_id[4096];
} panel_st;

typedef struct { int fd; tui_fd_cb cb; void *ctx; int active; } fd_watch;
typedef struct {
    int id, ms, active;
    struct timeval fire;
    tui_timer_cb cb; void *ctx;
} timer_ent;

struct tui {
    sqlite3       *db;
    int            tty_fd;
    struct termios orig_tios;
    int            tty_raw, rows, cols;

    panel_st       panels[MAX_PANELS];
    int            npanels, focus;

    char           status[1024];

    tui_key_cb     key_cb;
    void          *key_ctx;
    fd_watch       watches[MAX_WATCHES];
    timer_ent      timers[MAX_TIMERS];
    int            next_timer_id, quit_flag;

    char          *scr;
    int            scr_len, scr_cap;
};

/* ── Globals ───────────────────────────────────────────────────────── */
static volatile int g_resized = 0;
static tui_t *g_atexit_tui = NULL;

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
    char buf[4096]; va_list a; va_start(a, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, a); va_end(a);
    if (n > 0) sa(t, buf, n < (int)sizeof buf ? n : (int)sizeof buf - 1);
}
static void sflush(tui_t *t) {
    if (t->scr_len > 0 && t->tty_fd >= 0) {
        int r = write(t->tty_fd, t->scr, t->scr_len); (void)r;
    }
    t->scr_len = 0;
}

/* ── Visible-width text output ─────────────────────────────────────── */
static int visible_len(const char *s) {
    int n = 0;
    while (*s) {
        if (*s == '\x1b') { while (*s && *s != 'm') s++; if (*s) s++; continue; }
        if ((*s & 0xC0) != 0x80) n++;
        s++;
    }
    return n;
}

static void sput_field(tui_t *t, const char *s, int w, int align, int ovf) {
    if (w <= 0) return;
    if (!s) s = "";
    int vl = visible_len(s);
    if (vl <= w) {
        int pad = w - vl, lp = 0, rp = 0;
        if (align == TUI_ALIGN_RIGHT) { lp = pad; rp = 0; }
        else if (align == TUI_ALIGN_CENTER) { lp = pad / 2; rp = pad - lp; }
        else { lp = 0; rp = pad; }
        for (int i = 0; i < lp; i++) sp(t, " ");
        while (*s) {
            if (*s == '\x1b') { while (*s && *s != 'm') { sa(t, s, 1); s++; } if (*s) { sa(t, s, 1); s++; } continue; }
            sa(t, s, 1); s++;
        }
        for (int i = 0; i < rp; i++) sp(t, " ");
    } else {
        int lim = (ovf == TUI_OVERFLOW_ELLIPSIS && w >= 3) ? w - 1 : w;
        int p = 0;
        while (*s && p < lim) {
            if (*s == '\x1b') { while (*s && *s != 'm') { sa(t, s, 1); s++; } if (*s) { sa(t, s, 1); s++; } continue; }
            sa(t, s, 1); if ((*s & 0xC0) != 0x80) p++; s++;
        }
        if (ovf == TUI_OVERFLOW_ELLIPSIS && w >= 3 && p < vl) { sp(t, "\xe2\x80\xa6"); p++; }
        while (p < w) { sp(t, " "); p++; }
    }
}

/* ── Style map ─────────────────────────────────────────────────────── */
static const char *style_ansi(const char *s) {
    if (!s || !s[0]) return "\x1b[0m";
    switch (s[0]) {
    case 'b': return "\x1b[1m";
    case 'c': return s[4] == '_' ? "\x1b[36;1m" : "\x1b[36m";
    case 'd': return "\x1b[2m";
    case 'e': return "\x1b[31m";
    case 'g': return "\x1b[32m";
    case 'h': return "\x1b[33;1m";
    case 'n': return "\x1b[0m";
    case 's': return "\x1b[1;35m";
    case 'y': return "\x1b[33m";
    }
    return "\x1b[0m";
}

/* ── Terminal ──────────────────────────────────────────────────────── */
static void tty_restore(tui_t *t) {
    if (t->tty_raw && t->tty_fd >= 0) {
        tcsetattr(t->tty_fd, TCSAFLUSH, &t->orig_tios);
        int r = write(t->tty_fd, "\x1b[?25h\x1b[?1049l", 14); (void)r;
        t->tty_raw = 0;
    }
    if (t->tty_fd >= 0) { close(t->tty_fd); t->tty_fd = -1; }
}
static void atexit_restore(void) { if (g_atexit_tui) tty_restore(g_atexit_tui); }
static void sigwinch(int sig) { (void)sig; g_resized = 1; }
static void tty_size(tui_t *t) {
    struct winsize ws;
    if (t->tty_fd >= 0 && ioctl(t->tty_fd, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) {
        t->rows = ws.ws_row; t->cols = ws.ws_col;
    }
}

/* ── Panel helpers ─────────────────────────────────────────────────── */
static panel_st *pfind(tui_t *t, const char *nm) {
    if (!nm) return NULL;
    for (int i = 0; i < t->npanels; i++)
        if (strcmp(t->panels[i].def.name, nm) == 0) return &t->panels[i];
    return NULL;
}
static int pfind_idx(tui_t *t, const char *nm) {
    if (!nm) return -1;
    for (int i = 0; i < t->npanels; i++)
        if (strcmp(t->panels[i].def.name, nm) == 0) return i;
    return -1;
}

static void p_update_count(tui_t *t, panel_st *p) {
    char sql[256];
    snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM \"%s\"", p->def.name);
    sqlite3_stmt *st; p->row_count = 0;
    if (sqlite3_prepare_v2(t->db, sql, -1, &st, 0) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) p->row_count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
}

static void p_clamp(panel_st *p) {
    if (p->row_count == 0) { p->cursor = 0; p->scroll = 0; return; }
    if (p->cursor >= p->row_count) p->cursor = p->row_count - 1;
    if (p->cursor < 0) p->cursor = 0;
    int vh = p->h - (p->def.title ? 1 : 0);
    if (vh < 1) vh = 1;
    if (p->cursor < p->scroll) p->scroll = p->cursor;
    if (p->cursor >= p->scroll + vh) p->scroll = p->cursor - vh + 1;
    if (p->scroll < 0) p->scroll = 0;
}

static void p_sync_id(tui_t *t, panel_st *p) {
    p->cursor_id[0] = '\0';
    if (p->row_count == 0) return;
    char sql[1024];
    snprintf(sql, sizeof sql, "SELECT id FROM \"%s\" ORDER BY %s LIMIT 1 OFFSET %d",
             p->def.name, p->def.order_by, p->cursor);
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(t->db, sql, -1, &st, 0) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *v = (const char *)sqlite3_column_text(st, 0);
            if (v) snprintf(p->cursor_id, sizeof p->cursor_id, "%s", v);
        }
        sqlite3_finalize(st);
    }
}

static void p_resolve_id(tui_t *t, panel_st *p) {
    if (!p->cursor_id[0]) { p->cursor = 0; return; }
    char sql[1024];
    snprintf(sql, sizeof sql,
        "SELECT _rn FROM (SELECT id,ROW_NUMBER()OVER(ORDER BY %s)-1 AS _rn FROM \"%s\") WHERE id=?",
        p->def.order_by, p->def.name);
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(t->db, sql, -1, &st, 0) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, p->cursor_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) p->cursor = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
}

/* ── Layout resolution ─────────────────────────────────────────────── */
static void resolve_layout(tui_t *t) {
    int ah = t->rows - 1, aw = t->cols;
    for (int i = 0; i < t->npanels; i++) {
        panel_st *p = &t->panels[i];
        p->x = p->x_pct * aw / 100; p->y = p->y_pct * ah / 100;
        p->w = p->w_pct * aw / 100; p->h = p->h_pct * ah / 100;
        if (p->w < 1) p->w = 1; if (p->h < 1) p->h = 1;
        if (p->x + p->w > aw) p->w = aw - p->x;
        if (p->y + p->h > ah) p->h = ah - p->y;
    }
}

static void resolve_col_widths(const tui_panel_def *d, int tw, int *out) {
    int fx = 0, fl = 0;
    for (int i = 0; i < d->ncols; i++) {
        if (d->cols[i].width > 0) fx += d->cols[i].width; else fl += -(d->cols[i].width);
    }
    int rem = tw - fx; if (rem < 0) rem = 0;
    int sum = 0;
    for (int i = 0; i < d->ncols; i++) {
        out[i] = d->cols[i].width > 0 ? d->cols[i].width : (fl > 0 ? rem * (-(d->cols[i].width)) / fl : 0);
        sum += out[i];
    }
    if (sum < tw) for (int i = d->ncols - 1; i >= 0; i--) if (d->cols[i].width < 0) { out[i] += tw - sum; break; }
}

/* ── Read key ──────────────────────────────────────────────────────── */
static int read_key(tui_t *t) {
    if (t->tty_fd < 0) return TUI_K_NONE;
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
                    case '1': case '7': return TUI_K_HOME; case '4': case '8': return TUI_K_END;
                    case '5': return TUI_K_PGUP; case '6': return TUI_K_PGDN;
                }
            } else switch (s[1]) {
                case 'A': return TUI_K_UP;  case 'B': return TUI_K_DOWN;
                case 'C': return TUI_K_RIGHT; case 'D': return TUI_K_LEFT;
                case 'H': return TUI_K_HOME; case 'F': return TUI_K_END;
            }
        } else if (s[0] == 'O') switch (s[1]) {
            case 'H': return TUI_K_HOME; case 'F': return TUI_K_END;
        }
        return TUI_K_ESC;
    }
    return (unsigned char)c;
}

/* ── Render one panel ──────────────────────────────────────────────── */
static void render_panel(tui_t *t, panel_st *p) {
    const tui_panel_def *d = &p->def;
    int focused = (t->focus >= 0 && &t->panels[t->focus] == p);
    int cy = p->y, ch = p->h;

    if (d->title) {
        sf(t, "\x1b[%d;%dH", cy + 1, p->x + 1);
        sp(t, focused ? "\x1b[1;45;37m" : "\x1b[7m");
        char hdr[512]; snprintf(hdr, sizeof hdr, " %s ", d->title);
        sput_field(t, hdr, p->w, TUI_ALIGN_LEFT, TUI_OVERFLOW_TRUNCATE);
        sp(t, "\x1b[0m");
        cy++; ch--;
    }
    if (ch <= 0) return;

    int cw[32], pw = p->w;
    if (d->flags & TUI_PANEL_BORDER) pw--;
    resolve_col_widths(d, pw, cw);

    char sql[4096]; int pos = 0;
    pos += snprintf(sql + pos, sizeof sql - pos, "SELECT id,style");
    for (int c = 0; c < d->ncols; c++)
        pos += snprintf(sql + pos, sizeof sql - pos, ",\"%s\"", d->cols[c].name);
    pos += snprintf(sql + pos, sizeof sql - pos,
        " FROM \"%s\" ORDER BY %s LIMIT %d OFFSET %d", d->name, d->order_by, ch, p->scroll);

    sqlite3_stmt *st; int row = 0;
    if (sqlite3_prepare_v2(t->db, sql, -1, &st, 0) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW && row < ch) {
            int sr = cy + row + 1, sc = p->x + 1;
            if (d->flags & TUI_PANEL_BORDER) sc++;
            sf(t, "\x1b[%d;%dH", sr, sc);
            int idx = p->scroll + row;
            int is_cur = (d->flags & TUI_PANEL_CURSOR) && idx == p->cursor;
            if (is_cur && focused) sp(t, "\x1b[1;7m");
            else if (is_cur) sp(t, "\x1b[7m");
            else sp(t, style_ansi((const char *)sqlite3_column_text(st, 1)));
            for (int c = 0; c < d->ncols; c++) {
                const char *v = (const char *)sqlite3_column_text(st, 2 + c);
                sput_field(t, v ? v : "", cw[c], d->cols[c].align, d->cols[c].overflow);
            }
            sp(t, "\x1b[0m"); row++;
        }
        sqlite3_finalize(st);
    }
    while (row < ch) {
        sf(t, "\x1b[%d;%dH\x1b[0m", cy + row + 1, p->x + 1);
        for (int c = 0; c < p->w; c++) sp(t, " ");
        row++;
    }
    if (d->flags & TUI_PANEL_BORDER)
        for (int r = 0; r < p->h; r++)
            sf(t, "\x1b[%d;%dH\x1b[0m\xe2\x94\x82", p->y + r + 1, p->x + 1);
}

static void render_status(tui_t *t) {
    sf(t, "\x1b[%d;1H\x1b[7;1m", t->rows);
    sput_field(t, t->status, t->cols, TUI_ALIGN_LEFT, TUI_OVERFLOW_TRUNCATE);
    sp(t, "\x1b[0m");
}

static void render_all(tui_t *t) {
    resolve_layout(t);
    t->scr_len = 0; sp(t, "\x1b[H");
    for (int i = 0; i < t->npanels; i++) {
        panel_st *p = &t->panels[i];
        if (p->dirty) {
            p_update_count(t, p);
            p_resolve_id(t, p);
            p_clamp(p);
            p_sync_id(t, p);
            p->dirty = 0;
        }
        render_panel(t, p);
    }
    render_status(t);
    sflush(t);
}

/* ── Default navigation ────────────────────────────────────────────── */
static void default_nav(tui_t *t, int k) {
    if (t->focus < 0 || t->focus >= t->npanels) return;
    panel_st *p = &t->panels[t->focus];
    if (!(p->def.flags & TUI_PANEL_CURSOR)) return;
    int vh = p->h - (p->def.title ? 1 : 0);
    int pg = vh > 2 ? vh - 1 : 1;
    switch (k) {
    case TUI_K_UP:   case 'k': p->cursor--; break;
    case TUI_K_DOWN: case 'j': p->cursor++; break;
    case TUI_K_PGUP:           p->cursor -= pg; break;
    case TUI_K_PGDN:           p->cursor += pg; break;
    case TUI_K_HOME: case 'g': p->cursor = 0; break;
    case TUI_K_END:            p->cursor = p->row_count > 0 ? p->row_count - 1 : 0; break;
    default: return;
    }
    p_clamp(p);
    p_sync_id(t, p);
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  PUBLIC API                                                        */
/* ═══════════════════════════════════════════════════════════════════ */

tui_t *tui_open(sqlite3 *db) {
    tui_t *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->db = db; t->tty_fd = -1; t->focus = -1;
    t->next_timer_id = 1; t->rows = 24; t->cols = 80;

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
    r.c_cc[VMIN] = 0; r.c_cc[VTIME] = 1;
    tcsetattr(t->tty_fd, TCSAFLUSH, &r);
    t->tty_raw = 1;

    int wr = write(t->tty_fd, "\x1b[?1049h\x1b[?25l", 14); (void)wr;
    tty_size(t);

    struct sigaction sa = {{0}};
    sa.sa_handler = sigwinch;
    sigaction(SIGWINCH, &sa, 0);
    return t;
}

void tui_close(tui_t *t) {
    if (!t) return;
    tty_restore(t);
    if (t == g_atexit_tui) g_atexit_tui = NULL;
    free(t->scr); free(t);
}

void tui_add_panel(tui_t *tui, const tui_panel_def *def,
                   int x_pct, int y_pct, int w_pct, int h_pct) {
    if (!tui || tui->npanels >= MAX_PANELS) return;
    panel_st *p = &tui->panels[tui->npanels];
    memset(p, 0, sizeof *p);
    p->def = *def;
    p->x_pct = x_pct; p->y_pct = y_pct; p->w_pct = w_pct; p->h_pct = h_pct;
    p->dirty = 1;
    if (tui->focus < 0 && (def->flags & TUI_PANEL_CURSOR))
        tui->focus = tui->npanels;
    tui->npanels++;
}

void tui_dirty(tui_t *tui, const char *panel) {
    if (!tui) return;
    if (!panel) { for (int i = 0; i < tui->npanels; i++) tui->panels[i].dirty = 1; return; }
    panel_st *p = pfind(tui, panel);
    if (p) p->dirty = 1;
}

void tui_focus(tui_t *tui, const char *panel) {
    int i = pfind_idx(tui, panel);
    if (i >= 0) tui->focus = i;
}

const char *tui_get_focus(tui_t *tui) {
    if (!tui || tui->focus < 0 || tui->focus >= tui->npanels) return "";
    return tui->panels[tui->focus].def.name;
}

void tui_set_cursor(tui_t *tui, const char *panel, const char *id) {
    panel_st *p = tui ? pfind(tui, panel) : NULL;
    if (!p) return;
    if (!id) { p->cursor = 0; p->cursor_id[0] = '\0'; return; }
    snprintf(p->cursor_id, sizeof p->cursor_id, "%s", id);
    p_update_count(tui, p);
    p_resolve_id(tui, p);
    p_clamp(p);
}

void tui_set_cursor_idx(tui_t *tui, const char *panel, int idx) {
    panel_st *p = tui ? pfind(tui, panel) : NULL;
    if (!p) return;
    p_update_count(tui, p);
    p->cursor = idx;
    p_clamp(p);
    p_sync_id(tui, p);
}

int tui_get_cursor(tui_t *tui, const char *panel) {
    panel_st *p = tui ? pfind(tui, panel) : NULL;
    return p ? p->cursor : -1;
}

const char *tui_get_cursor_id(tui_t *tui, const char *panel) {
    panel_st *p = tui ? pfind(tui, panel) : NULL;
    return (p && p->cursor_id[0]) ? p->cursor_id : "";
}

int tui_row_count(tui_t *tui, const char *panel) {
    panel_st *p = tui ? pfind(tui, panel) : NULL;
    if (!p) return 0;
    p_update_count(tui, p);
    return p->row_count;
}

void tui_on_key(tui_t *tui, tui_key_cb cb, void *ctx) {
    if (!tui) return; tui->key_cb = cb; tui->key_ctx = ctx;
}

void tui_watch_fd(tui_t *tui, int fd, tui_fd_cb cb, void *ctx) {
    if (!tui) return;
    for (int i = 0; i < MAX_WATCHES; i++)
        if (!tui->watches[i].active) { tui->watches[i] = (fd_watch){fd, cb, ctx, 1}; return; }
}

void tui_unwatch_fd(tui_t *tui, int fd) {
    if (!tui) return;
    for (int i = 0; i < MAX_WATCHES; i++)
        if (tui->watches[i].active && tui->watches[i].fd == fd) { tui->watches[i].active = 0; return; }
}

int tui_add_timer(tui_t *tui, int ms, tui_timer_cb cb, void *ctx) {
    if (!tui) return -1;
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!tui->timers[i].active) {
            int id = tui->next_timer_id++;
            struct timeval now; gettimeofday(&now, NULL);
            tui->timers[i].id = id; tui->timers[i].ms = ms;
            tui->timers[i].fire.tv_sec = now.tv_sec + ms / 1000;
            tui->timers[i].fire.tv_usec = now.tv_usec + (ms % 1000) * 1000;
            if (tui->timers[i].fire.tv_usec >= 1000000) { tui->timers[i].fire.tv_sec++; tui->timers[i].fire.tv_usec -= 1000000; }
            tui->timers[i].cb = cb; tui->timers[i].ctx = ctx; tui->timers[i].active = 1;
            return id;
        }
    }
    return -1;
}

void tui_remove_timer(tui_t *tui, int timer_id) {
    if (!tui) return;
    for (int i = 0; i < MAX_TIMERS; i++)
        if (tui->timers[i].active && tui->timers[i].id == timer_id) { tui->timers[i].active = 0; return; }
}

void tui_quit(tui_t *tui) { if (tui) tui->quit_flag = 1; }

void tui_run(tui_t *tui) {
    if (!tui) return;
    tui->quit_flag = 0;
    while (!tui->quit_flag) {
        if (g_resized) {
            g_resized = 0; tty_size(tui);
            for (int i = 0; i < tui->npanels; i++) tui->panels[i].dirty = 1;
        }
        render_all(tui);

        fd_set rfds; FD_ZERO(&rfds); int mfd = -1;
        if (tui->tty_fd >= 0) { FD_SET(tui->tty_fd, &rfds); mfd = tui->tty_fd; }
        for (int i = 0; i < MAX_WATCHES; i++)
            if (tui->watches[i].active) { FD_SET(tui->watches[i].fd, &rfds); if (tui->watches[i].fd > mfd) mfd = tui->watches[i].fd; }

        struct timeval tv, *tvp = NULL;
        { struct timeval now; gettimeofday(&now, NULL); long min_ms = -1;
          for (int i = 0; i < MAX_TIMERS; i++) {
            if (!tui->timers[i].active) continue;
            long ms = (tui->timers[i].fire.tv_sec - now.tv_sec) * 1000 + (tui->timers[i].fire.tv_usec - now.tv_usec) / 1000;
            if (ms < 0) ms = 0;
            if (min_ms < 0 || ms < min_ms) min_ms = ms;
          }
          if (min_ms >= 0) { tv.tv_sec = min_ms / 1000; tv.tv_usec = (min_ms % 1000) * 1000; tvp = &tv; }
        }

        int sel = select(mfd + 1, &rfds, NULL, NULL, tvp);
        if (sel < 0 && errno == EINTR) continue;

        /* Timers */
        { struct timeval now; gettimeofday(&now, NULL);
          for (int i = 0; i < MAX_TIMERS; i++) {
            if (!tui->timers[i].active) continue;
            if (now.tv_sec > tui->timers[i].fire.tv_sec || (now.tv_sec == tui->timers[i].fire.tv_sec && now.tv_usec >= tui->timers[i].fire.tv_usec)) {
                int ms = tui->timers[i].ms;
                int re = tui->timers[i].cb(tui, tui->timers[i].ctx);
                if (re && tui->timers[i].active) {
                    tui->timers[i].fire.tv_sec = now.tv_sec + ms / 1000;
                    tui->timers[i].fire.tv_usec = now.tv_usec + (ms % 1000) * 1000;
                    if (tui->timers[i].fire.tv_usec >= 1000000) { tui->timers[i].fire.tv_sec++; tui->timers[i].fire.tv_usec -= 1000000; }
                } else tui->timers[i].active = 0;
            }
          }
        }
        if (tui->quit_flag) break;

        /* FD callbacks */
        if (sel > 0)
            for (int i = 0; i < MAX_WATCHES; i++)
                if (tui->watches[i].active && FD_ISSET(tui->watches[i].fd, &rfds))
                    tui->watches[i].cb(tui, tui->watches[i].fd, tui->watches[i].ctx);
        if (tui->quit_flag) break;

        /* Keyboard */
        if (sel > 0 && tui->tty_fd >= 0 && FD_ISSET(tui->tty_fd, &rfds)) {
            int k = read_key(tui);
            if (k != TUI_K_NONE) {
                const char *fp = "", *fid = ""; int fc = 0;
                if (tui->focus >= 0 && tui->focus < tui->npanels) {
                    panel_st *f = &tui->panels[tui->focus];
                    fp = f->def.name; fc = f->cursor; fid = f->cursor_id;
                }
                int res = TUI_DEFAULT;
                if (tui->key_cb) res = tui->key_cb(tui, k, fp, fc, fid, tui->key_ctx);
                if (res == TUI_QUIT) break;
                if (res == TUI_DEFAULT) default_nav(tui, k);
            }
        }
    }
}

void tui_set_status(tui_t *tui, const char *text) {
    if (!tui) return;
    if (text) snprintf(tui->status, sizeof tui->status, "%s", text);
    else tui->status[0] = '\0';
}

int tui_rows(tui_t *tui) { return tui ? tui->rows : 24; }
int tui_cols(tui_t *tui) { return tui ? tui->cols : 80; }

/* ── Line editor ───────────────────────────────────────────────────── */
int tui_line_edit(tui_t *tui, const char *prompt, char *buf, int bsz) {
    if (!tui || tui->tty_fd < 0) return 0;
    int len = strlen(buf), pos = len;
    for (;;) {
        tui->scr_len = 0;
        sf(tui, "\x1b[%d;1H\x1b[7m%s%s", tui->rows, prompt, buf);
        for (int i = (int)strlen(prompt) + len; i < tui->cols; i++) sp(tui, " ");
        sf(tui, "\x1b[0m\x1b[%d;%dH\x1b[?25h", tui->rows, (int)strlen(prompt) + pos + 1);
        sflush(tui);
        int k = read_key(tui);
        if (k == TUI_K_NONE) continue;
        if (k == TUI_K_ENTER || k == '\n') { sp(tui, "\x1b[?25l"); sflush(tui); return 1; }
        if (k == TUI_K_ESC) { sp(tui, "\x1b[?25l"); sflush(tui); return 0; }
        if ((k == TUI_K_BS || k == 8) && pos > 0) { memmove(buf+pos-1, buf+pos, len-pos+1); pos--; len--; }
        else if (k >= 32 && k < 127 && len < bsz - 1) { memmove(buf+pos+1, buf+pos, len-pos+1); buf[pos++] = k; len++; }
    }
}

/* ── Help screen ───────────────────────────────────────────────────── */
void tui_show_help(tui_t *tui, const char **lines) {
    if (!tui || tui->tty_fd < 0) return;
    tui->scr_len = 0; sp(tui, "\x1b[H\x1b[2J");
    for (int i = 0; lines[i]; i++) sf(tui, "\x1b[%d;1H\x1b[36m%s\x1b[0m", i+1, lines[i]);
    sflush(tui);
    while (read_key(tui) == TUI_K_NONE) ;
}

/* ── SQL prompt ────────────────────────────────────────────────────── */
void tui_sql_prompt(tui_t *tui) {
    if (!tui || tui->tty_fd < 0) return;
    sqlite3 *db = tui->db;
    char sql[1024] = "";
    if (!tui_line_edit(tui, "SQL> ", sql, sizeof sql) || !sql[0]) return;
    tui->scr_len = 0; sp(tui, "\x1b[H\x1b[2J");
    sf(tui, "\x1b[1;1H\x1b[33;1mSQL: %s\x1b[0m", sql);
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, sql, -1, &st, 0) != SQLITE_OK) {
        sf(tui, "\x1b[3;1H\x1b[31m%s\x1b[0m", sqlite3_errmsg(db));
        sflush(tui); while (read_key(tui) == TUI_K_NONE) ; return;
    }
    int nc = sqlite3_column_count(st), row = 3;
    sf(tui, "\x1b[%d;1H\x1b[36;1m", row++);
    for (int c = 0; c < nc && c < 10; c++) sf(tui, "%-20s", sqlite3_column_name(st, c));
    sp(tui, "\x1b[0m");
    sf(tui, "\x1b[%d;1H", row++);
    for (int c = 0; c < nc && c < 10; c++) sp(tui, "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 ");
    int nr = 0;
    while (sqlite3_step(st) == SQLITE_ROW && row < tui->rows - 2) {
        sf(tui, "\x1b[%d;1H", row++);
        for (int c = 0; c < nc && c < 10; c++) {
            const char *v = (const char *)sqlite3_column_text(st, c);
            char tmp[21]; snprintf(tmp, sizeof tmp, "%.20s", v ? v : "NULL");
            sf(tui, "%-20s", tmp);
        }
        nr++;
    }
    sqlite3_finalize(st);
    sf(tui, "\x1b[%d;1H\x1b[2m%d rows.\x1b[0m", row + 1, nr);
    sflush(tui); while (read_key(tui) == TUI_K_NONE) ;
}
