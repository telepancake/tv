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

#define MAX_PANELS  32
#define MAX_WATCHES 16
#define MAX_TIMERS  16
#define PANEL_CACHE_ROWS  256
#define PANEL_NCOLS_MAX    32
#define PANEL_CACHE_POOL  (256*1024)

typedef struct {
    int id_off;
    int style_off;
    int col_off[PANEL_NCOLS_MAX];
} pcache_row_t;

typedef struct {
    tui_panel_def def;
    int x, y, w, h;
    int cursor, scroll;
    int row_count;
    int dirty;
    char cursor_id[4096];
    pcache_row_t *cache_rows;
    char         *cache_pool;
    int           cache_pool_pos;
    int           cache_start;
    int           cache_count;
} panel_st;

typedef struct { int fd; tui_fd_cb cb; void *ctx; int active; } fd_watch;
typedef struct {
    int id, ms, active;
    struct timeval fire;
    tui_timer_cb cb;
    void *ctx;
} timer_ent;

struct tui {
    tui_data_source source;
    void *source_ctx;
    int tty_fd;
    struct termios orig_tios;
    int tty_raw, rows, cols;
    panel_st panels[MAX_PANELS];
    int npanels, focus;
    tui_box_t *layout_root;
    char status[1024];
    tui_key_cb key_cb;
    void *key_ctx;
    fd_watch watches[MAX_WATCHES];
    timer_ent timers[MAX_TIMERS];
    int next_timer_id, quit_flag;
    char *scr;
    int scr_len, scr_cap;
};

static volatile int g_resized = 0;
static tui_t *g_atexit_tui = NULL;

static void sa(tui_t *t, const char *s, int n) {
    if (t->scr_len + n + 1 > t->scr_cap) {
        t->scr_cap = (t->scr_len + n + 1) * 2;
        if (t->scr_cap < 8192) t->scr_cap = 8192;
        t->scr = realloc(t->scr, t->scr_cap);
    }
    memcpy(t->scr + t->scr_len, s, n);
    t->scr_len += n;
}
static void sp(tui_t *t, const char *s) { sa(t, s, (int)strlen(s)); }
static void sf(tui_t *t, const char *fmt, ...) {
    char buf[4096];
    va_list a;
    va_start(a, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, a);
    va_end(a);
    if (n > 0) sa(t, buf, n < (int)sizeof buf ? n : (int)sizeof buf - 1);
}
static void sflush(tui_t *t) {
    if (t->scr_len > 0 && t->tty_fd >= 0) {
        int r = (int)write(t->tty_fd, t->scr, t->scr_len);
        (void)r;
    }
    t->scr_len = 0;
}

static int visible_len(const char *s) {
    int n = 0;
    while (*s) {
        if (*s == '\x1b') {
            while (*s && *s != 'm') s++;
            if (*s) s++;
            continue;
        }
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
        if (align == TUI_ALIGN_RIGHT) lp = pad;
        else if (align == TUI_ALIGN_CENTER) { lp = pad / 2; rp = pad - lp; }
        else rp = pad;
        for (int i = 0; i < lp; i++) sp(t, " ");
        while (*s) {
            if (*s == '\x1b') {
                while (*s && *s != 'm') { sa(t, s, 1); s++; }
                if (*s) { sa(t, s, 1); s++; }
                continue;
            }
            sa(t, s, 1);
            s++;
        }
        for (int i = 0; i < rp; i++) sp(t, " ");
    } else {
        int lim = (ovf == TUI_OVERFLOW_ELLIPSIS && w >= 3) ? w - 1 : w;
        int p = 0;
        while (*s && p < lim) {
            if (*s == '\x1b') {
                while (*s && *s != 'm') { sa(t, s, 1); s++; }
                if (*s) { sa(t, s, 1); s++; }
                continue;
            }
            sa(t, s, 1);
            if ((*s & 0xC0) != 0x80) p++;
            s++;
        }
        if (ovf == TUI_OVERFLOW_ELLIPSIS && w >= 3 && p < vl) {
            sp(t, "\xe2\x80\xa6");
            p++;
        }
        while (p < w) { sp(t, " "); p++; }
    }
}

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
    default: return "\x1b[0m";
    }
}

static void notify_size_changed(tui_t *t) {
    if (t && t->source.size_changed) t->source.size_changed(t->rows, t->cols, t->source_ctx);
}

static void tty_restore(tui_t *t) {
    if (t->tty_raw && t->tty_fd >= 0) {
        tcsetattr(t->tty_fd, TCSAFLUSH, &t->orig_tios);
        int r = (int)write(t->tty_fd, "\x1b[?25h\x1b[?1049l", 14);
        (void)r;
        t->tty_raw = 0;
    }
    if (t->tty_fd >= 0) { close(t->tty_fd); t->tty_fd = -1; }
}
static void atexit_restore(void) { if (g_atexit_tui) tty_restore(g_atexit_tui); }
static void sigwinch(int sig) { (void)sig; g_resized = 1; }
static void tty_size(tui_t *t) {
    struct winsize ws;
    if (t->tty_fd >= 0 && ioctl(t->tty_fd, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) {
        t->rows = ws.ws_row;
        t->cols = ws.ws_col;
        notify_size_changed(t);
    }
}

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
    p->row_count = 0;
    if (t->source.row_count)
        p->row_count = t->source.row_count(p->def.name, t->source_ctx);
    if (p->row_count < 0) p->row_count = 0;
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
    if (p->row_count == 0 || !t->source.row_get) return;
    int ci = p->cursor - p->cache_start;
    if (p->cache_count > 0 && p->cache_rows && p->cache_pool &&
        ci >= 0 && ci < p->cache_count && p->cache_rows[ci].id_off >= 0) {
        snprintf(p->cursor_id, sizeof p->cursor_id, "%s",
                 p->cache_pool + p->cache_rows[ci].id_off);
        return;
    }
    tui_row_ref row;
    memset(&row, 0, sizeof row);
    if (t->source.row_get(p->def.name, p->cursor, &row, t->source_ctx) && row.id)
        snprintf(p->cursor_id, sizeof p->cursor_id, "%s", row.id);
}

static void p_resolve_id(tui_t *t, panel_st *p) {
    if (!p->cursor_id[0]) { p->cursor = 0; return; }
    if (t->source.row_find) {
        int idx = t->source.row_find(p->def.name, p->cursor_id, t->source_ctx);
        if (idx >= 0) p->cursor = idx;
        return;
    }
    if (!t->source.row_get) return;
    tui_row_ref row;
    for (int i = 0; i < p->row_count; i++) {
        memset(&row, 0, sizeof row);
        if (t->source.row_get(p->def.name, i, &row, t->source_ctx) && row.id && strcmp(row.id, p->cursor_id) == 0) {
            p->cursor = i;
            return;
        }
    }
}

static int pool_add(panel_st *p, const char *s) {
    if (!s) return -1;
    int len = (int)strlen(s) + 1;
    if (p->cache_pool_pos + len > PANEL_CACHE_POOL) return -1;
    int off = p->cache_pool_pos;
    memcpy(p->cache_pool + off, s, len);
    p->cache_pool_pos += len;
    return off;
}

static void p_load_cache(tui_t *t, panel_st *p, int from_row) {
    if (!p->cache_rows || !p->cache_pool || !t->source.row_get) return;
    if (from_row < 0) from_row = 0;
    p->cache_pool_pos = 0;
    p->cache_count = 0;
    p->cache_start = from_row;
    int nc = p->def.ncols < PANEL_NCOLS_MAX ? p->def.ncols : PANEL_NCOLS_MAX;
    tui_row_ref row;
    for (int i = from_row; i < p->row_count && p->cache_count < PANEL_CACHE_ROWS; i++) {
        memset(&row, 0, sizeof row);
        if (!t->source.row_get(p->def.name, i, &row, t->source_ctx)) break;
        pcache_row_t *r = &p->cache_rows[p->cache_count++];
        r->id_off = pool_add(p, row.id);
        r->style_off = pool_add(p, row.style);
        for (int c = 0; c < nc; c++) r->col_off[c] = pool_add(p, row.cols[c]);
        for (int c = nc; c < PANEL_NCOLS_MAX; c++) r->col_off[c] = -1;
    }
}

static void p_ensure_cached(tui_t *t, panel_st *p, int rn) {
    if (p->cache_count > 0 && rn >= p->cache_start && rn < p->cache_start + p->cache_count) return;
    int ahead = PANEL_CACHE_ROWS / 4;
    int from = rn > ahead ? rn - ahead : 0;
    p_load_cache(t, p, from);
}

static int box_contains_focus(tui_t *t, tui_box_t *b) {
    if (!b) return 0;
    if (b->type == TUI_BOX_PANEL) {
        if (t->focus < 0 || t->focus >= t->npanels) return 0;
        return b->def && strcmp(b->def->name, t->panels[t->focus].def.name) == 0;
    }
    for (int i = 0; i < b->nchildren; i++)
        if (box_contains_focus(t, b->children[i])) return 1;
    return 0;
}

static void resolve_box(tui_t *t, tui_box_t *b, int x, int y, int w, int h) {
    if (!b) return;
    if (b->type == TUI_BOX_PANEL) {
        panel_st *p = pfind(t, b->def->name);
        if (p) { p->x = x; p->y = y; p->w = w < 1 ? 1 : w; p->h = h < 1 ? 1 : h; }
        return;
    }
    int is_hbox = (b->type == TUI_BOX_HBOX);
    int axis = is_hbox ? w : h;

    /* hscroll: visible subset of children, auto-scroll to keep focus visible */
    if (is_hbox && (b->flags & TUI_BOX_HSCROLL) && b->nchildren > 0) {
        int min_col = 14, nvis = w / min_col;
        if (nvis < 1) nvis = 1;
        if (nvis > b->nchildren) nvis = b->nchildren;
        int cw = w / nvis;
        int focus_child = 0;
        for (int i = 0; i < b->nchildren; i++)
            if (box_contains_focus(t, b->children[i])) { focus_child = i; break; }
        int first = focus_child - nvis / 2;
        if (first < 0) first = 0;
        if (first + nvis > b->nchildren) first = b->nchildren - nvis;
        if (first < 0) first = 0;
        int pos = x;
        for (int i = 0; i < b->nchildren; i++) {
            if (i >= first && i < first + nvis) {
                int tw = (i == first + nvis - 1) ? w - (pos - x) : cw;
                resolve_box(t, b->children[i], pos, y, tw, h);
                pos += tw;
            } else {
                resolve_box(t, b->children[i], -9999, y, 1, h);
            }
        }
        return;
    }

    int total_weight = 0, fixed_sum = 0;
    for (int i = 0; i < b->nchildren; i++) {
        tui_box_t *c = b->children[i];
        if (c->weight == 0) fixed_sum += c->min_size;
        else { total_weight += c->weight; if (c->min_size > 0) fixed_sum += c->min_size; }
    }
    int flex = axis - fixed_sum;
    if (flex < 0) flex = 0;
    int pos = is_hbox ? x : y;
    int remaining = axis;
    for (int i = 0; i < b->nchildren; i++) {
        tui_box_t *c = b->children[i];
        int sz;
        if (c->weight == 0) sz = c->min_size;
        else {
            sz = c->min_size + (total_weight > 0 ? flex * c->weight / total_weight : 0);
            int is_last_flex = 1;
            for (int j = i + 1; j < b->nchildren; j++)
                if (b->children[j]->weight > 0) { is_last_flex = 0; break; }
            if (is_last_flex) {
                int tail_fixed = 0;
                for (int j = i + 1; j < b->nchildren; j++)
                    if (b->children[j]->weight == 0) tail_fixed += b->children[j]->min_size;
                sz = remaining - tail_fixed;
            }
        }
        if (sz < 1) sz = 1;
        if (is_hbox) resolve_box(t, c, pos, y, sz, h);
        else resolve_box(t, c, x, pos, w, sz);
        pos += sz;
        remaining -= sz;
    }
}

static void resolve_layout(tui_t *t) {
    int ah = t->rows - 1;
    int aw = t->cols;
    if (t->layout_root) resolve_box(t, t->layout_root, 0, 0, aw, ah);
}

static void resolve_col_widths(const tui_panel_def *d, int tw, int *out) {
    int fx = 0, fl = 0;
    for (int i = 0; i < d->ncols; i++) {
        if (d->cols[i].width > 0) fx += d->cols[i].width;
        else fl += -d->cols[i].width;
    }
    int rem = tw - fx;
    if (rem < 0) rem = 0;
    int sum = 0;
    for (int i = 0; i < d->ncols; i++) {
        out[i] = d->cols[i].width > 0 ? d->cols[i].width : (fl > 0 ? rem * (-d->cols[i].width) / fl : 0);
        sum += out[i];
    }
    if (sum < tw) {
        for (int i = d->ncols - 1; i >= 0; i--) {
            if (d->cols[i].width < 0) { out[i] += tw - sum; break; }
        }
    }
}

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
                    case '1': case '7': return TUI_K_HOME;
                    case '4': case '8': return TUI_K_END;
                    case '5': return TUI_K_PGUP;
                    case '6': return TUI_K_PGDN;
                }
            } else switch (s[1]) {
                case 'A': return TUI_K_UP;
                case 'B': return TUI_K_DOWN;
                case 'C': return TUI_K_RIGHT;
                case 'D': return TUI_K_LEFT;
                case 'H': return TUI_K_HOME;
                case 'F': return TUI_K_END;
            }
        } else if (s[0] == 'O') switch (s[1]) {
            case 'H': return TUI_K_HOME;
            case 'F': return TUI_K_END;
        }
        return TUI_K_ESC;
    }
    return (unsigned char)c;
}

static void render_panel(tui_t *t, panel_st *p) {
    if (p->x < -9000) return;  /* hidden by hscroll */
    const tui_panel_def *d = &p->def;
    int focused = (t->focus >= 0 && &t->panels[t->focus] == p);
    int cy = p->y, ch = p->h;
    if (d->title) {
        sf(t, "\x1b[%d;%dH", cy + 1, p->x + 1);
        sp(t, focused ? "\x1b[1;45;37m" : "\x1b[7m");
        char hdr[512];
        snprintf(hdr, sizeof hdr, " %s ", d->title);
        sput_field(t, hdr, p->w, TUI_ALIGN_LEFT, TUI_OVERFLOW_TRUNCATE);
        sp(t, "\x1b[0m");
        cy++;
        ch--;
    }
    if (ch <= 0) return;
    int cw[32], pw = p->w;
    if (d->flags & TUI_PANEL_BORDER) pw--;
    resolve_col_widths(d, pw, cw);
    if (p->cache_rows && p->cache_pool && p->row_count > 0) {
        p_ensure_cached(t, p, p->scroll);
        int last_vis = p->scroll + ch - 1;
        if (last_vis >= p->row_count) last_vis = p->row_count - 1;
        if (last_vis >= p->cache_start + p->cache_count) p_ensure_cached(t, p, last_vis);
    }
    int row = 0;
    int nc = d->ncols < PANEL_NCOLS_MAX ? d->ncols : PANEL_NCOLS_MAX;
    for (int rn = p->scroll; row < ch; rn++, row++) {
        int sr = cy + row + 1, sc = p->x + 1;
        if (d->flags & TUI_PANEL_BORDER) sc++;
        sf(t, "\x1b[%d;%dH", sr, sc);
        int ci = rn - p->cache_start;
        int has_row = (p->cache_rows && p->cache_pool && p->cache_count > 0 && ci >= 0 && ci < p->cache_count);
        if (!has_row) {
            sp(t, "\x1b[0m");
            for (int c = 0; c < pw; c++) sp(t, " ");
            continue;
        }
        pcache_row_t *r = &p->cache_rows[ci];
        int is_cur = (d->flags & TUI_PANEL_CURSOR) && rn == p->cursor;
        if (is_cur && focused) sp(t, "\x1b[1;7m");
        else if (is_cur) sp(t, "\x1b[7m");
        else {
            const char *sty = (r->style_off >= 0) ? p->cache_pool + r->style_off : "";
            sp(t, style_ansi(sty));
        }
        for (int c = 0; c < nc; c++) {
            const char *v = (r->col_off[c] >= 0) ? p->cache_pool + r->col_off[c] : "";
            sput_field(t, v, cw[c], d->cols[c].align, d->cols[c].overflow);
        }
        sp(t, "\x1b[0m");
    }
    if (d->flags & TUI_PANEL_BORDER) {
        for (int r = 0; r < p->h; r++)
            sf(t, "\x1b[%d;%dH\x1b[0m\xe2\x94\x82", p->y + r + 1, p->x + 1);
    }
}

static void render_status(tui_t *t) {
    sf(t, "\x1b[%d;1H\x1b[7;1m", t->rows);
    sput_field(t, t->status, t->cols, TUI_ALIGN_LEFT, TUI_OVERFLOW_TRUNCATE);
    sp(t, "\x1b[0m");
}

static void render_all(tui_t *t) {
    resolve_layout(t);
    t->scr_len = 0;
    sp(t, "\x1b[H");
    for (int i = 0; i < t->npanels; i++) {
        panel_st *p = &t->panels[i];
        if (p->dirty) {
            p_update_count(t, p);
            p_resolve_id(t, p);
            p_clamp(p);
            p->cache_count = 0;
            p_sync_id(t, p);
            p->dirty = 0;
        }
        render_panel(t, p);
    }
    render_status(t);
    sflush(t);
}

static int is_engine_nav_key(int k) {
    switch (k) {
    case TUI_K_UP: case TUI_K_DOWN:
    case TUI_K_PGUP: case TUI_K_PGDN:
    case TUI_K_HOME: case TUI_K_END:
    case TUI_K_TAB:
    case 'j': case 'k': case 'g':
        return 1;
    default:
        return 0;
    }
}

static void default_nav(tui_t *t, int k) {
    if (k == TUI_K_TAB) {
        if (t->npanels <= 0) return;
        int start = t->focus < 0 ? 0 : t->focus;
        for (int off = 1; off <= t->npanels; off++) {
            int idx = (start + off) % t->npanels;
            if (t->panels[idx].def.flags & TUI_PANEL_CURSOR) {
                t->focus = idx;
                p_update_count(t, &t->panels[idx]);
                p_clamp(&t->panels[idx]);
                p_sync_id(t, &t->panels[idx]);
                return;
            }
        }
        return;
    }
    if (t->focus < 0 || t->focus >= t->npanels) return;
    panel_st *p = &t->panels[t->focus];
    if (!(p->def.flags & TUI_PANEL_CURSOR)) return;
    int vh = p->h - (p->def.title ? 1 : 0);
    int pg = vh > 2 ? vh - 1 : 1;
    switch (k) {
    case TUI_K_UP: case 'k': p->cursor--; break;
    case TUI_K_DOWN: case 'j': p->cursor++; break;
    case TUI_K_PGUP: p->cursor -= pg; break;
    case TUI_K_PGDN: p->cursor += pg; break;
    case TUI_K_HOME: case 'g': p->cursor = 0; break;
    case TUI_K_END: p->cursor = p->row_count > 0 ? p->row_count - 1 : 0; break;
    default: return;
    }
    p_clamp(p);
    p_sync_id(t, p);
}

tui_t *tui_open(const tui_data_source *source, void *source_ctx) {
    tui_t *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    if (source) t->source = *source;
    t->source_ctx = source_ctx;
    t->tty_fd = -1;
    t->focus = -1;
    t->next_timer_id = 1;
    t->rows = 24;
    t->cols = 80;
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
    int wr = (int)write(t->tty_fd, "\x1b[?1049h\x1b[?25l", 14);
    (void)wr;
    tty_size(t);
    notify_size_changed(t);
    struct sigaction sa = {{0}};
    sa.sa_handler = sigwinch;
    sigaction(SIGWINCH, &sa, 0);
    return t;
}

tui_t *tui_open_headless(const tui_data_source *source, void *source_ctx, int rows, int cols) {
    tui_t *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    if (source) t->source = *source;
    t->source_ctx = source_ctx;
    t->tty_fd = -1;
    t->focus = -1;
    t->next_timer_id = 1;
    t->rows = rows > 0 ? rows : 24;
    t->cols = cols > 0 ? cols : 80;
    notify_size_changed(t);
    return t;
}

void tui_close(tui_t *t) {
    if (!t) return;
    for (int i = 0; i < t->npanels; i++) {
        free(t->panels[i].cache_rows);
        free(t->panels[i].cache_pool);
    }
    tty_restore(t);
    if (t == g_atexit_tui) g_atexit_tui = NULL;
    free(t->scr);
    free(t);
}

void tui_set_layout(tui_t *tui, tui_box_t *root) {
    if (!tui) return;
    tui->layout_root = root;
    struct { tui_box_t *b; } stack[256];
    int top = 0;
    stack[top++].b = root;
    while (top > 0) {
        tui_box_t *b = stack[--top].b;
        if (!b) continue;
        if (b->type == TUI_BOX_PANEL) {
            if (!pfind(tui, b->def->name) && tui->npanels < MAX_PANELS) {
                panel_st *p = &tui->panels[tui->npanels];
                memset(p, 0, sizeof *p);
                p->def = *b->def;
                p->dirty = 1;
                p->cache_rows = malloc(PANEL_CACHE_ROWS * sizeof(pcache_row_t));
                p->cache_pool = malloc(PANEL_CACHE_POOL);
                if (!p->cache_rows || !p->cache_pool) {
                    free(p->cache_rows); p->cache_rows = NULL;
                    free(p->cache_pool); p->cache_pool = NULL;
                }
                if (tui->focus < 0 && (b->def->flags & TUI_PANEL_CURSOR)) tui->focus = tui->npanels;
                tui->npanels++;
            }
        } else {
            for (int i = b->nchildren - 1; i >= 0 && top < 256; i--) stack[top++].b = b->children[i];
        }
    }
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

int tui_get_scroll(tui_t *tui, const char *panel) {
    panel_st *p = tui ? pfind(tui, panel) : NULL;
    return p ? p->scroll : 0;
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
    if (!tui) return;
    tui->key_cb = cb;
    tui->key_ctx = ctx;
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
            tui->timers[i].id = id;
            tui->timers[i].ms = ms;
            tui->timers[i].fire.tv_sec = now.tv_sec + ms / 1000;
            tui->timers[i].fire.tv_usec = now.tv_usec + (ms % 1000) * 1000;
            if (tui->timers[i].fire.tv_usec >= 1000000) { tui->timers[i].fire.tv_sec++; tui->timers[i].fire.tv_usec -= 1000000; }
            tui->timers[i].cb = cb;
            tui->timers[i].ctx = ctx;
            tui->timers[i].active = 1;
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
            g_resized = 0;
            tty_size(tui);
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
          if (min_ms >= 0) { tv.tv_sec = min_ms / 1000; tv.tv_usec = (min_ms % 1000) * 1000; tvp = &tv; } }
        int sel = select(mfd + 1, &rfds, NULL, NULL, tvp);
        if (sel < 0 && errno == EINTR) continue;
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
          } }
        if (tui->quit_flag) break;
        if (sel > 0)
            for (int i = 0; i < MAX_WATCHES; i++)
                if (tui->watches[i].active && FD_ISSET(tui->watches[i].fd, &rfds))
                    tui->watches[i].cb(tui, tui->watches[i].fd, tui->watches[i].ctx);
        if (tui->quit_flag) break;
        if (sel > 0 && tui->tty_fd >= 0 && FD_ISSET(tui->tty_fd, &rfds)) {
            int k = read_key(tui);
            if (k != TUI_K_NONE) {
                if (is_engine_nav_key(k)) {
                    default_nav(tui, k);
                    if (tui->key_cb) {
                        const char *fp2 = "", *fid2 = ""; int fc2 = 0;
                        if (tui->focus >= 0 && tui->focus < tui->npanels) {
                            panel_st *f2 = &tui->panels[tui->focus];
                            fp2 = f2->def.name; fc2 = f2->cursor; fid2 = f2->cursor_id;
                        }
                        int res = tui->key_cb(tui, TUI_K_NONE, fp2, fc2, fid2, tui->key_ctx);
                        if (res == TUI_QUIT) break;
                    }
                    continue;
                }
                const char *fp = "", *fid = ""; int fc = 0;
                if (tui->focus >= 0 && tui->focus < tui->npanels) {
                    panel_st *f = &tui->panels[tui->focus];
                    fp = f->def.name; fc = f->cursor; fid = f->cursor_id;
                }
                int res = TUI_DEFAULT;
                if (tui->key_cb) res = tui->key_cb(tui, k, fp, fc, fid, tui->key_ctx);
                if (res == TUI_QUIT) break;
                if (res == TUI_DEFAULT) {
                    default_nav(tui, k);
                    if (tui->key_cb) {
                        const char *fp2 = "", *fid2 = ""; int fc2 = 0;
                        if (tui->focus >= 0 && tui->focus < tui->npanels) {
                            panel_st *f2 = &tui->panels[tui->focus];
                            fp2 = f2->def.name; fc2 = f2->cursor; fid2 = f2->cursor_id;
                        }
                        tui->key_cb(tui, TUI_K_NONE, fp2, fc2, fid2, tui->key_ctx);
                    }
                }
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

int tui_line_edit(tui_t *tui, const char *prompt, char *buf, int bsz) {
    if (!tui || tui->tty_fd < 0) return 0;
    int len = (int)strlen(buf), pos = len;
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
        if ((k == TUI_K_BS || k == 8) && pos > 0) { memmove(buf + pos - 1, buf + pos, len - pos + 1); pos--; len--; }
        else if (k >= 32 && k < 127 && len < bsz - 1) { memmove(buf + pos + 1, buf + pos, len - pos + 1); buf[pos++] = (char)k; len++; }
    }
}

void tui_show_help(tui_t *tui, const char **lines) {
    if (!tui || tui->tty_fd < 0) return;
    tui->scr_len = 0;
    sp(tui, "\x1b[H\x1b[2J");
    for (int i = 0; lines[i]; i++) sf(tui, "\x1b[%d;1H\x1b[36m%s\x1b[0m", i + 1, lines[i]);
    sflush(tui);
    while (read_key(tui) == TUI_K_NONE) ;
}

void tui_input_key(tui_t *tui, int key) {
    if (!tui) return;
    for (int i = 0; i < tui->npanels; i++) {
        panel_st *p = &tui->panels[i];
        p_update_count(tui, p);
        if (p->dirty) { p_resolve_id(tui, p); p_clamp(p); p->dirty = 0; }
    }
    if (is_engine_nav_key(key)) {
        default_nav(tui, key);
        if (tui->key_cb) {
            const char *fp2 = "", *fid2 = ""; int fc2 = 0;
            if (tui->focus >= 0 && tui->focus < tui->npanels) {
                panel_st *f2 = &tui->panels[tui->focus];
                fp2 = f2->def.name; fc2 = f2->cursor; fid2 = f2->cursor_id;
            }
            tui->key_cb(tui, TUI_K_NONE, fp2, fc2, fid2, tui->key_ctx);
        }
        return;
    }
    int res = TUI_DEFAULT;
    const char *fp = "", *fid = ""; int fc = 0;
    if (tui->focus >= 0 && tui->focus < tui->npanels) {
        panel_st *f = &tui->panels[tui->focus];
        fp = f->def.name; fc = f->cursor; fid = f->cursor_id;
    }
    if (tui->key_cb) res = tui->key_cb(tui, key, fp, fc, fid, tui->key_ctx);
    if (res == TUI_DEFAULT) {
        default_nav(tui, key);
        if (tui->key_cb) {
            const char *fp2 = "", *fid2 = ""; int fc2 = 0;
            if (tui->focus >= 0 && tui->focus < tui->npanels) {
                panel_st *f2 = &tui->panels[tui->focus];
                fp2 = f2->def.name; fc2 = f2->cursor; fid2 = f2->cursor_id;
            }
            tui->key_cb(tui, TUI_K_NONE, fp2, fc2, fid2, tui->key_ctx);
        }
    }
}

void tui_resize(tui_t *tui, int rows, int cols) {
    if (!tui) return;
    if (rows > 0) tui->rows = rows;
    if (cols > 0) tui->cols = cols;
    notify_size_changed(tui);
    for (int i = 0; i < tui->npanels; i++) tui->panels[i].dirty = 1;
}
