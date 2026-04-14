/*
 * fv - filesystem viewer
 *
 * A Smalltalk-style column browser built on engine.h/engine.c.
 *
 * Layout:
 *   ┌──────┬──────┬──────┐
 *   │ d0   │ d1   │ d2   │   <- equally-wide dir columns (one per depth)
 *   │ ...  │ ...  │ ...  │      engine auto-scrolls to keep focused column
 *   ├──────┴──────┴──────┤      visible (TUI_BOX_HSCROLL)
 *   │ content            │   <- large file-content pane (text or hex+text)
 *   └────────────────────┘
 *   full path of entity under cursor               <- status bar
 *
 * Keys:
 *   ↑ ↓ j k  PgUp PgDn  Home/g End   Navigate within a column
 *   ←  h                              Focus the left column
 *   →  Enter                          Enter dir / focus content pane
 *   Tab                               Cycle all panels
 *   H                                 Toggle hex mode in content pane
 *   .                                 Toggle hidden files
 *   ?                                 Help
 *   q  Esc                            Quit
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>

#include "engine.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Maximum depth we can navigate.  We create one engine panel per depth,
 * and the engine scrolls the hbox so only a visible subset is rendered.
 * Reserve 1 panel slot for the content pane. */
#define FV_MAX_DEPTH  (TUI_MAX_PANELS - 1)
/* Maximum bytes read from a file for the content pane. */
#define FV_READ_MAX   (4 * 1024 * 1024)

/* -----------------------------------------------------------------------
 * Data types
 * --------------------------------------------------------------------- */

typedef struct {
    char name[256];
    int  is_dir;
} fv_entry_t;

typedef struct {
    /* navigation: one path per depth */
    char        path_stack[FV_MAX_DEPTH][PATH_MAX];
    int         depth_count;  /* number of panel depth slots */

    /* per-depth directory listings */
    fv_entry_t *entries[FV_MAX_DEPTH];
    int         nentries[FV_MAX_DEPTH];

    /* file content */
    char      **lines;
    int         nlines;
    int         hex_mode;
    int         show_hidden;
    char        shown_path[PATH_MAX];

    /* terminal / tui */
    int rows, cols;
    tui_t *tui;

    /* layout: one panel_def per depth + content */
    tui_panel_def dir_def[FV_MAX_DEPTH];
    tui_col_def   dir_col;           /* shared: all columns use same col_def */
    tui_panel_def content_def;
    tui_col_def   content_col;

    /* box tree for layout (heap-allocated) */
    tui_box_t *dir_pbox[FV_MAX_DEPTH]; /* leaf boxes for dir panels */
    tui_box_t *content_pbox;
    tui_box_t *top_hbox;
    tui_box_t *root_vbox;
    tui_box_t **hbox_children;
    tui_box_t **root_children;

    /* panel name strings */
    char pnames[FV_MAX_DEPTH][8];
} fv_state_t;

static fv_state_t g;

/* -----------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

static void *xm(size_t n)
{
    void *p = calloc(1, n ? n : 1);
    if (!p) { perror("fv: calloc"); exit(1); }
    return p;
}

static void child_path(char *out, size_t sz, const char *parent, const char *name)
{
    if (strcmp(parent, "/") == 0)
        snprintf(out, sz, "/%s", name);
    else
        snprintf(out, sz, "%s/%s", parent, name);
}

/* -----------------------------------------------------------------------
 * Directory loading
 * --------------------------------------------------------------------- */

static int entry_cmp(const void *a, const void *b)
{
    const fv_entry_t *ea = a, *eb = b;
    if (ea->is_dir != eb->is_dir) return eb->is_dir - ea->is_dir;
    return strcmp(ea->name, eb->name);
}

static void load_dir(int depth)
{
    if (depth < 0 || depth >= FV_MAX_DEPTH) return;
    free(g.entries[depth]);
    g.entries[depth] = NULL;
    g.nentries[depth] = 0;
    if (!g.path_stack[depth][0]) return;

    DIR *dir = opendir(g.path_stack[depth]);
    if (!dir) return;

    int cap = 64, n = 0;
    fv_entry_t *arr = xm((size_t)cap * sizeof *arr);
    struct dirent *de;
    while ((de = readdir(dir))) {
        const char *nm = de->d_name;
        if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0')))
            continue;
        if (!g.show_hidden && nm[0] == '.')
            continue;
        if (n >= cap) {
            cap *= 2;
            fv_entry_t *tmp = realloc(arr, (size_t)cap * sizeof *arr);
            if (!tmp) { free(arr); closedir(dir); return; }
            arr = tmp;
        }
        snprintf(arr[n].name, sizeof arr[n].name, "%s", nm);
        char full[PATH_MAX];
        child_path(full, sizeof full, g.path_stack[depth], nm);
        struct stat st;
        arr[n].is_dir = (stat(full, &st) == 0 && S_ISDIR(st.st_mode));
        n++;
    }
    closedir(dir);
    if (n > 0) qsort(arr, (size_t)n, sizeof *arr, entry_cmp);
    g.entries[depth] = arr;
    g.nentries[depth] = n;
}

/* -----------------------------------------------------------------------
 * Content (file) loading
 * --------------------------------------------------------------------- */

static void free_lines(void)
{
    for (int i = 0; i < g.nlines; i++) free(g.lines[i]);
    free(g.lines);
    g.lines = NULL;
    g.nlines = 0;
    g.shown_path[0] = '\0';
}

static int looks_binary(const unsigned char *buf, int n)
{
    int check = n < 512 ? n : 512;
    for (int i = 0; i < check; i++) {
        unsigned char c = buf[i];
        if (c == 0) return 1;
        if (c < 8 && c != '\t' && c != '\n' && c != '\r') return 1;
    }
    return 0;
}

static char *mk_hex_line(const unsigned char *buf, int off, int bufsz)
{
    char tmp[80];
    int p = 0, len = bufsz - off;
    if (len > 16) len = 16;
    p += snprintf(tmp + p, sizeof tmp - (size_t)p, "%08x  ", off);
    for (int i = 0; i < 16; i++) {
        if (i < len) p += snprintf(tmp + p, sizeof tmp - (size_t)p, "%02x ", (unsigned)buf[off + i]);
        else         p += snprintf(tmp + p, sizeof tmp - (size_t)p, "   ");
        if (i == 7 && p < (int)sizeof tmp - 1) tmp[p++] = ' ';
    }
    if (p < (int)sizeof tmp - 1) tmp[p++] = ' ';
    if (p < (int)sizeof tmp - 1) tmp[p++] = '|';
    for (int i = 0; i < len && p < (int)sizeof tmp - 2; i++) {
        unsigned char c = buf[off + i];
        tmp[p++] = (c >= 32 && c < 127) ? (char)c : '.';
    }
    if (p < (int)sizeof tmp - 1) tmp[p++] = '|';
    tmp[p] = '\0';
    return strdup(tmp);
}

static void load_content(const char *path)
{
    free_lines();
    snprintf(g.shown_path, sizeof g.shown_path, "%s", path);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        g.lines = xm(sizeof(char *));
        g.lines[0] = strdup(strerror(errno));
        g.nlines = 1;
        return;
    }

    unsigned char *buf = xm(FV_READ_MAX + 1);
    int bufsz = 0;
    while (bufsz < FV_READ_MAX) {
        int n = (int)read(fd, buf + bufsz, (size_t)(FV_READ_MAX - bufsz));
        if (n <= 0) break;
        bufsz += n;
    }
    close(fd);

    if (g.hex_mode || looks_binary(buf, bufsz)) {
        int nlines = bufsz ? (bufsz + 15) / 16 : 1;
        g.lines = xm((size_t)nlines * sizeof(char *));
        if (bufsz == 0) {
            g.lines[0] = strdup("(empty)");
            g.nlines = 1;
        } else {
            for (int off = 0; off < bufsz; off += 16)
                g.lines[g.nlines++] = mk_hex_line(buf, off, bufsz);
        }
    } else {
        int cap = 256, n = 0;
        char **arr = xm((size_t)cap * sizeof(char *));
        char *cp = (char *)buf, *end = cp + bufsz;
        while (cp < end) {
            char *nl = memchr(cp, '\n', (size_t)(end - cp));
            int len = nl ? (int)(nl - cp) : (int)(end - cp);
            if (n >= cap) {
                cap *= 2;
                char **tmp = realloc(arr, (size_t)cap * sizeof(char *));
                if (!tmp) { free(arr); arr = NULL; break; }
                arr = tmp;
            }
            char *line = xm((size_t)len + 1);
            memcpy(line, cp, (size_t)len);
            if (len > 0 && line[len - 1] == '\r') line[len - 1] = '\0';
            arr[n++] = line;
            cp = nl ? nl + 1 : end;
        }
        if (!arr || n == 0) {
            if (arr) free(arr);
            g.lines = xm(sizeof(char *));
            g.lines[0] = strdup("(empty)");
            g.nlines = 1;
        } else {
            g.lines = arr;
            g.nlines = n;
        }
    }
    free(buf);
}

/* -----------------------------------------------------------------------
 * Data source callbacks
 * --------------------------------------------------------------------- */

static int fv_row_count(const char *panel, void *ctx)
{
    (void)ctx;
    if (strcmp(panel, "content") == 0) return g.nlines;
    int d;
    if (sscanf(panel, "d%d", &d) == 1 && d >= 0 && d < FV_MAX_DEPTH)
        return g.nentries[d];
    return 0;
}

static int fv_row_get(const char *panel, int rownum, tui_row_ref *row, void *ctx)
{
    (void)ctx;
    static char idbuf[32], namebuf[258];

    if (strcmp(panel, "content") == 0) {
        if (rownum < 0 || rownum >= g.nlines || !g.lines) return 0;
        snprintf(idbuf, sizeof idbuf, "%d", rownum);
        row->id     = idbuf;
        row->style  = "";
        row->cols[0] = g.lines[rownum];
        return 1;
    }

    int d;
    if (sscanf(panel, "d%d", &d) != 1) return 0;
    if (d < 0 || d >= FV_MAX_DEPTH || !g.entries[d]) return 0;
    if (rownum < 0 || rownum >= g.nentries[d]) return 0;

    fv_entry_t *e = &g.entries[d][rownum];
    row->id    = e->name;
    row->style = e->is_dir ? "cyan" : "";
    if (e->is_dir) snprintf(namebuf, sizeof namebuf, "%s/", e->name);
    else           snprintf(namebuf, sizeof namebuf, "%s",  e->name);
    row->cols[0] = namebuf;
    return 1;
}

static int fv_row_find(const char *panel, const char *id, void *ctx)
{
    (void)ctx;
    if (strcmp(panel, "content") == 0) return id ? atoi(id) : 0;
    int d;
    if (sscanf(panel, "d%d", &d) != 1) return -1;
    if (d < 0 || d >= FV_MAX_DEPTH || !g.entries[d]) return -1;
    for (int i = 0; i < g.nentries[d]; i++)
        if (strcmp(g.entries[d][i].name, id) == 0) return i;
    return -1;
}

static void fv_size_changed(int rows, int cols, void *ctx)
{
    (void)ctx;
    g.rows = rows;
    g.cols = cols;
}

static const tui_data_source g_src = {
    fv_row_count, fv_row_get, fv_row_find, fv_size_changed
};

/* -----------------------------------------------------------------------
 * Sync helpers
 * --------------------------------------------------------------------- */

static const char *dpname(int d)
{
    return (d >= 0 && d < FV_MAX_DEPTH) ? g.pnames[d] : "";
}

static void sync_right_of(int d)
{
    if (d < 0 || d >= FV_MAX_DEPTH) return;
    int cursor = tui_get_cursor(g.tui, dpname(d));

    /* Clear deeper levels. */
    for (int i = d + 1; i < g.depth_count; i++) {
        free(g.entries[i]);
        g.entries[i] = NULL;
        g.nentries[i] = 0;
        g.path_stack[i][0] = '\0';
        tui_dirty(g.tui, dpname(i));
    }

    if (cursor < 0 || cursor >= g.nentries[d] || !g.entries[d]) {
        free_lines();
        tui_dirty(g.tui, "content");
        return;
    }

    fv_entry_t *e = &g.entries[d][cursor];
    char full[PATH_MAX];
    child_path(full, sizeof full, g.path_stack[d], e->name);

    if (e->is_dir && d + 1 < g.depth_count) {
        snprintf(g.path_stack[d + 1], sizeof g.path_stack[d + 1], "%s", full);
        load_dir(d + 1);
        tui_set_cursor_idx(g.tui, dpname(d + 1), 0);
        tui_dirty(g.tui, dpname(d + 1));
        if (strcmp(g.shown_path, full) != 0) {
            free_lines();
            snprintf(g.shown_path, sizeof g.shown_path, "%s", full);
        }
    } else if (!e->is_dir) {
        if (strcmp(g.shown_path, full) != 0) {
            load_content(full);
            tui_set_cursor_idx(g.tui, "content", 0);
        }
    }
    tui_dirty(g.tui, "content");
}

/* -----------------------------------------------------------------------
 * Status bar
 * --------------------------------------------------------------------- */

static void update_status(void)
{
    const char *focus = tui_get_focus(g.tui);
    char status[PATH_MAX + 64];
    int d = -1;

    if (focus && sscanf(focus, "d%d", &d) == 1 && d >= 0 && d < FV_MAX_DEPTH) {
        int cursor = tui_get_cursor(g.tui, dpname(d));
        if (cursor >= 0 && cursor < g.nentries[d] && g.entries[d]) {
            fv_entry_t *e = &g.entries[d][cursor];
            char full[PATH_MAX];
            child_path(full, sizeof full, g.path_stack[d], e->name);
            snprintf(status, sizeof status, " %s%s", full, e->is_dir ? "/" : "");
        } else {
            snprintf(status, sizeof status, " %s/", g.path_stack[d]);
        }
    } else if (focus && strcmp(focus, "content") == 0) {
        snprintf(status, sizeof status, " [content]  %s",
                 g.shown_path[0] ? g.shown_path : "(nothing)");
    } else {
        status[0] = '\0';
    }
    tui_set_status(g.tui, status);
}

/* -----------------------------------------------------------------------
 * Cursor change callback (fires automatically on cursor movement)
 * --------------------------------------------------------------------- */

static void on_cursor_change(tui_t *tui, const char *panel,
                             int cursor, const char *row_id, void *ctx)
{
    (void)tui; (void)cursor; (void)row_id; (void)ctx;
    int d = -1;
    if (panel && sscanf(panel, "d%d", &d) == 1)
        sync_right_of(d);
    update_status();
}

/* -----------------------------------------------------------------------
 * Key callback — only app-specific keys
 * --------------------------------------------------------------------- */

static const char *HELP[] = {
    "",
    "  fv \xe2\x80\x94 filesystem viewer",
    "  \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80",
    "",
    "  \xe2\x86\x91 \xe2\x86\x93  j k   Navigate within column",
    "  PgUp PgDn  Page up / down",
    "  Home g     First item     End  Last item",
    "  Tab        Cycle between columns and content pane",
    "",
    "  \xe2\x86\x90  h       Move focus to the left column",
    "  \xe2\x86\x92  Enter   Enter directory / focus content pane",
    "",
    "  H           Toggle hex mode in the content pane",
    "  .           Toggle hidden files",
    "  ?           This help",
    "  q  Esc      Quit",
    "",
    "  Press any key to close.",
    NULL
};

static int on_key(tui_t *tui, int key, const char *panel,
                  int cursor, const char *row_id, void *ctx)
{
    (void)cursor; (void)row_id; (void)ctx;

    int d = -1;
    int in_content = (panel && strcmp(panel, "content") == 0);
    if (panel) sscanf(panel, "d%d", &d);

    /* The TUI_K_NONE notification is still fired for backward compat
     * but we use on_cursor_change now, so ignore it here. */
    if (key == TUI_K_NONE) return TUI_HANDLED;

    if (key == 'q' || key == TUI_K_ESC) {
        tui_quit(tui);
        return TUI_HANDLED;
    }
    if (key == '?') {
        tui_show_help(tui, HELP);
        tui_dirty(tui, NULL);
        return TUI_HANDLED;
    }
    if (key == 'H') {
        g.hex_mode = !g.hex_mode;
        if (g.shown_path[0]) {
            char saved[PATH_MAX];
            snprintf(saved, sizeof saved, "%s", g.shown_path);
            load_content(saved);
            tui_set_cursor_idx(tui, "content", 0);
        }
        tui_dirty(tui, "content");
        return TUI_HANDLED;
    }
    if (key == '.') {
        g.show_hidden = !g.show_hidden;
        for (int i = 0; i < g.depth_count; i++) {
            if (g.path_stack[i][0]) load_dir(i);
            tui_dirty(tui, dpname(i));
        }
        tui_dirty(tui, "content");
        return TUI_HANDLED;
    }

    /* LEFT: move focus to the left column. */
    if (key == TUI_K_LEFT || key == 'h') {
        if (in_content) {
            /* Find the deepest populated dir column. */
            for (int i = g.depth_count - 1; i >= 0; i--) {
                if (g.nentries[i] > 0 || g.path_stack[i][0]) {
                    tui_focus(tui, dpname(i));
                    update_status();
                    break;
                }
            }
        } else if (d > 0) {
            tui_focus(tui, dpname(d - 1));
            update_status();
        }
        return TUI_HANDLED;
    }

    /* RIGHT / ENTER: enter directory or focus content pane. */
    if (key == TUI_K_RIGHT || (key == TUI_K_ENTER && !in_content)) {
        if (d >= 0 && d < FV_MAX_DEPTH && g.entries[d]) {
            int c = tui_get_cursor(tui, dpname(d));
            if (c >= 0 && c < g.nentries[d]) {
                fv_entry_t *e = &g.entries[d][c];
                if (e->is_dir && d + 1 < g.depth_count) {
                    /* Focus next column; engine hscroll auto-scrolls. */
                    tui_focus(tui, dpname(d + 1));
                    update_status();
                } else if (!e->is_dir) {
                    tui_focus(tui, "content");
                    update_status();
                }
            }
        }
        return TUI_HANDLED;
    }

    return TUI_DEFAULT;
}

/* -----------------------------------------------------------------------
 * Layout builder: create all dir panel slots + content panel.
 * The dir panels live in an hbox with TUI_BOX_HSCROLL; the engine
 * decides how many columns fit on screen and scrolls automatically.
 * --------------------------------------------------------------------- */

static void build_layout(void)
{
    int ndepths = FV_MAX_DEPTH;
    g.depth_count = ndepths;

    /* Shared column definition for all dir panels */
    g.dir_col.name     = "name";
    g.dir_col.width    = -1;
    g.dir_col.align    = TUI_ALIGN_LEFT;
    g.dir_col.overflow = TUI_OVERFLOW_ELLIPSIS;

    /* Panel definitions and leaf boxes for each depth */
    g.hbox_children = xm((size_t)ndepths * sizeof(tui_box_t *));
    for (int i = 0; i < ndepths; i++) {
        snprintf(g.pnames[i], sizeof g.pnames[i], "d%d", i);
        g.dir_def[i].name   = g.pnames[i];
        g.dir_def[i].title  = NULL;
        g.dir_def[i].cols   = &g.dir_col;
        g.dir_def[i].ncols  = 1;
        g.dir_def[i].flags  = TUI_PANEL_CURSOR | TUI_PANEL_BORDER;

        g.dir_pbox[i] = xm(sizeof(tui_box_t));
        g.dir_pbox[i]->type      = TUI_BOX_PANEL;
        g.dir_pbox[i]->weight    = 1;
        g.dir_pbox[i]->min_size  = 0;
        g.dir_pbox[i]->box_flags = 0;
        g.dir_pbox[i]->def       = &g.dir_def[i];
        g.dir_pbox[i]->children  = NULL;
        g.dir_pbox[i]->nchildren = 0;

        g.hbox_children[i] = g.dir_pbox[i];
    }

    /* Content panel */
    g.content_col.name     = "text";
    g.content_col.width    = -1;
    g.content_col.align    = TUI_ALIGN_LEFT;
    g.content_col.overflow = TUI_OVERFLOW_TRUNCATE;

    g.content_def.name   = "content";
    g.content_def.title  = NULL;
    g.content_def.cols   = &g.content_col;
    g.content_def.ncols  = 1;
    g.content_def.flags  = TUI_PANEL_CURSOR;

    g.content_pbox = xm(sizeof(tui_box_t));
    g.content_pbox->type      = TUI_BOX_PANEL;
    g.content_pbox->weight    = 3;
    g.content_pbox->min_size  = 3;
    g.content_pbox->box_flags = 0;
    g.content_pbox->def       = &g.content_def;
    g.content_pbox->children  = NULL;
    g.content_pbox->nchildren = 0;

    /* Top hbox with HSCROLL flag: engine decides visible column count. */
    g.top_hbox = xm(sizeof(tui_box_t));
    g.top_hbox->type      = TUI_BOX_HBOX;
    g.top_hbox->weight    = 1;
    g.top_hbox->min_size  = 3;
    g.top_hbox->box_flags = TUI_BOX_HSCROLL;
    g.top_hbox->def       = NULL;
    g.top_hbox->children  = g.hbox_children;
    g.top_hbox->nchildren = ndepths;

    /* Root vbox */
    g.root_children = xm(2 * sizeof(tui_box_t *));
    g.root_children[0] = g.top_hbox;
    g.root_children[1] = g.content_pbox;

    g.root_vbox = xm(sizeof(tui_box_t));
    g.root_vbox->type      = TUI_BOX_VBOX;
    g.root_vbox->weight    = 1;
    g.root_vbox->min_size  = 0;
    g.root_vbox->box_flags = 0;
    g.root_vbox->def       = NULL;
    g.root_vbox->children  = g.root_children;
    g.root_vbox->nchildren = 2;
}

/* -----------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    memset(&g, 0, sizeof g);

    const char *startpath = (argc > 1) ? argv[1] : ".";

    char abspath[PATH_MAX];
    if (!realpath(startpath, abspath)) {
        fprintf(stderr, "fv: %s: %s\n", startpath, strerror(errno));
        return 1;
    }

    struct stat st;
    if (stat(abspath, &st) != 0) {
        fprintf(stderr, "fv: %s: %s\n", abspath, strerror(errno));
        return 1;
    }

    if (S_ISREG(st.st_mode)) {
        char *slash = strrchr(abspath, '/');
        if (slash && slash > abspath) *slash = '\0';
        else { abspath[0] = '/'; abspath[1] = '\0'; }
    }
    snprintf(g.path_stack[0], sizeof g.path_stack[0], "%s", abspath);

    tui_t *tui = tui_open(&g_src, NULL);
    if (!tui) {
        fprintf(stderr, "fv: cannot open terminal\n");
        return 1;
    }
    g.tui  = tui;
    g.rows = tui_rows(tui);
    g.cols = tui_cols(tui);

    build_layout();
    tui_set_layout(tui, g.root_vbox);
    tui_on_key(tui, on_key, NULL);
    tui_on_cursor_change(tui, on_cursor_change, NULL);

    load_dir(0);
    tui_focus(tui, "d0");
    sync_right_of(0);
    update_status();
    tui_dirty(tui, NULL);

    tui_run(tui);
    tui_close(tui);

    for (int i = 0; i < FV_MAX_DEPTH; i++) free(g.entries[i]);
    free_lines();
    return 0;
}
