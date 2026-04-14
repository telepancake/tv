/*
 * fv - filesystem viewer
 *
 * A Smalltalk-style column browser built on engine.h/engine.c.
 *
 * Layout:
 *   ┌──────┬──────┬──────┐
 *   │ d0   │ d1   │ d2   │   <- equally-wide dir columns (count = cols/18)
 *   │ ...  │ ...  │ ...  │
 *   ├──────┴──────┴──────┤
 *   │ content            │   <- large file-content pane (text or hex+text)
 *   └────────────────────┘
 *   full path of item under cursor               <- status bar
 *
 * Keys:
 *   ↑ ↓ j k  PgUp PgDn  Home/g End   Navigate within a column
 *   ←  h                              Move focus to the left column
 *   →  Enter                          Move focus to the right column / enter dir
 *   Tab                               Cycle panels (dir columns + content)
 *   H                                 Toggle hex mode in content pane
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

/* Maximum directory depth we track; also bounds top_depth+nvis. */
#define FV_MAX_DEPTH  64
/* Maximum number of visible directory columns.
 * Must be <= (MAX_PANELS - 1) where MAX_PANELS=8 in engine.c, so <= 7. */
#define FV_MAX_COLS    7
/* Maximum bytes read from a file for the content pane. */
#define FV_READ_MAX   (4 * 1024 * 1024)

/* -----------------------------------------------------------------------
 * Data types
 * --------------------------------------------------------------------- */

typedef struct {
    char name[256];   /* entry name (no trailing slash) */
    int  is_dir;
} fv_entry_t;

typedef struct {
    /* --- navigation -------------------------------------------------- */
    char        path_stack[FV_MAX_DEPTH][PATH_MAX]; /* absolute path at each depth */
    int         top_depth; /* depth index of the leftmost visible column */
    int         nvis;      /* number of visible dir columns */

    /* --- per-depth directory listings -------------------------------- */
    fv_entry_t *entries[FV_MAX_DEPTH];
    int         nentries[FV_MAX_DEPTH];

    /* --- file content ------------------------------------------------ */
    char      **lines;
    int         nlines;
    int         hex_mode;
    char        shown_path[PATH_MAX]; /* path of the file currently displayed */

    /* --- terminal size ----------------------------------------------- */
    int rows, cols;

    /* --- tui handle -------------------------------------------------- */
    tui_t *tui;

    /* --- panel / column definitions (heap-allocated) ----------------- */
    tui_col_def  *dir_col[FV_MAX_COLS];   /* one col_def per dir column */
    tui_panel_def dir_def[FV_MAX_COLS];   /* one panel_def per dir column */
    tui_col_def   content_col;
    tui_panel_def content_def;

    /* --- layout box tree (heap-allocated) ---------------------------- */
    tui_box_t  *dir_pbox[FV_MAX_COLS];  /* leaf panel-boxes for dir columns */
    tui_box_t  *content_pbox;           /* leaf panel-box for content */
    tui_box_t  *top_hbox;               /* hbox containing all dir columns */
    tui_box_t  *root_vbox;              /* vbox: top_hbox above content_pbox */
    tui_box_t **hbox_children;          /* children array for top_hbox */
    tui_box_t **root_children;          /* children array for root_vbox */
} fv_state_t;

static fv_state_t g; /* global state (single instance) */

/* -----------------------------------------------------------------------
 * Memory helpers
 * --------------------------------------------------------------------- */

static void *xm(size_t n)
{
    void *p = calloc(1, n ? n : 1);
    if (!p) { perror("fv: calloc"); exit(1); }
    return p;
}

/* -----------------------------------------------------------------------
 * Path helper
 * --------------------------------------------------------------------- */

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
    if (ea->is_dir != eb->is_dir) return eb->is_dir - ea->is_dir; /* dirs first */
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
            continue; /* skip . and .. */
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
    p += snprintf(tmp + p, sizeof tmp - p, "%08x  ", off);
    for (int i = 0; i < 16; i++) {
        if (i < len) p += snprintf(tmp + p, sizeof tmp - p, "%02x ", (unsigned)buf[off + i]);
        else         p += snprintf(tmp + p, sizeof tmp - p, "   ");
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
        /* hex+text view */
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
        /* text view */
        int cap = 256, n = 0;
        char **arr = xm((size_t)cap * sizeof(char *));
        char *p = (char *)buf, *end = p + bufsz;
        while (p < end) {
            char *nl = memchr(p, '\n', (size_t)(end - p));
            int len = nl ? (int)(nl - p) : (int)(end - p);
            if (n >= cap) {
                cap *= 2;
                char **tmp = realloc(arr, (size_t)cap * sizeof(char *));
                if (!tmp) { free(arr); arr = NULL; break; }
                arr = tmp;
            }
            char *line = xm((size_t)len + 1);
            memcpy(line, p, (size_t)len);
            if (len > 0 && line[len - 1] == '\r') line[len - 1] = '\0';
            arr[n++] = line;
            p = nl ? nl + 1 : end;
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
    int col;
    if (sscanf(panel, "d%d", &col) == 1) {
        int d = g.top_depth + col;
        return (d >= 0 && d < FV_MAX_DEPTH) ? g.nentries[d] : 0;
    }
    return 0;
}

static int fv_row_get(const char *panel, int rownum, tui_row_ref *row, void *ctx)
{
    (void)ctx;
    /* Static buffers are safe here: the engine copies all strings into its
     * own cache pool immediately after each row_get call. */
    static char idbuf[32], namebuf[258];

    if (strcmp(panel, "content") == 0) {
        if (rownum < 0 || rownum >= g.nlines || !g.lines) return 0;
        snprintf(idbuf, sizeof idbuf, "%d", rownum);
        row->id     = idbuf;
        row->style  = "";
        row->cols[0] = g.lines[rownum];
        return 1;
    }

    int col;
    if (sscanf(panel, "d%d", &col) != 1) return 0;
    int d = g.top_depth + col;
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
    int col;
    if (sscanf(panel, "d%d", &col) != 1) return -1;
    int d = g.top_depth + col;
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
 * Column sync helpers
 * --------------------------------------------------------------------- */

/*
 * Called after cursor moves in column `col`.
 * Reloads the directory shown in col+1 (and clears col+2 onward),
 * or loads file content if the selected item is a file.
 */
static void sync_right_of(int col)
{
    int d = g.top_depth + col;
    if (d < 0 || d >= FV_MAX_DEPTH) return;

    char pname[16];
    snprintf(pname, sizeof pname, "d%d", col);
    int cursor = tui_get_cursor(g.tui, pname);

    /* Clear all columns to the right and the content pane, then repopulate. */
    for (int c = col + 1; c < g.nvis; c++) {
        int nd = g.top_depth + c;
        if (nd >= 0 && nd < FV_MAX_DEPTH) {
            free(g.entries[nd]);
            g.entries[nd] = NULL;
            g.nentries[nd] = 0;
            g.path_stack[nd][0] = '\0';
        }
        char np[16];
        snprintf(np, sizeof np, "d%d", c);
        tui_dirty(g.tui, np);
    }

    if (cursor < 0 || cursor >= g.nentries[d] || !g.entries[d]) {
        free_lines();
        tui_dirty(g.tui, "content");
        return;
    }

    fv_entry_t *e = &g.entries[d][cursor];
    char full[PATH_MAX];
    child_path(full, sizeof full, g.path_stack[d], e->name);

    if (e->is_dir) {
        /* Populate next column with this directory's contents. */
        if (col + 1 < g.nvis) {
            int nd = g.top_depth + col + 1;
            if (nd >= 0 && nd < FV_MAX_DEPTH) {
                snprintf(g.path_stack[nd], sizeof g.path_stack[nd], "%s", full);
                load_dir(nd);
                char np[16];
                snprintf(np, sizeof np, "d%d", col + 1);
                tui_set_cursor_idx(g.tui, np, 0);
                tui_dirty(g.tui, np);
            }
        }
        /* Content pane shows nothing (it's a directory). */
        if (strcmp(g.shown_path, full) != 0) {
            free_lines();
            snprintf(g.shown_path, sizeof g.shown_path, "%s", full);
        }
        tui_dirty(g.tui, "content");
    } else {
        /* File: load into content pane. */
        if (strcmp(g.shown_path, full) != 0) {
            load_content(full);
            tui_set_cursor_idx(g.tui, "content", 0);
        }
        tui_dirty(g.tui, "content");
    }
}

/* -----------------------------------------------------------------------
 * Status bar
 * --------------------------------------------------------------------- */

static void update_status(void)
{
    const char *focus = tui_get_focus(g.tui);
    char status[PATH_MAX + 64];
    int col = -1;

    if (focus && sscanf(focus, "d%d", &col) == 1) {
        int d = g.top_depth + col;
        char pname[16];
        snprintf(pname, sizeof pname, "d%d", col);
        int cursor = tui_get_cursor(g.tui, pname);
        if (d >= 0 && d < FV_MAX_DEPTH &&
            cursor >= 0 && cursor < g.nentries[d] && g.entries[d]) {
            fv_entry_t *e = &g.entries[d][cursor];
            char full[PATH_MAX];
            child_path(full, sizeof full, g.path_stack[d], e->name);
            snprintf(status, sizeof status, " %s%s", full, e->is_dir ? "/" : "");
        } else {
            int sd = (d >= 0 && d < FV_MAX_DEPTH) ? d : 0;
            snprintf(status, sizeof status, " %s/", g.path_stack[sd]);
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
 * Key callback
 * --------------------------------------------------------------------- */

static const char *HELP[] = {
    "",
    "  fv \xe2\x80\x94 filesystem viewer",   /* em dash */
    "  ──────────────────────",             /* box-drawing horizontal lines */
    "",
    "  ↑ ↓  j k   Navigate within column",
    "  PgUp PgDn  Page up / down",
    "  Home g     First item     End  Last item",
    "  Tab        Cycle between columns and content pane",
    "",
    "  ←  h       Move focus to the left column",
    "  →  Enter   Move focus to the right column / enter dir",
    "",
    "  H           Toggle hex mode in the content pane",
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

    int col = -1;
    int in_content = (panel && strcmp(panel, "content") == 0);
    if (panel) sscanf(panel, "d%d", &col);

    /* --- Navigation notification (engine moved the cursor) ----------- */
    if (key == TUI_K_NONE) {
        if (col >= 0) sync_right_of(col);
        update_status();
        return TUI_HANDLED;
    }

    /* --- Quit -------------------------------------------------------- */
    if (key == 'q' || key == TUI_K_ESC) {
        tui_quit(tui);
        return TUI_HANDLED;
    }

    /* --- Help -------------------------------------------------------- */
    if (key == '?') {
        tui_show_help(tui, HELP);
        tui_dirty(tui, NULL);
        return TUI_HANDLED;
    }

    /* --- Toggle hex mode --------------------------------------------- */
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

    /* --- LEFT: move focus to the left column ------------------------- */
    if (key == TUI_K_LEFT || key == 'h') {
        if (in_content) {
            /* From content pane → focus the rightmost dir column. */
            char pname[16];
            snprintf(pname, sizeof pname, "d%d", g.nvis - 1);
            tui_focus(tui, pname);
            update_status();
        } else if (col > 0) {
            /* Move one column left. */
            char pname[16];
            snprintf(pname, sizeof pname, "d%d", col - 1);
            tui_focus(tui, pname);
            update_status();
        } else if (col == 0 && g.top_depth > 0) {
            /*
             * Already at leftmost visible column, but there are parent
             * directories to the left: scroll the window leftward.
             */
            g.top_depth--;
            for (int c = 0; c < g.nvis; c++) {
                int nd = g.top_depth + c;
                if (nd >= 0 && nd < FV_MAX_DEPTH && g.path_stack[nd][0])
                    load_dir(nd);
                char np[16];
                snprintf(np, sizeof np, "d%d", c);
                tui_dirty(tui, np);
            }
            tui_dirty(tui, "content");
            update_status();
        }
        return TUI_HANDLED;
    }

    /* --- RIGHT / ENTER: move focus right or enter directory ---------- */
    if (key == TUI_K_RIGHT || (key == TUI_K_ENTER && !in_content)) {
        if (col >= 0) {
            int d = g.top_depth + col;
            if (d >= 0 && d < FV_MAX_DEPTH && g.entries[d]) {
                int c = tui_get_cursor(tui, panel);
                if (c >= 0 && c < g.nentries[d]) {
                    fv_entry_t *e = &g.entries[d][c];
                    if (e->is_dir) {
                        if (col + 1 < g.nvis) {
                            /* Focus the next column (already populated). */
                            char np[16];
                            snprintf(np, sizeof np, "d%d", col + 1);
                            tui_focus(tui, np);
                        } else {
                            /*
                             * At rightmost column: scroll the window rightward
                             * so we can show the next level.
                             */
                            g.top_depth++;
                            for (int c2 = 0; c2 < g.nvis; c2++) {
                                int nd = g.top_depth + c2;
                                if (nd >= 0 && nd < FV_MAX_DEPTH &&
                                    g.path_stack[nd][0])
                                    load_dir(nd);
                                char np[16];
                                snprintf(np, sizeof np, "d%d", c2);
                                tui_dirty(tui, np);
                            }
                            tui_focus(tui, "d0");
                        }
                        update_status();
                    } else {
                        /* It is a file: focus the content pane. */
                        tui_focus(tui, "content");
                        update_status();
                    }
                }
            }
        }
        return TUI_HANDLED;
    }

    return TUI_DEFAULT;
}

/* -----------------------------------------------------------------------
 * Layout builder
 *
 * We allocate tui_box_t structs on the heap instead of using the static
 * pool helpers (tui_hbox / tui_vbox / tui_panel_box), because the number
 * of dir columns is only known at runtime.  The engine's tui_set_layout
 * traverses the tree by pointer and copies panel_def structs by value, so
 * heap allocation is fully supported.
 * --------------------------------------------------------------------- */

static void build_layout(int nvis)
{
    g.nvis = nvis;

    /* --- dir panel definitions and leaf boxes ------------------------ */
    for (int i = 0; i < nvis; i++) {
        g.dir_col[i] = xm(sizeof(tui_col_def));
        g.dir_col[i]->name     = "name";
        g.dir_col[i]->width    = -1;  /* flex: fill available width */
        g.dir_col[i]->align    = TUI_ALIGN_LEFT;
        g.dir_col[i]->overflow = TUI_OVERFLOW_ELLIPSIS;

        char *pname = xm(8);
        snprintf(pname, 8, "d%d", i);
        g.dir_def[i].name   = pname;
        g.dir_def[i].title  = NULL;
        g.dir_def[i].cols   = g.dir_col[i];
        g.dir_def[i].ncols  = 1;
        g.dir_def[i].flags  = TUI_PANEL_CURSOR | TUI_PANEL_BORDER;

        g.dir_pbox[i] = xm(sizeof(tui_box_t));
        g.dir_pbox[i]->type      = TUI_BOX_PANEL;
        g.dir_pbox[i]->weight    = 1;
        g.dir_pbox[i]->min_size  = 0;
        g.dir_pbox[i]->def       = &g.dir_def[i];
        g.dir_pbox[i]->children  = NULL;
        g.dir_pbox[i]->nchildren = 0;
    }

    /* --- content panel definition and leaf box ----------------------- */
    g.content_col.name     = "text";
    g.content_col.width    = -1;
    g.content_col.align    = TUI_ALIGN_LEFT;
    g.content_col.overflow = TUI_OVERFLOW_TRUNCATE;

    g.content_def.name   = "content";
    g.content_def.title  = NULL;
    g.content_def.cols   = &g.content_col;
    g.content_def.ncols  = 1;
    g.content_def.flags  = TUI_PANEL_CURSOR; /* cursor = scroll position */

    g.content_pbox = xm(sizeof(tui_box_t));
    g.content_pbox->type      = TUI_BOX_PANEL;
    g.content_pbox->weight    = 3;  /* content gets ~3/4 of total height */
    g.content_pbox->min_size  = 3;
    g.content_pbox->def       = &g.content_def;
    g.content_pbox->children  = NULL;
    g.content_pbox->nchildren = 0;

    /* --- top hbox (dir columns side by side) ------------------------- */
    g.hbox_children = xm((size_t)nvis * sizeof(tui_box_t *));
    for (int i = 0; i < nvis; i++) g.hbox_children[i] = g.dir_pbox[i];

    g.top_hbox = xm(sizeof(tui_box_t));
    g.top_hbox->type      = TUI_BOX_HBOX;
    g.top_hbox->weight    = 1;  /* dir row gets ~1/4 of total height */
    g.top_hbox->min_size  = 3;
    g.top_hbox->def       = NULL;
    g.top_hbox->children  = g.hbox_children;
    g.top_hbox->nchildren = nvis;

    /* --- root vbox (top hbox above content) -------------------------- */
    g.root_children = xm(2 * sizeof(tui_box_t *));
    g.root_children[0] = g.top_hbox;
    g.root_children[1] = g.content_pbox;

    g.root_vbox = xm(sizeof(tui_box_t));
    g.root_vbox->type      = TUI_BOX_VBOX;
    g.root_vbox->weight    = 1;
    g.root_vbox->min_size  = 0;
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

    /* If a file was given, start in its parent directory. */
    if (S_ISREG(st.st_mode)) {
        char *slash = strrchr(abspath, '/');
        if (slash && slash > abspath) {
            *slash = '\0';
        } else {
            abspath[0] = '/';
            abspath[1] = '\0';
        }
    }
    snprintf(g.path_stack[0], sizeof g.path_stack[0], "%s", abspath);

    /* Open terminal. */
    tui_t *tui = tui_open(&g_src, NULL);
    if (!tui) {
        fprintf(stderr, "fv: cannot open terminal\n");
        return 1;
    }
    g.tui  = tui;
    g.rows = tui_rows(tui);
    g.cols = tui_cols(tui);

    /* Number of visible dir columns: at least 1, at most FV_MAX_COLS,
     * sized so each column is at least 18 characters wide. */
    int nvis = g.cols / 18;
    if (nvis < 1)         nvis = 1;
    if (nvis > FV_MAX_COLS) nvis = FV_MAX_COLS;

    build_layout(nvis);
    tui_set_layout(tui, g.root_vbox);
    tui_on_key(tui, on_key, NULL);

    /* Populate the root directory and sync all columns. */
    load_dir(0);
    tui_focus(tui, "d0");
    sync_right_of(0);
    update_status();
    tui_dirty(tui, NULL);

    tui_run(tui);
    tui_close(tui);

    /* Clean up. */
    for (int i = 0; i < FV_MAX_DEPTH; i++) free(g.entries[i]);
    free_lines();
    return 0;
}
