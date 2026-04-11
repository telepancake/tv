/*
 * engine.h — Generic panel-based TUI engine.
 *
 * ═══════════════════════════════════════════════════════════════════
 *  OVERVIEW
 * ═══════════════════════════════════════════════════════════════════
 *
 * A terminal UI engine that renders named panels from SQLite tables.
 * The engine owns terminal I/O, the event loop, rendering, cursor
 * navigation, scrolling, and column layout.  The application provides
 * data in SQLite tables and receives callbacks on events.
 *
 *   Engine responsibilities              Application responsibilities
 *   ─────────────────────────────────    ─────────────────────────────
 *   Terminal raw mode, alt screen        Database schema & population
 *   Event loop (select on fds)           Register fds, timers, key cb
 *   Read & decode keypresses             Decide what keys mean (via cb)
 *   Render panels from SQL tables        Populate/rebuild panel tables
 *   Cursor navigation & scroll           Mark panels dirty after changes
 *   Column alignment & truncation        Define panel layout (columns)
 *   Status bar rendering                 Set status text
 *   Line editor, help overlay            Provide help text
 *
 * ═══════════════════════════════════════════════════════════════════
 *  PANEL DATA TABLE FORMAT
 * ═══════════════════════════════════════════════════════════════════
 *
 * Each panel reads from a table whose name matches the panel name.
 * Required columns:
 *
 *   id      TEXT    — unique row identifier, passed back in callbacks
 *   style   TEXT    — row style name (see STYLES)
 *   <col>   TEXT    — one per column in the panel layout definition
 *
 * Row ordering: determined by tui_panel_def.order_by (a SQL ORDER BY
 * fragment, e.g. "rownum" or "name ASC").  No explicit numbering needed.
 *
 * Additional columns for app use are ignored by the engine.
 *
 * ═══════════════════════════════════════════════════════════════════
 *  PANEL LAYOUT
 * ═══════════════════════════════════════════════════════════════════
 *
 * tui_panel_def describes how to render one panel:
 *   name       — panel and SQL table name
 *   title      — header shown at top of panel (NULL = no header)
 *   order_by   — SQL ORDER BY fragment
 *   cols/ncols — column definitions
 *   flags      — TUI_PANEL_CURSOR, TUI_PANEL_BORDER
 *
 * tui_col_def describes one column:
 *   name       — SQL column name
 *   width      — >0 = fixed chars, <0 = flex weight (share of rest)
 *   align      — TUI_ALIGN_LEFT / RIGHT / CENTER
 *   overflow   — TUI_OVERFLOW_TRUNCATE / ELLIPSIS
 *
 * Panel position: given as percentages (0-100) of terminal area.
 *
 * ═══════════════════════════════════════════════════════════════════
 *  STYLES
 * ═══════════════════════════════════════════════════════════════════
 *
 *   "normal"    — default terminal color
 *   "error"     — red
 *   "green"     — green
 *   "yellow"    — yellow
 *   "cyan"      — cyan
 *   "cyan_bold" — bold cyan
 *   "heading"   — bold yellow
 *   "search"    — bold magenta
 *   "dim"       — dim
 *   "bold"      — bold
 *
 * ═══════════════════════════════════════════════════════════════════
 *  EVENT LOOP
 * ═══════════════════════════════════════════════════════════════════
 *
 * tui_run() runs a select()-based loop.  The app registers:
 *   • FD watchers via tui_watch_fd() — fires when fd is readable
 *   • Timers via tui_add_timer() — fires after N ms
 *   • Key handler via tui_on_key() — called per keypress with
 *     focused panel, cursor index, and row id
 *
 * After each callback, dirty panels are re-rendered automatically.
 * Terminal resize (SIGWINCH) is handled internally.
 *
 * ═══════════════════════════════════════════════════════════════════
 *  NAVIGATION
 * ═══════════════════════════════════════════════════════════════════
 *
 * For panels with TUI_PANEL_CURSOR, the engine handles:
 *   up/down/j/k  — move cursor one row
 *   pgup/pgdn    — move cursor one page
 *   home/g/end   — jump to first/last row
 *
 * The key callback is called FIRST.  If it returns TUI_HANDLED,
 * the engine skips default navigation.  If TUI_DEFAULT, the engine
 * applies built-in movement, then calls the callback a second time
 * with key=TUI_K_NONE so the app can observe the new cursor position
 * (e.g. to update a cursor_id column in the state table).
 *
 * The app can move the cursor programmatically via tui_set_cursor()
 * and query it via tui_get_cursor() / tui_get_cursor_id().
 *
 * ═══════════════════════════════════════════════════════════════════
 *  TYPICAL USAGE
 * ═══════════════════════════════════════════════════════════════════
 *
 *   sqlite3 *db = ...;
 *   tui_t *tui = tui_open(db);
 *
 *   tui_col_def lc[] = {{"text", -1, TUI_ALIGN_LEFT, TUI_OVERFLOW_ELLIPSIS}};
 *   tui_panel_def lp = {"lpane", NULL, "rownum", lc, 1, TUI_PANEL_CURSOR};
 *   tui_add_panel(tui, &lp, 0, 0, 50, 100);
 *
 *   tui_on_key(tui, my_key_cb, ctx);
 *   tui_watch_fd(tui, trace_fd, on_trace_data, ctx);
 *   tui_set_status(tui, " Ready");
 *   tui_dirty(tui, NULL);
 *   tui_run(tui);
 *   tui_close(tui);
 */
#ifndef ENGINE_H
#define ENGINE_H

#include "sqlite3.h"

/* ── Key constants ─────────────────────────────────────────────────── */
enum {
    TUI_K_NONE  = -1,
    TUI_K_UP    = 256, TUI_K_DOWN, TUI_K_LEFT, TUI_K_RIGHT,
    TUI_K_PGUP, TUI_K_PGDN, TUI_K_HOME, TUI_K_END,
    TUI_K_TAB   = 9,
    TUI_K_ENTER = 13,
    TUI_K_ESC   = 27,
    TUI_K_BS    = 127
};

/* Key callback return values */
#define TUI_HANDLED  1   /* app handled; skip default navigation */
#define TUI_DEFAULT  0   /* apply default navigation */
#define TUI_QUIT    -1   /* exit the event loop */

/* Column alignment */
enum { TUI_ALIGN_LEFT = 0, TUI_ALIGN_RIGHT, TUI_ALIGN_CENTER };

/* Column overflow */
enum { TUI_OVERFLOW_TRUNCATE = 0, TUI_OVERFLOW_ELLIPSIS };

/* Panel flags */
#define TUI_PANEL_CURSOR  0x01
#define TUI_PANEL_BORDER  0x02

/* ── Column definition ─────────────────────────────────────────────── */
typedef struct {
    const char *name;       /* SQL column name */
    int         width;      /* >0 = fixed chars, <0 = flex weight */
    int         align;      /* TUI_ALIGN_* */
    int         overflow;   /* TUI_OVERFLOW_* */
} tui_col_def;

/* ── Panel definition ──────────────────────────────────────────────── */
typedef struct {
    const char       *name;       /* panel name = SQL table name */
    const char       *title;      /* header title (NULL = none) */
    const char       *order_by;   /* SQL ORDER BY fragment */
    const tui_col_def *cols;
    int               ncols;
    int               flags;      /* TUI_PANEL_* */
} tui_panel_def;

/* ── Opaque handle ─────────────────────────────────────────────────── */
typedef struct tui tui_t;

/* ── Callback types ────────────────────────────────────────────────── */

/*
 * Key callback.  Return TUI_HANDLED, TUI_DEFAULT, or TUI_QUIT.
 *   panel  — focused panel name ("" if none)
 *   cursor — 0-based cursor index in focused panel
 *   row_id — id column value of cursor row ("" if empty)
 */
typedef int (*tui_key_cb)(tui_t *tui, int key,
                          const char *panel, int cursor,
                          const char *row_id, void *ctx);

/* FD callback.  Called when fd is readable. */
typedef void (*tui_fd_cb)(tui_t *tui, int fd, void *ctx);

/* Timer callback.  Return 1 to repeat, 0 to cancel. */
typedef int (*tui_timer_cb)(tui_t *tui, void *ctx);

/* ═══════════════════════════════════════════════════════════════════ */

/* Lifecycle */
tui_t *tui_open(sqlite3 *db);
void   tui_close(tui_t *tui);

/* Panel management */
void        tui_add_panel(tui_t *tui, const tui_panel_def *def,
                          int x_pct, int y_pct, int w_pct, int h_pct);
void        tui_dirty(tui_t *tui, const char *panel);  /* NULL = all */
void        tui_focus(tui_t *tui, const char *panel);
const char *tui_get_focus(tui_t *tui);

/* Cursor */
void        tui_set_cursor(tui_t *tui, const char *panel, const char *id);
void        tui_set_cursor_idx(tui_t *tui, const char *panel, int idx);
int         tui_get_cursor(tui_t *tui, const char *panel);
const char *tui_get_cursor_id(tui_t *tui, const char *panel);
int         tui_row_count(tui_t *tui, const char *panel);

/* Event loop */
void tui_on_key(tui_t *tui, tui_key_cb cb, void *ctx);
void tui_watch_fd(tui_t *tui, int fd, tui_fd_cb cb, void *ctx);
void tui_unwatch_fd(tui_t *tui, int fd);
int  tui_add_timer(tui_t *tui, int ms, tui_timer_cb cb, void *ctx);
void tui_remove_timer(tui_t *tui, int timer_id);
void tui_run(tui_t *tui);
void tui_quit(tui_t *tui);

/* Status bar */
void tui_set_status(tui_t *tui, const char *text);

/* Interactive utilities */
int  tui_line_edit(tui_t *tui, const char *prompt, char *buf, int bsz);
void tui_show_help(tui_t *tui, const char **lines);
void tui_sql_prompt(tui_t *tui);

/* Terminal info */
int tui_rows(tui_t *tui);
int tui_cols(tui_t *tui);

#endif /* ENGINE_H */
