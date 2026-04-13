/*
 * engine.h — Generic panel-based TUI engine.
 *
 * ═══════════════════════════════════════════════════════════════════
 *  OVERVIEW
 * ═══════════════════════════════════════════════════════════════════
 *
 * A terminal UI engine that renders named panels from SQLite views.
 * The engine owns terminal I/O, the event loop, rendering, cursor
 * navigation, scrolling, and layout.  The application provides data
 * in SQLite views and receives callbacks on events.
 *
 *   Engine responsibilities              Application responsibilities
 *   ─────────────────────────────────    ─────────────────────────────
 *   Terminal raw mode, alt screen        Database schema & SQL views
 *   Event loop (select on fds)           Register fds, timers, key cb
 *   Read & decode keypresses             Decide what keys mean (via cb)
 *   Render panels from SQL views         Update state params in SQL
 *   Cursor navigation & scroll           Mark panels dirty after changes
 *   Column alignment & truncation        Provide layout in _layout table
 *   Status bar rendering                 Set status text
 *   Line editor, help overlay            Provide help text
 *   Load layout from _layout table       Populate _layout table in SQL
 *   Headless mode for testing            Insert test input into inbox
 *   Dump panel/state for test output     Drive tests via JSON input events
 *
 * ═══════════════════════════════════════════════════════════════════
 *  LIFECYCLE
 * ═══════════════════════════════════════════════════════════════════
 *
 * Two modes of operation:
 *
 *   Interactive:  tui_open(db) → opens terminal, enter raw mode
 *   Headless:     tui_open_headless(db) → no terminal, for tests
 *
 * Both return the same tui_t handle.  The headless engine tracks
 * cursor, panel row counts, focus, and navigation — everything
 * except terminal rendering.  This means tests go through the exact
 * same input→key dispatch→navigation→state update path as a real
 * interactive session.
 *
 * After opening, call tui_load_layout(tui) to read panel definitions
 * from the _layout table in the database (see LAYOUT FROM DB below).
 * Then register callbacks and either tui_run() or use tui_input_key().
 *
 * ═══════════════════════════════════════════════════════════════════
 *  PANEL DATA VIEW FORMAT
 * ═══════════════════════════════════════════════════════════════════
 *
 * Each panel reads from a SQL view whose name matches the panel name.
 * Required columns:
 *
 *   rownum  INT     — 0-based row position (determines display order)
 *   id      TEXT    — unique row identifier, passed back in callbacks
 *   style   TEXT    — row style name (see STYLES)
 *   <col>   TEXT    — one per column in the panel definition
 *
 * Rows are ordered by rownum ASC.  The view can compute rownum using
 * ROW_NUMBER()OVER()-1 or any other method that produces 0-based
 * contiguous integers.
 *
 * Additional columns are ignored by the engine.
 *
 * ═══════════════════════════════════════════════════════════════════
 *  ROW CACHE
 * ═══════════════════════════════════════════════════════════════════
 *
 * Each panel maintains an in-memory cache of up to 256 rows.  SQL is
 * only re-executed when:
 *   1. tui_dirty(tui, panel) is called — full cache invalidation.
 *   2. The user scrolls outside the currently cached row window —
 *      the needed rows are fetched on demand via
 *      WHERE rownum>=? AND rownum<?.
 *
 * Repeated redraws (e.g. cursor movement within the cached window,
 * focus changes, status bar updates) do not re-query the database.
 *
 * The app must call tui_dirty() after updating any SQL view that a
 * panel reads from, to ensure the display reflects the new data.
 *
 * ═══════════════════════════════════════════════════════════════════
 *  LAYOUT
 * ═══════════════════════════════════════════════════════════════════
 *
 * Layout can be defined two ways:
 *
 * 1. PROGRAMMATIC (legacy):
 *    Build a tree of tui_box_t nodes using tui_hbox(), tui_vbox(),
 *    tui_panel_box(), then pass the root to tui_set_layout().
 *
 * 2. FROM DATABASE (preferred):
 *    Populate the _layout temp table, then call tui_load_layout(tui).
 *    The engine reads the table and builds the layout tree internally.
 *
 *    CREATE TEMP TABLE _layout(
 *        id INTEGER PRIMARY KEY,       -- node id
 *        parent_id INT,                -- parent node (NULL=root)
 *        type TEXT NOT NULL,           -- 'hbox','vbox','panel'
 *        name TEXT,                    -- panel name = SQL view name
 *        weight INT DEFAULT 1,        -- flex weight for parent split
 *        min_size INT DEFAULT 0,      -- minimum columns/lines
 *        flags INT DEFAULT 0,         -- TUI_PANEL_* for panels
 *        col_name TEXT,               -- SQL column name (for panel)
 *        col_width INT DEFAULT -1,    -- column width
 *        col_align INT DEFAULT 0,     -- column alignment
 *        col_overflow INT DEFAULT 1   -- column overflow mode
 *    );
 *
 *    Example — two equal panels side by side:
 *      INSERT INTO _layout VALUES(1,NULL,'hbox',NULL,1,0,0,NULL,-1,0,1);
 *      INSERT INTO _layout VALUES(2,1,'panel','lpane',1,0,1,'text',-1,0,1);
 *      INSERT INTO _layout VALUES(3,1,'panel','rpane',1,0,3,'text',-1,0,1);
 *
 * tui_panel_def describes how to render one panel:
 *   name       — panel and SQL view name
 *   title      — header shown at top of panel (NULL = no header)
 *   cols/ncols — column definitions
 *   flags      — TUI_PANEL_CURSOR, TUI_PANEL_BORDER
 *
 * tui_col_def describes one column:
 *   name       — SQL column name
 *   width      — >0 = fixed chars, <0 = flex weight (share of rest)
 *   align      — TUI_ALIGN_LEFT / RIGHT / CENTER
 *   overflow   — TUI_OVERFLOW_TRUNCATE / ELLIPSIS
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
 *   • Key handler via tui_on_key() — called for semantic cursor updates
 *     and non-navigation keys with focused panel and row id
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
 * The engine owns cursor/focus movement:
 *   up/down/j/k, pgup/pgdn, home/g/end, tab
 *
 * After any engine-owned navigation, the key callback is invoked with
 * key=TUI_K_NONE so the application can observe the focused panel and
 * row id now under the cursor.
 *
 * For other keys, the callback is invoked with the raw key value and
 * may return TUI_HANDLED, TUI_DEFAULT, or TUI_QUIT.
 *
 * ═══════════════════════════════════════════════════════════════════
 *  TYPICAL USAGE
 * ═══════════════════════════════════════════════════════════════════
 *
 *   // Interactive mode
 *   sqlite3 *db = ...;
 *   tui_t *tui = tui_open(db);          // or tui_open_headless(db)
 *   tui_load_layout(tui);               // reads _layout table
 *   tui_focus(tui, "lpane");
 *   tui_on_key(tui, my_key_cb, ctx);
 *   tui_dirty(tui, NULL);
 *   tui_run(tui);
 *   tui_close(tui);
 *
 *   // Headless test mode
 *   sqlite3 *db = ...;
 *   tui_t *tui = tui_open_headless(db);
 *   tui_load_layout(tui);
 *   tui_focus(tui, "lpane");
 *   tui_on_key(tui, my_key_cb, ctx);
 *   tui_input_key(tui, 'j');            // simulate keypress
 *   tui_dump(tui, "lpane", stdout);     // dump panel content
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
/* The SQL view named `name` must have columns: rownum INT, id TEXT, style TEXT,
 * plus one column per entry in `cols`.  Rows are ordered by rownum ASC. */
typedef struct {
    const char       *name;       /* panel name = SQL view name */
    const char       *title;      /* header title (NULL = none) */
    const tui_col_def *cols;
    int               ncols;
    int               flags;      /* TUI_PANEL_* */
} tui_panel_def;

/* ── Layout tree ───────────────────────────────────────────────────── */
/*
 * Layout is described as a tree of tui_box_t nodes.
 *
 *   tui_hbox(n, child, ...)  — children placed side by side (horizontal)
 *   tui_vbox(n, child, ...)  — children stacked vertically
 *   tui_panel_box(def, w, m) — leaf: renders one panel
 *
 * Each node's `weight` and `min_size` control how space is divided among
 * siblings in a split.  The parent iterates children:
 *   • Fixed children (weight==0): given exactly min_size columns/lines.
 *   • Flex children  (weight >0): given at least min_size, then share of
 *     remaining space proportional to weight.
 *
 * Example — two equal panels side by side:
 *   tui_set_layout(tui, tui_hbox(2,
 *       tui_panel_box(&left_def,  1, 0),
 *       tui_panel_box(&right_def, 1, 0)));
 *
 * Example — top row (3 equal, min 5 tall), large middle, 1-line status:
 *   tui_box_t *top = tui_hbox(3,
 *       tui_panel_box(&pa, 1, 0),
 *       tui_panel_box(&pb, 1, 0),
 *       tui_panel_box(&pc, 1, 0));
 *   top->min_size = 5;             // enforce minimum height for this row
 *   tui_set_layout(tui, tui_vbox(3,
 *       top,
 *       tui_panel_box(&main_def, 3, 0),
 *       tui_panel_box(&stat_def, 0, 1)));  // fixed 1 line
 */
#define TUI_BOX_HBOX  0   /* horizontal split */
#define TUI_BOX_VBOX  1   /* vertical split */
#define TUI_BOX_PANEL 2   /* leaf: renders a panel */

typedef struct tui_box {
    int type;                   /* TUI_BOX_* */
    int weight;                 /* flex weight for parent split (default 1) */
    int min_size;               /* min cols (in HBOX) or min lines (in VBOX) */
    const tui_panel_def *def;   /* TUI_BOX_PANEL only */
    struct tui_box **children;  /* TUI_BOX_HBOX/VBOX only */
    int nchildren;
} tui_box_t;

/* Opaque handle */
typedef struct tui tui_t;

/* Layout constructors.  All allocation is internal; call tui_close() to free.
 *   tui_hbox(n, box1, box2, ...) — n children placed horizontally
 *   tui_vbox(n, box1, box2, ...) — n children placed vertically
 *   tui_panel_box(def, weight, min_size) — leaf panel node
 */
tui_box_t *tui_panel_box(const tui_panel_def *def, int weight, int min_size);
tui_box_t *tui_hbox(int n, ...);
tui_box_t *tui_vbox(int n, ...);

/* Apply the layout tree.  Replaces any previous layout.  Panels in the tree
 * are registered automatically; no tui_add_panel() calls needed. */
void tui_set_layout(tui_t *tui, tui_box_t *root);

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
tui_t *tui_open_headless(sqlite3 *db);   /* no terminal; for testing */
void   tui_close(tui_t *tui);

/* Layout from DB */
void tui_load_layout(tui_t *tui);  /* read _layout table */

/* Panels / layout */
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

/* Headless input dispatch */
void tui_input_key(tui_t *tui, int key);  /* simulate keypress */
void tui_resize(tui_t *tui, int rows, int cols);

/* Dump panel/state for tests */
void tui_dump(tui_t *tui, const char *what, FILE *out);  /* "lpane","rpane","state" */

/* Interactive utilities */
int  tui_line_edit(tui_t *tui, const char *prompt, char *buf, int bsz);
void tui_show_help(tui_t *tui, const char **lines);
void tui_sql_prompt(tui_t *tui);

/* Terminal info */
int tui_rows(tui_t *tui);
int tui_cols(tui_t *tui);

#endif /* ENGINE_H */
