/*
 * engine.h — Generic two-pane TUI engine.
 *
 * ═══════════════════════════════════════════════════════════════════
 *  OVERVIEW
 * ═══════════════════════════════════════════════════════════════════
 *
 * This engine renders a two-pane terminal UI: a scrollable left list
 * and a scrollable right detail pane, plus a bottom status bar.  It
 * knows nothing about what is being displayed — processes, files,
 * htop rows, Norton Commander panels, Lotus 123 cells, whatever.
 *
 * The application is responsible for:
 *   • Managing the SQLite database (opening, schema, populating data)
 *   • The event loop (poll/select/kqueue, reading fds, timers)
 *   • Populating the display tables (lpane, rpane) before each render
 *   • Handling keypresses (engine reads keys; app decides what they mean)
 *
 * The engine provides:
 *   • Terminal management (raw mode, alternate screen, cleanup)
 *   • Key reading from the terminal fd
 *   • Rendering the two-pane layout from display tables in a DB
 *   • A line editor for interactive prompts
 *   • Help screen display
 *   • Screen-buffer utilities
 *
 * ═══════════════════════════════════════════════════════════════════
 *  DISPLAY TABLES  (the contract between app and engine)
 * ═══════════════════════════════════════════════════════════════════
 *
 * The engine reads from these tables in the sqlite3* you give it.
 * The app must CREATE them and keep them populated.  The engine never
 * writes to them except where noted below.
 *
 *   lpane — left pane content
 *   ─────────────────────────────────────────────────────────────────
 *   rownum  INTEGER PRIMARY KEY   — 0-based sequential row index
 *   id      TEXT NOT NULL         — app-defined row identifier
 *   style   TEXT DEFAULT 'normal' — rendering style (see STYLES)
 *   text    TEXT NOT NULL         — display text (may contain ANSI)
 *
 *   rpane — right pane content
 *   ─────────────────────────────────────────────────────────────────
 *   rownum  INTEGER PRIMARY KEY   — 0-based sequential row index
 *   style   TEXT DEFAULT 'normal' — rendering style (see STYLES)
 *   text    TEXT NOT NULL         — display text (may contain ANSI)
 *
 *   state — UI navigation state
 *   ─────────────────────────────────────────────────────────────────
 *   cursor   INT  — lpane cursor position (0-based rownum)
 *   scroll   INT  — lpane scroll offset
 *   focus    INT  — 0 = left pane focused, 1 = right pane focused
 *   dcursor  INT  — rpane cursor position
 *   dscroll  INT  — rpane scroll offset
 *   rows     INT  — terminal height (engine writes on resize)
 *   cols     INT  — terminal width  (engine writes on resize)
 *   status   TEXT — text for the status bar (app-provided)
 *
 *   The engine WRITES to state: rows, cols (on tui_resize).
 *   The engine READS: cursor, scroll, focus, dcursor, dscroll, rows,
 *                     cols, status.
 *   The app is responsible for all other writes to state (updating
 *   cursor, scroll, focus, etc. in response to keys).
 *
 * ═══════════════════════════════════════════════════════════════════
 *  STYLES
 * ═══════════════════════════════════════════════════════════════════
 *
 *   The style column maps to ANSI colors:
 *     "normal"    — default terminal color
 *     "error"     — red
 *     "green"     — green
 *     "yellow"    — yellow
 *     "cyan"      — cyan
 *     "cyan_bold" — bold cyan
 *     "heading"   — bold yellow
 *     "search"    — bold magenta
 *     "dim"       — dim
 *
 * ═══════════════════════════════════════════════════════════════════
 *  TYPICAL USAGE
 * ═══════════════════════════════════════════════════════════════════
 *
 *   sqlite3 *db = ...;          // app opens & populates DB
 *   tui_t *tui = tui_open(db);  // engine opens terminal
 *
 *   // app event loop:
 *   for (;;) {
 *       rebuild_lpane(db);       // app populates lpane
 *       rebuild_rpane(db);       // app populates rpane
 *       tui_render(tui);         // engine draws from tables
 *
 *       // app does select/poll on tui_fd(tui) + its own fds
 *       int k = tui_read_key(tui);
 *       if (k == 'q') break;
 *       handle_key(db, k);       // app updates state/tables
 *   }
 *
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

/* ── Opaque TUI handle ─────────────────────────────────────────────── */
typedef struct tui tui_t;

/* ═══════════════════════════════════════════════════════════════════
 *  LIFECYCLE
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * tui_open — initialise terminal for TUI rendering.
 *
 * Opens /dev/tty, enters raw mode / alternate screen, registers
 * atexit cleanup, and writes initial rows/cols into state table.
 *
 * db:  The app's SQLite database.  Must already contain the state
 *      table with rows and cols columns.  Engine will UPDATE them.
 *
 * Returns an opaque handle, or NULL on failure.
 */
tui_t *tui_open(sqlite3 *db);

/*
 * tui_close — restore terminal and free resources.
 *
 * Restores the original terminal state (cooked mode, main screen,
 * visible cursor).  Safe to call with NULL.
 */
void tui_close(tui_t *tui);

/* ═══════════════════════════════════════════════════════════════════
 *  TERMINAL QUERIES
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * tui_fd — return the file descriptor for the terminal.
 *
 * The app should include this fd in its poll/select set to know when
 * keyboard input is available.  Returns -1 if tui is NULL.
 */
int tui_fd(tui_t *tui);

/* ═══════════════════════════════════════════════════════════════════
 *  INPUT
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * tui_read_key — read one keypress from the terminal.
 *
 * Non-blocking if no data is available (returns TUI_K_NONE).
 * Decodes ANSI escape sequences into TUI_K_* constants.
 * Single printable bytes are returned as-is (e.g. 'q', '/').
 */
int tui_read_key(tui_t *tui);

/* ═══════════════════════════════════════════════════════════════════
 *  RENDERING
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * tui_render — draw the two-pane layout to the terminal.
 *
 * Reads from lpane, rpane, and state tables in the DB.
 *
 * Layout:
 *   rows 1..rows-1  — content area
 *   row  rows       — status bar (from state.status)
 *
 * Left pane occupies cols/2 columns; right pane gets the rest.
 * If the right pane would be < 20 columns, it is hidden and the
 * left pane uses the full width.
 *
 * Cursor highlight: the row at state.cursor gets inverse video.
 * If state.focus=0, the cursor is bold+inverse; if focus=1, just
 * inverse.  Similarly for rpane with state.dcursor.
 *
 * The engine adjusts scroll/dscroll to keep cursors visible, and
 * writes the adjusted values back to state.
 */
void tui_render(tui_t *tui);

/* ═══════════════════════════════════════════════════════════════════
 *  RESIZE
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * tui_check_resize — query actual terminal size and update state.
 *
 * Call this after SIGWINCH or at the top of each loop iteration.
 * Returns 1 if the size changed, 0 otherwise.
 * Updates state.rows and state.cols if changed.
 */
int tui_check_resize(tui_t *tui);

/* ═══════════════════════════════════════════════════════════════════
 *  LINE EDITOR
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * tui_line_edit — interactive single-line text editor.
 *
 * Draws a prompt on the bottom row, lets the user type, and returns
 * when Enter or Esc is pressed.
 *
 * prompt: displayed before the text (e.g. "/", "SQL> ")
 * buf:    in/out buffer; pre-populated text is shown initially
 * bsz:   size of buf in bytes
 *
 * Returns 1 on Enter (accept), 0 on Esc (cancel).
 * buf is updated in-place with the edited text.
 */
int tui_line_edit(tui_t *tui, const char *prompt, char *buf, int bsz);

/* ═══════════════════════════════════════════════════════════════════
 *  HELP SCREEN
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * tui_show_help — display a full-screen help overlay.
 *
 * lines: NULL-terminated array of strings, one per line.
 * Clears the screen, shows the lines in cyan, then blocks until
 * any key is pressed.
 */
void tui_show_help(tui_t *tui, const char **lines);

/* ═══════════════════════════════════════════════════════════════════
 *  SQL PROMPT
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * tui_sql_prompt — interactive SQL query and result display.
 *
 * Prompts the user for a SQL statement, executes it against the DB,
 * and shows the results in a table.  Blocks until any key is pressed
 * after showing results.
 */
void tui_sql_prompt(tui_t *tui);

/* ═══════════════════════════════════════════════════════════════════
 *  HEADLESS OUTPUT
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * tui_dump_table — print contents of a display table to stdout.
 *
 * table: one of "lpane", "rpane", "state".
 *
 * Prints a section header ("=== LPANE ==="), one row per line with
 * pipe-delimited fields, then a footer ("=== END LPANE ===").
 * For "state", prints key=value pairs on one line.
 *
 * This does not require the terminal to be open; it works headless.
 */
void tui_dump_table(sqlite3 *db, const char *table);

/* ═══════════════════════════════════════════════════════════════════
 *  SIGWINCH SUPPORT
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * tui_sigwinch_handler — signal handler for SIGWINCH.
 *
 * Install this with sigaction(SIGWINCH, ...) if you want automatic
 * resize detection via tui_check_resize().
 */
void tui_sigwinch_handler(int sig);

#endif /* ENGINE_H */
