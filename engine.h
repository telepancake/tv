/*
 * engine.h — Generic TUI engine API for a two-pane SQLite-driven viewer.
 *
 * The engine manages:
 *   • An in-memory SQLite database with well-known tables
 *     (lpane, rpane, state, outbox, inbox)
 *   • A terminal-based two-pane TUI (left list + right detail)
 *   • The main event loop (keyboard + optional streaming fd)
 *   • DB helper utilities (xexec, qint, etc.)
 *
 * All application-specific logic is provided via callbacks.
 * The engine has no knowledge of processes, traces, or files —
 * it only renders what the app puts into lpane/rpane.
 */
#ifndef ENGINE_H
#define ENGINE_H

#include "sqlite3.h"
#include <stdio.h>
#include <sys/types.h>

/* ── Key constants ─────────────────────────────────────────────────── */
enum {
    K_NONE  = -1,
    K_UP    = 256, K_DOWN, K_LEFT, K_RIGHT,
    K_PGUP, K_PGDN, K_HOME, K_END,
    K_TAB   = 9,
    K_ENTER = 13,
    K_ESC   = 27,
    K_BS    = 127
};

/* ── Opaque engine handle ──────────────────────────────────────────── */
typedef struct tv_engine tv_engine;

/* ── SQL custom function registration ──────────────────────────────── */
typedef struct {
    const char *name;
    int         nargs;
    void      (*xFunc)(sqlite3_context*, int, sqlite3_value**);
} tv_sql_func;

/* ── Application callbacks ─────────────────────────────────────────── */
typedef struct {
    void *app_data;

    /* Called for every keypress.  Return non-zero to quit. */
    int  (*on_key)(tv_engine *eng, void *app_data, int key);

    /* Called when outbox.rl is set — repopulate lpane table. */
    void (*rebuild_lpane)(tv_engine *eng, void *app_data);

    /* Called when outbox.rr is set — repopulate rpane table. */
    void (*rebuild_rpane)(tv_engine *eng, void *app_data);

    /* Called for each JSONL trace line from the streaming fd. */
    void (*on_trace_line)(tv_engine *eng, void *app_data, const char *line);

    /* Called for each input event from the inbox. */
    void (*on_input)(tv_engine *eng, void *app_data, const char *data);

    /* Called when the trace stream ends (e.g. to build FTS). */
    void (*on_stream_end)(tv_engine *eng, void *app_data);
} tv_callbacks;

/* ── Lifecycle ─────────────────────────────────────────────────────── */

/* Create an engine with an in-memory SQLite DB.
 * Registers the given SQL custom functions.
 * Does NOT execute any schema — call tv_xexec() afterwards. */
tv_engine *tv_engine_new(const tv_callbacks *cb,
                         const tv_sql_func  *funcs, int nfuncs);

/* Destroy engine, close DB, free resources. */
void tv_engine_destroy(tv_engine *eng);

/* ── Database access ───────────────────────────────────────────────── */
sqlite3    *tv_db(tv_engine *eng);

void        tv_xexec (tv_engine *eng, const char *sql);
void        tv_xexecf(tv_engine *eng, const char *fmt, ...);
int         tv_qint  (tv_engine *eng, const char *sql, int def);
int         tv_qintf (tv_engine *eng, int def, const char *fmt, ...);
double      tv_qdbl  (tv_engine *eng, const char *sql, double def);

/* ── Pane dirty flags ──────────────────────────────────────────────── */
void tv_dirty_lp  (tv_engine *eng);   /* mark left pane for rebuild  */
void tv_dirty_rp  (tv_engine *eng);   /* mark right pane for rebuild */
void tv_dirty_both(tv_engine *eng);   /* mark both panes             */
void tv_sync_panes(tv_engine *eng);   /* check outbox, call rebuild  */

/* ── Database loading ──────────────────────────────────────────────── */

/* Load a saved DB file into the in-memory DB (sqlite3_backup). */
void tv_load_db(tv_engine *eng, const char *path);

/* Save the in-memory DB to a file. */
void tv_save_to_file(tv_engine *eng, const char *path);

/* ── Ingest ────────────────────────────────────────────────────────── */

/* Insert a JSONL line into the inbox table. */
void tv_ingest_line(tv_engine *eng, const char *line);

/* Ingest an entire file line-by-line into inbox. */
void tv_ingest_file(tv_engine *eng, const char *path);

/* Drain inbox: process trace events (calls on_trace_line),
 * then (if !trace_only) process input events (calls on_input). */
void tv_process_inbox(tv_engine *eng, int trace_only);

/* ── TUI utilities (for use by callbacks) ──────────────────────────── */

/* Interactive line editor.  Returns 1 on Enter, 0 on Esc. */
int  tv_line_edit(tv_engine *eng, const char *prompt, char *buf, int bsz);

/* Display a help screen (NULL-terminated array of lines). */
void tv_show_help(tv_engine *eng, const char **lines);

/* Interactive SQL query tool. */
void tv_run_sql(tv_engine *eng);

/* Save DB via interactive filename prompt. */
void tv_save_db(tv_engine *eng);

/* ── Headless output ───────────────────────────────────────────────── */
void tv_dump_lpane(tv_engine *eng);
void tv_dump_rpane(tv_engine *eng);
void tv_dump_state(tv_engine *eng);

/* ── Main loop ─────────────────────────────────────────────────────── */

/* Run the TUI main loop.
 * trace_fd:    fd to read streaming JSONL from (-1 if none)
 * trace_pipe:  popen'd FILE* owning trace_fd (NULL if not popen'd)
 * child_pid:   child process to reap (0 if none)
 * headless:    if true, skip TUI entirely (just process inbox)
 * Returns 0. */
int tv_engine_run(tv_engine *eng,
                  int trace_fd, FILE *trace_pipe, pid_t child_pid,
                  int headless);

/* ── State accessors ───────────────────────────────────────────────── */
void tv_set_headless (tv_engine *eng, int h);
int  tv_is_headless  (tv_engine *eng);
void tv_set_own_tgid (tv_engine *eng, int tgid);
int  tv_own_tgid     (tv_engine *eng);

/* ── Render (exposed so callbacks can force a re-render) ───────────── */
void tv_render(tv_engine *eng);
void tv_need_render(tv_engine *eng);

#endif /* ENGINE_H */
