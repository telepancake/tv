/* data_source.h - SQL-backed row iterators for tv's panels.
 *
 * Each panel mode runs SQL against the .tvdb. The DataSource exposed
 * to the engine is just an iterator wrapper. Heavy aggregations are
 * cached in tv_idx_* tables that are built on first use.
 *
 * Modes (visible numbering matches keys 1..7):
 *   1  process tree   (cursor: tgid)
 *   2  file tree      (cursor: path)
 *   3  event log      (cursor: "tgid:ts_ns" or just ts_ns)
 *   4  deps           (anchor: a path; rows: paths read to produce it)
 *   5  reverse deps   (anchor: a path; rows: paths derived from it)
 *   6  dep cmds       (anchor: a path; rows: processes in dep closure)
 *   7  rdep cmds      (anchor: a path; rows: processes in rdep closure)
 */
#pragma once

#include "engine.h"

#include <string>
#include <vector>

class TvDb;

struct AppState {
    int          mode = 1;
    std::string  cursor_id;        /* current cursor row id (mode-dependent) */
    std::string  search;           /* /search query - substring/glob filter */
    /* Flag filter - string of one-letter category codes that must ALL
     * be satisfied by a row. Vocabulary is mode-dependent:
     *   mode 2 (files): R W E w f s k   (see lpane_files for meaning)
     *   mode 1 (procs): K F D            (see lpane_processes for meaning)
     * The string syntax keeps composing simple: "WE" = writes AND errors.
     */
    std::string  flag_filter;
    std::string  subject_file;     /* anchor for modes 4..7 */
    bool         grouped = true;   /* tree (true) vs flat (false) view */
    bool         subtree_only = false;  /* mode 1: restrict to subtree of cursor */
    std::string  subtree_root;     /* mode 1: tgid of subtree root */
    bool         show_pids = false;     /* mode 1: prefix labels with [tgid] */
    /* Right-pane section collapsing: heading id (e.g. "__ho") -> collapsed. */
    std::vector<std::string> collapsed_sections;
    /* Time-range cutoffs (0 = no cutoff). Applied to ts_ns columns in
     * modes 0/1/2/3. Bound to keys '<' (before) and '>' (after) in the
     * UI: first press seeds the cutoff from the cursor's timestamp,
     * second press clears it. Lets you slice a long trace down to a
     * window without losing the rest of the filter state. */
    int64_t      ts_after_ns  = 0;
    int64_t      ts_before_ns = 0;
};

class TvDataSource {
public:
    explicit TvDataSource(TvDb &db, AppState &state);

    DataSource make_data_source();
    void invalidate();         /* both panes - for live data updates */
    void invalidate_rpane();   /* cursor change - keep lpane cache */

    /* Per-mode column layout for the left pane. Returned ColDef
     * pointer is owned by the data source (stable across calls).
     * The engine receives this via Tui::set_panel_columns() on every
     * mode change - see apply_layout(). */
    struct PanelLayout {
        const ColDef *cols;
        int           ncols;
        const char   *title;   /* used as a column-header row in the title bar */
    };
    PanelLayout lpane_layout() const;
    PanelLayout rpane_layout() const;
    /* Convenience: push both layouts to the engine. Call after every
     * mode change so cols/title match the new mode's row shape. */
    void apply_layout(class Tui &tui, int lpane, int rpane) const;

private:
    void row_begin(int panel);
    bool row_has_more(int panel);
    RowData row_next(int panel);

    void rebuild_lpane();
    void rebuild_rpane();

    /* Mode-specific lpane builders. */
    void lpane_outputs();             /* mode 0: stdout/stderr stream */
    void lpane_processes();
    void lpane_files();
    void lpane_events();
    void lpane_deps(int reverse);     /* 0=deps, 1=rdeps */
    void lpane_dep_cmds(int reverse); /* 0=dcmds, 1=rcmds */
    /* Common-prefix "hat" row(s) inserted at the top of list views
     * when all visible rows share a deep parent path / chain.
     *   - emit_path_hat(): mode 2 (file lists). Longest common
     *     path-segment prefix.
     *   - mode 1 (proc trees) does its own variant inline inside
     *     lpane_processes() because it needs access to the procs map
     *     to walk parent_id chains. */
    void emit_path_hat();

    /* Mode-specific rpane builders. */
    void rpane_process_detail(const std::string &tgid);
    void rpane_file_detail(const std::string &path);
    void rpane_event_detail(const std::string &id);
    void rpane_output_detail(const std::string &id); /* mode 0 cursor */

    TvDb     &db_;
    AppState &state_;

    std::vector<RowData> lpane_;
    std::vector<RowData> rpane_;
    size_t lpane_idx_ = 0;
    size_t rpane_idx_ = 0;
    bool   built_lpane_ = false;
    bool   built_rpane_ = false;
    std::string built_for_cursor_;
    std::string built_for_subject_;
    int    built_for_mode_ = -1;
    std::string built_for_search_;
    std::string built_for_flag_filter_;
    bool   built_for_grouped_ = true;
    bool   built_for_subtree_only_ = false;
    std::string built_for_subtree_root_;
    bool   built_for_show_pids_ = false;
    std::vector<std::string> built_for_collapsed_;
    int64_t built_for_ts_after_ns_  = 0;
    int64_t built_for_ts_before_ns_ = 0;
};
