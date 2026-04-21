/* data_source.h — SQL-backed row iterators for tv's panels.
 *
 * Each panel mode has its own row source. The row source is a thin
 * adapter that runs a SQL query against the .tvdb and turns each
 * result row into an engine RowData.
 *
 * Currently implemented:
 *   - Mode 1 (process tree, flat order): SELECT one row per process.
 *   - Right-pane process detail: SELECT exec/exit/argv columns.
 *
 * All other modes return a single sentinel row "(mode N: not yet
 * ported to the SQL backend)" so the binary keeps running and the
 * key bindings still resolve.
 */
#pragma once

#include "engine.h"

#include <string>
#include <vector>

class TvDb;

struct AppState {
    int          mode = 1;          /* 1=processes, 2=files, 3=output, 4..=deps */
    std::string  cursor_id;         /* lpane current cursor row id */
    std::string  search;            /* /search query */
};

class TvDataSource {
public:
    explicit TvDataSource(TvDb &db, AppState &state);

    /* Build a DataSource bound to *this. The DataSource callbacks
     * forward into row_begin/row_has_more/row_next below. */
    DataSource make_data_source();

    /* Used by the key handler when search/mode/cursor changes. */
    void invalidate();

    /* Direct query helpers (also used by the right-pane builder). */
    std::vector<std::vector<std::string>> rpane_process(const std::string &cursor_id,
                                                        std::string *err);

private:
    void row_begin(int panel);
    bool row_has_more(int panel);
    RowData row_next(int panel);

    void rebuild_lpane();
    void rebuild_rpane();

    TvDb     &db_;
    AppState &state_;

    std::vector<RowData> lpane_;
    std::vector<RowData> rpane_;
    size_t lpane_idx_ = 0;
    size_t rpane_idx_ = 0;
    bool   built_lpane_ = false;
    bool   built_rpane_ = false;
    std::string built_for_cursor_;
    int    built_for_mode_ = -1;
};
