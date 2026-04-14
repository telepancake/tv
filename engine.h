#ifndef ENGINE_H
#define ENGINE_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    TUI_K_NONE  = -1,
    TUI_K_UP    = 256, TUI_K_DOWN, TUI_K_LEFT, TUI_K_RIGHT,
    TUI_K_PGUP, TUI_K_PGDN, TUI_K_HOME, TUI_K_END,
    TUI_K_TAB   = 9,
    TUI_K_ENTER = 13,
    TUI_K_ESC   = 27,
    TUI_K_BS    = 127
};

#define TUI_HANDLED  1
#define TUI_DEFAULT  0
#define TUI_QUIT    -1

enum { TUI_ALIGN_LEFT = 0, TUI_ALIGN_RIGHT, TUI_ALIGN_CENTER };
enum { TUI_OVERFLOW_TRUNCATE = 0, TUI_OVERFLOW_ELLIPSIS };

#define TUI_PANEL_CURSOR  0x01
#define TUI_PANEL_BORDER  0x02

typedef struct {
    const char *name;
    int         width;
    int         align;
    int         overflow;
} tui_col_def;

typedef struct {
    const char        *name;
    const char        *title;
    const tui_col_def *cols;
    int                ncols;
    int                flags;
} tui_panel_def;

#define TUI_BOX_HBOX  0
#define TUI_BOX_VBOX  1
#define TUI_BOX_PANEL 2

/* Box flags */
#define TUI_BOX_HSCROLL  0x01  /* hbox: auto-scroll to keep focused child visible */

typedef struct tui_box {
    int type;
    int weight;
    int min_size;
    int flags;
    const tui_panel_def *def;
    struct tui_box **children;
    int nchildren;
} tui_box_t;

typedef struct tui tui_t;

typedef struct {
    const char *id;
    const char *style;
    const char *cols[32];
} tui_row_ref;

typedef struct {
    int  (*row_count)(const char *panel, void *ctx);
    int  (*row_get)(const char *panel, int rownum, tui_row_ref *row, void *ctx);
    int  (*row_find)(const char *panel, const char *id, void *ctx);
    void (*size_changed)(int rows, int cols, void *ctx);
} tui_data_source;

typedef int (*tui_key_cb)(tui_t *tui, int key,
                          const char *panel, int cursor,
                          const char *row_id, void *ctx);
typedef void (*tui_fd_cb)(tui_t *tui, int fd, void *ctx);
typedef int (*tui_timer_cb)(tui_t *tui, void *ctx);

void tui_set_layout(tui_t *tui, tui_box_t *root);

tui_t *tui_open(const tui_data_source *source, void *source_ctx);
tui_t *tui_open_headless(const tui_data_source *source, void *source_ctx, int rows, int cols);
void   tui_close(tui_t *tui);

void        tui_dirty(tui_t *tui, const char *panel);
void        tui_focus(tui_t *tui, const char *panel);
const char *tui_get_focus(tui_t *tui);

void        tui_set_cursor(tui_t *tui, const char *panel, const char *id);
void        tui_set_cursor_idx(tui_t *tui, const char *panel, int idx);
int         tui_get_cursor(tui_t *tui, const char *panel);
int         tui_get_scroll(tui_t *tui, const char *panel);
const char *tui_get_cursor_id(tui_t *tui, const char *panel);
int         tui_row_count(tui_t *tui, const char *panel);

void tui_on_key(tui_t *tui, tui_key_cb cb, void *ctx);
void tui_watch_fd(tui_t *tui, int fd, tui_fd_cb cb, void *ctx);
void tui_unwatch_fd(tui_t *tui, int fd);
int  tui_add_timer(tui_t *tui, int ms, tui_timer_cb cb, void *ctx);
void tui_remove_timer(tui_t *tui, int timer_id);
void tui_run(tui_t *tui);
void tui_quit(tui_t *tui);

void tui_set_status(tui_t *tui, const char *text);

void tui_input_key(tui_t *tui, int key);
void tui_resize(tui_t *tui, int rows, int cols);

int tui_line_edit(tui_t *tui, const char *prompt, char *buf, int bsz);
void tui_show_help(tui_t *tui, const char **lines);

int tui_rows(tui_t *tui);
int tui_cols(tui_t *tui);

#ifdef __cplusplus
}
#endif

#endif
