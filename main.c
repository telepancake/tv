#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <time.h>

#include <zstd.h>

#include "engine.h"

extern int uproctrace_main(int argc, char **argv);

#define MAX_JSON_LINE (1 << 20)
#define ARRAY_LEN(a) ((int)(sizeof(a) / sizeof((a)[0])))
#define GROW(arr, n, cap) do { \
    if ((n) >= (cap)) { \
        (cap) = (cap) ? (cap) * 2 : 16; \
        (arr) = xrealloc((arr), (size_t)(cap) * sizeof(*(arr))); \
    } \
} while (0)

typedef struct { const char *s, *e; } span_t;

typedef enum {
    EV_CWD,
    EV_EXEC,
    EV_OPEN,
    EV_EXIT,
    EV_STDOUT,
    EV_STDERR
} event_kind_t;

typedef struct {
    int id;
    event_kind_t kind;
    double ts;
    int pid, tgid, ppid, nspid, nstgid;
    char *path;
    char *resolved_path;
    char *exe;
    char **argv;
    int argc;
    char *flags_text;
    int fd;
    int err;
    int inherited;
    char *data;
    int len;
    char *status;
    int code;
    int signal;
    int core_dumped;
    int raw;
} trace_event_t;

typedef struct {
    int tgid, pid, ppid, nspid, nstgid;
    int parent_index;
    int *children;
    int nchildren, capchildren;
    int descendant_count;
    double start_ts, end_ts;
    int has_start, has_end;
    char *exe;
    char **argv;
    int argc;
    char *cwd;
    char *exit_status;
    int exit_code;
    int exit_signal;
    int core_dumped;
    int exit_raw;
    int has_write_open;
    int has_stdout;
    int has_stderr;
    char **read_paths;
    int nreads, capreads;
    char **write_paths;
    int nwrites, capwrites;
} process_t;

typedef struct {
    int kind;
    int key;
    int rows, cols;
    char *text;
} input_cmd_t;

typedef struct {
    char *id;
    char *style;
    char *text;
    char *parent_id;
    int link_mode;
    char *link_id;
    int has_children;
} view_row_t;

typedef struct {
    view_row_t *rows;
    int count, cap;
} view_t;

typedef struct {
    char **items;
    int count, cap;
} strset_t;

typedef struct {
    int mode;
    int grouped;
    int ts_mode;
    int sort_key;
    int lp_filter;
    int dep_filter;
    int rows, cols;
    int focus;
    int cursor, scroll, dcursor, dscroll;
    char cursor_id[4096];
    char dcursor_id[4096];
    char search[256];
    char evfilt[64];
} app_state_t;

typedef struct {
    int tgid;
    char *name;
    trace_event_t **events;
    int count, cap;
} output_group_t;

typedef struct {
    char *path;
    int opens;
    int procs;
    int errs;
} file_stat_t;

typedef struct {
    char *path;
    char *parent;
    char *name;
    int opens;
    int procs;
    int errs;
    int has_children;
} dir_stat_t;

typedef struct {
    char *src;
    char *dst;
} file_edge_t;

enum {
    INPUT_KEY,
    INPUT_RESIZE,
    INPUT_SELECT,
    INPUT_SEARCH,
    INPUT_EVFILT,
    INPUT_PRINT
};

enum {
    LIVE_TRACE_BATCH_ROWS = 256,
    LIVE_TRACE_BATCH_MS = 50,
};

static trace_event_t *g_events;
static int g_nevents, g_cap_events, g_next_event_id = 1;
static process_t *g_processes;
static int g_nprocs, g_cap_procs;
static char **g_raw_trace_lines;
static int g_nraw, g_cap_raw;
static input_cmd_t *g_inputs;
static int g_ninputs, g_cap_inputs;
static view_t g_lpane, g_rpane;
static app_state_t g_state = { .grouped = 1, .rows = 24, .cols = 80 };
static tui_t *g_tui;
static int g_headless;
static double g_base_ts;
static strset_t g_proc_collapsed, g_file_collapsed, g_output_collapsed, g_dep_collapsed;

static char t_rbuf[MAX_JSON_LINE];
static int t_rbuf_len = 0;
static int t_trace_fd = -1;
static pid_t t_child_pid = 0;
static int t_pending_live_rows = 0;
static long long t_live_batch_start_ms = 0;

static const char *HELP[] = {
    "", "  Process Trace Viewer", "  ════════════════════", "",
    "  ↑↓ jk  Navigate    PgUp/PgDn  Page    g  First    Tab  Switch pane",
    "  ← h  Collapse/back    → l  Expand/detail    Enter  Follow link", "",
    "  1 Process  2 File  3 Output    G  Toggle tree/flat    s  Sort    t  Timestamps",
    "  4 Deps  5 Reverse-deps  6 Dep-cmds  7 Reverse-dep-cmds    d  Toggle dep filter",
    "  /  Search    n/N  Next/prev    f/F  Filter events/clear    e/E  Expand/collapse all",
    "  v  Cycle proc filter (none→failed→running)    V  Clear proc filter",
    "  W  Save trace to file    x  SQL removed    q  Quit    ?  Help", "", "  Press any key.", 0
};

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { perror("malloc"); exit(1); }
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { perror("realloc"); exit(1); }
    return q;
}

static char *xstrdup(const char *s) {
    if (!s) s = "";
    size_t n = strlen(s) + 1;
    char *r = xmalloc(n);
    memcpy(r, s, n);
    return r;
}

static char *xstrndup(const char *s, size_t n) {
    char *r = xmalloc(n + 1);
    memcpy(r, s, n);
    r[n] = 0;
    return r;
}

static char *fmtdup(const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    char *buf = xmalloc((size_t)n + 1);
    vsnprintf(buf, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return buf;
}

static long long monotonic_millis(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

static const char *json_skip_string(const char *p, const char *end) {
    if (p >= end || *p != '"') return NULL;
    p++;
    while (p < end) {
        if (*p == '\\') {
            p += 2;
            continue;
        }
        if (*p == '"') return p + 1;
        p++;
    }
    return NULL;
}

static const char *json_skip_value(const char *p, const char *end) {
    p = skip_ws(p, end);
    if (p >= end) return NULL;
    if (*p == '"') return json_skip_string(p, end);
    if (*p == '{') {
        int depth = 1;
        p++;
        while (p < end && depth > 0) {
            if (*p == '"') {
                p = json_skip_string(p, end);
                if (!p) return NULL;
                continue;
            }
            if (*p == '{') depth++;
            else if (*p == '}') depth--;
            p++;
        }
        return depth == 0 ? p : NULL;
    }
    if (*p == '[') {
        int depth = 1;
        p++;
        while (p < end && depth > 0) {
            if (*p == '"') {
                p = json_skip_string(p, end);
                if (!p) return NULL;
                continue;
            }
            if (*p == '[') depth++;
            else if (*p == ']') depth--;
            p++;
        }
        return depth == 0 ? p : NULL;
    }
    while (p < end && *p != ',' && *p != '}' && *p != ']') p++;
    return p;
}

static int span_string_eq(span_t sp, const char *s) {
    size_t n = strlen(s);
    return (size_t)(sp.e - sp.s) == n && memcmp(sp.s, s, n) == 0;
}

static char *json_decode_string(span_t sp) {
    if (sp.e <= sp.s || *sp.s != '"') return NULL;
    const char *p = sp.s + 1, *end = sp.e - 1;
    char *out = xmalloc((size_t)(sp.e - sp.s) + 1);
    int oi = 0;
    while (p < end) {
        if (*p == '\\' && p + 1 < end) {
            p++;
            switch (*p) {
            case 'n': out[oi++] = '\n'; break;
            case 'r': out[oi++] = '\r'; break;
            case 't': out[oi++] = '\t'; break;
            case 'b': out[oi++] = '\b'; break;
            case 'f': out[oi++] = '\f'; break;
            case '"': out[oi++] = '"'; break;
            case '\\': out[oi++] = '\\'; break;
            case '/': out[oi++] = '/'; break;
            case 'u':
                if (p + 4 < end) {
                    unsigned v = 0;
                    for (int i = 0; i < 4; i++) {
                        char c = p[1 + i];
                        v <<= 4;
                        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
                        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
                    }
                    out[oi++] = (v >= 32 && v < 127) ? (char)v : '?';
                    p += 4;
                }
                break;
            default:
                out[oi++] = *p;
                break;
            }
            p++;
            continue;
        }
        out[oi++] = *p++;
    }
    out[oi] = 0;
    return out;
}

static int json_obj_get(const char *json, const char *key, span_t *out) {
    const char *p = json;
    const char *end = json + strlen(json);
    p = skip_ws(p, end);
    if (p >= end || *p != '{') return 0;
    p++;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end || *p == '}') return 0;
        const char *ks = p;
        p = json_skip_string(p, end);
        if (!p) return 0;
        span_t keysp = { ks + 1, p - 1 };
        p = skip_ws(p, end);
        if (p >= end || *p != ':') return 0;
        p++;
        p = skip_ws(p, end);
        const char *vs = p;
        p = json_skip_value(p, end);
        if (!p) return 0;
        if ((size_t)(keysp.e - keysp.s) == strlen(key) && memcmp(keysp.s, key, strlen(key)) == 0) {
            out->s = vs;
            out->e = p;
            return 1;
        }
        p = skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
    return 0;
}

static int span_to_int(span_t sp, int def) {
    char *tmp = xstrndup(sp.s, (size_t)(sp.e - sp.s));
    char *ep = NULL;
    long v = strtol(tmp, &ep, 10);
    free(tmp);
    return (ep && *ep == 0) ? (int)v : def;
}

static double span_to_double(span_t sp, double def) {
    char *tmp = xstrndup(sp.s, (size_t)(sp.e - sp.s));
    char *ep = NULL;
    double v = strtod(tmp, &ep);
    free(tmp);
    return (ep && *ep == 0) ? v : def;
}

static int span_to_bool(span_t sp, int def) {
    if (span_string_eq(sp, "true")) return 1;
    if (span_string_eq(sp, "false")) return 0;
    return def;
}

static char **json_array_of_strings(span_t sp, int *count_out) {
    char **arr = NULL;
    int n = 0, cap = 0;
    const char *p = skip_ws(sp.s, sp.e);
    if (p >= sp.e || *p != '[') { *count_out = 0; return NULL; }
    p++;
    while (p < sp.e) {
        p = skip_ws(p, sp.e);
        if (p >= sp.e || *p == ']') break;
        span_t item = { p, NULL };
        p = json_skip_string(p, sp.e);
        if (!p) break;
        item.e = p;
        GROW(arr, n, cap);
        arr[n++] = json_decode_string(item);
        p = skip_ws(p, sp.e);
        if (p < sp.e && *p == ',') p++;
    }
    *count_out = n;
    return arr;
}

static void free_string_array(char **arr, int n) {
    if (!arr) return;
    for (int i = 0; i < n; i++) free(arr[i]);
    free(arr);
}

static const char *basename_c(const char *path) {
    const char *s;
    if (!path || !path[0]) return "";
    s = strrchr(path, '/');
    return s ? s + 1 : path;
}

static void canon_path_c(char *path, int maxlen) {
    if (!path || !path[0]) return;
    char *parts[256]; int np = 0;
    char tmp[4096]; snprintf(tmp, sizeof tmp, "%s", path);
    int ab = (tmp[0] == '/'); char *s = tmp; if (ab) s++;
    while (*s && np < 256) {
        char *sl = strchr(s, '/'); if (sl) *sl = 0;
        if (strcmp(s, "..") == 0) { if (np > 0) np--; }
        else if (strcmp(s, ".") != 0 && *s) parts[np++] = s;
        if (sl) s = sl + 1; else break;
    }
    char out[4096]; int p = 0;
    if (ab && p < (int)sizeof(out) - 1) out[p++] = '/';
    for (int i = 0; i < np; i++) {
        if (i > 0 && p < (int)sizeof(out) - 1) out[p++] = '/';
        int l = (int)strlen(parts[i]);
        if (p + l >= (int)sizeof(out)) l = (int)sizeof(out) - p - 1;
        memcpy(out + p, parts[i], (size_t)l); p += l;
    }
    out[p] = 0;
    snprintf(path, maxlen, "%s", out);
}

static char *resolve_path_dup(const char *raw, const char *cwd) {
    char out[8192];
    if (!raw || !raw[0]) return xstrdup("");
    if (raw[0] != '/' && raw[0] != '.' && strchr(raw, ':')) return xstrdup(raw);
    if (raw[0] == '/') snprintf(out, sizeof out, "%s", raw);
    else if (cwd && cwd[0]) snprintf(out, sizeof out, "%s/%s", cwd, raw);
    else snprintf(out, sizeof out, "%s", raw);
    if (out[0] == '/') canon_path_c(out, sizeof out);
    return xstrdup(out);
}

static int strset_contains(const strset_t *set, const char *s) {
    for (int i = 0; i < set->count; i++) if (strcmp(set->items[i], s) == 0) return 1;
    return 0;
}

static void strset_add(strset_t *set, const char *s) {
    if (!s || !s[0] || strset_contains(set, s)) return;
    GROW(set->items, set->count, set->cap);
    set->items[set->count++] = xstrdup(s);
}

static void strset_remove(strset_t *set, const char *s) {
    if (!s || !s[0]) return;
    for (int i = 0; i < set->count; i++) {
        if (strcmp(set->items[i], s) == 0) {
            free(set->items[i]);
            memmove(&set->items[i], &set->items[i + 1], (size_t)(set->count - i - 1) * sizeof(set->items[0]));
            set->count--;
            return;
        }
    }
}

static void strset_clear(strset_t *set) {
    for (int i = 0; i < set->count; i++) free(set->items[i]);
    free(set->items);
    memset(set, 0, sizeof *set);
}

static void free_view(view_t *v) {
    for (int i = 0; i < v->count; i++) {
        free(v->rows[i].id);
        free(v->rows[i].style);
        free(v->rows[i].text);
        free(v->rows[i].parent_id);
        free(v->rows[i].link_id);
    }
    free(v->rows);
    memset(v, 0, sizeof *v);
}

static view_row_t *view_add_row(view_t *v, const char *id, const char *style, const char *parent_id,
                                const char *text, int link_mode, const char *link_id, int has_children) {
    GROW(v->rows, v->count, v->cap);
    view_row_t *r = &v->rows[v->count++];
    r->id = xstrdup(id ? id : "");
    r->style = xstrdup(style ? style : "normal");
    r->text = xstrdup(text ? text : "");
    r->parent_id = xstrdup(parent_id ? parent_id : "");
    r->link_mode = link_mode;
    r->link_id = xstrdup(link_id ? link_id : "");
    r->has_children = has_children;
    return r;
}

static view_row_t *view_find_row(view_t *v, const char *id) {
    if (!id) return NULL;
    for (int i = 0; i < v->count; i++) if (strcmp(v->rows[i].id, id) == 0) return &v->rows[i];
    return NULL;
}

static int view_find_index(const view_t *v, const char *id) {
    if (!id || !id[0]) return -1;
    for (int i = 0; i < v->count; i++) if (strcmp(v->rows[i].id, id) == 0) return i;
    return -1;
}

static process_t *find_process(int tgid) {
    for (int i = 0; i < g_nprocs; i++) if (g_processes[i].tgid == tgid) return &g_processes[i];
    return NULL;
}

static int process_index(int tgid) {
    for (int i = 0; i < g_nprocs; i++) if (g_processes[i].tgid == tgid) return i;
    return -1;
}

static process_t *get_process(int tgid) {
    process_t *p = find_process(tgid);
    if (p) return p;
    GROW(g_processes, g_nprocs, g_cap_procs);
    p = &g_processes[g_nprocs++];
    memset(p, 0, sizeof *p);
    p->tgid = tgid;
    p->parent_index = -1;
    return p;
}

static int string_in_list(char **arr, int n, const char *s) {
    for (int i = 0; i < n; i++) if (strcmp(arr[i], s) == 0) return 1;
    return 0;
}

static void proc_add_path(char ***arr, int *n, int *cap, const char *path) {
    if (!path || !path[0] || string_in_list(*arr, *n, path)) return;
    GROW(*arr, *n, *cap);
    (*arr)[(*n)++] = xstrdup(path);
}

static void append_raw_trace(const char *line) {
    GROW(g_raw_trace_lines, g_nraw, g_cap_raw);
    g_raw_trace_lines[g_nraw++] = xstrdup(line);
}

static trace_event_t *append_event(void) {
    GROW(g_events, g_nevents, g_cap_events);
    trace_event_t *ev = &g_events[g_nevents++];
    memset(ev, 0, sizeof *ev);
    ev->id = g_next_event_id++;
    ev->fd = -1;
    ev->err = 0;
    return ev;
}

static int parse_key_name(const char *n) {
    if (strcmp(n, "up") == 0) return TUI_K_UP;
    if (strcmp(n, "down") == 0) return TUI_K_DOWN;
    if (strcmp(n, "left") == 0) return TUI_K_LEFT;
    if (strcmp(n, "right") == 0) return TUI_K_RIGHT;
    if (strcmp(n, "pgup") == 0) return TUI_K_PGUP;
    if (strcmp(n, "pgdn") == 0) return TUI_K_PGDN;
    if (strcmp(n, "home") == 0) return TUI_K_HOME;
    if (strcmp(n, "end") == 0) return TUI_K_END;
    if (strcmp(n, "tab") == 0) return TUI_K_TAB;
    if (strcmp(n, "enter") == 0) return TUI_K_ENTER;
    if (strcmp(n, "esc") == 0) return TUI_K_ESC;
    if (strlen(n) == 1) return (unsigned char)n[0];
    return TUI_K_NONE;
}

static int has_flag(const char *flags, const char *flag) {
    return flags && strstr(flags, flag) != NULL;
}

static int is_write_open(const trace_event_t *ev) {
    return ev->kind == EV_OPEN && ev->flags_text &&
        (has_flag(ev->flags_text, "O_WRONLY") || has_flag(ev->flags_text, "O_RDWR") ||
         has_flag(ev->flags_text, "O_CREAT") || has_flag(ev->flags_text, "O_TRUNC"));
}

static int is_read_open(const trace_event_t *ev) {
    return ev->kind == EV_OPEN && ev->flags_text &&
        (has_flag(ev->flags_text, "O_RDONLY") || has_flag(ev->flags_text, "O_RDWR"));
}

static char *join_with_pipe(char **arr, int n) {
    if (n <= 0) return xstrdup("");
    size_t total = 1;
    for (int i = 0; i < n; i++) total += strlen(arr[i]) + 1;
    char *out = xmalloc(total);
    out[0] = 0;
    for (int i = 0; i < n; i++) {
        if (i) strcat(out, "|");
        strcat(out, arr[i]);
    }
    return out;
}

static void ingest_input_line(const char *line) {
    span_t sp;
    char *kind = NULL;
    if (!json_obj_get(line, "input", &sp)) return;
    kind = json_decode_string(sp);
    if (!kind) return;
    GROW(g_inputs, g_ninputs, g_cap_inputs);
    input_cmd_t *cmd = &g_inputs[g_ninputs++];
    memset(cmd, 0, sizeof *cmd);
    if (strcmp(kind, "key") == 0) {
        char *name = NULL;
        cmd->kind = INPUT_KEY;
        if (json_obj_get(line, "key", &sp)) name = json_decode_string(sp);
        cmd->key = name ? parse_key_name(name) : TUI_K_NONE;
        free(name);
    } else if (strcmp(kind, "resize") == 0) {
        cmd->kind = INPUT_RESIZE;
        if (json_obj_get(line, "rows", &sp)) cmd->rows = span_to_int(sp, 0);
        if (json_obj_get(line, "cols", &sp)) cmd->cols = span_to_int(sp, 0);
    } else if (strcmp(kind, "select") == 0) {
        cmd->kind = INPUT_SELECT;
        if (json_obj_get(line, "id", &sp)) cmd->text = json_decode_string(sp);
    } else if (strcmp(kind, "search") == 0) {
        cmd->kind = INPUT_SEARCH;
        if (json_obj_get(line, "q", &sp)) cmd->text = json_decode_string(sp);
    } else if (strcmp(kind, "evfilt") == 0) {
        cmd->kind = INPUT_EVFILT;
        if (json_obj_get(line, "q", &sp)) cmd->text = json_decode_string(sp);
    } else if (strcmp(kind, "print") == 0) {
        cmd->kind = INPUT_PRINT;
        if (json_obj_get(line, "what", &sp)) cmd->text = json_decode_string(sp);
    } else {
        g_ninputs--;
    }
    free(kind);
}

static void ingest_trace_line(const char *line) {
    span_t sp;
    char *kind = NULL;
    trace_event_t *ev;
    process_t *proc;

    if (!json_obj_get(line, "event", &sp)) return;
    kind = json_decode_string(sp);
    if (!kind) return;
    append_raw_trace(line);
    ev = append_event();
    if (strcmp(kind, "CWD") == 0) ev->kind = EV_CWD;
    else if (strcmp(kind, "EXEC") == 0) ev->kind = EV_EXEC;
    else if (strcmp(kind, "OPEN") == 0) ev->kind = EV_OPEN;
    else if (strcmp(kind, "EXIT") == 0) ev->kind = EV_EXIT;
    else if (strcmp(kind, "STDOUT") == 0) ev->kind = EV_STDOUT;
    else if (strcmp(kind, "STDERR") == 0) ev->kind = EV_STDERR;
    else { free(kind); g_nevents--; g_next_event_id--; free(ev); return; }
    free(kind);

    if (json_obj_get(line, "ts", &sp)) ev->ts = span_to_double(sp, 0.0);
    if (json_obj_get(line, "pid", &sp)) ev->pid = span_to_int(sp, 0);
    if (json_obj_get(line, "tgid", &sp)) ev->tgid = span_to_int(sp, 0);
    if (json_obj_get(line, "ppid", &sp)) ev->ppid = span_to_int(sp, 0);
    if (json_obj_get(line, "nspid", &sp)) ev->nspid = span_to_int(sp, 0);
    if (json_obj_get(line, "nstgid", &sp)) ev->nstgid = span_to_int(sp, 0);
    if (g_base_ts == 0.0 || ev->ts < g_base_ts) g_base_ts = ev->ts;

    proc = get_process(ev->tgid);
    if (!proc->has_start || ev->ts < proc->start_ts) { proc->start_ts = ev->ts; proc->has_start = 1; }
    if (!proc->has_end || ev->ts > proc->end_ts) { proc->end_ts = ev->ts; proc->has_end = 1; }
    proc->pid = ev->pid;
    proc->ppid = ev->ppid;
    proc->nspid = ev->nspid;
    proc->nstgid = ev->nstgid;

    switch (ev->kind) {
    case EV_CWD:
        if (json_obj_get(line, "path", &sp)) ev->path = json_decode_string(sp);
        free(proc->cwd);
        proc->cwd = xstrdup(ev->path ? ev->path : "");
        break;
    case EV_EXEC:
        if (json_obj_get(line, "exe", &sp)) ev->exe = json_decode_string(sp);
        if (json_obj_get(line, "argv", &sp)) ev->argv = json_array_of_strings(sp, &ev->argc);
        free(proc->exe);
        proc->exe = xstrdup(ev->exe ? ev->exe : "");
        free_string_array(proc->argv, proc->argc);
        proc->argc = ev->argc;
        if (proc->argc > 0) {
            proc->argv = xmalloc((size_t)proc->argc * sizeof(proc->argv[0]));
            for (int i = 0; i < proc->argc; i++) proc->argv[i] = xstrdup(ev->argv[i]);
        } else {
            proc->argv = NULL;
        }
        break;
    case EV_OPEN: {
        char **flags = NULL;
        int nfl = 0;
        if (json_obj_get(line, "path", &sp) && *sp.s != 'n') ev->path = json_decode_string(sp);
        if (json_obj_get(line, "flags", &sp)) flags = json_array_of_strings(sp, &nfl);
        ev->flags_text = join_with_pipe(flags, nfl);
        if (json_obj_get(line, "fd", &sp)) ev->fd = span_to_int(sp, -1);
        if (json_obj_get(line, "err", &sp)) ev->err = span_to_int(sp, 0);
        if (json_obj_get(line, "inherited", &sp)) ev->inherited = span_to_bool(sp, 0);
        ev->resolved_path = resolve_path_dup(ev->path, proc->cwd);
        if (is_write_open(ev)) proc->has_write_open = 1;
        if (ev->resolved_path && ev->resolved_path[0]) {
            if (is_read_open(ev)) proc_add_path(&proc->read_paths, &proc->nreads, &proc->capreads, ev->resolved_path);
            if (is_write_open(ev)) proc_add_path(&proc->write_paths, &proc->nwrites, &proc->capwrites, ev->resolved_path);
        }
        free_string_array(flags, nfl);
        break;
    }
    case EV_EXIT:
        if (json_obj_get(line, "status", &sp)) ev->status = json_decode_string(sp);
        if (json_obj_get(line, "code", &sp)) ev->code = span_to_int(sp, 0);
        if (json_obj_get(line, "signal", &sp)) ev->signal = span_to_int(sp, 0);
        if (json_obj_get(line, "core_dumped", &sp)) ev->core_dumped = span_to_bool(sp, 0);
        if (json_obj_get(line, "raw", &sp)) ev->raw = span_to_int(sp, 0);
        free(proc->exit_status);
        proc->exit_status = xstrdup(ev->status ? ev->status : "");
        proc->exit_code = ev->code;
        proc->exit_signal = ev->signal;
        proc->core_dumped = ev->core_dumped;
        proc->exit_raw = ev->raw;
        proc->end_ts = ev->ts;
        proc->has_end = 1;
        break;
    case EV_STDOUT:
    case EV_STDERR:
        if (json_obj_get(line, "data", &sp)) ev->data = json_decode_string(sp);
        if (json_obj_get(line, "len", &sp)) ev->len = span_to_int(sp, 0);
        if (ev->kind == EV_STDOUT) proc->has_stdout = 1;
        else proc->has_stderr = 1;
        break;
    }
}

static void ingest_line(const char *line) {
    span_t sp;
    if (!line || !line[0] || line[0] != '{') return;
    if (json_obj_get(line, "input", &sp)) ingest_input_line(line);
    else ingest_trace_line(line);
}

static int path_has_suffix(const char *path, const char *suffix) {
    size_t n = strlen(path), m = strlen(suffix);
    return n >= m && strcmp(path + n - m, suffix) == 0;
}

static void ingest_zstd_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "tv: cannot open %s\n", path); exit(1); }
    size_t in_cap = ZSTD_DStreamInSize(), out_cap = ZSTD_DStreamOutSize();
    unsigned char *in_buf = xmalloc(in_cap), *out_buf = xmalloc(out_cap);
    char *line = xmalloc(MAX_JSON_LINE);
    ZSTD_DStream *stream = ZSTD_createDStream();
    size_t line_len = 0, line_cap = MAX_JSON_LINE;
    if (ZSTD_isError(ZSTD_initDStream(stream))) { fprintf(stderr, "tv: zstd init failed for %s\n", path); exit(1); }
    for (;;) {
        size_t nread = fread(in_buf, 1, in_cap, f);
        ZSTD_inBuffer input = { in_buf, nread, 0 };
        while (input.pos < input.size) {
            ZSTD_outBuffer output = { out_buf, out_cap, 0 };
            size_t rc = ZSTD_decompressStream(stream, &output, &input);
            if (ZSTD_isError(rc)) { fprintf(stderr, "tv: zstd decompress failed for %s: %s\n", path, ZSTD_getErrorName(rc)); exit(1); }
            size_t pos = 0;
            while (pos < output.pos) {
                unsigned char *nl = memchr(out_buf + pos, '\n', output.pos - pos);
                size_t chunk = nl ? (size_t)(nl - (out_buf + pos)) : (output.pos - pos);
                if (line_len + chunk + 1 > line_cap) {
                    while (line_len + chunk + 1 > line_cap) line_cap *= 2;
                    line = xrealloc(line, line_cap);
                }
                memcpy(line + line_len, out_buf + pos, chunk);
                line_len += chunk;
                pos += chunk;
                if (nl) {
                    if (line_len > 0 && line[line_len - 1] == '\r') line_len--;
                    line[line_len] = 0;
                    ingest_line(line);
                    line_len = 0;
                    pos++;
                }
            }
        }
        if (nread == 0) break;
    }
    if (line_len > 0) {
        if (line[line_len - 1] == '\r') line_len--;
        line[line_len] = 0;
        ingest_line(line);
    }
    ZSTD_freeDStream(stream);
    free(line);
    free(in_buf);
    free(out_buf);
    fclose(f);
}

static void ingest_file(const char *path) {
    if (path_has_suffix(path, ".zst")) { ingest_zstd_file(path); return; }
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "tv: cannot open %s\n", path); exit(1); }
    char line[MAX_JSON_LINE];
    while (fgets(line, sizeof line, f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (nl && nl > line && nl[-1] == '\r') nl[-1] = 0;
        ingest_line(line);
    }
    fclose(f);
}

static int cmp_child_index(const void *a, const void *b) {
    const int ia = *(const int *)a, ib = *(const int *)b;
    const process_t *pa = &g_processes[ia], *pb = &g_processes[ib];
    if (g_state.sort_key == 1) {
        if (pa->start_ts < pb->start_ts) return -1;
        if (pa->start_ts > pb->start_ts) return 1;
    } else if (g_state.sort_key == 2) {
        if (pa->end_ts < pb->end_ts) return -1;
        if (pa->end_ts > pb->end_ts) return 1;
    }
    return pa->tgid - pb->tgid;
}

static int compute_descendants(int idx) {
    process_t *p = &g_processes[idx];
    int total = 0;
    for (int i = 0; i < p->nchildren; i++) total += 1 + compute_descendants(p->children[i]);
    p->descendant_count = total;
    return total;
}

static void finalize_process_tree(void) {
    for (int i = 0; i < g_nprocs; i++) {
        process_t *p = &g_processes[i];
        p->parent_index = process_index(p->ppid);
    }
    for (int i = 0; i < g_nprocs; i++) {
        process_t *p = &g_processes[i];
        if (p->parent_index >= 0) {
            process_t *par = &g_processes[p->parent_index];
            GROW(par->children, par->nchildren, par->capchildren);
            par->children[par->nchildren++] = i;
        }
    }
    for (int i = 0; i < g_nprocs; i++) {
        process_t *p = &g_processes[i];
        if (p->nchildren > 1) qsort(p->children, (size_t)p->nchildren, sizeof(p->children[0]), cmp_child_index);
    }
    for (int i = 0; i < g_nprocs; i++) if (g_processes[i].parent_index < 0) compute_descendants(i);
}

static int proc_matches_search(const process_t *p) {
    char pidbuf[32];
    if (!g_state.search[0]) return 0;
    snprintf(pidbuf, sizeof pidbuf, "%d", p->tgid);
    if (strstr(pidbuf, g_state.search)) return 1;
    if (p->exe && strstr(p->exe, g_state.search)) return 1;
    for (int i = 0; i < p->argc; i++) if (strstr(p->argv[i], g_state.search)) return 1;
    for (int i = 0; i < g_nevents; i++) {
        const trace_event_t *ev = &g_events[i];
        if (ev->tgid != p->tgid) continue;
        if ((ev->kind == EV_STDOUT || ev->kind == EV_STDERR) && ev->data && strstr(ev->data, g_state.search)) return 1;
    }
    return 0;
}

static int proc_is_interesting_failure(const process_t *p) {
    if (!p->exit_status || !p->exit_status[0]) return 0;
    if (strcmp(p->exit_status, "signaled") == 0) return 1;
    if (strcmp(p->exit_status, "exited") == 0 && p->exit_code != 0)
        return p->has_write_open || p->nchildren > 0 || p->has_stdout;
    return 0;
}

static int proc_matches_filter(const process_t *p) {
    if (g_state.lp_filter == 1) return proc_is_interesting_failure(p);
    if (g_state.lp_filter == 2) return !p->exit_status || !p->exit_status[0];
    return 1;
}

static int proc_should_show(int idx) {
    process_t *p = &g_processes[idx];
    if (g_state.lp_filter == 0) return 1;
    if (proc_matches_filter(p)) return 1;
    for (int i = 0; i < p->nchildren; i++) if (proc_should_show(p->children[i])) return 1;
    return 0;
}

static char *format_duration(double s, double e, int running) {
    double d = running ? 0.0 : (e - s);
    if (running) return xstrdup("");
    if (d >= 1.0) return fmtdup("%.2fs", d);
    return fmtdup("%.1fms", d * 1000.0);
}

static const char *proc_style(const process_t *p) {
    if (proc_matches_search(p)) return "search";
    if (proc_is_interesting_failure(p)) return "error";
    return "normal";
}

static void build_proc_rows_rec(int idx, int depth) {
    process_t *p = &g_processes[idx];
    int collapsed = strset_contains(&g_proc_collapsed, fmtdup("%d", p->tgid));
    char *id = fmtdup("%d", p->tgid);
    const char *name = basename_c(p->exe && p->exe[0] ? p->exe : (p->argc > 0 ? p->argv[0] : ""));
    char *marker = xstrdup("");
    if (p->exit_status && strcmp(p->exit_status, "exited") == 0)
        marker = xstrdup(p->exit_code == 0 ? " ✓" : " ✗");
    else if (p->exit_status && strcmp(p->exit_status, "signaled") == 0)
        marker = fmtdup(" ⚡%d", p->exit_signal);
    char *dur = format_duration(p->start_ts, p->end_ts, !(p->exit_status && p->exit_status[0]));
    char *prefix = g_state.grouped ? fmtdup("%*s%s", depth * 4, "", p->nchildren ? (collapsed ? "▶ " : "▼ ") : "  ") : xstrdup("");
    char *extra = p->descendant_count > 0 ? fmtdup(" (%d)", p->descendant_count) : xstrdup("");
    char *text = fmtdup("%s[%d] %s%s%s%s%s%s", prefix, p->tgid, name, marker, extra, dur[0] ? "  " : "", dur, "");
    view_add_row(&g_lpane, id, proc_style(p), p->parent_index >= 0 ? fmtdup("%d", g_processes[p->parent_index].tgid) : "", text, 0, id, p->nchildren > 0);
    free(id); free(marker); free(dur); free(prefix); free(extra); free(text);
    if (g_state.grouped && collapsed) return;
    for (int i = 0; i < p->nchildren; i++) if (proc_should_show(p->children[i])) build_proc_rows_rec(p->children[i], g_state.grouped ? depth + 1 : 0);
}

static int cmp_proc_flat(const void *a, const void *b) {
    int ia = *(const int *)a, ib = *(const int *)b;
    return cmp_child_index(&ia, &ib);
}

static void build_lpane_process(void) {
    int *roots = NULL, nroots = 0, caproots = 0;
    for (int i = 0; i < g_nprocs; i++) if (g_processes[i].parent_index < 0 && proc_should_show(i)) { GROW(roots, nroots, caproots); roots[nroots++] = i; }
    if (nroots > 1) qsort(roots, (size_t)nroots, sizeof(roots[0]), cmp_child_index);
    if (g_state.grouped) {
        for (int i = 0; i < nroots; i++) build_proc_rows_rec(roots[i], 0);
    } else {
        int *all = NULL, nall = 0, capall = 0;
        for (int i = 0; i < g_nprocs; i++) if (proc_should_show(i)) { GROW(all, nall, capall); all[nall++] = i; }
        if (nall > 1) qsort(all, (size_t)nall, sizeof(all[0]), cmp_proc_flat);
        for (int i = 0; i < nall; i++) {
            process_t *p = &g_processes[all[i]];
            char *id = fmtdup("%d", p->tgid);
            const char *name = basename_c(p->exe && p->exe[0] ? p->exe : (p->argc > 0 ? p->argv[0] : ""));
            char *marker = xstrdup("");
            if (p->exit_status && strcmp(p->exit_status, "exited") == 0)
                marker = xstrdup(p->exit_code == 0 ? " ✓" : " ✗");
            else if (p->exit_status && strcmp(p->exit_status, "signaled") == 0)
                marker = fmtdup(" ⚡%d", p->exit_signal);
            char *dur = format_duration(p->start_ts, p->end_ts, !(p->exit_status && p->exit_status[0]));
            char *text = fmtdup("[%d] %s%s%s%s", p->tgid, name, marker, dur[0] ? "  " : "", dur);
            view_add_row(&g_lpane, id, proc_style(p), "", text, 0, id, 0);
            free(id); free(marker); free(dur); free(text);
        }
        free(all);
    }
    free(roots);
}

static file_stat_t *build_file_stats(int *count_out) {
    file_stat_t *fs = NULL;
    int n = 0, cap = 0;
    for (int i = 0; i < g_nevents; i++) {
        const trace_event_t *ev = &g_events[i];
        if (ev->kind != EV_OPEN || !ev->resolved_path || !ev->resolved_path[0]) continue;
        int j;
        for (j = 0; j < n; j++) if (strcmp(fs[j].path, ev->resolved_path) == 0) break;
        if (j == n) {
            GROW(fs, n, cap);
            fs[n].path = xstrdup(ev->resolved_path);
            fs[n].opens = fs[n].procs = fs[n].errs = 0;
            n++;
        }
        fs[j].opens++;
        if (ev->err) fs[j].errs++;
    }
    for (int i = 0; i < n; i++) {
        int *tgids = NULL, nt = 0, capt = 0;
        for (int j = 0; j < g_nevents; j++) {
            const trace_event_t *ev = &g_events[j];
            if (ev->kind != EV_OPEN || !ev->resolved_path || strcmp(ev->resolved_path, fs[i].path) != 0) continue;
            int seen = 0;
            for (int k = 0; k < nt; k++) if (tgids[k] == ev->tgid) { seen = 1; break; }
            if (!seen) { GROW(tgids, nt, capt); tgids[nt++] = ev->tgid; }
        }
        fs[i].procs = nt;
        free(tgids);
    }
    *count_out = n;
    return fs;
}

static const char *path_leaf(const char *path) {
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

static int file_matches_search(const char *path) {
    return g_state.search[0] && strstr(path, g_state.search) != NULL;
}

static void free_file_stats(file_stat_t *fs, int n) {
    for (int i = 0; i < n; i++) free(fs[i].path);
    free(fs);
}

static dir_stat_t *build_dir_stats(file_stat_t *fs, int nfs, int *count_out) {
    dir_stat_t *dirs = NULL;
    int n = 0, cap = 0;
    for (int i = 0; i < nfs; i++) {
        if (fs[i].path[0] != '/') continue;
        char *tmp = xstrdup(fs[i].path);
        for (char *p = strchr(tmp + 1, '/'); p; p = strchr(p + 1, '/')) {
            *p = 0;
            int j;
            for (j = 0; j < n; j++) if (strcmp(dirs[j].path, tmp) == 0) break;
            if (j == n) {
                GROW(dirs, n, cap);
                dirs[n].path = xstrdup(tmp);
                char *slash = strrchr(tmp, '/');
                dirs[n].parent = (!slash || slash == tmp) ? xstrdup("/") : xstrndup(tmp, (size_t)(slash - tmp));
                if (strcmp(dirs[n].path, "/") == 0) { free(dirs[n].parent); dirs[n].parent = xstrdup(""); }
                dirs[n].name = xstrdup(path_leaf(tmp));
                dirs[n].opens = dirs[n].procs = dirs[n].errs = dirs[n].has_children = 0;
                n++;
            }
            *p = '/';
        }
        free(tmp);
    }
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < nfs; j++) {
            size_t m = strlen(dirs[i].path);
            if (strncmp(fs[j].path, dirs[i].path, m) == 0 && (fs[j].path[m] == '/' || (m == 1 && fs[j].path[0] == '/'))) {
                dirs[i].opens += fs[j].opens;
                dirs[i].procs += fs[j].procs;
                dirs[i].errs += fs[j].errs;
            }
        }
        for (int j = 0; j < n; j++) if (strcmp(dirs[j].parent, dirs[i].path) == 0) dirs[i].has_children = 1;
        for (int j = 0; j < nfs; j++) {
            const char *parent = strrchr(fs[j].path, '/');
            if (!parent) continue;
            if ((size_t)(parent - fs[j].path) == strlen(dirs[i].path) && strncmp(fs[j].path, dirs[i].path, strlen(dirs[i].path)) == 0)
                dirs[i].has_children = 1;
        }
    }
    *count_out = n;
    return dirs;
}

static void free_dir_stats(dir_stat_t *dirs, int n) {
    for (int i = 0; i < n; i++) { free(dirs[i].path); free(dirs[i].parent); free(dirs[i].name); }
    free(dirs);
}

static int cmp_strings(const void *a, const void *b) {
    const char * const *sa = a, * const *sb = b;
    return strcmp(*sa, *sb);
}

static void add_file_tree_rec(const char *dir, dir_stat_t *dirs, int ndirs, file_stat_t *fs, int nfs, int depth) {
    char **children_dirs = NULL, **children_files = NULL;
    int nd = 0, capd = 0, nf = 0, capf = 0;
    for (int i = 0; i < ndirs; i++) if (strcmp(dirs[i].parent, dir) == 0) { GROW(children_dirs, nd, capd); children_dirs[nd++] = dirs[i].path; }
    for (int i = 0; i < nfs; i++) {
        const char *parent = strrchr(fs[i].path, '/');
        char buf[4096];
        if (!parent) continue;
        if (parent == fs[i].path) strcpy(buf, "/");
        else { size_t m = (size_t)(parent - fs[i].path); memcpy(buf, fs[i].path, m); buf[m] = 0; }
        if (strcmp(buf, dir) == 0) { GROW(children_files, nf, capf); children_files[nf++] = fs[i].path; }
    }
    if (nd > 1) qsort(children_dirs, (size_t)nd, sizeof(children_dirs[0]), cmp_strings);
    if (nf > 1) qsort(children_files, (size_t)nf, sizeof(children_files[0]), cmp_strings);
    for (int i = 0; i < nd; i++) {
        dir_stat_t *d = NULL;
        for (int j = 0; j < ndirs; j++) if (strcmp(dirs[j].path, children_dirs[i]) == 0) { d = &dirs[j]; break; }
        if (!d) continue;
        int collapsed = strset_contains(&g_file_collapsed, d->path);
        char *text = fmtdup("%*s%s%s/  [%d opens, %d procs%s]", depth * 2, "", collapsed ? "▶ " : "▼ ", d->name,
                            d->opens, d->procs, d->errs ? fmtdup(", %d errs", d->errs) : "");
        view_add_row(&g_lpane, d->path, file_matches_search(d->path) ? "search" : (d->errs ? "error" : "normal"), d->parent, text, 1, d->path, 1);
        free(text);
        if (!collapsed) add_file_tree_rec(d->path, dirs, ndirs, fs, nfs, depth + 1);
    }
    for (int i = 0; i < nf; i++) {
        file_stat_t *f = NULL;
        for (int j = 0; j < nfs; j++) if (strcmp(fs[j].path, children_files[i]) == 0) { f = &fs[j]; break; }
        if (!f) continue;
        char *text = fmtdup("%*s%s  [%d opens, %d procs%s]", depth * 2, "", f->path[0] == '/' ? path_leaf(f->path) : f->path,
                            f->opens, f->procs, f->errs ? fmtdup(", %d errs", f->errs) : "");
        char parent[4096] = "";
        const char *slash = strrchr(f->path, '/');
        if (slash) {
            if (slash == f->path) strcpy(parent, "/");
            else { size_t m = (size_t)(slash - f->path); memcpy(parent, f->path, m); parent[m] = 0; }
        }
        view_add_row(&g_lpane, f->path, file_matches_search(f->path) ? "search" : (f->errs ? "error" : "normal"), parent, text, 1, f->path, 0);
        free(text);
    }
    free(children_dirs);
    free(children_files);
}

static void build_lpane_files(void) {
    int nfs = 0, ndirs = 0;
    file_stat_t *fs = build_file_stats(&nfs);
    if (!g_state.grouped) {
        char **paths = NULL; int n = 0, cap = 0;
        for (int i = 0; i < nfs; i++) { GROW(paths, n, cap); paths[n++] = fs[i].path; }
        if (n > 1) qsort(paths, (size_t)n, sizeof(paths[0]), cmp_strings);
        for (int i = 0; i < n; i++) {
            file_stat_t *f = NULL;
            for (int j = 0; j < nfs; j++) if (strcmp(fs[j].path, paths[i]) == 0) { f = &fs[j]; break; }
            if (!f) continue;
            char *text = fmtdup("%s  [%d opens, %d procs%s]", f->path, f->opens, f->procs, f->errs ? fmtdup(", %d errs", f->errs) : "");
            view_add_row(&g_lpane, f->path, file_matches_search(f->path) ? "search" : (f->errs ? "error" : "normal"), "", text, 1, f->path, 0);
            free(text);
        }
        free(paths);
    } else {
        dir_stat_t *dirs = build_dir_stats(fs, nfs, &ndirs);
        add_file_tree_rec("/", dirs, ndirs, fs, nfs, 0);
        for (int i = 0; i < nfs; i++) {
            if (fs[i].path[0] == '/') continue;
            char *text = fmtdup("  %s  [%d opens, %d procs%s]", fs[i].path, fs[i].opens, fs[i].procs, fs[i].errs ? fmtdup(", %d errs", fs[i].errs) : "");
            view_add_row(&g_lpane, fs[i].path, file_matches_search(fs[i].path) ? "search" : (fs[i].errs ? "error" : "normal"), "", text, 1, fs[i].path, 0);
            free(text);
        }
        free_dir_stats(dirs, ndirs);
    }
    free_file_stats(fs, nfs);
}

static output_group_t *build_output_groups(int *count_out) {
    output_group_t *groups = NULL;
    int n = 0, cap = 0;
    for (int i = 0; i < g_nevents; i++) {
        trace_event_t *ev = &g_events[i];
        if (ev->kind != EV_STDOUT && ev->kind != EV_STDERR) continue;
        int j;
        for (j = 0; j < n; j++) if (groups[j].tgid == ev->tgid) break;
        if (j == n) {
            GROW(groups, n, cap);
            groups[n].tgid = ev->tgid;
            groups[n].name = xstrdup("");
            groups[n].events = NULL; groups[n].count = groups[n].cap = 0;
            process_t *p = find_process(ev->tgid);
            free(groups[n].name);
            groups[n].name = xstrdup(p ? basename_c(p->exe && p->exe[0] ? p->exe : (p->argc ? p->argv[0] : "")) : "");
            n++;
        }
        GROW(groups[j].events, groups[j].count, groups[j].cap);
        groups[j].events[groups[j].count++] = ev;
    }
    *count_out = n;
    return groups;
}

static void free_output_groups(output_group_t *groups, int n) {
    for (int i = 0; i < n; i++) { free(groups[i].name); free(groups[i].events); }
    free(groups);
}

static void build_lpane_output(void) {
    int ng = 0;
    output_group_t *groups = build_output_groups(&ng);
    if (!g_state.grouped) {
        for (int i = 0; i < g_nevents; i++) {
            trace_event_t *ev = &g_events[i];
            if (ev->kind != EV_STDOUT && ev->kind != EV_STDERR) continue;
            process_t *p = find_process(ev->tgid);
            char *id = fmtdup("%d", ev->id);
            char *text = fmtdup("[%s] PID %d %s: %s", ev->kind == EV_STDOUT ? "STDOUT" : "STDERR", ev->tgid,
                                p ? basename_c(p->exe && p->exe[0] ? p->exe : (p->argc ? p->argv[0] : "")) : "",
                                ev->data ? ev->data : "");
            view_add_row(&g_lpane, id, ev->kind == EV_STDERR ? "error" : "normal", "", text, 2, id, 0);
            free(id); free(text);
        }
    } else {
        for (int i = 0; i < ng; i++) {
            char *gid = fmtdup("io_%d", groups[i].tgid);
            int collapsed = strset_contains(&g_output_collapsed, gid);
            char *text = fmtdup("%sPID %d %s", collapsed ? "▶ " : "▼ ", groups[i].tgid, groups[i].name);
            view_add_row(&g_lpane, gid, "heading", "", text, 2, gid, 1);
            if (!collapsed) {
                for (int j = 0; j < groups[i].count; j++) {
                    trace_event_t *ev = groups[i].events[j];
                    char *id = fmtdup("%d", ev->id);
                    char *row = fmtdup("  [%s] %s", ev->kind == EV_STDOUT ? "STDOUT" : "STDERR", ev->data ? ev->data : "");
                    view_add_row(&g_lpane, id, ev->kind == EV_STDERR ? "error" : "normal", gid, row, 2, id, 0);
                    free(id); free(row);
                }
            }
            free(gid); free(text);
        }
    }
    free_output_groups(groups, ng);
}

static file_edge_t *build_file_edges(int *count_out) {
    file_edge_t *edges = NULL;
    int n = 0, cap = 0;
    for (int i = 0; i < g_nprocs; i++) {
        process_t *p = &g_processes[i];
        for (int r = 0; r < p->nreads; r++) for (int w = 0; w < p->nwrites; w++) {
            int seen = 0;
            for (int k = 0; k < n; k++) if (strcmp(edges[k].src, p->read_paths[r]) == 0 && strcmp(edges[k].dst, p->write_paths[w]) == 0) { seen = 1; break; }
            if (!seen) {
                GROW(edges, n, cap);
                edges[n].src = xstrdup(p->read_paths[r]);
                edges[n].dst = xstrdup(p->write_paths[w]);
                n++;
            }
        }
    }
    *count_out = n;
    return edges;
}

static void free_file_edges(file_edge_t *edges, int n) {
    for (int i = 0; i < n; i++) { free(edges[i].src); free(edges[i].dst); }
    free(edges);
}

static void build_lpane_deps(int reverse) {
    const char *start = g_state.cursor_id;
    file_edge_t *edges = NULL;
    int nedge = 0;
    char **queue = NULL, **seen = NULL;
    int qh = 0, qt = 0, qcap = 0, ns = 0, caps = 0;
    if (!start || !start[0]) return;
    edges = build_file_edges(&nedge);
    GROW(queue, qt, qcap); queue[qt++] = xstrdup(start);
    while (qh < qt) {
        char *cur = queue[qh++];
        if (string_in_list(seen, ns, cur)) { free(cur); continue; }
        GROW(seen, ns, caps); seen[ns++] = cur;
        for (int i = 0; i < nedge; i++) {
            const char *next = reverse ? (strcmp(edges[i].dst, cur) == 0 ? edges[i].src : NULL)
                                       : (strcmp(edges[i].src, cur) == 0 ? edges[i].dst : NULL);
            if (next && !string_in_list(seen, ns, next)) { GROW(queue, qt, qcap); queue[qt++] = xstrdup(next); }
        }
    }
    if (ns > 1) qsort(seen, (size_t)ns, sizeof(seen[0]), cmp_strings);
    for (int i = 0; i < ns; i++) {
        int mode = reverse ? 4 : 3;
        view_add_row(&g_lpane, seen[i], file_matches_search(seen[i]) ? "search" : "normal", "", seen[i], mode, seen[i], 0);
        free(seen[i]);
    }
    free(seen);
    for (int i = qh; i < qt; i++) free(queue[i]);
    free(queue);
    free_file_edges(edges, nedge);
}

static int format_ts(char *buf, size_t bufsz, double ts, double prev) {
    if (g_state.ts_mode == 1) snprintf(buf, bufsz, "+%.3fs", ts - g_base_ts);
    else if (g_state.ts_mode == 2) snprintf(buf, bufsz, "Δ%.3fs", prev < 0 ? 0.0 : ts - prev);
    else snprintf(buf, bufsz, "%.3f", ts);
    return 1;
}

static int event_allowed(const trace_event_t *ev) {
    char kind[16];
    if (!g_state.evfilt[0]) return 1;
    switch (ev->kind) {
    case EV_CWD: strcpy(kind, "CWD"); break;
    case EV_EXEC: strcpy(kind, "EXEC"); break;
    case EV_OPEN: strcpy(kind, "OPEN"); break;
    case EV_EXIT: strcpy(kind, "EXIT"); break;
    case EV_STDOUT: strcpy(kind, "STDOUT"); break;
    case EV_STDERR: strcpy(kind, "STDERR"); break;
    default: kind[0] = 0; break;
    }
    return strstr(kind, g_state.evfilt) != NULL;
}

static void build_rpane_process(const char *id) {
    process_t *p = find_process(id ? atoi(id) : 0);
    if (!p) return;
    view_add_row(&g_rpane, "hdr", "heading", "", "─── Process ───", -1, "", 0);
    view_add_row(&g_rpane, "tgid", "normal", "", fmtdup("TGID:  %d", p->tgid), -1, "", 0);
    view_add_row(&g_rpane, "ppid", "normal", "", fmtdup("PPID:  %d", p->ppid), -1, "", 0);
    view_add_row(&g_rpane, "exe", "normal", "", fmtdup("EXE:   %s", p->exe ? p->exe : ""), -1, "", 0);
    if (p->exit_status && p->exit_status[0]) {
        char *text = strcmp(p->exit_status, "signaled") == 0
            ? fmtdup("Exit: signal %d%s", p->exit_signal, p->core_dumped ? " (core)" : "")
            : fmtdup("Exit: exited code=%d", p->exit_code);
        view_add_row(&g_rpane, "exit", strcmp(p->exit_status, "exited") == 0 && p->exit_code == 0 ? "green" : "error", "", text, -1, "", 0);
        free(text);
    }
    if (p->descendant_count > 0) {
        view_add_row(&g_rpane, "kids_hdr", "heading", "", fmtdup("Children (%d)", p->descendant_count), -1, "", 0);
        for (int i = 0; i < p->nchildren; i++) {
            process_t *c = &g_processes[p->children[i]];
            char *cid = fmtdup("child_%d", c->tgid);
            char *text = fmtdup("[%d] %s", c->tgid, basename_c(c->exe && c->exe[0] ? c->exe : (c->argc ? c->argv[0] : "")));
            view_add_row(&g_rpane, cid, "normal", "", text, 0, fmtdup("%d", c->tgid), 0);
            free(cid); free(text);
        }
    }
    if (p->argc > 0) {
        view_add_row(&g_rpane, "argv_hdr", "heading", "", "─── Argv ───", -1, "", 0);
        for (int i = 0; i < p->argc; i++) view_add_row(&g_rpane, fmtdup("argv_%d", i), "normal", "", fmtdup("[%d] %s", i, p->argv[i]), -1, "", 0);
    }
    view_add_row(&g_rpane, "evt_hdr", "heading", "", "─── Events ───", -1, "", 0);
    double prev_ts = -1;
    for (int i = 0; i < g_nevents; i++) {
        trace_event_t *ev = &g_events[i];
        char tsbuf[64];
        char *text = NULL;
        if (ev->tgid != p->tgid || !event_allowed(ev)) continue;
        format_ts(tsbuf, sizeof tsbuf, ev->ts, prev_ts);
        prev_ts = ev->ts;
        switch (ev->kind) {
        case EV_CWD: text = fmtdup("%s [CWD] %s", tsbuf, ev->path ? ev->path : ""); break;
        case EV_EXEC: text = fmtdup("%s [EXEC] %s", tsbuf, ev->exe ? ev->exe : ""); break;
        case EV_OPEN: text = fmtdup("%s [OPEN] %s [%s]%s", tsbuf, ev->resolved_path ? ev->resolved_path : "", ev->flags_text ? ev->flags_text : "", ev->err ? fmtdup(" err=%d", ev->err) : ""); break;
        case EV_EXIT:
            text = strcmp(ev->status ? ev->status : "", "signaled") == 0
                ? fmtdup("%s [EXIT] signal %d%s", tsbuf, ev->signal, ev->core_dumped ? " (core)" : "")
                : fmtdup("%s [EXIT] exited code=%d", tsbuf, ev->code);
            break;
        case EV_STDOUT: text = fmtdup("%s [STDOUT] %s", tsbuf, ev->data ? ev->data : ""); break;
        case EV_STDERR: text = fmtdup("%s [STDERR] %s", tsbuf, ev->data ? ev->data : ""); break;
        }
        view_add_row(&g_rpane, fmtdup("ev_%d", ev->id), ev->kind == EV_STDERR ? "error" : "normal", "", text, -1, "", 0);
        free(text);
    }
}

static void build_rpane_file(const char *id) {
    int opens = 0, errs = 0;
    int *ptgids = NULL, npt = 0, cappt = 0;
    if (!id || !id[0]) return;
    view_add_row(&g_rpane, "hdr", "heading", "", "─── File ───", -1, "", 0);
    view_add_row(&g_rpane, "path", "normal", "", id, -1, "", 0);
    for (int i = 0; i < g_nevents; i++) {
        trace_event_t *ev = &g_events[i];
        if (ev->kind != EV_OPEN || !ev->resolved_path || strcmp(ev->resolved_path, id) != 0) continue;
        opens++;
        if (ev->err) errs++;
        int seen = 0;
        for (int j = 0; j < npt; j++) if (ptgids[j] == ev->tgid) seen = 1;
        if (!seen) { GROW(ptgids, npt, cappt); ptgids[npt++] = ev->tgid; }
    }
    view_add_row(&g_rpane, "opens", "normal", "", fmtdup("Opens: %d", opens), -1, "", 0);
    view_add_row(&g_rpane, "procs", "normal", "", fmtdup("Procs: %d", npt), -1, "", 0);
    view_add_row(&g_rpane, "errs", errs ? "error" : "normal", "", fmtdup("Errors: %d", errs), -1, "", 0);
    for (int i = 0; i < g_nevents; i++) {
        trace_event_t *ev = &g_events[i];
        process_t *p;
        char *text;
        if (ev->kind != EV_OPEN || !ev->resolved_path || strcmp(ev->resolved_path, id) != 0) continue;
        p = find_process(ev->tgid);
        text = fmtdup("PID %d %s [%s]%s", ev->tgid, p ? basename_c(p->exe && p->exe[0] ? p->exe : (p->argc ? p->argv[0] : "")) : "",
                      ev->flags_text ? ev->flags_text : "", ev->err ? fmtdup(" err=%d", ev->err) : "");
        view_add_row(&g_rpane, fmtdup("open_%d", ev->id), ev->err ? "error" : (ev->kind == EV_STDERR ? "error" : "normal"), "", text, 0, fmtdup("%d", ev->tgid), 0);
        free(text);
    }
    free(ptgids);
}

static void build_rpane_output(const char *id) {
    int eid = id ? atoi(id) : 0;
    trace_event_t *ev = NULL;
    process_t *p = NULL;
    for (int i = 0; i < g_nevents; i++) if (g_events[i].id == eid) { ev = &g_events[i]; break; }
    if (!ev) return;
    p = find_process(ev->tgid);
    view_add_row(&g_rpane, "hdr", "heading", "", "─── Output ───", -1, "", 0);
    view_add_row(&g_rpane, "stream", ev->kind == EV_STDERR ? "error" : "normal", "", fmtdup("Stream: %s", ev->kind == EV_STDOUT ? "STDOUT" : "STDERR"), -1, "", 0);
    view_add_row(&g_rpane, "pid", "normal", "", fmtdup("PID: %d", ev->tgid), -1, "", 0);
    view_add_row(&g_rpane, "proc", "normal", "", fmtdup("Proc: %s", p ? basename_c(p->exe && p->exe[0] ? p->exe : (p->argc ? p->argv[0] : "")) : ""), -1, "", 0);
    view_add_row(&g_rpane, "content_hdr", "heading", "", "─── Content ───", -1, "", 0);
    view_add_row(&g_rpane, "content", ev->kind == EV_STDERR ? "error" : "normal", "", ev->data ? ev->data : "", -1, "", 0);
}

static void build_rpane(void) {
    const char *id = g_state.cursor_id;
    if (!id[0]) return;
    if (g_state.mode == 0) build_rpane_process(id);
    else if (g_state.mode == 1 || g_state.mode >= 3) build_rpane_file(id);
    else build_rpane_output(id);
}

static void ensure_selection(view_t *v, char *id_buf, int *idx, int *scroll) {
    int pos = view_find_index(v, id_buf);
    if (pos < 0 && v->count > 0) {
        snprintf(id_buf, 4096, "%s", v->rows[0].id);
        pos = 0;
    }
    if (pos < 0) { id_buf[0] = 0; pos = 0; }
    *idx = pos;
    if (*scroll < 0) *scroll = 0;
}

static void rebuild_views(void) {
    free_view(&g_lpane);
    free_view(&g_rpane);
    switch (g_state.mode) {
    case 0: build_lpane_process(); break;
    case 1: build_lpane_files(); break;
    case 2: build_lpane_output(); break;
    case 3: case 5: build_lpane_deps(0); break;
    case 4: case 6: build_lpane_deps(1); break;
    default: build_lpane_process(); break;
    }
    ensure_selection(&g_lpane, g_state.cursor_id, &g_state.cursor, &g_state.scroll);
    build_rpane();
    ensure_selection(&g_rpane, g_state.dcursor_id, &g_state.dcursor, &g_state.dscroll);
}

static void sync_engine_from_state(void) {
    if (!g_tui) return;
    tui_set_cursor(g_tui, "lpane", g_state.cursor_id[0] ? g_state.cursor_id : NULL);
    tui_set_cursor(g_tui, "rpane", g_state.dcursor_id[0] ? g_state.dcursor_id : NULL);
    tui_focus(g_tui, g_state.focus ? "rpane" : "lpane");
}

static void sync_state_from_engine(void) {
    if (!g_tui) return;
    g_state.cursor = tui_get_cursor(g_tui, "lpane");
    g_state.scroll = tui_get_scroll(g_tui, "lpane");
    g_state.dcursor = tui_get_cursor(g_tui, "rpane");
    g_state.dscroll = tui_get_scroll(g_tui, "rpane");
    snprintf(g_state.cursor_id, sizeof g_state.cursor_id, "%s", tui_get_cursor_id(g_tui, "lpane"));
    snprintf(g_state.dcursor_id, sizeof g_state.dcursor_id, "%s", tui_get_cursor_id(g_tui, "rpane"));
    g_state.focus = strcmp(tui_get_focus(g_tui), "rpane") == 0;
}

static int search_hit_count(void) {
    int n = 0;
    for (int i = 0; i < g_lpane.count; i++) if (strcmp(g_lpane.rows[i].style, "search") == 0) n++;
    return n;
}

static void update_status(void) {
    static const char *mn[] = {"PROCS","FILES","OUTPUT","DEPS","RDEPS","DEP-CMDS","RDEP-CMDS"};
    static const char *tsl[] = {"abs","rel","Δ"};
    char s[1024];
    int p = snprintf(s, sizeof s, " %s%s | %d/%d | TS:%s", mn[g_state.mode], g_state.grouped ? " tree" : "",
                     g_state.cursor + 1, g_lpane.count, tsl[g_state.ts_mode]);
    if (g_state.evfilt[0]) p += snprintf(s + p, sizeof s - (size_t)p, " | F:%s", g_state.evfilt);
    if (g_state.search[0]) p += snprintf(s + p, sizeof s - (size_t)p, " | /%s[%d]", g_state.search, search_hit_count());
    if (g_state.lp_filter == 1) p += snprintf(s + p, sizeof s - (size_t)p, " | V:failed");
    else if (g_state.lp_filter == 2) p += snprintf(s + p, sizeof s - (size_t)p, " | V:running");
    if (g_state.mode >= 3 && g_state.mode <= 6) p += snprintf(s + p, sizeof s - (size_t)p, " | D:%s", g_state.dep_filter ? "written" : "all");
    snprintf(s + p, sizeof s - (size_t)p, " | 1:proc 2:file 3:out 4:dep 5:rdep 6:dcmd 7:rcmd ?:help");
    if (g_tui) tui_set_status(g_tui, s);
}

static const tui_col_def g_text_col[] = {{"text", -1, TUI_ALIGN_LEFT, TUI_OVERFLOW_TRUNCATE}};
static const tui_panel_def g_lpane_def = {"lpane", NULL, g_text_col, 1, TUI_PANEL_CURSOR};
static const tui_panel_def g_rpane_def = {"rpane", NULL, g_text_col, 1, TUI_PANEL_CURSOR | TUI_PANEL_BORDER};

static int source_row_count(const char *panel, void *ctx) {
    (void)ctx;
    return strcmp(panel, "lpane") == 0 ? g_lpane.count : g_rpane.count;
}

static int source_row_get(const char *panel, int rownum, tui_row_ref *row, void *ctx) {
    view_t *v = (strcmp(panel, "lpane") == 0) ? &g_lpane : &g_rpane;
    (void)ctx;
    if (rownum < 0 || rownum >= v->count) return 0;
    row->id = v->rows[rownum].id;
    row->style = v->rows[rownum].style;
    row->cols[0] = v->rows[rownum].text;
    return 1;
}

static int source_row_find(const char *panel, const char *id, void *ctx) {
    (void)ctx;
    return view_find_index(strcmp(panel, "lpane") == 0 ? &g_lpane : &g_rpane, id);
}

static void source_size_changed(int rows, int cols, void *ctx) {
    (void)ctx;
    g_state.rows = rows;
    g_state.cols = cols;
}

static const tui_data_source g_source = {
    source_row_count,
    source_row_get,
    source_row_find,
    source_size_changed,
};

static void reset_mode_selection(void) {
    g_state.focus = 0;
    g_state.cursor = g_state.scroll = g_state.dcursor = g_state.dscroll = 0;
    g_state.cursor_id[0] = 0;
    g_state.dcursor_id[0] = 0;
}

static strset_t *collapsed_set_for_mode(void) {
    if (g_state.mode == 0) return &g_proc_collapsed;
    if (g_state.mode == 1) return &g_file_collapsed;
    if (g_state.mode == 2) return &g_output_collapsed;
    return &g_dep_collapsed;
}

static void set_cursor_to_search_hit(int dir) {
    if (g_lpane.count == 0) return;
    int start = g_state.cursor;
    for (int step = 1; step <= g_lpane.count; step++) {
        int idx = (start + dir * step + g_lpane.count) % g_lpane.count;
        if (strcmp(g_lpane.rows[idx].style, "search") == 0) {
            snprintf(g_state.cursor_id, sizeof g_state.cursor_id, "%s", g_lpane.rows[idx].id);
            g_state.cursor = idx;
            return;
        }
    }
}

static void apply_search(const char *q) {
    snprintf(g_state.search, sizeof g_state.search, "%s", q ? q : "");
    rebuild_views();
    for (int i = 0; i < g_lpane.count; i++) {
        if (strcmp(g_lpane.rows[i].style, "search") == 0) {
            snprintf(g_state.cursor_id, sizeof g_state.cursor_id, "%s", g_lpane.rows[i].id);
            g_state.cursor = i;
            break;
        }
    }
}

static void collapse_or_back(void) {
    view_row_t *row = view_find_row(&g_lpane, g_state.cursor_id);
    strset_t *set = collapsed_set_for_mode();
    if (!row) return;
    if (g_state.focus) { g_state.focus = 0; return; }
    if (row->has_children && !strset_contains(set, row->id)) strset_add(set, row->id);
    else if (row->parent_id && row->parent_id[0]) snprintf(g_state.cursor_id, sizeof g_state.cursor_id, "%s", row->parent_id);
}

static void expand_or_detail(void) {
    view_row_t *row = g_state.focus ? view_find_row(&g_rpane, g_state.dcursor_id) : view_find_row(&g_lpane, g_state.cursor_id);
    strset_t *set = collapsed_set_for_mode();
    if (!row) return;
    if (g_state.focus) {
        if (row->link_mode >= 0 && row->link_id && row->link_id[0]) {
            g_state.mode = row->link_mode;
            reset_mode_selection();
            snprintf(g_state.cursor_id, sizeof g_state.cursor_id, "%s", row->link_id);
        }
        return;
    }
    if (row->has_children && strset_contains(set, row->id)) strset_remove(set, row->id);
    else g_state.focus = 1;
}

static void expand_subtree(int expand) {
    view_row_t *row = view_find_row(&g_lpane, g_state.cursor_id);
    strset_t *set = collapsed_set_for_mode();
    if (!row) return;
    for (int i = 0; i < g_lpane.count; i++) {
        view_row_t *r = &g_lpane.rows[i];
        const char *p = r->parent_id;
        while (p && p[0]) {
            if (strcmp(p, row->id) == 0) {
                if (expand) strset_remove(set, r->id);
                else if (r->has_children) strset_add(set, r->id);
                break;
            }
            view_row_t *pr = view_find_row(&g_lpane, p);
            p = pr ? pr->parent_id : "";
        }
    }
    if (!expand && row->has_children) strset_add(set, row->id);
    if (expand) strset_remove(set, row->id);
}

static void dump_lpane(FILE *out) {
    fprintf(out, "=== LPANE ===\n");
    for (int i = 0; i < g_lpane.count; i++)
        fprintf(out, "%d|%s|%s|%s|%s\n", i, g_lpane.rows[i].style, g_lpane.rows[i].id,
                g_lpane.rows[i].parent_id ? g_lpane.rows[i].parent_id : "", g_lpane.rows[i].text);
    fprintf(out, "=== END LPANE ===\n");
}

static void dump_rpane(FILE *out) {
    fprintf(out, "=== RPANE ===\n");
    for (int i = 0; i < g_rpane.count; i++)
        fprintf(out, "%d|%s|%s|%d|%s\n", i, g_rpane.rows[i].style, g_rpane.rows[i].text,
                g_rpane.rows[i].link_mode, g_rpane.rows[i].link_id ? g_rpane.rows[i].link_id : "");
    fprintf(out, "=== END RPANE ===\n");
}

static void dump_state(FILE *out) {
    sync_state_from_engine();
    fprintf(out, "=== STATE ===\n");
    fprintf(out, "cursor=%d scroll=%d focus=%d dcursor=%d dscroll=%d ts_mode=%d sort_key=%d grouped=%d mode=%d lp_filter=%d search=%s evfilt=%s rows=%d cols=%d dep_filter=%d\n",
            g_state.cursor, g_state.scroll, g_state.focus, g_state.dcursor, g_state.dscroll,
            g_state.ts_mode, g_state.sort_key, g_state.grouped, g_state.mode, g_state.lp_filter,
            g_state.search, g_state.evfilt, g_state.rows, g_state.cols, g_state.dep_filter);
    fprintf(out, "=== END STATE ===\n");
}

static void process_print(const char *what) {
    if (!what) return;
    if (strcmp(what, "lpane") == 0) dump_lpane(stdout);
    else if (strcmp(what, "rpane") == 0) dump_rpane(stdout);
    else if (strcmp(what, "state") == 0) dump_state(stdout);
    g_headless = 1;
}

static void apply_state_change(void) {
    rebuild_views();
    sync_engine_from_state();
    if (g_tui) tui_dirty(g_tui, NULL);
    update_status();
}

static int on_key_cb(tui_t *tui, int key, const char *panel, int cursor, const char *row_id, void *ctx) {
    (void)cursor; (void)ctx;
    if (key == TUI_K_NONE) {
        if (strcmp(panel ? panel : "", "lpane") == 0) snprintf(g_state.cursor_id, sizeof g_state.cursor_id, "%s", row_id ? row_id : "");
        else snprintf(g_state.dcursor_id, sizeof g_state.dcursor_id, "%s", row_id ? row_id : "");
        sync_state_from_engine();
        rebuild_views();
        sync_engine_from_state();
        tui_dirty(tui, NULL);
        update_status();
        return TUI_HANDLED;
    }
    switch (key) {
    case 'q': return TUI_QUIT;
    case '?': tui_show_help(tui, HELP); break;
    case '1': g_state.mode = 0; reset_mode_selection(); break;
    case '2': g_state.mode = 1; reset_mode_selection(); break;
    case '3': g_state.mode = 2; reset_mode_selection(); break;
    case '4': g_state.mode = 3; reset_mode_selection(); break;
    case '5': g_state.mode = 4; reset_mode_selection(); break;
    case '6': g_state.mode = 5; reset_mode_selection(); break;
    case '7': g_state.mode = 6; reset_mode_selection(); break;
    case 'G': g_state.grouped = !g_state.grouped; reset_mode_selection(); break;
    case 's': g_state.sort_key = (g_state.sort_key + 1) % 3; break;
    case 't': g_state.ts_mode = (g_state.ts_mode + 1) % 3; break;
    case 'v': g_state.lp_filter = (g_state.lp_filter + 1) % 3; reset_mode_selection(); break;
    case 'V': g_state.lp_filter = 0; break;
    case 'd': g_state.dep_filter ^= 1; break;
    case 'F': g_state.evfilt[0] = 0; break;
    case '/': {
        char buf[256] = "";
        if (tui_line_edit(tui, "/", buf, sizeof buf)) apply_search(buf);
        break;
    }
    case 'f': {
        char buf[64] = "";
        if (tui_line_edit(tui, "Filter: ", buf, sizeof buf)) {
            for (char *p = buf; *p; p++) *p = (char)toupper((unsigned char)*p);
            snprintf(g_state.evfilt, sizeof g_state.evfilt, "%s", buf);
        }
        break;
    }
    case 'n': set_cursor_to_search_hit(1); break;
    case 'N': set_cursor_to_search_hit(-1); break;
    case 'e': expand_subtree(1); break;
    case 'E': expand_subtree(0); break;
    case TUI_K_LEFT: case 'h': collapse_or_back(); break;
    case TUI_K_RIGHT: case 'l': case TUI_K_ENTER: expand_or_detail(); break;
    case 'W': {
        char fname[256] = "trace.db";
        if (tui_line_edit(tui, "Save to: ", fname, sizeof fname) && fname[0]) {
            FILE *f = fopen(fname, "w");
            if (f) { for (int i = 0; i < g_nraw; i++) fprintf(f, "%s\n", g_raw_trace_lines[i]); fclose(f); }
        }
        break;
    }
    case 'x': tui_set_status(tui, " SQL prompt removed with SQLite"); break;
    default: return TUI_HANDLED;
    }
    apply_state_change();
    return TUI_HANDLED;
}

static void process_input_cmd(const input_cmd_t *cmd) {
    if (!cmd) return;
    switch (cmd->kind) {
    case INPUT_KEY:
        if (cmd->key != TUI_K_NONE) tui_input_key(g_tui, cmd->key);
        break;
    case INPUT_RESIZE:
        tui_resize(g_tui, cmd->rows, cmd->cols);
        sync_state_from_engine();
        update_status();
        break;
    case INPUT_SELECT:
        reset_mode_selection();
        snprintf(g_state.cursor_id, sizeof g_state.cursor_id, "%s", cmd->text ? cmd->text : "");
        apply_state_change();
        break;
    case INPUT_SEARCH:
        apply_search(cmd->text ? cmd->text : "");
        sync_engine_from_state();
        break;
    case INPUT_EVFILT:
        snprintf(g_state.evfilt, sizeof g_state.evfilt, "%s", cmd->text ? cmd->text : "");
        for (char *p = g_state.evfilt; *p; p++) *p = (char)toupper((unsigned char)*p);
        apply_state_change();
        break;
    case INPUT_PRINT:
        process_print(cmd->text);
        break;
    }
}

static void save_to_file(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "tv: cannot create %s\n", path); return; }
    for (int i = 0; i < g_nraw; i++) fprintf(f, "%s\n", g_raw_trace_lines[i]);
    fclose(f);
}

static void on_live_batch(void) {
    finalize_process_tree();
    apply_state_change();
}

static void on_trace_fd_cb(tui_t *tui, int fd, void *ctx) {
    (void)ctx;
    int n = (int)read(fd, t_rbuf + t_rbuf_len, sizeof(t_rbuf) - (size_t)t_rbuf_len - 1);
    if (n <= 0) {
        if (t_rbuf_len > 0) {
            t_rbuf[t_rbuf_len] = 0;
            ingest_line(t_rbuf);
            t_rbuf_len = 0;
        }
        t_pending_live_rows = 0;
        t_live_batch_start_ms = 0;
        on_live_batch();
        tui_unwatch_fd(tui, fd);
        if (t_trace_fd >= 0) { close(t_trace_fd); t_trace_fd = -1; }
        return;
    }
    t_rbuf_len += n;
    int did = 0;
    while (1) {
        char *nl = memchr(t_rbuf, '\n', (size_t)t_rbuf_len);
        if (!nl) break;
        if (nl > t_rbuf && nl[-1] == '\r') nl[-1] = 0;
        *nl = 0;
        ingest_line(t_rbuf);
        did++;
        int used = (int)(nl - t_rbuf) + 1;
        memmove(t_rbuf, nl + 1, (size_t)(t_rbuf_len - used));
        t_rbuf_len -= used;
    }
    if (did) {
        long long now = monotonic_millis();
        if (t_pending_live_rows == 0 && now >= 0) t_live_batch_start_ms = now;
        t_pending_live_rows += did;
        if (t_pending_live_rows >= LIVE_TRACE_BATCH_ROWS || now < 0 || (t_live_batch_start_ms > 0 && now - t_live_batch_start_ms >= LIVE_TRACE_BATCH_MS)) {
            finalize_process_tree();
            apply_state_change();
            t_pending_live_rows = 0;
            t_live_batch_start_ms = 0;
        }
    }
    update_status();
}

static void free_all(void) {
    free_view(&g_lpane);
    free_view(&g_rpane);
    for (int i = 0; i < g_nevents; i++) {
        free(g_events[i].path); free(g_events[i].resolved_path); free(g_events[i].exe);
        free_string_array(g_events[i].argv, g_events[i].argc);
        free(g_events[i].flags_text); free(g_events[i].data); free(g_events[i].status);
    }
    free(g_events);
    for (int i = 0; i < g_nprocs; i++) {
        free(g_processes[i].exe); free(g_processes[i].cwd); free(g_processes[i].exit_status);
        free_string_array(g_processes[i].argv, g_processes[i].argc);
        free(g_processes[i].children);
        free_string_array(g_processes[i].read_paths, g_processes[i].nreads);
        free_string_array(g_processes[i].write_paths, g_processes[i].nwrites);
    }
    free(g_processes);
    for (int i = 0; i < g_nraw; i++) free(g_raw_trace_lines[i]);
    free(g_raw_trace_lines);
    for (int i = 0; i < g_ninputs; i++) free(g_inputs[i].text);
    free(g_inputs);
    strset_clear(&g_proc_collapsed); strset_clear(&g_file_collapsed); strset_clear(&g_output_collapsed); strset_clear(&g_dep_collapsed);
}

enum live_trace_backend {
    LIVE_TRACE_BACKEND_AUTO = 0,
    LIVE_TRACE_BACKEND_MODULE,
    LIVE_TRACE_BACKEND_SUD,
    LIVE_TRACE_BACKEND_PTRACE,
};

int main(int argc, char **argv) {
    int load_mode = 0;
    enum live_trace_backend live_backend = LIVE_TRACE_BACKEND_AUTO;
    char load_file[256] = "", trace_file[256] = "", save_file[256] = "";
    char **cmd = NULL;
    if (argc >= 2 && strcmp(argv[1], "--uproctrace") == 0) return uproctrace_main(argc - 1, argv + 1);
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--load") == 0 && i + 1 < argc) { load_mode = 1; snprintf(load_file, sizeof load_file, "%s", argv[++i]); }
        else if (strcmp(argv[i], "--trace") == 0 && i + 1 < argc) snprintf(trace_file, sizeof trace_file, "%s", argv[++i]);
        else if (strcmp(argv[i], "--save") == 0 && i + 1 < argc) snprintf(save_file, sizeof save_file, "%s", argv[++i]);
        else if (strcmp(argv[i], "--module") == 0) live_backend = LIVE_TRACE_BACKEND_MODULE;
        else if (strcmp(argv[i], "--sud") == 0) live_backend = LIVE_TRACE_BACKEND_SUD;
        else if (strcmp(argv[i], "--ptrace") == 0) live_backend = LIVE_TRACE_BACKEND_PTRACE;
        else if (strcmp(argv[i], "--") == 0 && i + 1 < argc) { cmd = argv + i + 1; break; }
    }
    if (!load_mode && !trace_file[0] && !cmd) {
        fprintf(stderr,
            "Usage: tv [--module|--sud|--ptrace] -- <command> [args...]\n"
            "       tv --load <file.db>\n"
            "       tv --trace <file.jsonl[.zst]> [--save <file.db>]\n"
            "       tv --load <file.db> --trace <input.jsonl[.zst]>\n"
            "       tv --uproctrace [-o FILE[.zst]] [--module|--sud|--ptrace] -- <command> [args...]\n");
        return 1;
    }

    if (load_mode) ingest_file(load_file);
    if (trace_file[0]) ingest_file(trace_file);
    finalize_process_tree();
    if (save_file[0]) save_to_file(save_file);

    if (cmd) {
        int pipefd[2];
        if (pipe(pipefd) < 0) { perror("pipe"); free_all(); return 1; }
        t_child_pid = fork();
        if (t_child_pid < 0) { perror("fork"); free_all(); return 1; }
        if (t_child_pid == 0) {
            close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(127);
            close(pipefd[1]);
            size_t cmdc = 0; while (cmd[cmdc]) cmdc++;
            size_t extra = 2 + cmdc + 1;
            if (live_backend != LIVE_TRACE_BACKEND_AUTO) extra++;
            char **uargv = calloc(extra, sizeof(*uargv));
            size_t ui = 0;
            uargv[ui++] = "--uproctrace";
            if (live_backend == LIVE_TRACE_BACKEND_MODULE) uargv[ui++] = "--module";
            else if (live_backend == LIVE_TRACE_BACKEND_SUD) uargv[ui++] = "--sud";
            else if (live_backend == LIVE_TRACE_BACKEND_PTRACE) uargv[ui++] = "--ptrace";
            uargv[ui++] = "--";
            for (size_t j = 0; j < cmdc; j++) uargv[ui++] = cmd[j];
            uargv[ui] = NULL;
            _exit(uproctrace_main((int)ui, uargv));
        }
        close(pipefd[1]);
        t_trace_fd = pipefd[0];
        g_state.lp_filter = 2;
    }

    rebuild_views();
    int headless_mode = (g_ninputs > 0) || (trace_file[0] && !cmd && !isatty(STDIN_FILENO)) || (save_file[0] && !cmd);
    if (headless_mode) g_tui = tui_open_headless(&g_source, NULL, g_state.rows, g_state.cols);
    else g_tui = tui_open(&g_source, NULL);
    if (!g_tui) {
        if (!headless_mode) fprintf(stderr, "tv: cannot open terminal\n");
        free_all();
        return headless_mode ? 0 : 1;
    }

    tui_set_layout(g_tui, tui_hbox(2,
        tui_panel_box(&g_lpane_def, 1, 0),
        tui_panel_box(&g_rpane_def, 1, 0)));
    tui_on_key(g_tui, on_key_cb, NULL);
    sync_engine_from_state();
    update_status();
    tui_dirty(g_tui, NULL);

    for (int i = 0; i < g_ninputs; i++) process_input_cmd(&g_inputs[i]);
    if (g_headless || (save_file[0] && !cmd)) {
        tui_close(g_tui);
        g_tui = NULL;
        free_all();
        return 0;
    }

    if (t_trace_fd >= 0) tui_watch_fd(g_tui, t_trace_fd, on_trace_fd_cb, NULL);
    tui_run(g_tui);

    tui_close(g_tui);
    g_tui = NULL;
    if (t_trace_fd >= 0) close(t_trace_fd);
    if (t_child_pid > 0) { kill(t_child_pid, SIGTERM); waitpid(t_child_pid, NULL, 0); }
    free_all();
    return 0;
}
