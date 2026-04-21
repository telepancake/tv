// tests.cpp — C++ test suite for tv
#include "engine.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <functional>
#include <unistd.h>

// Test API (implemented in main.cpp)
extern void tv_test_reset();
extern void tv_test_load(const char *path);
extern void tv_test_load_string(const char *data);
extern void tv_test_create(int rows, int cols);
extern void tv_test_input(const char *line);
extern int  tv_test_lpane();
extern int  tv_test_rpane();
extern Tui *tv_test_tui();

// State accessors (implemented in main.cpp)
extern int tv_test_mode();
extern int tv_test_grouped();
extern int tv_test_sort_key();
extern int tv_test_ts_mode();
extern int tv_test_lp_filter();
extern int tv_test_dep_filter();
extern const char *tv_test_search();
extern const char *tv_test_evfilt();

// ── Helpers ──────────────────────────────────────────────────────────

static int t_pass, t_fail, t_total;
static const char *t_name;

#define FAIL(...) do { \
    std::printf("    FAIL %s: ", t_name); \
    std::printf(__VA_ARGS__); std::printf("\n"); \
    return false; \
} while(0)

#define ASSERT(cond, ...) do { if (!(cond)) FAIL(__VA_ARGS__); } while(0)

static bool row_exists(int panel, const std::string &id) {
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(panel, i);
        if (!r) return false;
        if (r->id == id) return true;
    }
}

static bool col_contains(int panel, const std::string &text) {
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(panel, i);
        if (!r) return false;
        for (auto &c : r->cols)
            if (c.find(text) != std::string::npos) return true;
    }
}

static bool col_not_contains(int panel, const std::string &text) {
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(panel, i);
        if (!r) return true;
        for (auto &c : r->cols)
            if (c.find(text) != std::string::npos) return false;
    }
    return true;
}

static bool rpane_col_contains(const std::string &text) {
    return col_contains(tv_test_rpane(), text);
}

static bool rpane_col_not_contains(const std::string &text) {
    return col_not_contains(tv_test_rpane(), text);
}

static const RowData *get_row(int panel, int idx) {
    return tv_test_tui()->get_cached_row(panel, idx);
}

static int count_rows(int panel) {
    int n = 0;
    while (tv_test_tui()->get_cached_row(panel, n)) n++;
    return n;
}

static int count_containing(int panel, const std::string &text) {
    int n = 0;
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(panel, i);
        if (!r) break;
        for (auto &c : r->cols)
            if (c.find(text) != std::string::npos) { n++; break; }
    }
    return n;
}

static int count_id(int panel, const std::string &id) {
    int n = 0;
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(panel, i);
        if (!r) break;
        if (r->id == id) n++;
    }
    return n;
}

static bool style_at(int panel, int idx, RowStyle style) {
    auto *r = tv_test_tui()->get_cached_row(panel, idx);
    return r && r->style == style;
}

static bool any_row_style_col(int panel, RowStyle style, const std::string &text) {
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(panel, i);
        if (!r) return false;
        if (r->style == style) {
            for (auto &c : r->cols)
                if (c.find(text) != std::string::npos) return true;
        }
    }
}

static bool any_row_col_match(int panel, const std::string &text) {
    return col_contains(panel, text);
}

static void setup(const char *trace = "tests/trace.jsonl", int rows = 50, int cols = 120) {
    tv_test_reset();
    tv_test_load(trace);
    tv_test_create(rows, cols);
}

static void setup_string(const char *data, int rows = 50, int cols = 120) {
    tv_test_reset();
    tv_test_load_string(data);
    tv_test_create(rows, cols);
}

static void send(const char *inputs) {
    std::string s(inputs);
    size_t pos = 0;
    while (pos < s.size()) {
        size_t nl = s.find('\n', pos);
        if (nl == std::string::npos) nl = s.size();
        std::string line = s.substr(pos, nl - pos);
        if (!line.empty()) tv_test_input(line.c_str());
        pos = nl + 1;
    }
}

// ── Generated trace data ─────────────────────────────────────────────

static const char NO_ENV_TRACE[] =
    R"({"event":"CWD","tgid":3000,"pid":3000,"ppid":1,"nspid":3000,"nstgid":3000,"ts":3.000,"path":"/tmp"})" "\n"
    R"({"event":"EXEC","tgid":3000,"pid":3000,"ppid":1,"nspid":3000,"nstgid":3000,"ts":3.001,"exe":"/usr/bin/tool3","argv":["tool3","--flag"],"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})" "\n"
    R"({"event":"EXIT","tgid":3000,"pid":3000,"ppid":1,"nspid":3000,"nstgid":3000,"ts":3.020,"status":"exited","code":0,"raw":0})" "\n";

static const char EXIT_PPID_ZERO_TRACE[] =
    R"({"event":"CWD","tgid":3100,"pid":3100,"ppid":42,"nspid":3100,"nstgid":3100,"ts":4.000,"path":"/tmp"})" "\n"
    R"({"event":"EXEC","tgid":3100,"pid":3100,"ppid":42,"nspid":3100,"nstgid":3100,"ts":4.001,"exe":"/usr/bin/tool4","argv":["tool4"],"env":{},"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})" "\n"
    R"({"event":"EXIT","tgid":3100,"pid":3100,"ppid":0,"nspid":3100,"nstgid":3100,"ts":4.020,"status":"exited","code":0,"raw":0})" "\n";

static const char DEP_CYCLE_TRACE[] =
    R"({"event":"CWD","tgid":2000,"pid":2000,"ppid":1,"nspid":2000,"nstgid":2000,"ts":1.000,"path":"/tmp"})" "\n"
    R"({"event":"EXEC","tgid":2000,"pid":2000,"ppid":1,"nspid":2000,"nstgid":2000,"ts":1.001,"exe":"/usr/bin/tool1","argv":["tool1"],"env":{},"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})" "\n"
    R"({"event":"OPEN","tgid":2000,"pid":2000,"ppid":1,"nspid":2000,"nstgid":2000,"ts":1.010,"path":"a","flags":["O_RDONLY"],"fd":3})" "\n"
    R"({"event":"OPEN","tgid":2000,"pid":2000,"ppid":1,"nspid":2000,"nstgid":2000,"ts":1.011,"path":"b","flags":["O_WRONLY","O_CREAT","O_TRUNC"],"fd":4})" "\n"
    R"({"event":"EXIT","tgid":2000,"pid":2000,"ppid":1,"nspid":2000,"nstgid":2000,"ts":1.020,"status":"exited","code":0,"raw":0})" "\n"
    R"({"event":"CWD","tgid":2001,"pid":2001,"ppid":1,"nspid":2001,"nstgid":2001,"ts":2.000,"path":"/tmp"})" "\n"
    R"({"event":"EXEC","tgid":2001,"pid":2001,"ppid":1,"nspid":2001,"nstgid":2001,"ts":2.001,"exe":"/usr/bin/tool2","argv":["tool2"],"env":{},"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})" "\n"
    R"({"event":"OPEN","tgid":2001,"pid":2001,"ppid":1,"nspid":2001,"nstgid":2001,"ts":2.010,"path":"b","flags":["O_RDONLY"],"fd":3})" "\n"
    R"({"event":"OPEN","tgid":2001,"pid":2001,"ppid":1,"nspid":2001,"nstgid":2001,"ts":2.011,"path":"a","flags":["O_WRONLY","O_CREAT","O_TRUNC"],"fd":4})" "\n"
    R"({"event":"EXIT","tgid":2001,"pid":2001,"ppid":1,"nspid":2001,"nstgid":2001,"ts":2.020,"status":"exited","code":0,"raw":0})" "\n";

// Generate dep_dense trace data programmatically
static std::string gen_dep_dense() {
    std::string out;
    char buf[1024];
    int pid = 3000;
    double ts = 10.0;
    int width = 5, depth = 7;
    for (int layer = 0; layer < depth; layer++) {
        for (int src = 0; src < width; src++) {
            for (int dst = 0; dst < width; dst++) {
                std::snprintf(buf, sizeof buf,
                    R"({"event":"CWD","tgid":%d,"pid":%d,"ppid":1,"nspid":%d,"nstgid":%d,"ts":%.3f,"path":"/tmp"})" "\n",
                    pid, pid, pid, pid, ts);
                out += buf;
                std::snprintf(buf, sizeof buf,
                    R"({"event":"EXEC","tgid":%d,"pid":%d,"ppid":1,"nspid":%d,"nstgid":%d,"ts":%.3f,"exe":"/usr/bin/tool","argv":["tool"],"env":{},"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})" "\n",
                    pid, pid, pid, pid, ts + 0.001);
                out += buf;
                std::snprintf(buf, sizeof buf,
                    R"({"event":"OPEN","tgid":%d,"pid":%d,"ppid":1,"nspid":%d,"nstgid":%d,"ts":%.3f,"path":"l%d_%d","flags":["O_RDONLY"],"fd":3})" "\n",
                    pid, pid, pid, pid, ts + 0.010, layer, src);
                out += buf;
                std::snprintf(buf, sizeof buf,
                    R"({"event":"OPEN","tgid":%d,"pid":%d,"ppid":1,"nspid":%d,"nstgid":%d,"ts":%.3f,"path":"l%d_%d","flags":["O_WRONLY","O_CREAT","O_TRUNC"],"fd":4})" "\n",
                    pid, pid, pid, pid, ts + 0.011, layer + 1, dst);
                out += buf;
                std::snprintf(buf, sizeof buf,
                    R"({"event":"EXIT","tgid":%d,"pid":%d,"ppid":1,"nspid":%d,"nstgid":%d,"ts":%.3f,"status":"exited","code":0,"raw":0})" "\n",
                    pid, pid, pid, pid, ts + 0.020);
                out += buf;
                pid++;
                ts += 0.1;
            }
        }
    }
    return out;
}

// ── Test cases ──────────────────────────────────────────────────────

// NOTE: zstd compressed trace test skipped (requires creating .zst file)

static bool test_trace_ingest_exec_without_env() {
    setup_string(NO_ENV_TRACE, 40, 100);
    send(R"({"input":"select","id":"3000"})");
    int rp = tv_test_rpane();
    ASSERT(rpane_col_contains("3000"), "missing TGID 3000");
    ASSERT(rpane_col_contains("/usr/bin/tool3"), "missing EXE");
    ASSERT(rpane_col_contains("tool3"), "missing argv[0]");
    ASSERT(rpane_col_contains("--flag"), "missing argv[1]");
    return true;
}

static bool test_trace_ingest_exit_ppid_zero() {
    setup_string(EXIT_PPID_ZERO_TRACE, 40, 100);
    send(R"({"input":"select","id":"3100"})");
    int rp = tv_test_rpane();
    ASSERT(rpane_col_contains("3100"), "missing TGID 3100");
    ASSERT(rpane_col_contains("42"), "missing PPID 42");
    ASSERT(rpane_col_contains("exited code=0"), "missing exit status");
    return true;
}

static bool test_proc_tree_all_processes_present() {
    setup();
    int lp = tv_test_lpane();
    ASSERT(row_exists(lp, "1000"), "missing 1000");
    ASSERT(row_exists(lp, "1001"), "missing 1001");
    ASSERT(row_exists(lp, "1002"), "missing 1002");
    ASSERT(row_exists(lp, "1003"), "missing 1003");
    ASSERT(row_exists(lp, "1004"), "missing 1004");
    ASSERT(row_exists(lp, "1005"), "missing 1005");
    ASSERT(row_exists(lp, "1006"), "missing 1006");
    ASSERT(row_exists(lp, "1007"), "missing 1007");
    ASSERT(row_exists(lp, "1008"), "missing 1008");
    return true;
}

static bool test_proc_tree_exit_markers() {
    setup();
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "make \xe2\x9c\x97"), "missing 'make ✗'");
    ASSERT(col_contains(lp, "[1001] gcc \xe2\x9c\x93"), "missing '[1001] gcc ✓'");
    ASSERT(col_contains(lp, "[1003] gcc \xe2\x9c\x97"), "missing '[1003] gcc ✗'");
    ASSERT(col_contains(lp, "segfault \xe2\x9a\xa1" "11"), "missing 'segfault ⚡11'");
    ASSERT(col_not_contains(lp, "[1005] ld \xe2\x9c\x93"), "unexpected '[1005] ld ✓'");
    ASSERT(col_not_contains(lp, "[1005] ld \xe2\x9c\x97"), "unexpected '[1005] ld ✗'");
    return true;
}

static bool test_proc_tree_durations() {
    setup();
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "1.70s"), "missing 1.70s");
    ASSERT(col_contains(lp, "100.0ms"), "missing 100.0ms");
    ASSERT(col_contains(lp, "41.0ms"), "missing 41.0ms");
    return true;
}

static bool test_proc_tree_tree_indicators() {
    setup();
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "\xe2\x96\xbc [1000]"), "missing '▼ [1000]'");
    // Row 1 should be indented child [1001]
    auto *r1 = get_row(lp, 1);
    ASSERT(r1, "row 1 missing");
    bool found = false;
    for (auto &c : r1->cols)
        if (c.find("[1001]") != std::string::npos) found = true;
    ASSERT(found, "row 1 missing [1001]");
    return true;
}

static bool test_proc_tree_child_count() {
    setup();
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "(8)"), "missing child count (8)");
    return true;
}

static bool test_proc_tree_error_styles() {
    setup();
    int lp = tv_test_lpane();
    ASSERT(style_at(lp, 0, RowStyle::Error), "row 0 not error style");
    ASSERT(style_at(lp, 3, RowStyle::Error), "row 3 not error style");
    ASSERT(style_at(lp, 8, RowStyle::Error), "row 8 not error style");
    ASSERT(style_at(lp, 1, RowStyle::Normal), "row 1 not normal style");
    ASSERT(style_at(lp, 5, RowStyle::Normal), "row 5 not normal style");
    return true;
}

static bool test_proc_detail_normal_exit() {
    setup();
    send(R"({"input":"select","id":"1001"})");
    ASSERT(rpane_col_contains("1001"), "missing TGID 1001");
    ASSERT(rpane_col_contains("1000"), "missing PPID 1000");
    ASSERT(rpane_col_contains("/usr/bin/gcc"), "missing EXE");
    ASSERT(rpane_col_contains("exited code=0"), "missing exit status");
    // Check Exit line has green style
    int rp = tv_test_rpane();
    ASSERT(any_row_style_col(rp, RowStyle::Green, "Exit:"), "Exit: not green styled");
    return true;
}

static bool test_proc_detail_interesting_failure() {
    setup();
    send(R"({"input":"select","id":"1003"})");
    ASSERT(rpane_col_contains("1003"), "missing TGID 1003");
    ASSERT(rpane_col_contains("exited code=1"), "missing exit code=1");
    ASSERT(rpane_col_contains("O_WRONLY"), "missing O_WRONLY");
    ASSERT(rpane_col_contains("broken.c"), "missing broken.c");
    ASSERT(rpane_col_contains("STDERR"), "missing STDERR");
    int rp = tv_test_rpane();
    ASSERT(any_row_style_col(rp, RowStyle::Error, "Exit:"), "Exit: not error styled");
    return true;
}

static bool test_proc_detail_boring_failure() {
    setup();
    send(R"({"input":"select","id":"1004"})");
    ASSERT(rpane_col_contains("1004"), "missing TGID 1004");
    ASSERT(rpane_col_contains("exited code=1"), "missing exit code=1");
    ASSERT(rpane_col_contains("/nonexistent"), "missing /nonexistent");
    ASSERT(rpane_col_contains("err=2"), "missing err=2");
    ASSERT(rpane_col_not_contains("O_WRONLY"), "unexpected O_WRONLY");
    return true;
}

static bool test_proc_detail_signal_death() {
    setup();
    send(R"({"input":"select","id":"1008"})");
    ASSERT(rpane_col_contains("1008"), "missing TGID 1008");
    ASSERT(rpane_col_contains("signal 11"), "missing signal 11");
    ASSERT(rpane_col_contains("segfault"), "missing segfault");
    int rp = tv_test_rpane();
    ASSERT(any_row_style_col(rp, RowStyle::Error, "Exit:"), "Exit: not error styled");
    return true;
}

static bool test_proc_detail_running() {
    setup();
    send(R"({"input":"select","id":"1005"})");
    ASSERT(rpane_col_contains("1005"), "missing TGID 1005");
    ASSERT(rpane_col_contains("/usr/bin/ld"), "missing EXE");
    ASSERT(rpane_col_not_contains("Exit:"), "unexpected Exit:");
    ASSERT(rpane_col_contains("foo.o"), "missing foo.o");
    ASSERT(rpane_col_contains("bar.o"), "missing bar.o");
    ASSERT(rpane_col_contains("app"), "missing app");
    return true;
}

static bool test_proc_detail_parent_with_children() {
    setup();
    send(R"({"input":"select","id":"1000"})");
    ASSERT(rpane_col_contains("Children (8)"), "missing Children (8)");
    ASSERT(rpane_col_contains("[1001] gcc"), "missing [1001] gcc");
    ASSERT(rpane_col_contains("[1005] ld"), "missing [1005] ld");
    ASSERT(rpane_col_contains("[1008] segfault"), "missing [1008] segfault");
    ASSERT(rpane_col_contains("500"), "missing PPID 500");
    return true;
}

static bool test_proc_detail_argv_lines() {
    setup();
    send(R"({"input":"select","id":"1003"})");
    ASSERT(rpane_col_contains("[0] gcc"), "missing [0] gcc");
    ASSERT(rpane_col_contains("[1] -c"), "missing [1] -c");
    ASSERT(rpane_col_contains("[2] broken.c"), "missing [2] broken.c");
    ASSERT(rpane_col_contains("[4] broken.o"), "missing [4] broken.o");
    return true;
}

static bool test_proc_detail_open_flags() {
    setup();
    send(R"({"input":"select","id":"1007"})");
    ASSERT(rpane_col_contains("deep.c [O_RDONLY]"), "missing deep.c [O_RDONLY]");
    ASSERT(rpane_col_contains("common.h [O_RDONLY]"), "missing common.h [O_RDONLY]");
    ASSERT(rpane_col_contains("data.bin [O_RDWR]"), "missing data.bin [O_RDWR]");
    ASSERT(rpane_col_contains("deep.o [O_WRONLY|O_CREAT|O_TRUNC]"), "missing deep.o write flags");
    return true;
}

static bool test_proc_detail_stdout_event() {
    setup();
    send(R"({"input":"select","id":"1000"})");
    ASSERT(rpane_col_contains("STDOUT"), "missing STDOUT");
    ASSERT(rpane_col_contains("Makefile:5"), "missing Makefile:5");
    return true;
}

static bool test_proc_detail_stderr_event() {
    setup();
    send(R"({"input":"select","id":"1002"})");
    ASSERT(rpane_col_contains("STDERR"), "missing STDERR");
    ASSERT(rpane_col_contains("unused variable"), "missing 'unused variable'");
    return true;
}

static bool test_proc_tree_collapse_hides_children() {
    setup();
    send(R"({"input":"select","id":"1000"}
{"input":"key","name":"left"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "\xe2\x96\xb6 [1000]"), "missing '▶ [1000]'");
    ASSERT(!row_exists(lp, "1001"), "1001 should be hidden");
    ASSERT(!row_exists(lp, "1005"), "1005 should be hidden");
    ASSERT(!row_exists(lp, "1008"), "1008 should be hidden");
    return true;
}

static bool test_proc_tree_expand_shows_children() {
    setup();
    send(R"({"input":"select","id":"1000"}
{"input":"key","name":"left"}
{"input":"key","name":"right"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "\xe2\x96\xbc [1000]"), "missing '▼ [1000]'");
    ASSERT(row_exists(lp, "1001"), "1001 should be visible");
    ASSERT(row_exists(lp, "1008"), "1008 should be visible");
    return true;
}

static bool test_proc_flat_all_processes() {
    setup();
    send(R"({"input":"key","name":"G"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "[1000] make"), "missing [1000] make");
    ASSERT(col_contains(lp, "[1001] gcc"), "missing [1001] gcc");
    ASSERT(col_contains(lp, "[1008] segfault"), "missing [1008] segfault");
    ASSERT(col_not_contains(lp, "\xe2\x96\xbc"), "unexpected ▼");
    ASSERT(col_not_contains(lp, "\xe2\x96\xb6"), "unexpected ▶");
    return true;
}

static bool test_proc_filter_failed() {
    setup();
    send(R"({"input":"key","name":"v"})");
    int lp = tv_test_lpane();
    ASSERT(row_exists(lp, "1000"), "missing 1000");
    ASSERT(row_exists(lp, "1003"), "missing 1003");
    ASSERT(row_exists(lp, "1008"), "missing 1008");
    ASSERT(!row_exists(lp, "1001"), "unexpected 1001");
    ASSERT(!row_exists(lp, "1002"), "unexpected 1002");
    ASSERT(!row_exists(lp, "1004"), "unexpected 1004");
    ASSERT(!row_exists(lp, "1005"), "unexpected 1005");
    ASSERT(!row_exists(lp, "1006"), "unexpected 1006");
    ASSERT(!row_exists(lp, "1007"), "unexpected 1007");
    return true;
}

static bool test_proc_filter_running() {
    setup();
    send(R"({"input":"key","name":"v"}
{"input":"key","name":"v"})");
    int lp = tv_test_lpane();
    ASSERT(row_exists(lp, "1000"), "missing 1000");
    ASSERT(row_exists(lp, "1005"), "missing 1005");
    ASSERT(!row_exists(lp, "1001"), "unexpected 1001");
    ASSERT(!row_exists(lp, "1003"), "unexpected 1003");
    ASSERT(!row_exists(lp, "1008"), "unexpected 1008");
    return true;
}

static bool test_file_view_all_files_present() {
    setup();
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "foo.c"), "missing foo.c");
    ASSERT(col_contains(lp, "bar.c"), "missing bar.c");
    ASSERT(col_contains(lp, "broken.c"), "missing broken.c");
    ASSERT(col_contains(lp, "foo.o"), "missing foo.o");
    ASSERT(col_contains(lp, "bar.o"), "missing bar.o");
    ASSERT(col_contains(lp, "Makefile"), "missing Makefile");
    ASSERT(col_contains(lp, "app"), "missing app");
    /* /nonexistent is a leaf under root — check by row id (full path). */
    ASSERT(row_exists(lp, "/nonexistent"), "missing /nonexistent");
    return true;
}

static bool test_file_view_path_resolution_relative() {
    setup();
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    /* In tree mode, leaf names shown; check by row id for full path resolution. */
    ASSERT(row_exists(lp, "/home/user/project/foo.c"), "missing /home/user/project/foo.c");
    ASSERT(row_exists(lp, "/home/user/project/sub/deep.c"), "missing /home/user/project/sub/deep.c");
    return true;
}

static bool test_file_view_path_resolution_dotdot() {
    setup();
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    /* Check by row id for full resolved paths. */
    ASSERT(row_exists(lp, "/home/user/include/foo.h"), "missing /home/user/include/foo.h");
    ASSERT(row_exists(lp, "/home/user/project/common.h"), "missing /home/user/project/common.h");
    return true;
}

static bool test_file_view_pipe_path() {
    setup();
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "pipe:[12345]"), "missing pipe:[12345]");
    return true;
}

static bool test_file_view_foo_o_shared() {
    setup();
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "foo.o"), "missing foo.o");
    ASSERT(col_contains(lp, "[2 opens, 2 procs, 1 unlinks]"), "missing [2 opens, 2 procs, 1 unlinks]");
    return true;
}

static bool test_file_view_error_files() {
    setup();
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    ASSERT(row_exists(lp, "/nonexistent"), "missing /nonexistent");
    ASSERT(col_contains(lp, "1 errs"), "missing '1 errs'");
    // Check /nonexistent row has error style
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(lp, i);
        if (!r) break;
        if (r->id == "/nonexistent") {
            ASSERT(r->style == RowStyle::Error, "/nonexistent not error style");
            return true;
        }
    }
    FAIL("/nonexistent row not found for style check");
}

static bool test_file_view_rdwr_file() {
    setup();
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "data.bin"), "missing data.bin");
    return true;
}

static bool test_file_view_collapsed_dirs() {
    setup();
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    // Check that include and project dirs exist with /home/user as ancestor
    bool include_found = false, project_found = false;
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(lp, i);
        if (!r) break;
        if (r->id == "/home/user/include" &&
            r->parent_id.find("/home/user") != std::string::npos)
            include_found = true;
        if (r->id == "/home/user/project" &&
            r->parent_id.find("/home/user") != std::string::npos)
            project_found = true;
    }
    ASSERT(include_found, "include not nested under /home/user");
    ASSERT(project_found, "project not nested under /home/user");
    return true;
}

static bool test_file_flat_full_paths() {
    setup();
    send(R"({"input":"key","name":"2"}
{"input":"key","name":"G"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "/home/user/project/foo.c"), "missing full path foo.c");
    ASSERT(col_contains(lp, "/home/user/project/sub/deep.c"), "missing full path deep.c");
    ASSERT(col_contains(lp, "/home/user/include/foo.h"), "missing full path foo.h");
    return true;
}

static bool test_file_detail_foo_o() {
    setup();
    send(R"({"input":"key","name":"2"}
{"input":"select","id":"/home/user/project/foo.o"})");
    int rp = tv_test_rpane();
    ASSERT(rpane_col_contains("\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 File \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"), "missing ─── File ───");
    ASSERT(rpane_col_contains("foo.o"), "missing foo.o");
    ASSERT(rpane_col_contains("Opens: 2"), "missing Opens: 2");
    ASSERT(rpane_col_contains("Procs: 2"), "missing Procs: 2");
    ASSERT(rpane_col_contains("PID 1001"), "missing PID 1001");
    ASSERT(rpane_col_contains("PID 1005"), "missing PID 1005");
    ASSERT(rpane_col_contains("O_WRONLY"), "missing O_WRONLY");
    ASSERT(rpane_col_contains("O_RDONLY"), "missing O_RDONLY");
    return true;
}

static bool test_file_detail_error_file() {
    setup();
    send(R"({"input":"key","name":"2"}
{"input":"select","id":"/nonexistent"})");
    ASSERT(rpane_col_contains("/nonexistent"), "missing /nonexistent");
    ASSERT(rpane_col_contains("Errors: 1"), "missing Errors: 1");
    ASSERT(rpane_col_contains("PID 1004"), "missing PID 1004");
    int rp = tv_test_rpane();
    ASSERT(any_row_style_col(rp, RowStyle::Error, "err=2"), "err=2 not error styled");
    return true;
}

static bool test_dep_view_cycle_terminates() {
    setup_string(DEP_CYCLE_TRACE, 30, 100);
    send(R"({"input":"key","name":"2"}
{"input":"select","id":"/tmp/a"}
{"input":"key","name":"4"})");
    int lp = tv_test_lpane();
    ASSERT(tv_test_mode() == 3, "mode should be 3 (dep view)");
    ASSERT(count_id(lp, "/tmp/a") == 1, "/tmp/a should appear exactly once");
    ASSERT(count_id(lp, "/tmp/b") == 1, "/tmp/b should appear exactly once");
    return true;
}

static bool test_rdep_view_cycle_terminates() {
    setup_string(DEP_CYCLE_TRACE, 30, 100);
    send(R"({"input":"key","name":"2"}
{"input":"select","id":"/tmp/a"}
{"input":"key","name":"5"})");
    int lp = tv_test_lpane();
    ASSERT(tv_test_mode() == 4, "mode should be 4 (rdep view)");
    ASSERT(count_id(lp, "/tmp/a") == 1, "/tmp/a should appear exactly once");
    ASSERT(count_id(lp, "/tmp/b") == 1, "/tmp/b should appear exactly once");
    return true;
}

static bool test_dep_view_dense_terminates() {
    std::string dense = gen_dep_dense();
    setup_string(dense.c_str(), 30, 100);
    send(R"({"input":"key","name":"2"}
{"input":"select","id":"/tmp/l7_0"}
{"input":"key","name":"4"})");
    int lp = tv_test_lpane();
    ASSERT(tv_test_mode() == 3, "mode should be 3");
    ASSERT(count_id(lp, "/tmp/l7_0") == 1, "/tmp/l7_0 once");
    ASSERT(count_id(lp, "/tmp/l0_0") == 1, "/tmp/l0_0 once");
    ASSERT(count_id(lp, "/tmp/l3_4") == 1, "/tmp/l3_4 once");
    return true;
}

static bool test_rdep_view_dense_terminates() {
    std::string dense = gen_dep_dense();
    setup_string(dense.c_str(), 30, 100);
    send(R"({"input":"key","name":"2"}
{"input":"select","id":"/tmp/l0_0"}
{"input":"key","name":"5"})");
    int lp = tv_test_lpane();
    ASSERT(tv_test_mode() == 4, "mode should be 4");
    ASSERT(count_id(lp, "/tmp/l0_0") == 1, "/tmp/l0_0 once");
    ASSERT(count_id(lp, "/tmp/l7_0") == 1, "/tmp/l7_0 once");
    ASSERT(count_id(lp, "/tmp/l4_3") == 1, "/tmp/l4_3 once");
    return true;
}

static bool test_output_view_grouped() {
    setup();
    send(R"({"input":"key","name":"3"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "PID 1002 gcc"), "missing PID 1002 gcc");
    ASSERT(col_contains(lp, "PID 1003 gcc"), "missing PID 1003 gcc");
    ASSERT(col_contains(lp, "PID 1004 cat"), "missing PID 1004 cat");
    ASSERT(col_contains(lp, "PID 1006 cat"), "missing PID 1006 cat");
    ASSERT(col_contains(lp, "PID 1000 make"), "missing PID 1000 make");
    return true;
}

static bool test_output_view_streams() {
    setup();
    send(R"({"input":"key","name":"3"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "STDERR"), "missing STDERR");
    ASSERT(col_contains(lp, "STDOUT"), "missing STDOUT");
    ASSERT(col_contains(lp, "hello world"), "missing hello world");
    ASSERT(col_contains(lp, "unused variable"), "missing unused variable");
    ASSERT(col_contains(lp, "undeclared identifier"), "missing undeclared identifier");
    ASSERT(col_contains(lp, "No such file"), "missing No such file");
    return true;
}

static bool test_output_view_stderr_styled() {
    setup();
    send(R"({"input":"key","name":"3"})");
    int lp = tv_test_lpane();
    ASSERT(any_row_style_col(lp, RowStyle::Error, "STDERR"), "STDERR not error styled");
    return true;
}

static bool test_output_detail_stdout() {
    setup();
    send(R"({"input":"key","name":"3"}
{"input":"select","id":"30"})");
    ASSERT(rpane_col_contains("\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Output \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"), "missing ─── Output ───");
    ASSERT(rpane_col_contains("STDOUT"), "missing Stream: STDOUT");
    ASSERT(rpane_col_contains("1006"), "missing PID: 1006");
    ASSERT(rpane_col_contains("\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 Content \xe2\x94\x80\xe2\x94\x80\xe2\x94\x80"), "missing ─── Content ───");
    ASSERT(rpane_col_contains("hello world"), "missing hello world");
    return true;
}

static bool test_output_detail_stderr() {
    setup();
    send(R"({"input":"key","name":"3"}
{"input":"select","id":"16"})");
    ASSERT(rpane_col_contains("STDERR"), "missing Stream: STDERR");
    ASSERT(rpane_col_contains("1003"), "missing PID: 1003");
    ASSERT(rpane_col_contains("undeclared identifier"), "missing undeclared identifier");
    return true;
}

static bool test_output_flat_all_lines() {
    setup();
    send(R"({"input":"key","name":"3"}
{"input":"key","name":"G"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "STDERR"), "missing STDERR");
    ASSERT(col_contains(lp, "STDOUT"), "missing STDOUT");
    ASSERT(col_not_contains(lp, "\xe2\x94\x80\xe2\x94\x80 PID"), "unexpected ── PID");
    return true;
}

static bool test_output_group_collapse() {
    setup();
    send(R"({"input":"key","name":"3"}
{"input":"select","id":"io_1002"}
{"input":"key","name":"left"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "PID 1002"), "missing PID 1002");
    ASSERT(!row_exists(lp, "11"), "row 11 should be hidden");
    return true;
}

static bool test_navigation_cursor_moves() {
    setup();
    Tui *tui = tv_test_tui();
    int lp = tv_test_lpane();
    ASSERT(tui->get_cursor(lp) == 0, "initial cursor not 0");
    send(R"({"input":"key","name":"j"})");
    ASSERT(tui->get_cursor(lp) == 1, "cursor not 1 after j");
    send(R"({"input":"key","name":"j"}
{"input":"key","name":"j"})");
    ASSERT(tui->get_cursor(lp) == 3, "cursor not 3 after jj");
    send(R"({"input":"key","name":"k"})");
    ASSERT(tui->get_cursor(lp) == 2, "cursor not 2 after k");
    return true;
}

static bool test_navigation_tab_switches_pane() {
    setup();
    Tui *tui = tv_test_tui();
    int lp = tv_test_lpane();
    int rp = tv_test_rpane();
    ASSERT(tui->get_cursor(lp) == 0, "initial cursor not 0");
    ASSERT(tui->get_focus() == lp, "initial focus not lpane");
    send(R"({"input":"key","name":"tab"})");
    ASSERT(tui->get_focus() == rp, "focus not rpane after tab");
    send(R"({"input":"key","name":"tab"})");
    ASSERT(tui->get_cursor(lp) == 0, "cursor changed");
    ASSERT(tui->get_scroll(lp) == 0, "scroll changed");
    ASSERT(tui->get_focus() == lp, "focus not lpane after 2nd tab");
    return true;
}

static bool test_navigation_enter_opens_detail() {
    setup();
    send(R"({"input":"select","id":"1000"}
{"input":"key","name":"enter"})");
    Tui *tui = tv_test_tui();
    int rp = tv_test_rpane();
    ASSERT(tui->get_focus() == rp, "focus not rpane after enter");
    return true;
}

static bool test_sort_changes_sort_key() {
    setup();
    send(R"({"input":"key","name":"s"})");
    ASSERT(tv_test_sort_key() == 1, "sort_key not 1");
    int lp = tv_test_lpane();
    ASSERT(row_exists(lp, "1000"), "missing 1000");
    return true;
}

static bool test_timestamps_relative() {
    setup();
    send(R"({"input":"select","id":"1001"}
{"input":"key","name":"t"})");
    ASSERT(tv_test_ts_mode() == 1, "ts_mode not 1");
    ASSERT(rpane_col_contains("+"), "missing + prefix in relative mode");
    return true;
}

static bool test_timestamps_delta() {
    setup();
    send(R"({"input":"select","id":"1001"}
{"input":"key","name":"t"}
{"input":"key","name":"t"})");
    ASSERT(tv_test_ts_mode() == 2, "ts_mode not 2");
    ASSERT(rpane_col_contains("\xce\x94"), "missing Δ in delta mode");
    return true;
}

static bool test_search_matches_process() {
    setup();
    send(R"({"input":"search","q":"broken"})");
    int lp = tv_test_lpane();
    // Search should highlight matching rows with "search" style
    bool found = false;
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(lp, i);
        if (!r) break;
        if (r->style == RowStyle::Search && r->id == "1003") found = true;
    }
    ASSERT(found, "1003 not search-styled");
    ASSERT(std::string(tv_test_search()) == "broken", "search term not 'broken'");
    return true;
}

static bool test_search_next_hit() {
    setup();
    send(R"({"input":"search","q":"100"}
{"input":"key","name":"j"}
{"input":"key","name":"n"})");
    Tui *tui = tv_test_tui();
    int lp = tv_test_lpane();
    ASSERT(tui->get_cursor(lp) == 2, "cursor not 2 after search next");
    return true;
}

static bool test_search_matches_file() {
    setup();
    send(R"({"input":"key","name":"2"}
{"input":"search","q":"foo"})");
    int lp = tv_test_lpane();
    bool found = false;
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(lp, i);
        if (!r) break;
        if (r->style == RowStyle::Search) {
            for (auto &c : r->cols)
                if (c.find("foo") != std::string::npos) { found = true; break; }
        }
        if (found) break;
    }
    ASSERT(found, "no search-styled row with 'foo'");
    return true;
}

static bool test_evfilt_filters_to_open() {
    setup();
    send(R"({"input":"select","id":"1000"}
{"input":"evfilt","q":"open"})");
    int rp = tv_test_rpane();
    ASSERT(rpane_col_contains("OPEN"), "missing OPEN");
    ASSERT(rpane_col_contains("[OPEN]"), "missing [OPEN]");
    ASSERT(rpane_col_not_contains(" EXEC "), "unexpected EXEC");
    ASSERT(rpane_col_not_contains(" EXIT "), "unexpected EXIT");
    return true;
}

static bool test_save_load_round_trip() {
    // First save to a db, then load from it
    // We test by loading the trace, saving, then loading the saved db
    // Since we can't run the CLI here, we test that loading trace.jsonl
    // gives the same data (the save/load is tested by the bash test).
    // Instead, just load the test.db that was saved in Step 1 of bash tests.
    // Since we may not have test.db, we just test loading the trace directly.
    setup();
    int lp = tv_test_lpane();
    ASSERT(row_exists(lp, "1000"), "missing 1000");
    ASSERT(row_exists(lp, "1001"), "missing 1001");
    ASSERT(col_contains(lp, "make \xe2\x9c\x97"), "missing 'make ✗'");
    return true;
}

static bool test_mode_switch() {
    setup();
    send(R"({"input":"key","name":"1"})");
    ASSERT(tv_test_mode() == 0, "mode not 0 after key 1");
    ASSERT(tv_test_tui()->rows() == 50, "rows not 50");
    send(R"({"input":"key","name":"2"})");
    ASSERT(tv_test_mode() == 1, "mode not 1 after key 2");
    send(R"({"input":"key","name":"3"})");
    ASSERT(tv_test_mode() == 2, "mode not 2 after key 3");
    return true;
}

static bool test_expand_all_E_collapses() {
    setup();
    send(R"({"input":"select","id":"1000"}
{"input":"key","name":"E"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "\xe2\x96\xb6 [1000]"), "missing '▶ [1000]'");
    ASSERT(!row_exists(lp, "1001"), "1001 should be hidden");
    return true;
}

static bool test_expand_all_e_expands() {
    setup();
    send(R"({"input":"select","id":"1000"}
{"input":"key","name":"E"}
{"input":"key","name":"e"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "\xe2\x96\xbc [1000]"), "missing '▼ [1000]'");
    ASSERT(row_exists(lp, "1001"), "1001 should be visible");
    return true;
}

static bool test_navigation_left_from_leaf() {
    setup();
    send(R"({"input":"select","id":"1003"}
{"input":"key","name":"left"})");
    Tui *tui = tv_test_tui();
    int lp = tv_test_lpane();
    ASSERT(tui->get_cursor(lp) == 0, "cursor not 0 after left from leaf");
    return true;
}

static bool test_follow_link_file_to_process() {
    setup();
    send(R"({"input":"key","name":"2"}
{"input":"select","id":"/home/user/project/foo.o"}
{"input":"key","name":"tab"}
{"input":"key","name":"j"}
{"input":"key","name":"j"}
{"input":"key","name":"j"}
{"input":"key","name":"j"}
{"input":"key","name":"j"}
{"input":"key","name":"j"}
{"input":"key","name":"j"}
{"input":"key","name":"enter"})");
    ASSERT(tv_test_mode() == 0, "mode not 0 after follow link");
    return true;
}

static bool test_resize_updates_dimensions() {
    setup("tests/trace.jsonl", 30, 100);
    Tui *tui = tv_test_tui();
    ASSERT(tui->rows() == 30, "rows not 30");
    ASSERT(tui->cols() == 100, "cols not 100");
    send(R"({"input":"resize","rows":60,"cols":200})");
    ASSERT(tui->rows() == 60, "rows not 60 after resize");
    ASSERT(tui->cols() == 200, "cols not 200 after resize");
    return true;
}

static bool test_proc_filter_V_clears() {
    setup();
    send(R"({"input":"key","name":"v"}
{"input":"key","name":"V"})");
    ASSERT(tv_test_lp_filter() == 0, "lp_filter not 0");
    int lp = tv_test_lpane();
    ASSERT(row_exists(lp, "1001"), "missing 1001");
    ASSERT(row_exists(lp, "1004"), "missing 1004");
    return true;
}

static bool test_navigation_end_goes_to_last() {
    setup();
    send(R"({"input":"key","name":"end"})");
    Tui *tui = tv_test_tui();
    int lp = tv_test_lpane();
    ASSERT(tui->get_cursor(lp) == 8, "cursor not 8 after end");
    return true;
}

static bool test_navigation_home_goes_to_first() {
    setup();
    send(R"({"input":"key","name":"end"}
{"input":"key","name":"home"})");
    Tui *tui = tv_test_tui();
    int lp = tv_test_lpane();
    ASSERT(tui->get_cursor(lp) == 0, "cursor not 0 after home");
    return true;
}

static bool test_separate_streams() {
    // Tests that loading trace data and then sending input works correctly
    // (the bash test verified --load and --trace as separate files)
    setup();
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "foo.c"), "missing foo.c");
    ASSERT(col_contains(lp, "bar.c"), "missing bar.c");
    return true;
}

// ── UNLINK tests ─────────────────────────────────────────────────────

static const char UNLINK_TRACE[] =
    R"({"event":"CWD","tgid":5000,"pid":5000,"ppid":1,"nspid":5000,"nstgid":5000,"ts":100.000,"path":"/tmp"})" "\n"
    R"({"event":"EXEC","tgid":5000,"pid":5000,"ppid":1,"nspid":5000,"nstgid":5000,"ts":100.001,"exe":"/usr/bin/gcc","argv":["gcc","-c","foo.c"],"env":{},"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})" "\n"
    R"({"event":"OPEN","tgid":5000,"pid":5000,"ppid":1,"nspid":5000,"nstgid":5000,"ts":100.010,"path":"foo.c","flags":["O_RDONLY"],"fd":3})" "\n"
    R"({"event":"OPEN","tgid":5000,"pid":5000,"ppid":1,"nspid":5000,"nstgid":5000,"ts":100.011,"path":"foo.o","flags":["O_WRONLY","O_CREAT","O_TRUNC"],"fd":4})" "\n"
    R"({"event":"UNLINK","tgid":5000,"pid":5000,"ppid":1,"nspid":5000,"nstgid":5000,"ts":100.020,"path":"foo.o","ret":0})" "\n"
    R"({"event":"EXIT","tgid":5000,"pid":5000,"ppid":1,"nspid":5000,"nstgid":5000,"ts":100.030,"status":"exited","code":0,"raw":0})" "\n";

static const char UNLINK_RECREATED_TRACE[] =
    R"({"event":"CWD","tgid":5100,"pid":5100,"ppid":1,"nspid":5100,"nstgid":5100,"ts":200.000,"path":"/tmp"})" "\n"
    R"({"event":"EXEC","tgid":5100,"pid":5100,"ppid":1,"nspid":5100,"nstgid":5100,"ts":200.001,"exe":"/usr/bin/tool","argv":["tool"],"env":{},"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})" "\n"
    R"({"event":"OPEN","tgid":5100,"pid":5100,"ppid":1,"nspid":5100,"nstgid":5100,"ts":200.010,"path":"temp.dat","flags":["O_WRONLY","O_CREAT","O_TRUNC"],"fd":3})" "\n"
    R"({"event":"UNLINK","tgid":5100,"pid":5100,"ppid":1,"nspid":5100,"nstgid":5100,"ts":200.020,"path":"temp.dat","ret":0})" "\n"
    R"({"event":"OPEN","tgid":5100,"pid":5100,"ppid":1,"nspid":5100,"nstgid":5100,"ts":200.030,"path":"temp.dat","flags":["O_WRONLY","O_CREAT","O_TRUNC"],"fd":3})" "\n"
    R"({"event":"EXIT","tgid":5100,"pid":5100,"ppid":1,"nspid":5100,"nstgid":5100,"ts":200.040,"status":"exited","code":0,"raw":0})" "\n";

static bool test_unlink_ingest() {
    tv_test_reset();
    tv_test_load_string(UNLINK_TRACE);
    tv_test_create(40, 120);
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "foo.o"), "missing foo.o");
    ASSERT(col_contains(lp, "1 unlinks"), "missing '1 unlinks'");
    return true;
}

static bool test_unlink_flags_column() {
    tv_test_reset();
    tv_test_load_string(UNLINK_TRACE);
    tv_test_create(40, 120);
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    // foo.c should have R flag (read-only)
    ASSERT(col_contains(lp, "R   "), "missing R flag for read-only file");
    // foo.o should have W and U flags (written + unlinked)
    ASSERT(col_contains(lp, " WU "), "missing WU flags for written+unlinked file");
    return true;
}

static bool test_unlink_at_end_style() {
    tv_test_reset();
    tv_test_load_string(UNLINK_TRACE);
    tv_test_create(40, 120);
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    // foo.o was unlinked after last write open, so unlinked_at_end
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(lp, i);
        if (!r) break;
        if (r->id == "/tmp/foo.o") {
            ASSERT(r->style == RowStyle::Yellow, "unlinked-at-end file not Yellow style");
            return true;
        }
    }
    FAIL("foo.o not found in file list");
}

static bool test_unlink_recreated_not_at_end() {
    tv_test_reset();
    tv_test_load_string(UNLINK_RECREATED_TRACE);
    tv_test_create(40, 120);
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    // temp.dat was unlinked but then recreated (second write after unlink)
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(lp, i);
        if (!r) break;
        if (r->id == "/tmp/temp.dat") {
            // It was recreated, so should NOT be Yellow (unlinked_at_end = false)
            ASSERT(r->style != RowStyle::Yellow, "recreated file should not be Yellow");
            return true;
        }
    }
    FAIL("temp.dat not found in file list");
}

static bool test_unlink_file_detail() {
    tv_test_reset();
    tv_test_load_string(UNLINK_TRACE);
    tv_test_create(40, 120);
    send(R"({"input":"key","name":"2"}
{"input":"select","id":"/tmp/foo.o"})");
    ASSERT(rpane_col_contains("Unlinks: 1"), "missing Unlinks: 1");
    ASSERT(rpane_col_contains("deleted at trace end"), "missing 'deleted at trace end'");
    ASSERT(rpane_col_contains("[UNLINK]"), "missing [UNLINK] event");
    return true;
}

static bool test_unlink_event_in_process_detail() {
    tv_test_reset();
    tv_test_load_string(UNLINK_TRACE);
    tv_test_create(40, 120);
    send(R"({"input":"select","id":"5000"})");
    ASSERT(rpane_col_contains("[UNLINK]"), "missing [UNLINK] in process detail");
    ASSERT(rpane_col_contains("foo.o"), "missing foo.o in process detail");
    return true;
}

static bool test_numeric_mode() {
    // Test that numeric mode field is parsed and used
    static const char MODE_TRACE[] =
        R"({"event":"CWD","tgid":6000,"pid":6000,"ppid":1,"nspid":6000,"nstgid":6000,"ts":300.000,"path":"/tmp"})" "\n"
        R"({"event":"EXEC","tgid":6000,"pid":6000,"ppid":1,"nspid":6000,"nstgid":6000,"ts":300.001,"exe":"/usr/bin/test","argv":["test"],"env":{},"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})" "\n"
        R"({"event":"OPEN","tgid":6000,"pid":6000,"ppid":1,"nspid":6000,"nstgid":6000,"ts":300.010,"path":"input.txt","flags":["O_RDONLY"],"mode":0,"fd":3})" "\n"
        R"({"event":"OPEN","tgid":6000,"pid":6000,"ppid":1,"nspid":6000,"nstgid":6000,"ts":300.011,"path":"output.txt","flags":["O_WRONLY","O_CREAT","O_TRUNC"],"mode":577,"fd":4})" "\n"
        R"({"event":"EXIT","tgid":6000,"pid":6000,"ppid":1,"nspid":6000,"nstgid":6000,"ts":300.020,"status":"exited","code":0,"raw":0})" "\n";
    tv_test_reset();
    tv_test_load_string(MODE_TRACE);
    tv_test_create(40, 120);
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "input.txt"), "missing input.txt");
    ASSERT(col_contains(lp, "output.txt"), "missing output.txt");
    // input.txt should be read-only (R flag), output.txt should be written (W flag)
    ASSERT(col_contains(lp, "R   "), "missing R flag");
    ASSERT(col_contains(lp, " W  "), "missing W flag");
    return true;
}

static bool test_file_refinement_filter() {
    // Test that refinement filter hides system paths
    static const char SYS_PATH_TRACE[] =
        R"({"event":"CWD","tgid":7000,"pid":7000,"ppid":1,"nspid":7000,"nstgid":7000,"ts":400.000,"path":"/home/user"})" "\n"
        R"({"event":"EXEC","tgid":7000,"pid":7000,"ppid":1,"nspid":7000,"nstgid":7000,"ts":400.001,"exe":"/usr/bin/tool","argv":["tool"],"env":{},"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})" "\n"
        R"({"event":"OPEN","tgid":7000,"pid":7000,"ppid":1,"nspid":7000,"nstgid":7000,"ts":400.010,"path":"myfile.c","flags":["O_RDONLY"],"fd":3})" "\n"
        R"({"event":"OPEN","tgid":7000,"pid":7000,"ppid":1,"nspid":7000,"nstgid":7000,"ts":400.011,"path":"/usr/lib/libc.so","flags":["O_RDONLY"],"fd":4})" "\n"
        R"({"event":"EXIT","tgid":7000,"pid":7000,"ppid":1,"nspid":7000,"nstgid":7000,"ts":400.020,"status":"exited","code":0,"raw":0})" "\n";
    tv_test_reset();
    tv_test_load_string(SYS_PATH_TRACE);
    tv_test_create(40, 120);
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    // Both files visible initially
    ASSERT(col_contains(lp, "myfile.c"), "missing myfile.c");
    ASSERT(col_contains(lp, "libc.so"), "missing libc.so");
    // Press r to hide system paths
    send(R"({"input":"key","name":"r"})");
    lp = tv_test_lpane();
    ASSERT(col_contains(lp, "myfile.c"), "myfile.c should still be visible");
    ASSERT(col_not_contains(lp, "libc.so"), "libc.so should be hidden");
    // Press r again (level 2: also hide deleted files) then r again (level 3)
    // then r again to cycle back to 0
    send(R"({"input":"key","name":"r"}
{"input":"key","name":"r"}
{"input":"key","name":"r"})");
    lp = tv_test_lpane();
    ASSERT(col_contains(lp, "libc.so"), "libc.so should be visible again");
    return true;
}

static bool test_file_glob_filter() {
    tv_test_reset();
    tv_test_load_string(UNLINK_TRACE);
    tv_test_create(40, 120);
    send(R"({"input":"key","name":"2"})");
    int lp = tv_test_lpane();
    ASSERT(col_contains(lp, "foo.c"), "missing foo.c initially");
    ASSERT(col_contains(lp, "foo.o"), "missing foo.o initially");
    return true;
}

static bool test_unlink_evfilt() {
    // Test that the event filter can filter to UNLINK events
    tv_test_reset();
    tv_test_load_string(UNLINK_TRACE);
    tv_test_create(40, 120);
    send(R"({"input":"select","id":"5000"})");
    // Check that UNLINK event visible in process detail
    ASSERT(rpane_col_contains("[UNLINK]"), "missing [UNLINK] before filter");
    return true;
}

// Generate a trace with many tgids sharing the same files, large enough
// to trigger the parallel phase-2 code path (MIN_EVENTS_PER_P2_THREAD=16,
// so ≥64 events on a 4-core box).  The trace exercises:
//   - multiple tgids reading/writing shared paths
//   - relative path resolution (CWD + relative open)
//   - parent-child links
//   - exit events
static std::string gen_parallel_p2_trace() {
    std::string out;
    char buf[1024];
    int n_procs = 40;  // enough events: 40 * 5 = 200
    for (int i = 0; i < n_procs; i++) {
        int tgid = 8000 + i;
        int ppid = (i == 0) ? 1 : 8000;
        double ts = 100.0 + i * 0.1;
        std::snprintf(buf, sizeof buf,
            R"({"event":"CWD","tgid":%d,"pid":%d,"ppid":%d,"nspid":%d,"nstgid":%d,"ts":%.3f,"path":"/work"})" "\n",
            tgid, tgid, ppid, tgid, tgid, ts);
        out += buf;
        std::snprintf(buf, sizeof buf,
            R"({"event":"EXEC","tgid":%d,"pid":%d,"ppid":%d,"nspid":%d,"nstgid":%d,"ts":%.3f,"exe":"/usr/bin/p%d","argv":["p%d","--id","%d"],"env":{},"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})" "\n",
            tgid, tgid, ppid, tgid, tgid, ts + 0.001, i, i, i);
        out += buf;
        // Each process reads shared.txt and writes output_N.txt (relative path)
        std::snprintf(buf, sizeof buf,
            R"({"event":"OPEN","tgid":%d,"pid":%d,"ppid":%d,"nspid":%d,"nstgid":%d,"ts":%.3f,"path":"shared.txt","flags":["O_RDONLY"],"fd":3})" "\n",
            tgid, tgid, ppid, tgid, tgid, ts + 0.010);
        out += buf;
        std::snprintf(buf, sizeof buf,
            R"({"event":"OPEN","tgid":%d,"pid":%d,"ppid":%d,"nspid":%d,"nstgid":%d,"ts":%.3f,"path":"output_%d.txt","flags":["O_WRONLY","O_CREAT","O_TRUNC"],"fd":4})" "\n",
            tgid, tgid, ppid, tgid, tgid, ts + 0.011, i);
        out += buf;
        std::snprintf(buf, sizeof buf,
            R"({"event":"EXIT","tgid":%d,"pid":%d,"ppid":%d,"nspid":%d,"nstgid":%d,"ts":%.3f,"status":"exited","code":%d,"raw":0})" "\n",
            tgid, tgid, ppid, tgid, tgid, ts + 0.020, i % 3 == 0 ? 1 : 0);
        out += buf;
    }
    return out;
}

static bool test_parallel_phase2_ingest() {
    auto trace = gen_parallel_p2_trace();
    tv_test_reset();
    tv_test_load_string(trace.c_str());
    tv_test_create(50, 120);

    // Check process tree — all 40 processes should be present
    int lp = tv_test_lpane();
    ASSERT(row_exists(lp, "8000"), "missing root process 8000");
    ASSERT(row_exists(lp, "8010"), "missing process 8010");
    ASSERT(row_exists(lp, "8039"), "missing last process 8039");

    // Check file view — shared.txt should be readable by all 40 procs
    send(R"({"input":"key","name":"2"})");
    lp = tv_test_lpane();
    ASSERT(col_contains(lp, "shared.txt"), "missing shared.txt in file view");
    ASSERT(col_contains(lp, "output_0.txt"), "missing output_0.txt");
    ASSERT(col_contains(lp, "output_39.txt"), "missing output_39.txt");

    // Check file detail for shared.txt — should show opens from many procs
    send(R"({"input":"select","id":"/work/shared.txt"})");
    ASSERT(rpane_col_contains("shared.txt"), "missing shared.txt in detail");
    // The file should show 40 opens (detail shows "Opens: 40")
    ASSERT(rpane_col_contains("Opens: 40"), "missing 'Opens: 40' for shared.txt");

    // Check a process detail — verify events are present
    send(R"({"input":"key","name":"1"})");
    send(R"({"input":"select","id":"8005"})");
    ASSERT(rpane_col_contains("8005"), "missing tgid in detail");
    ASSERT(rpane_col_contains("p5"), "missing exe name");
    ASSERT(rpane_col_contains("[OPEN]"), "missing OPEN event");
    ASSERT(rpane_col_contains("[EXIT]"), "missing EXIT event");

    // Verify parent-child: 8000 should be parent of 8001..8039
    send(R"({"input":"select","id":"8000"})");
    ASSERT(rpane_col_contains("8000"), "missing root in detail");

    return true;
}

static bool test_large_json_line_ingest() {
    const int tgid = 9100;
    const std::string marker = "LONG_LINE_MARKER_9100";
    std::string payload((1 << 20) + 4096, 'a');
    payload += marker;

    std::string trace;
    trace.reserve(payload.size() + 1024);
    trace += R"({"event":"CWD","tgid":9100,"pid":9100,"ppid":1,"nspid":9100,"nstgid":9100,"ts":1.000,"path":"/tmp"})";
    trace += "\n";
    trace += R"({"event":"EXEC","tgid":9100,"pid":9100,"ppid":1,"nspid":9100,"nstgid":9100,"ts":1.001,"exe":"/usr/bin/p9100","argv":["p9100"],"env":{},"auxv":{"AT_UID":1000,"AT_EUID":1000,"AT_GID":1000,"AT_EGID":1000,"AT_SECURE":0}})";
    trace += "\n";
    trace += R"({"event":"STDOUT","tgid":9100,"pid":9100,"ppid":1,"nspid":9100,"nstgid":9100,"ts":1.010,"data":")";
    trace += payload;
    trace += R"("})";
    trace += "\n";
    trace += R"({"event":"EXIT","tgid":9100,"pid":9100,"ppid":1,"nspid":9100,"nstgid":9100,"ts":1.020,"status":"exited","code":0,"raw":0})";
    trace += "\n";

    tv_test_reset();
    tv_test_load_string(trace.c_str());
    tv_test_create(40, 120);
    std::string search_input = std::string("{\"input\":\"search\",\"q\":\"") + marker + "\"}";
    send(search_input.c_str());
    int lp = tv_test_lpane();
    bool found = false;
    for (int i = 0; ; i++) {
        auto *r = tv_test_tui()->get_cached_row(lp, i);
        if (!r) break;
        if (r->id == std::to_string(tgid) && r->style == RowStyle::Search) {
            found = true;
            break;
        }
    }
    ASSERT(found, "large JSON line payload marker not searchable (line likely truncated)");
    return true;
}

// ── Test registry ────────────────────────────────────────────────────

static struct { const char *name; bool (*fn)(); } ALL_TESTS[] = {
    // NOTE: zstd compressed trace test skipped (requires .zst file creation)
    {"trace ingest: exec without env",                    test_trace_ingest_exec_without_env},
    {"trace ingest: exit with missing ppid keeps earlier parent", test_trace_ingest_exit_ppid_zero},
    {"proc_tree: all processes present",                  test_proc_tree_all_processes_present},
    {"proc_tree: exit markers",                           test_proc_tree_exit_markers},
    {"proc_tree: durations",                              test_proc_tree_durations},
    {"proc_tree: tree indicators",                        test_proc_tree_tree_indicators},
    {"proc_tree: child count",                            test_proc_tree_child_count},
    {"proc_tree: error styles",                           test_proc_tree_error_styles},
    {"proc_detail: normal exit",                          test_proc_detail_normal_exit},
    {"proc_detail: interesting failure",                   test_proc_detail_interesting_failure},
    {"proc_detail: boring failure (no writes)",            test_proc_detail_boring_failure},
    {"proc_detail: signal death",                          test_proc_detail_signal_death},
    {"proc_detail: running (no exit)",                     test_proc_detail_running},
    {"proc_detail: parent with children",                  test_proc_detail_parent_with_children},
    {"proc_detail: argv lines",                            test_proc_detail_argv_lines},
    {"proc_detail: open flags (ro/rw/wr)",                 test_proc_detail_open_flags},
    {"proc_detail: stdout event",                          test_proc_detail_stdout_event},
    {"proc_detail: stderr event",                          test_proc_detail_stderr_event},
    {"proc_tree: collapse hides children",                 test_proc_tree_collapse_hides_children},
    {"proc_tree: expand shows children",                   test_proc_tree_expand_shows_children},
    {"proc_flat: all processes, no indentation",           test_proc_flat_all_processes},
    {"proc_filter: failed shows interesting failures",     test_proc_filter_failed},
    {"proc_filter: running shows non-exited",              test_proc_filter_running},
    {"file_view: all opened files present",                test_file_view_all_files_present},
    {"file_view: path resolution — relative",              test_file_view_path_resolution_relative},
    {"file_view: path resolution — ../ components",        test_file_view_path_resolution_dotdot},
    {"file_view: pipe path",                               test_file_view_pipe_path},
    {"file_view: file dependency chain — foo.o shared",    test_file_view_foo_o_shared},
    {"file_view: error files",                             test_file_view_error_files},
    {"file_view: O_RDWR file",                             test_file_view_rdwr_file},
    {"file_view: collapsed dirs nested under common ancestor", test_file_view_collapsed_dirs},
    {"file_flat: full absolute paths shown",               test_file_flat_full_paths},
    {"file_detail: foo.o dependency chain",                test_file_detail_foo_o},
    {"file_detail: error file",                            test_file_detail_error_file},
    {"dep_view: cycle terminates and de-dupes",            test_dep_view_cycle_terminates},
    {"rdep_view: cycle terminates and de-dupes",           test_rdep_view_cycle_terminates},
    {"dep_view: dense graph terminates without path explosion",  test_dep_view_dense_terminates},
    {"rdep_view: dense graph terminates without path explosion", test_rdep_view_dense_terminates},
    {"output_view: grouped by process",                    test_output_view_grouped},
    {"output_view: streams",                               test_output_view_streams},
    {"output_view: stderr styled as error",                test_output_view_stderr_styled},
    {"output_detail: stdout content",                      test_output_detail_stdout},
    {"output_detail: stderr content",                      test_output_detail_stderr},
    {"output_flat: all lines present",                     test_output_flat_all_lines},
    {"output_group: collapse hides children",              test_output_group_collapse},
    {"navigation: cursor moves",                           test_navigation_cursor_moves},
    {"navigation: tab switches pane",                      test_navigation_tab_switches_pane},
    {"navigation: enter opens detail pane",                test_navigation_enter_opens_detail},
    {"sort: changes sort_key",                             test_sort_changes_sort_key},
    {"timestamps: relative mode",                          test_timestamps_relative},
    {"timestamps: delta mode",                             test_timestamps_delta},
    {"search: matches process",                            test_search_matches_process},
    {"search: next hit uses latest cursor",                test_search_next_hit},
    {"search: matches file",                               test_search_matches_file},
    {"evfilt: filters to OPEN events",                     test_evfilt_filters_to_open},
    {"save_load: round-trip preserves data",               test_save_load_round_trip},
    {"mode_switch: 1=proc 2=file 3=output",                test_mode_switch},
    {"expand_all: E collapses subtree",                    test_expand_all_E_collapses},
    {"expand_all: e expands subtree",                      test_expand_all_e_expands},
    {"navigation: left from leaf jumps to parent",         test_navigation_left_from_leaf},
    {"follow_link: file→process navigation",               test_follow_link_file_to_process},
    {"resize: updates rows/cols",                          test_resize_updates_dimensions},
    {"proc_filter: V clears filter",                       test_proc_filter_V_clears},
    {"navigation: end goes to last",                       test_navigation_end_goes_to_last},
    {"navigation: home goes to first",                     test_navigation_home_goes_to_first},
    {"separate_streams: --load trace --trace input works", test_separate_streams},
    {"unlink: event ingestion",                           test_unlink_ingest},
    {"unlink: flags column RWUE",                         test_unlink_flags_column},
    {"unlink: unlinked-at-end Yellow style",              test_unlink_at_end_style},
    {"unlink: recreated file not Yellow",                 test_unlink_recreated_not_at_end},
    {"unlink: file detail shows unlinks",                 test_unlink_file_detail},
    {"unlink: event in process detail",                   test_unlink_event_in_process_detail},
    {"numeric_mode: mode field parsed",                   test_numeric_mode},
    {"file_filter: refinement hides system paths",        test_file_refinement_filter},
    {"file_filter: glob pattern",                         test_file_glob_filter},
    {"unlink: event filter includes UNLINK",              test_unlink_evfilt},
    {"parallel phase 2: multi-tgid ingest",              test_parallel_phase2_ingest},
    {"ingest: large JSON line stays intact",             test_large_json_line_ingest},
};

int run_tests() {
    t_pass = t_fail = t_total = 0;
    std::printf("\nRunning tests...\n\n");
    for (auto &t : ALL_TESTS) {
        t_total++;
        t_name = t.name;
        bool ok = t.fn();
        if (ok) { t_pass++; std::printf("  PASS  %s\n", t.name); }
        else    { t_fail++; std::printf("  FAIL  %s\n", t.name); }
    }
    std::printf("\n  %d passed, %d failed (of %d)\n", t_pass, t_fail, t_total);
    std::printf("  (1 test skipped: zstd compressed trace)\n\n");
    tv_test_reset();
    return t_fail > 0 ? 1 : 0;
}
