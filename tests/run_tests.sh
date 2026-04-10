#!/bin/bash
# tests/run_tests.sh — test suite for tv
# Tests run by piping combined trace+input JSON streams into tv --trace /dev/stdin.
# Input events embedded in the stream: {"input":"nav","d":1}
# {"input":"resize","rows":50,"cols":120}  {"input":"select","id":"1003"}
# {"input":"search","q":"term"}  {"input":"evfilt","q":"OPEN"}
# {"input":"print","what":"lpane|rpane|state"}
set -eo pipefail

cd "$(dirname "$0")/.."
TV=./tv
TRACE=tests/trace.jsonl
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0 FAIL=0 TOTAL=0

# ── helpers ────────────────────────────────────────────────────────────

# $1 = input JSON lines (appended after the trace)
drive() {
    printf '%s\n' "$1" > "$TMPDIR/input.jsonl"
    cat "$TRACE" "$TMPDIR/input.jsonl" | "$TV" --trace /dev/stdin 2>&1
}

# $1 = db file, $2 = input JSON lines
drive_db() {
    printf '%s\n' "$2" > "$TMPDIR/input.jsonl"
    "$TV" --load "$1" --trace "$TMPDIR/input.jsonl" 2>&1
}

assert_contains() {
    if echo "$2" | grep -qF "$3"; then return 0
    else echo "    FAIL assert_contains: missing: $3"; return 1; fi
}

assert_not_contains() {
    if echo "$2" | grep -qF "$3"; then
        echo "    FAIL assert_not_contains: unexpected: $3"; return 1
    else return 0; fi
}

assert_line_match() {
    if echo "$2" | grep -qE "$3"; then return 0
    else echo "    FAIL assert_line_match: no match: $3"; return 1; fi
}

run_test() {
    TOTAL=$((TOTAL+1))
    local name="$1"; shift
    local ok=1
    for cmd in "$@"; do
        eval "$cmd" || ok=0
    done
    if [ $ok -eq 1 ]; then
        PASS=$((PASS+1)); echo "  PASS  $name"
    else
        FAIL=$((FAIL+1)); echo "  FAIL  $name"
    fi
}

# ── Step 0: Build ──────────────────────────────────────────────────────
echo "Building tv…"
make tv 2>/dev/null || { echo "Build failed"; exit 1; }

# ── Step 1: Ingest & save ─────────────────────────────────────────────
echo "Ingesting trace and saving DB…"
"$TV" --trace "$TRACE" --save "$TMPDIR/test.db"
[ -f "$TMPDIR/test.db" ] || { echo "Save failed"; exit 1; }

echo ""
echo "Running tests…"

# ═══════════════════════════════════════════════════════════════════════
# Test: process tree default view
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"print","what":"lpane"}')
run_test "proc_tree: all processes present" \
    'assert_contains t "$OUT" "|1000|"' \
    'assert_contains t "$OUT" "|1001|"' \
    'assert_contains t "$OUT" "|1002|"' \
    'assert_contains t "$OUT" "|1003|"' \
    'assert_contains t "$OUT" "|1004|"' \
    'assert_contains t "$OUT" "|1005|"' \
    'assert_contains t "$OUT" "|1006|"' \
    'assert_contains t "$OUT" "|1007|"' \
    'assert_contains t "$OUT" "|1008|"'

run_test "proc_tree: exit markers" \
    'assert_contains t "$OUT" "make ✗"' \
    'assert_contains t "$OUT" "[1001] gcc ✓"' \
    'assert_contains t "$OUT" "[1003] gcc ✗"' \
    'assert_contains t "$OUT" "segfault ⚡11"' \
    'assert_not_contains t "$OUT" "[1005] ld ✓"' \
    'assert_not_contains t "$OUT" "[1005] ld ✗"'

run_test "proc_tree: durations" \
    'assert_contains t "$OUT" "1.70s"' \
    'assert_contains t "$OUT" "100.0ms"' \
    'assert_contains t "$OUT" "30.0ms"'

run_test "proc_tree: tree indicators" \
    'assert_contains t "$OUT" "▼ [1000]"' \
    'assert_line_match t "$OUT" "    \[1001\]"'

run_test "proc_tree: child count" \
    'assert_contains t "$OUT" "(8)"'

run_test "proc_tree: error styles" \
    'assert_line_match t "$OUT" "^0\|error\|1000"' \
    'assert_line_match t "$OUT" "^3\|error\|1003"' \
    'assert_line_match t "$OUT" "^8\|error\|1008"' \
    'assert_line_match t "$OUT" "^1\|normal\|1001"' \
    'assert_line_match t "$OUT" "^5\|normal\|1005"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — normal exit (code 0)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1001"}
{"input":"print","what":"rpane"}')
run_test "proc_detail: normal exit" \
    'assert_contains t "$OUT" "TGID:  1001"' \
    'assert_contains t "$OUT" "PPID:  1000"' \
    'assert_contains t "$OUT" "EXE:   /usr/bin/gcc"' \
    'assert_contains t "$OUT" "Exit: exited code=0"' \
    'assert_line_match t "$OUT" "green\|Exit:"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — interesting failure (non-zero exit + writes)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1003"}
{"input":"print","what":"rpane"}')
run_test "proc_detail: interesting failure" \
    'assert_contains t "$OUT" "TGID:  1003"' \
    'assert_contains t "$OUT" "Exit: exited code=1"' \
    'assert_contains t "$OUT" "O_WRONLY|O_CREAT|O_TRUNC"' \
    'assert_contains t "$OUT" "broken.c"' \
    'assert_contains t "$OUT" "STDERR"' \
    'assert_line_match t "$OUT" "error\|Exit:"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — boring failure (non-zero exit, no writes)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1004"}
{"input":"print","what":"rpane"}')
run_test "proc_detail: boring failure (no writes)" \
    'assert_contains t "$OUT" "TGID:  1004"' \
    'assert_contains t "$OUT" "Exit: exited code=1"' \
    'assert_contains t "$OUT" "/nonexistent"' \
    'assert_contains t "$OUT" "err=2"' \
    'assert_not_contains t "$OUT" "O_WRONLY"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — signal death
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1008"}
{"input":"print","what":"rpane"}')
run_test "proc_detail: signal death" \
    'assert_contains t "$OUT" "TGID:  1008"' \
    'assert_contains t "$OUT" "Exit: signal 11 (core)"' \
    'assert_contains t "$OUT" "segfault"' \
    'assert_line_match t "$OUT" "error\|Exit: signal"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — running process (no exit event)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1005"}
{"input":"print","what":"rpane"}')
run_test "proc_detail: running (no exit)" \
    'assert_contains t "$OUT" "TGID:  1005"' \
    'assert_contains t "$OUT" "EXE:   /usr/bin/ld"' \
    'assert_not_contains t "$OUT" "Exit:"' \
    'assert_contains t "$OUT" "foo.o"' \
    'assert_contains t "$OUT" "bar.o"' \
    'assert_contains t "$OUT" "app"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — parent with children
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1000"}
{"input":"print","what":"rpane"}')
run_test "proc_detail: parent with children" \
    'assert_contains t "$OUT" "Children (8)"' \
    'assert_contains t "$OUT" "[1001] gcc"' \
    'assert_contains t "$OUT" "[1005] ld"' \
    'assert_contains t "$OUT" "[1008] segfault"' \
    'assert_contains t "$OUT" "PPID:  500"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — argv displayed correctly
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1003"}
{"input":"print","what":"rpane"}')
run_test "proc_detail: argv lines" \
    'assert_contains t "$OUT" "[0] gcc"' \
    'assert_contains t "$OUT" "[1] -c"' \
    'assert_contains t "$OUT" "[2] broken.c"' \
    'assert_contains t "$OUT" "[4] broken.o"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — open flags (ro, rw, write)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1007"}
{"input":"print","what":"rpane"}')
run_test "proc_detail: open flags (ro/rw/wr)" \
    'assert_contains t "$OUT" "deep.c [O_RDONLY]"' \
    'assert_contains t "$OUT" "common.h [O_RDONLY]"' \
    'assert_contains t "$OUT" "data.bin [O_RDWR]"' \
    'assert_contains t "$OUT" "deep.o [O_WRONLY|O_CREAT|O_TRUNC]"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — stdout event
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1000"}
{"input":"print","what":"rpane"}')
run_test "proc_detail: stdout event" \
    'assert_contains t "$OUT" "STDOUT"' \
    'assert_contains t "$OUT" "Makefile:5"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — stderr event
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1002"}
{"input":"print","what":"rpane"}')
run_test "proc_detail: stderr event" \
    'assert_contains t "$OUT" "STDERR"' \
    'assert_contains t "$OUT" "unused variable"'

# ═══════════════════════════════════════════════════════════════════════
# Test: collapse/expand in tree view
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1000"}
{"input":"left","id":"1000"}
{"input":"print","what":"lpane"}')
run_test "proc_tree: collapse hides children" \
    'assert_contains t "$OUT" "▶ [1000]"' \
    'assert_not_contains t "$OUT" "|1001|"' \
    'assert_not_contains t "$OUT" "|1005|"' \
    'assert_not_contains t "$OUT" "|1008|"'

OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1000"}
{"input":"left","id":"1000"}
{"input":"right","id":"1000"}
{"input":"print","what":"lpane"}')
run_test "proc_tree: expand shows children" \
    'assert_contains t "$OUT" "▼ [1000]"' \
    'assert_contains t "$OUT" "|1001|"' \
    'assert_contains t "$OUT" "|1008|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: flat mode
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"group"}
{"input":"print","what":"lpane"}')
run_test "proc_flat: all processes, no indentation" \
    'assert_contains t "$OUT" "[1000] make"' \
    'assert_contains t "$OUT" "[1001] gcc"' \
    'assert_contains t "$OUT" "[1008] segfault"' \
    'assert_not_contains t "$OUT" "▼"' \
    'assert_not_contains t "$OUT" "▶"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process filter — failed (interesting failures + ancestors)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"lpfilter","v":1}
{"input":"print","what":"lpane"}')
run_test "proc_filter: failed shows interesting failures" \
    'assert_contains t "$OUT" "|1000|"' \
    'assert_contains t "$OUT" "|1003|"' \
    'assert_contains t "$OUT" "|1008|"' \
    'assert_not_contains t "$OUT" "|1001|"' \
    'assert_not_contains t "$OUT" "|1002|"' \
    'assert_not_contains t "$OUT" "|1004|"' \
    'assert_not_contains t "$OUT" "|1005|"' \
    'assert_not_contains t "$OUT" "|1006|"' \
    'assert_not_contains t "$OUT" "|1007|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process filter — running (no EXIT + ancestors)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"lpfilter","v":1}
{"input":"lpfilter","v":2}
{"input":"print","what":"lpane"}')
run_test "proc_filter: running shows non-exited" \
    'assert_contains t "$OUT" "|1000|"' \
    'assert_contains t "$OUT" "|1005|"' \
    'assert_not_contains t "$OUT" "|1001|"' \
    'assert_not_contains t "$OUT" "|1003|"' \
    'assert_not_contains t "$OUT" "|1008|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: file view
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":1}
{"input":"print","what":"lpane"}')
run_test "file_view: all opened files present" \
    'assert_contains t "$OUT" "foo.c"' \
    'assert_contains t "$OUT" "bar.c"' \
    'assert_contains t "$OUT" "broken.c"' \
    'assert_contains t "$OUT" "foo.o"' \
    'assert_contains t "$OUT" "bar.o"' \
    'assert_contains t "$OUT" "Makefile"' \
    'assert_contains t "$OUT" "app"' \
    'assert_contains t "$OUT" "/nonexistent"'

run_test "file_view: path resolution — relative" \
    'assert_contains t "$OUT" "/home/user/project/foo.c"' \
    'assert_contains t "$OUT" "/home/user/project/sub/deep.c"'

run_test "file_view: path resolution — ../ components" \
    'assert_contains t "$OUT" "/home/user/project/../include/foo.h"' \
    'assert_contains t "$OUT" "/home/user/project/sub/../common.h"'

run_test "file_view: pipe path" \
    'assert_contains t "$OUT" "pipe:[12345]"'

run_test "file_view: file dependency chain — foo.o shared" \
    'assert_contains t "$OUT" "foo.o  [2 opens, 2 procs]"'

run_test "file_view: error files" \
    'assert_contains t "$OUT" "/nonexistent"' \
    'assert_contains t "$OUT" "1 errs"' \
    'assert_line_match t "$OUT" "error\|/nonexistent"'

run_test "file_view: O_RDWR file" \
    'assert_contains t "$OUT" "data.bin"'

# ═══════════════════════════════════════════════════════════════════════
# Test: file detail — dependency chain
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":1}
{"input":"select","id":"/home/user/project/foo.o"}
{"input":"print","what":"rpane"}')
run_test "file_detail: foo.o dependency chain" \
    'assert_contains t "$OUT" "─── File ───"' \
    'assert_contains t "$OUT" "foo.o"' \
    'assert_contains t "$OUT" "Opens: 2"' \
    'assert_contains t "$OUT" "Procs: 2"' \
    'assert_contains t "$OUT" "PID 1001"' \
    'assert_contains t "$OUT" "PID 1005"' \
    'assert_contains t "$OUT" "O_WRONLY"' \
    'assert_contains t "$OUT" "O_RDONLY"'

# ═══════════════════════════════════════════════════════════════════════
# Test: file detail — error file
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":1}
{"input":"select","id":"/nonexistent"}
{"input":"print","what":"rpane"}')
run_test "file_detail: error file" \
    'assert_contains t "$OUT" "/nonexistent"' \
    'assert_contains t "$OUT" "Errors: 1"' \
    'assert_contains t "$OUT" "PID 1004"' \
    'assert_line_match t "$OUT" "error.*err=2"'

# ═══════════════════════════════════════════════════════════════════════
# Test: output view
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":2}
{"input":"print","what":"lpane"}')
run_test "output_view: grouped by process" \
    'assert_contains t "$OUT" "PID 1002 gcc"' \
    'assert_contains t "$OUT" "PID 1003 gcc"' \
    'assert_contains t "$OUT" "PID 1004 cat"' \
    'assert_contains t "$OUT" "PID 1006 cat"' \
    'assert_contains t "$OUT" "PID 1000 make"'

run_test "output_view: streams" \
    'assert_contains t "$OUT" "STDERR"' \
    'assert_contains t "$OUT" "STDOUT"' \
    'assert_contains t "$OUT" "hello world"' \
    'assert_contains t "$OUT" "unused variable"' \
    'assert_contains t "$OUT" "undeclared identifier"' \
    'assert_contains t "$OUT" "No such file"'

run_test "output_view: stderr styled as error" \
    'assert_line_match t "$OUT" "error.*STDERR"'

# ═══════════════════════════════════════════════════════════════════════
# Test: output detail — stdout content
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":2}
{"input":"select","id":"28"}
{"input":"print","what":"rpane"}')
run_test "output_detail: stdout content" \
    'assert_contains t "$OUT" "─── Output ───"' \
    'assert_contains t "$OUT" "Stream: STDOUT"' \
    'assert_contains t "$OUT" "PID: 1006"' \
    'assert_contains t "$OUT" "─── Content ───"' \
    'assert_contains t "$OUT" "hello world"'

# ═══════════════════════════════════════════════════════════════════════
# Test: output detail — stderr content
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":2}
{"input":"select","id":"16"}
{"input":"print","what":"rpane"}')
run_test "output_detail: stderr content" \
    'assert_contains t "$OUT" "Stream: STDERR"' \
    'assert_contains t "$OUT" "PID: 1003"' \
    'assert_contains t "$OUT" "undeclared identifier"'

# ═══════════════════════════════════════════════════════════════════════
# Test: output view — flat mode (ungrouped)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":2}
{"input":"group"}
{"input":"print","what":"lpane"}')
run_test "output_flat: all lines present" \
    'assert_contains t "$OUT" "STDERR"' \
    'assert_contains t "$OUT" "STDOUT"' \
    'assert_not_contains t "$OUT" "── PID"'

# ═══════════════════════════════════════════════════════════════════════
# Test: output group expand/collapse
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":2}
{"input":"select","id":"io_1002"}
{"input":"left","id":"io_1002"}
{"input":"print","what":"lpane"}')
run_test "output_group: collapse hides children" \
    'assert_contains t "$OUT" "PID 1002"' \
    'assert_not_contains t "$OUT" "|11|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: navigation — cursor movement
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"print","what":"state"}
{"input":"nav","d":1}
{"input":"print","what":"state"}
{"input":"nav","d":1}
{"input":"nav","d":1}
{"input":"print","what":"state"}
{"input":"nav","d":-1}
{"input":"print","what":"state"}')
run_test "navigation: cursor moves" \
    'assert_line_match t "$OUT" "^cursor=0 "' \
    'assert_line_match t "$OUT" "^cursor=1 "' \
    'assert_line_match t "$OUT" "^cursor=3 "' \
    'assert_line_match t "$OUT" "^cursor=2 "'

# ═══════════════════════════════════════════════════════════════════════
# Test: navigation — pane switch
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"print","what":"state"}
{"input":"focus","v":-1}
{"input":"print","what":"state"}
{"input":"focus","v":-1}
{"input":"print","what":"state"}')
run_test "navigation: tab switches pane" \
    'assert_line_match t "$OUT" "^cursor=0.*focus=0"' \
    'assert_line_match t "$OUT" "focus=1"' \
    'assert_line_match t "$OUT" "^cursor=0 scroll=0 focus=0"'

# ═══════════════════════════════════════════════════════════════════════
# Test: navigation — enter and follow link
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1000"}
{"input":"focus","v":1}
{"input":"print","what":"state"}')
run_test "navigation: enter opens detail pane" \
    'assert_line_match t "$OUT" "focus=1"'

# ═══════════════════════════════════════════════════════════════════════
# Test: sort modes
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"sort"}
{"input":"print","what":"state"}
{"input":"print","what":"lpane"}')
run_test "sort: changes sort_key" \
    'assert_line_match t "$OUT" "sort_key=1"' \
    'assert_contains t "$OUT" "|1000|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: timestamp modes
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1001"}
{"input":"tsmode"}
{"input":"print","what":"rpane"}
{"input":"print","what":"state"}')
run_test "timestamps: relative mode" \
    'assert_line_match t "$OUT" "ts_mode=1"' \
    'assert_line_match t "$OUT" "\+[0-9]"'

OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1001"}
{"input":"tsmode"}
{"input":"tsmode"}
{"input":"print","what":"rpane"}
{"input":"print","what":"state"}')
run_test "timestamps: delta mode" \
    'assert_line_match t "$OUT" "ts_mode=2"' \
    'assert_contains t "$OUT" "Δ"'

# ═══════════════════════════════════════════════════════════════════════
# Test: search
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"search","q":"broken"}
{"input":"print","what":"lpane"}
{"input":"print","what":"state"}')
run_test "search: matches process" \
    'assert_line_match t "$OUT" "search\|1003"' \
    'assert_line_match t "$OUT" "search=broken"'

OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":1}
{"input":"search","q":"foo"}
{"input":"print","what":"lpane"}')
run_test "search: matches file" \
    'assert_line_match t "$OUT" "search.*foo"'

# ═══════════════════════════════════════════════════════════════════════
# Test: event filter
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1000"}
{"input":"evfilt","q":"open"}
{"input":"print","what":"rpane"}')
run_test "evfilt: filters to OPEN events" \
    'assert_contains t "$OUT" "OPEN"' \
    'assert_contains t "$OUT" "[OPEN]"' \
    'assert_not_contains t "$OUT" " EXEC "' \
    'assert_not_contains t "$OUT" " EXIT "'

# ═══════════════════════════════════════════════════════════════════════
# Test: save/load round-trip
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive_db "$TMPDIR/test.db" '{"input":"resize","rows":50,"cols":120}
{"input":"print","what":"lpane"}')
run_test "save_load: round-trip preserves data" \
    'assert_contains t "$OUT" "|1000|"' \
    'assert_contains t "$OUT" "|1001|"' \
    'assert_contains t "$OUT" "make ✗"'

# ═══════════════════════════════════════════════════════════════════════
# Test: mode switching
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":0}
{"input":"print","what":"state"}
{"input":"mode","m":1}
{"input":"print","what":"state"}
{"input":"mode","m":2}
{"input":"print","what":"state"}')
run_test "mode_switch: 1=proc 2=file 3=output" \
    'assert_line_match t "$OUT" "mode=0.*rows=50"' \
    'assert_line_match t "$OUT" "mode=1"' \
    'assert_line_match t "$OUT" "mode=2"'

# ═══════════════════════════════════════════════════════════════════════
# Test: expand all / collapse all
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1000"}
{"input":"collapse","id":"1000"}
{"input":"print","what":"lpane"}')
run_test "expand_all: E collapses subtree" \
    'assert_contains t "$OUT" "▶ [1000]"' \
    'assert_not_contains t "$OUT" "|1001|"'

OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1000"}
{"input":"collapse","id":"1000"}
{"input":"expand","id":"1000"}
{"input":"print","what":"lpane"}')
run_test "expand_all: e expands subtree" \
    'assert_contains t "$OUT" "▼ [1000]"' \
    'assert_contains t "$OUT" "|1001|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: navigate to parent via left arrow
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"select","id":"1003"}
{"input":"left","id":"1003"}
{"input":"print","what":"state"}')
run_test "navigation: left from leaf jumps to parent" \
    'assert_line_match t "$OUT" "cursor=0"'

# ═══════════════════════════════════════════════════════════════════════
# Test: follow link from rpane
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"mode","m":1}
{"input":"select","id":"/home/user/project/foo.o"}
{"input":"focus","v":1}
{"input":"nav","d":1}
{"input":"nav","d":1}
{"input":"nav","d":1}
{"input":"nav","d":1}
{"input":"follow"}
{"input":"print","what":"state"}
{"input":"print","what":"lpane"}')
run_test "follow_link: file→process navigation" \
    'assert_line_match t "$OUT" "mode=0"'

# ═══════════════════════════════════════════════════════════════════════
# Test: resize changes dimensions
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":30,"cols":100}
{"input":"print","what":"state"}
{"input":"resize","rows":60,"cols":200}
{"input":"print","what":"state"}')
run_test "resize: updates rows/cols" \
    'assert_line_match t "$OUT" "rows=30 cols=100"' \
    'assert_line_match t "$OUT" "rows=60 cols=200"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process filter clear
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"lpfilter","v":1}
{"input":"lpfilter","v":0}
{"input":"print","what":"lpane"}
{"input":"print","what":"state"}')
run_test "proc_filter: V clears filter" \
    'assert_line_match t "$OUT" "lp_filter=0"' \
    'assert_contains t "$OUT" "|1001|"' \
    'assert_contains t "$OUT" "|1004|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: home/end navigation
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"goto","v":1}
{"input":"print","what":"state"}')
run_test "navigation: end goes to last" \
    'assert_line_match t "$OUT" "cursor=8"'

OUT=$(drive '{"input":"resize","rows":50,"cols":120}
{"input":"goto","v":1}
{"input":"goto","v":0}
{"input":"print","what":"state"}')
run_test "navigation: home goes to first" \
    'assert_line_match t "$OUT" "cursor=0"'

# ═══════════════════════════════════════════════════════════════════════
# Test: input events can be catted directly (same format as trace)
# ═══════════════════════════════════════════════════════════════════════
# Verify that the stream is truly unified: no separate driver file needed
printf '%s\n' \
    '{"input":"resize","rows":50,"cols":120}' \
    '{"input":"mode","m":1}' \
    '{"input":"print","what":"lpane"}' \
    > "$TMPDIR/input_only.jsonl"
OUT=$(cat "$TRACE" "$TMPDIR/input_only.jsonl" | "$TV" --trace /dev/stdin 2>&1)
run_test "unified_stream: cat trace+input works" \
    'assert_contains t "$OUT" "foo.c"' \
    'assert_contains t "$OUT" "bar.c"' \
    'assert_contains t "$OUT" "=== LPANE ==="'

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════"
echo "  $PASS passed, $FAIL failed (of $TOTAL)"
echo "═══════════════════════════════════════"
[ "$FAIL" -eq 0 ]
