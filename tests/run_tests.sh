#!/bin/bash
# tests/run_tests.sh — test suite for tv
# Uses the "direct drive" mode (--trace / --drive) to exercise the same code
# paths that are used interactively.
set -eo pipefail

cd "$(dirname "$0")/.."
TV=./tv
TRACE=tests/trace.jsonl
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0 FAIL=0 TOTAL=0

# ── helpers ────────────────────────────────────────────────────────────

drive() {                        # $1 = drive script (multiline string)
    echo "$1" > "$TMPDIR/drive.txt"
    "$TV" --trace "$TRACE" --drive "$TMPDIR/drive.txt" 2>&1
}

drive_db() {                     # $1 = db, $2 = drive script
    echo "$2" > "$TMPDIR/drive.txt"
    "$TV" --load "$1" --drive "$TMPDIR/drive.txt" 2>&1
}

assert_contains() {              # $1 = label, $2 = haystack, $3 = needle
    if echo "$2" | grep -qF "$3"; then return 0
    else echo "    FAIL assert_contains: missing: $3"; return 1; fi
}

assert_not_contains() {          # $1 = label, $2 = haystack, $3 = needle
    if echo "$2" | grep -qF "$3"; then
        echo "    FAIL assert_not_contains: unexpected: $3"; return 1
    else return 0; fi
}

assert_line_match() {            # $1 = label, $2 = haystack, $3 = regex
    if echo "$2" | grep -qE "$3"; then return 0
    else echo "    FAIL assert_line_match: no match: $3"; return 1; fi
}

run_test() {                     # $1 = name, $2+ = assertion commands
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
OUT=$(drive "resize 50 120
print lpane")
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
OUT=$(drive "resize 50 120
select 1001
print rpane")
run_test "proc_detail: normal exit" \
    'assert_contains t "$OUT" "TGID:  1001"' \
    'assert_contains t "$OUT" "PPID:  1000"' \
    'assert_contains t "$OUT" "EXE:   /usr/bin/gcc"' \
    'assert_contains t "$OUT" "Exit: exited code=0"' \
    'assert_line_match t "$OUT" "green\|Exit:"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — interesting failure (non-zero exit + writes)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1003
print rpane")
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
OUT=$(drive "resize 50 120
select 1004
print rpane")
run_test "proc_detail: boring failure (no writes)" \
    'assert_contains t "$OUT" "TGID:  1004"' \
    'assert_contains t "$OUT" "Exit: exited code=1"' \
    'assert_contains t "$OUT" "/nonexistent"' \
    'assert_contains t "$OUT" "err=2"' \
    'assert_not_contains t "$OUT" "O_WRONLY"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — signal death
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1008
print rpane")
run_test "proc_detail: signal death" \
    'assert_contains t "$OUT" "TGID:  1008"' \
    'assert_contains t "$OUT" "Exit: signal 11 (core)"' \
    'assert_contains t "$OUT" "segfault"' \
    'assert_line_match t "$OUT" "error\|Exit: signal"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — running process (no exit event)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1005
print rpane")
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
OUT=$(drive "resize 50 120
select 1000
print rpane")
run_test "proc_detail: parent with children" \
    'assert_contains t "$OUT" "Children (8)"' \
    'assert_contains t "$OUT" "[1001] gcc"' \
    'assert_contains t "$OUT" "[1005] ld"' \
    'assert_contains t "$OUT" "[1008] segfault"' \
    'assert_contains t "$OUT" "PPID:  500"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — argv displayed correctly
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1003
print rpane")
run_test "proc_detail: argv lines" \
    'assert_contains t "$OUT" "[0] gcc"' \
    'assert_contains t "$OUT" "[1] -c"' \
    'assert_contains t "$OUT" "[2] broken.c"' \
    'assert_contains t "$OUT" "[4] broken.o"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — open flags (ro, rw, write)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1007
print rpane")
run_test "proc_detail: open flags (ro/rw/wr)" \
    'assert_contains t "$OUT" "deep.c [O_RDONLY]"' \
    'assert_contains t "$OUT" "common.h [O_RDONLY]"' \
    'assert_contains t "$OUT" "data.bin [O_RDWR]"' \
    'assert_contains t "$OUT" "deep.o [O_WRONLY|O_CREAT|O_TRUNC]"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — stdout event
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1000
print rpane")
run_test "proc_detail: stdout event" \
    'assert_contains t "$OUT" "STDOUT"' \
    'assert_contains t "$OUT" "Makefile:5"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process detail — stderr event
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1002
print rpane")
run_test "proc_detail: stderr event" \
    'assert_contains t "$OUT" "STDERR"' \
    'assert_contains t "$OUT" "unused variable"'

# ═══════════════════════════════════════════════════════════════════════
# Test: collapse/expand in tree view
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1000
key left
print lpane")
run_test "proc_tree: collapse hides children" \
    'assert_contains t "$OUT" "▶ [1000]"' \
    'assert_not_contains t "$OUT" "|1001|"' \
    'assert_not_contains t "$OUT" "|1005|"' \
    'assert_not_contains t "$OUT" "|1008|"'

OUT=$(drive "resize 50 120
select 1000
key left
key right
print lpane")
run_test "proc_tree: expand shows children" \
    'assert_contains t "$OUT" "▼ [1000]"' \
    'assert_contains t "$OUT" "|1001|"' \
    'assert_contains t "$OUT" "|1008|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: flat mode
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key G
print lpane")
run_test "proc_flat: all processes, no indentation" \
    'assert_contains t "$OUT" "[1000] make"' \
    'assert_contains t "$OUT" "[1001] gcc"' \
    'assert_contains t "$OUT" "[1008] segfault"' \
    'assert_not_contains t "$OUT" "▼"' \
    'assert_not_contains t "$OUT" "▶"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process filter — failed (interesting failures + ancestors)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key v
print lpane")
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
OUT=$(drive "resize 50 120
key v
key v
print lpane")
run_test "proc_filter: running shows non-exited" \
    'assert_contains t "$OUT" "|1000|"' \
    'assert_contains t "$OUT" "|1005|"' \
    'assert_not_contains t "$OUT" "|1001|"' \
    'assert_not_contains t "$OUT" "|1003|"' \
    'assert_not_contains t "$OUT" "|1008|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: file view
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key 2
print lpane")
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
OUT=$(drive "resize 50 120
key 2
select /home/user/project/foo.o
print rpane")
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
OUT=$(drive "resize 50 120
key 2
select /nonexistent
print rpane")
run_test "file_detail: error file" \
    'assert_contains t "$OUT" "/nonexistent"' \
    'assert_contains t "$OUT" "Errors: 1"' \
    'assert_contains t "$OUT" "PID 1004"' \
    'assert_line_match t "$OUT" "error.*err=2"'

# ═══════════════════════════════════════════════════════════════════════
# Test: output view
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key 3
print lpane")
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
OUT=$(drive "resize 50 120
key 3
select 28
print rpane")
run_test "output_detail: stdout content" \
    'assert_contains t "$OUT" "─── Output ───"' \
    'assert_contains t "$OUT" "Stream: STDOUT"' \
    'assert_contains t "$OUT" "PID: 1006"' \
    'assert_contains t "$OUT" "─── Content ───"' \
    'assert_contains t "$OUT" "hello world"'

# ═══════════════════════════════════════════════════════════════════════
# Test: output detail — stderr content
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key 3
select 16
print rpane")
run_test "output_detail: stderr content" \
    'assert_contains t "$OUT" "Stream: STDERR"' \
    'assert_contains t "$OUT" "PID: 1003"' \
    'assert_contains t "$OUT" "undeclared identifier"'

# ═══════════════════════════════════════════════════════════════════════
# Test: output view — flat mode (ungrouped)
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key 3
key G
print lpane")
run_test "output_flat: all lines present" \
    'assert_contains t "$OUT" "STDERR"' \
    'assert_contains t "$OUT" "STDOUT"' \
    'assert_not_contains t "$OUT" "── PID"'

# ═══════════════════════════════════════════════════════════════════════
# Test: output group expand/collapse
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key 3
select io_1002
key left
print lpane")
run_test "output_group: collapse hides children" \
    'assert_contains t "$OUT" "PID 1002"' \
    'assert_not_contains t "$OUT" "|11|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: navigation — cursor movement
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
print state
key j
print state
key j
key j
print state
key k
print state")
run_test "navigation: cursor moves" \
    'assert_line_match t "$OUT" "^cursor=0 "' \
    'assert_line_match t "$OUT" "^cursor=1 "' \
    'assert_line_match t "$OUT" "^cursor=3 "' \
    'assert_line_match t "$OUT" "^cursor=2 "'

# ═══════════════════════════════════════════════════════════════════════
# Test: navigation — pane switch
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
print state
key tab
print state
key tab
print state")
run_test "navigation: tab switches pane" \
    'assert_line_match t "$OUT" "^cursor=0.*focus=0"' \
    'assert_line_match t "$OUT" "focus=1"' \
    'assert_line_match t "$OUT" "^cursor=0 scroll=0 focus=0"'

# ═══════════════════════════════════════════════════════════════════════
# Test: navigation — enter and follow link
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1000
key enter
print state")
run_test "navigation: enter opens detail pane" \
    'assert_line_match t "$OUT" "focus=1"'

# ═══════════════════════════════════════════════════════════════════════
# Test: sort modes
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key s
print state
print lpane")
run_test "sort: changes sort_key" \
    'assert_line_match t "$OUT" "sort_key=1"' \
    'assert_contains t "$OUT" "|1000|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: timestamp modes
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1001
key t
print rpane
print state")
run_test "timestamps: relative mode" \
    'assert_line_match t "$OUT" "ts_mode=1"' \
    'assert_line_match t "$OUT" "\+[0-9]"'

OUT=$(drive "resize 50 120
select 1001
key t
key t
print rpane
print state")
run_test "timestamps: delta mode" \
    'assert_line_match t "$OUT" "ts_mode=2"' \
    'assert_contains t "$OUT" "Δ"'

# ═══════════════════════════════════════════════════════════════════════
# Test: search
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
search broken
print lpane
print state")
run_test "search: matches process" \
    'assert_line_match t "$OUT" "search\|1003"' \
    'assert_line_match t "$OUT" "search=broken"'

OUT=$(drive "resize 50 120
key 2
search foo
print lpane")
run_test "search: matches file" \
    'assert_line_match t "$OUT" "search.*foo"'

# ═══════════════════════════════════════════════════════════════════════
# Test: event filter
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1000
evfilt open
print rpane")
run_test "evfilt: filters to OPEN events" \
    'assert_contains t "$OUT" "OPEN"' \
    'assert_contains t "$OUT" "[OPEN]"' \
    'assert_not_contains t "$OUT" " EXEC "' \
    'assert_not_contains t "$OUT" " EXIT "'

# ═══════════════════════════════════════════════════════════════════════
# Test: save/load round-trip
# ═══════════════════════════════════════════════════════════════════════
OUT_ORIG=$(drive "resize 50 120
print lpane")
OUT_LOAD=$(drive_db "$TMPDIR/test.db" "resize 50 120
print lpane")
run_test "save_load: round-trip preserves data" \
    'assert_contains t "$OUT_LOAD" "|1000|"' \
    'assert_contains t "$OUT_LOAD" "|1001|"' \
    'assert_contains t "$OUT_LOAD" "make ✗"'

# ═══════════════════════════════════════════════════════════════════════
# Test: mode switching
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key 1
print state
key 2
print state
key 3
print state")
run_test "mode_switch: 1=proc 2=file 3=output" \
    'assert_line_match t "$OUT" "mode=0.*rows=50"' \
    'assert_line_match t "$OUT" "mode=1"' \
    'assert_line_match t "$OUT" "mode=2"'

# ═══════════════════════════════════════════════════════════════════════
# Test: expand all / collapse all
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1000
key E
print lpane")
run_test "expand_all: E collapses subtree" \
    'assert_contains t "$OUT" "▶ [1000]"' \
    'assert_not_contains t "$OUT" "|1001|"'

OUT=$(drive "resize 50 120
select 1000
key E
key e
print lpane")
run_test "expand_all: e expands subtree" \
    'assert_contains t "$OUT" "▼ [1000]"' \
    'assert_contains t "$OUT" "|1001|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: navigate to parent via left arrow
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
select 1003
key left
print state")
run_test "navigation: left from leaf jumps to parent" \
    'assert_line_match t "$OUT" "cursor=0"'

# ═══════════════════════════════════════════════════════════════════════
# Test: follow link from rpane
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key 2
select /home/user/project/foo.o
key tab
# cursor to first access line (with PID link)
key j
key j
key j
key j
key enter
print state
print lpane")
run_test "follow_link: file→process navigation" \
    'assert_line_match t "$OUT" "mode=0"'

# ═══════════════════════════════════════════════════════════════════════
# Test: resize changes dimensions
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 30 100
print state
resize 60 200
print state")
run_test "resize: updates rows/cols" \
    'assert_line_match t "$OUT" "rows=30 cols=100"' \
    'assert_line_match t "$OUT" "rows=60 cols=200"'

# ═══════════════════════════════════════════════════════════════════════
# Test: process filter clear
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key v
key V
print lpane
print state")
run_test "proc_filter: V clears filter" \
    'assert_line_match t "$OUT" "lp_filter=0"' \
    'assert_contains t "$OUT" "|1001|"' \
    'assert_contains t "$OUT" "|1004|"'

# ═══════════════════════════════════════════════════════════════════════
# Test: home/end navigation
# ═══════════════════════════════════════════════════════════════════════
OUT=$(drive "resize 50 120
key end
print state")
run_test "navigation: end goes to last" \
    'assert_line_match t "$OUT" "cursor=8"'

OUT=$(drive "resize 50 120
key end
key home
print state")
run_test "navigation: home goes to first" \
    'assert_line_match t "$OUT" "cursor=0"'

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════"
echo "  $PASS passed, $FAIL failed (of $TOTAL)"
echo "═══════════════════════════════════════"
[ "$FAIL" -eq 0 ]
