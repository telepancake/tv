#!/bin/bash
# Test runner for tv direct-drive mode.
# Usage: bash tests/run_tests.sh
#
# On first run (or when expected/ files are missing), generates expected outputs.
# On subsequent runs, compares against them.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
TV="$REPO_DIR/tv"
DB="/tmp/tv_test_$$.db"
PASS=0; FAIL=0

cleanup() { rm -f "$DB"; }
trap cleanup EXIT

# Build if stale
if [ ! -x "$TV" ] || [ "$REPO_DIR/tv.c" -nt "$TV" ]; then
    echo "Building tv..."
    make -C "$REPO_DIR" tv
fi

# Ingest sample trace into a temporary DB
"$TV" --ingest "$SCRIPT_DIR/trace.jsonl" --save "$DB"

run_test() {
    local name="$1"
    local spec="$2"
    local expected="$SCRIPT_DIR/expected/${name}.txt"
    local actual
    actual=$("$TV" --load "$DB" --dd "$spec")
    if [ ! -f "$expected" ]; then
        mkdir -p "$SCRIPT_DIR/expected"
        printf '%s\n' "$actual" > "$expected"
        echo "GENERATED: $name"
        PASS=$((PASS+1))
        return
    fi
    if diff -u "$expected" <(printf '%s\n' "$actual") > /dev/null 2>&1; then
        echo "PASS: $name"
        PASS=$((PASS+1))
    else
        echo "FAIL: $name"
        diff -u "$expected" <(printf '%s\n' "$actual") || true
        FAIL=$((FAIL+1))
    fi
}

# ── Process view ─────────────────────────────────────────────────────────────

# Tree view: all 8 processes; make has 7 descendants; durations correct
run_test procs_tree \
    '{"rows":30,"cols":100,"mode":0,"grouped":1,"pane":"left"}'

# Flat view: ordered by tgid; no tree indent; no child-count decoration
run_test procs_flat \
    '{"rows":30,"cols":100,"mode":0,"grouped":0,"pane":"left"}'

# Collapsed root: 1000 collapsed → only root visible with ▶ indicator
run_test procs_collapsed \
    '{"rows":30,"cols":100,"mode":0,"grouped":1,"collapse":["1000"],"pane":"left"}'

# Filter: failed (interesting = signal OR non-zero-exit+writes); boring failures hidden
# Expected: make (ancestor), gcc bar.c (code=1 + O_WRONLY), prog (SIGSEGV)
# NOT shown: gcc baz.c (code=1 but no writes = boring failure)
run_test filter_failed \
    '{"rows":30,"cols":100,"mode":0,"grouped":1,"lp_filter":1,"pane":"left"}'

# Filter: running (no EXIT event); expected: make (ancestor), ld (still running)
run_test filter_running \
    '{"rows":30,"cols":100,"mode":0,"grouped":1,"lp_filter":2,"pane":"left"}'

# ── File view ────────────────────────────────────────────────────────────────

# Files: includes pipe:[88231] (not prefixed with CWD), /build/subdir/../bar.c
# (relative path with ../ stored as-is), nosuchfile.h with error count
run_test files \
    '{"rows":30,"cols":100,"mode":1,"pane":"left"}'

# ── Output view ──────────────────────────────────────────────────────────────

# Outputs: STDOUT and STDERR events grouped by process
run_test outputs \
    '{"rows":30,"cols":100,"mode":2,"pane":"left"}'

# ── Right pane: process detail ───────────────────────────────────────────────

# Clean success: relative path resolved (foo.c → /build/foo.c), O_WRONLY open, STDOUT
run_test rpane_proc1001 \
    '{"rows":30,"cols":100,"mode":0,"select_id":"1001","pane":"right"}'

# Interesting failure: code=1, CWD=/build/subdir, relative ../bar.c path, STDERR
run_test rpane_proc1002 \
    '{"rows":30,"cols":100,"mode":0,"select_id":"1002","pane":"right"}'

# Non-exited (running) process: no Exit line, O_RDONLY + O_RDWR opens (dep chain)
run_test rpane_proc1004 \
    '{"rows":30,"cols":100,"mode":0,"select_id":"1004","pane":"right"}'

# Signaled process: signal=11 (SIGSEGV), core dumped, single-element argv
run_test rpane_proc1007 \
    '{"rows":30,"cols":100,"mode":0,"select_id":"1007","pane":"right"}'

# ── Right pane: file detail ───────────────────────────────────────────────────

# File dependency chain: foo.o written by gcc (1001), read by ld (1004)
run_test rpane_file_foo_o \
    '{"rows":30,"cols":100,"mode":1,"select_id":"/build/foo.o","pane":"right"}'

# Failed open: nosuchfile.h with err=-2 (ENOENT), 1 error count
run_test rpane_file_nosuchfile \
    '{"rows":30,"cols":100,"mode":1,"select_id":"/build/nosuchfile.h","pane":"right"}'

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
