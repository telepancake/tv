#!/bin/bash
# Test runner for tv.
#
# Phase 1 (ingest): TV_TRACE_PATH feeds the trace through the existing streaming
#   code path; --dd '["W"]' presses the 'W' (save) key via handle_key(), and
#   TV_SAVE_PATH makes save_db() write to the given path without a tty prompt.
#
# Phase 2 (navigation): --load + --dd inject keystroke sequences through
#   handle_key() to verify the UI state machine (cursor, mode, filter, etc.).
#
# Usage: bash tests/run_tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
TV="$REPO_DIR/tv"
BASE_DB="/tmp/tv_base_$$.db"
NAV_DB="/tmp/tv_nav_$$.db"
PASS=0; FAIL=0

cleanup() { rm -f "$BASE_DB" "$NAV_DB"; }
trap cleanup EXIT

# Build if stale
if [ ! -x "$TV" ] || [ "$REPO_DIR/tv.c" -nt "$TV" ]; then
    echo "Building tv..."
    make -C "$REPO_DIR" tv
fi

# ── Phase 1: ingest trace via existing streaming code path ──────────────────
# TV_TRACE_PATH overrides /proc/proctrace/new with the JSONL fixture.
# --dd '["W"]' presses the save key (W) through handle_key() after trace EOF.
# TV_SAVE_PATH is used by save_db() instead of a tty prompt.
TV_TRACE_PATH="$SCRIPT_DIR/trace.jsonl" TV_SAVE_PATH="$BASE_DB" \
    "$TV" --dd '["W"]' -- /bin/true 2>/dev/null
echo "Trace ingested → $BASE_DB"

# ── Assertion helpers ────────────────────────────────────────────────────────

q()  { sqlite3 "$BASE_DB" "$1"; }
qn() { sqlite3 "$NAV_DB"  "$1"; }

assert_eq() {
    local expected="$1" actual="$2" label="$3"
    if [ "$actual" = "$expected" ]; then
        echo "PASS: $label"
        PASS=$((PASS+1))
    else
        echo "FAIL: $label — expected '$expected', got '$actual'"
        FAIL=$((FAIL+1))
    fi
}

# ── Phase 1 tests: data model correctness ────────────────────────────────────

# T1: All 8 processes ingested (PIDs 1000–1007)
assert_eq 8 "$(q "SELECT COUNT(*) FROM processes")" \
    "process count"

# T2: make (1000) is the parent with exactly 7 children
assert_eq 7 "$(q "SELECT COUNT(*) FROM processes WHERE ppid=1000")" \
    "make child count"

# T3: gcc (1001) exited cleanly (code=0)
assert_eq 0 "$(q "SELECT x.code FROM exit_events x
    JOIN events e ON e.id=x.eid WHERE e.tgid=1001")" \
    "gcc 1001 exit code"

# T4: gcc (1002) failed with exit code 1
assert_eq 1 "$(q "SELECT x.code FROM exit_events x
    JOIN events e ON e.id=x.eid WHERE e.tgid=1002")" \
    "gcc 1002 exit code"

# T5: gcc (1003) failed with exit code 1 (boring: no writes, just failed open)
assert_eq 1 "$(q "SELECT x.code FROM exit_events x
    JOIN events e ON e.id=x.eid WHERE e.tgid=1003")" \
    "gcc 1003 exit code"

# T6: ld (1004) has no EXIT event (still running / no exit recorded)
assert_eq 0 "$(q "SELECT COUNT(*) FROM events WHERE tgid=1004 AND event='EXIT'")" \
    "ld no exit"

# T7: prog (1007) was killed by signal 11 (SIGSEGV)
assert_eq 11 "$(q "SELECT x.signal FROM exit_events x
    JOIN events e ON e.id=x.eid WHERE e.tgid=1007")" \
    "prog signal 11"

# T8: prog (1007) has core_dumped=1
assert_eq 1 "$(q "SELECT x.core_dumped FROM exit_events x
    JOIN events e ON e.id=x.eid WHERE e.tgid=1007")" \
    "prog core dumped"

# T9: foo.o was opened by exactly 2 processes (gcc write, ld read)
assert_eq 2 "$(q "SELECT COUNT(*) FROM open_events WHERE path='/build/foo.o'")" \
    "foo.o open count"

# T10: nosuchfile.h has err=-2 (ENOENT) on open
assert_eq "-2" "$(q "SELECT err FROM open_events WHERE path='/build/nosuchfile.h' LIMIT 1")" \
    "nosuchfile.h open error"

# T11: pipe:[88231] paths are NOT prefixed with CWD
assert_eq 2 "$(q "SELECT COUNT(*) FROM open_events WHERE path='pipe:[88231]'")" \
    "pipe path not CWD-prefixed"

# T12: STDOUT event captured for gcc (1001) — "Compiling foo.c"
assert_eq 1 "$(q "SELECT COUNT(*) FROM io_events i
    JOIN events e ON e.id=i.eid WHERE e.tgid=1001 AND i.stream='STDOUT'")" \
    "gcc stdout event"

# T13: STDERR event captured for gcc (1002) — compiler error
assert_eq 1 "$(q "SELECT COUNT(*) FROM io_events i
    JOIN events e ON e.id=i.eid WHERE e.tgid=1002 AND i.stream='STDERR'")" \
    "gcc stderr event"

# T14: STDERR event captured for prog (1007) — segfault message
assert_eq 1 "$(q "SELECT COUNT(*) FROM io_events i
    JOIN events e ON e.id=i.eid WHERE e.tgid=1007 AND i.stream='STDERR'")" \
    "prog stderr event"

# T15: make duration = last_ts - first_ts = 9.5 - 1.0 = 8.5
assert_eq "8.5" "$(q "SELECT last_ts - first_ts FROM processes WHERE tgid=1000")" \
    "make duration"

# T16: ld duration = 5.25 - 5.0 = 0.25
assert_eq "0.25" "$(q "SELECT last_ts - first_ts FROM processes WHERE tgid=1004")" \
    "ld duration"

# T17: CWD recorded for each process (make=1000 → /build)
assert_eq "/build" "$(q "SELECT cwd FROM processes WHERE tgid=1000")" \
    "make CWD"

# T18: subdir CWD recorded for gcc 1002 (/build/subdir)
assert_eq "/build/subdir" "$(q "SELECT cwd FROM processes WHERE tgid=1002")" \
    "gcc 1002 CWD"

# T19: relative path from subdir resolved against CWD for the read-only open
#      ../bar.c from /build/subdir → stored as /build/subdir/../bar.c
assert_eq 1 "$(q "SELECT COUNT(*) FROM open_events WHERE path='/build/subdir/../bar.c'")" \
    "relative path resolution"

# T20: absolute path open stored as-is (/build/bar.o from gcc 1002)
assert_eq 1 "$(q "SELECT COUNT(*) FROM open_events WHERE path='/build/bar.o'
    AND eid IN(SELECT id FROM events WHERE tgid=1002)")" \
    "absolute path stored as-is"

# T21: FTS index built (has_fts=1 in state)
assert_eq 1 "$(q "SELECT has_fts FROM state")" \
    "FTS index built"

# T22: base_ts set to earliest event timestamp (1.0)
assert_eq "1.0" "$(q "SELECT base_ts FROM state")" \
    "base_ts set"

# T23: argv split correctly — make has 'all' as second arg
assert_eq "all" "$(q "SELECT TRIM(SUBSTR(argv, INSTR(argv, char(10))+1))
    FROM processes WHERE tgid=1000")" \
    "make argv[1]"

# T24: single-arg process (prog/1007) has argv without duplicates
#      (regression: argv CTE bug caused single-element argv to appear twice)
assert_eq 1 "$(q "WITH RECURSIVE sp(i,rest,line) AS(
    SELECT 0,
      CASE WHEN INSTR(argv,char(10))>0 THEN SUBSTR(argv,INSTR(argv,char(10))+1) ELSE '' END,
      CASE WHEN INSTR(argv,char(10))>0 THEN SUBSTR(argv,1,INSTR(argv,char(10))-1) ELSE argv END
    FROM processes WHERE tgid=1007 AND argv IS NOT NULL
  UNION ALL SELECT i+1,
      CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,INSTR(rest,char(10))+1) ELSE '' END,
      CASE WHEN INSTR(rest,char(10))>0 THEN SUBSTR(rest,1,INSTR(rest,char(10))-1) ELSE rest END
    FROM sp WHERE LENGTH(rest)>0
) SELECT COUNT(*) FROM sp")" \
    "single-arg argv no duplicate"

# ── Phase 2: UI interaction tests (--load + --dd drives handle_key) ──────────
#
# Each test loads base.db into memory, injects keystrokes through handle_key(),
# saves the resulting state, and asserts on the DB.

run_dd() {
    # run_dd <keys_json> <label_prefix>
    local keys="$1"
    TV_SAVE_PATH="$NAV_DB" "$TV" --load "$BASE_DB" --dd "$keys" 2>/dev/null
}

# T25: cursor moves down by 2 (j j → cursor=2)
run_dd '["j","j","W"]' "nav"
assert_eq 2 "$(qn "SELECT cursor FROM state")" \
    "cursor after jj"

# T26: cursor jumps to end (END key → cursor = lpane count - 1 = 7)
run_dd '["END","W"]' "nav"
assert_eq 7 "$(qn "SELECT cursor FROM state")" \
    "cursor at end after END"

# T27: switch to files mode (2 key → mode=1); lpane has file entries
run_dd '["2","W"]' "nav"
assert_eq 1 "$(qn "SELECT mode FROM state")" \
    "mode=1 after key 2"
assert_eq 1 "$(qn "SELECT COUNT(*)>0 FROM lpane")" \
    "lpane populated in files mode"

# T28: switch to output mode (3 key → mode=2); lpane has io entries
run_dd '["3","W"]' "nav"
assert_eq 2 "$(qn "SELECT mode FROM state")" \
    "mode=2 after key 3"

# T29: cycle view filter once (v key → lp_filter=1, only failed procs shown)
run_dd '["v","W"]' "nav"
assert_eq 1 "$(qn "SELECT lp_filter FROM state")" \
    "lp_filter=1 after v"
NFAIL="$(qn "SELECT COUNT(*) FROM lpane")"
assert_eq 1 "$([ "$NFAIL" -lt 8 ] && echo 1 || echo 0)" \
    "fewer rows when lp_filter=1"

# T30: cycle sort order (s key → sort_key=1); lpane still populated
run_dd '["s","W"]' "nav"
assert_eq 1 "$(qn "SELECT sort_key FROM state")" \
    "sort_key=1 after s"

# ── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
