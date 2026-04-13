#!/bin/bash
# tests/sudtrace_test.sh — integration tests for sudtrace
#
# Tests that sudtrace correctly traces programs, including multithreaded
# ones, and produces valid JSONL output.
set -eo pipefail

cd "$(dirname "$0")/.."
SUDTRACE=./sudtrace
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0 FAIL=0 TOTAL=0

run_test() {
    local name="$1"; shift
    TOTAL=$((TOTAL + 1))
    local ok=1
    for assertion in "$@"; do
        if ! eval "$assertion"; then ok=0; fi
    done
    if [ $ok -eq 1 ]; then
        PASS=$((PASS + 1))
        echo "  PASS  $name"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL  $name"
    fi
}

# ── Compile test programs ──────────────────────────────────────────────

cat > "$TMPDIR/hello.c" << 'EOF'
#include <stdio.h>
int main(void) {
    fprintf(stderr, "hello world\n");
    return 0;
}
EOF
gcc -o "$TMPDIR/hello" "$TMPDIR/hello.c"

cat > "$TMPDIR/threads.c" << 'EOF'
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

void *worker(void *arg) {
    int id = *(int *)arg;
    fprintf(stderr, "thread %d\n", id);
    int fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) { write(fd, "x", 1); close(fd); }
    return NULL;
}

int main(void) {
    pthread_t threads[4];
    int ids[4];
    for (int i = 0; i < 4; i++) {
        ids[i] = i;
        pthread_create(&threads[i], NULL, worker, &ids[i]);
    }
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);
    fprintf(stderr, "done\n");
    return 0;
}
EOF
gcc -o "$TMPDIR/threads" "$TMPDIR/threads.c" -lpthread

# ── Test: basic single-threaded tracing ────────────────────────────────

if [ -x "$SUDTRACE" ]; then

OUT=$("$SUDTRACE" -o "$TMPDIR/hello.jsonl" -- "$TMPDIR/hello" 2>&1)
run_test "basic: hello world traced" \
    'grep -q "\"event\":\"EXEC\"" "$TMPDIR/hello.jsonl"' \
    'grep -q "\"event\":\"EXIT\"" "$TMPDIR/hello.jsonl"' \
    'grep -q "\"status\":\"exited\"" "$TMPDIR/hello.jsonl"' \
    '! grep -q "\"signal\"" "$TMPDIR/hello.jsonl"'

run_test "basic: stderr captured" \
    'grep -q "STDERR" "$TMPDIR/hello.jsonl"' \
    'grep -q "hello world" "$TMPDIR/hello.jsonl"'

# ── Test: multithreaded tracing ────────────────────────────────────────

# Run 3 times to detect race conditions — the clone3 child/parent
# synchronization and signal handler re-entrancy are timing-sensitive.
for attempt in 1 2 3; do
    OUT=$("$SUDTRACE" -o "$TMPDIR/threads_${attempt}.jsonl" -- "$TMPDIR/threads" 2>&1)
    run_test "threads attempt $attempt: no crash" \
        '! grep -q "\"signal\"" "$TMPDIR/threads_${attempt}.jsonl"' \
        'grep -q "\"status\":\"exited\"" "$TMPDIR/threads_${attempt}.jsonl"'
    run_test "threads attempt $attempt: stderr captured" \
        'grep -q "done" "$TMPDIR/threads_${attempt}.jsonl"'
done

else
    echo "  SKIP  sudtrace not built (run 'make sudtrace' first)"
fi

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════"
echo "  $PASS passed, $FAIL failed (of $TOTAL)"
echo "═══════════════════════════════════════"
[ "$FAIL" -eq 0 ]
