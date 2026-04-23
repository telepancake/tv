#!/bin/bash
# tests/sud_stress.sh — driver for the sud_stress harness.
#
# Builds tests/sud_stress and runs each subtest under sud64 (and sud32
# when a 32-bit toolchain is available).  Failure conditions:
#   • subtest exit ≠ expected
#   • timeout
#   • any line containing "sudtrace: CRASH DIAGNOSTIC" on stderr
#   • child killed by a signal (status 128+sig)
#
# Usage:
#   tests/sud_stress.sh                  # one pass of every subtest
#   tests/sud_stress.sh --soak 20        # 20 passes (catch races)
#   tests/sud_stress.sh --only NAME      # one subtest, repeated
#   tests/sud_stress.sh --no-build       # reuse existing binary
#   tests/sud_stress.sh --32             # also exercise sud32

set -uo pipefail

cd "$(dirname "$0")/.."

SOAK=1
ONLY=""
NO_BUILD=0
WANT_32=0
TIMEOUT=60

while [ $# -gt 0 ]; do
    case "$1" in
        --soak)     SOAK="$2"; shift 2;;
        --only)     ONLY="$2"; shift 2;;
        --no-build) NO_BUILD=1; shift;;
        --32)       WANT_32=1; shift;;
        --timeout)  TIMEOUT="$2"; shift 2;;
        -h|--help)
            sed -n '2,17p' "$0"; exit 0;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

# ── Build harness ─────────────────────────────────────────────────────
HARNESS=tests/sud_stress
if [ "$NO_BUILD" -eq 0 ] || [ ! -x "$HARNESS" ]; then
    echo "[build] $HARNESS"
    cc -O2 -Wall -Wextra -pthread -o "$HARNESS" tests/sud_stress.c \
        || { echo "build failed" >&2; exit 2; }
fi

# Build sud64/sud32 if not already present.
if [ "$NO_BUILD" -eq 0 ]; then
    [ -x sud64 ] || make sud64 >/dev/null 2>&1 || true
    [ "$WANT_32" -eq 1 ] && [ ! -x sud32 ] && make sud32 >/dev/null 2>&1 || true
fi

if [ ! -x sud64 ]; then
    echo "FATAL: sud64 not built" >&2; exit 2
fi

# ── Subtest table: name, expected exit, args ──────────────────────────
# Format: "name|expected_exit|args..."
TESTS=(
    "argv-huge|0|"
    "argv-single-huge|0|"
    "shebang-chain|0|10"
    "thread-exec-storm|0|6 30"
    "posix-spawn-storm|0|6 30"
    "vfork-exec-loop|0|150"
    "signal-storm|0|4 25"
    "ptrace-traceme|0|"
    "execve-null|0|"
    "waitid-tight|0|150"
)

# ── Run helper ────────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0; FAIL=0; CRASH=0
FAILED_NAMES=()

run_one() {
    local launcher="$1"; shift
    local label="$1"; shift
    local name="$1"; shift
    local expect="$1"; shift
    # remaining args = subtest args

    local out="$TMPDIR/$label.$name.out"
    local err="$TMPDIR/$label.$name.err"
    local wire="$TMPDIR/$label.$name.wire"

    SUDTRACE_OUTFILE="$wire" timeout --kill-after=5 "$TIMEOUT" \
        "$launcher" "$PWD/$HARNESS" "$name" "$@" \
        >"$out" 2>"$err"
    local rc=$?

    local crashed=0
    if grep -q "sudtrace: CRASH DIAGNOSTIC" "$err" 2>/dev/null; then
        crashed=1
    fi
    # 128+SIGSEGV(11)=139, +SIGBUS(7)=135, +SIGSYS(31)=159, +SIGABRT(6)=134
    case "$rc" in
        139|135|159|134) crashed=1;;
    esac
    # timeout uses 124, 137 (SIGKILL after grace)
    local tmoed=0
    case "$rc" in
        124|137) tmoed=1;;
    esac

    if [ "$crashed" -eq 1 ]; then
        CRASH=$((CRASH+1))
        FAIL=$((FAIL+1))
        FAILED_NAMES+=("$label/$name (CRASH)")
        echo "  CRASH  [$label] $name (rc=$rc)"
        echo "    --- stderr (last 60 lines) ---"
        tail -n 60 "$err" | sed 's/^/    /'
        echo "    --- end stderr ---"
        return
    fi
    if [ "$tmoed" -eq 1 ]; then
        FAIL=$((FAIL+1))
        FAILED_NAMES+=("$label/$name (TIMEOUT)")
        echo "  TIMEOUT [$label] $name (${TIMEOUT}s)"
        return
    fi
    if [ "$rc" -ne "$expect" ]; then
        FAIL=$((FAIL+1))
        FAILED_NAMES+=("$label/$name (rc=$rc want=$expect)")
        echo "  FAIL   [$label] $name (rc=$rc want=$expect)"
        echo "    --- stderr (last 30 lines) ---"
        tail -n 30 "$err" | sed 's/^/    /'
        echo "    --- end stderr ---"
        return
    fi
    PASS=$((PASS+1))
    echo "  PASS   [$label] $name"
}

# ── Iterate ───────────────────────────────────────────────────────────
LAUNCHERS=("sud64:$PWD/sud64")
if [ "$WANT_32" -eq 1 ] && [ -x sud32 ]; then
    LAUNCHERS+=("sud32:$PWD/sud32")
fi

echo "==> sud_stress: soak=$SOAK launchers=${#LAUNCHERS[@]}"

for soak in $(seq 1 "$SOAK"); do
    [ "$SOAK" -gt 1 ] && echo "--- pass $soak/$SOAK ---"
    for entry in "${TESTS[@]}"; do
        IFS='|' read -r name expect rest <<<"$entry"
        if [ -n "$ONLY" ] && [ "$ONLY" != "$name" ]; then continue; fi
        # shellcheck disable=SC2086
        for L in "${LAUNCHERS[@]}"; do
            label="${L%%:*}"
            launcher="${L#*:}"
            run_one "$launcher" "$label" "$name" "$expect" $rest
        done
    done
done

echo
echo "==> sud_stress summary"
echo "    PASS=$PASS  FAIL=$FAIL  CRASH=$CRASH"
if [ "$FAIL" -gt 0 ]; then
    echo "    failures:"
    for f in "${FAILED_NAMES[@]}"; do echo "      - $f"; done
    exit 1
fi
exit 0
