#!/usr/bin/env bash
# test_operator_dsf_sweep.sh — regression gate for tools/operator_dsf_sweep.sh
# (the DSF-SPEC §Q6 overnight generated-variant sweep runner).
#
# Sweep contract under test:
#   exit 0  all runs green
#   exit 1  at least one variant failed (REPRO block with exact repro command
#           lines; trace dir preserved and its path printed)
#   exit 2  usage error (unknown flag, missing value, bad number, unknown
#           template name, unusable --trace-dir)
#   exit 3  determ-dsf binary not found
#
# OFFLINE assertions (always run, no binary needed):
#   1. bash -n on the sweep script is clean.
#   2. --help exits 0 and mentions the exit-code table (structural needles,
#      not exact prose).
#   3. unknown flag (--frobnicate) exits 2.
#   4. a value-taking flag as the LAST argument (--bin, no value) exits 2 —
#      the arg-parse infinite-loop regression guard, timeout-fenced so a
#      regression cannot hang the suite (timeout rc 124 = FAIL).
#   5. --templates broadcast,bogus exits 2 (unknown template rejected —
#      guards the determ-dsf silent-broadcast-fallback hazard).
#   6. --bin /nonexistent/x exits 3.
#
# LIVE assertions (SKIP-clean when determ-dsf is not discoverable; the
# offline half above still gates and the PASS marker still prints):
#   7. --quick exits 0, summary reports zero failures, and at least one
#      "replay ok" replay-determinism check ran.
#   8. failure path: a stub wrapper binary (in $TMPD, never in the repo)
#      that fails any --scenario run makes the sweep exit 1, print a REPRO
#      line carrying "--scenario gen_run_00", and print the preserved
#      trace-dir path.
#   9. seed-derivation determinism: two --quick runs emit identical @0x...
#      seed-token sequences (seed_i = seed_base + i*0x9E37, no wall clock).
#      rc-gated: a non-green quick run is reported as instability with both
#      rcs + output tails, NOT misdiagnosed as nondeterministic derivation.
#
# Deliberately does NOT pin template names or counts: DEFAULT_TEMPLATES /
# KNOWN_TEMPLATES at the top of the sweep script GROW as templates ship.
# The only template name relied on is "broadcast" — the permanent base /
# fallback template.
#
# Exit 0 = all assertions passed (live half may be SKIPped).

set -u
cd "$(dirname "$0")/.."

SWEEP="tools/operator_dsf_sweep.sh"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_sweeptest.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

# Timeout fence: a hang in the script under test must never wedge the suite.
HAVE_TIMEOUT=""
command -v timeout >/dev/null 2>&1 && HAVE_TIMEOUT=1
run_to() { # run_to SECONDS CMD ARGS...
    local secs="$1"; shift
    if [ -n "$HAVE_TIMEOUT" ]; then timeout "$secs" "$@"; else "$@"; fi
}

if [ ! -f "$SWEEP" ]; then
    fail "$SWEEP not found"
    echo ""
    echo "  FAIL: test_operator_dsf_sweep ($FAILS assertion(s))"
    exit 1
fi

# ── assertion 1 (offline): syntax check ───────────────────────────────────────
if bash -n "$SWEEP" 2>"$TMPD/syntax.err"; then
    ok "bash -n $SWEEP is clean"
else
    fail "bash -n $SWEEP: $(cat "$TMPD/syntax.err")"
fi

# ── assertion 2 (offline): --help exits 0 + documents the exit-code table ─────
HELP="$(run_to 10 bash "$SWEEP" --help 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "--help exits 0"
else fail "--help exited $rc (expected 0)"; fi
if echo "$HELP" | grep -qi 'exit code'; then ok "--help mentions the exit-code table"
else fail "--help does not mention exit codes"; fi
if echo "$HELP" | grep -qiE '3.*binary'; then ok "--help documents exit 3 = binary not found"
else fail "--help does not document exit 3 (binary not found)"; fi

# ── assertion 3 (offline): unknown flag -> exit 2 ─────────────────────────────
run_to 10 bash "$SWEEP" --frobnicate >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 2 ]; then ok "unknown flag --frobnicate exits 2"
else fail "unknown flag --frobnicate exited $rc (expected 2)"; fi

# ── assertion 4 (offline): value-taking flag as LAST arg -> exit 2, no hang ───
# (Regression guard: a `shift 2` with no value present fails WITHOUT shifting,
# which would re-parse the same flag forever. rc 124 = timeout = hang = FAIL.)
run_to 10 bash "$SWEEP" --bin >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 124 ]; then
    fail "--bin with no value HUNG (arg-parse infinite-loop regression)"
elif [ "$rc" -eq 2 ]; then
    ok "--bin as last argument exits 2 (no arg-parse loop)"
else
    fail "--bin with no value exited $rc (expected 2)"
fi

# ── assertion 5 (offline): unknown template name rejected -> exit 2 ───────────
run_to 10 bash "$SWEEP" --templates broadcast,bogus >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 2 ]; then ok "--templates broadcast,bogus exits 2 (unknown template rejected)"
else fail "--templates broadcast,bogus exited $rc (expected 2 — silent-broadcast-fallback hazard unguarded)"; fi

# ── assertion 6 (offline): nonexistent --bin -> exit 3 ────────────────────────
run_to 10 bash "$SWEEP" --bin /nonexistent/x >/dev/null 2>&1; rc=$?
if [ "$rc" -eq 3 ]; then ok "--bin /nonexistent/x exits 3"
else fail "--bin /nonexistent/x exited $rc (expected 3)"; fi

# ── live half: needs a discoverable determ-dsf ────────────────────────────────
DSF=""
if [ -n "${DETERM_DSF_BIN:-}" ] && [ -x "${DETERM_DSF_BIN:-}" ]; then DSF="$DETERM_DSF_BIN"
elif [ -x "build/Release/determ-dsf.exe" ]; then DSF="build/Release/determ-dsf.exe"
elif [ -x "build/determ-dsf.exe" ]; then DSF="build/determ-dsf.exe"
elif [ -x "build/determ-dsf" ]; then DSF="build/determ-dsf"
elif [ -x "build/Release/determ-dsf" ]; then DSF="build/Release/determ-dsf"
fi

if [ -z "$DSF" ]; then
    echo "  SKIP (live half, assertions 7-9): determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "       or build the determ-dsf CMake target); offline assertions above still gate."
else
    echo "test_operator_dsf_sweep: live half using $DSF"

    # ── assertion 7 (live): --quick is green ──────────────────────────────────
    OUT="$(run_to 60 bash "$SWEEP" --bin "$DSF" --quick 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then ok "--quick exits 0"
    else
        fail "--quick exited $rc (expected 0)"
        echo "$OUT" | tail -8 | sed 's/^/    | /'
    fi
    if echo "$OUT" | grep -qE 'failures[[:space:]]*:[[:space:]]*0([^0-9]|$)'; then
        ok "--quick summary reports zero failures"
    else
        fail "--quick summary does not report zero failures"
    fi
    if echo "$OUT" | grep -q 'replay ok'; then ok "--quick ran at least one replay-determinism check (replay ok)"
    else fail "--quick output has no 'replay ok' line"; fi

    # ── assertion 8 (live): failure path -> exit 1 + REPRO + preserved traces ─
    # Stub wrapper (in $TMPD only): passes through to the real binary except
    # for --scenario runs, which fail — simulates one failing generated
    # variant. No .sh suffix; Git Bash executes shebang scripts fine.
    DSF_ABS="$(cd "$(dirname "$DSF")" && pwd)/$(basename "$DSF")"
    STUB="$TMPD/dsf_stub"
    cat >"$STUB" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do
    if [ "\$a" = "--scenario" ]; then
        echo "stub: planted variant failure" >&2
        exit 1
    fi
done
exec "$DSF_ABS" "\$@"
EOF
    chmod +x "$STUB"
    STRACE="$TMPD/sweep_traces"
    OUT="$(run_to 60 bash "$SWEEP" --bin "$STUB" --templates broadcast --seeds 1 --variants 1 --trace-dir "$STRACE" 2>&1)"; rc=$?
    if [ "$rc" -eq 1 ]; then ok "failing variant makes the sweep exit 1"
    else fail "sweep with failing stub exited $rc (expected 1)"; fi
    if echo "$OUT" | grep -q 'REPRO'; then ok "failure output contains the REPRO block"
    else fail "failure output has no REPRO block"; fi
    if echo "$OUT" | grep -q -- '--scenario gen_run_00'; then ok "repro line carries --scenario gen_run_00"
    else fail "no repro line with --scenario gen_run_00"; fi
    if echo "$OUT" | grep -q 'preserved' && echo "$OUT" | grep -qF "$STRACE"; then
        ok "preserved trace-dir path printed"
    else
        fail "preserved trace-dir path not printed on failure"
    fi

    # ── assertion 9 (live): seed derivation is deterministic across runs ──────
    # rc-gated: a non-green run adds FAIL/REPRO lines carrying extra @0x tokens,
    # which would misreport a sweep flake (e.g. the binary being rebuilt by a
    # concurrent session) as "nondeterministic seed derivation". Only compare
    # seed sequences when both runs were green; otherwise fail with the rcs.
    run_to 60 bash "$SWEEP" --bin "$DSF" --quick >"$TMPD/q1.out" 2>&1; rc1=$?
    run_to 60 bash "$SWEEP" --bin "$DSF" --quick >"$TMPD/q2.out" 2>&1; rc2=$?
    if [ "$rc1" -ne 0 ] || [ "$rc2" -ne 0 ]; then
        fail "assertion-9 --quick runs exited rc1=$rc1 rc2=$rc2 (expected 0/0 — sweep or binary instability, seed comparison not reached)"
        tail -6 "$TMPD/q1.out" | sed 's/^/    q1| /'
        tail -6 "$TMPD/q2.out" | sed 's/^/    q2| /'
    else
        grep -oE '@0x[0-9a-fA-F]+' "$TMPD/q1.out" >"$TMPD/q1.seeds"
        grep -oE '@0x[0-9a-fA-F]+' "$TMPD/q2.out" >"$TMPD/q2.seeds"
        if [ -s "$TMPD/q1.seeds" ] && diff -q "$TMPD/q1.seeds" "$TMPD/q2.seeds" >/dev/null 2>&1; then
            ok "seed sequence identical across two --quick runs ($(wc -l <"$TMPD/q1.seeds" | tr -d ' ') @0x tokens)"
        else
            fail "seed sequences differ across --quick runs or are empty (nondeterministic derivation?)"
            diff "$TMPD/q1.seeds" "$TMPD/q2.seeds" | head -20 | sed 's/^/    | /'
        fi
    fi
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_operator_dsf_sweep (sweep-runner contract: --help + usage exit codes 0/2/3, arg-parse no-hang guard on a dangling value flag, unknown-template rejection, quick sweep green with replay checks, failing-variant path with REPRO block + preserved trace dir, deterministic @0x seed derivation; template list deliberately unpinned)"
    exit 0
else
    echo "  FAIL: test_operator_dsf_sweep ($FAILS assertion(s))"
    exit 1
fi
