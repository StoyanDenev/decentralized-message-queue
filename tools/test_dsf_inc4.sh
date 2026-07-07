#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 4 — §Q5 randomized generator.
#
# Build-agnostic: SKIP-clean if determ-dsf isn't built. Asserts the increment-4
# contract over the 6 generated reliable-broadcast variants + 1 self-test:
#   1. --list shows all 6 gen_broadcast_NN + gen_overcount_selftest.
#   2. GENERATION IS DETERMINISTIC: two --list invocations are byte-identical
#      (same generator seed -> same variants).
#   3. GENERATION IS VARIED: the 6 variants do NOT all share one fault profile
#      (the generator actually draws distinct followers/drop/dup — not fixed).
#   4. Each variant is run-DETERMINISTIC: same variant+seed twice -> identical trace.
#   5. Each variant converges (exits 0, non-vacuously) across several run seeds
#      (the reliable-broadcast template tolerates any drawn fault realization).
#   6. The self-test exits 0 AND fires gen_no_overcount AND prints the repro seed
#      (a generated fault profile surfaces a real non-idempotent-apply bug).
#
# Exit 0 = all assertions passed OR clean SKIP.

set -u
cd "$(dirname "$0")/.."

DSF=""
if [ -n "${DETERM_DSF_BIN:-}" ] && [ -x "${DETERM_DSF_BIN:-}" ]; then DSF="$DETERM_DSF_BIN"
elif [ -x "build/Release/determ-dsf.exe" ]; then DSF="build/Release/determ-dsf.exe"
elif [ -x "build/determ-dsf.exe" ]; then DSF="build/determ-dsf.exe"
elif [ -x "build/determ-dsf" ]; then DSF="build/determ-dsf"
elif [ -x "build/Release/determ-dsf" ]; then DSF="build/Release/determ-dsf"
fi

if [ -z "$DSF" ]; then
    echo "SKIP test_dsf_inc4: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Generator is header-only."
    exit 0
fi

echo "test_dsf_inc4: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc4.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

GENVARS="gen_broadcast_00 gen_broadcast_01 gen_broadcast_02 gen_broadcast_03 gen_broadcast_04 gen_broadcast_05"

# ── assertion 1: --list shows all 6 variants + the self-test ────────────────
LIST="$("$DSF" --list 2>&1)"
for s in $GENVARS gen_overcount_selftest; do
    if echo "$LIST" | grep -q "^  $s"; then ok "--list contains $s"
    else fail "--list missing '$s'"; fi
done

# ── assertion 2: generation is deterministic (--list byte-stable) ───────────
"$DSF" --list > "$TMPD/list_a" 2>&1
"$DSF" --list > "$TMPD/list_b" 2>&1
if diff -q "$TMPD/list_a" "$TMPD/list_b" >/dev/null 2>&1; then
    ok "generator output (--list) is byte-stable across runs"
else
    fail "generator --list DIFFERS across runs (non-deterministic generation!)"
fi

# ── assertion 3: generation is varied (not all one profile) ────────────────
DISTINCT_DROPS="$(echo "$LIST" | grep -oE 'drop=[0-9.]+' | grep -E 'gen|drop' | sort -u | wc -l)"
# count distinct fault-profile description lines among the 6 variants
PROFILES="$(echo "$LIST" | grep -A1 '^  gen_broadcast_' | grep -oE 'followers=[0-9]+ latency=[0-9]+ms jitter=[0-9]+ms drop=[0-9.]+ dup=[0-9.]+' | sort -u | wc -l)"
if [ "${PROFILES:-0}" -ge 2 ]; then
    ok "the 6 generated variants span $PROFILES distinct fault profiles (seed-driven)"
else
    fail "generated variants are not varied (only $PROFILES distinct profile) — generator may be fixed"
fi

# ── assertion 4+5: run-determinism + convergence across seeds (non-vacuous) ──
for s in $GENVARS; do
    "$DSF" --scenario "$s" --seed 0xD5F4 --trace "$TMPD/${s}_a.log" --quiet >/dev/null 2>&1
    "$DSF" --scenario "$s" --seed 0xD5F4 --trace "$TMPD/${s}_b.log" --quiet >/dev/null 2>&1
    if [ -s "$TMPD/${s}_a.log" ] && diff -q "$TMPD/${s}_a.log" "$TMPD/${s}_b.log" >/dev/null 2>&1; then
        ok "$s is run-deterministic (identical trace @0xD5F4)"
    else
        fail "$s trace differs across runs or is empty"
    fi
    bad=""
    for seed in 0x1 0xABC 0xD5F4 0xFFFF; do
        OUT="$("$DSF" --scenario "$s" --seed "$seed" 2>&1)" || bad="$bad $seed"
        echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps' || bad="$bad(vacuous@$seed)"
    done
    if [ -z "$bad" ]; then ok "$s converges non-vacuously across 4 seeds"
    else fail "$s failed / vacuous @$bad"; fi
done

# ── assertion 6: the self-test surfaces the planted bug ─────────────────────
OUT="$("$DSF" --scenario gen_overcount_selftest --seed 0xD5F4 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "gen_overcount_selftest exits 0 (planted bug caught)"
else fail "gen_overcount_selftest exited $rc (expected 0 for expect-violation self-test)"; fi
if echo "$OUT" | grep -q "gen_no_overcount"; then ok "gen_overcount_selftest fired the correct invariant (gen_no_overcount)"
else fail "gen_overcount_selftest did NOT fire gen_no_overcount"; fi
if echo "$OUT" | grep -qi "seed 0xd5f4"; then ok "gen_overcount_selftest prints the reproducing seed"
else fail "gen_overcount_selftest did not print the reproducing seed"; fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc4 (§Q5 generator: 6 deterministic, varied, always-converging reliable-broadcast variants + a self-test that surfaces a non-idempotent-apply bug)"
    exit 0
else
    echo "  FAIL: test_dsf_inc4 ($FAILS assertion(s))"
    exit 1
fi
