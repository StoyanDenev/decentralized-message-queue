#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 3 — adversarial scenarios.
#
# Build-agnostic: SKIP-clean if determ-dsf isn't built. Asserts the increment-3
# contract over the 6 new scenarios (3 §Q7 families × {behavior, self-test}):
#   1. --list shows all 6 increment-3 scenarios.
#   2. Each is DETERMINISTIC: same scenario+seed twice -> byte-identical trace.
#   3. The 3 behavior scenarios exit 0 (invariants held, non-vacuously).
#   4. The 3 self-tests exit 0 AND name the CORRECT violated invariant AND print
#      the reproducing seed.
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
    echo "SKIP test_dsf_inc3: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Scenarios are header-only."
    exit 0
fi

echo "test_dsf_inc3: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc3.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

BEHAVIOR="dkg_all_commit f2_reconcile_intersect partition_minority_stalls"
SELFTEST="dkg_below_threshold f2_phantom_evidence partition_split_brain"
SEED="0xD5F3"

# ── assertion 1: --list shows all 6 increment-3 scenarios ──────────────────
LIST="$("$DSF" --list 2>&1)"
for s in $BEHAVIOR $SELFTEST; do
    if echo "$LIST" | grep -q "^  $s"; then ok "--list contains $s"
    else fail "--list missing scenario '$s'"; fi
done

# ── assertion 2: fixed seed is deterministic (identical trace twice) ────────
for s in $BEHAVIOR $SELFTEST; do
    "$DSF" --scenario "$s" --seed "$SEED" --trace "$TMPD/${s}_a.log" --quiet >/dev/null 2>&1
    "$DSF" --scenario "$s" --seed "$SEED" --trace "$TMPD/${s}_b.log" --quiet >/dev/null 2>&1
    if [ ! -s "$TMPD/${s}_a.log" ]; then fail "$s produced an empty trace"; continue; fi
    if diff -q "$TMPD/${s}_a.log" "$TMPD/${s}_b.log" >/dev/null 2>&1; then
        ok "$s @ $SEED is deterministic (identical trace)"
    else
        fail "$s @ $SEED traces DIFFER across runs (non-deterministic!)"
    fi
done

# ── assertion 3: the 3 behavior scenarios exit 0 + non-vacuous ──────────────
for s in $BEHAVIOR; do
    OUT="$("$DSF" --scenario "$s" --seed "$SEED" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then ok "$s exits 0 (invariants held)"
    else fail "$s exited $rc (unexpected invariant violation)"; fi
    if echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps'; then
        ok "$s held its invariants over a non-zero number of steps"
    else
        fail "$s did not evaluate its invariants over any step (vacuous?)"
    fi
done

# ── assertion 4: each self-test fires the CORRECT invariant + repro seed ────
check_selftest() {
    local sc="$1" inv="$2"
    local out; out="$("$DSF" --scenario "$sc" --seed "$SEED" 2>&1)"; local rc=$?
    if [ "$rc" -eq 0 ]; then ok "$sc self-test exits 0 (planted bug caught)"
    else fail "$sc exited $rc (expected 0 for expect-violation self-test)"; fi
    if echo "$out" | grep -q "$inv"; then ok "$sc fired the correct invariant ($inv)"
    else fail "$sc did NOT fire $inv (vacuous or wrong-invariant pass)"; fi
    if echo "$out" | grep -qi "seed 0xd5f3"; then ok "$sc prints the reproducing seed"
    else fail "$sc did not print the reproducing seed"; fi
}
check_selftest dkg_below_threshold    dkg_needs_threshold
check_selftest f2_phantom_evidence    no_phantom_evidence
check_selftest partition_split_brain  single_decision

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc3 (6 adversarial scenarios: DKG-threshold / F2-reconciliation / partition-quorum; each self-test verified non-vacuous)"
    exit 0
else
    echo "  FAIL: test_dsf_inc3 ($FAILS assertion(s))"
    exit 1
fi
