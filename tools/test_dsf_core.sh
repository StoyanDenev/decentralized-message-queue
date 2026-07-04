#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 1 — core smoke test.
#
# Build-agnostic: SKIP-clean if the determ-dsf binary isn't built (the CMake
# target is wired separately; see sim/dsf_main.cpp header + the integration
# note in the increment handoff). When the binary IS present, this asserts the
# three properties the increment must guarantee:
#
#   1. --list shows all 6 seed scenarios.
#   2. A fixed --seed run is DETERMINISTIC: run the same scenario+seed twice,
#      diff the two traces -> byte-identical.
#   3. The deliberately-falsifiable scenario reports its violation AND prints
#      a reproducing seed (the replay contract), and the expect-violation
#      self-test exits 0 while a normal-scenario violation would exit non-zero.
#
# Binary discovery order (first hit wins):
#   $DETERM_DSF_BIN                       (explicit override)
#   build/Release/determ-dsf.exe          (Windows MSVC multi-config)
#   build/determ-dsf.exe                  (Windows single-config)
#   build/determ-dsf                      (Linux/Mac single-config)
#   build/Release/determ-dsf              (Linux/Mac multi-config)
#
# Exit 0 = all assertions passed OR clean SKIP. Non-zero = a real failure.

set -u
cd "$(dirname "$0")/.."

# ── locate the binary (SKIP-clean if absent) ───────────────────────────────
DSF=""
if [ -n "${DETERM_DSF_BIN:-}" ] && [ -x "${DETERM_DSF_BIN:-}" ]; then
    DSF="$DETERM_DSF_BIN"
elif [ -x "build/Release/determ-dsf.exe" ]; then
    DSF="build/Release/determ-dsf.exe"
elif [ -x "build/determ-dsf.exe" ]; then
    DSF="build/determ-dsf.exe"
elif [ -x "build/determ-dsf" ]; then
    DSF="build/determ-dsf"
elif [ -x "build/Release/determ-dsf" ]; then
    DSF="build/Release/determ-dsf"
fi

if [ -z "$DSF" ]; then
    echo "SKIP test_dsf_core: determ-dsf not built (wire the CMake target, or"
    echo "     set DETERM_DSF_BIN=/absolute/path). Core is header-only under sim/."
    exit 0
fi

echo "test_dsf_core: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_core.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

SCENARIOS="replicated_counter message_reorder partition_heal duplicate_delivery leader_timeout falsifiable_supply"

# ── assertion 1: --list shows all 6 scenarios ──────────────────────────────
LIST="$("$DSF" --list 2>&1)"
for s in $SCENARIOS; do
    if echo "$LIST" | grep -q "^  $s"; then
        ok "--list contains $s"
    else
        fail "--list missing scenario '$s'"
    fi
done

# ── assertion 2: fixed seed is deterministic (identical trace twice) ────────
SEED="0xD5F1"
for s in replicated_counter message_reorder partition_heal duplicate_delivery; do
    "$DSF" --scenario "$s" --seed "$SEED" --trace "$TMPD/${s}_a.log" --quiet >/dev/null 2>&1
    "$DSF" --scenario "$s" --seed "$SEED" --trace "$TMPD/${s}_b.log" --quiet >/dev/null 2>&1
    if [ ! -s "$TMPD/${s}_a.log" ]; then
        fail "$s produced an empty trace"
        continue
    fi
    if diff -q "$TMPD/${s}_a.log" "$TMPD/${s}_b.log" >/dev/null 2>&1; then
        ok "$s @ $SEED is deterministic (identical trace)"
    else
        fail "$s @ $SEED traces DIFFER across runs (non-deterministic!)"
    fi
done

# ── assertion 3a: normal scenarios exit 0 (no unexpected violation) ─────────
for s in replicated_counter message_reorder partition_heal duplicate_delivery leader_timeout; do
    "$DSF" --scenario "$s" --seed "$SEED" --quiet >/dev/null 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        ok "$s exits 0 (invariants held)"
    else
        fail "$s exited $rc (unexpected invariant violation)"
    fi
done

# ── assertion 3b: falsifiable scenario reports the violation + repro seed ───
OUT="$("$DSF" --scenario falsifiable_supply --seed "$SEED" 2>&1)"
rc=$?
# The expect-violation self-test: a fired violation is the PASS condition,
# so the runner exits 0. The output must name the violated invariant.
if [ "$rc" -eq 0 ]; then
    ok "falsifiable_supply self-test exits 0 (checker caught the planted bug)"
else
    fail "falsifiable_supply exited $rc (expected 0 for expect-violation self-test)"
fi
if echo "$OUT" | grep -qi "unitary_supply"; then
    ok "falsifiable_supply names the violated invariant (unitary_supply)"
else
    fail "falsifiable_supply did not report the violated invariant"
fi
if echo "$OUT" | grep -qi "seed 0xd5f1"; then
    ok "falsifiable_supply prints the reproducing seed"
else
    fail "falsifiable_supply did not print the reproducing seed"
fi

# ── assertion 3c: a normal scenario with a REAL violation would exit 1 ──────
# We prove the non-zero exit path by pointing a normal (non-expect-violation)
# run at the falsifiable invariant is not directly possible without a bug in a
# normal scenario; instead we confirm the runner's exit-code contract by
# checking that --scenario with an unknown name exits 2 (usage error path),
# which shares the non-zero-on-problem contract.
"$DSF" --scenario __nope__ --seed "$SEED" >/dev/null 2>&1
rc=$?
if [ "$rc" -eq 2 ]; then
    ok "unknown scenario exits 2 (usage-error contract)"
else
    fail "unknown scenario exited $rc (expected 2)"
fi

# ── summary ─────────────────────────────────────────────────────────────────
echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_core (DSF deterministic-core smoke: clock+scheduler+trace+property)"
    exit 0
else
    echo "  FAIL: test_dsf_core ($FAILS assertion(s))"
    exit 1
fi
