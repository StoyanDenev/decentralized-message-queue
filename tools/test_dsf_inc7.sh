#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 7 — a THIRD generator
# template: monotone RATCHET / non-regression (§Q7 BFT-escalation / commit-index).
#
# Increments 4-6 shipped two generator templates (reliable-broadcast no-overcount;
# single-value-flood agreement no-split). Increment 7 adds a third §Q7 checker
# family under the same randomized fault profiles: a leader ramps a ceiling and
# re-floods it; each follower keeps a monotone high-water mark and commits it, so
# its committed value NEVER regresses — robust by construction under any drawn
# drop/dup/latency/jitter profile (max-latching is idempotent + reorder-immune).
# A `--template broadcast|agree|ratchet` selector routes `--generate`.
# Build-agnostic: SKIP-clean if determ-dsf isn't built. Asserts:
#   1. --list shows all 6 baked gen_ratchet_NN + gen_regress_selftest.
#   2. Each baked gen_ratchet_NN is run-deterministic AND advances non-vacuously
#      across several seeds (safety ratchet_no_regress + liveness ratchet_advanced).
#   3. gen_regress_selftest exits 0, fires ratchet_no_regress, prints the repro
#      seed (a raw-committing follower + a Byzantine decreasing leader is caught).
#   4. --template ratchet --generate N --list shows N gen_run_NN whose description
#      is the RATCHET template (not broadcast/agreement).
#   5. REGRESSION GUARD: --generate N with no --template still yields the
#      broadcast template (inc-5 default path unchanged); --template agree still
#      routes to agreement (inc-6 intact).
#   6. A generated ratchet variant runs, advances, and replays byte-identically.
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
    echo "SKIP test_dsf_inc7: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Generator is header-only."
    exit 0
fi

echo "test_dsf_inc7: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc7.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

RATCHETVARS="gen_ratchet_00 gen_ratchet_01 gen_ratchet_02 gen_ratchet_03 gen_ratchet_04 gen_ratchet_05"

# ── assertion 1: --list shows all 6 baked ratchet variants + the self-test ────
LIST="$("$DSF" --list 2>&1)"
for s in $RATCHETVARS gen_regress_selftest; do
    if echo "$LIST" | grep -q "^  $s"; then ok "--list contains $s"
    else fail "--list missing '$s'"; fi
done

# ── assertion 2: each baked ratchet variant is deterministic + advances ───────
for s in $RATCHETVARS; do
    "$DSF" --scenario "$s" --seed 0xA6 --trace "$TMPD/${s}_a.log" --quiet >/dev/null 2>&1
    "$DSF" --scenario "$s" --seed 0xA6 --trace "$TMPD/${s}_b.log" --quiet >/dev/null 2>&1
    if [ -s "$TMPD/${s}_a.log" ] && diff -q "$TMPD/${s}_a.log" "$TMPD/${s}_b.log" >/dev/null 2>&1; then
        ok "$s is run-deterministic (identical trace @0xA6)"
    else
        fail "$s trace differs across runs or is empty"
    fi
    bad=""
    for seed in 0x1 0xABC 0xA6 0xFFFF; do
        OUT="$("$DSF" --scenario "$s" --seed "$seed" 2>&1)" || bad="$bad $seed"
        echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps' || bad="$bad(vacuous@$seed)"
    done
    if [ -z "$bad" ]; then ok "$s advances non-vacuously across 4 seeds"
    else fail "$s failed / vacuous @$bad"; fi
done

# ── assertion 3: the self-test fires the no-regress checker ───────────────────
OUT="$("$DSF" --scenario gen_regress_selftest --seed 0xA6 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "gen_regress_selftest exits 0 (planted regression caught)"
else fail "gen_regress_selftest exited $rc (expected 0 for expect-violation self-test)"; fi
if echo "$OUT" | grep -q "ratchet_no_regress"; then ok "gen_regress_selftest fired the correct invariant (ratchet_no_regress)"
else fail "gen_regress_selftest did NOT fire ratchet_no_regress"; fi
if echo "$OUT" | grep -qi "seed 0xa6"; then ok "gen_regress_selftest prints the reproducing seed"
else fail "gen_regress_selftest did not print the reproducing seed"; fi

# ── assertion 4: --template ratchet routes --generate to the ratchet template ─
RGEN="$("$DSF" --generate 6 --seed 0xFEED --template ratchet --list 2>&1)"
NR="$(echo "$RGEN" | grep -cE '^  gen_run_[0-9][0-9]')"
if [ "$NR" -eq 6 ]; then ok "--template ratchet --generate 6 registers 6 gen_run variants"
else fail "--template ratchet --generate 6 -> $NR gen_run variants (expected 6)"; fi
if echo "$RGEN" | grep -A1 '^  gen_run_00' | grep -qi 'ratchet'; then
    ok "--template ratchet gen_run variants use the RATCHET template"
else
    fail "--template ratchet gen_run variant description is not the ratchet template"
fi

# ── assertion 5: regression — default is still broadcast; agree still agree ───
BGEN="$("$DSF" --generate 6 --seed 0xFEED --list 2>&1)"
if echo "$BGEN" | grep -A1 '^  gen_run_00' | grep -qi 'reliable-broadcast'; then
    ok "default --generate (no --template) is still the broadcast template (inc-5 path intact)"
else
    fail "default --generate is no longer the broadcast template (inc-5 regression!)"
fi
AGEN="$("$DSF" --generate 6 --seed 0xFEED --template agree --list 2>&1)"
if echo "$AGEN" | grep -A1 '^  gen_run_00' | grep -qi 'agreement'; then
    ok "--template agree still routes to the agreement template (inc-6 path intact)"
else
    fail "--template agree no longer routes to agreement (inc-6 regression!)"
fi

# ── assertion 6: a generated ratchet variant runs + replays byte-identically ──
"$DSF" --generate 6 --seed 0xFEED --template ratchet --scenario gen_run_02 --trace "$TMPD/gr_a.log" --quiet >/dev/null 2>&1
"$DSF" --generate 6 --seed 0xFEED --template ratchet --scenario gen_run_02 --trace "$TMPD/gr_b.log" --quiet >/dev/null 2>&1
OUT="$("$DSF" --generate 6 --seed 0xFEED --template ratchet --scenario gen_run_02 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ -s "$TMPD/gr_a.log" ] && diff -q "$TMPD/gr_a.log" "$TMPD/gr_b.log" >/dev/null 2>&1 \
   && echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps'; then
    ok "generated ratchet variant runs, advances, and replays byte-identically (§Q6)"
else
    fail "generated ratchet variant did not advance / replay (rc=$rc)"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc7 (3rd generator template — monotone ratchet / non-regression: 6 deterministic always-advancing variants, a self-test that catches a raw-committing follower under a decreasing Byzantine leader, and a --template ratchet selector; inc-5 broadcast + inc-6 agreement defaults intact)"
    exit 0
else
    echo "  FAIL: test_dsf_inc7 ($FAILS assertion(s))"
    exit 1
fi
