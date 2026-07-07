#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 6 — a SECOND generator
# template: single-value-flood AGREEMENT (§Q7 equivocation / network-partition).
#
# Increment 4-5 shipped ONE generator template (reliable-broadcast: no-overcount
# + convergence). Increment 6 adds a genuinely different §Q7 checker family under
# the same randomized fault profiles: a leader floods one decision value V; each
# follower latches the FIRST value (first-write-wins). Honest variants never split
# (only V is sent) and always decide. A `--template broadcast|agree` selector
# routes `--generate` to either template. Build-agnostic: SKIP-clean if
# determ-dsf isn't built. Asserts:
#   1. --list shows all 6 baked gen_agree_NN + gen_disagree_selftest.
#   2. Each baked gen_agree_NN is run-deterministic AND converges non-vacuously
#      across several seeds (safety agree_no_split + liveness agree_all_decided).
#   3. gen_disagree_selftest exits 0, fires agree_no_split, prints the repro seed
#      (a Byzantine-equivocating leader is caught by the no-split checker).
#   4. --template agree --generate N --list shows N gen_run_NN whose description
#      is the AGREEMENT template (not broadcast).
#   5. REGRESSION GUARD: --generate N with no --template still yields the
#      broadcast template (inc-5 default path unchanged).
#   6. A generated agreement variant runs, converges, and replays byte-identically.
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
    echo "SKIP test_dsf_inc6: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Generator is header-only."
    exit 0
fi

echo "test_dsf_inc6: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc6.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

AGREEVARS="gen_agree_00 gen_agree_01 gen_agree_02 gen_agree_03 gen_agree_04 gen_agree_05"

# ── assertion 1: --list shows all 6 baked agreement variants + the self-test ──
LIST="$("$DSF" --list 2>&1)"
for s in $AGREEVARS gen_disagree_selftest; do
    if echo "$LIST" | grep -q "^  $s"; then ok "--list contains $s"
    else fail "--list missing '$s'"; fi
done

# ── assertion 2: each baked agree variant is deterministic + converges ──────
for s in $AGREEVARS; do
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
    if [ -z "$bad" ]; then ok "$s converges non-vacuously across 4 seeds"
    else fail "$s failed / vacuous @$bad"; fi
done

# ── assertion 3: the self-test fires the no-split checker ────────────────────
OUT="$("$DSF" --scenario gen_disagree_selftest --seed 0xA6 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "gen_disagree_selftest exits 0 (planted equivocation caught)"
else fail "gen_disagree_selftest exited $rc (expected 0 for expect-violation self-test)"; fi
if echo "$OUT" | grep -q "agree_no_split"; then ok "gen_disagree_selftest fired the correct invariant (agree_no_split)"
else fail "gen_disagree_selftest did NOT fire agree_no_split"; fi
if echo "$OUT" | grep -qi "seed 0xa6"; then ok "gen_disagree_selftest prints the reproducing seed"
else fail "gen_disagree_selftest did not print the reproducing seed"; fi

# ── assertion 4: --template agree routes --generate to the agreement template ─
AGEN="$("$DSF" --generate 6 --seed 0xFEED --template agree --list 2>&1)"
NA="$(echo "$AGEN" | grep -cE '^  gen_run_[0-9][0-9]')"
if [ "$NA" -eq 6 ]; then ok "--template agree --generate 6 registers 6 gen_run variants"
else fail "--template agree --generate 6 -> $NA gen_run variants (expected 6)"; fi
if echo "$AGEN" | grep -A1 '^  gen_run_00' | grep -qi 'agreement'; then
    ok "--template agree gen_run variants use the AGREEMENT template"
else
    fail "--template agree gen_run variant description is not the agreement template"
fi

# ── assertion 5: regression — default template is still broadcast ────────────
BGEN="$("$DSF" --generate 6 --seed 0xFEED --list 2>&1)"
if echo "$BGEN" | grep -A1 '^  gen_run_00' | grep -qi 'reliable-broadcast'; then
    ok "default --generate (no --template) is still the broadcast template (inc-5 path intact)"
else
    fail "default --generate is no longer the broadcast template (inc-5 regression!)"
fi

# ── assertion 6: a generated agreement variant runs + replays byte-identically ─
"$DSF" --generate 6 --seed 0xFEED --template agree --scenario gen_run_02 --trace "$TMPD/ga_a.log" --quiet >/dev/null 2>&1
"$DSF" --generate 6 --seed 0xFEED --template agree --scenario gen_run_02 --trace "$TMPD/ga_b.log" --quiet >/dev/null 2>&1
OUT="$("$DSF" --generate 6 --seed 0xFEED --template agree --scenario gen_run_02 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ -s "$TMPD/ga_a.log" ] && diff -q "$TMPD/ga_a.log" "$TMPD/ga_b.log" >/dev/null 2>&1 \
   && echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps'; then
    ok "generated agreement variant runs, converges, and replays byte-identically (§Q6)"
else
    fail "generated agreement variant did not converge / replay (rc=$rc)"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc6 (2nd generator template — single-value-flood agreement: 6 deterministic always-converging variants, a self-test that catches an equivocating leader, and a --template selector; inc-5 broadcast default intact)"
    exit 0
else
    echo "  FAIL: test_dsf_inc6 ($FAILS assertion(s))"
    exit 1
fi
