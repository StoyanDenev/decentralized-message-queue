#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 14 — a NINTH generator
# template: committee-rotation FAIRNESS (§Q7 selective-abort / selection-bias).
#
# The last untapped §Q7 checker family from the GeneratorTemplateFamily.md
# recipe: a leader runs 12 selection rounds and must rotate FAIRLY over the N
# candidates (the inc-2/3 hand-written `no_selection_bias` checker, now under
# generated fault profiles). Honest selector = deterministic round-robin
# sel(r) = r % N, so no candidate is ever assigned more than ceil(rounds/N)
# selections at any point of the ramp; candidates dedup notifications by
# round id (dup harmless) and the leader re-floods every completed round
# (drop healed). 12 divides evenly by every drawn N in {2,3,4}, so the final
# fair share is exact. A `--template ...|rotation` selector routes --generate.
# Build-agnostic: SKIP-clean if determ-dsf isn't built. Asserts:
#   1. --list shows all 6 baked gen_rotation_NN + gen_bias_selftest.
#   2. Each baked gen_rotation_NN is run-deterministic AND advances
#      non-vacuously across several seeds (safety rotation_no_bias +
#      liveness rotation_fair_complete, which REQUIRES rounds == 12 AND an
#      exact fair share per candidate).
#   3. gen_bias_selftest exits 0, fires rotation_no_bias, prints the repro
#      seed (a biased selector starving f0 is caught).
#   4. --template rotation --generate N --list shows N gen_run_NN whose
#      description is the ROTATION template (not the other eight).
#   5. REGRESSION GUARD: --generate N with no --template still yields the
#      broadcast template; --template agree/ratchet/quorum/conserve/recon/
#      crashrec/partition still route to their families (inc-6..12 intact).
#   6. A generated rotation variant runs, distributes fairly, and replays
#      byte-identically — including under the inc-13 --gen-seed form.
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
    echo "SKIP test_dsf_inc14: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Generator is header-only."
    exit 0
fi

echo "test_dsf_inc14: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc14.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

ROTVARS="gen_rotation_00 gen_rotation_01 gen_rotation_02 gen_rotation_03 gen_rotation_04 gen_rotation_05"

# ── assertion 1: --list shows all 6 baked rotation variants + the self-test ──
LIST="$("$DSF" --list 2>&1)"
for s in $ROTVARS gen_bias_selftest; do
    if echo "$LIST" | grep -q "^  $s"; then ok "--list contains $s"
    else fail "--list missing '$s'"; fi
done

# ── assertion 2: each baked variant is deterministic + advances ───────────────
for s in $ROTVARS; do
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

# ── assertion 3: the self-test fires the no-bias checker ──────────────────────
OUT="$("$DSF" --scenario gen_bias_selftest --seed 0xA6 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "gen_bias_selftest exits 0 (planted selection bias caught)"
else fail "gen_bias_selftest exited $rc (expected 0 for expect-violation self-test)"; fi
if echo "$OUT" | grep -q "rotation_no_bias"; then ok "gen_bias_selftest fired the correct invariant (rotation_no_bias)"
else fail "gen_bias_selftest did NOT fire rotation_no_bias"; fi
if echo "$OUT" | grep -qi "seed 0xa6"; then ok "gen_bias_selftest prints the reproducing seed"
else fail "gen_bias_selftest did not print the reproducing seed"; fi

# ── assertion 4: --template rotation routes --generate correctly ──────────────
RGEN="$("$DSF" --generate 6 --seed 0xFEED --template rotation --list 2>&1)"
NG="$(echo "$RGEN" | grep -cE '^  gen_run_[0-9][0-9]')"
if [ "$NG" -eq 6 ]; then ok "--template rotation --generate 6 registers 6 gen_run variants"
else fail "--template rotation --generate 6 -> $NG gen_run variants (expected 6)"; fi
if echo "$RGEN" | grep -A1 '^  gen_run_00' | grep -qi 'rotation-fairness'; then
    ok "--template rotation gen_run variants use the ROTATION template"
else
    fail "--template rotation gen_run variant description is not the rotation template"
fi

# ── assertion 5: regression — default broadcast; the other seven still route ──
BGEN="$("$DSF" --generate 6 --seed 0xFEED --list 2>&1)"
if echo "$BGEN" | grep -A1 '^  gen_run_00' | grep -qi 'reliable-broadcast'; then
    ok "default --generate (no --template) is still the broadcast template (inc-5 path intact)"
else
    fail "default --generate is no longer the broadcast template (inc-5 regression!)"
fi
for pair in "agree:agreement:inc-6" "ratchet:ratchet:inc-7" "quorum:quorum:inc-8" "conserve:receipt-conservation:inc-9" "recon:view-reconciliation:inc-10" "crashrec:crash/recover:inc-11" "partition:partition/heal:inc-12"; do
    tname="${pair%%:*}"; rest="${pair#*:}"; needle="${rest%%:*}"; inc="${rest#*:}"
    TGEN="$("$DSF" --generate 6 --seed 0xFEED --template "$tname" --list 2>&1)"
    if echo "$TGEN" | grep -A1 '^  gen_run_00' | grep -qi "$needle"; then
        ok "--template $tname still routes to its template ($inc path intact)"
    else
        fail "--template $tname no longer routes to its template ($inc regression!)"
    fi
done

# ── assertion 6: generated variant runs + replays, incl. the --gen-seed form ──
"$DSF" --generate 6 --gen-seed 0xC3 --seed 0x5 --template rotation --scenario gen_run_01 --trace "$TMPD/gr_a.log" --quiet >/dev/null 2>&1
"$DSF" --generate 6 --gen-seed 0xC3 --seed 0x5 --template rotation --scenario gen_run_01 --trace "$TMPD/gr_b.log" --quiet >/dev/null 2>&1
OUT="$("$DSF" --generate 6 --gen-seed 0xC3 --seed 0x5 --template rotation --scenario gen_run_01 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ -s "$TMPD/gr_a.log" ] && diff -q "$TMPD/gr_a.log" "$TMPD/gr_b.log" >/dev/null 2>&1 \
   && echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps'; then
    ok "generated rotation variant runs fairly and replays byte-identically under --gen-seed (§Q6 + inc-13)"
else
    fail "generated rotation variant did not advance / replay under --gen-seed (rc=$rc)"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc14 (9th generator template — committee-rotation fairness: 6 deterministic exactly-fair variants, a self-test that catches a biased selector starving a candidate, and a --template rotation selector; inc-5..12 defaults intact; composes with the inc-13 --gen-seed form)"
    exit 0
else
    echo "  FAIL: test_dsf_inc14 ($FAILS assertion(s))"
    exit 1
fi
