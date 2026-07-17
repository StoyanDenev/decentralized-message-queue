#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 9 — a FIFTH generator
# template: cross-shard receipt CONSERVATION (§Q7 FA7 no-double-credit).
#
# Increments 4-8 shipped four generator templates (reliable-broadcast
# no-overcount; single-value-flood agreement no-split; monotone ratchet
# non-regression; quorum/threshold no-early-commit). Increment 9 adds a fifth
# §Q7 checker family under the same randomized fault profiles: a source issues
# receipts with unique ids and re-floods them; each ledger credits a receipt
# EXACTLY ONCE, keyed on its id (the production FA7 applied-receipt registry
# rule), so a duplicated or re-delivered receipt never inflates the credited
# total — robust by construction under any drawn drop/dup/latency/jitter
# profile (per-id dedup is idempotent + reorder-immune; the re-flood makes it
# drop-tolerant). A `--template broadcast|agree|ratchet|quorum|conserve`
# selector routes `--generate`.
# Build-agnostic: SKIP-clean if determ-dsf isn't built. Asserts:
#   1. --list shows all 6 baked gen_conserve_NN + gen_doublecredit_selftest.
#   2. Each baked gen_conserve_NN is run-deterministic AND advances
#      non-vacuously across several seeds (safety conserve_no_double_credit +
#      liveness conserve_all_credited).
#   3. gen_doublecredit_selftest exits 0, fires conserve_no_double_credit,
#      prints the repro seed (a raw-delivery-counting ledger double-crediting
#      a re-delivered receipt under forced duplication is caught).
#   4. --template conserve --generate N --list shows N gen_run_NN whose
#      description is the CONSERVATION template (not the other four).
#   5. REGRESSION GUARD: --generate N with no --template still yields the
#      broadcast template (inc-5 default path unchanged); --template agree /
#      ratchet / quorum still route to their families (inc-6/7/8 intact).
#   6. A generated conservation variant runs, credits everything, and replays
#      byte-identically.
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
    echo "SKIP test_dsf_inc9: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Generator is header-only."
    exit 0
fi

echo "test_dsf_inc9: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc9.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

CONSVARS="gen_conserve_00 gen_conserve_01 gen_conserve_02 gen_conserve_03 gen_conserve_04 gen_conserve_05"

# ── assertion 1: --list shows all 6 baked conservation variants + self-test ──
LIST="$("$DSF" --list 2>&1)"
for s in $CONSVARS gen_doublecredit_selftest; do
    if echo "$LIST" | grep -q "^  $s"; then ok "--list contains $s"
    else fail "--list missing '$s'"; fi
done

# ── assertion 2: each baked variant is deterministic + advances ───────────────
for s in $CONSVARS; do
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

# ── assertion 3: the self-test fires the no-double-credit checker ─────────────
OUT="$("$DSF" --scenario gen_doublecredit_selftest --seed 0xA6 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "gen_doublecredit_selftest exits 0 (planted double-credit caught)"
else fail "gen_doublecredit_selftest exited $rc (expected 0 for expect-violation self-test)"; fi
if echo "$OUT" | grep -q "conserve_no_double_credit"; then ok "gen_doublecredit_selftest fired the correct invariant (conserve_no_double_credit)"
else fail "gen_doublecredit_selftest did NOT fire conserve_no_double_credit"; fi
if echo "$OUT" | grep -qi "seed 0xa6"; then ok "gen_doublecredit_selftest prints the reproducing seed"
else fail "gen_doublecredit_selftest did not print the reproducing seed"; fi

# ── assertion 4: --template conserve routes --generate correctly ──────────────
CGEN="$("$DSF" --generate 6 --seed 0xFEED --template conserve --list 2>&1)"
NR="$(echo "$CGEN" | grep -cE '^  gen_run_[0-9][0-9]')"
if [ "$NR" -eq 6 ]; then ok "--template conserve --generate 6 registers 6 gen_run variants"
else fail "--template conserve --generate 6 -> $NR gen_run variants (expected 6)"; fi
if echo "$CGEN" | grep -A1 '^  gen_run_00' | grep -qi 'receipt-conservation'; then
    ok "--template conserve gen_run variants use the CONSERVATION template"
else
    fail "--template conserve gen_run variant description is not the conservation template"
fi

# ── assertion 5: regression — default broadcast; agree/ratchet/quorum intact ──
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
RGEN="$("$DSF" --generate 6 --seed 0xFEED --template ratchet --list 2>&1)"
if echo "$RGEN" | grep -A1 '^  gen_run_00' | grep -qi 'ratchet'; then
    ok "--template ratchet still routes to the ratchet template (inc-7 path intact)"
else
    fail "--template ratchet no longer routes to ratchet (inc-7 regression!)"
fi
QGEN="$("$DSF" --generate 6 --seed 0xFEED --template quorum --list 2>&1)"
if echo "$QGEN" | grep -A1 '^  gen_run_00' | grep -qi 'quorum'; then
    ok "--template quorum still routes to the quorum template (inc-8 path intact)"
else
    fail "--template quorum no longer routes to quorum (inc-8 regression!)"
fi

# ── assertion 6: a generated variant runs + replays byte-identically ──────────
"$DSF" --generate 6 --seed 0xFEED --template conserve --scenario gen_run_02 --trace "$TMPD/gc_a.log" --quiet >/dev/null 2>&1
"$DSF" --generate 6 --seed 0xFEED --template conserve --scenario gen_run_02 --trace "$TMPD/gc_b.log" --quiet >/dev/null 2>&1
OUT="$("$DSF" --generate 6 --seed 0xFEED --template conserve --scenario gen_run_02 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ -s "$TMPD/gc_a.log" ] && diff -q "$TMPD/gc_a.log" "$TMPD/gc_b.log" >/dev/null 2>&1 \
   && echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps'; then
    ok "generated conservation variant runs, credits everything, and replays byte-identically (§Q6)"
else
    fail "generated conservation variant did not advance / replay (rc=$rc)"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc9 (5th generator template — cross-shard receipt conservation: 6 deterministic always-crediting variants, a self-test that catches a raw-delivery-counting ledger double-crediting under forced duplication, and a --template conserve selector; inc-5 broadcast + inc-6 agreement + inc-7 ratchet + inc-8 quorum defaults intact)"
    exit 0
else
    echo "  FAIL: test_dsf_inc9 ($FAILS assertion(s))"
    exit 1
fi
