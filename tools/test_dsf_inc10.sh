#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 10 — a SIXTH generator
# template: F2 view RECONCILIATION (§Q7 no-phantom-evidence).
#
# Increments 4-9 shipped five generator templates (reliable-broadcast
# no-overcount; single-value-flood agreement no-split; monotone ratchet
# non-regression; quorum/threshold no-early-commit; receipt-conservation
# no-double-credit). Increment 10 adds a sixth §Q7 checker family under the
# same randomized fault profiles: two sources each flood their half of a
# growing entry universe (src_a odd ids, src_b even ids); each reconciler
# merges by union-keyed-on-entry-id (the production F2 no_phantom_evidence
# rule: a reconciler must never hold evidence present in NEITHER source
# view), so re-delivery and reorder never fabricate or duplicate evidence —
# robust by construction under any drawn drop/dup/latency/jitter profile. A
# `--template broadcast|agree|ratchet|quorum|conserve|recon` selector routes
# `--generate`.
# Build-agnostic: SKIP-clean if determ-dsf isn't built. Asserts:
#   1. --list shows all 6 baked gen_recon_NN + gen_phantom_selftest.
#   2. Each baked gen_recon_NN is run-deterministic AND advances non-vacuously
#      across several seeds (safety recon_no_phantom + liveness recon_complete).
#   3. gen_phantom_selftest exits 0, fires recon_no_phantom, prints the repro
#      seed (a reconciler fabricating a phantom entry no source issued is
#      caught on a clean-delivery profile).
#   4. --template recon --generate N --list shows N gen_run_NN whose
#      description is the RECONCILIATION template (not the other five).
#   5. REGRESSION GUARD: --generate N with no --template still yields the
#      broadcast template (inc-5 default path unchanged); --template agree /
#      ratchet / quorum / conserve still route to their families (inc-6/7/8/9
#      intact).
#   6. A generated reconciliation variant runs, merges the full universe, and
#      replays byte-identically.
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
    echo "SKIP test_dsf_inc10: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Generator is header-only."
    exit 0
fi

echo "test_dsf_inc10: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc10.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

RECONVARS="gen_recon_00 gen_recon_01 gen_recon_02 gen_recon_03 gen_recon_04 gen_recon_05"

# ── assertion 1: --list shows all 6 baked recon variants + the self-test ──────
LIST="$("$DSF" --list 2>&1)"
for s in $RECONVARS gen_phantom_selftest; do
    if echo "$LIST" | grep -q "^  $s"; then ok "--list contains $s"
    else fail "--list missing '$s'"; fi
done

# ── assertion 2: each baked recon variant is deterministic + advances ─────────
for s in $RECONVARS; do
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

# ── assertion 3: the self-test fires the no-phantom checker ───────────────────
OUT="$("$DSF" --scenario gen_phantom_selftest --seed 0xA6 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "gen_phantom_selftest exits 0 (planted phantom caught)"
else fail "gen_phantom_selftest exited $rc (expected 0 for expect-violation self-test)"; fi
if echo "$OUT" | grep -q "recon_no_phantom"; then ok "gen_phantom_selftest fired the correct invariant (recon_no_phantom)"
else fail "gen_phantom_selftest did NOT fire recon_no_phantom"; fi
if echo "$OUT" | grep -qi "seed 0xa6"; then ok "gen_phantom_selftest prints the reproducing seed"
else fail "gen_phantom_selftest did not print the reproducing seed"; fi

# ── assertion 4: --template recon routes --generate correctly ─────────────────
RGEN="$("$DSF" --generate 6 --seed 0xFEED --template recon --list 2>&1)"
NR="$(echo "$RGEN" | grep -cE '^  gen_run_[0-9][0-9]')"
if [ "$NR" -eq 6 ]; then ok "--template recon --generate 6 registers 6 gen_run variants"
else fail "--template recon --generate 6 -> $NR gen_run variants (expected 6)"; fi
if echo "$RGEN" | grep -A1 '^  gen_run_00' | grep -qi 'view-reconciliation'; then
    ok "--template recon gen_run variants use the RECONCILIATION template"
else
    fail "--template recon gen_run variant description is not the reconciliation template"
fi

# ── assertion 5: regression — default broadcast; the other four still route ───
BGEN="$("$DSF" --generate 6 --seed 0xFEED --list 2>&1)"
if echo "$BGEN" | grep -A1 '^  gen_run_00' | grep -qi 'reliable-broadcast'; then
    ok "default --generate (no --template) is still the broadcast template (inc-5 path intact)"
else
    fail "default --generate is no longer the broadcast template (inc-5 regression!)"
fi
for pair in "agree:agreement:inc-6" "ratchet:ratchet:inc-7" "quorum:quorum:inc-8" "conserve:receipt-conservation:inc-9"; do
    tname="${pair%%:*}"; rest="${pair#*:}"; needle="${rest%%:*}"; inc="${rest#*:}"
    TGEN="$("$DSF" --generate 6 --seed 0xFEED --template "$tname" --list 2>&1)"
    if echo "$TGEN" | grep -A1 '^  gen_run_00' | grep -qi "$needle"; then
        ok "--template $tname still routes to its template ($inc path intact)"
    else
        fail "--template $tname no longer routes to its template ($inc regression!)"
    fi
done

# ── assertion 6: a generated recon variant runs + replays byte-identically ────
"$DSF" --generate 6 --seed 0xFEED --template recon --scenario gen_run_02 --trace "$TMPD/gr_a.log" --quiet >/dev/null 2>&1
"$DSF" --generate 6 --seed 0xFEED --template recon --scenario gen_run_02 --trace "$TMPD/gr_b.log" --quiet >/dev/null 2>&1
OUT="$("$DSF" --generate 6 --seed 0xFEED --template recon --scenario gen_run_02 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ -s "$TMPD/gr_a.log" ] && diff -q "$TMPD/gr_a.log" "$TMPD/gr_b.log" >/dev/null 2>&1 \
   && echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps'; then
    ok "generated reconciliation variant runs, merges, and replays byte-identically (§Q6)"
else
    fail "generated reconciliation variant did not advance / replay (rc=$rc)"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc10 (6th generator template — F2 view reconciliation: 6 deterministic always-merging variants, a self-test that catches a reconciler fabricating phantom evidence no source issued, and a --template recon selector; inc-5 broadcast + inc-6 agreement + inc-7 ratchet + inc-8 quorum + inc-9 conservation defaults intact)"
    exit 0
else
    echo "  FAIL: test_dsf_inc10 ($FAILS assertion(s))"
    exit 1
fi
