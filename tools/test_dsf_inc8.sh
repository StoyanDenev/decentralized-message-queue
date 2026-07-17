#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 8 — a FOURTH generator
# template: quorum/threshold COMMIT (§Q7 DKG-threshold / BFT-pre-vote / merge).
#
# Increments 4-7 shipped three generator templates (reliable-broadcast
# no-overcount; single-value-flood agreement no-split; monotone ratchet
# non-regression). Increment 8 adds a fourth §Q7 checker family under the same
# randomized fault profiles: a set of ACK sources each ack a single collector;
# the collector counts DISTINCT senders (a set keyed on the sender id, so
# duplicate acks from one source do NOT inflate the tally) and commits exactly
# once that distinct count reaches quorum K = floor(N/2)+1. Distinct-set
# insertion is idempotent under duplication and reorder-immune, so — like the
# other three templates — every generated variant is robust under any drawn
# drop/dup/latency/jitter profile (it eventually reaches quorum, and it never
# commits below it). A `--template broadcast|agree|ratchet|quorum` selector
# routes `--generate`.
# Build-agnostic: SKIP-clean if determ-dsf isn't built. Asserts:
#   1. --list shows all 6 baked gen_quorum_NN + gen_underquorum_selftest.
#   2. Each baked gen_quorum_NN is run-deterministic AND advances non-vacuously
#      across several seeds (safety quorum_no_early_commit + liveness
#      quorum_commits).
#   3. gen_underquorum_selftest exits 0, fires quorum_no_early_commit, prints the
#      repro seed (a raw-ack-counting collector committing below the distinct
#      threshold under forced duplication is caught).
#   4. --template quorum --generate N --list shows N gen_run_NN whose description
#      is the QUORUM template (not broadcast/agreement/ratchet).
#   5. REGRESSION GUARD: --generate N with no --template still yields the
#      broadcast template (inc-5 default path unchanged); --template agree still
#      routes to agreement (inc-6 intact); --template ratchet still routes to
#      ratchet (inc-7 intact).
#   6. A generated quorum variant runs, advances, and replays byte-identically.
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
    echo "SKIP test_dsf_inc8: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Generator is header-only."
    exit 0
fi

echo "test_dsf_inc8: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc8.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

QUORUMVARS="gen_quorum_00 gen_quorum_01 gen_quorum_02 gen_quorum_03 gen_quorum_04 gen_quorum_05"

# ── assertion 1: --list shows all 6 baked quorum variants + the self-test ─────
LIST="$("$DSF" --list 2>&1)"
for s in $QUORUMVARS gen_underquorum_selftest; do
    if echo "$LIST" | grep -q "^  $s"; then ok "--list contains $s"
    else fail "--list missing '$s'"; fi
done

# ── assertion 2: each baked quorum variant is deterministic + advances ────────
for s in $QUORUMVARS; do
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

# ── assertion 3: the self-test fires the no-early-commit checker ──────────────
OUT="$("$DSF" --scenario gen_underquorum_selftest --seed 0xA6 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "gen_underquorum_selftest exits 0 (planted under-quorum commit caught)"
else fail "gen_underquorum_selftest exited $rc (expected 0 for expect-violation self-test)"; fi
if echo "$OUT" | grep -q "quorum_no_early_commit"; then ok "gen_underquorum_selftest fired the correct invariant (quorum_no_early_commit)"
else fail "gen_underquorum_selftest did NOT fire quorum_no_early_commit"; fi
if echo "$OUT" | grep -qi "seed 0xa6"; then ok "gen_underquorum_selftest prints the reproducing seed"
else fail "gen_underquorum_selftest did not print the reproducing seed"; fi

# ── assertion 4: --template quorum routes --generate to the quorum template ───
QGEN="$("$DSF" --generate 6 --seed 0xFEED --template quorum --list 2>&1)"
NR="$(echo "$QGEN" | grep -cE '^  gen_run_[0-9][0-9]')"
if [ "$NR" -eq 6 ]; then ok "--template quorum --generate 6 registers 6 gen_run variants"
else fail "--template quorum --generate 6 -> $NR gen_run variants (expected 6)"; fi
if echo "$QGEN" | grep -A1 '^  gen_run_00' | grep -qi 'quorum'; then
    ok "--template quorum gen_run variants use the QUORUM template"
else
    fail "--template quorum gen_run variant description is not the quorum template"
fi

# ── assertion 5: regression — default broadcast; agree/ratchet still route ────
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

# ── assertion 6: a generated quorum variant runs + replays byte-identically ───
"$DSF" --generate 6 --seed 0xFEED --template quorum --scenario gen_run_02 --trace "$TMPD/gq_a.log" --quiet >/dev/null 2>&1
"$DSF" --generate 6 --seed 0xFEED --template quorum --scenario gen_run_02 --trace "$TMPD/gq_b.log" --quiet >/dev/null 2>&1
OUT="$("$DSF" --generate 6 --seed 0xFEED --template quorum --scenario gen_run_02 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ -s "$TMPD/gq_a.log" ] && diff -q "$TMPD/gq_a.log" "$TMPD/gq_b.log" >/dev/null 2>&1 \
   && echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps'; then
    ok "generated quorum variant runs, advances, and replays byte-identically (§Q6)"
else
    fail "generated quorum variant did not advance / replay (rc=$rc)"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc8 (4th generator template — quorum/threshold commit: 6 deterministic always-reaching-quorum variants, a self-test that catches a raw-ack-counting collector committing below the distinct threshold under forced duplication, and a --template quorum selector; inc-5 broadcast + inc-6 agreement + inc-7 ratchet defaults intact)"
    exit 0
else
    echo "  FAIL: test_dsf_inc8 ($FAILS assertion(s))"
    exit 1
fi
