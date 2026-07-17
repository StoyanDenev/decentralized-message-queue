#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 11 — a SEVENTH generator
# template: CRASH/RECOVER replay (§Q7 crash-recovery / non-idempotent-replay).
#
# Increments 4-10 shipped six generator templates, all exercising ONLY the
# message-fault seam (drop/dup/latency/jitter). Increment 11 is the first
# generated template to exercise the simulator's CRASH/RECOVER seam
# (Node::alive — deliveries to a crashed node are dropped, its kv persists):
# every follower crashes and recovers on a deterministic index-derived
# schedule layered under the drawn fault profile. Because state persists, the
# honest recovery procedure does NOTHING (the leader's re-flood heals the
# missed window, like a transient drop burst); the planted bug is the classic
# NON-IDEMPOTENT RECOVERY REPLAY — re-applying the pre-crash journal on top
# of persisted state. A `--template ...|crashrec` selector routes --generate.
# Build-agnostic: SKIP-clean if determ-dsf isn't built. Asserts:
#   1. --list shows all 6 baked gen_crashrec_NN + gen_replay_selftest.
#   2. Each baked gen_crashrec_NN is run-deterministic AND advances
#      non-vacuously across several seeds (safety crashrec_no_replay +
#      liveness crashrec_all_converged, which itself REQUIRES crashes ==
#      recoveries == followers, so the crash path can never go vacuous).
#   3. A baked variant's trace contains CRASH and RECOVER events (the new
#      fault seam demonstrably exercised).
#   4. gen_replay_selftest exits 0, fires crashrec_no_replay, prints the repro
#      seed (a recovery procedure double-applying its journal is caught).
#   5. --template crashrec --generate N --list shows N gen_run_NN whose
#      description is the CRASH/RECOVER template (not the other six).
#   6. REGRESSION GUARD: --generate N with no --template still yields the
#      broadcast template; --template agree/ratchet/quorum/conserve/recon
#      still route to their families (inc-6..10 intact).
#   7. A generated crashrec variant runs, converges, and replays
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
    echo "SKIP test_dsf_inc11: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Generator is header-only."
    exit 0
fi

echo "test_dsf_inc11: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc11.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

CRVARS="gen_crashrec_00 gen_crashrec_01 gen_crashrec_02 gen_crashrec_03 gen_crashrec_04 gen_crashrec_05"

# ── assertion 1: --list shows all 6 baked crashrec variants + the self-test ──
LIST="$("$DSF" --list 2>&1)"
for s in $CRVARS gen_replay_selftest; do
    if echo "$LIST" | grep -q "^  $s"; then ok "--list contains $s"
    else fail "--list missing '$s'"; fi
done

# ── assertion 2: each baked variant is deterministic + advances ───────────────
for s in $CRVARS; do
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

# ── assertion 3: the crash seam demonstrably fires (trace-level) ──────────────
NC="$(grep -c 'CRASH'   "$TMPD/gen_crashrec_00_a.log" 2>/dev/null || echo 0)"
NR="$(grep -c 'RECOVER' "$TMPD/gen_crashrec_00_a.log" 2>/dev/null || echo 0)"
if [ "$NC" -ge 1 ] && [ "$NR" -ge 1 ] && [ "$NC" -eq "$NR" ]; then
    ok "gen_crashrec_00 trace shows $NC CRASH + $NR RECOVER events (crash seam exercised)"
else
    fail "gen_crashrec_00 trace CRASH/RECOVER events missing or unbalanced (crash=$NC recover=$NR)"
fi

# ── assertion 4: the self-test fires the no-replay checker ────────────────────
OUT="$("$DSF" --scenario gen_replay_selftest --seed 0xA6 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "gen_replay_selftest exits 0 (planted recovery replay caught)"
else fail "gen_replay_selftest exited $rc (expected 0 for expect-violation self-test)"; fi
if echo "$OUT" | grep -q "crashrec_no_replay"; then ok "gen_replay_selftest fired the correct invariant (crashrec_no_replay)"
else fail "gen_replay_selftest did NOT fire crashrec_no_replay"; fi
if echo "$OUT" | grep -qi "seed 0xa6"; then ok "gen_replay_selftest prints the reproducing seed"
else fail "gen_replay_selftest did not print the reproducing seed"; fi

# ── assertion 5: --template crashrec routes --generate correctly ──────────────
CGEN="$("$DSF" --generate 6 --seed 0xFEED --template crashrec --list 2>&1)"
NG="$(echo "$CGEN" | grep -cE '^  gen_run_[0-9][0-9]')"
if [ "$NG" -eq 6 ]; then ok "--template crashrec --generate 6 registers 6 gen_run variants"
else fail "--template crashrec --generate 6 -> $NG gen_run variants (expected 6)"; fi
if echo "$CGEN" | grep -A1 '^  gen_run_00' | grep -qi 'crash/recover'; then
    ok "--template crashrec gen_run variants use the CRASH/RECOVER template"
else
    fail "--template crashrec gen_run variant description is not the crash/recover template"
fi

# ── assertion 6: regression — default broadcast; the other five still route ───
BGEN="$("$DSF" --generate 6 --seed 0xFEED --list 2>&1)"
if echo "$BGEN" | grep -A1 '^  gen_run_00' | grep -qi 'reliable-broadcast'; then
    ok "default --generate (no --template) is still the broadcast template (inc-5 path intact)"
else
    fail "default --generate is no longer the broadcast template (inc-5 regression!)"
fi
for pair in "agree:agreement:inc-6" "ratchet:ratchet:inc-7" "quorum:quorum:inc-8" "conserve:receipt-conservation:inc-9" "recon:view-reconciliation:inc-10"; do
    tname="${pair%%:*}"; rest="${pair#*:}"; needle="${rest%%:*}"; inc="${rest#*:}"
    TGEN="$("$DSF" --generate 6 --seed 0xFEED --template "$tname" --list 2>&1)"
    if echo "$TGEN" | grep -A1 '^  gen_run_00' | grep -qi "$needle"; then
        ok "--template $tname still routes to its template ($inc path intact)"
    else
        fail "--template $tname no longer routes to its template ($inc regression!)"
    fi
done

# ── assertion 7: a generated crashrec variant runs + replays byte-identically ─
"$DSF" --generate 6 --seed 0xFEED --template crashrec --scenario gen_run_02 --trace "$TMPD/gcr_a.log" --quiet >/dev/null 2>&1
"$DSF" --generate 6 --seed 0xFEED --template crashrec --scenario gen_run_02 --trace "$TMPD/gcr_b.log" --quiet >/dev/null 2>&1
OUT="$("$DSF" --generate 6 --seed 0xFEED --template crashrec --scenario gen_run_02 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ -s "$TMPD/gcr_a.log" ] && diff -q "$TMPD/gcr_a.log" "$TMPD/gcr_b.log" >/dev/null 2>&1 \
   && echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps'; then
    ok "generated crashrec variant runs, converges, and replays byte-identically (§Q6)"
else
    fail "generated crashrec variant did not advance / replay (rc=$rc)"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc11 (7th generator template — crash/recover replay: 6 deterministic always-converging variants with a per-follower crash/recover schedule under the drawn profile, a self-test that catches a non-idempotent recovery replay, and a --template crashrec selector; inc-5..10 defaults intact)"
    exit 0
else
    echo "  FAIL: test_dsf_inc11 ($FAILS assertion(s))"
    exit 1
fi
