#!/usr/bin/env bash
# DSF (Deterministic-Simulation Framework) INCREMENT 12 — an EIGHTH generator
# template: PARTITION/HEAL split-brain (§Q7 partition-quorum).
#
# Increment 11 brought the crash/recover seam into the generator; increment 12
# brings the PARTITION seam (NetModel link cuts, decided at send time, healed
# later). Two quorum collectors observe the same N ack sources; col_a keeps
# full connectivity, col_b is cut from ceil(N/2) of the N sources for a
# deterministic window, leaving it exactly K-1 reachable senders — one short
# of quorum. An honest minority-side collector CANNOT commit while partitioned
# (distinct-sender counting defeats dup) and commits only after the heal.
# The planted bug is the inc-3 `single_decision` class: col_b's effective
# quorum mis-set to K-1 — exactly its reachable minority — so it commits
# WHILE PARTITIONED. A `--template ...|partition` selector routes --generate.
# Build-agnostic: SKIP-clean if determ-dsf isn't built. Asserts:
#   1. --list shows all 6 baked gen_partition_NN + gen_splitbrain_selftest.
#   2. Each baked gen_partition_NN is run-deterministic AND advances
#      non-vacuously across several seeds (safety part_no_minority_commit +
#      liveness part_both_commit, which itself REQUIRES the heal to have
#      happened, so the partition window can never go vacuous).
#   3. A baked variant's trace contains partition-reason drops (the partition
#      seam demonstrably exercised).
#   4. gen_splitbrain_selftest exits 0, fires part_no_minority_commit, prints
#      the repro seed (a mis-set minority quorum committing pre-heal is
#      caught).
#   5. --template partition --generate N --list shows N gen_run_NN whose
#      description is the PARTITION/HEAL template (not the other seven).
#   6. REGRESSION GUARD: --generate N with no --template still yields the
#      broadcast template; --template agree/ratchet/quorum/conserve/recon/
#      crashrec still route to their families (inc-6..11 intact).
#   7. A generated partition variant runs, commits both sides, and replays
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
    echo "SKIP test_dsf_inc12: determ-dsf not built (set DETERM_DSF_BIN=/abs/path"
    echo "     or build the determ-dsf CMake target). Generator is header-only."
    exit 0
fi

echo "test_dsf_inc12: using $DSF"

FAILS=0
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
ok()   { echo "  ok: $*"; }

TMPD="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dsf_inc12.$$")"
mkdir -p "$TMPD"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

PTVARS="gen_partition_00 gen_partition_01 gen_partition_02 gen_partition_03 gen_partition_04 gen_partition_05"

# ── assertion 1: --list shows all 6 baked partition variants + the self-test ──
LIST="$("$DSF" --list 2>&1)"
for s in $PTVARS gen_splitbrain_selftest; do
    if echo "$LIST" | grep -q "^  $s"; then ok "--list contains $s"
    else fail "--list missing '$s'"; fi
done

# ── assertion 2: each baked variant is deterministic + advances ───────────────
for s in $PTVARS; do
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

# ── assertion 3: the partition seam demonstrably fires (trace-level) ──────────
# Anchor on the trace kind column (' DROP partition') — a bare 'partition' grep
# would also match the SCENARIO header line (the scenario NAME contains
# "partition"), making the >=1 gate vacuous. grep -c always prints a count for
# a readable file, so default only the missing-file case (no `|| echo 0`,
# which would double-emit "0\n0" on zero matches and break the -ge test).
NP="$(grep -c ' DROP partition' "$TMPD/gen_partition_00_a.log" 2>/dev/null)"
NP="${NP:-0}"
if [ "$NP" -ge 1 ]; then
    ok "gen_partition_00 trace shows $NP partition-reason drops (partition seam exercised)"
else
    fail "gen_partition_00 trace shows NO partition-reason drops (seam not exercised)"
fi

# ── assertion 4: the self-test fires the no-minority-commit checker ───────────
OUT="$("$DSF" --scenario gen_splitbrain_selftest --seed 0xA6 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then ok "gen_splitbrain_selftest exits 0 (planted split-brain caught)"
else fail "gen_splitbrain_selftest exited $rc (expected 0 for expect-violation self-test)"; fi
if echo "$OUT" | grep -q "part_no_minority_commit"; then ok "gen_splitbrain_selftest fired the correct invariant (part_no_minority_commit)"
else fail "gen_splitbrain_selftest did NOT fire part_no_minority_commit"; fi
if echo "$OUT" | grep -qi "seed 0xa6"; then ok "gen_splitbrain_selftest prints the reproducing seed"
else fail "gen_splitbrain_selftest did not print the reproducing seed"; fi

# ── assertion 5: --template partition routes --generate correctly ─────────────
PGEN="$("$DSF" --generate 6 --seed 0xFEED --template partition --list 2>&1)"
NG="$(echo "$PGEN" | grep -cE '^  gen_run_[0-9][0-9]')"
if [ "$NG" -eq 6 ]; then ok "--template partition --generate 6 registers 6 gen_run variants"
else fail "--template partition --generate 6 -> $NG gen_run variants (expected 6)"; fi
if echo "$PGEN" | grep -A1 '^  gen_run_00' | grep -qi 'partition/heal'; then
    ok "--template partition gen_run variants use the PARTITION/HEAL template"
else
    fail "--template partition gen_run variant description is not the partition/heal template"
fi

# ── assertion 6: regression — default broadcast; the other six still route ────
BGEN="$("$DSF" --generate 6 --seed 0xFEED --list 2>&1)"
if echo "$BGEN" | grep -A1 '^  gen_run_00' | grep -qi 'reliable-broadcast'; then
    ok "default --generate (no --template) is still the broadcast template (inc-5 path intact)"
else
    fail "default --generate is no longer the broadcast template (inc-5 regression!)"
fi
for pair in "agree:agreement:inc-6" "ratchet:ratchet:inc-7" "quorum:quorum:inc-8" "conserve:receipt-conservation:inc-9" "recon:view-reconciliation:inc-10" "crashrec:crash/recover:inc-11"; do
    tname="${pair%%:*}"; rest="${pair#*:}"; needle="${rest%%:*}"; inc="${rest#*:}"
    TGEN="$("$DSF" --generate 6 --seed 0xFEED --template "$tname" --list 2>&1)"
    if echo "$TGEN" | grep -A1 '^  gen_run_00' | grep -qi "$needle"; then
        ok "--template $tname still routes to its template ($inc path intact)"
    else
        fail "--template $tname no longer routes to its template ($inc regression!)"
    fi
done

# ── assertion 7: a generated partition variant runs + replays byte-identically ─
"$DSF" --generate 6 --seed 0xFEED --template partition --scenario gen_run_02 --trace "$TMPD/gp_a.log" --quiet >/dev/null 2>&1
"$DSF" --generate 6 --seed 0xFEED --template partition --scenario gen_run_02 --trace "$TMPD/gp_b.log" --quiet >/dev/null 2>&1
OUT="$("$DSF" --generate 6 --seed 0xFEED --template partition --scenario gen_run_02 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ -s "$TMPD/gp_a.log" ] && diff -q "$TMPD/gp_a.log" "$TMPD/gp_b.log" >/dev/null 2>&1 \
   && echo "$OUT" | grep -qE 'invariant\(s\) held over [1-9][0-9]* steps'; then
    ok "generated partition variant runs, commits both sides, and replays byte-identically (§Q6)"
else
    fail "generated partition variant did not advance / replay (rc=$rc)"
fi

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "  PASS: test_dsf_inc12 (8th generator template — partition/heal split-brain: 6 deterministic always-committing variants with a majority-cut partition window under the drawn profile, a self-test that catches a mis-set minority quorum committing while partitioned, and a --template partition selector; inc-5..11 defaults intact)"
    exit 0
else
    echo "  FAIL: test_dsf_inc12 ($FAILS assertion(s))"
    exit 1
fi
