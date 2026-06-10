#!/usr/bin/env bash
# test_light_negative_footing.sh — contract for the F-2 `negative_footing` field
# on determ-light's NOT-INCLUDED --json verdicts (NegativeVerdictSoundness.md F-2).
#
# WHAT THIS LOCKS
# --------------
# NegativeVerdictSoundness.md proves the determ-light NOT-INCLUDED verdict has a
# NON-UNIFORM trust footing: the block-body negative (`verify-tx-inclusion`) is
# CRYPTOGRAPHIC (sound under A2 via the full-set tx_root recompute, NV-1), while
# the state-proof negatives (`verify-receipt-inclusion` i:, `verify-merge-state`
# m:, `verify-param-change` p:) are DAEMON_ASSERTED — sound only under the
# non-cryptographic (H-neg) premise (NV-2/NV-3). F-2 recommends surfacing this
# distinction in the `--json` output so a downstream consumer can apply NV-6
# clause (2) (treat as authoritative absence) vs clause (3) (treat as "no proof
# obtained") AUTOMATICALLY rather than hard-coding which command it called.
#
# The `negative_footing` field carries exactly that: "cryptographic" for the
# block-body negative, "daemon_asserted" for the three state-proof negatives,
# emitted ONLY for the NOT-INCLUDED verdict (absent on INCLUDED / UNVERIFIABLE).
#
# WHAT RUNS HERE (offline, no cluster) vs CI
# ------------------------------------------
#   * OFFLINE (always): the SOURCE CONTRACT over light/main.cpp — exactly one
#     "cryptographic" emission (tx-inclusion) + three "daemon_asserted" (i:/m:/p:),
#     each GATED on the NOT_INCLUDED verdict on the immediately preceding line.
#     This pins the field's value-per-command + the not-included gating without a
#     daemon. A regression (wrong value, ungated emission, a dropped site, or a
#     new state-proof negative that forgets the field) turns this RED.
#   * CI/WSL2 (cluster): the live behavioral leg — drive each command to a real
#     NOT-INCLUDED against an advancing cluster and assert the emitted footing.
#     Needs a live daemon (state-proof not_found / a verified block missing the
#     tx), so it is documented + SKIPPED here, not faked.
#
# Pure read-only source check (grep/awk over light/main.cpp); no determ binary,
# no build, no cluster. SKIP-clean (exit 0) when light/main.cpp is absent.
# Run from repo root: bash tools/test_light_negative_footing.sh
set -u
cd "$(dirname "$0")/.."

TARGET="light/main.cpp"

pass=0; fail=0; skip=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
no()  { echo "  FAIL: $1" >&2; fail=$((fail+1)); }
skp() { echo "  SKIP: $1"; skip=$((skip+1)); }

if [ ! -f "$TARGET" ]; then
    echo "  SKIP: $TARGET absent — nothing to contract (source-light checkout)."
    echo "  PASS: test_light_negative_footing (SKIP — target absent)"
    exit 0
fi

echo "=== F-2 negative_footing source contract ($TARGET) ==="

# ── 1. exactly 1 "cryptographic" + 3 "daemon_asserted" emissions ────────────────
n_crypto=$(grep -cE 'out\["negative_footing"\][[:space:]]*=[[:space:]]*"cryptographic"' "$TARGET")
n_daemon=$(grep -cE 'out\["negative_footing"\][[:space:]]*=[[:space:]]*"daemon_asserted"' "$TARGET")
if [ "$n_crypto" = "1" ]; then ok "exactly 1 cryptographic footing (verify-tx-inclusion / NV-1 block-body)"
else no "expected 1 'cryptographic' negative_footing, got $n_crypto"; fi
if [ "$n_daemon" = "3" ]; then ok "exactly 3 daemon_asserted footings (i:/m:/p: state-proof / NV-2/NV-3)"
else no "expected 3 'daemon_asserted' negative_footing, got $n_daemon"; fi

# ── 2. every emission is GATED on the NOT_INCLUDED verdict on the line above ─────
# A footing must never be emitted for INCLUDED/UNVERIFIABLE. We assert that each
# `out["negative_footing"]` line is immediately preceded by an
# `if (... verdict == InclusionVerdict::NOT_INCLUDED)` gate. (1-line proximity is
# robust here — the emission is a single gated statement we control.)
ungated=$(awk '
    prev ~ /InclusionVerdict::NOT_INCLUDED\)/ { gated=1 } prev !~ /InclusionVerdict::NOT_INCLUDED\)/ { gated=0 }
    /out\["negative_footing"\]/ { if (!gated) { bad++; print "    ungated @" NR ": " $0 > "/dev/stderr" } }
    { prev=$0 }
    END { printf "%d", bad+0 }
' "$TARGET")
if [ "$ungated" = "0" ]; then ok "all 4 negative_footing emissions gated on NOT_INCLUDED (never on INCLUDED/UNVERIFIABLE)"
else no "$ungated negative_footing emission(s) NOT gated on NOT_INCLUDED — would mislabel a positive/unverifiable verdict"; fi

# ── 3. total emissions == 4 (one per negative-verdict command; no stragglers) ────
n_total=$(grep -cE 'out\["negative_footing"\]' "$TARGET")
if [ "$n_total" = "4" ]; then ok "exactly 4 negative_footing emissions (one per NOT-INCLUDED-capable command)"
else no "expected 4 negative_footing emissions total, got $n_total (a command added/removed without updating the contract?)"; fi

# ── 4. live behavioral leg — CI/WSL2 cluster only ───────────────────────────────
echo
echo "=== live behavioral leg (drive each command to NOT-INCLUDED, assert footing) ==="
skp "live negative_footing leg (needs a cluster: tx-inclusion missing-tx -> cryptographic; i:/m:/p: not_found -> daemon_asserted) — CI/WSL2"

echo
echo "=== Test summary ==="
echo "  $pass pass / $fail fail / $skip skip"
if [ "$fail" = "0" ]; then
    echo "  PASS: test_light_negative_footing (F-2 source contract; live leg is a CI leg)"
    exit 0
else
    echo "  FAIL: test_light_negative_footing"
    exit 1
fi
