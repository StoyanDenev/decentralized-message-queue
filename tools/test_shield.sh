#!/usr/bin/env bash
# §3.22 SHIELD — transparent -> confidential on-ramp CONSENSUS test.
#
# SHIELD is the first shielded-pool operation: it debits a PUBLIC amount A
# (+ fee) from a transparent sender and moves that value into the confidential
# commitment set (the `cn:` state namespace) as a Pedersen commitment C, tallied
# in the shielded-supply counter `accumulated_shielded_`. The accept-rule proves
# C commits to EXACTLY A (the excess E = C - A*G opens to zero on the blinding
# generator H — a Schnorr PoK of the blinding r), so a depositor cannot mint
# value by committing to more than they debit.
#
# What this test pins (Chain-level apply path, no validator/committee needed):
#   - accept-rule: a valid 98-byte payload (C33 || balance_proof65) verifies for
#     the declared amount, REJECTS for a wrong (inflated) amount, and REJECTS a
#     tampered proof.
#   - apply: the SHIELD block applies without violating the A1 unitary-supply
#     invariant (append() asserts it internally); accumulated_shielded == A;
#     exactly one confidential note lands in the pool; the sender is debited
#     EXACTLY amount + fee.
#   - conservation: transparent live + confidential pool - minted subsidy ==
#     the genesis baseline (value is conserved, just relocated off the
#     transparent ledger).
#   - state-root observability: a SHIELD changes the state root (the cn:/c:
#     leaves are emitted), while a shield-free genesis has zero shielded supply
#     and an empty pool (the additive, state-root-invariant guard is off until
#     used — the FAST golden vectors are the invariance proof).
#   - belt-and-suspenders apply rejections: a bad-proof SHIELD is a no-op (sender
#     NOT debited, no note created) and a duplicate-commitment SHIELD is a no-op
#     (double-mint blocked).
#
# Proof: docs/proofs/ShieldedPoolSoundness.md (SP-1..SP-5). §3.22a.
#
# Run from repo root: bash tools/test_shield.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== §3.22 SHIELD — transparent -> confidential on-ramp ==="
OUT=$($DETERM test-shield 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-shield"; then
  echo ""
  echo "  PASS: shield unit test"
  exit 0
else
  echo ""
  echo "  FAIL: shield had assertion failures"
  exit 1
fi
