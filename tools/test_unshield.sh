#!/usr/bin/env bash
# §3.22b UNSHIELD — confidential -> transparent withdraw CONSENSUS test.
#
# UNSHIELD is the second shielded-pool operation: it SPENDS an unspent note C
# from the confidential set and returns its PUBLIC amount A to a transparent
# recipient (minus fee). The commitment IS its own nullifier — apply removes C
# from the pool, so a note is spendable at most once.
#
# The load-bearing property is the CONTEXT-BOUND proof. A bare proof-of-knowledge
# of the note blinding r would be REPLAYABLE: a mempool observer could copy the
# public C||proof into their own tx and redirect the credit to themselves (front-
# running theft), because the balance proof is decoupled from the tx signer. The
# fix binds the proof's Fiat-Shamir challenge to ctx = SHA-256(from||to||nonce||
# amount) of the withdrawing tx, so any change to those fields invalidates the
# proof. The SAME ctx helper (unshield_spend_ctx_hash) is used by the client
# prover, the validator accept-rule, and the apply re-verify (S-043 rule).
#
# What this test pins (Chain-level apply path):
#   - accept-rule: a bound proof verifies for its own (from,to,nonce,amount);
#     REJECTS when redirected to a different recipient (the front-run defence);
#     rejects a wrong amount; and an UNBOUND (SHIELD) proof is rejected by the
#     UNSHIELD verifier (domain separation).
#   - apply: the note is removed from the pool (accumulated_shielded_ -= A back to
#     0), the recipient is credited EXACTLY amount - fee, the withdrawer's
#     transparent balance is untouched (value came from the pool), and the A1
#     unitary-supply invariant holds (append throws on drift — value relocated
#     back to the transparent ledger, not created).
#   - front-running theft is a no-op at apply (redirected UNSHIELD skipped, note
#     NOT spent, attacker NOT credited).
#   - double-spend is a no-op (re-UNSHIELDing a spent/removed note is skipped).
#
# Proof: docs/proofs/ShieldedPoolSoundness.md (SP-6..SP-9). §3.22b.
#
# Run from repo root: bash tools/test_unshield.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== §3.22b UNSHIELD — confidential -> transparent withdraw (context-bound proof) ==="
OUT=$($DETERM test-unshield 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-unshield"; then
  echo ""
  echo "  PASS: unshield unit test"
  exit 0
else
  echo ""
  echo "  FAIL: unshield had assertion failures"
  exit 1
fi
