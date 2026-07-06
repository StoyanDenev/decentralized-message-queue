#!/usr/bin/env bash
# §3.22c CONFIDENTIAL_TRANSFER — confidential -> confidential CONSENSUS test.
#
# The third shielded-pool operation and the FIRST consensus consumer of the
# shipped DCT1 confidential-transfer bundle (CTX-1). A transfer consumes n_in
# unspent NAMED input notes and produces m output notes with HIDDEN amounts,
# verified by determ_ctx_bundle_verify (range: each hidden output in [0,2^n);
# balance: Σv_in = Σv_out + fee, fee PUBLIC). The commitment is its own nullifier:
# apply removes the inputs and adds the outputs. Amount-private in motion — the
# transferred amounts are hidden — but NOT input-unlinkable (inputs are named),
# and there is no on-chain output-secret delivery to a recipient (off-chain memo).
#
# What this test pins (Chain-level apply path):
#   - apply consumes the input notes + adds the output notes; the shielded supply
#     drops by EXACTLY the public fee (Σv_in - Σv_out); the fee is credited to
#     creators; and the A1 unitary-supply invariant holds (append throws on drift
#     — value stays confidential, only the fee leaves the pool).
#   - a tampered bundle is a no-op (inputs NOT consumed).
#   - a double-spend (re-submitting a consumed transfer) is a no-op.
#   - THE INFLATION GUARD: a bundle that lists the SAME input note twice is
#     cryptographically valid (the crypto sees two commitments and the balance
#     holds for 2*value) but is REJECTED at apply by the input-dedup check — so an
#     attacker cannot consume one note worth V as 2V and inflate the pool.
#
# Proof: docs/proofs/ShieldedPoolSoundness.md (SP-10..13). §3.22c.
#
# Run from repo root: bash tools/test_confidential_transfer.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== §3.22c CONFIDENTIAL_TRANSFER — confidential -> confidential (DCT1 bundle) ==="
OUT=$($DETERM test-confidential-transfer 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-confidential-transfer"; then
  echo ""
  echo "  PASS: confidential-transfer unit test"
  exit 0
else
  echo ""
  echo "  FAIL: confidential-transfer had assertion failures"
  exit 1
fi
