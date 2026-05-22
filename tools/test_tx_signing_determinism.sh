#!/usr/bin/env bash
# Transaction::signing_bytes determinism + field-binding completeness —
# pin three axes:
#   (a) Replay determinism: signing_bytes() is byte-identical across
#       3 consecutive calls on the same Transaction AND across a fresh
#       Transaction with identical field values (no hidden state, no
#       object-identity dependence).
#   (b) Field-binding completeness: every consensus-bound field
#       contributing to signing_bytes (type, from, to, amount, fee,
#       nonce, payload) MUST bind the signature — mutating any one
#       changes the pre-image. Per-tx-type sentinels (PARAM_CHANGE
#       target_height, DAPP_REGISTER service_pubkey, MERGE_EVENT
#       shard_id + region) also bind via payload.
#   (c) Type discriminator + cross-tx-type isolation: 10 enum values
#       across all current TxTypes produce pairwise-distinct
#       signing_bytes; type byte at offset 0 takes 10 distinct values.
#
# Companion to:
#   - test-tx-signing-bytes (byte-layout golden vectors)
#   - test-binary-codec-roundtrip-exhaustive (per-MsgType binary)
#   - docs/PROTOCOL.md §4.1 (signing_bytes canonical pre-image)
#
# 24 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_tx_signing_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== tx-signing determinism + field-binding contract ==="
OUT=$($DETERM test-tx-signing-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: tx-signing-determinism all assertions"; then
  echo ""
  echo "  PASS: tx-signing-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: tx-signing-determinism had assertion failures"
  exit 1
fi
