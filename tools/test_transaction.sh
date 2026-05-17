#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for Transaction (the
# smallest authentic wire unit on the chain).
#
# Every transaction — TRANSFER, REGISTER, DEREGISTER, STAKE, UNSTAKE,
# PARAM_CHANGE, MERGE_EVENT, COMPOSABLE_BATCH, DAPP_REGISTER,
# DAPP_CALL — passes through Transaction::signing_bytes,
# Transaction::compute_hash, and Transaction::{to,from}_json. A
# regression in any of these would either silently break sender
# authentication (sig verifies with tampered tx) OR break wire-format
# interoperability (gossip round-trip drops a field).
#
# 28 assertions covering:
#
#   signing_bytes (3): determinism, per-field sensitivity for all
#     8 core fields (type/from/to/amount/fee/nonce/payload), and the
#     EXCLUSION contract (sig + hash NOT included in signing_bytes —
#     a tx signs over its OWN signing bytes, including sig would
#     be circular).
#
#   compute_hash (2): determinism, == SHA-256(signing_bytes) contract.
#
#   Ed25519 sign/verify integration (2): a real Ed25519 sign over
#     signing_bytes verifies under the signer's pubkey; tampered tx
#     (amount mutated AFTER signing) fails verification.
#
#   JSON round-trip (18): full 9-field round-trip for TRANSFER;
#     type-preservation round-trip for each of the 9 enum variants
#     (REGISTER through DAPP_CALL).
#
#   S-018 strict-rejection (2): missing required field 'amount'
#     throws with field-name diagnostic; wrong-length sig hex throws.
#
#   Hash distinctness (1): two txs differing in nonce alone have
#     distinct compute_hash outputs (the unique-tx-identity contract
#     that mempool dedup relies on).
#
# Run from repo root: bash tools/test_transaction.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Transaction::signing_bytes + compute_hash + sign/verify + JSON round-trip ==="
OUT=$($DETERM test-transaction 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: transaction all assertions"; then
  echo ""
  echo "  PASS: transaction unit test"
  exit 0
else
  echo ""
  echo "  FAIL: transaction had assertion failures"
  exit 1
fi
