#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the binary
# Transaction codec path (`src/net/binary_codec.cpp`'s
# `encode_tx_frame` / `decode_tx_frame` exercised via the
# public encode_binary / decode_binary Message-level API).
#
# This is the v1 (binary) wire-format path for TRANSACTION
# MsgType. The codec uses a 4×32-byte fixed-slot area + a
# variable-length trailer.
#
# **S-002 dependency**: admission-side sig verification reads
# amount/fee/nonce from the FIXED slots (not the trailer). A
# regression that dropped these values during binary transit —
# as happened pre-S-002 closure, see docs/proofs/S002-Mempool-
# Sig-Verify.md — would silently zero these fields and let
# corrupted txs into the mempool until the validator filtered
# them later. This test locks the values through the round-trip
# explicitly.
#
# 24 assertions covering:
#
#   TRANSFER round-trip (7): amount + fee + nonce (S-002 fixed-
#     slot fields) + from + to (trailer length-prefixed) + payload
#     + type.
#
#   compute_hash invariance (1): a tx's compute_hash is identical
#     before and after a binary round-trip. The CRITICAL invariant
#     under admission-side sig verification (S-002): a peer that
#     received bytes recomputes the hash and verifies the sig
#     against it. Any field loss breaks signature validation.
#
#   Distinct-tx → distinct frames (1): no cross-tx state leak in
#     the codec.
#
#   Trailer overflow (2): 64-byte payload — first 32 bytes in
#     the fixed slot at offset 96, overflow in the trailer after
#     type + payload_len. Both content + size preserved.
#
#   Every TxType (9): TRANSFER / REGISTER / DEREGISTER / STAKE /
#     UNSTAKE / PARAM_CHANGE / COMPOSABLE_BATCH / DAPP_REGISTER /
#     DAPP_CALL. Discriminator round-trip.
#
#   Boundary values (4): all-zero numeric fields; UINT64_MAX
#     amount + fee + nonce (LE u64 encoding boundary).
#
# Run from repo root: bash tools/test_tx_binary_codec.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Transaction binary codec (encode_binary / decode_binary for TRANSACTION MsgType) ==="
OUT=$($DETERM test-tx-binary-codec 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: tx-binary-codec all assertions"; then
  echo ""
  echo "  PASS: tx-binary-codec unit test"
  exit 0
else
  echo ""
  echo "  FAIL: tx-binary-codec had assertion failures"
  exit 1
fi
