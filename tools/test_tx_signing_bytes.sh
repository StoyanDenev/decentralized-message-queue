#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the
# `Transaction::signing_bytes` byte-layout invariant.
#
# Wire-format layout (canonical, must match across all
# implementations to verify sigs interoperably):
#
#   [type: 1 byte]                 — TxType discriminator at offset 0
#   [from: utf-8 bytes][0x00]      — sender identifier, null-terminated
#   [to:   utf-8 bytes][0x00]      — recipient identifier, null-terminated
#   [amount: 8 bytes big-endian]   — Preliminaries §1.3 BE convention
#   [fee:    8 bytes big-endian]
#   [nonce:  8 bytes big-endian]
#   [payload: variable]            — application bytes (REGISTER pubkey,
#                                     DAPP_CALL ciphertext, TRANSFER memo,
#                                     etc.)
#
# A regression in any byte ordering, terminator position, or
# BE-vs-LE encoding would silently break sig verification across
# versions — clients running old code would sign over a different
# layout than the validator recomputes. test-transaction covers
# high-level signing_bytes determinism + field sensitivity; this
# test locks the EXACT byte layout via golden vectors.
#
# 40 assertions in six blocks:
#
#   Empty-tx golden vector (2):
#     - signing_bytes() on default Transaction is exactly 27 bytes
#       (1 type + 1 from-terminator + 1 to-terminator + 24 BE u64s).
#     - All 27 bytes are zero.
#
#   Type-byte position (3):
#     - Type byte at offset 0.
#     - Mutating type (TRANSFER → REGISTER) flips byte 0 only;
#       the 26 trailing bytes are unchanged.
#
#   From string + 0x00 terminator (4):
#     - From string starts at offset 1.
#     - Null terminator follows the string content.
#
#   To string + 0x00 terminator (4):
#     - To string follows from-terminator.
#     - Null terminator follows to-string content.
#
#   Big-endian u64 encoding (24):
#     - amount/fee/nonce each encoded as 8 BE bytes at correct
#       offsets ([3..10] / [11..18] / [19..26]).
#     - Golden vectors: 1, 0x0102030405060708, 0xFF, 0x42 placed
#       at the LSB position with MSB-side zeros.
#
#   Payload position (3 + 1):
#     - Payload appended at offset 27 (no from/to bytes).
#     - 4-byte payload {0xDE, 0xAD, 0xBE, 0xEF} preserved
#       byte-for-byte at offsets [27..30].
#     - Total signing_bytes size for tx with from="alice", to="bob",
#       no payload = 1+5+1+3+1+24 = 35 bytes.
#
# Run from repo root: bash tools/test_tx_signing_bytes.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Transaction::signing_bytes byte-layout invariant ==="
OUT=$($DETERM test-tx-signing-bytes 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: tx-signing-bytes all assertions"; then
  echo ""
  echo "  PASS: tx-signing-bytes unit test"
  exit 0
else
  echo ""
  echo "  FAIL: tx-signing-bytes had assertion failures"
  exit 1
fi
