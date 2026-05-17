#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the protocol-level
# enum integer encodings used as wire-format discriminators:
#
#   * TxType         (chain/block.hpp)       — every tx prepends this
#   * MsgType        (net/messages.hpp)      — gossip envelope type byte
#   * ConsensusMode  (chain/block.hpp)       — block-level mode discriminator
#   * ChainRole      (types.hpp)             — operator-config + HELLO
#   * ShardingMode   (types.hpp)             — operator-config posture
#   * InclusionModel (chain/genesis.hpp)     — genesis-pinned admission policy
#
# Every enum integer above is on the wire:
#
#   * Transaction::signing_bytes() prepends `static_cast<uint8_t>(type)`
#     — a TxType reorder silently corrupts every tx hash.
#   * compute_block_digest binds `static_cast<uint8_t>(consensus_mode)`.
#   * MsgType is the gossip envelope's type byte for every peer-to-peer
#     message.
#
# A regression that reorders any of these — even just swapping two
# slots — would silently fork the wire format. Operator wouldn't see
# an error; transactions from old binaries would simply fail to
# verify against new ones, and gossip dispatchers would mis-route.
#
# 46 assertions:
#
#   TxType (11): TRANSFER=0, REGISTER=1, DEREGISTER=2, STAKE=3,
#     UNSTAKE=4, REGION_CHANGE=5, PARAM_CHANGE=6, MERGE_EVENT=7,
#     COMPOSABLE_BATCH=8, DAPP_REGISTER=9, DAPP_CALL=10.
#
#   MsgType (19): HELLO=0 through HEADERS_RESPONSE=18.
#
#   ConsensusMode (2): MUTUAL_DISTRUST=0, BFT=1.
#
#   ChainRole (3): SINGLE=0, BEACON=1, SHARD=2.
#
#   ShardingMode (3): NONE=0, CURRENT=1, EXTENDED=2.
#
#   InclusionModel (2): STAKE_INCLUSION=0, DOMAIN_INCLUSION=1.
#
#   Wire-format size invariants (6): sizeof(<enum>) == sizeof(uint8_t)
#     for all six enums — confirms the wire-format ABI assumption that
#     each fits in one byte.
#
# Run from repo root: bash tools/test_enum_values.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Protocol-level enum integer encodings (TxType / MsgType / ConsensusMode / ChainRole / ShardingMode / InclusionModel) ==="
OUT=$($DETERM test-enum-values 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: enum-values all assertions"; then
  echo ""
  echo "  PASS: enum-values unit test"
  exit 0
else
  echo ""
  echo "  FAIL: enum-values had assertion failures"
  exit 1
fi
