#!/usr/bin/env bash
# Exhaustive per-MsgType binary envelope round-trip + tamper-rejection.
#
# Companion to tools/test_binary_codec.sh — that test exercises the
# codec surface at a high level (one or two MsgTypes per code path
# plus the S-022 cap table). This one walks every non-HELLO MsgType
# defined in include/determ/net/messages.hpp with a representative
# payload and pins three invariants per type:
#
#   1. encode_binary → decode_binary preserves MsgType + payload
#      (byte-for-byte for fixed-frame TRANSACTION, JSON-structural for
#      everything else via the JSON-fallback path).
#   2. Magic header bytes: byte[0] == 0xB1, byte[1] == 0x01,
#      byte[2] == MsgType, byte[3] == 0x00.
#   3. Tamper-rejection: flipping a byte past the envelope header
#      either makes decode_binary throw OR yields a payload that
#      doesn't equal the original — never silent-accept.
#
# Plus contract invariants:
#   * HELLO is rejected by encode_binary (always JSON pre-negotiation).
#   * decode_binary on malformed-header / truncated-payload throws.
#   * encode_binary itself does NOT enforce the 16 MB framing cap;
#     that's the wire-side `Peer::read_body` defense. Pinned so a
#     future refactor doesn't silently fold the cap into the codec.
#
# MsgTypes covered:
#   TRANSACTION, BLOCK, CONTRIB, BLOCK_SIG, ABORT_CLAIM, ABORT_EVENT,
#   EQUIVOCATION_EVIDENCE, BEACON_HEADER, SHARD_TIP,
#   CROSS_SHARD_RECEIPT_BUNDLE, GET_CHAIN, CHAIN_RESPONSE,
#   STATUS_REQUEST, STATUS_RESPONSE, SNAPSHOT_REQUEST,
#   SNAPSHOT_RESPONSE, HEADERS_REQUEST, HEADERS_RESPONSE.
#   HELLO is explicitly tested for the encode-rejection contract.
#
# Run from repo root: bash tools/test_binary_codec_roundtrip_exhaustive.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== binary codec roundtrip exhaustive (per-MsgType + tamper) ==="
OUT=$($DETERM test-binary-codec-roundtrip-exhaustive 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: binary-codec-roundtrip-exhaustive all assertions"; then
  echo ""
  echo "  PASS: binary-codec roundtrip exhaustive"
  exit 0
else
  echo ""
  echo "  FAIL: binary-codec roundtrip exhaustive had assertion failures"
  exit 1
fi
