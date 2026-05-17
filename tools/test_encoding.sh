#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the foundation-layer
# encoding helpers in `include/determ/types.hpp`:
#
#   * to_hex(uint8_t*, size_t)      — bytes-to-hex (lowercase)
#   * to_hex<N>(array<uint8_t, N>)  — templated overload for Hash /
#                                     PubKey / Signature
#   * from_hex(string)              — hex-to-bytes (case-insensitive)
#   * from_hex_arr<N>(string)       — to fixed-size array; length-checked
#   * to_string(ChainRole)          — enum → "single"/"beacon"/"shard"
#   * to_string(ShardingMode)       — enum → "none"/"current"/"extended"
#   * now_unix()                    — wall-clock seconds since epoch
#
# These helpers sit under EVERY hex serialization in the codebase:
# Block::to_json / from_json, Transaction sig encoding, RPC output,
# Merkle leaf hashing, snapshot wire format, light-client headers.
# A regression in any of them would cascade across the entire wire
# format. The test locks them all in at unit level.
#
# 23 assertions:
#
#   to_hex / from_hex round-trip (3): empty, single-byte boundaries
#     (0x00, 0xff with leading-zero preservation), multi-byte pattern.
#   Case-insensitivity (2): from_hex parses upper / lower / mixed
#     identically (the underlying std::stoul base-16 path).
#   Odd-length rejection (1): from_hex(3 chars) throws.
#   Templated to_hex<N> (3): Hash (64 chars), Signature (128 chars),
#     leading-zero preservation in "000102...".
#   from_hex_arr<N> (3): correct N → all bytes preserved; short
#     input rejected; long input rejected.
#   Cross-helper round-trip (1): Hash → to_hex → from_hex_arr<32>
#     preserves all 32 bytes.
#   Enum → string mappings (6): ChainRole {SINGLE, BEACON, SHARD} +
#     ShardingMode {NONE, CURRENT, EXTENDED}.
#   Determinism (2): to_hex called twice produces identical strings
#     (no internal-state leak from std::ostringstream); golden
#     vector "{0x10,0x20,0x30}" → "102030".
#   now_unix (1): returns plausible post-2017 unix time (sanity
#     that the wall-clock wiring works).
#
# Run from repo root: bash tools/test_encoding.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== types.hpp encoding helpers — to_hex / from_hex / from_hex_arr / enum to_string ==="
OUT=$($DETERM test-encoding 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: encoding all assertions"; then
  echo ""
  echo "  PASS: encoding unit test"
  exit 0
else
  echo ""
  echo "  FAIL: encoding had assertion failures"
  exit 1
fi
