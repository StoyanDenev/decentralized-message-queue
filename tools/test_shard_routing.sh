#!/usr/bin/env bash
# v2.1 / S-035 Option 1 seed — in-process unit test for
# crypto::shard_id_for_address, the v1.x cross-shard routing
# foundation.
#
# Maps any address string (registered domain or anonymous bearer
# wallet) to one of `shard_count` shards via a salted SHA-256. The
# salt comes from genesis (GenesisConfig::shard_address_salt) and is
# fixed for the chain's lifetime, so every node — beacon, every
# shard, every external wallet — must agree on which shard owns
# which address.
#
# Assertions covered (7 total):
#   1. Single-shard mode (shard_count = 1): always returns 0
#      regardless of address (the only degenerate case).
#   2. Determinism: same (addr, count, salt) → same shard.
#   3. In-range invariant: routed shard_id < shard_count.
#   4. Salt-sensitivity: different salts route same address to
#      different shards (catches a regression that ignores the salt).
#   5. Distribution sanity: 1000 addresses distribute across 4 shards
#      with >5% per shard (chi-squared sanity on the SHA-256-uniform
#      claim; catches a regression in the modulo-bias handling).
#   6. Case-sensitivity: routing is byte-exact (matches the protocol
#      claim that S-028 normalizes at RPC ingress, not at routing).
#   7. Empty address routes deterministically to a valid shard
#      (function doesn't reject; caller validates upstream).
#
# Foundation test: every cross-shard transaction's destination is
# derived through shard_id_for_address. A regression here would
# silently corrupt cross-shard receipt routing (FA7) and result in
# misrouted funds.
#
# Run from repo root: bash tools/test_shard_routing.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== v2.1 shard-routing primitive ==="
OUT=$($DETERM test-shard-routing 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: shard-routing all assertions"; then
  echo ""
  echo "  PASS: v2.1 shard-routing unit test"
  exit 0
else
  echo ""
  echo "  FAIL: shard-routing had assertion failures"
  exit 1
fi
