#!/usr/bin/env bash
# crypto::shard_id_for_address determinism + salt-sensitivity +
# uniformity contract — companion to test-shard-routing (primitive
# 7-assertion baseline). This test focuses on DETERMINISM (replay /
# cross-instance), salt+address single-byte avalanche, and EXTENDED
# uniformity properties that pin the cross-shard routing surface
# every cross-shard transaction relies on.
#
# Coverage (~20 assertions across 8 scenarios):
#   (1) Replay determinism: 3 consecutive calls produce byte-
#       identical shard_id; cross-instance salt rebuild matches.
#   (2) Single-byte avalanche: address single-byte flip changes
#       shard within 8 positions; salt single-byte flip changes
#       shard within 8 positions.
#   (3) Address vs domain — byte-form contract: same logical owner
#       in domain vs anon form generally map to different shards
#       (routing operates on the byte form, not the logical owner);
#       both forms are deterministic and in-range.
#   (4) Per-shard uniformity over 1000 anon addresses: total =
#       1000 (no addresses lost to out-of-range); empirical
#       stddev < 30 around binomial(1000, 1/8) stddev ≈ 10.5
#       (catches modulo-bias or salt-truncation drift).
#   (5) Salt-only variation: fixed address routes to different
#       shards across 1000 salts (catches salt-drop regression);
#       every shard 0..7 is hit at least once (no salt-degenerate
#       cases; SHA-256 uniformity).
#   (6) shard_count boundary cases: count=1 always routes to 0;
#       count=0 doesn't crash (count<=1 short-circuit returns 0);
#       count=65536 stays in range (no narrowing conversion or
#       modulo bypass).
#   (7) Empty address: routes deterministically to a valid shard
#       under either salt (function doesn't reject; caller
#       validates upstream).
#   (8) S-028 canonical-lowercase routing: normalize_anon_address
#       collapses upper/lower-case anon-address variants to the
#       same shard (composes with the upstream S-028 RPC ingress
#       normalization); routing on the canonical form is itself
#       deterministic.
#
# Foundation test: every cross-shard transaction's destination is
# derived through shard_id_for_address. A regression here would
# silently fork the chain at the routing layer (determinism break)
# or concentrate funds on a single shard (uniformity break) — both
# without an explicit failure mode. Pinning these axes loudly
# surfaces either regression.
#
# Companion to:
#   - test-shard-routing (primitive 7-assertion baseline)
#   - test-anon-routing (Chain-layer integration contract)
#   - test-chain-shard-routing-config (Chain ctor uses the salt)
#   - test-cross-shard-receipt-apply / test-cross-shard-outbound-apply
#     (FA7 receipt-routing apply-side)
#
# Run from repo root: bash tools/test_shard_routing_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== shard-routing-determinism: shard_id_for_address byte-identity + uniformity ==="
OUT=$($DETERM test-shard-routing-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: shard-routing-determinism all assertions"; then
  echo ""
  echo "  PASS: shard-routing-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: shard-routing-determinism had assertion failures"
  exit 1
fi
