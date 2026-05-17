#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for Config::to_json /
# Config::from_json round-trip. Config is the operator-facing
# config.json that holds every operator-tunable knob: ports, peer
# addresses, rate-limits, regions, sharding mode, governance flags.
#
# A regression in round-trip would mean operators can't reload
# their saved configs cleanly: missing fields would silently reset
# to defaults, breaking the operator's intent without an error
# message. This is more pernicious than a hard failure because
# the node would boot but behave differently than the operator
# configured.
#
# 47 assertions covering:
#
#   Default Config round-trip (9): documented defaults survive
#     save+reload (listen_port=7777, rpc_port=7778,
#     rpc_localhost_only=true [S-001 secure default], rate-limits=0,
#     bft_enabled=true, escalation=5, m_creators=3, chain_role=SINGLE,
#     sharding_mode=CURRENT).
#
#   Custom Config full-field round-trip (32): every field set to a
#     non-default value round-trips through to_json+from_json. Covers
#     scalar fields (uint16, uint32, double, bool, string), vector
#     fields (bootstrap_peers, beacon_peers, shard_peers), enum
#     fields (chain_role / sharding_mode).
#
#   Empty JSON → all defaults (5): Config::from_json is permissive
#     by design — empty {} produces a default Config. Verifies key
#     defaults still come through.
#
#   Enum encoding (2): chain_role=SHARD (uint8_t=2) and
#     sharding_mode=NONE (uint8_t=0) round-trip via the int
#     representation in JSON.
#
# Permissive contract preserved: Config::from_json uses j.value(...)
# for every field. This is intentional — operators expect a config
# missing optional fields to load with defaults rather than throw.
# Strict S-018 rejection is reserved for wire-format peer messages
# (Block / Transaction / consensus msgs) where operator-vs-attacker
# distinction matters.
#
# Run from repo root: bash tools/test_config_roundtrip.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Config::to_json / Config::from_json — operator config round-trip ==="
OUT=$($DETERM test-config-roundtrip 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: config-roundtrip all assertions"; then
  echo ""
  echo "  PASS: config-roundtrip unit test"
  exit 0
else
  echo ""
  echo "  FAIL: config-roundtrip had assertion failures"
  exit 1
fi
