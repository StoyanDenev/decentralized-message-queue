#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for
# GenesisConfig::genesis_message + its hash-mixing contract.
#
# The `genesis_message` field is an optional UTF-8 inscription (max
# 256 bytes) that operators can include in genesis: a per-deployment
# cultural anchor, mission statement, regulatory disclosure, or
# commemorative text. The default value (DEFAULT_GENESIS_MESSAGE) is
# a protocol-level philosophical anchor present on every Determ
# deployment unless overridden.
#
# Hash-mixing contract has three rules:
#
#   1. Default value: compute_genesis_hash SKIPS the mix. This
#      preserves byte-identical hashes for pre-message genesis files
#      (backward-compat invariant).
#   2. Custom value (incl. empty string): hash incorporates it
#      length-prefixed (u64 BE per Preliminaries §1.3). Distinct
#      messages → distinct chain hashes → distinct chain identities.
#   3. Size cap: 256 bytes max (GENESIS_MESSAGE_MAX_BYTES). from_json
#      throws on oversized input.
#
# A regression in this hashing logic would EITHER silently break
# chain-identity stability for existing deployments (pre-message
# chains would suddenly compute a different genesis hash) OR
# silently allow chain-identity collisions (two deployments intending
# different messages would share a hash). Locking the contract in at
# unit level catches both.
#
# Assertions covered (10 total):
#   1. default genesis_message hash == explicit DEFAULT hash
#      (default-member-initializer matches the named constant)
#   2. compute_genesis_hash is deterministic (same config -> same hash)
#   3. Custom genesis_message yields distinct hash from default
#   4. Empty genesis_message ALSO yields distinct hash (empty != default)
#   5. Different custom messages yield distinct hashes
#   6. Identical custom messages yield same hash (determinism under override)
#   7. to_json + from_json round-trips genesis_message
#   8. from_json: absent key in JSON -> DEFAULT_GENESIS_MESSAGE
#   9. from_json rejects oversized message (>256B)
#  10. Boundary: exactly 256 bytes is accepted
#
# Run from repo root: bash tools/test_genesis_message.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== GenesisConfig::genesis_message hash-mixing contract ==="
OUT=$($DETERM test-genesis-message 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: genesis-message all assertions"; then
  echo ""
  echo "  PASS: genesis_message unit test"
  exit 0
else
  echo ""
  echo "  FAIL: genesis-message had assertion failures"
  exit 1
fi
