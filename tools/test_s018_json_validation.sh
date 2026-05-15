#!/usr/bin/env bash
# S-018 — JSON schema validation regression test.
#
# Runs the in-process `determ test-s018-json-validation` subcommand
# which exercises the json_require<T> / json_require_hex helpers
# (include/determ/util/json_validate.hpp) + the converted from_json
# paths in chain/block.cpp and node/producer.cpp. Verifies that
# malformed JSON produces a clear field-name diagnostic instead of an
# opaque nlohmann-internal type error.
#
# Assertions covered (9 total):
#   1. Happy path: Transaction round-trips through to_json/from_json
#   2. Missing required field 'amount' names the field
#   3. Wrong-type 'amount' (string where uint64 expected) names the
#      field with "wrong type" diagnostic
#   4. Wrong-hex-length 'sig' (100 chars where 128 required) names
#      the field with "hex length" diagnostic
#   5. AbortEvent missing 'event_hash' names the field
#   6. EquivocationEvent missing 'sig_b' names the field
#   7. Block missing 'transactions' names the field
#   8. GenesisAlloc missing 'domain' names the field (covers snapshot
#      initial_state + genesis-tool initial_balances paths)
#   9. Block optional 'state_root' wrong hex length names the field
#      (covers S-033 state_root snapshot-restore path)
#
# Coverage scope: chain::Transaction, chain::AbortEvent,
# chain::EquivocationEvent, chain::Block (required + optional fields),
# chain::GenesisAlloc. Per-message types (ContribMsg, AbortClaimMsg,
# BlockSigMsg) use the same helpers; the happy-path test exercises
# the helpers' code path so a regression would be caught by any of
# the wire-format consumers. The gossip envelope deserializer
# (net::Message::deserialize) and node-key loader
# (crypto::load_node_key) also use the same helpers — same regression
# coverage.
#
# Run from repo root: bash tools/test_s018_json_validation.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe

echo "=== S-018 JSON schema validation ==="
OUT=$($DETERM test-s018-json-validation 2>&1)
echo "$OUT"

# Pass condition: final line says "PASS: s018_json_validation all assertions"
if echo "$OUT" | tail -3 | grep -q "PASS: s018_json_validation all assertions"; then
  echo ""
  echo "  PASS: S-018 JSON validation"
  exit 0
else
  echo ""
  echo "  FAIL: S-018 JSON validation had assertion failures"
  exit 1
fi
