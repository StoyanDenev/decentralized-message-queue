#!/usr/bin/env bash
# Config::to_json + Config::from_json byte-identity round-trip +
# field-binding completeness contract — pin five axes:
#   (a) Empty Config round-trip: default-constructed Config serializes
#       → deserializes → re-serializes to byte-identical JSON (both
#       pretty-printed and compact forms; AST semantic equality also).
#   (b) All-fields-populated round-trip: a Config with every field set
#       to a non-default value round-trips byte-identically. Cross-
#       check that representative fields (rpc_port, sharding_mode,
#       peer vectors, rate-limit doubles, bool flags) survive the
#       round-trip exactly (catches silent field drops in from_json
#       that text-identity alone wouldn't surface).
#   (c) Order-independent input + canonical output: two JSON inputs
#       with the SAME field-value set but fields in different orders
#       (alphabetical vs reverse) re-serialize to byte-identical
#       output — pins that nlohmann::json's std::map-backed key
#       ordering produces canonical dump regardless of source order
#       and that no future migration to ordered_json silently
#       re-introduces order sensitivity.
#   (d) Cross-instance + replay determinism: two Configs arriving at
#       the same logical state via different code paths (direct
#       assignment vs from_json) produce byte-identical to_json; the
#       same Config serialized 3 times in a row produces 3 identical
#       outputs (no hidden state); a fresh Config with identical
#       field values produces the same string (no object-identity
#       dependence).
#   (e) Boundary values + field-binding completeness: empty / zero /
#       false everywhere round-trips byte-for-byte (no default-
#       fallback confusion in from_json on wire-zero inputs); max u16/
#       u32 numerics + 1024-byte secrets + 100-element peer lists
#       round-trip without truncation; mutating any single Config
#       field changes to_json output (the "every field is bound /
#       no silently-dropped field" contract analogous to
#       test-tx-signing-determinism scenario 2 for Transaction).
#
# Companion to:
#   - test-config-defaults    (default-value pin for empty input)
#   - test-config-load-save   (Config::load + Config::save file IO)
#   - test-config-permissive  (unknown-field tolerance for legacy
#                              + future configs)
#
# 29 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_config_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Config to_json + from_json determinism + field-binding contract ==="
OUT=$($DETERM test-config-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: config-determinism all assertions"; then
  echo ""
  echo "  PASS: config-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: config-determinism had assertion failures"
  exit 1
fi
