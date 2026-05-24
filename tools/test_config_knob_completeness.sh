#!/usr/bin/env bash
# Operator-knob completeness contract for the node::Config struct —
# a meta-property pin that complements the existing per-field tests:
#   - test-config-defaults    pins default values for empty-object input
#   - test-config-determinism pins byte-identity round-trip across every
#                             field
#   - test-config-roundtrip   pins in-memory JSON round-trip
#   - test-config-permissive  pins unknown-field tolerance
#   - test-config-load-save   pins file IO round-trip
#
# This test pins the META-property: every field declared in Config is
# exercised by BOTH to_json (writes it) AND from_json (reads it back),
# AND every field has a documented default. The regression class this
# catches: a future change that DROPS a field from to_json or DROPS the
# reading branch in from_json would silently break operator config —
# an operator's saved value for a tunable would be lost on reload, and
# the binary would fall back to a default. The structural pin catches
# that class of bug at the meta level rather than per-field.
#
# Scenarios (~19 assertions across 5):
#   (1) Default-construct → to_json: result is a JSON object with >= 30
#       fields, and every load-bearing operator knob (rpc_port, listen_
#       port, bft_enabled, m_creators, k_block_sigs, snapshot_path,
#       chain_path, log_quiet, rpc_localhost_only) is present by name.
#       (10 assertions.)
#   (2) Round-trip every load-bearing field: u16 (rpc_port, listen_port),
#       u32 (m_creators), string (snapshot_path, chain_path), bool
#       (bft_enabled, log_quiet, rpc_localhost_only), double (rpc_rate_
#       per_sec) all round-trip exactly across to_json → from_json.
#       (7 assertions covering 9 fields across 4 types.)
#   (3) Field-binding regression sentinel: set 9 distinct fields to
#       known-distinct values, to_json, parse JSON; assert ALL 9 fields
#       are present in the JSON with the expected values. Catches
#       accidental field-drop bugs in to_json that would silently lose
#       operator-tunable knobs (a bug that round-trip-via-from_json
#       wouldn't catch if from_json also silently defaulted that key).
#       (1 assertion checking 9 fields simultaneously.)
#   (4) from_json with empty object: parse `{}` → Config; every field
#       defaults to the documented value. Cross-checks defaults match
#       Scenario 1's defaults (default-constructed Config and
#       Config::from_json({}) produce equivalent state for the
#       documented defaults). (3 assertions.)
#   (5) Permissive contract sanity: set one valid field + several
#       unknown fields → unknown fields silently ignored AND valid
#       field bound correctly. Complements the deeper coverage in
#       test-config-permissive. (2 assertions.)
#
# Run from repo root: bash tools/test_config_knob_completeness.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Config operator-knob completeness — every-field to_json/from_json + defaults pin ==="
OUT=$($DETERM test-config-knob-completeness 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: config-knob-completeness all assertions"; then
  echo ""
  echo "  PASS: config-knob-completeness unit test"
  exit 0
else
  echo ""
  echo "  FAIL: config-knob-completeness had assertion failures"
  exit 1
fi
