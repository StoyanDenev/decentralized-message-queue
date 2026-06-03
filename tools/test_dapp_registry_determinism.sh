#!/usr/bin/env bash
# DApp registry (`d:` state-root namespace) serialize/restore round-trip +
# state_root binding — focused in-process unit pin of the S-037 / S-038
# closure. S-037 fixed a latent bug where dapp_registry_ contributed to
# compute_state_root() via the `d:` namespace (build_state_leaves,
# src/chain/chain.cpp) but was absent from Chain::serialize_state /
# restore_from_snapshot — so a DApp-active chain failed the S-033
# state_root gate on snapshot restore. S-038 closed the paired
# producer-side gap (body.state_root population). tools/test_dapp_snapshot.sh
# covers the integration (cluster) surface; THIS test pins the focused
# in-process unit contract:
#
#   (1) Round-trip: serialize → restore_from_snapshot → serialize yields
#       byte-identical dapp_registry JSON, and the restored chain's
#       compute_state_root() exactly matches the source (the S-033 gate
#       accepts a DApp-active snapshot — the S-037 guard).
#   (2) Empty registry: a fresh chain serializes a stable empty array and
#       round-trips empty with a stable state_root (no phantom d: leaf).
#   (3) Field sensitivity: two registries differing by ONE field
#       (endpoint_url, then service_pubkey) produce DISTINCT serialized
#       JSON — every field reaches the snapshot.
#   (4) Deterministic ordering: entries serialize sorted by domain key
#       (std::map ascending) regardless of REGISTER insertion order; the
#       snapshot JSON + state_root are registration-order-independent.
#   (5) state_root binding (S-038 guard): toggling a DAppEntry field
#       (endpoint_url, then metadata) changes compute_state_root() —
#       proving the d: value-hash genuinely incorporates the field and
#       the producer's body.state_root commitment is real, not dormant.
#   (6) Field completeness: every DAppEntry field survives restore
#       field-for-field (service_pubkey, endpoint_url, topics, retention,
#       metadata, registered_at, active_from, inactive_from), including
#       empty-container entries (no silent drop / fabrication).
#
# Companion to:
#   - test-dapp-state-transition  (register → update → deactivate apply path)
#   - test-state-root-namespaces  (exhaustive 10-namespace state_root coverage)
#   - tools/test_dapp_snapshot.sh (cluster integration of the same closure)
#
# 12 assertions across 6 scenarios.
#
# Run from repo root: bash tools/test_dapp_registry_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== DApp registry determinism — d:-namespace serialize/restore + state_root binding ==="
OUT=$($DETERM test-dapp-registry-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dapp-registry-determinism all assertions"; then
  echo ""
  echo "  PASS: dapp-registry-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: dapp-registry-determinism had assertion failures"
  exit 1
fi
