#!/usr/bin/env bash
# BlockIngress MEM-equiv-evidence-blockindex-amplification — pending equivocation
# evidence dedups on the equivocator ALONE, not the attacker-chosen block_index.
#
# EquivocationEvent.block_index is bound by NEITHER of the two signatures, so the
# old (equivocator, block_index) dedup let one valid double-sign be re-gossiped /
# re-submitted with block_index = 0,1,2,… (each re-passing the two sig checks)
# into unbounded pending_equivocation_evidence_ entries — a node-local memory-
# exhaustion DoS. The fix is one shared identity predicate
# node::same_equivocation_identity (equivocator-only) used at every dedup /
# inspect / prune site, consistent with the credited-evidence prune (which
# already erases by equivocator) and with per-equivocator full-stake slashing.
#
# This gate drives the shared predicate directly: a replay with a different
# block_index is deduped (amplification defeated), a same-equivocator different-
# proof is deduped, but a DIFFERENT equivocator is NOT deduped (distinct
# equivocators still each pooled -> slashing coverage preserved). Falsify-on-
# mutant: restore block_index to the identity -> the "replay is deduped" asserts
# flip while the "different equivocator not deduped" assert stays green. The
# live-engine test-fa-equivocation-trace is the wiring/regression gate.
#
# Run from repo root: bash tools/test_equivocation_dedup_identity.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== equivocation-dedup-identity — pool dedups on the equivocator, not the unsigned block_index ==="
OUT=$($DETERM test-equivocation-dedup-identity 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: equivocation-dedup-identity"; then
  echo ""
  echo "  PASS: equivocation-dedup-identity unit test"
  exit 0
else
  echo ""
  echo "  FAIL: equivocation-dedup-identity had assertion failures"
  exit 1
fi
