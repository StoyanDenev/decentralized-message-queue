#!/usr/bin/env bash
# FA-Apply-8 (p: namespace, dedicated) — in-process unit test pinning the
# pending_param_changes (p:) state-root namespace end to end: snapshot
# round-trip + height-triggered activation determinism.
#
# The sibling p:-touching tests each cover one angle:
#   - test-pending-param-changes        in-memory stage API + map shape
#   - test-param-change-apply           stage -> activate at apply entry
#   - test-governance-param-determinism insertion-order + validator
#                                       forwarding + a single snapshot case
#   - test-snapshot-full-determinism    p: as 1 of 10 namespaces (one
#                                       spliced entry)
#
# None of them pins the p: namespace's SNAPSHOT contract FIELD-FOR-FIELD
# across MULTIPLE staged entries at MULTIPLE effective_heights, nor that
# compute_state_root() is EXACTLY preserved across serialize -> restore
# while the entries are still pending (the snapshot-tail-header invariant
# the S-033 / S-038 state_root gate consumes), nor that height-triggered
# activation is order-INDEPENDENT. This test is the dedicated p: round-
# trip + activation-determinism pin covering exactly that uncovered triad:
#
#   (0) fixture: p: has 2 height buckets (500:1 entry, 1000:3 entries).
#   (1) serialize_state -> restore_from_snapshot restores the p:
#       namespace field-for-field (every (eff_height, name, value-bytes)
#       tuple, in per-bucket order; whole-map deep-equal + explicit
#       value-byte spot checks).
#   (2) compute_state_root() preserved across the round-trip WHILE the
#       p: entries are still pending (S-033 / S-038 contract).
#   (3) p: binds into state_root: perturbing a pending value OR adding
#       an entry changes the root (S-037-class omission guard).
#   (4) staging is insertion-order-independent across distinct
#       (height, name) keys: identical map, identical serialized
#       snapshot bytes, identical state_root.
#   (5) height-triggered activation is deterministic + order-independent:
#       two opposite-order chains reach identical final param fields AND
#       identical state_root after activation (later-height override
#       wins; the p: map drains).
#   (6) snapshot-restore mid-staging then activate is idempotent: a
#       restored chain advanced past the activation heights reaches the
#       same final field state + state_root as a never-snapshotted replay.
#
# Network-level coverage of the governance flow lives in
# tools/test_governance_param_change.sh (full PARAM_CHANGE tx -> validator
# -> stage -> apply -> snapshot across a live cluster). This in-process
# test pins the p: snapshot + activation determinism in <1s, no network,
# no flakes.
#
# 14 assertions in seven blocks (see the handler in src/main.cpp).
#
# Run from repo root: bash tools/test_pending_param_change_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA-Apply-8 p: namespace determinism (field-for-field snapshot round-trip / state_root preserved while pending / order-independent height activation) ==="
OUT=$($DETERM test-pending-param-change-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: pending-param-change-determinism all assertions"; then
  echo ""
  echo "  PASS: pending-param-change-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: pending-param-change-determinism had assertion failures"
  exit 1
fi
