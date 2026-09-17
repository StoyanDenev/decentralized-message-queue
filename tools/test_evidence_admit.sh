#!/usr/bin/env bash
# S-105 (docs/SECURITY.md; found 2026-09-17 while designing O-1 step 3b) — the
# producer asks the verifier before proposing equivocation evidence, and evicts
# what the verifier would reject.
#
# The defect: `build_body`'s evidence arm included `pool INTERSECT
# reconcile_union` with NO admissibility check, while
# `BlockValidator::check_equivocation_events` rejects a block whose equivocator
# no longer resolves ("equivocator not in registry"). Cost: one eligible key,
# two OFFLINE signatures and one DEREGISTER. The key gossips a self-manufactured
# record about itself; every node adopts it (it resolves at that head); its
# DEREGISTER's `inactive_from` arrives; from that height
# `NodeRegistry::build_from_chain` omits the domain, so every honest assembler
# proposes the record, every honest verifier rejects the block,
# `apply_block_locked` never appends — and the ONLY prune is POST-inclusion, so
# nothing ever removes the record. Permanent. The same S-056 class the
# 2026-09-14 increments closed for transactions, on the evidence arm.
#
# Now (node-local; no accept rule, wire format, apply path or digest changes):
# the per-event core is factored out of the verifier as
# `BlockValidator::check_equivocation_event` — ONE rule set, the way
# `check_transaction` is the one per-transaction rule set — `Node::eq_admit_locked`
# hands it to `build_body` as an `EvAdmit` (fail-safe: no predicate admits
# nothing), and a rejected record is EVICTED from the pool. Verdicts are memoized
# per head, so the pool is verified at most once per head instead of three times
# per round.
#
# Fixture (in-process): a FOLLOWER node ("watch", not a registrant, so the
# committee never waits on it) plus a test-side miner that assembles real K-of-K
# blocks from the genesis creators' keys through the production `build_body`.
# Every block is offered to the follower through `apply_block_for_test` — the real
# ingress, which runs the FULL validator and appends only on success, so "the
# block validates and the chain advances" is read off the node's own height.
# Arms: the record is adopted and INCLUDED while `evil` resolves (control, the
# block validates); `evil` DEREGISTERs and the record is re-pooled; idle blocks
# carry the head to `inactive_from` with the record still resident; the pre-fix
# producer (an always-true predicate) proposes it and the follower REFUSES to
# append — the halt; the fixed producer does not propose it, EVICTS it, and the
# follower appends — the chain advances; and an absent predicate proposes nothing.
#
# Falsify-on-mutant (executed 2026-09-17, reverted; logs under the audit dir):
#   F2-M1 remove the EvAdmit call from build_body's evidence arm  -> fix arms RED
#         (this restores the defect verbatim)
#   F2-M2 admit-check but do not evict                            -> eviction arm RED
#   F2-M3 a predicate that only checks presence in the registrants map instead
#         of resolvability (the careless implementation)          -> fix arms RED
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_evidence_admit.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== S-105: build_body asks the verifier before proposing evidence, and evicts what it rejects ==="
OUT=$("$DETERM" test-evidence-admit 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-evidence-admit all assertions"; then
  echo "  PASS: test_evidence_admit"
  exit 0
else
  echo "  FAIL: test_evidence_admit (exit $rc)"
  exit 1
fi
