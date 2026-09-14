#!/usr/bin/env bash
# S-056 / S-059 / S-061 / S-062 (docs/SECURITY.md; DECISION-LOG 2026-08-13
# `3dbe5f2`, 2026-08-14 `5e4afec`/`1c0a61d`) — the "producer includes what the
# verifier rejects" halt class.
#
# build_body mirrored none of check_transactions' per-transaction rules, so a
# transaction every node rejects (over-cap TRANSFER payload, amount+fee wrapping
# to zero from an unfunded sender, a malformed REGISTER, an unknown TxType) was
# included, the self-assembled block was rejected by every validator,
# apply_block_locked returned before the only mempool-eviction site, and the
# transaction was re-selected every round: a remote, anonymous, zero-cost
# absorbing halt. Fix: check_transactions' loop body is now
# BlockValidator::check_transaction — the ONE per-tx rule set — and build_body
# asks it (TxAdmit, wired by Node::tx_admit_locked) before including a candidate.
#
# The subcommand drives build_body directly with that predicate. Both-legs
# design: each "excluded" arm has a control proving the same tx IS included
# without the predicate (so the exclusion is the verdict, not a fixture
# artifact), plus an equivalence arm pinning the per-tx predicate to the
# block-level check_transactions verdict.
#
# Falsify-on-mutant (executed 2026-09-14, reverted):
#   M1 delete the `if (!admit || !admit(tx, nn)) continue;` line in build_body
#      -> the four "EXCLUDED" arms, "nothing else was included", "the verifier
#         ACCEPTS the body" and the fail-safe arm flip RED; every control stays
#         GREEN.
#   M2 delete the TRANSFER_PAYLOAD_MAX rule in check_transaction
#      -> the S-056 arm (and "nothing else was included") flips RED while the
#         equivalence arm stays GREEN (both layers now accept — proving they
#         share ONE definition site).
# The Node -> build_body wiring (tx_admit_locked() at all three call sites) is
# outside this gate's reach and is pinned by
# tools/test_producer_admit_wiring_guard.sh (a ci_local doc/source guard).
#
# RESIDUAL of this increment: the rejected transaction stayed in the mempool
# and every resident transaction was re-checked (signature / proof
# verification) on every rebuild — closed by the second increment
# (tools/test_mempool_admit_eviction.sh: build-time rejection evicts, verdicts
# memoized per head). NOT closed by either: the cost of the FIRST verification
# of a resident transaction (an invalid-proof CT tx costs ~2 s under the
# consensus lock) — SECURITY.md S-065.
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_producer_admit.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== S-056/S-059/S-061/S-062: build_body admits only what the verifier accepts ==="
OUT=$("$DETERM" test-producer-admit 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-producer-admit"; then
  echo "  PASS: test_producer_admit"
  exit 0
else
  echo "  FAIL: test_producer_admit (exit $rc)"
  exit 1
fi
