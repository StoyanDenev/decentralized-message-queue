#!/usr/bin/env bash
# D13 gate (owner decision 2026-09-16, O-1b; DECISION-LOG 2026-09-16 "OWNER
# DECISIONS" §C) — in-process unit test for the apply-side handling of a
# round-1 AbortEvent: it RECORDS the suspension and moves NO stake.
#
# Each `round=1` AbortEvent baked into a finalized block:
#   (a) Increments abort_records[domain] (count + last_block) — the S-032
#       cache that NodeRegistry::build_from_chain reads to compute the
#       suspension window (eligibility_floor.hpp).
#   (b) Moves nothing else: stake, balance, registry entry, the A1
#       counters (accumulated_slashed stays 0) and live supply are
#       unchanged. The former min(SUSPENSION_SLASH, locked) deduction is
#       RETIRED: against the default min_stake = 1000 one abort dropped a
#       floor-staked validator to 990, below the eligibility floor, and
#       S-051 lifts suspensions, never floor breaches (SECURITY.md S-087).
#
# Phase-2 (round=2) AbortEvents are neither recorded nor suspended —
# timing-skew aborts on healthy creators.
#
# Network-level integration via the multi-node round-1 fail injection
# scripts; this in-process test pins the apply semantics in <1s.
#
# Implementation note: every block in the fixture sets
# `b.creators = {"alice"}` so fees route back and A1 stays balanced
# (see test-chain-apply-block gotcha).
#
# 31 assertions in seven blocks:
#
#   Control (1): the inert suspension_slash is non-zero (10) — "nothing
#     moves" is the retirement, not a zero-configured deduction.
#
#   Round-1 abort against a staked, registered domain (9):
#     - stake, balance, accumulated_slashed, live supply unchanged; A1
#     - POSITIVE CONTROL: abort_records[alice] == {count 1, last_block 1}
#     - registry entry untouched; the event IS in the appended block
#
#   round != 1 (2): no record, nothing moves
#
#   Repeated aborts (2): 51 aborts → stake constant + A1 after every
#     block; abort_records == {51, last_block 51}
#
#   Stake-free domain (3): apply succeeds, record lands, others unaffected
#
#   The S-087 hazard through the REAL eligibility path (7): a domain staked
#     EXACTLY at min_stake (and one above it) — stakes unchanged; suspended
#     inside the window (positive control: the record has its effect);
#     ELIGIBLE again via NodeRegistry::build_from_chain once the window
#     expires; the shared suspension formula's exact window
#
#   Abort-free twin (6): every s:/a:/r: leaf, the five A1 counter leaves and
#     the 13 k: genesis-constant leaves byte-identical (state_proof value
#     hashes — every non-b: leaf the fixture populates); the b: leaf exists
#     ONLY on the aborted chain; state_root and block hash differ (the record
#     IS committed — root equality is not expected)
#
#   Determinism (1): two chains apply the same abort → same root + record
#
# Run from repo root: bash tools/test_abort_event_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== AbortEvent apply (D13: suspension record only — no stake moves; S-032 cache; at-floor eligibility; A1) ==="
OUT=$($DETERM test-abort-event-apply 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: abort-event-apply all assertions"; then
  echo ""
  echo "  PASS: abort-event-apply unit test"
  exit 0
else
  echo ""
  echo "  FAIL: abort-event-apply had assertion failures"
  exit 1
fi
