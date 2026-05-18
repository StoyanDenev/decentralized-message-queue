#!/usr/bin/env bash
# S-035 Option 1 seed — multi-tx block apply semantics: in-block
# tx-ordering, multi-sender, fee accumulation, mid-block skip.
#
# `apply_transactions` iterates `b.transactions` in vector order
# (left to right). For each tx, sender's `next_nonce` is checked for
# match (defense-in-depth post-validator). On match, the tx applies
# and sender's `next_nonce` increments — so subsequent txs from the
# same sender in the same block must use the incremented value.
# Different senders track independent nonce counters; both can have
# nonce 0 in the same block.
#
# Mid-block insufficient balance: the cost check fires before any
# sender state is touched, so the tx silently skips without
# incrementing nonce or affecting subsequent txs in the block.
#
# 16 assertions in six blocks:
#
#   Same sender, ascending nonce (3):
#     - both apply; both nonces consumed; receiver credited twice
#
#   Same sender, wrong nonce on second (3):
#     - first applies, second skips silently
#     - sender nonce reflects only first apply
#
#   Different senders in same block (3):
#     - each sender's nonce independently increments
#     - receiver credited from both
#     - creator (alice) gets all fees back
#
#   Interleaved alice → bob → alice (4):
#     - all three apply; nonce ordering preserved within sender
#     - balance math: alice debited 30+10+2 fees, +3 fees back = -39
#     - bob debited 20+1, +30+10 in = +19
#     - carol +20
#
#   Insufficient balance mid-block (1+3):
#     - bob skips silently; alice still applies; nonces correct
#
#   A1 invariant under multi-tx (1):
#     - expected == live after multi-tx block
#
# Run from repo root: bash tools/test_multi_tx_block.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== multi-tx block apply semantics (ordering, multi-sender, mid-block skip) ==="
OUT=$($DETERM test-multi-tx-block 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: multi-tx-block all assertions"; then
  echo ""
  echo "  PASS: multi-tx-block unit test"
  exit 0
else
  echo ""
  echo "  FAIL: multi-tx-block had assertion failures"
  exit 1
fi
