#!/usr/bin/env bash
# S-078 (D19a backlog item 1, DECISION-LOG 2026-09-16): Chain::load seeds
# EVERY genesis-pinned parameter BEFORE the store replay.
#
# Before the fix the replay chain carried the in-class defaults for
# min_stake, suspension_slash, unstake_delay, the three merge thresholds,
# crypto_profile, subsidy_mode, subsidy_pool_initial and
# lottery_jackpot_multiplier — all `k:` state-root leaves — and the node's
# setters ran only AFTER Chain::load returned, so the first restart of ANY
# chain whose genesis differed from the defaults (the tactical / cluster FIPS
# profiles included) threw S-033 on the first replayed block that declared a
# state_root. Now the node hands one Chain::Params (built from the genesis it
# parsed) to Chain::load, which seeds the replay chain with it first, and the
# same struct seeds the genesis-bootstrap chain.
#
# In-process gate (`determ test-chain-load-genesis-params`):
#   CL-1..8  a store whose genesis is NON-default in every replay-relevant
#            field, six blocks with declared state_roots (lottery + pool cap +
#            a governance PARAM_CHANGE), reloads through Chain::load(path,
#            Params) with the node's parameter set: no throw, height /
#            head_hash / state_root / all 16 getters equal, A1 holds, one more
#            block appends on the reloaded chain;
#   NL-1..6  the REAL restart path — node::Node constructed on the store + the
#            saved genesis file — and a no-store bootstrap of the same genesis
#            seed the identical parameter set (one struct, both paths);
#   FI-*     per-parameter fault injection: each leaf parameter left at its
#            default alone makes the load THROW the S-033 message (positive
#            control per field); the six-field legacy overload throws too;
#            epoch_blocks / k_block_sigs (not leaves) are only checked seeded;
#   GV-1..2  the governance-activated MIN_STAKE survives the restart.
#
# Run from repo root: bash tools/test_chain_load_genesis_params.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== S-078: Chain::load seeds every genesis parameter before the replay ==="
OUT=$($DETERM test-chain-load-genesis-params 2>&1)
RC=$?
echo "$OUT"

if [ "$RC" -eq 0 ] && echo "$OUT" | tail -3 | grep -q "PASS: chain-load-genesis-params all assertions"; then
  echo ""
  echo "  PASS: chain-load-genesis-params unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-load-genesis-params (exit=$RC or missing PASS marker)"
  exit 1
fi
