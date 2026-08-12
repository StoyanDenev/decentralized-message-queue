#!/usr/bin/env bash
# tools/test_straggler_resync.sh — S-050 straggler-recovery gate
# (DECISION-LOG 2026-08-12).
#
# apply_block_locked handed a FUTURE block (b.index > height() — proof a peer
# minted past our head while we are missing >= 1 block) straight to validate(),
# which rejects it for prev_hash mismatch with NO catch-up. An idle
# non-committee follower arms no round timer, so the S-050 stall valve never
# fires for it: it strands permanently, spamming "prev_hash mismatch". The fix
# triggers the SAME tolerance-0 catch-up the valve uses (stalled_resync_ + one
# STATUS_REQUEST), guarded to fire at most once per stall episode so a stream of
# future/duplicate blocks cannot become a re-broadcast amplifier.
#
# Falsify-on-mutant:
#   (a) delete the trigger                -> FUTURE-BLOCK assert RED
#   (b) widen `b.index > height()` to `>=` -> NORMAL-NEXT boundary assert RED
#   (c) delete the !stalled_resync_ guard  -> ONCE (DoS) assert RED
#
# Run from repo root: bash tools/test_straggler_resync.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

OUT=$($DETERM test-straggler-resync 2>&1)
echo "$OUT"
if echo "$OUT" | tail -3 | grep -q "PASS: test-straggler-resync"; then
  echo "  PASS: test_straggler_resync"
  exit 0
fi
echo "  FAIL: test_straggler_resync"
exit 1
