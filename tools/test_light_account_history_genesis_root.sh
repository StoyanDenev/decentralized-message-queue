#!/usr/bin/env bash
# LightVerify AH-1 — account-history's GENESIS (h=0) row must not echo the daemon's
# unbound, forgeable state_root FIELD.
#
# THE GAP: verify_header_state_root_at's idx==0 branch returned
# page["headers"][0].value("state_root", ...) — the daemon's self-declared genesis
# state_root. But genesis carries NO committee-attested state_root
# (make_genesis_block never sets it → the genuine value is the all-zero Hash{}) and
# has zero creator_block_sigs, and anchor_genesis binds only block-0's block_hash.
# So a hostile daemon could put an ARBITRARY forged root on the h=0 row (rank-3:
# informational-only — balance/nonce come from the Merkle-verified head_view).
#
# THE FIX (client-side, no wire/consensus change): route the genesis-row value
# through the pure genesis_row_state_root(served), which returns the genuine (empty)
# root — rendered "(none)" — DELIBERATELY IGNORING the served field.
#
# GATE (FAST, offline; the determ-light selftest-genesis-row subcommand drives the
# pure helper): a forged served value is NOT echoed (2 NEG); an empty served value
# stays empty (CTRL). Falsify (return the served value): the 2 NEG asserts flip,
# CTRL stays green.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh
if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi
OUT=$("$DETERM_LIGHT" selftest-genesis-row 2>&1); RC=$?
if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "PASS: selftest-genesis-row"; then
  echo "  PASS: test_light_account_history_genesis_root"
  exit 0
else
  echo "$OUT"
  echo "  FAIL: test_light_account_history_genesis_root"
  exit 1
fi
