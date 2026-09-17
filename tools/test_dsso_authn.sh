#!/usr/bin/env bash
# determ-dsso authentication gate — the second factor and everything the level
# requires around it.
#
# The shipped DSSO login derives everything from the password: the threshold
# OPRF unseals an envelope holding the credential key, so a "credential" is a
# stored secret recovered from knowledge, not an independently held object.
# Commission Implementing Regulation (EU) 2015/1502 Annex §2.2.1 wants two
# factors from DIFFERENT categories at level substantial, and §2.3.1 wants a
# dynamic authentication; n servers are one factor evaluated in a distributed
# way, not n factors. This gate pins the module that closes that gap: a
# device-resident P-256 key that must answer a fresh, session-and-server-set-
# bound challenge at every login; enrolment that a password alone can never
# authorise; a recovery state machine in which one factor may only REDUCE
# assurance; revocation that kills live sessions; and an attempt limiter a
# subset-rotating attacker cannot walk around.
#
# Deterministic by construction — the module reads no clock and draws no
# randomness, so this run is byte-reproducible.
#
# Run from repo root: bash tools/test_dsso_authn.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== determ-dsso authn (two factors, enrolment/recovery/revocation, aggregate limiter) ==="
OUT=$($DETERM_DSSO selftest-authn 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dsso-authn all assertions"; then
  echo ""
  echo "  PASS: dsso_authn"
  exit 0
else
  echo ""
  echo "  FAIL: dsso_authn had assertion failures"
  exit 1
fi
