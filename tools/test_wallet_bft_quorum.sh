#!/usr/bin/env bash
# determ-wallet bft-quorum CLI test.
#
# Exercises the OFFLINE calculator for the chain's two-level BFT committee +
# block-signature quorum arithmetic. Given a genesis committee size K plus the
# round's abort/pool context, the command reproduces — byte-for-byte, with no
# daemon and no crypto — the decisions made at three daemon call sites:
#
#   * src/node/node.cpp::start_new_round       (BFT escalation gate)
#   * src/node/producer.cpp::required_block_sigs (Q = signature floor)
#   * src/node/validator.cpp accept gate       (sentinel slack = eff - Q)
#
# Formulae (must match src/ byte-for-byte):
#   k_bft = (2K + 2) / 3                       (ceil(2K/3))
#   escalate ⟺ pool<K ∧ bft_enabled ∧ aborts>=T ∧ pool>=k_bft
#   eff   = escalate ? k_bft : K
#   Q     = (mode==bft) ? (2*eff+2)/3 : eff
#   slack = eff - Q
#
# This test recomputes the EXPECTED values independently in Python and asserts
# the wallet output matches exactly — correctness, not just output shape. No
# cluster, no daemon, no network, no crypto: pure offline integer arithmetic.
#
# Differentiation vs sibling commands:
#   * committee-signature-verify — VERIFIES real Ed25519 sigs against a
#       daemon-pinned digest (needs a block + committee file + libsodium).
#   * bft-quorum — COMPUTES the sig floor / sentinel slack / escalation
#       decision from K and round context alone (no block, no crypto).
#
# Assertions (~24):
#   1.  Global help mentions bft-quorum.
#   2.  bft-quorum --help exits 0.
#   3.  Unknown CLI arg: exit 1.
#   4.  Missing --committee-size: exit 1.
#   5.  --committee-size 0 (< 1): exit 1.
#   6.  Non-decimal --committee-size: exit 1.
#   7.  Bad --mode value: exit 1.
#   8.  K=3 default (full pool): k_bft == 2.
#   9.  K=3 default: not escalated, mode MUTUAL_DISTRUST, Q == 3, slack == 0.
#  10.  K=6 default: k_bft == 4.
#  11.  K=6 default: Q == 6 (full K-of-K), slack == 0.
#  12.  K=9 --mode bft (forced): eff == k_bft == 6, Q == 4, slack == 2.
#  13.  K=6 --mode bft (forced): eff == 4, Q == 3, slack == 1.
#  14.  K=3 --mode bft (forced): eff == 2, Q == 2, slack == 0 (degenerate).
#  15.  K=6 escalation FIRES (pool=4,aborts=5,bft-enabled): escalated true.
#  16.  ...escalated round: mode BFT, eff == 4, Q == 3, slack == 1.
#  17.  Same context WITHOUT --bft-enabled: gate inert, not escalated, MD.
#  18.  Gate blocked by pool >= K (full pool): not escalated even w/ aborts.
#  19.  Gate blocked by aborts < threshold: not escalated.
#  20.  Gate blocked by pool < k_bft: not escalated.
#  21.  --json parseable + has all required keys.
#  22.  --json escalation_gates.all matches escalated for an escalated case.
#  23.  Text-mode required_sigs == JSON-mode required_sigs.
#  24.  Determinism: two invocations give identical JSON.
#
# Run from repo root: bash tools/test_wallet_bft_quorum.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

field() {  # field <json> <key>
  echo "$1" | $PY -c "import json,sys; print(json.loads(sys.stdin.read()).get('$2',''))"
}

# ── Independent reference computations (Python, mirrors src/ formulae) ───
ref() {  # ref <K> <mode md|bft|gate> <pool> <aborts> <threshold> <bft_enabled 0|1>
  $PY - "$@" <<'PYEOF'
import sys
K=int(sys.argv[1]); mode=sys.argv[2]; pool=int(sys.argv[3])
aborts=int(sys.argv[4]); thr=int(sys.argv[5]); bfton=int(sys.argv[6])
k_bft=(2*K+2)//3
if mode in ('md','bft'):
    forced=True; escalate=False
    is_bft=(mode=='bft')
else:
    forced=False
    escalate=(pool<K and bfton==1 and aborts>=thr and pool>=k_bft)
    is_bft=escalate
eff = k_bft if (escalate or (forced and is_bft)) else K
Q = (2*eff+2)//3 if is_bft else eff
slack = eff - Q
cmode = 'BFT' if is_bft else 'MUTUAL_DISTRUST'
print(f"{k_bft} {eff} {Q} {slack} {cmode} {str(escalate).lower()}")
PYEOF
}

echo "=== 1. Global help mentions bft-quorum ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "bft-quorum" "help mentions bft-quorum"

echo
echo "=== 2. bft-quorum --help exits 0 ==="
set +e
"$WALLET" bft-quorum --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "bft-quorum --help exits 0"

echo
echo "=== 3. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" bft-quorum --committee-size 3 --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 4. Missing --committee-size: exit 1 ==="
set +e
"$WALLET" bft-quorum --mode bft >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --committee-size returns 1"

echo
echo "=== 5. --committee-size 0: exit 1 ==="
set +e
"$WALLET" bft-quorum --committee-size 0 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "committee-size 0 returns 1"

echo
echo "=== 6. Non-decimal --committee-size: exit 1 ==="
set +e
"$WALLET" bft-quorum --committee-size 0x3 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "non-decimal committee-size returns 1"

echo
echo "=== 7. Bad --mode value: exit 1 ==="
set +e
"$WALLET" bft-quorum --committee-size 6 --mode pbft >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "bad --mode returns 1"

echo
echo "=== 8-9. K=3 default (full pool, gate inert) ==="
read -r R_KBFT R_EFF R_Q R_SLACK R_MODE R_ESC <<<"$(ref 3 gate 3 0 5 0)"
J=$("$WALLET" bft-quorum --committee-size 3 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" k_bft)"              "$R_KBFT"  "K=3 k_bft == $R_KBFT"
assert_eq "$(field "$J" escalated)"          "$R_ESC"   "K=3 escalated == $R_ESC"
assert_eq "$(field "$J" consensus_mode)"     "$R_MODE"  "K=3 mode == $R_MODE"
assert_eq "$(field "$J" required_sigs)"      "$R_Q"     "K=3 Q == $R_Q"
assert_eq "$(field "$J" sentinel_slack)"     "$R_SLACK" "K=3 slack == $R_SLACK"

echo
echo "=== 10-11. K=6 default (full K-of-K) ==="
read -r R_KBFT R_EFF R_Q R_SLACK R_MODE R_ESC <<<"$(ref 6 gate 6 0 5 0)"
J=$("$WALLET" bft-quorum --committee-size 6 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" k_bft)"          "$R_KBFT"  "K=6 k_bft == $R_KBFT"
assert_eq "$(field "$J" required_sigs)"  "$R_Q"     "K=6 Q == $R_Q (full K-of-K)"
assert_eq "$(field "$J" sentinel_slack)" "$R_SLACK" "K=6 slack == $R_SLACK"

echo
echo "=== 12. K=9 --mode bft forced ==="
read -r R_KBFT R_EFF R_Q R_SLACK R_MODE R_ESC <<<"$(ref 9 bft 9 0 5 0)"
J=$("$WALLET" bft-quorum --committee-size 9 --mode bft --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" effective_committee)" "$R_EFF"   "K=9 bft eff == $R_EFF"
assert_eq "$(field "$J" required_sigs)"       "$R_Q"     "K=9 bft Q == $R_Q"
assert_eq "$(field "$J" sentinel_slack)"      "$R_SLACK" "K=9 bft slack == $R_SLACK"

echo
echo "=== 13. K=6 --mode bft forced ==="
read -r R_KBFT R_EFF R_Q R_SLACK R_MODE R_ESC <<<"$(ref 6 bft 6 0 5 0)"
J=$("$WALLET" bft-quorum --committee-size 6 --mode bft --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" effective_committee)" "$R_EFF"   "K=6 bft eff == $R_EFF"
assert_eq "$(field "$J" required_sigs)"       "$R_Q"     "K=6 bft Q == $R_Q"
assert_eq "$(field "$J" sentinel_slack)"      "$R_SLACK" "K=6 bft slack == $R_SLACK"

echo
echo "=== 14. K=3 --mode bft forced (degenerate) ==="
read -r R_KBFT R_EFF R_Q R_SLACK R_MODE R_ESC <<<"$(ref 3 bft 3 0 5 0)"
J=$("$WALLET" bft-quorum --committee-size 3 --mode bft --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" effective_committee)" "$R_EFF"   "K=3 bft eff == $R_EFF"
assert_eq "$(field "$J" required_sigs)"       "$R_Q"     "K=3 bft Q == $R_Q"
assert_eq "$(field "$J" sentinel_slack)"      "$R_SLACK" "K=3 bft slack == $R_SLACK (degenerate)"

echo
echo "=== 15-16. K=6 escalation FIRES (pool=4 aborts=5 thr=5 bft-enabled) ==="
read -r R_KBFT R_EFF R_Q R_SLACK R_MODE R_ESC <<<"$(ref 6 gate 4 5 5 1)"
J=$("$WALLET" bft-quorum --committee-size 6 --pool 4 --aborts 5 --threshold 5 --bft-enabled --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" escalated)"           "$R_ESC"   "escalated == $R_ESC"
assert_eq "$(field "$J" consensus_mode)"      "$R_MODE"  "escalated mode == $R_MODE"
assert_eq "$(field "$J" effective_committee)" "$R_EFF"   "escalated eff == $R_EFF"
assert_eq "$(field "$J" required_sigs)"       "$R_Q"     "escalated Q == $R_Q"
assert_eq "$(field "$J" sentinel_slack)"      "$R_SLACK" "escalated slack == $R_SLACK"

echo
echo "=== 17. Same context WITHOUT --bft-enabled: gate inert ==="
read -r R_KBFT R_EFF R_Q R_SLACK R_MODE R_ESC <<<"$(ref 6 gate 4 5 5 0)"
J=$("$WALLET" bft-quorum --committee-size 6 --pool 4 --aborts 5 --threshold 5 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" escalated)"      "$R_ESC"  "no --bft-enabled: escalated == $R_ESC"
assert_eq "$(field "$J" consensus_mode)" "$R_MODE" "no --bft-enabled: mode == $R_MODE"

echo
echo "=== 18. Gate blocked by full pool (pool == K) ==="
J=$("$WALLET" bft-quorum --committee-size 6 --pool 6 --aborts 9 --threshold 5 --bft-enabled --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" escalated)" "false" "pool==K: not escalated"

echo
echo "=== 19. Gate blocked by aborts < threshold ==="
J=$("$WALLET" bft-quorum --committee-size 6 --pool 4 --aborts 4 --threshold 5 --bft-enabled --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" escalated)" "false" "aborts<threshold: not escalated"

echo
echo "=== 20. Gate blocked by pool < k_bft ==="
# K=6 -> k_bft=4; pool=3 < 4 blocks escalation even though pool<K and aborts ok.
J=$("$WALLET" bft-quorum --committee-size 6 --pool 3 --aborts 9 --threshold 5 --bft-enabled --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" escalated)" "false" "pool<k_bft: not escalated"

echo
echo "=== 21. --json shape: all required keys present ==="
J=$("$WALLET" bft-quorum --committee-size 6 --json 2>&1 | tr -d '\r')
PARSED_OK=$(echo "$J" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
keys = ('committee_size_K','k_bft','pool','aborts','threshold','bft_enabled',
        'mode_forced','escalated','effective_committee','consensus_mode',
        'required_sigs','sentinel_slack','escalation_gates')
print('yes' if all(k in d for k in keys) else 'no')
" 2>/dev/null || echo "no")
assert_eq "$PARSED_OK" "yes" "--json has all required keys"

echo
echo "=== 22. escalation_gates.all matches escalated (escalated case) ==="
J=$("$WALLET" bft-quorum --committee-size 6 --pool 4 --aborts 5 --threshold 5 --bft-enabled --json 2>&1 | tr -d '\r')
GATE_ALL=$(echo "$J" | $PY -c "import json,sys; print(str(json.loads(sys.stdin.read())['escalation_gates']['all']).lower())")
assert_eq "$GATE_ALL" "$(field "$J" escalated)" "escalation_gates.all == escalated"

echo
echo "=== 23. Text-mode required_sigs == JSON-mode ==="
TEXT_Q=$("$WALLET" bft-quorum --committee-size 6 --mode bft 2>&1 \
  | tr -d '\r' | grep '^required_sigs' | awk -F: '{print $2}' | tr -d ' ')
JSON_Q=$(field "$("$WALLET" bft-quorum --committee-size 6 --mode bft --json 2>&1 | tr -d '\r')" required_sigs)
assert_eq "$TEXT_Q" "$JSON_Q" "text-mode Q == JSON-mode Q"

echo
echo "=== 24. Determinism: two invocations identical ==="
R1=$("$WALLET" bft-quorum --committee-size 6 --pool 4 --aborts 5 --threshold 5 --bft-enabled --json 2>&1 | tr -d '\r')
R2=$("$WALLET" bft-quorum --committee-size 6 --pool 4 --aborts 5 --threshold 5 --bft-enabled --json 2>&1 | tr -d '\r')
assert_eq "$R1" "$R2" "two invocations give identical JSON"

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
