#!/usr/bin/env bash
# determ-light audit — one-shot composite trust-minimized node audit.
#
# Boots a 3-node cluster. Runs `determ-light audit`, which composes two
# already-tested whole-chain verifiers into a single PASS/FAIL verdict with a
# monitor-friendly exit code:
#   CHAIN  — verify_chain_to_head: genesis pin + prev_hash continuity + every
#            block's K-of-K committee Ed25519 sigs (the same path verify-chain
#            exercises), surfacing the head's state_root.
#   SUPPLY — cmd_supply_trustless: the A1 unitary-supply conservation read,
#            Merkle-verified against the same committee-signed head.
# SUPPLY is attempted only when CHAIN passes; on CHAIN failure it is SKIPped
# (never reported PASS). Exit 0 = all pass, non-zero = any fail/error.
#
# The composition's soundness is the conjunction of its components — see
# docs/proofs/LightClientAuditComposition.md. This test asserts both the
# healthy-cluster PASS path (text + --json) AND a fail-closed negative: an
# audit pointed at a WRONG genesis file must fail the CHAIN anchor, SKIP
# SUPPLY, and exit non-zero with AUDIT: FAIL — never a false PASS.
#
# Assertions:
#   1. audit (text) exits 0 on the healthy cluster.
#   2. text output contains "AUDIT: PASS".
#   3. text output shows CHAIN PASS and SUPPLY PASS.
#   4. audit --json exits 0.
#   5. JSON audit == "PASS".
#   6. JSON failed == 0 (and passed == 2).
#   7. JSON checks array has CHAIN=PASS and SUPPLY=PASS.
#   8. JSON head_state_root populated (64 hex chars, post-S-038).
#   9. NEGATIVE: audit --genesis <wrong> exits non-zero (fail-closed).
#  10. NEGATIVE: that run prints AUDIT: FAIL and marks SUPPLY SKIP.
#
# Run from repo root: bash tools/test_light_audit.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_audit
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS

cleanup() {
  rc=$?
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
  # Preserve the script's real exit status — kill -9 of an already-dead PID
  # returns non-zero and would otherwise clobber a passing run's exit 0.
  return $rc
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init 3 nodes + genesis with staked creators ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-audit",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "alice", "balance": 500}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

# A WRONG genesis for the fail-closed negative: identical creators/balances
# but a different chain_id, so compute_genesis_hash differs from the daemon's
# real block 0. anchor_genesis must reject it (CHAIN fail).
sed 's/"test-light-audit"/"test-light-audit-WRONG"/' $T/gen.json > $T/gen_bad.json

configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = 'node$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n$n/chain.json'
c['key_path']   = '$TABS/n$n/node_key.json'
c['data_dir']   = '$TABS/n$n'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
with open('$T/n$n/config.json','w') as f: json.dump(c, f, indent=2)
"
}
configure_node 1 7841 8841 '["127.0.0.1:7842","127.0.0.1:7843"]'
configure_node 2 7842 8842 '["127.0.0.1:7841","127.0.0.1:7843"]'
configure_node 3 7843 8843 '["127.0.0.1:7841","127.0.0.1:7842"]'

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 2. Wait for chain past height 5 (subsidy accumulates) ==="
for _ in $(seq 1 80); do
  H=$($DETERM status --rpc-port 8841 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo
echo "=== 3. determ-light audit (text) ==="
set +e
TXT=$($DETERM_LIGHT audit --rpc-port 8841 --genesis $T/gen.json 2>&1)
TRC=$?
set -e
echo "$TXT"
if [ "$TRC" = "0" ]; then
    assert "true" "audit (text) exit 0 on healthy cluster"
else
    assert "false" "audit (text) exit 0 (got $TRC)"
fi

if echo "$TXT" | grep -q "AUDIT: PASS"; then
    assert "true" "text output contains AUDIT: PASS"
else
    assert "false" "text output contains AUDIT: PASS"
fi

# Both per-check lines present and PASS (summary lines look like
# "  CHAIN   PASS" / "  SUPPLY  PASS").
if echo "$TXT" | grep -Eq "CHAIN[[:space:]]+PASS" \
   && echo "$TXT" | grep -Eq "SUPPLY[[:space:]]+PASS"; then
    assert "true" "summary shows CHAIN PASS and SUPPLY PASS"
else
    assert "false" "summary shows CHAIN PASS and SUPPLY PASS"
fi

echo
echo "=== 4. determ-light audit --json ==="
set +e
OUT=$($DETERM_LIGHT audit --rpc-port 8841 --genesis $T/gen.json --json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "audit --json exit 0"
else
    assert "false" "audit --json exit 0 (got $RC)"
fi

# The --json mode prints ONLY the aggregate JSON object (sub-command human
# output is captured to a sink), so the whole stdout parses as one object.
AUDIT_OK=$(echo "$OUT" | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print('true' if d.get('audit') == 'PASS' else 'false')
except Exception:
    print('false')
")
assert "$AUDIT_OK" "JSON audit == PASS"

COUNTS_OK=$(echo "$OUT" | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print('true' if d.get('failed') == 0 and d.get('passed') == 2 else 'false')
except Exception:
    print('false')
")
assert "$COUNTS_OK" "JSON failed==0 and passed==2"

CHECKS_OK=$(echo "$OUT" | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    m = {c['check']: c['verdict'] for c in d.get('checks', [])}
    print('true' if m.get('CHAIN')=='PASS' and m.get('SUPPLY')=='PASS' else 'false')
except Exception:
    print('false')
")
assert "$CHECKS_OK" "JSON checks: CHAIN=PASS and SUPPLY=PASS"

SR_OK=$(echo "$OUT" | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    sr = d.get('head_state_root', '')
    print('true' if len(sr) == 64 else 'false')
except Exception:
    print('false')
")
assert "$SR_OK" "JSON head_state_root populated (64 hex chars)"

echo
echo "=== 5. NEGATIVE: audit against a WRONG genesis must fail closed ==="
set +e
BAD=$($DETERM_LIGHT audit --rpc-port 8841 --genesis $T/gen_bad.json 2>&1)
BRC=$?
set -e
echo "$BAD"
if [ "$BRC" != "0" ]; then
    assert "true" "wrong-genesis audit exits non-zero ($BRC)"
else
    assert "false" "wrong-genesis audit exits non-zero (got 0 — FALSE PASS!)"
fi

if echo "$BAD" | grep -q "AUDIT: FAIL" \
   && echo "$BAD" | grep -Eq "SUPPLY[[:space:]]+SKIP"; then
    assert "true" "wrong-genesis: AUDIT FAIL + SUPPLY SKIP (CHAIN short-circuits)"
else
    assert "false" "wrong-genesis: AUDIT FAIL + SUPPLY SKIP"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_audit"; exit 0
else
  echo "  FAIL: test_light_audit"; exit 1
fi
