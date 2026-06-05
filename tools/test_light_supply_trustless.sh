#!/usr/bin/env bash
# determ-light supply-trustless — verified A1 unitary-supply conservation read.
#
# Boots a 3-node cluster. Runs the composite `supply-trustless --json` which:
# (1) anchors the genesis hash, (2) walks the chain verifying every committee
# sig, (3) fetches a state-proof for each of the five A1 supply counters from
# the `c:` namespace (genesis_total, accumulated_subsidy/inbound/slashed/
# outbound), each Merkle-verified against the SAME committee-signed
# state_root and hash-bound to the daemon's chain_summary cleartext, then
# (4) recomputes the closed-form A1 identity (genesis_total + subsidy +
# inbound - slashed - outbound) from the committed values and compares it
# against the daemon's claimed total_supply. Parity-checks the verified
# counters + the recomputed expected_total against `determ supply` from the
# full-binary side.
#
# This is the supply-namespace (c:) analogue of test_light_balance_trustless.sh
# (a:) and test_light_stake_trustless.sh (s:). Unlike those single-leaf reads,
# supply-trustless verifies a CROSS-LEAF invariant: the five committed counters
# are bound by the A1 identity the apply path enforces at every block
# (chain.cpp: `if (live_total_supply() != expected_total()) throw`), which is
# publicly recomputable from the committed counters alone — see
# docs/proofs/SupplyProofSoundness.md (SU-1..SU-E).
#
# Assertions:
#   1. supply-trustless --json exits 0 (CONSERVED).
#   2. JSON has conserved=true.
#   3. JSON verdict == CONSERVED.
#   4. All five counter fields present.
#   5. state_root field populated (post-S-038, 64 hex chars).
#   6. expected_total == genesis+subsidy+inbound-slashed-outbound (recompute).
#   7. Parity: light expected_total == full-daemon `supply --field expected_total`.
#   8. Parity: light counters == full-daemon `supply --field` per counter.
#
# Run from repo root: bash tools/test_light_supply_trustless.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_supply_trustless
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
  # Preserve the script's real exit status — the kill -9 of an
  # already-dead PID returns non-zero and would otherwise clobber a
  # passing run's exit 0.
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
  "chain_id": "test-light-su",
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
configure_node 1 7811 8811 '["127.0.0.1:7812","127.0.0.1:7813"]'
configure_node 2 7812 8812 '["127.0.0.1:7811","127.0.0.1:7813"]'
configure_node 3 7813 8813 '["127.0.0.1:7811","127.0.0.1:7812"]'

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
  H=$($DETERM status --rpc-port 8811 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo
echo "=== 3. determ-light supply-trustless --json ==="
set +e
OUT=$($DETERM_LIGHT supply-trustless --rpc-port 8811 --genesis $T/gen.json --json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "supply-trustless --json exit 0 (CONSERVED)"
else
    assert "false" "supply-trustless --json exit 0 (got $RC)"
fi

echo
echo "=== 4. JSON has conserved=true ==="
CONSERVED=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print('true' if d.get('conserved', False) else 'false')
except Exception:
    print('false')
")
assert "$CONSERVED" "supply-trustless JSON has conserved=true"

echo
echo "=== 5. verdict == CONSERVED ==="
VERDICT=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d.get('verdict', 'MISSING'))
except Exception:
    print('MISSING')
")
if [ "$VERDICT" = "CONSERVED" ]; then
    assert "true" "verdict=CONSERVED"
else
    assert "false" "verdict=CONSERVED (got $VERDICT)"
fi

echo
echo "=== 6. all five counter fields present ==="
FIELDS_OK=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    need = ['genesis_total','accumulated_subsidy','accumulated_inbound',
            'accumulated_slashed','accumulated_outbound','expected_total']
    print('true' if all(k in d for k in need) else 'false')
except Exception:
    print('false')
")
assert "$FIELDS_OK" "five counters + expected_total present"

echo
echo "=== 7. state_root present (64 hex chars) ==="
SR_PRESENT=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    sr = d.get('state_root', '')
    print('true' if len(sr) == 64 else 'false')
except Exception:
    print('false')
")
assert "$SR_PRESENT" "state_root populated (64 hex chars)"

echo
echo "=== 8. expected_total recomputes from the five committed counters ==="
RECOMPUTE_OK=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    g = int(d['genesis_total']); s = int(d['accumulated_subsidy'])
    i = int(d['accumulated_inbound']); sl = int(d['accumulated_slashed'])
    o = int(d['accumulated_outbound'])
    exp = g + s + i - sl - o
    print('true' if exp == int(d['expected_total']) else 'false')
except Exception:
    print('false')
")
assert "$RECOMPUTE_OK" "expected_total == g+subsidy+inbound-slashed-outbound"

echo
echo "=== 9. Parity vs determ supply (full binary) ==="
# The full daemon exposes per-counter scalars via `supply --field <name>`.
LIGHT_EXP=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try: print(int(json.loads(sys.stdin.read())['expected_total']))
except Exception: print(-1)
")
FULL_EXP=$($DETERM supply --rpc-port 8811 --field expected_total 2>/dev/null | tr -d '[:space:]')
if [ -n "$FULL_EXP" ] && [ "$FULL_EXP" = "$LIGHT_EXP" ]; then
    assert "true" "parity expected_total: light=$LIGHT_EXP == full=$FULL_EXP"
else
    assert "false" "parity expected_total: light=$LIGHT_EXP vs full=$FULL_EXP"
fi

# Per-counter parity (genesis_total + accumulated_subsidy are stable enough
# between the two reads; subsidy may advance a block, so compare only the
# two counters that are fixed at genesis on this single-shard chain).
for FIELD in genesis_total accumulated_slashed accumulated_outbound; do
  LIGHT_V=$(echo "$OUT" | tail -1 | python -c "
import json, sys
try: print(int(json.loads(sys.stdin.read())['$FIELD']))
except Exception: print(-1)
")
  FULL_V=$($DETERM supply --rpc-port 8811 --field $FIELD 2>/dev/null | tr -d '[:space:]')
  if [ -n "$FULL_V" ] && [ "$FULL_V" = "$LIGHT_V" ]; then
      assert "true" "parity $FIELD: light=$LIGHT_V == full=$FULL_V"
  else
      assert "false" "parity $FIELD: light=$LIGHT_V vs full=$FULL_V"
  fi
done

echo
echo "=== 10. text mode exits 0 and prints CONSERVED ==="
set +e
TXT=$($DETERM_LIGHT supply-trustless --rpc-port 8811 --genesis $T/gen.json 2>&1)
TRC=$?
set -e
if [ "$TRC" = "0" ] && echo "$TXT" | head -1 | grep -q "CONSERVED"; then
    assert "true" "text mode exit 0 + CONSERVED header"
else
    assert "false" "text mode exit 0 + CONSERVED header (rc=$TRC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_supply_trustless"; exit 0
else
  echo "  FAIL: test_light_supply_trustless"; exit 1
fi
