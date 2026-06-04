#!/usr/bin/env bash
# determ-light supply-trustless — committee-verified c: supply-counter read.
#
# Boots a 3-node cluster. Runs the composite `supply-trustless --json` which:
# (1) anchors genesis hash, (2) walks the chain verifying every committee
# sig, (3) for each of the five A1 supply counters (genesis_total,
# accumulated_subsidy, accumulated_slashed, accumulated_inbound,
# accumulated_outbound) fetches a state-proof in the c: namespace,
# Merkle-verifies it against the committee-signed state_root, then
# cross-checks the daemon's `chain_summary` cleartext against the proof's
# value_hash, and (4) recomputes the chain-wide A1 identity LHS
# (expected_total = genesis_total + accumulated_subsidy + accumulated_inbound
#  - accumulated_slashed - accumulated_outbound) from the verified counters.
# Parity-checks every counter + expected_total against `determ supply` from
# the full-binary side.
#
# This is the exact c:-namespace analogue of test_light_stake_trustless.sh
# (s: namespace) and test_light_balance_trustless.sh (a: namespace). The
# differences: no --domain (the counters are chain-wide singletons), the
# namespace is c:, the cleartext RPC is chain_summary, the committed leaf
# encoding is SHA256(u64_be(value)) per counter, and the output reports an
# A1-identity-holds bit derived from the five verified counters.
#
# Assertions:
#   1. supply-trustless --json exits 0.
#   2. JSON has verified=true.
#   3. JSON has a1_identity_holds=true.
#   4. All five counters present (genesis_total > 0 since genesis-staked).
#   5. state_root field populated (64 hex chars; post-S-038).
#   6. expected_total present + equals the locally-recomputed A1 LHS.
#   7-11. Parity: each light counter == full-daemon `determ supply --field`.
#   12. Parity: light expected_total == full-daemon expected_total.
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
  "chain_id": "test-light-supply",
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
configure_node 1 7821 8821 '["127.0.0.1:7822","127.0.0.1:7823"]'
configure_node 2 7822 8822 '["127.0.0.1:7821","127.0.0.1:7823"]'
configure_node 3 7823 8823 '["127.0.0.1:7821","127.0.0.1:7822"]'

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 2. Wait for chain past height 5 ==="
for _ in $(seq 1 80); do
  H=$($DETERM status --rpc-port 8821 2>/dev/null \
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
OUT=$($DETERM_LIGHT supply-trustless --rpc-port 8821 --genesis $T/gen.json --json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "supply-trustless --json exit 0"
else
    assert "false" "supply-trustless --json exit 0 (got $RC)"
fi

# Parse the final JSON line once into shell vars.
eval "$(echo "$OUT" | tail -1 | python -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    for k in ['genesis_total','accumulated_subsidy','accumulated_slashed',
              'accumulated_inbound','accumulated_outbound','expected_total',
              'height']:
        print('L_%s=%s' % (k, d.get(k, 'MISSING')))
    print('L_verified=%s' % ('true' if d.get('verified', False) else 'false'))
    print('L_a1=%s' % ('true' if d.get('a1_identity_holds', False) else 'false'))
    sr = d.get('state_root', '')
    print('L_sr_len=%d' % len(sr))
except Exception as e:
    print('L_verified=false'); print('L_a1=false'); print('L_sr_len=0')
    for k in ['genesis_total','accumulated_subsidy','accumulated_slashed',
              'accumulated_inbound','accumulated_outbound','expected_total','height']:
        print('L_%s=MISSING' % k)
")"

echo
echo "=== 4. JSON has verified=true ==="
assert "${L_verified:-false}" "supply-trustless JSON has verified=true"

echo
echo "=== 5. JSON has a1_identity_holds=true ==="
assert "${L_a1:-false}" "supply-trustless JSON has a1_identity_holds=true"

echo
echo "=== 6. All five counters present + genesis_total non-zero ==="
ALL_PRESENT=true
for k in L_genesis_total L_accumulated_subsidy L_accumulated_slashed \
         L_accumulated_inbound L_accumulated_outbound; do
  v=$(eval echo "\${$k:-MISSING}")
  if [ "$v" = "MISSING" ]; then ALL_PRESENT=false; fi
done
assert "$ALL_PRESENT" "all five c: counters present in JSON"
if [ "${L_genesis_total:-0}" -gt 0 ] 2>/dev/null; then
    assert "true" "genesis_total=${L_genesis_total} (non-zero; genesis-staked)"
else
    assert "false" "genesis_total non-zero (got ${L_genesis_total:-MISSING})"
fi

echo
echo "=== 7. state_root present (64 hex chars) ==="
if [ "${L_sr_len:-0}" = "64" ]; then
    assert "true" "state_root populated (64 hex chars)"
else
    assert "false" "state_root populated (len=${L_sr_len:-0})"
fi

echo
echo "=== 8. expected_total matches locally-recomputed A1 LHS ==="
# expected = genesis_total + accumulated_subsidy + accumulated_inbound
#            - accumulated_slashed - accumulated_outbound
RECOMPUTED=$(python -c "
print(${L_genesis_total:-0} + ${L_accumulated_subsidy:-0} + ${L_accumulated_inbound:-0}
      - ${L_accumulated_slashed:-0} - ${L_accumulated_outbound:-0})
")
if [ "${L_expected_total:-MISSING}" = "$RECOMPUTED" ]; then
    assert "true" "expected_total=${L_expected_total} == recomputed A1 LHS=$RECOMPUTED"
else
    assert "false" "expected_total=${L_expected_total:-MISSING} vs recomputed=$RECOMPUTED"
fi

echo
echo "=== 9. Parity vs determ supply --field (full-binary side) ==="
parity_field() {
  local field=$1 light_val=$2
  local full_val
  full_val=$($DETERM supply --field "$field" --rpc-port 8821 2>/dev/null | tr -d '[:space:]')
  if [ -n "$full_val" ] && [ "$full_val" = "$light_val" ]; then
    assert "true" "parity $field: light=$light_val == full=$full_val"
  else
    assert "false" "parity $field: light=$light_val vs full=$full_val"
  fi
}
parity_field genesis_total        "${L_genesis_total:-MISSING}"
parity_field accumulated_subsidy  "${L_accumulated_subsidy:-MISSING}"
parity_field accumulated_slashed  "${L_accumulated_slashed:-MISSING}"
parity_field accumulated_inbound  "${L_accumulated_inbound:-MISSING}"
parity_field accumulated_outbound "${L_accumulated_outbound:-MISSING}"
parity_field expected_total       "${L_expected_total:-MISSING}"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_supply_trustless"; exit 0
else
  echo "  FAIL: test_light_supply_trustless"; exit 1
fi
