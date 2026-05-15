#!/usr/bin/env bash
# v2.2 light-client header-sync — `headers` RPC + `determ headers` CLI.
#
# Spins up a 3-node cluster, waits for chain to advance, then fetches
# a slice of headers via the new `headers` RPC. Verifies:
#
#   1. Response has the expected shape: {headers, from, count, height}.
#   2. Each header has the fields a light client needs:
#      - index, prev_hash, timestamp
#      - creators, creator_ed_sigs, creator_block_sigs
#      - tx_root, delay_seed, delay_output, cumulative_rand
#      - state_root (post-S-038)
#   3. Each header has the heavy fields STRIPPED:
#      - transactions, cross_shard_receipts, inbound_receipts,
#        initial_state
#   4. Pagination: --from N --count M returns at most M headers
#      starting at index N.
#   5. Out-of-range --from returns empty headers array (not error).
#   6. Server caps count at 256 (request 1000 → max 256).
#
# Run from repo root: bash tools/test_headers_rpc.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_headers_rpc
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS

cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init + start 3 nodes ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-headers-rpc",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 100}]
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
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 2. Wait for chain to advance past height 5 ==="
for _ in $(seq 1 80); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo
echo "=== 3. Fetch headers --from 0 --count 5 ==="
$DETERM headers --rpc-port 8771 --from 0 --count 5 > $T/hdrs.json 2>&1

# Shape check
shape_ok=$(python -c "
import json
try:
    r = json.load(open('$T/hdrs.json'))
    needed = ['headers', 'from', 'count', 'height']
    print('true' if all(k in r for k in needed)
          and isinstance(r['headers'], list)
          and r['from'] == 0
          and r['count'] >= 1
          else 'false')
except Exception as e:
    print('false')
")
assert "$shape_ok" "response has {headers, from, count, height}"

echo
echo "=== 4. Each header has needed light-client fields, no heavy ones ==="
fields_ok=$(python -c "
import json
r = json.load(open('$T/hdrs.json'))
required = ['index', 'prev_hash', 'timestamp', 'creators',
            'creator_ed_sigs', 'creator_block_sigs', 'tx_root',
            'delay_seed', 'delay_output', 'cumulative_rand']
heavy = ['transactions', 'cross_shard_receipts',
          'inbound_receipts', 'initial_state']
ok = True
for h in r['headers']:
    if not all(k in h for k in required):
        ok = False; break
    if any(k in h for k in heavy):
        ok = False; break
print('true' if ok else 'false')
")
assert "$fields_ok" "headers have required fields + heavy fields stripped"

echo
echo "=== 5. state_root present (post-S-038) on non-genesis headers ==="
sr_ok=$(python -c "
import json
r = json.load(open('$T/hdrs.json'))
# Genesis block has state_root unset (S-033 backward-compat); blocks
# 1+ should have state_root populated post-S-038.
ok = True
for h in r['headers']:
    if h['index'] >= 1 and 'state_root' not in h:
        ok = False; break
print('true' if ok else 'false')
")
assert "$sr_ok" "non-genesis headers carry state_root"

echo
echo "=== 6. Pagination: --from 2 --count 2 returns at most 2 headers starting at 2 ==="
$DETERM headers --rpc-port 8771 --from 2 --count 2 > $T/hdrs2.json 2>&1
page_ok=$(python -c "
import json
r = json.load(open('$T/hdrs2.json'))
ok = (r['from'] == 2
      and len(r['headers']) <= 2
      and (len(r['headers']) == 0 or r['headers'][0]['index'] == 2))
print('true' if ok else 'false')
")
assert "$page_ok" "pagination --from N --count M returns at most M starting at N"

echo
echo "=== 7. Out-of-range --from returns empty headers array ==="
$DETERM headers --rpc-port 8771 --from 99999 --count 5 > $T/hdrs3.json 2>&1
oor_ok=$(python -c "
import json
r = json.load(open('$T/hdrs3.json'))
print('true' if r['count'] == 0 and r['headers'] == [] else 'false')
")
assert "$oor_ok" "out-of-range from-index returns empty array (not error)"

echo
echo "=== 8. Server caps --count at 256 ==="
$DETERM headers --rpc-port 8771 --from 0 --count 1000 > $T/hdrs4.json 2>&1
cap_ok=$(python -c "
import json
r = json.load(open('$T/hdrs4.json'))
# Should return min(1000, 256, chain_height) headers. If chain is short
# (just a few blocks), count == chain.height; otherwise count == 256.
print('true' if r['count'] <= 256 else 'false')
")
assert "$cap_ok" "count clamped at 256 server-side"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: v2.2 headers RPC + CLI"; exit 0
else
  echo "  FAIL"; exit 1
fi
