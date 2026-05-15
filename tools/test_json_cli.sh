#!/usr/bin/env bash
# v2.2 / operator UX — `--json` flag on info CLIs (validators,
# committee, peers, chain-summary).
#
# All four CLIs historically had human-readable table / line output.
# Commits fbeb477 + d261a09 added a `--json` flag that emits the raw
# RPC response verbatim, suitable for piping into jq / Python /
# `verify-block-sigs --committee`. This test locks in the behavior:
#
#   1. `validators --json` returns a JSON array.
#   2. `committee --json` returns a JSON array.
#   3. `peers --json` returns a JSON array (possibly empty).
#   4. `chain-summary --json` returns a JSON object with `blocks` +
#      A1 supply counters.
#   5. `validators --json` output is verify-block-sigs-compatible
#      (each entry has {domain, ed_pub}).
#   6. Default output (no --json) is NOT valid JSON for the 4 CLIs
#      that have human-readable formatting — so a script that needs
#      JSON output unambiguously gets it via --json.
#
# Run from repo root: bash tools/test_json_cli.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_json_cli
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

# Helper: returns "true" if the given file is parseable JSON.
is_json() {
  python -c "
import json, sys
try:
    with open('$1') as f: json.load(f)
    print('true')
except Exception:
    print('false')
"
}

echo "=== 1. Init + start 3-node cluster ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-json-cli",
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

# Wait for chain to advance so chain-summary has data.
for _ in $(seq 1 40); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.5
done

echo
echo "=== 2. validators --json returns a JSON array ==="
$DETERM validators --rpc-port 8771 --json > $T/validators.json 2>&1
is_arr=$(python -c "
import json
try:
    j = json.load(open('$T/validators.json'))
    print('true' if isinstance(j, list) and len(j) >= 1 else 'false')
except Exception:
    print('false')")
assert "$is_arr" "validators --json returns a non-empty JSON array"

echo
echo "=== 3. validators --json entries have {domain, ed_pub} (verify-block-sigs-compatible) ==="
compat=$(python -c "
import json
j = json.load(open('$T/validators.json'))
print('true' if all('domain' in e and 'ed_pub' in e
                      and len(e['ed_pub']) == 64 for e in j) else 'false')")
assert "$compat" "validators --json entries are verify-block-sigs-compatible"

echo
echo "=== 4. committee --json returns a JSON array ==="
$DETERM committee --rpc-port 8771 --json > $T/committee.json 2>&1
is_arr=$(python -c "
import json
try:
    j = json.load(open('$T/committee.json'))
    print('true' if isinstance(j, list) else 'false')
except Exception:
    print('false')")
assert "$is_arr" "committee --json returns a JSON array"

echo
echo "=== 5. peers --json returns a JSON array ==="
$DETERM peers --rpc-port 8771 --json > $T/peers.json 2>&1
is_arr=$(python -c "
import json
try:
    j = json.load(open('$T/peers.json'))
    print('true' if isinstance(j, list) else 'false')
except Exception:
    print('false')")
assert "$is_arr" "peers --json returns a JSON array"

echo
echo "=== 6. chain-summary --json returns a JSON object with blocks + A1 counters ==="
$DETERM chain-summary --rpc-port 8771 --last 3 --json > $T/chain.json 2>&1
shape_ok=$(python -c "
import json
try:
    j = json.load(open('$T/chain.json'))
    # A1: should have 'blocks' (array) + 'total_supply' + 'genesis_total'
    # + accumulated_* counters. (Backward-compat: legacy array-only
    # response would also pass for blocks=array but skip the A1 check.)
    if not isinstance(j, dict):
        print('false')
    else:
        ok = ('blocks' in j and isinstance(j['blocks'], list)
              and 'total_supply' in j
              and 'genesis_total' in j
              and 'accumulated_subsidy' in j)
        print('true' if ok else 'false')
except Exception:
    print('false')")
assert "$shape_ok" "chain-summary --json has blocks + A1 supply counters"

echo
echo "=== 7. Default output (no --json) is NOT valid JSON ==="
# This is the negative case — confirms --json is the way to get JSON
# (so a script that needs JSON must opt in via the flag).
$DETERM validators --rpc-port 8771 > $T/validators_default.txt 2>&1
not_json=$(is_json $T/validators_default.txt)
assert "$([ "$not_json" = "false" ] && echo true || echo false)" \
    "validators default output is NOT JSON (--json required for machine consumption)"

echo
echo "=== 8. validators --json piped directly into verify-block-sigs works ==="
# End-to-end demonstration: --json output is the right shape for the
# light-client verifier without any transformation.
$DETERM headers --rpc-port 8771 --from 1 --count 1 > $T/hdr.json 2>&1
OUT=$($DETERM verify-block-sigs --header $T/hdr.json --committee $T/validators.json 2>&1)
verify_ok=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
assert "$verify_ok" "validators --json feeds directly into verify-block-sigs --committee"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: --json flag on info CLIs"; exit 0
else
  echo "  FAIL"; exit 1
fi
