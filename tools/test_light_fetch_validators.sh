#!/usr/bin/env bash
# determ-light fetch-validators — fetch the committee set with ONLY the
# trust-minimized binary, and prove the determ-light-only offline workflow
# composes end-to-end: fetch-headers + fetch-validators -> verify-chain-file.
#
# fetch-validators calls the `validators` RPC and saves the bare array the
# daemon's rpc_validators emits ({domain, ed_pub, ...}). Combined with
# fetch-headers, an operator gets BOTH inputs for verify-chain-file /
# committee-diff using determ-light alone — no full determ node binary needed.
#
# Assertions:
#   1. fetch-validators saves a non-empty array with domain + ed_pub.
#   2. fetch-validators output == the full node's `determ validators --json`.
#   3. END-TO-END: fetch-headers + fetch-validators -> verify-chain-file PASS.
#   4. committee-diff(fetched, fetched) -> SIGNING IDENTICAL (self-consistency).
#   5. NEGATIVES: missing --rpc-port exit 1; unreachable daemon exit 1.
#
# Run from repo root: bash tools/test_light_fetch_validators.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    echo "  PASS: test_light_fetch_validators (SKIP — determ-light binary not built)"
    exit 0
fi

T=test_light_fetch_validators
TABS=$PROJECT_ROOT/$T
declare -a NODE_PIDS
cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
}
# Abnormal-exit guard: `set -e` is active for parts of the body below, so a
# failing unguarded command would otherwise exit without a final marker.
# Stop the nodes and emit a last-line FAIL marker for run_all.sh.
on_abort() {
  trap - EXIT INT
  cleanup
  echo "  FAIL: test_light_fetch_validators (aborted before summary)"
  exit 1
}
trap on_abort EXIT INT
rm -rf $T; mkdir -p $T/n1 $T/n2 $T/n3

# Per-check lines use "  ok:"/"  bad:" so a stray "PASS:" can never land in
# run_all.sh's last-10-lines marker window; only the final verdict uses PASS:/FAIL:.
pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  ok:  $2"; pass_count=$((pass_count + 1))
  else echo "  bad: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init + start 3-node cluster ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done
cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-fv",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)
configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain']='node$n'; c['listen_port']=$listen; c['rpc_port']=$rpc
c['bootstrap_peers']=$peers
c['genesis_path']='$TABS/gen.json'; c['genesis_hash']='$GHASH'
c['chain_path']='$TABS/n$n/chain.json'; c['key_path']='$TABS/n$n/node_key.json'
c['data_dir']='$TABS/n$n'
c['tx_commit_ms']=500; c['block_sig_ms']=500; c['abort_claim_ms']=250
with open('$T/n$n/config.json','w') as f: json.dump(c, f, indent=2)
"
}
configure_node 1 7821 8821 '["127.0.0.1:7822","127.0.0.1:7823"]'
configure_node 2 7822 8822 '["127.0.0.1:7821","127.0.0.1:7823"]'
configure_node 3 7823 8823 '["127.0.0.1:7821","127.0.0.1:7822"]'
NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 & NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 & NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 & NODE_PIDS[2]=$!; sleep 0.5

echo; echo "=== 2. Wait for chain past height 4 ==="
for _ in $(seq 1 60); do
  H=$($DETERM status --rpc-port 8821 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 4 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo; echo "=== 3. fetch-validators saves a non-empty array with domain+ed_pub ==="
$DETERM_LIGHT fetch-validators --rpc-port 8821 --out $T/committee.json > $T/fv.out 2>&1
OK=$([ -s "$T/committee.json" ] && python -c "
import json
a=json.load(open('$T/committee.json'))
print('true' if isinstance(a,list) and len(a)>=1 and 'domain' in a[0] and 'ed_pub' in a[0] else 'false')" 2>/dev/null || echo false)
assert "$OK" "fetch-validators saved a non-empty {domain,ed_pub,...} array"

echo; echo "=== 4. fetch-validators == full node 'determ validators --json' ==="
$DETERM validators --rpc-port 8821 --json > $T/committee_full.json 2>&1
SAME=$(python -c "import json;print(json.load(open('$T/committee.json'))==json.load(open('$T/committee_full.json')))" 2>/dev/null)
assert "$([ "$SAME" = "True" ] && echo true || echo false)" "determ-light fetch-validators matches determ validators --json"

echo; echo "=== 5. END-TO-END: fetch-headers + fetch-validators -> verify-chain-file PASS ==="
$DETERM_LIGHT fetch-headers --rpc-port 8821 --from 0 --count $((H+1)) --out $T/headers.json > $T/fh.out 2>&1
set +e
OUT=$($DETERM_LIGHT verify-chain-file --in $T/headers.json --committee $T/committee.json 2>&1); RC=$?
set -e
# Raw verifier output prefixed "    | " so it can't collide with run_all.sh's
# marker grep (also keeps this diagnostic pipeline from tripping set -e).
echo "$OUT" | grep -E "CONTINUITY|SIGS|VERIFY-CHAIN-FILE" | sed 's/^/    | /'
echo "$OUT" | grep -Eq "VERIFY-CHAIN-FILE: PASS" && [ $RC -eq 0 ] \
  && assert true "determ-light-only workflow (fetch-headers+fetch-validators->verify-chain-file) PASS" \
  || assert false "determ-light-only workflow PASS"

echo; echo "=== 6. committee-diff(fetched, fetched) -> SIGNING IDENTICAL ==="
set +e; $DETERM_LIGHT committee-diff --a $T/committee.json --b $T/committee.json >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 0 ] && echo true || echo false)" "committee-diff self-compare -> IDENTICAL exit 0"

echo; echo "=== 7. NEGATIVES ==="
set +e; $DETERM_LIGHT fetch-validators >/dev/null 2>&1; RC1=$?
$DETERM_LIGHT fetch-validators --rpc-port 59999 >/dev/null 2>&1; RC2=$?; set -e
assert "$([ $RC1 -eq 1 ] && echo true || echo false)" "missing --rpc-port -> exit 1"
assert "$([ $RC2 -eq 1 ] && echo true || echo false)" "unreachable daemon -> exit 1"

echo; echo "=== Test summary ==="
echo "  checks: $pass_count ok, $fail_count failed"
set +e   # negative-test blocks left -e enabled; teardown runs in the
         # script's true -u-only mode so a dead-PID kill can't abort before
         # the final marker (would exit 1 with 0 failures otherwise).
trap - EXIT INT
cleanup
if [ "$fail_count" = "0" ]; then echo "  PASS: test_light_fetch_validators"; exit 0
else echo "  FAIL: test_light_fetch_validators ($fail_count checks failed)"; exit 1; fi
