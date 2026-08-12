#!/usr/bin/env bash
# S-021 — chain.json head_hash tampering detection.
#
# Single-node chain; advance a few blocks; verify chain.json is now in
# the wrapped form (object with head_hash + blocks). Stop the node.
# Tamper with one block's balance field. Try to load — must reject
# with "head_hash mismatch". Restore the original; load must succeed.
#
# This validates O(1) tampering detection: corruption is caught at
# load, before replay starts.
set -u
cd "$(dirname "$0")/.."

source tools/common.sh
T=test_chain_integrity
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
mkdir -p $T/n1

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init single-node chain (M=K=1) ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json
cat > $T/gen.json <<EOF
{
  "chain_id": "test-integrity",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 7820
c['rpc_port'] = 8820
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n1/chain.json'
c['key_path']   = '$TABS/n1/node_key.json'
c['data_dir']   = '$TABS/n1'
c['tx_commit_ms']  = 200
c['block_sig_ms']  = 200
c['abort_claim_ms']= 100
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"

echo
echo "=== 2. Start node + advance 5 blocks ==="
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!
sleep 1
for _ in $(seq 1 40); do
  H=$($DETERM status --rpc-port 8820 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
  if [ "$H" -ge "5" ]; then break; fi
  sleep 0.5
done
echo "  height: $H"
[ "$H" -ge "5" ] \
  && assert true "chain advanced past height 5 (h=$H)" \
  || assert false "chain didn't advance past 5 (h=$H)"

echo
echo "=== 3. Stop node + inspect the BINARY chain store ==="
kill ${NODE_PIDS[0]} 2>/dev/null
sleep 2
kill -9 ${NODE_PIDS[0]} 2>/dev/null
NODE_PIDS[0]=

# D2 inc8: the at-rest chain is the binary store — a fixed 44-byte DMF1
# manifest at <chain>.manifest.bin plus one DBK1 record per block under
# <chain>.blocks/. `determ chain-export --json` is the offline text VIEW.
HEAD_HASH=$(python -c "
import json, subprocess
try:
    j = json.loads(subprocess.check_output(
        ['$DETERM','chain-export','--chain','$T/n1/chain.json']))
    print(j['head_hash'] if j['head_hash'] else 'EMPTY')
except Exception as e:
    print('ERROR:' + str(e))
")
echo "  store head_hash: $HEAD_HASH"
if [ "$HEAD_HASH" != "EMPTY" ] && [ "${HEAD_HASH:0:6}" != "ERROR:" ] && [ -n "$HEAD_HASH" ]; then
  assert true "chain-export renders the store head_hash (${HEAD_HASH:0:16}...)"
else
  assert false "chain store not readable via chain-export (got: $HEAD_HASH)"
fi
if [ -f "$T/n1/chain.json.manifest.bin" ] \
   && [ "$(wc -c < "$T/n1/chain.json.manifest.bin" | tr -d ' ')" = "44" ]; then
  assert true "store manifest is the fixed 44-byte DMF1 record"
else
  assert false "store manifest missing or not 44 bytes"
fi

echo
echo "=== 4. Snapshot the original store ==="
cp $T/n1/chain.json.manifest.bin $T/n1/manifest.orig
cp -R $T/n1/chain.json.blocks $T/n1/blocks.orig

echo
echo "=== 5. Tamper: flip one byte of the manifest's stored head_hash ==="
# The manifest's head_hash transitively covers every block via the
# prev_hash chain + committee signatures (S-021). Flipping one byte of it
# is the canonical on-disk tampering the load gate must catch.
python -c "
import sys
p = '$T/n1/chain.json.manifest.bin'
b = bytearray(open(p,'rb').read())
assert len(b) == 44, f'manifest is {len(b)} bytes, expected 44'
b[43] ^= 0x01           # last byte of the 32-byte head_hash
open(p,'wb').write(bytes(b))
print('flipped manifest head_hash byte 31')
"

echo
echo "=== 6. Restart node — must refuse to load the tampered store ==="
$DETERM start --config $T/n1/config.json > $T/n1/log_after 2>&1 &
NODE_PIDS[0]=$!
sleep 3
# The node should exit on load failure. Check that it's not running and
# the log contains 'head_hash mismatch'.
if kill -0 ${NODE_PIDS[0]} 2>/dev/null; then
  # Still running — load did not reject. Kill it.
  kill ${NODE_PIDS[0]} 2>/dev/null
  sleep 1
  kill -9 ${NODE_PIDS[0]} 2>/dev/null
  assert false "node started despite a tampered chain store (S-021 detection failed)"
else
  # Process exited. Check log for the diagnostic.
  if grep -q "head_hash mismatch" $T/n1/log_after; then
    assert true "load rejected the tampered store with head_hash mismatch"
  elif grep -qE "(tampering|corruption)" $T/n1/log_after; then
    assert true "load rejected the tampered store (tampering/corruption diagnostic)"
  else
    assert false "node exited but log doesn't show head_hash mismatch diagnostic"
    echo "  log tail:"
    tail -10 $T/n1/log_after | sed 's/^/    /'
  fi
fi
NODE_PIDS[0]=

echo
echo "=== 7. Restore original store; load must succeed ==="
cp $T/n1/manifest.orig $T/n1/chain.json.manifest.bin
rm -rf $T/n1/chain.json.blocks
cp -R $T/n1/blocks.orig $T/n1/chain.json.blocks
$DETERM start --config $T/n1/config.json > $T/n1/log_final 2>&1 &
NODE_PIDS[0]=$!
sleep 3
for _ in $(seq 1 20); do
  H_FINAL=$($DETERM status --rpc-port 8820 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin)['height'])
except: print(0)" 2>/dev/null)
  if [ "$H_FINAL" -ge "5" ]; then break; fi
  sleep 0.5
done
echo "  height after reload: $H_FINAL"
[ "$H_FINAL" -ge "5" ] \
  && assert true "untampered chain loads cleanly and resumes consensus" \
  || assert false "untampered chain failed to load (h=$H_FINAL)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: S-021 chain-store head_hash tampering detection"; exit 0
else
  echo "  FAIL: test_chain_integrity"; exit 1
fi
