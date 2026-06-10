#!/usr/bin/env bash
# determ-light block-verify — self-contained OFFLINE single-block verifier.
#
# Unlike determ-wallet block-verify (which needs an operator-supplied
# block_digest because the wallet does not link the chain library), determ-light
# RECOMPUTES the digest itself (light_compute_block_digest), so it verifies a
# block from a file + committee alone — no external digest, no genesis anchor.
# Composes STRUCTURE (well-formedness) + TX-ROOT (recompute compute_tx_root ==
# stored) + SIGS (committee Ed25519 over the self-recomputed digest, via
# verify_block_sigs) into one PASS/FAIL.
#
# Boots a 3-node cluster, fetches block 1 as a FULL Block via `determ block-info
# 1 --json` (NOT determ-light fetch-headers, which strips creator_tx_lists) plus
# the committee via `determ validators --json`, then runs block-verify locally.
# (This offline verify path does NOT anchor genesis, so it is unaffected by the
# determ-light genesis-hash cross-platform gap — verified working on this box.)
#
# Assertions:
#   1. block-info + validators produce fixtures.
#   2. block-verify (text) PASS on a real block, exit 0; every check PASS.
#   3. --json: audit=PASS, passed==3.
#   4. NEGATIVE: tampered tx_root -> TX-ROOT FAIL, exit 2.
#   5. NEGATIVE: tampered creator_block_sig -> SIGS FAIL, exit 2.
#   6. NEGATIVE: wrong committee pubkey -> SIGS FAIL, exit 2.
#   7. NEGATIVE: malformed block (missing field) -> STRUCTURE FAIL, exit 2.
#
# Run from repo root: bash tools/test_light_block_verify.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    echo "  PASS: test_light_block_verify (SKIP — determ-light binary not built)"
    exit 0
fi

T=test_light_block_verify
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
  echo "  FAIL: test_light_block_verify (aborted before summary)"
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
  "chain_id": "test-light-bv",
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
configure_node 1 7791 8791 '["127.0.0.1:7792","127.0.0.1:7793"]'
configure_node 2 7792 8792 '["127.0.0.1:7791","127.0.0.1:7793"]'
configure_node 3 7793 8793 '["127.0.0.1:7791","127.0.0.1:7792"]'
NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 & NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 & NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 & NODE_PIDS[2]=$!; sleep 0.5

echo; echo "=== 2. Wait for chain past height 3 ==="
for _ in $(seq 1 60); do
  H=$($DETERM status --rpc-port 8791 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo; echo "=== 3. fetch full block 1 (determ block-info) + committee ==="
$DETERM block-info 1 --rpc-port 8791 --json > $T/block.json 2>$T/bi.err
$DETERM validators --rpc-port 8791 --json > $T/committee.json 2>&1
HAVE=$([ -s "$T/block.json" ] && python -c "import json;d=json.load(open('$T/block.json'));print('true' if 'creator_tx_lists' in d or ('block' in d and 'creator_tx_lists' in d['block']) else 'false')" 2>/dev/null || echo false)
assert "$HAVE" "block-info produced a full block (has creator_tx_lists)"

echo; echo "=== 4. block-verify (text) PASS on real block ==="
set +e
OUT=$($DETERM_LIGHT block-verify --block $T/block.json --committee $T/committee.json 2>&1); RC=$?
set -e
# Raw verifier output prefixed "    | " so it can't collide with run_all.sh's
# marker grep (also keeps this diagnostic pipeline from tripping set -e).
echo "$OUT" | grep -E "STRUCTURE|TX-ROOT|SIGS|BLOCK-VERIFY" | sed 's/^/    | /'
assert "$([ $RC -eq 0 ] && echo true || echo false)" "block-verify exit 0 on real block"
echo "$OUT" | grep -q "BLOCK-VERIFY: PASS" && assert true "summary PASS" || assert false "summary PASS"
echo "$OUT" | grep -Eq "STRUCTURE PASS" && echo "$OUT" | grep -Eq "TX-ROOT   PASS" && echo "$OUT" | grep -Eq "SIGS      PASS" \
  && assert true "STRUCTURE + TX-ROOT + SIGS all PASS" || assert false "STRUCTURE + TX-ROOT + SIGS all PASS"

echo; echo "=== 5. --json: audit=PASS, passed==3 ==="
set +e
J=$($DETERM_LIGHT block-verify --block $T/block.json --committee $T/committee.json --json 2>/dev/null); JRC=$?
set -e
JOK=$(echo "$J" | python -c "
import json,sys
try:
  d=json.loads(sys.stdin.read()); m={c['check']:c['verdict'] for c in d.get('checks',[])}
  print('true' if d.get('audit')=='PASS' and d.get('passed')==3 and m.get('SIGS')=='PASS' else 'false')
except Exception: print('false')")
assert "$JOK" "--json audit=PASS passed=3"
assert "$([ $JRC -eq 0 ] && echo true || echo false)" "--json exit 0"

echo; echo "=== 6. NEGATIVE: tampered tx_root -> TX-ROOT FAIL exit 2 ==="
python -c "
import json
d=json.load(open('$T/block.json')); b=d['block'] if 'block' in d and isinstance(d['block'],dict) else d
s=b['tx_root']; b['tx_root']=('00' if s[:2]!='00' else 'ff')+s[2:]
json.dump(d,open('$T/block_badroot.json','w'))"
set +e; OUT=$($DETERM_LIGHT block-verify --block $T/block_badroot.json --committee $T/committee.json 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "TX-ROOT   FAIL" && [ $RC -eq 2 ] && assert true "tampered tx_root -> TX-ROOT FAIL exit 2" || assert false "tampered tx_root -> TX-ROOT FAIL exit 2"

echo; echo "=== 7. NEGATIVE: tampered creator_block_sig -> SIGS FAIL exit 2 ==="
python -c "
import json
d=json.load(open('$T/block.json')); b=d['block'] if 'block' in d and isinstance(d['block'],dict) else d
s=b['creator_block_sigs'][0]; b['creator_block_sigs'][0]=('1' if s[0]!='1' else '2')+s[1:]
json.dump(d,open('$T/block_badsig.json','w'))"
set +e; OUT=$($DETERM_LIGHT block-verify --block $T/block_badsig.json --committee $T/committee.json 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "SIGS      FAIL" && [ $RC -eq 2 ] && assert true "tampered sig -> SIGS FAIL exit 2" || assert false "tampered sig -> SIGS FAIL exit 2"

echo; echo "=== 8. NEGATIVE: wrong committee pubkey -> SIGS FAIL ==="
python -c "
import json
c=json.load(open('$T/committee.json')); arr=c if isinstance(c,list) else c.get('members',c)
if arr: pk=arr[0]['ed_pub']; arr[0]['ed_pub']=('1' if pk[0]!='1' else '2')+pk[1:]
json.dump(arr,open('$T/committee_wrong.json','w'))"
set +e; OUT=$($DETERM_LIGHT block-verify --block $T/block.json --committee $T/committee_wrong.json 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "SIGS      FAIL" && [ $RC -eq 2 ] && assert true "wrong committee -> SIGS FAIL exit 2" || assert false "wrong committee -> SIGS FAIL exit 2"

echo; echo "=== 9. NEGATIVE: malformed block (missing field) -> STRUCTURE FAIL ==="
echo '{"index":1,"prev_hash":"x","timestamp":1,"creators":["n1"]}' > $T/malformed.json
set +e; OUT=$($DETERM_LIGHT block-verify --block $T/malformed.json --committee $T/committee.json 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "STRUCTURE FAIL" && [ $RC -eq 2 ] && assert true "malformed -> STRUCTURE FAIL exit 2" || assert false "malformed -> STRUCTURE FAIL exit 2"

echo; echo "=== Test summary ==="
echo "  checks: $pass_count ok, $fail_count failed"
set +e   # negative-test blocks left -e enabled; teardown runs in the
         # script's true -u-only mode so a dead-PID kill can't abort before
         # the final marker (would exit 1 with 0 failures otherwise).
trap - EXIT INT
cleanup
if [ "$fail_count" = "0" ]; then echo "  PASS: test_light_block_verify"; exit 0
else echo "  FAIL: test_light_block_verify ($fail_count checks failed)"; exit 1; fi
