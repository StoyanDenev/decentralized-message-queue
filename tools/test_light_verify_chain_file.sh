#!/usr/bin/env bash
# determ-light verify-chain-file — self-contained OFFLINE whole-chain verifier.
#
# The file-based dual of the online verify-chain: given an EXPORTED headers file
# (fetch-headers / `headers` RPC `{headers:[...], from}` shape) + a committee
# file, it verifies CONTINUITY (prev_hash walk, optionally anchored) + SIGS
# (every non-genesis header's committee Ed25519 over its INTERNALLY-recomputed
# digest) with NO daemon. Sig-less headers (genesis, empty creator_block_sigs)
# are skipped.
#
# Boots a 3-node cluster, exports the header chain via determ-light fetch-headers
# + the committee via determ validators, then verifies OFFLINE. This path does
# NOT call compute_genesis_hash, so it is unaffected by the determ-light
# genesis-hash cross-platform gap — verified working on this box. The optional
# --genesis-hash anchor is exercised with the daemon's ACTUAL block-0 hash
# (header[0].block_hash), not compute_genesis_hash, so it too works natively.
#
# Assertions:
#   1. fetch-headers + validators produce fixtures.
#   2. verify-chain-file PASS (CONTINUITY + SIGS), exit 0; both checks PASS.
#   3. --json: audit=PASS.
#   4. --genesis-hash = real block-0 hash -> CONTINUITY genesis-anchored PASS.
#   5. NEGATIVE: wrong --genesis-hash (all-zero) -> CONTINUITY FAIL exit 2.
#   6. NEGATIVE: tampered prev_hash -> CONTINUITY FAIL exit 2.
#   7. NEGATIVE: tampered creator_block_sig -> SIGS FAIL exit 2.
#
# Run from repo root: bash tools/test_light_verify_chain_file.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    echo "  PASS: test_light_verify_chain_file (SKIP — determ-light binary not built)"
    exit 0
fi

T=test_light_verify_chain_file
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
  echo "  FAIL: test_light_verify_chain_file (aborted before summary)"
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
  "chain_id": "test-light-vcf",
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
configure_node 1 7801 8801 '["127.0.0.1:7802","127.0.0.1:7803"]'
configure_node 2 7802 8802 '["127.0.0.1:7801","127.0.0.1:7803"]'
configure_node 3 7803 8803 '["127.0.0.1:7801","127.0.0.1:7802"]'
NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 & NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 & NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 & NODE_PIDS[2]=$!; sleep 0.5

echo; echo "=== 2. Wait for chain past height 4 ==="
for _ in $(seq 1 60); do
  H=$($DETERM status --rpc-port 8801 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 4 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo; echo "=== 3. export headers [0..H] + committee ==="
$DETERM_LIGHT fetch-headers --rpc-port 8801 --from 0 --count $((H+1)) --out $T/headers.json > $T/fetch.out 2>&1
$DETERM validators --rpc-port 8801 --json > $T/committee.json 2>&1
NH=$([ -s "$T/headers.json" ] && python -c "import json;d=json.load(open('$T/headers.json'));print(len(d.get('headers',[])))" 2>/dev/null || echo 0)
assert "$([ "$NH" -ge 4 ] 2>/dev/null && echo true || echo false)" "fetch-headers exported $NH headers + committee"

echo; echo "=== 4. verify-chain-file PASS (CONTINUITY + SIGS) ==="
set +e
OUT=$($DETERM_LIGHT verify-chain-file --in $T/headers.json --committee $T/committee.json 2>&1); RC=$?
set -e
# Raw verifier output prefixed "    | " so it can't collide with run_all.sh's
# marker grep (also keeps this diagnostic pipeline from tripping set -e).
echo "$OUT" | grep -E "CONTINUITY|SIGS|VERIFY-CHAIN-FILE" | sed 's/^/    | /'
assert "$([ $RC -eq 0 ] && echo true || echo false)" "verify-chain-file exit 0"
echo "$OUT" | grep -Eq "CONTINUITY  PASS" && echo "$OUT" | grep -Eq "SIGS        PASS" \
  && assert true "CONTINUITY + SIGS both PASS" || assert false "CONTINUITY + SIGS both PASS"

echo; echo "=== 5. --json audit=PASS ==="
set +e; J=$($DETERM_LIGHT verify-chain-file --in $T/headers.json --committee $T/committee.json --json 2>/dev/null); set -e
JOK=$(echo "$J" | python -c "
import json,sys
try:
  d=json.loads(sys.stdin.read()); m={c['check']:c['verdict'] for c in d.get('checks',[])}
  print('true' if d.get('audit')=='PASS' and m.get('CONTINUITY')=='PASS' and m.get('SIGS')=='PASS' else 'false')
except Exception: print('false')")
assert "$JOK" "--json audit=PASS, both checks PASS"

echo; echo "=== 6. --genesis-hash = real block-0 hash -> genesis-anchored PASS ==="
B0=$(python -c "import json;print(json.load(open('$T/headers.json'))['headers'][0]['block_hash'])")
set +e; $DETERM_LIGHT verify-chain-file --in $T/headers.json --committee $T/committee.json --genesis-hash "$B0" >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 0 ] && echo true || echo false)" "genesis-anchored (real block-0 hash) -> PASS exit 0"

echo; echo "=== 7. NEGATIVE: wrong --genesis-hash -> CONTINUITY FAIL exit 2 ==="
set +e; OUT=$($DETERM_LIGHT verify-chain-file --in $T/headers.json --committee $T/committee.json --genesis-hash "$(printf '0%.0s' {1..64})" 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "CONTINUITY  FAIL" && [ $RC -eq 2 ] && assert true "wrong genesis-hash -> CONTINUITY FAIL exit 2" || assert false "wrong genesis-hash -> CONTINUITY FAIL exit 2"

echo; echo "=== 8. NEGATIVE: tampered prev_hash -> CONTINUITY FAIL exit 2 ==="
python -c "
import json
d=json.load(open('$T/headers.json')); hs=d['headers']
i=len(hs)-1; s=hs[i]['prev_hash']; hs[i]['prev_hash']=('00' if s[:2]!='00' else 'ff')+s[2:]
json.dump(d,open('$T/headers_badprev.json','w'))"
set +e; OUT=$($DETERM_LIGHT verify-chain-file --in $T/headers_badprev.json --committee $T/committee.json 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "CONTINUITY  FAIL" && [ $RC -eq 2 ] && assert true "tampered prev_hash -> CONTINUITY FAIL exit 2" || assert false "tampered prev_hash -> CONTINUITY FAIL exit 2"

echo; echo "=== 9. NEGATIVE: tampered creator_block_sig -> SIGS FAIL exit 2 ==="
python -c "
import json
d=json.load(open('$T/headers.json')); hs=d['headers']
# find first header with sigs (a non-genesis block) and flip one sig byte
for h in hs:
    sg=h.get('creator_block_sigs',[])
    if sg:
        s=sg[0]; h['creator_block_sigs'][0]=('1' if s[0]!='1' else '2')+s[1:]; break
json.dump(d,open('$T/headers_badsig.json','w'))"
set +e; OUT=$($DETERM_LIGHT verify-chain-file --in $T/headers_badsig.json --committee $T/committee.json 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "SIGS        FAIL" && [ $RC -eq 2 ] && assert true "tampered sig -> SIGS FAIL exit 2" || assert false "tampered sig -> SIGS FAIL exit 2"

echo; echo "=== 10. NEGATIVE: STRIPPED sigs on a non-genesis block -> SIGS FAIL exit 2 ==="
# Closes the emptiness-skip hole: creator_block_sigs are NOT recomputed by
# CONTINUITY (stored-linkage walk), so a stripped real block must FAIL in SIGS,
# not be silently skipped as if it were genesis. The skip keys on index==0 only.
python -c "
import json
d=json.load(open('$T/headers.json')); hs=d['headers']
for h in hs:                                  # first NON-genesis block (index>0)
    if h.get('index',0) != 0 and h.get('creator_block_sigs'):
        h['creator_block_sigs']=[]; break     # strip its committee sigs
json.dump(d,open('$T/headers_stripped.json','w'))"
set +e; OUT=$($DETERM_LIGHT verify-chain-file --in $T/headers_stripped.json --committee $T/committee.json 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "SIGS        FAIL" && [ $RC -eq 2 ] && assert true "stripped non-genesis sigs -> SIGS FAIL exit 2" || assert false "stripped non-genesis sigs -> SIGS FAIL exit 2"

echo; echo "=== 11. --committee-manifest (2 ranges, same committee) covers [0..H] -> PASS ==="
M=$((H/2))
cat > $T/manifest_ok.json <<EOF
[{"from":0,"to":$M,"committee":"$T/committee.json"},
 {"from":$((M+1)),"to":9999999,"committee":"$T/committee.json"}]
EOF
set +e
OUT=$($DETERM_LIGHT verify-chain-file --in $T/headers.json --committee-manifest $T/manifest_ok.json 2>&1); RC=$?
set -e
echo "$OUT" | grep -E "SIGS|VERIFY-CHAIN-FILE" | sed 's/^/    | /'
echo "$OUT" | grep -Eq "SIGS        PASS" && [ $RC -eq 0 ] && assert true "manifest 2-range -> PASS exit 0" || assert false "manifest 2-range -> PASS exit 0"

echo; echo "=== 12. NEGATIVE: manifest upper range -> WRONG committee -> SIGS FAIL exit 2 ==="
python -c "
import json
c=json.load(open('$T/committee.json')); arr=c if isinstance(c,list) else c.get('members',c)
if arr: pk=arr[0]['ed_pub']; arr[0]['ed_pub']=('1' if pk[0]!='1' else '2')+pk[1:]
json.dump(arr,open('$T/committee_wrong.json','w'))"
cat > $T/manifest_bad.json <<EOF
[{"from":0,"to":$M,"committee":"$T/committee.json"},
 {"from":$((M+1)),"to":9999999,"committee":"$T/committee_wrong.json"}]
EOF
set +e; OUT=$($DETERM_LIGHT verify-chain-file --in $T/headers.json --committee-manifest $T/manifest_bad.json 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "SIGS        FAIL" && [ $RC -eq 2 ] && assert true "manifest wrong-committee range -> SIGS FAIL exit 2" || assert false "manifest wrong-committee range -> SIGS FAIL exit 2"

echo; echo "=== 13. NEGATIVE: manifest GAP (uncovered block) -> SIGS FAIL exit 2 ==="
cat > $T/manifest_gap.json <<EOF
[{"from":0,"to":$M,"committee":"$T/committee.json"}]
EOF
set +e; OUT=$($DETERM_LIGHT verify-chain-file --in $T/headers.json --committee-manifest $T/manifest_gap.json 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "no manifest range covers" && [ $RC -eq 2 ] && assert true "manifest gap -> SIGS FAIL exit 2 (uncovered block)" || assert false "manifest gap -> SIGS FAIL exit 2 (uncovered block)"

echo; echo "=== 14. arg validation: both / neither committee source -> exit 1 ==="
set +e; $DETERM_LIGHT verify-chain-file --in $T/headers.json --committee $T/committee.json --committee-manifest $T/manifest_ok.json >/dev/null 2>&1; RC_BOTH=$?
$DETERM_LIGHT verify-chain-file --in $T/headers.json >/dev/null 2>&1; RC_NEITHER=$?; set -e
[ $RC_BOTH -eq 1 ] && [ $RC_NEITHER -eq 1 ] && assert true "both/neither committee source -> exit 1" || assert false "both/neither committee source -> exit 1 (both=$RC_BOTH neither=$RC_NEITHER)"

echo; echo "=== Test summary ==="
echo "  checks: $pass_count ok, $fail_count failed"
set +e   # negative-test blocks left -e enabled; teardown runs in the
         # script's true -u-only mode so a dead-PID kill can't abort before
         # the final marker (would exit 1 with 0 failures otherwise).
trap - EXIT INT
cleanup
if [ "$fail_count" = "0" ]; then echo "  PASS: test_light_verify_chain_file"; exit 0
else echo "  FAIL: test_light_verify_chain_file ($fail_count checks failed)"; exit 1; fi
