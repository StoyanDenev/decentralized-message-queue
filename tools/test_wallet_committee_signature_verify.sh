#!/usr/bin/env bash
# `determ-wallet committee-signature-verify` — offline Ed25519 verification
# of K-of-K committee signatures on a real block, against an operator-
# supplied block_digest. Mirrors the chain daemon's `verify-block-sigs`
# but executes inside the lean wallet binary (no chain-library link).
#
# Workflow exercised:
#   1. Spin up a 3-node cluster, wait for a block past height 1.
#   2. Fetch the block via `block-info --json` (full Block::to_json shape).
#   3. Fetch the committee pubkeys via `validators --json`.
#   4. Fetch the canonical block_digest via `verify-block-sigs`'s emitted
#      `digest:` line (the wallet binary doesn't link the chain library,
#      so it can't compute block_digest itself — the operator pins it).
#   5. Run `determ-wallet committee-signature-verify` and assert:
#      - happy-path verifies (PASS exit 0)
#      - tampered digest fails (exit 2, FAIL diagnostic)
#      - missing committee entry fails loudly (exit 1)
#      - two tampered sigs (1-of-3 valid < 2-quorum) fail (exit 2)
#      - one tampered sig (2-of-3 valid >= 2-quorum) still passes
#        but flags the bad signer's row valid=false
#      - abstention (sentinel-zero sig) counts toward missing not failure
#      - JSON output is well-formed and carries the expected fields
#      - {block: {...}} envelope shape is accepted
#      - {validators: [...]} committee envelope shape is accepted
#
# Run from repo root: bash tools/test_wallet_committee_signature_verify.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "$DETERM_WALLET" ]; then
    echo "FAIL: DETERM_WALLET binary not found (build with cmake --build build --target determ-wallet)"
    exit 1
fi

T=test_wallet_committee_signature_verify
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

echo "=== 1. Init + start 3-node cluster ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-wcsv",
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
configure_node 1 7791 8791 '["127.0.0.1:7792","127.0.0.1:7793"]'
configure_node 2 7792 8792 '["127.0.0.1:7791","127.0.0.1:7793"]'
configure_node 3 7793 8793 '["127.0.0.1:7791","127.0.0.1:7792"]'

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 2. Wait for chain to advance past height 3 ==="
H=0
for _ in $(seq 1 60); do
  H=$($DETERM status --rpc-port 8791 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"
if [ "$H" -lt 1 ]; then
  echo "  FAIL: chain failed to advance"; exit 1
fi

echo
echo "=== 3. Export full block 1 + committee + digest ==="
# Full block (Block::to_json shape — has creators + creator_block_sigs).
$DETERM block-info 1 --rpc-port 8791 --json > $T/block.json 2>&1
# Committee via validators RPC (raw array shape).
$DETERM validators --rpc-port 8791 --json > $T/committee.json 2>&1
# Canonical block_digest via verify-block-sigs (we don't link the chain
# lib in the wallet, so we pin it from a trusted source: the daemon).
$DETERM headers --rpc-port 8791 --from 1 --count 1 > $T/hdr.json 2>&1
VBS_OUT=$($DETERM verify-block-sigs --header $T/hdr.json --committee $T/committee.json 2>&1)
DIGEST=$(echo "$VBS_OUT" | grep '^  digest:' | awk '{print $2}')
echo "  digest:         $DIGEST"
if [ -z "$DIGEST" ] || [ ${#DIGEST} -ne 64 ]; then
  echo "  FAIL: failed to extract 64-hex digest from verify-block-sigs output"
  echo "  Got: '$DIGEST' (len=${#DIGEST})"; exit 1
fi

# Also pre-build a "validators envelope" version of the committee file —
# the wallet command accepts {validators: [...]} too.
python -c "
import json
arr = json.load(open('$T/committee.json'))
with open('$T/committee_env.json','w') as f: json.dump({'validators': arr}, f)
"

# Pre-build a {block: {...}} envelope version of the block.
python -c "
import json
b = json.load(open('$T/block.json'))
with open('$T/block_env.json','w') as f: json.dump({'block': b}, f)
"

echo
echo "=== 4. Happy path: wallet committee-signature-verify PASS ==="
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block.json \
        --committee $T/committee.json \
        --block-digest $DIGEST 2>&1)
RC=$?
PASS_LINE=$(echo "$OUT" | head -1 | grep -q "^PASS" && echo true || echo false)
assert "$PASS_LINE" "happy-path: first output line starts with PASS"
[ "$RC" = "0" ] && OK=true || OK=false
assert "$OK" "happy-path: exit code 0"

# Per-signer rows present.
ROW_COUNT=$(echo "$OUT" | grep -c "^  \[")
[ "$ROW_COUNT" -ge 3 ] && OK=true || OK=false
assert "$OK" "happy-path: at least 3 per-signer rows emitted ($ROW_COUNT)"

# All three rows show valid=true.
VALID_COUNT=$(echo "$OUT" | grep -c "valid=true")
[ "$VALID_COUNT" -ge 3 ] && OK=true || OK=false
assert "$OK" "happy-path: all three sigs report valid=true (count=$VALID_COUNT)"

echo
echo "=== 5. JSON output well-formed ==="
JSON_OUT=$($DETERM_WALLET committee-signature-verify \
            --block $T/block.json \
            --committee $T/committee.json \
            --block-digest $DIGEST --json 2>&1)
RC=$?
[ "$RC" = "0" ] && OK=true || OK=false
assert "$OK" "json mode: exit 0"

python -c "
import json, sys
try:
    r = json.loads('''$JSON_OUT''')
except Exception as e:
    print('JSON parse error:', e); sys.exit(1)
needed = ['block_digest_hex','committee_size','present_count','valid_count',
          'missing_count','abstention_count','required','pass','signers']
for k in needed:
    assert k in r, 'missing key: '+k
assert r['pass'] is True, 'pass should be True on happy path'
assert r['valid_count'] == 3, 'expected valid_count=3, got %d' % r['valid_count']
assert r['committee_size'] == 3, 'expected committee_size=3, got %d' % r['committee_size']
assert r['block_digest_hex'].lower() == '$DIGEST'.lower(), 'digest hex mismatch'
assert isinstance(r['signers'], list) and len(r['signers']) == 3
for s in r['signers']:
    assert 'domain' in s and 'sig_present' in s and 'valid' in s
print('JSON_VALID')
" > $T/json_check.out 2>&1
JSON_OK=$(grep -q "^JSON_VALID$" $T/json_check.out && echo true || echo false)
assert "$JSON_OK" "json mode: shape matches spec (block_digest_hex, committee_size, present_count, valid_count, missing_count, abstention_count, required, pass, signers[])"

echo
echo "=== 6. Tampered block_digest should FAIL (exit 2) ==="
# Flip the first hex char of the digest.
TAMP_DIGEST=$(python -c "d='$DIGEST'; print(('1' if d[0]!='1' else '2') + d[1:])")
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block.json \
        --committee $T/committee.json \
        --block-digest $TAMP_DIGEST 2>&1)
RC=$?
[ "$RC" = "2" ] && OK=true || OK=false
assert "$OK" "tampered digest: exit code 2 (auth-style alert)"
echo "$OUT" | head -1 | grep -q "^FAIL" && OK=true || OK=false
assert "$OK" "tampered digest: first output line FAIL"

echo
echo "=== 7. Missing committee entry should FAIL loudly (exit 1) ==="
python -c "
import json
arr = json.load(open('$T/committee.json'))
arr = arr[1:]  # drop the first member
with open('$T/committee_missing.json','w') as f: json.dump(arr, f)
"
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block.json \
        --committee $T/committee_missing.json \
        --block-digest $DIGEST 2>&1)
RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK" "missing committee entry: exit code 1 (operator error, not auth)"
echo "$OUT" | grep -q "is not in the supplied committee" && OK=true || OK=false
assert "$OK" "missing committee entry: diagnostic names the missing domain (loud)"

echo
echo "=== 8. Abstention sentinel zero counts toward missing not failure ==="
# Flip one creator's block_sig to the all-zero sentinel.
python -c "
import json
b = json.load(open('$T/block.json'))
b['creator_block_sigs'][0] = '0' * 128
with open('$T/block_abstain.json','w') as f: json.dump(b, f)
"
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block_abstain.json \
        --committee $T/committee.json \
        --block-digest $DIGEST --json 2>&1)
RC=$?
python -c "
import json
r = json.loads('''$OUT''')
# After abstention: 3 creators, 2 present, 1 missing.
assert r['committee_size']    == 3, 'committee_size != 3'
assert r['present_count']     == 2, 'present_count != 2'
assert r['missing_count']     == 1, 'missing_count != 1'
assert r['abstention_count']  == 1, 'abstention_count != 1'
assert r['valid_count']       == 2, 'valid_count != 2'
# Quorum: required = ceil(2*2/3) = 2. valid_count=2 ⇒ pass.
assert r['required']          == 2, 'required != 2 (expected ceil(2*2/3))'
assert r['pass']              is True, 'pass should be True (2 valid >= 2 required)'
# Sentinel row records sig_present=false, valid=false.
abstain = [s for s in r['signers'] if not s['sig_present']]
assert len(abstain) == 1, 'expected exactly one abstain row'
assert abstain[0]['valid'] is False, 'abstain row valid must be False'
print('ABSTAIN_OK')
" > $T/abstain_check.out 2>&1
ABSTAIN_OK=$(grep -q "^ABSTAIN_OK$" $T/abstain_check.out && echo true || echo false)
assert "$ABSTAIN_OK" "abstention: sentinel sig counts toward missing (not failure); quorum still passes (2/3 present, 2/2 valid >= ceil(2*2/3)=2)"
[ "$RC" = "0" ] && OK=true || OK=false
assert "$OK" "abstention: exit code 0 (quorum still met)"

echo
echo "=== 9. Tampered signatures past quorum should FAIL (exit 2) ==="
# K=3 with BFT-quorum ceil(2*3/3)=2 means a single tampered sig still leaves 2
# valid ⇒ quorum met. Tamper TWO sigs so valid_count=1 < required=2.
python -c "
import json
b = json.load(open('$T/block.json'))
for idx in [0, 1]:
    s = b['creator_block_sigs'][idx]
    b['creator_block_sigs'][idx] = ('1' if s[0] != '1' else '2') + s[1:]
with open('$T/block_tampered.json','w') as f: json.dump(b, f)
"
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block_tampered.json \
        --committee $T/committee.json \
        --block-digest $DIGEST 2>&1)
RC=$?
[ "$RC" = "2" ] && OK=true || OK=false
assert "$OK" "tampered sigs past quorum: exit code 2"
echo "$OUT" | head -1 | grep -q "^FAIL" && OK=true || OK=false
assert "$OK" "tampered sigs past quorum: first output line FAIL"

# Also verify the single-sig tamper case: with K=3, tampering one sig
# still passes (2-of-3 ≥ ceil(2*3/3)=2), and is reflected in the
# per-signer rows: exactly one row reports valid=false.
python -c "
import json
b = json.load(open('$T/block.json'))
s = b['creator_block_sigs'][0]
b['creator_block_sigs'][0] = ('1' if s[0] != '1' else '2') + s[1:]
with open('$T/block_one_tampered.json','w') as f: json.dump(b, f)
"
JSON_OUT=$($DETERM_WALLET committee-signature-verify \
            --block $T/block_one_tampered.json \
            --committee $T/committee.json \
            --block-digest $DIGEST --json 2>&1)
python -c "
import json
r = json.loads('''$JSON_OUT''')
# Quorum still met (2 valid of 3 present, ceil(2*3/3)=2 required).
assert r['pass']           is True,  'one-tamper quorum should still pass'
assert r['valid_count']    == 2,     'expected valid_count=2 (one tampered)'
assert r['present_count']  == 3,     'present_count must still be 3'
# Exactly one signer reports valid=false.
invalid = [s for s in r['signers'] if not s['valid']]
assert len(invalid) == 1,  'expected exactly one signer with valid=false'
print('SINGLE_TAMPER_OK')
" > $T/single_tamper.out 2>&1
SINGLE_OK=$(grep -q "^SINGLE_TAMPER_OK$" $T/single_tamper.out && echo true || echo false)
assert "$SINGLE_OK" "single-sig tamper: quorum still passes; exactly one signer reports valid=false (K=3, BFT-mode ceil(2K/3)=2)"

echo
echo "=== 10. {block: {...}} envelope shape accepted ==="
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block_env.json \
        --committee $T/committee.json \
        --block-digest $DIGEST 2>&1)
RC=$?
[ "$RC" = "0" ] && OK=true || OK=false
assert "$OK" "envelope: {block:{...}} accepted (exit 0)"
echo "$OUT" | head -1 | grep -q "^PASS" && OK=true || OK=false
assert "$OK" "envelope: {block:{...}} verifies (PASS)"

echo
echo "=== 11. {validators: [...]} committee envelope shape accepted ==="
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block.json \
        --committee $T/committee_env.json \
        --block-digest $DIGEST 2>&1)
RC=$?
[ "$RC" = "0" ] && OK=true || OK=false
assert "$OK" "envelope: {validators:[...]} accepted (exit 0)"

echo
echo "=== 12. Missing required args should fail (exit 1) ==="
OUT=$($DETERM_WALLET committee-signature-verify 2>&1)
RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK" "no args: exit 1"
echo "$OUT" | grep -q "Usage:" && OK=true || OK=false
assert "$OK" "no args: prints Usage line"

# --block missing
OUT=$($DETERM_WALLET committee-signature-verify \
        --committee $T/committee.json \
        --block-digest $DIGEST 2>&1)
RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK" "missing --block: exit 1"

# --committee missing
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block.json \
        --block-digest $DIGEST 2>&1)
RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK" "missing --committee: exit 1"

# --block-digest missing
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block.json \
        --committee $T/committee.json 2>&1)
RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK" "missing --block-digest: exit 1"

echo
echo "=== 13. Malformed --block-digest hex should fail (exit 1) ==="
# Wrong length.
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block.json \
        --committee $T/committee.json \
        --block-digest "abcd" 2>&1)
RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK" "short --block-digest: exit 1"
echo "$OUT" | grep -q "64 hex chars" && OK=true || OK=false
assert "$OK" "short --block-digest: diagnostic mentions 64 hex chars"

# Non-hex chars (64 of them).
NONHEX=$(python -c "print('z' * 64)")
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/block.json \
        --committee $T/committee.json \
        --block-digest "$NONHEX" 2>&1)
RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK" "non-hex --block-digest: exit 1"

echo
echo "=== 14. Missing --block file should fail (exit 1) ==="
OUT=$($DETERM_WALLET committee-signature-verify \
        --block $T/nonexistent.json \
        --committee $T/committee.json \
        --block-digest $DIGEST 2>&1)
RC=$?
[ "$RC" = "1" ] && OK=true || OK=false
assert "$OK" "missing --block file: exit 1"
echo "$OUT" | grep -q "cannot open" && OK=true || OK=false
assert "$OK" "missing --block file: diagnostic mentions cannot open"

echo
echo "=== 15. Tampered digest reports valid_count=0 in JSON ==="
JSON_OUT=$($DETERM_WALLET committee-signature-verify \
            --block $T/block.json \
            --committee $T/committee.json \
            --block-digest $TAMP_DIGEST --json 2>&1)
python -c "
import json
r = json.loads('''$JSON_OUT''')
assert r['pass']        is False, 'pass should be False on bad digest'
assert r['valid_count'] == 0,     'valid_count should be 0 on bad digest'
assert r['present_count'] == 3,   'present_count should still be 3 (sigs are there, just wrong)'
print('TAMP_OK')
" > $T/tamp_check.out 2>&1
TAMP_OK=$(grep -q "^TAMP_OK$" $T/tamp_check.out && echo true || echo false)
assert "$TAMP_OK" "tampered digest JSON: pass=false, valid_count=0, present_count=3"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet committee-signature-verify (offline K-of-K Ed25519 verifier)"
  exit 0
else
  echo "  FAIL: test_wallet_committee_signature_verify"
  exit 1
fi
