#!/usr/bin/env bash
# determ-light verify-archive — OFFLINE re-verification of an
# export-headers archive.
#
# Closes the audit loop with export-headers: boot a 3-node cluster,
# run export-headers to produce a verifiable archive (WITH committee
# sigs), then STOP THE CLUSTER and re-verify the archive offline with
# zero trust in any daemon. verify-archive opens no RPC and takes no
# --rpc-port — it re-checks the genesis anchor, the prev_hash chain,
# and the committee Ed25519 sigs from the archive bytes alone.
#
# Assertions:
#   1. Export an archive (--include-committee-sigs), verify-archive it
#      → exit 0; summary reports all headers verified + K sig sets.
#   2. OFFLINE proof: stop the cluster, re-run verify-archive on the
#      SAME archive → still exit 0 (no network needed).
#   3. Tampered archive (flip a byte in a header_json's state_root) →
#      verify-archive detects, exits non-zero, diagnostic names the
#      bad index.
#   4. Wrong genesis file (different chain_id → different genesis hash)
#      → genesis-hash mismatch, refuse, non-zero exit.
#   5. --require-sigs on a sigs-stripped archive (exported WITHOUT
#      --include-committee-sigs) → fail with "no committee sigs" diag.
#   6. prev_hash continuity break (corrupt one header's prev_hash) →
#      detected, non-zero exit.
#   7. (extra) Tampered committee sig (flip a byte in a creator_block_sigs
#      entry) → detected, non-zero exit.
#   8. (extra) sigs-stripped archive WITHOUT --require-sigs → exit 0
#      (genesis anchor + prev_hash chain still verify; sig check skipped).
#
# Run from repo root: bash tools/test_light_verify_archive.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_verify_archive
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS

cluster_running=1
stop_cluster() {
  # Bulletproof under `set -e`: never let a failed kill (already-dead
  # pid) or an empty array element abort the caller. Always returns 0.
  set +e
  if [ "$cluster_running" = "1" ]; then
    for pid in "${NODE_PIDS[@]:-}"; do
      [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
    sleep 1
    for pid in "${NODE_PIDS[@]:-}"; do
      [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    done
    cluster_running=0
  fi
  return 0
}
trap stop_cluster EXIT INT

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init 3-node cluster ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-verify-archive",
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

# A DIFFERENT genesis (same creators, different chain_id) → different
# compute_genesis_hash. Used by assertion 4 (wrong-genesis refusal).
# It need not match any running chain — verify-archive is offline.
cat > $T/gen_wrong.json <<EOF
{
  "chain_id": "WRONG-CHAIN-different-identity",
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
$DETERM genesis-tool build $T/gen_wrong.json | tail -1
GHASH_WRONG=$(cat $T/gen_wrong.json.hash)
echo "  genesis hash:        $GHASH"
echo "  wrong-genesis hash:  $GHASH_WRONG"

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
echo "=== 2. Wait for chain past height 10 ==="
H=0
for _ in $(seq 1 120); do
  H=$($DETERM status --rpc-port 8791 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 10 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

if [ "$H" -lt 10 ] 2>/dev/null; then
  echo "  FAIL: cluster did not reach height >= 10 (got $H)"
  exit 1
fi

# Export a known-safe sub-range [0, 10) that won't race the tip.
EXPORT_FROM=0
EXPORT_COUNT=10

echo
echo "=== 3. export-headers [0, $EXPORT_COUNT) WITH committee sigs ==="
set +e
OUT=$($DETERM_LIGHT export-headers \
        --rpc-port 8791 --genesis $T/gen.json \
        --from $EXPORT_FROM --count $EXPORT_COUNT \
        --out $T/archive.json \
        --include-committee-sigs 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "export-headers (with sigs) exits 0 [setup]"
else
    assert "false" "export-headers (with sigs) exits 0 [setup] (got $RC)"
fi

# Also export a sigs-STRIPPED archive (for assertions 5 + 8).
$DETERM_LIGHT export-headers \
        --rpc-port 8791 --genesis $T/gen.json \
        --from $EXPORT_FROM --count $EXPORT_COUNT \
        --out $T/archive_nosigs.json 2>&1 | tail -1

echo
echo "=== ASSERTION 1: verify-archive (with sigs, cluster up) → exit 0 ==="
set +e
OUT=$($DETERM_LIGHT verify-archive \
        --in $T/archive.json --genesis $T/gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "verify-archive exits 0 on a valid sigs-bearing archive"
else
    assert "false" "verify-archive exits 0 on valid archive (got $RC)"
fi
SUMMARY_OK=$(echo "$OUT" | grep -qiE "OK: [0-9]+ headers verified" && echo true || echo false)
assert "$SUMMARY_OK" "summary reports 'OK: N headers verified'"
SIGS_OK=$(echo "$OUT" | grep -qiE "committee-sig sets valid" && echo true || echo false)
assert "$SIGS_OK" "summary reports committee-sig sets valid"

# Capture the canonical summary line for the final report.
SAMPLE_SUMMARY=$(echo "$OUT" | grep -iE "^OK:" | head -1)

echo
echo "=== ASSERTION 2: OFFLINE proof — STOP cluster, re-verify → exit 0 ==="
stop_cluster
echo "  cluster stopped (PIDs killed); no daemon is listening on 879x now."
# Prove the daemon is truly gone: an RPC-using command must fail.
set +e
PROBE=$($DETERM_LIGHT verify-chain --rpc-port 8791 --genesis $T/gen.json 2>&1)
PROBE_RC=$?
set -e
if [ "$PROBE_RC" != "0" ]; then
    assert "true" "sanity: RPC-using verify-chain FAILS with cluster down (exit $PROBE_RC)"
else
    assert "false" "sanity: verify-chain should fail with cluster down but exit 0"
fi
# Now the offline verify-archive on the same archive must still pass.
set +e
OUT=$($DETERM_LIGHT verify-archive \
        --in $T/archive.json --genesis $T/gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "verify-archive exits 0 OFFLINE (cluster down, no network)"
else
    assert "false" "verify-archive exits 0 offline (got $RC)"
fi

echo
echo "=== ASSERTION 3: tampered header (block_hash) → detected, names index ==="
# Header-only verification trusts the STORED block_hash (it cannot
# recompute it: signing_bytes() consumes transactions / receipts /
# initial_state which rpc_headers strips). So the meaningful, detectable
# content tampers are (a) block_hash — caught by the prev_hash chain at
# the NEXT index — and (b) a committee sig — caught by verify_block_sigs
# (exercised in assertion 7). Here we flip a nibble in a mid-archive
# block_hash; the chain breaks at index+1. (A bare state_root flip in a
# stripped header is intentionally NOT a meaningful tamper target for
# header-only sync — it isn't bound into anything the verifier recomputes.)
python -c "
import json
a = json.load(open('$T/archive.json'))
# Tamper block_hash of index 3 → breaks prev_hash link of index 4.
rec = a['headers'][3]
h = rec['header_json']
bh = h['block_hash']
h['block_hash'] = ('f' if bh[0] != 'f' else '0') + bh[1:]
json.dump(a, open('$T/archive_tampered.json','w'))
print('TAMPERED_INDEX', rec['index'])
print('BREAK_AT_INDEX', a['headers'][4]['index'])
" | tee $T/tamper_info.txt
BAD_IDX=$(grep BREAK_AT_INDEX $T/tamper_info.txt | awk '{print $2}')
set +e
OUT=$($DETERM_LIGHT verify-archive \
        --in $T/archive_tampered.json --genesis $T/gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
    assert "true" "tampered archive rejected (exit $RC)"
else
    assert "false" "tampered archive should fail but exit 0"
fi
NAMES_IDX=$(echo "$OUT" | grep -qE "index $BAD_IDX|header $BAD_IDX|at .*$BAD_IDX" && echo true || echo false)
assert "$NAMES_IDX" "diagnostic names the bad index ($BAD_IDX)"

echo
echo "=== ASSERTION 4: wrong genesis file → genesis-hash mismatch ==="
set +e
OUT=$($DETERM_LIGHT verify-archive \
        --in $T/archive.json --genesis $T/gen_wrong.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
    assert "true" "wrong genesis rejected (exit $RC)"
else
    assert "false" "wrong genesis should fail but exit 0"
fi
MISMATCH_DIAG=$(echo "$OUT" | grep -qiE "genesis.*hash.*mismatch|mismatch.*genesis|refusing" && echo true || echo false)
assert "$MISMATCH_DIAG" "wrong-genesis diagnostic mentions genesis-hash mismatch"

echo
echo "=== ASSERTION 5: --require-sigs on sigs-STRIPPED archive → fail ==="
set +e
OUT=$($DETERM_LIGHT verify-archive \
        --in $T/archive_nosigs.json --genesis $T/gen.json --require-sigs 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
    assert "true" "--require-sigs on sigs-stripped archive fails (exit $RC)"
else
    assert "false" "--require-sigs on stripped archive should fail but exit 0"
fi
NOSIGS_DIAG=$(echo "$OUT" | grep -qiE "no committee sigs|without --include-committee-sigs|sigs-stripped" && echo true || echo false)
assert "$NOSIGS_DIAG" "diagnostic clearly states the archive has no committee sigs"

echo
echo "=== ASSERTION 6: prev_hash continuity break → detected ==="
python -c "
import json
a = json.load(open('$T/archive.json'))
# Corrupt the prev_hash of the 3rd record (index 2) to break the chain.
rec = a['headers'][2]
h = rec['header_json']
ph = h['prev_hash']
h['prev_hash'] = ('f' if ph[0] != 'f' else '0') + ph[1:]
json.dump(a, open('$T/archive_prevbreak.json','w'))
print('PREVBREAK_INDEX', rec['index'])
" | tee $T/prevbreak_info.txt
set +e
OUT=$($DETERM_LIGHT verify-archive \
        --in $T/archive_prevbreak.json --genesis $T/gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
    assert "true" "prev_hash chain break rejected (exit $RC)"
else
    assert "false" "prev_hash break should fail but exit 0"
fi
PREVBREAK_DIAG=$(echo "$OUT" | grep -qiE "prev_hash|chain break|continuity" && echo true || echo false)
assert "$PREVBREAK_DIAG" "diagnostic mentions prev_hash chain break"

echo
echo "=== ASSERTION 7 (extra): tampered committee sig → detected ==="
python -c "
import json
a = json.load(open('$T/archive.json'))
target = None
for rec in a['headers']:
    h = rec['header_json']
    if rec['index'] >= 1 and isinstance(h.get('creator_block_sigs'), list) and h['creator_block_sigs']:
        target = rec; break
if target is None:
    print('NO_SIGS_FOUND'); raise SystemExit(0)
h = target['header_json']
# Flip a nibble in the first creator_block_sig (hex string).
sig0 = h['creator_block_sigs'][0]
h['creator_block_sigs'][0] = ('f' if sig0[0] != 'f' else '0') + sig0[1:]
json.dump(a, open('$T/archive_sigtamper.json','w'))
print('SIGTAMPER_INDEX', target['index'])
" | tee $T/sigtamper_info.txt
if grep -q SIGTAMPER_INDEX $T/sigtamper_info.txt; then
  SIG_IDX=$(grep SIGTAMPER_INDEX $T/sigtamper_info.txt | awk '{print $2}')
  set +e
  OUT=$($DETERM_LIGHT verify-archive \
          --in $T/archive_sigtamper.json --genesis $T/gen.json 2>&1)
  RC=$?
  set -e
  echo "$OUT"
  if [ "$RC" != "0" ]; then
      assert "true" "tampered committee sig rejected (exit $RC)"
  else
      assert "false" "tampered sig should fail but exit 0"
  fi
else
  assert "false" "could not locate a creator_block_sig to tamper (archive lacks sigs?)"
fi

echo
echo "=== ASSERTION 8 (extra): sigs-stripped archive, NO --require-sigs → exit 0 ==="
set +e
OUT=$($DETERM_LIGHT verify-archive \
        --in $T/archive_nosigs.json --genesis $T/gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "sigs-stripped archive verifies (genesis + prev_hash) without --require-sigs"
else
    assert "false" "sigs-stripped archive should verify chain-only (got $RC)"
fi
SKIP_DIAG=$(echo "$OUT" | grep -qiE "sig check skipped|without --include-committee-sigs" && echo true || echo false)
assert "$SKIP_DIAG" "summary notes committee-sig check was skipped"

echo
echo "=== Sample verify-archive summary line ==="
echo "  $SAMPLE_SUMMARY"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_archive"; exit 0
else
  echo "  FAIL: test_light_verify_archive"; exit 1
fi
