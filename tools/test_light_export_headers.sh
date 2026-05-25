#!/usr/bin/env bash
# determ-light export-headers — verifiable header archive for off-chain audit.
#
# Boots a 3-node cluster, lets it advance ~10 blocks, then exercises
# the `determ-light export-headers` flow: fetch + verify + write a
# self-contained archive. Confirms the archive shape, genesis anchor,
# size delta between sig-include modes, range-error rejection, and a
# re-verification round-trip (run `verify-headers --in <archive>`
# against the exported file).
#
# Assertions:
#   1. Export headers 0..N where N is current head → archive has count
#      records, each carries verified_committee_sigs=true.
#   2. Genesis anchor: archive.genesis_hash matches the operator's
#      genesis-hash (compute_genesis_hash file).
#   3. Re-verification round-trip: build a synthetic rpc_headers-shaped
#      file from the archive's headers + run `verify-headers --in` →
#      exit 0.
#   4. Wrong-range request (--from > head) → exit non-zero with diag.
#   5. --include-committee-sigs mode produces a larger file than the
#      default (creator_block_sigs is preserved).
#
# Run from repo root: bash tools/test_light_export_headers.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_export_headers
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

echo "=== 1. Init 3-node cluster ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-export",
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
echo "=== 2. Wait for chain past height 10 ==="
H=0
for _ in $(seq 1 120); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
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

# Cap the export window to a known-safe sub-range that won't race the
# tip while we run the subcommands. Use blocks [0, 10) — 10 records.
EXPORT_FROM=0
EXPORT_COUNT=10

echo
echo "=== 3. export-headers [0, $EXPORT_COUNT) (default, sigs stripped) ==="
set +e
OUT=$($DETERM_LIGHT export-headers \
        --rpc-port 8771 --genesis $T/gen.json \
        --from $EXPORT_FROM --count $EXPORT_COUNT \
        --out $T/archive.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "export-headers exits 0"
else
    assert "false" "export-headers exits 0 (got $RC)"
fi

# Archive shape + per-record verified_committee_sigs flag.
SHAPE=$(python -c "
import json, sys
try:
    a = json.load(open('$T/archive.json'))
    if not isinstance(a, dict): print('false'); sys.exit(0)
    needed = ['exported_at_height','from','count','genesis_hash','headers']
    for k in needed:
        if k not in a: print('false'); sys.exit(0)
    if a['from'] != $EXPORT_FROM: print('false'); sys.exit(0)
    if a['count'] != $EXPORT_COUNT: print('false'); sys.exit(0)
    if len(a['headers']) != $EXPORT_COUNT: print('false'); sys.exit(0)
    for rec in a['headers']:
        if not rec.get('verified_committee_sigs'): print('false'); sys.exit(0)
        if 'header_json' not in rec: print('false'); sys.exit(0)
        if 'index' not in rec: print('false'); sys.exit(0)
    print('true')
except Exception as e:
    print('false')
")
assert "$SHAPE" "archive shape: $EXPORT_COUNT records, every verified_committee_sigs=true"

echo
echo "=== 4. genesis anchor: archive.genesis_hash == local GHASH ==="
GMATCH=$(python -c "
import json
a = json.load(open('$T/archive.json'))
print('true' if a.get('genesis_hash','').lower() == '$GHASH'.lower() else 'false')
")
assert "$GMATCH" "archive.genesis_hash matches operator's compute_genesis_hash"

echo
echo "=== 5. Re-verification round-trip: verify-headers --in <archive-derived> ==="
# verify-headers expects an rpc_headers envelope (i.e. {headers:[...]}).
# Unwrap each record's header_json back into that shape and run the
# offline verifier.
python -c "
import json
a = json.load(open('$T/archive.json'))
envelope = {
    'headers': [rec['header_json'] for rec in a['headers']],
    'from':    a['from'],
    'count':   a['count'],
    'height':  a['exported_at_height'],
}
with open('$T/replay.json','w') as f: json.dump(envelope, f)
"
set +e
OUT=$($DETERM_LIGHT verify-headers --in $T/replay.json --genesis-hash "$GHASH" 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "verify-headers round-trip exit 0 on exported archive"
else
    assert "false" "verify-headers round-trip exit 0 (got $RC)"
fi

echo
echo "=== 6. Wrong-range request (--from > head) → exit non-zero ==="
BEYOND=$((H + 1000))
set +e
OUT=$($DETERM_LIGHT export-headers \
        --rpc-port 8771 --genesis $T/gen.json \
        --from $BEYOND --count 1 \
        --out $T/should_not_exist.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" != "0" ]; then
    assert "true" "wrong-range --from=$BEYOND rejected (exit $RC)"
else
    assert "false" "wrong-range --from=$BEYOND should have failed but exit 0"
fi
HAS_DIAG=$(echo "$OUT" | grep -qi "head\|range\|beyond\|past" && echo true || echo false)
assert "$HAS_DIAG" "wrong-range prints diagnostic mentioning head/range"

echo
echo "=== 7. --include-committee-sigs produces a larger archive ==="
set +e
OUT=$($DETERM_LIGHT export-headers \
        --rpc-port 8771 --genesis $T/gen.json \
        --from $EXPORT_FROM --count $EXPORT_COUNT \
        --out $T/archive_full.json \
        --include-committee-sigs 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "export-headers --include-committee-sigs exits 0"
else
    assert "false" "export-headers --include-committee-sigs exits 0 (got $RC)"
fi

SIZE_STRIPPED=$(wc -c < $T/archive.json | tr -d ' ')
SIZE_FULL=$(wc -c < $T/archive_full.json | tr -d ' ')
echo "  stripped: $SIZE_STRIPPED bytes  /  full: $SIZE_FULL bytes"
if [ "$SIZE_FULL" -gt "$SIZE_STRIPPED" ] 2>/dev/null; then
    assert "true" "--include-committee-sigs file ($SIZE_FULL B) > default ($SIZE_STRIPPED B)"
else
    assert "false" "--include-committee-sigs file should be larger (full=$SIZE_FULL stripped=$SIZE_STRIPPED)"
fi

# Spot-check: full archive's first non-genesis record has creator_block_sigs.
HAS_SIGS=$(python -c "
import json
a = json.load(open('$T/archive_full.json'))
for rec in a['headers']:
    if rec['index'] >= 1:
        h = rec['header_json']
        print('true' if (isinstance(h.get('creator_block_sigs'), list) and len(h['creator_block_sigs']) > 0) else 'false')
        break
else:
    print('false')
")
assert "$HAS_SIGS" "full archive preserves creator_block_sigs in non-genesis headers"

# And the stripped archive does NOT have creator_block_sigs.
NO_SIGS=$(python -c "
import json
a = json.load(open('$T/archive.json'))
for rec in a['headers']:
    if rec['index'] >= 1:
        h = rec['header_json']
        print('true' if 'creator_block_sigs' not in h else 'false')
        break
else:
    print('false')
")
assert "$NO_SIGS" "default archive strips creator_block_sigs in non-genesis headers"

echo
echo "=== Archive snippet (first record) ==="
python -c "
import json
a = json.load(open('$T/archive.json'))
print('  exported_at_height:', a['exported_at_height'])
print('  from:', a['from'], ' count:', a['count'])
print('  genesis_hash:', a['genesis_hash'][:16], '...')
rec = a['headers'][0]
print('  headers[0].index:', rec['index'])
print('  headers[0].verified_committee_sigs:', rec['verified_committee_sigs'])
print('  headers[0].header_json.block_hash:', rec['header_json'].get('block_hash','')[:16], '...')
"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_export_headers"; exit 0
else
  echo "  FAIL: test_light_export_headers"; exit 1
fi
