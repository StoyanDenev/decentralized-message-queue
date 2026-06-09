#!/usr/bin/env bash
# determ-light state-proof bundle — OFFLINE state-side analog of verify-archive.
#
# A state-proof bundle proves "account/key K in namespace NS had value V at
# height H" to a third party who re-verifies it with NO daemon contact. It
# carries the FULL anchor block (whose state_root is the proof root), the
# committee-signed SUCCESSOR header (whose digest binds prev_hash =
# block_hash(anchor)), and the Merkle state-proof. The verifier recomputes
# compute_hash(anchor) and requires it == successor.prev_hash — the load-bearing
# binding that transitively commits the anchor's state_root (which is NOT in the
# committee-signed digest, only in signing_bytes -> block_hash). See
# light/verify_state_bundle.cpp + trustless_read.cpp::committee_bound_state_root.
#
# HONEST about what runs vs SKIPs on this Windows box:
#   * OFFLINE envelope/error legs (no cluster, no genesis-hash edge): ALWAYS run.
#       - help lists both subcommands
#       - missing/garbage --in -> clean UNVERIFIABLE / IO error (no crash)
#       - wrong-schema bundle -> UNVERIFIABLE exit 3
#   * NEGATIVE binding legs (need a real committee-signed bundle as the base):
#       - run ONLY if a live cluster comes up here AND export succeeds; they
#         tamper anchor_block.state_root (breaks the successor.prev_hash binding)
#         and successor_header.prev_hash, asserting UNVERIFIABLE in both cases.
#       - if the cluster does not come up on this box (the common Windows case),
#         these SKIP gracefully with a clear message (NOT a faked pass).
#   * POSITIVE export->verify round-trip: a CI/WSL2 cluster leg. Runs when the
#     cluster is up; otherwise SKIPs gracefully.
#
# Run from repo root: bash tools/test_light_state_bundle.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_state_bundle
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS

cluster_running=0
stop_cluster() {
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

pass_count=0; fail_count=0; skip_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
skip() { echo "  SKIP: $1"; skip_count=$((skip_count + 1)); }

# ── OFFLINE LEG 1: help lists both subcommands ──────────────────────────────
echo "=== 1. help lists export-state-bundle + verify-state-bundle ==="
HELP=$($DETERM_LIGHT help 2>&1)
echo "$HELP" | grep -qE "export-state-bundle" && A=true || A=false
assert "$A" "help lists export-state-bundle"
echo "$HELP" | grep -qE "verify-state-bundle" && A=true || A=false
assert "$A" "help lists verify-state-bundle"

# ── OFFLINE LEG 2: missing / garbage --in is handled cleanly (no crash) ─────
echo
echo "=== 2. verify-state-bundle on missing / garbage --in ==="
set +e
OUT=$($DETERM_LIGHT verify-state-bundle --in $T/does_not_exist.json \
        --genesis $T/does_not_exist_gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
# Missing --in is an IO error -> exit 1 (clean diagnostic, not a crash/exit 2+).
if [ "$RC" = "1" ]; then
    assert "true" "missing --in -> clean IO error (exit 1)"
else
    assert "false" "missing --in should exit 1 (got $RC)"
fi

# Garbage (non-JSON) --in -> UNVERIFIABLE exit 3, no crash.
echo 'this is not json {{{[[[' > $T/garbage.json
set +e
OUT=$($DETERM_LIGHT verify-state-bundle --in $T/garbage.json \
        --genesis $T/garbage.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "UNVERIFIABLE"; then
    assert "true" "garbage --in -> UNVERIFIABLE exit 3 (no crash)"
else
    assert "false" "garbage --in should be UNVERIFIABLE exit 3 (got $RC)"
fi

# Wrong-schema (valid JSON, wrong/absent schema string) -> UNVERIFIABLE exit 3.
echo '{"schema":"some-other-thing/9","genesis_hash":"00"}' > $T/wrongschema.json
set +e
OUT=$($DETERM_LIGHT verify-state-bundle --in $T/wrongschema.json \
        --genesis $T/wrongschema.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "schema"; then
    assert "true" "wrong-schema bundle -> UNVERIFIABLE exit 3, names schema"
else
    assert "false" "wrong-schema should be UNVERIFIABLE exit 3 (got $RC)"
fi

# ── OFFLINE LEG 2b: KEY-BINDING — the displayed (ns,key) must encode to the
#    proof's key_bytes. This is the regression catch for the unbound-displayed-key
#    forge (an honest bundle for "bob" re-labelled "alice"): the structural key
#    check is the FIRST gate in verify_state_bundle (before the crypto gates), so
#    it is fully testable offline here without a real committee-signed bundle. ─
echo
echo "=== 2b. KEY-BINDING: state_proof.key_bytes must encode the displayed ns/key ==="
GH64=$(printf 'a%.0s' $(seq 1 64))
# key_bytes 613a626f62 = "a:bob"; displayed key = "alice" -> MUST be refused.
cat > $T/keybind_mismatch.json <<JSON
{"schema":"determ-light-state-bundle/1","genesis_hash":"$GH64","namespace":"a","key":"alice",
 "anchor_index":1,"anchor_block":{"index":1},"successor_header":{"index":2},
 "state_proof":{"key_bytes":"613a626f62","state_root":"ab","value_hash":"cd","proof":[],"target_index":0,"leaf_count":1}}
JSON
set +e
OUT=$($DETERM_LIGHT verify-state-bundle --in $T/keybind_mismatch.json \
        --genesis $T/nonexistent_gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
# Must reject at the key-binding gate (exit 3) with the key_bytes diagnostic —
# BEFORE the genesis-load gate (so a nonexistent --genesis is irrelevant here).
if [ "$RC" = "3" ] && echo "$OUT" | grep -qiE "key_bytes.*does not encode|DIFFERENT leaf"; then
    assert "true" "key_bytes != displayed (ns,key) -> UNVERIFIABLE exit 3 (S-042-class forge refused)"
else
    assert "false" "key-binding mismatch should be UNVERIFIABLE exit 3 with key_bytes diagnostic (got $RC)"
fi
# Control: a MATCHING key_bytes ("a:alice" = 613a616c696365) must PASS the
# key-binding gate and fall through to a LATER gate (here: genesis load) — i.e.
# the gate is live (rejects mismatch) but not a tautology (accepts a match).
cat > $T/keybind_match.json <<JSON
{"schema":"determ-light-state-bundle/1","genesis_hash":"$GH64","namespace":"a","key":"alice",
 "anchor_index":1,"anchor_block":{"index":1},"successor_header":{"index":2},
 "state_proof":{"key_bytes":"613a616c696365","state_root":"ab","value_hash":"cd","proof":[],"target_index":0,"leaf_count":1}}
JSON
set +e
OUT2=$($DETERM_LIGHT verify-state-bundle --in $T/keybind_match.json \
         --genesis $T/nonexistent_gen.json 2>&1)
set -e
if echo "$OUT2" | grep -qiE "key_bytes.*does not encode|DIFFERENT leaf"; then
    assert "false" "matching key_bytes must NOT trip the key-binding gate (it did)"
else
    assert "true" "matching key_bytes passes the key-binding gate (falls through to a later gate)"
fi

# ── CLUSTER-DEPENDENT LEGS (positive round-trip + negative binding) ─────────
echo
echo "=== 3. Attempt a 3-node cluster for the export->verify round-trip ==="
echo "    (negative binding legs need a REAL committee-signed bundle as base)"

for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test >/dev/null 2>&1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-state-bundle",
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
$DETERM genesis-tool build $T/gen.json >/dev/null 2>&1 || true

# A DIFFERENT genesis (different chain_id -> different compute_genesis_hash),
# used to confirm the chain-identity pin refuses a wrong genesis on a real
# bundle (only meaningful when a real bundle was produced).
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
  "initial_balances": [{"domain": "alice", "balance": 500}]
}
EOF
$DETERM genesis-tool build $T/gen_wrong.json >/dev/null 2>&1 || true

GHASH=$(cat $T/gen.json.hash 2>/dev/null || echo "")

cluster_ok=0
if [ -n "$GHASH" ] && [ -f "$T/n1/config.json" ]; then
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
" 2>/dev/null
  }
  configure_node 1 7901 8901 '["127.0.0.1:7902","127.0.0.1:7903"]'
  configure_node 2 7902 8902 '["127.0.0.1:7901","127.0.0.1:7903"]'
  configure_node 3 7903 8903 '["127.0.0.1:7901","127.0.0.1:7902"]'

  NODE_PIDS=("" "" "")
  $DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
  NODE_PIDS[0]=$!; sleep 0.3
  $DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
  NODE_PIDS[1]=$!; sleep 0.3
  $DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
  NODE_PIDS[2]=$!; sleep 0.5
  cluster_running=1

  H=0
  for _ in $(seq 1 60); do
    H=$($DETERM status --rpc-port 8901 2>/dev/null \
         | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
    if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
    sleep 0.5
  done
  echo "  chain height: $H"
  if [ "$H" -ge 5 ] 2>/dev/null; then cluster_ok=1; fi
fi

if [ "$cluster_ok" != "1" ]; then
  stop_cluster
  echo
  echo "  Cluster did not reach height >= 5 on this box (expected on this"
  echo "  Windows runner without a working multi-node cluster)."
  skip "POSITIVE export->verify round-trip (needs a live daemon-signed bundle) — CI/WSL2 leg"
  skip "NEGATIVE binding: tamper anchor_block.state_root (needs real base bundle) — CI/WSL2 leg"
  skip "NEGATIVE binding: tamper successor_header.prev_hash (needs real base bundle) — CI/WSL2 leg"
  skip "chain-identity pin refusal on a real bundle (needs real base bundle) — CI/WSL2 leg"
  echo
  echo "=== Test summary ==="
  echo "  $pass_count pass / $fail_count fail / $skip_count skip"
  if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_light_state_bundle (offline legs; cluster legs skipped)"; exit 0
  else
    echo "  FAIL: test_light_state_bundle"; exit 1
  fi
fi

# ── POSITIVE round-trip: export a real bundle, then verify it offline. ──────
echo
echo "=== 4. export-state-bundle (ns=a, key=alice) ==="
set +e
OUT=$($DETERM_LIGHT export-state-bundle \
        --rpc-port 8901 --genesis $T/gen.json \
        --namespace a --key alice --out $T/bundle.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ]; then
    assert "true" "export-state-bundle exits 0 (committee-bound)"
else
    assert "false" "export-state-bundle exits 0 (got $RC)"
fi

if [ ! -s "$T/bundle.json" ]; then
  stop_cluster
  echo "  export produced no bundle; the rest of the round-trip cannot run."
  skip "verify-state-bundle round-trip (export failed) — CI/WSL2 leg"
  echo
  echo "=== Test summary ==="
  echo "  $pass_count pass / $fail_count fail / $skip_count skip"
  if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_light_state_bundle (export failed; round-trip skipped)"; exit 0
  else
    echo "  FAIL: test_light_state_bundle"; exit 1
  fi
fi

# Stop the cluster: every verify below is OFFLINE.
echo
echo "=== 5. STOP cluster — all verify legs below are OFFLINE ==="
stop_cluster
echo "  cluster stopped; no daemon listening on 890x now."
set +e
PROBE=$($DETERM_LIGHT verify-chain --rpc-port 8901 --genesis $T/gen.json 2>&1)
PROBE_RC=$?
set -e
if [ "$PROBE_RC" != "0" ]; then
    assert "true" "sanity: RPC-using verify-chain FAILS with cluster down (exit $PROBE_RC)"
else
    assert "false" "sanity: verify-chain should fail with cluster down"
fi

echo
echo "=== 6. POSITIVE: verify-state-bundle (offline) -> VERIFIED exit 0 ==="
set +e
OUT=$($DETERM_LIGHT verify-state-bundle --in $T/bundle.json \
        --genesis $T/gen.json --json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "0" ] && echo "$OUT" | tail -1 | grep -qi "VERIFIED"; then
    assert "true" "verify-state-bundle VERIFIED offline (exit 0)"
else
    assert "false" "verify-state-bundle should be VERIFIED exit 0 (got $RC)"
fi
# ns=a cleartext recompute leg: JSON should carry balance + value_hash.
VALOK=$(echo "$OUT" | tail -1 | python -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    print('true' if d.get('verdict')=='VERIFIED' and 'balance' in d and 'value_hash' in d else 'false')
except Exception: print('false')
" 2>/dev/null)
assert "$VALOK" "VERIFIED JSON carries balance + value_hash (ns=a cleartext bound)"

echo
echo "=== 7. NEGATIVE binding: tamper anchor_block.state_root -> UNVERIFIABLE ==="
# Flipping the anchor's state_root changes compute_hash(anchor), which then no
# longer equals the committee-signed successor.prev_hash -> the binding breaks.
python -c "
import json
b=json.load(open('$T/bundle.json'))
sr=b['anchor_block']['state_root']
b['anchor_block']['state_root']=('f' if sr[0]!='f' else '0')+sr[1:]
json.dump(b,open('$T/bundle_sr_tamper.json','w'))
" 2>/dev/null
set +e
OUT=$($DETERM_LIGHT verify-state-bundle --in $T/bundle_sr_tamper.json \
        --genesis $T/gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "UNVERIFIABLE"; then
    assert "true" "tampered anchor state_root -> UNVERIFIABLE exit 3"
else
    assert "false" "tampered anchor state_root should be UNVERIFIABLE exit 3 (got $RC)"
fi

echo
echo "=== 8. NEGATIVE binding: tamper successor_header.prev_hash -> UNVERIFIABLE ==="
# Corrupting prev_hash makes the successor's committee sigs fail (prev_hash is
# in compute_block_digest) OR breaks the binding equality — either way refused.
python -c "
import json
b=json.load(open('$T/bundle.json'))
ph=b['successor_header']['prev_hash']
b['successor_header']['prev_hash']=('f' if ph[0]!='f' else '0')+ph[1:]
json.dump(b,open('$T/bundle_ph_tamper.json','w'))
" 2>/dev/null
set +e
OUT=$($DETERM_LIGHT verify-state-bundle --in $T/bundle_ph_tamper.json \
        --genesis $T/gen.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "UNVERIFIABLE"; then
    assert "true" "tampered successor prev_hash -> UNVERIFIABLE exit 3"
else
    assert "false" "tampered successor prev_hash should be UNVERIFIABLE exit 3 (got $RC)"
fi

echo
echo "=== 9. chain-identity pin: wrong --genesis on the real bundle -> refused ==="
set +e
OUT=$($DETERM_LIGHT verify-state-bundle --in $T/bundle.json \
        --genesis $T/gen_wrong.json 2>&1)
RC=$?
set -e
echo "$OUT"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qiE "genesis.*mismatch|mismatch|refusing"; then
    assert "true" "wrong --genesis refused (UNVERIFIABLE, names mismatch)"
else
    assert "false" "wrong --genesis should be UNVERIFIABLE exit 3 (got $RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail / $skip_count skip"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_state_bundle"; exit 0
else
  echo "  FAIL: test_light_state_bundle"; exit 1
fi
