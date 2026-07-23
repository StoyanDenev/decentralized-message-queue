#!/usr/bin/env bash
# LSP-7 (LightStatePersistenceSoundness) — BEHAVIORAL (live-node) closure of the
# G1 resume head-monotonicity gate in anchored_head (light/trustless_read.cpp).
# The behavioral complement to the STATIC source guard
# tools/test_light_resume_monotonicity_guard.sh (which only asserts the throw
# TOKEN is present in source; a functional fail-open that keeps the token but
# regresses the height comparison is invisible to grep but caught here).
#
# THE GATE (light/trustless_read.cpp:443-454, inside anchored_head):
#     uint64_t daemon_head = fetch_head_height(rpc);
#     if (daemon_head < st.head_height)   // G1: daemon regressed below the
#         throw ... "is BELOW the previously committee-verified anchor" ...;
#   The cached anchor (st) is a PREVIOUSLY committee-verified head written by
#   `verify-chain --persist` ONLY after a full genesis-to-head verify (LSP-1,
#   main.cpp:1783). A fork-free chain never regresses, so a daemon whose head is
#   BELOW the cached anchor is serving stale/truncated state (the doc's
#   "restored from an old snapshot"). Pre-LSP-7 this silently fell back to a
#   full from-genesis verify and ACCEPTED the shorter chain — the cache held the
#   proof of regression and the code ignored it.
#
# THE DISCRIMINATOR (a pure HEIGHT comparison — no sampling luck, no fork):
#   * G1-NEGATIVE leg: a committee-verified cache at height H, then a --resume
#     read against a daemon whose head < H -> HONEST throws (exit 1, stderr
#     "is BELOW ... anchor"). The FAITHFUL mutant (:443-454 replaced by
#     fall-back-to-full-verify-and-accept, the pre-LSP-7 behavior) returns
#     exit 0 and accepts the regressed chain -> the assertion flips RED.
#     NB (verified): a BARE DELETE of the G1 throw does NOT discriminate — with
#     daemon_head<H the ==(:455) branch is false, control reaches the >anchor
#     resume branch (:509) whose own head fetch sees head<=anchor and re-throws
#     the G3 error at :526. So the honest side asserts BOTH exit==1 AND the
#     G1-specific "is BELOW ... anchor" token, never a bare exit!=0.
#   * POSITIVE CONTROL (non-vacuity): a --resume read against a daemon
#     legitimately AHEAD of the cache -> exit 0 (the >anchor resume branch
#     accepts an honestly-advancing daemon). Proves the gate is not always-reject.
#
# The below-anchor daemon is produced HONESTLY (no rpc_tamper_proxy, no file
# forgery): a FRESH data-dir seeded with node1's node_key.json + the SAME
# genesis rebuilds a short chain from height 0, self-signed and committee-VALID
# (load-bearing: if it were signed by a different key the mutant's full-verify
# would fail on sigs and both sides would throw, collapsing the discriminator).
#
# Single identity, M=K=1. Windows-standalone (needs live daemons); NOT in FAST /
# ci_local. Run from repo root: bash tools/test_light_resume_regression_live.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

T=test_light_resume_regression_live
TABS=$PROJECT_ROOT/$T
H_TARGET=6

declare -a NODE_PIDS
cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/A $T/B

pass_count=0; fail_count=0; skip_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
skip() { echo "  SKIP: $1"; skip_count=$((skip_count + 1)); }
summary_exit() {
  echo
  echo "=== Test summary ==="
  echo "  $pass_count pass / $fail_count fail / $skip_count skip"
  if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_light_resume_regression_live${1:+ ($1)}"; exit 0
  else
    echo "  FAIL: test_light_resume_regression_live"; exit 1
  fi
}
node_height() {  # node_height <rpc-port> -> integer height or "x"
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height','x'))
except: print('x')" 2>/dev/null
}

echo "=== 1. Genesis M=1/K=1 (single creator node1) ==="
$DETERM init --data-dir $T/A --profile single_test 2>&1 | tail -1
$DETERM init --data-dir $T/B --profile single_test >/dev/null 2>&1
$DETERM genesis-tool peer-info node1 --data-dir $T/A --stake 1000 > $T/p1.json
cat > $T/gen.json <<EOF
{
  "chain_id": "test-lsp7-resume",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "node1", "balance": 100}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

# Seed B with node1's identity so its rebuilt-from-0 chain is committee-VALID.
cp $T/A/node_key.json $T/B/node_key.json

# Node A: fast timers (build up to the anchor quickly). Port 8873.
python -c "
import json
with open('$T/A/config.json') as f: c = json.load(f)
c['domain']='node1'; c['listen_port']=7873; c['rpc_port']=8873
c['bootstrap_peers']=[]
c['genesis_path']='$TABS/gen.json'; c['genesis_hash']='$GHASH'
c['chain_path']='$TABS/A/chain.json'; c['key_path']='$TABS/A/node_key.json'
c['data_dir']='$TABS/A'
c['tx_commit_ms']=500; c['block_sig_ms']=500; c['abort_claim_ms']=250
with open('$T/A/config.json','w') as f: json.dump(c,f,indent=2)
"
# Node B: SLOW timers so the fresh chain lingers BELOW the anchor for a wide
# window (the reset-daemon "old snapshot"). Port 8874, partitioned.
python -c "
import json
with open('$T/B/config.json') as f: c = json.load(f)
c['domain']='node1'; c['listen_port']=7874; c['rpc_port']=8874
c['bootstrap_peers']=[]
c['genesis_path']='$TABS/gen.json'; c['genesis_hash']='$GHASH'
c['chain_path']='$TABS/B/chain.json'; c['key_path']='$TABS/B/node_key.json'
c['data_dir']='$TABS/B'
c['tx_commit_ms']=6000; c['block_sig_ms']=6000; c['abort_claim_ms']=3000
with open('$T/B/config.json','w') as f: json.dump(c,f,indent=2)
"

echo
echo "=== 2. Start node A (fast), build up to the anchor height >= $H_TARGET ==="
$DETERM start --config $T/A/config.json > $T/A/log 2>&1 &
NODE_PIDS[0]=$!
HA=0
for _ in $(seq 1 60); do
  HA=$(node_height 8873)
  if [ "$HA" != "x" ] && [ -n "$HA" ] && [ "$HA" -ge "$H_TARGET" ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  node A height: $HA"
if [ "$HA" = "x" ] || [ -z "$HA" ] || ! [ "$HA" -ge "$H_TARGET" ] 2>/dev/null; then
  skip "node A did not reach anchor height $H_TARGET (env; single-node mint unavailable)"
  summary_exit "daemon unavailable"
fi

echo
echo "=== 3. WRITE the committee-verified anchor (verify-chain --persist) ==="
set +e
OUT=$($DETERM_LIGHT verify-chain --rpc-port 8873 --genesis $T/gen.json \
        --persist --state $T/cache.json 2>&1); RC=$?
set -e
echo "$OUT" | tail -3
if [ "$RC" = "0" ] && [ -s "$T/cache.json" ]; then
  assert true "verify-chain --persist wrote the committee-verified anchor (exit 0)"
else
  assert false "verify-chain --persist should write the anchor (exit $RC)"
  summary_exit
fi
CACHE_H=$(python -c "import json;print(json.load(open('$T/cache.json')).get('head_height','?'))" 2>/dev/null)
echo "  cached anchor height: $CACHE_H"

echo
echo "=== 4. POSITIVE CONTROL: resume against an AHEAD daemon -> accepted (exit 0) ==="
# Let A advance a couple blocks beyond the cached anchor, then resume.
sleep 1.5
set +e
OUT=$($DETERM_LIGHT verify-chain --rpc-port 8873 --genesis $T/gen.json \
        --resume --state $T/cache.json 2>&1); RC=$?
set -e
echo "$OUT" | grep -iE "resume|height|OK" | head -4
if [ "$RC" = "0" ]; then
  assert true "resume against an honestly-ahead daemon is accepted (non-vacuity: gate is not always-reject)"
else
  assert false "resume against an ahead daemon should be exit 0 (got $RC)"
fi

echo
echo "=== 5. Start node B (fresh chain, node1 identity, SLOW) — the below-anchor daemon ==="
$DETERM start --config $T/B/config.json > $T/B/log 2>&1 &
NODE_PIDS[1]=$!
# Wait until B answers status; it rebuilds from genesis (height 0) and lingers
# low under the slow timers. Window guard: only assert while B head < anchor.
HB="x"
for _ in $(seq 1 40); do
  HB=$(node_height 8874)
  if [ "$HB" != "x" ] && [ -n "$HB" ]; then break; fi
  sleep 0.5
done
echo "  node B height: $HB (anchor $CACHE_H)"
if [ "$HB" = "x" ] || [ -z "$HB" ]; then
  skip "node B daemon did not answer status (env)"
  summary_exit "B unavailable"
fi
if ! [ "$HB" -lt "$CACHE_H" ] 2>/dev/null; then
  skip "node B already advanced to/past the cached anchor ($HB >= $CACHE_H) — timing window missed"
  summary_exit "window missed"
fi

echo
echo "=== 6. G1-NEGATIVE (the discriminator): resume against the below-anchor daemon ==="
set +e
OUT=$($DETERM_LIGHT verify-chain --rpc-port 8874 --genesis $T/gen.json \
        --resume --state $T/cache.json 2>&1); RC=$?
set -e
echo "  rc=$RC"
echo "$OUT" | grep -iE "BELOW|SECURITY|STALE|resume" | head -3
if [ "$RC" = "1" ] && echo "$OUT" | grep -q "is BELOW the previously committee-verified anchor"; then
  assert true "G1: resume vs below-anchor daemon THROWS (exit 1, 'is BELOW ... anchor') — stale/rollback refused"
else
  assert false "G1 should be exit 1 with 'is BELOW ... anchor' (got exit $RC) — fail-open regression?"
fi

summary_exit
