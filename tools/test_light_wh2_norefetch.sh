#!/usr/bin/env bash
# WH-2 (WaitHoldAndWaitSoundness) — the light client's `--wait` NO-RE-FETCH /
# NO-RACE neutrality, the LAST open register HIGH (ProofClaimGateTraceability).
#
# WH-2: read_account_trustless captures the `state_proof` for the anchor EXACTLY
# ONCE, before the `--wait` loop is entered; the loop (in committee_bound_state_
# root) re-polls ONLY the successor `headers`, never the proof. So a daemon that
# advances its state DURING the wait window cannot swap the bound root — the
# proof the verdict rests on was frozen before the loop began. The register asks
# this be proven by an EXECUTED MUTANT, not inspection.
#
# This gate proves it with a MOVING DAEMON: tools/rpc_tamper_proxy.py serves the
# HONEST `state_proof` on call #1 but FLIPS its `state_root` on call #2+
# (`--serve-first 1 --all`), and WITHHOLDS the successor-header poll K times
# (`--withhold-successor K`) so the client's `--wait` loop is forced to iterate.
# Against this daemon the CLEAN client is IMMUNE: it fetches the proof once, so
# the armed flip never fires, and it binds the honest root. Directly observable
# from the proxy's request log:
#   (a) it SUCCEEDS (verified, exit 0) despite the armed flip;
#   (b) it issues EXACTLY ONE `state_proof` request (fetch-once);
#   (c) its `--wait` loop iterated (successor withheld >=K times => it re-polled
#       ONLY headers); and
#   (d) the armed proof-flip NEVER fired (no 2nd state_proof to tamper).
#
# The EXECUTED MUTANT that closes WH-2 (run out-of-band, reverted) is a caller-
# side re-fetch of `state_proof` in read_account_trustless just before the held
# compare (light/trustless_read.cpp): the re-fetch is state_proof call #2 => the
# moving daemon flips it => proof_root != the committee-attested root => the
# client throws "SECURITY ... does NOT match proof.state_root" and exits 1. The
# clean/mutant differential (immune vs. caught) is the executed-mutant proof; see
# ProofClaimGateTraceability.md §3h.
#
# Cluster-bound; NOT part of FAST=1 (needs a bindable local node); self-skips if
# the node can't bootstrap.
#
# Run from repo root: bash tools/test_light_wh2_norefetch.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"; exit 0; fi
if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found (need the full node)"; exit 0; fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3
PROXY=tools/rpc_tamper_proxy.py

T=test_light_wh2
TABS=$PROJECT_ROOT/$T
NODE_RPC=8936
NODE_LISTEN=7936

declare -a NODE_PIDS
PROXY_PID=""
cleanup() {
  set +e
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  [ -n "$PROXY_PID" ] && kill -9 "$PROXY_PID" 2>/dev/null
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
  return 0
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/node

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
get_status_field() {
  $DETERM status --rpc-port "$1" 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}
verified_of() {
  echo "$1" | tail -1 | $PY -c "import json,sys
try: print('true' if json.loads(sys.stdin.read()).get('verified',False) else 'false')
except Exception: print('false')"
}

# Run balance-trustless --wait through a proxy on $1 (extra proxy args follow).
# Fills VIA_OUT / VIA_RC / VIA_LOG (the proxy request log).
VIA_OUT=""; VIA_RC=""; VIA_LOG=""
via_proxy() {
  local lport=$1; shift
  local plog=$T/proxy_$lport.log
  VIA_LOG=$T/reqlog_$lport.log
  set +e
  "$PY" "$PROXY" --listen "$lport" --upstream "$NODE_RPC" --log "$VIA_LOG" "$@" \
      > "$plog" 2>&1 &
  PROXY_PID=$!
  local ready=0
  for _ in $(seq 1 50); do
    grep -q "PROXY-READY" "$plog" 2>/dev/null && { ready=1; break; }; sleep 0.1
  done
  if [ "$ready" != "1" ]; then VIA_OUT="(proxy failed to start)"; VIA_RC=99
  else
    VIA_OUT=$($DETERM_LIGHT balance-trustless --rpc-port "$lport" \
                --genesis $T/node_gen.json --domain alice --wait 25 --json 2>&1)
    VIA_RC=$?
  fi
  kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null; PROXY_PID=""
  set +e   # this script never runs under errexit (grep -c on 0 matches exits 1)
}

# ── single-creator node with a funded `alice` account (the a: leaf to read) ──
$DETERM init --data-dir $T/node --profile regional_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node_n --data-dir $T/node --stake 1000 > $T/node_p.json
cat > $T/node_gen.json <<EOF
{
  "chain_id": "test-light-wh2",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/node_p.json | tr -d '\n')
  ],
  "initial_balances": [ {"domain": "alice", "balance": 500} ]
}
EOF
$DETERM genesis-tool build $T/node_gen.json | tail -1
NODE_HASH=$(cat $T/node_gen.json.hash)

$PY -c "
import json
cfg = '$T/node/config.json'
with open(cfg) as f: c = json.load(f)
c['domain']='node_n'; c['listen_port']=$NODE_LISTEN; c['rpc_port']=$NODE_RPC
c['bootstrap_peers']=[]; c['genesis_path']='$TABS/node_gen.json'
c['genesis_hash']='$NODE_HASH'; c['chain_path']='$TABS/node/chain.json'
c['key_path']='$TABS/node/node_key.json'; c['data_dir']='$TABS/node'
c['tx_commit_ms']=2000; c['block_sig_ms']=2000; c['abort_claim_ms']=1000
with open(cfg,'w') as f: json.dump(c,f,indent=2)
"

NODE_PIDS=("")
$DETERM start --config $T/node/config.json > $T/node/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
for _ in $(seq 1 90); do
  H=$(get_status_field $NODE_RPC height)
  [ "$H" != "-" ] && [ "$H" -ge 5 ] 2>/dev/null && break; sleep 0.3
done
NODE_H=$(get_status_field $NODE_RPC height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 5 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap (not a WH-2 defect)"
  echo "  PASS: test_light_wh2_norefetch (skipped)"; exit 0
fi

# ── CONTROL: honest read through a PASS-THROUGH proxy → verified ─────────────
via_proxy 8937
if [ "$VIA_RC" = "0" ] && [ "$(verified_of "$VIA_OUT")" = "true" ]; then
  assert "true" "CONTROL: honest balance read via pass-through proxy → verified, exit 0"
else
  assert "false" "CONTROL: pass-through → verified/exit0 (rc=$VIA_RC) — cannot gate WH-2 without a live control"
fi

# ── WH-2: MOVING DAEMON (state_proof honest #1, flip state_root #2+) + withhold
# the successor poll twice (forces the --wait loop to iterate). The CLEAN client
# must be IMMUNE: fetch-once means the armed flip never fires. ────────────────
via_proxy 8938 --method state_proof --match namespace=a,key=alice \
    --field state_root --mode flip-hex --serve-first 1 --all --withhold-successor 2
echo "--- moving-daemon run ---"; echo "$VIA_OUT" | tail -1
SP_COUNT=$(grep -c 'REQ state_proof' "$VIA_LOG" 2>/dev/null || true); SP_COUNT=${SP_COUNT:-0}
WH_COUNT=$(grep -c 'WITHHOLD headers' "$VIA_LOG" 2>/dev/null || true); WH_COUNT=${WH_COUNT:-0}
TAMP_COUNT=$(grep -c '^TAMPER' "$VIA_LOG" 2>/dev/null || true); TAMP_COUNT=${TAMP_COUNT:-0}
echo "  proxy log: state_proof reqs=$SP_COUNT  successor-withholds=$WH_COUNT  tampers-fired=$TAMP_COUNT"

if [ "$VIA_RC" = "0" ] && [ "$(verified_of "$VIA_OUT")" = "true" ]; then
  assert "true" "WH-2(a): the CLEAN client is IMMUNE to the mid-wait proof-flip (verified, exit 0)"
else
  assert "false" "WH-2(a): clean client → verified/exit0 (rc=$VIA_RC)"
fi
[ "$SP_COUNT" = "1" ] \
  && assert "true" "WH-2(b): the state_proof is fetched EXACTLY ONCE (fetch-once)" \
  || assert "false" "WH-2(b): exactly one state_proof request (got $SP_COUNT)"
[ "$WH_COUNT" -ge 2 ] 2>/dev/null \
  && assert "true" "WH-2(c): the --wait loop ITERATED (successor withheld ${WH_COUNT}x => it re-polled ONLY headers)" \
  || assert "false" "WH-2(c): --wait loop iterated (successor withheld $WH_COUNT, need >=2)"
[ "$TAMP_COUNT" = "0" ] \
  && assert "true" "WH-2(d): the armed proof-flip NEVER fired (no 2nd state_proof to tamper)" \
  || assert "false" "WH-2(d): 0 tampers fired on the clean run (got $TAMP_COUNT)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_wh2_norefetch"; exit 0
else
  echo "  FAIL: test_light_wh2_norefetch"; exit 1
fi
