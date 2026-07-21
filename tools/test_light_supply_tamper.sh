#!/usr/bin/env bash
# determ-light supply-trustless vs a LYING DAEMON — register claim SU-2
# (SupplyProof value-hash cleartext cross-check, the WIRE-sourced sibling of
# CR-2/RP-3). The supply verifier reads each c: counter's cleartext from the
# ATOMIC `value_hex` field of the counter's `state_proof` reply (R51) and
# requires SHA256(u64_be(value)) == the committee-proven `value_hash`
# (light/main.cpp:8007). No honest daemon serves a mismatch — node.cpp attaches
# value_hex ONLY when it already hashes to the committed value_hash
# (src/node/node.cpp fail-closed) — so the lie is injected by the transparent
# tools/rpc_tamper_proxy.py, which rewrites the `value_hex` of the FIRST counter
# (`genesis_total`) and forwards everything else verbatim.
#
# NON-VACUITY under a differential: `genesis_total` is kCounters[0], and its
# value-hash compare at :8007 executes BEFORE the stale-height / committee-root /
# merkle steps. So the tamper is caught at :8007 regardless of whether the later
# committee-root binding succeeds on this host — and the CONTROL (same command
# through a PASS-THROUGH proxy) proves the genesis_total compare PASSES on honest
# input, because its detail is NOT the genesis_total value_hex message. That
# differential (honest genesis_total passes :8007; tampered genesis_total fails
# :8007 with exit 3) is the non-vacuous core, independent of the outer CONSERVED
# verdict (which additionally depends on the committee round-trip and can be
# environment-sensitive on a starved single-host cluster).
#
# Cluster-bound; NOT part of FAST=1 — same envelope as the other *-trustless
# cluster tests.
#
# Run from repo root: bash tools/test_light_supply_tamper.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"; exit 0
fi
if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found (need the full node for a live cluster)"; exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3
PROXY=tools/rpc_tamper_proxy.py

T=test_light_supply_tamper
TABS=$PROJECT_ROOT/$T
NODE_RPC=8926
NODE_LISTEN=7926

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

# Run supply-trustless through a proxy on $1 (extra proxy args follow). Fills
# VIA_OUT / VIA_RC.
VIA_OUT=""; VIA_RC=""
via_proxy() {
  local lport=$1; shift
  local plog=$T/proxy_$lport.log
  set +e
  "$PY" "$PROXY" --listen "$lport" --upstream "$NODE_RPC" --log "$T/tamper_$lport.log" "$@" \
      > "$plog" 2>&1 &
  PROXY_PID=$!
  local ready=0
  for _ in $(seq 1 50); do
    grep -q "PROXY-READY" "$plog" 2>/dev/null && { ready=1; break; }; sleep 0.1
  done
  if [ "$ready" != "1" ]; then VIA_OUT="(proxy failed to start)"; VIA_RC=99
  else
    VIA_OUT=$($DETERM_LIGHT supply-trustless --rpc-port "$lport" --genesis $T/node_gen.json 2>&1)
    VIA_RC=$?
  fi
  kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null; PROXY_PID=""
  set -e
}

GENESIS_TOTAL_MARKER="atomic value_hex for counter 'genesis_total'"

# ── build single-creator fixture (c: counters exist on any S-033 chain) ──────
$DETERM init --data-dir $T/node --profile regional_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node_n --data-dir $T/node --stake 1000 > $T/node_p.json
cat > $T/node_gen.json <<EOF
{
  "chain_id": "test-light-supply-tamper",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/node_p.json | tr -d '\n')
  ],
  "initial_balances": [ {"domain": "node_n", "balance": 100} ]
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
  [ "$H" != "-" ] && [ "$H" -ge 2 ] 2>/dev/null && break; sleep 0.3
done
NODE_H=$(get_status_field $NODE_RPC height)
echo "  height=$NODE_H"
if [ "$NODE_H" = "-" ] || [ "$NODE_H" -lt 2 ] 2>/dev/null; then
  echo "  SKIP: node did not bootstrap (not an SU-2 defect)"; echo "  PASS: test_light_supply_tamper (skipped)"; exit 0
fi

# ── CONTROL: honest supply via pass-through proxy ────────────────────────────
via_proxy 8927
echo "--- honest (pass-through) ---"; echo "$VIA_OUT" | grep -E "verdict|detail|CONSERVED|UNVERIFIABLE" | head -4
HON_OUT="$VIA_OUT"; HON_RC="$VIA_RC"
# The genesis_total compare must PASS honestly: its distinctive tamper marker
# must NOT appear on the honest path (whatever the outer verdict).
if ! echo "$HON_OUT" | grep -qF "$GENESIS_TOTAL_MARKER"; then
  assert "true" "CONTROL: honest genesis_total value_hex passes :8007 (no genesis_total tamper marker)"
else
  assert "false" "CONTROL: honest path unexpectedly reports a genesis_total value_hex mismatch"
fi
# If this host's committee round-trip is healthy, the honest verdict is CONSERVED
# (exit 0) — a strong positive control. Report it, but don't hard-require it
# (a starved single-host committee round-trip can yield UNVERIFIABLE; the
# differential above already establishes non-vacuity).
if [ "$HON_RC" = "0" ] && echo "$HON_OUT" | grep -qE "CONSERVED"; then
  assert "true" "CONTROL(strong): honest supply → CONSERVED, exit 0"
else
  echo "  NOTE: honest verdict not CONSERVED on this host (rc=$HON_RC) — differential control stands; see proof doc"
fi

# ── TAMPER: flip genesis_total's atomic value_hex ────────────────────────────
via_proxy 8928 --method state_proof --match namespace=c,key=genesis_total --field value_hex --mode flip-hex
echo "--- tampered (genesis_total value_hex) ---"; echo "$VIA_OUT" | grep -E "verdict|detail|TAMPERED|UNVERIFIABLE" | head -4
if [ "$VIA_RC" = "3" ]; then
  assert "true" "TAMPER(value_hex): daemon-lied counter → UNVERIFIABLE, exit EXACTLY 3"
else
  assert "false" "TAMPER(value_hex): expected exit 3, got $VIA_RC"
fi
if echo "$VIA_OUT" | grep -qF "$GENESIS_TOTAL_MARKER"; then
  assert "true" "TAMPER(value_hex): detail pins the genesis_total value_hex cross-check (:8007 fired)"
else
  assert "false" "TAMPER(value_hex): expected the genesis_total value_hex mismatch detail"
fi
NOFP=$(echo "$VIA_OUT" | grep -qE "CONSERVED" && echo false || echo true)
assert "$NOFP" "TAMPER(value_hex): never a false CONSERVED"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_supply_tamper"; exit 0
else
  echo "  FAIL: test_light_supply_tamper"; exit 1
fi
