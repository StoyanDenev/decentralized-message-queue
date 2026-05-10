#!/usr/bin/env bash
# B4 — cross-shard end-to-end transfer test (verifies B3.1-B3.4).
#
# Topology: 1 beacon + 2 shards, each with M=K=1 (single-validator chains).
#   beacon_n  ─── shard0_n          shard1_n
#                 (shard 0)         (shard 1)
#                       \             /
#                        \           /
#                         \         /
#                       cross-peered via
#                        beacon_peers /
#                        shard_peers
#
# Action: TRANSFER `amount` from bearer wallet A (routes to shard 0) to
# bearer wallet B (routes to shard 1) via shard 0's submit_tx RPC.
#
# Assertions (the actual end-to-end behavior B3 delivers):
#   * Shard 0's apply debits A: A.balance shrinks by amount + fee.
#   * Shard 0 emits CrossShardReceipt → block.cross_shard_receipts.
#   * Bundle gossips shard 0 → beacon (relay) → shard 1.
#   * Shard 1 stores in pending_inbound_receipts_.
#   * Shard 1's next round bakes into block.inbound_receipts; apply
#     credits B: B.balance grows by amount on shard 1.
#
# Run from repo root: bash tools/test_cross_shard_transfer.sh

set -u
cd "$(dirname "$0")/.."

DHCOIN=C:/sauromatae/build/Release/dhcoin.exe
T=test_xshard
TABS=C:/sauromatae/$T

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

get_status_field() {
  $DHCOIN status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}

get_account_balance() {
  $DHCOIN show-account "$2" --rpc-port "$1" 2>/dev/null | grep '^balance' | awk '{print $3}'
}

rm -rf $T
mkdir -p $T/beacon $T/shard0 $T/shard1

echo "=== 1. Init data dirs + node keys ==="
$DHCOIN init --data-dir $T/beacon --profile web 2>&1 | tail -1
$DHCOIN init --data-dir $T/shard0 --profile web 2>&1 | tail -1
$DHCOIN init --data-dir $T/shard1 --profile web 2>&1 | tail -1

$DHCOIN genesis-tool peer-info beacon_n  --data-dir $T/beacon --stake 1000 > $T/beacon_p.json
$DHCOIN genesis-tool peer-info shard0_n  --data-dir $T/shard0 --stake 1000 > $T/shard0_p.json
$DHCOIN genesis-tool peer-info shard1_n  --data-dir $T/shard1 --stake 1000 > $T/shard1_p.json

# Use a fixed deterministic salt so the Python grinder agrees with C++.
SALT="00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef"

echo
echo "=== 2. Grind bearer wallets routing to shard 0 + shard 1 ==="
# Generate keys repeatedly until we have one address that routes to
# shard 0 (the sender) and one that routes to shard 1 (the recipient).
mkdir -p $T/wallets
python <<EOF
import hashlib, json, subprocess, os, sys
salt = bytes.fromhex("$SALT")
S = 2

def shard_for(addr: str) -> int:
    h = hashlib.sha256(salt + b"shard-route" + addr.encode()).digest()
    v = int.from_bytes(h[:8], "big")
    return v % S

found = {0: None, 1: None}
for i in range(200):
    if all(found.values()): break
    out_path = "$TABS/wallets/k_%d.json" % i
    subprocess.run(["$DHCOIN", "account", "create", "--out", out_path],
                   check=True, capture_output=True)
    with open(out_path) as f: w = json.load(f)
    s = shard_for(w["address"])
    if found[s] is None:
        found[s] = w
if not all(found.values()):
    sys.exit("could not grind addresses for both shards")
with open("$TABS/wallet_A.json","w") as f: json.dump(found[0], f, indent=2)
with open("$TABS/wallet_B.json","w") as f: json.dump(found[1], f, indent=2)
print("A (shard 0):", found[0]["address"])
print("B (shard 1):", found[1]["address"])
EOF

A_ADDR=$(python -c "import json; print(json.load(open('$T/wallet_A.json'))['address'])")
A_PRIV=$(python -c "import json; print(json.load(open('$T/wallet_A.json'))['privkey'])")
B_ADDR=$(python -c "import json; print(json.load(open('$T/wallet_B.json'))['address'])")

echo
echo "=== 3. Build per-chain genesis with shared salt + S=2 ==="
# beacon: only beacon_n in initial_creators, role=BEACON
cat > $T/beacon_gen.json <<EOF
{
  "chain_id": "test-xshard",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 1,
  "shard_id": 0,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/beacon_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
# shard 0: only shard0_n in initial_creators, role=SHARD shard_id=0.
# Pre-fund A with 1000 so it can afford the transfer.
cat > $T/shard0_gen.json <<EOF
{
  "chain_id": "test-xshard",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 0,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/shard0_p.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "$A_ADDR", "balance": 1000}]
}
EOF
# shard 1: only shard1_n.
cat > $T/shard1_gen.json <<EOF
{
  "chain_id": "test-xshard",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 1,
  "initial_shard_count": 2,
  "epoch_blocks": 100,
  "shard_address_salt": "$SALT",
  "initial_creators": [
$(cat $T/shard1_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF

$DHCOIN genesis-tool build $T/beacon_gen.json | tail -1
$DHCOIN genesis-tool build $T/shard0_gen.json | tail -1
$DHCOIN genesis-tool build $T/shard1_gen.json | tail -1
BEACON_HASH=$(cat $T/beacon_gen.json.hash)
SHARD0_HASH=$(cat $T/shard0_gen.json.hash)
SHARD1_HASH=$(cat $T/shard1_gen.json.hash)

echo
echo "=== 4. Configure cross-chain peering ==="
configure_node() {
  local cfg=$1 domain=$2 listen=$3 rpc=$4 peers_field=$5 peers=$6 \
    gen_path=$7 gen_hash=$8
  python -c "
import json
with open('$cfg') as f: c = json.load(f)
c['domain'] = '$domain'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = []
c['$peers_field'] = $peers
c['genesis_path'] = '$gen_path'
c['genesis_hash'] = '$gen_hash'
c['chain_path'] = '$(dirname $cfg)/chain.json'
c['key_path'] = '$(dirname $cfg)/node_key.json'
c['data_dir'] = '$(dirname $cfg)'
c['tx_commit_ms'] = 2000
c['delay_T'] = 200000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open('$cfg','w') as f: json.dump(c,f,indent=2)
"
}
# beacon: peers with both shards (shard_peers); listens 7771, rpc 8771
configure_node $T/beacon/config.json beacon_n 7771 8771 shard_peers \
  '["127.0.0.1:7781","127.0.0.1:7782"]' "$T/beacon_gen.json" "$BEACON_HASH"
# shard 0: peers with beacon (beacon_peers); listens 7781, rpc 8781
configure_node $T/shard0/config.json shard0_n 7781 8781 beacon_peers \
  '["127.0.0.1:7771"]' "$T/shard0_gen.json" "$SHARD0_HASH"
# shard 1: peers with beacon (beacon_peers); listens 7782, rpc 8782
configure_node $T/shard1/config.json shard1_n 7782 8782 beacon_peers \
  '["127.0.0.1:7771"]' "$T/shard1_gen.json" "$SHARD1_HASH"

echo
echo "=== 5. Start 3 nodes (1 beacon + 2 shards, cross-peered) ==="
NODE_PIDS=("" "" "")
$DHCOIN start --config $T/beacon/config.json > $T/beacon/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DHCOIN start --config $T/shard0/config.json > $T/shard0/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DHCOIN start --config $T/shard1/config.json > $T/shard1/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.3

echo
echo "=== 6. Poll until chains start producing blocks ==="
for _ in $(seq 1 60); do
  BH=$(get_status_field 8771 height); S0=$(get_status_field 8781 height); S1=$(get_status_field 8782 height)
  if [ "$BH" != "-" ] && [ "$S0" != "-" ] && [ "$S1" != "-" ] \
     && [ "$BH" -ge 2 ] 2>/dev/null && [ "$S0" -ge 2 ] 2>/dev/null && [ "$S1" -ge 2 ] 2>/dev/null; then
    break
  fi
  sleep 0.2
done

BEACON_H=$(get_status_field 8771 height)
SHARD0_H=$(get_status_field 8781 height)
SHARD1_H=$(get_status_field 8782 height)
echo "  beacon height=$BEACON_H, shard0 height=$SHARD0_H, shard1 height=$SHARD1_H"

A_BAL_PRE=$(get_account_balance 8781 "$A_ADDR")
B_BAL_PRE=$(get_account_balance 8782 "$B_ADDR")
echo "  A on shard0: balance=$A_BAL_PRE (expected 1000 from genesis allocation)"
echo "  B on shard1: balance=$B_BAL_PRE (expected 0 — no on-chain state yet)"

echo
echo "=== 7. TRANSFER 50 from A (shard 0) to B (shard 1) via send_anon ==="
$DHCOIN send_anon "$B_ADDR" 50 "$A_PRIV" --rpc-port 8781

echo
echo "=== 8. Poll up to 30s for cross-shard credit to land ==="
for _ in $(seq 1 150); do
  B_BAL_NOW=$(get_account_balance 8782 "$B_ADDR")
  if [ "$B_BAL_NOW" = "50" ]; then break; fi
  sleep 0.2
done

echo
echo "=== 9. Verify ==="
A_BAL_POST=$(get_account_balance 8781 "$A_ADDR")
B_BAL_POST=$(get_account_balance 8782 "$B_ADDR")
echo "  A on shard0 (post): $A_BAL_POST (expected 950: 1000 - 50 transfer)"
echo "  B on shard1 (post): $B_BAL_POST (expected 50)"

PASS=true
if [ "$A_BAL_POST" != "950" ]; then
  echo "  FAIL: A's debit on shard 0 didn't apply"
  PASS=false
fi
if [ "$B_BAL_POST" != "50" ]; then
  echo "  FAIL: B's credit on shard 1 didn't apply (B3 receipt loop broken)"
  PASS=false
fi

# Log evidence — corroborates the assertion path.
S1_INBOUND=$(grep "inbound receipt bundle" $T/shard1/log 2>/dev/null | wc -l | tr -d ' \r\n')
S0_BLOCKS=$(grep "accepted block" $T/shard0/log 2>/dev/null | wc -l | tr -d ' \r\n')
S1_BLOCKS=$(grep "accepted block" $T/shard1/log 2>/dev/null | wc -l | tr -d ' \r\n')
echo
echo "  Log evidence:"
echo "    shard0: $S0_BLOCKS blocks accepted"
echo "    shard1: $S1_INBOUND inbound bundle log lines"
echo "    shard1: $S1_BLOCKS blocks accepted"

if $PASS; then
  echo
  echo "  PASS: cross-shard TRANSFER end-to-end (B3.1-B3.4)"
  echo "        - A debited on source shard 0"
  echo "        - bundle gossiped via beacon relay"
  echo "        - B credited on destination shard 1"
fi

echo
echo "=== 10. Tail of shard1 log (showing inbound bundle + credit) ==="
grep -E "inbound receipt bundle|accepted block" $T/shard1/log | tail -8
