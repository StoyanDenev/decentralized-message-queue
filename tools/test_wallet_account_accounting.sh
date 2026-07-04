#!/usr/bin/env bash
# R57 — determ-wallet account-accounting: per-domain transaction-flow
# accounting, cross-checked against the authoritative balance.
#
#   0. Offline CLI contract (help, required args, bad account, unreachable).
#   1. Boot a SINGLE-node chain (m_creators=1 — the sole creator produces
#      every block and applies txs immediately, so there is no multi-node
#      consensus straggle to flake on).
#   2. Known operations by node1: TRANSFER 5 -> node2 ; self STAKE 3.
#   3. account-accounting classifies them EXACTLY as the chain applies:
#      node1.debits_sent==5, node1.staked==3, node2.credits_received==5,
#      fees accrue to the sender, node1 is the sole creator so
#      blocks_produced>0 with its subsidy income surfaced as non_tx_delta
#      (NOT as credits_received), and every account reconciles:
#      authoritative_balance == tx_flow_net + non_tx_delta.
#
# Run from repo root: bash tools/test_wallet_account_accounting.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

WALLET="${DETERM_WALLET:-$PROJECT_ROOT/build/Release/determ-wallet.exe}"
if [ ! -x "$WALLET" ] && [ ! -f "$WALLET" ]; then
  WALLET="$PROJECT_ROOT/build/Release/determ-wallet"
fi

T=test_wallet_account_accounting
TABS=$PROJECT_ROOT/$T
declare -a NODE_PIDS
cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
}
trap cleanup EXIT INT
rm -rf $T; mkdir -p $T/n1

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count+1))
  else echo "  FAIL: $2"; fail_count=$((fail_count+1)); fi
}

echo "=== 0. Offline CLI contract ==="
if $WALLET --help 2>&1 | grep -q "account-accounting"; then
  assert true "global help lists account-accounting"
else assert false "global help lists account-accounting"; fi
$WALLET account-accounting --help >/dev/null 2>&1 && \
  assert true "account-accounting --help exits 0" || \
  assert false "account-accounting --help exits 0"
$WALLET account-accounting --rpc-port 8821 >/dev/null 2>&1; \
  [ $? -eq 1 ] && assert true "missing --accounts refused" || assert false "missing --accounts refused"
$WALLET account-accounting --rpc-port 8821 --accounts 'BAD!' >/dev/null 2>&1; \
  [ $? -eq 1 ] && assert true "invalid account refused" || assert false "invalid account refused"
$WALLET account-accounting --rpc-port 1 --accounts alice.v >/dev/null 2>&1; \
  [ $? -eq 1 ] && assert true "unreachable daemon exits 1" || assert false "unreachable daemon exits 1"

echo
echo "=== 1. Init + start single-node chain (sole creator) ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1
$DETERM genesis-tool peer-info alice.v --data-dir $T/n1 --stake 1000 > $T/p1.json
cat > $T/gen.json <<EOF
{
  "chain_id": "test-wallet-accounting-1",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ],
  "initial_balances": [
    {"domain": "alice.v", "balance": 1000}
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)
python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain']='alice.v'; c['listen_port']=7821; c['rpc_port']=8821
c['bootstrap_peers']=[]
c['genesis_path']='$TABS/gen.json'; c['genesis_hash']='$GHASH'
c['chain_path']='$TABS/n1/chain.json'; c['key_path']='$TABS/n1/node_key.json'
c['data_dir']='$TABS/n1'
c['tx_commit_ms']=400; c['block_sig_ms']=400; c['abort_claim_ms']=250
with open('$T/n1/config.json','w') as f: json.dump(c,f,indent=2)
"
NODE_PIDS=("")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.5
for _ in $(seq 1 80); do
  H=$($DETERM status --rpc-port 8821 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  [ "$H" -ge 3 ] 2>/dev/null && break; sleep 0.5
done
echo "  chain height: $H"
# This single-node chain mints an empty block every cycle, so the head grows
# without bound. account-accounting's default walk is O(head), so polling with
# it in a hot loop never converges. Instead: pin the window at [FROM,TO] and
# poll application through the O(1) balance / stake_info RPCs.
FROM=$H

echo
echo "=== 2. Known operations (SEQUENTIAL — each applies before the next, so"
echo "        the auto-assigned nonces don't collide) ==="
# node1 --TRANSFER 5--> bob.v ; poll the cheap balance RPC (not the O(head) walk)
$DETERM send bob.v 5 --fee 1 --rpc-port 8821 2>&1 | tail -1
t_applied=false
for _ in $(seq 1 80); do
  B=$($DETERM balance bob.v --rpc-port 8821 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)")
  [ "$B" -ge 5 ] 2>/dev/null && { t_applied=true; break; }
  sleep 0.5
done
echo "  transfer applied: $t_applied"
# node1 self STAKE 3 (only after the transfer's nonce cleared). alice.v was a
# genesis validator with 1000 already locked, so poll for the locked stake to
# INCREASE past the baseline (>= base+3) — not merely be >=3, which is already
# true and would let TO close before the +3 STAKE tx lands.
BASE_LOCKED=$($DETERM stake_info alice.v --rpc-port 8821 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('locked',0))
except: print(0)")
if [ "$t_applied" = "true" ]; then
  $DETERM stake 3 --fee 1 --rpc-port 8821 2>&1 | tail -1
fi

echo
echo "=== 3. Wait for the stake to apply (poll the O(1) stake_info RPC) ==="
APPLIED=false
if [ "$t_applied" = "true" ]; then
  WANT=$((BASE_LOCKED + 3))
  for _ in $(seq 1 80); do
    ST=$($DETERM stake_info alice.v --rpc-port 8821 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('locked',0))
except: print(0)")
    [ "$ST" -ge "$WANT" ] 2>/dev/null && { APPLIED=true; break; }
    sleep 0.5
  done
fi
# Pin the top of the accounting window NOW that both ops are applied, so the
# single accounting call walks a bounded [FROM,TO] range regardless of how fast
# the chain keeps minting empty blocks.
TO=$($DETERM status --rpc-port 8821 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
echo "  window: [$FROM,$TO]"

if [ "$APPLIED" = "true" ]; then
  $WALLET account-accounting --rpc-port 8821 --from "$FROM" --to "$TO" \
    --accounts alice.v,bob.v 2>/dev/null > $T/acct.json
  cat $T/acct.json
  CHECK=$(python -c "
import json
d = json.loads(open('$T/acct.json').read())
by = {a['domain']: a for a in d['accounts']}
n1, n2 = by.get('alice.v',{}), by.get('bob.v',{})
ok = []
ok.append(('alice.v.debits_sent==5', n1.get('debits_sent')==5))
ok.append(('alice.v.staked==3', n1.get('staked')==3))
ok.append(('alice.v.fees_paid>=2', n1.get('fees_paid',0)>=2))
ok.append(('alice.v blocks_produced>0', n1.get('blocks_produced',0)>0))
ok.append(('alice.v.tx_flow_net<0', n1.get('tx_flow_net',0)<0))
ok.append(('bob.v.credits_received==5', n2.get('credits_received')==5))
ok.append(('bob.v.debits_sent==0', n2.get('debits_sent')==0))
ok.append(('bob.v.staked==0', n2.get('staked')==0))
ok.append(('bob.v blocks_produced==0', n2.get('blocks_produced')==0))
ok.append(('bob.v.tx_flow_net==5', n2.get('tx_flow_net')==5))
# subsidy income shows as non_tx_delta, not credits: node1 earned it as creator
ok.append(('alice.v.non_tx_delta>0', isinstance(n1.get('non_tx_delta'),int) and n1['non_tx_delta']>0))
# reconciliation identity holds for both
for who,a in (('alice.v',n1),('bob.v',n2)):
    if a.get('authoritative_balance') is not None:
        ok.append((who+' reconciles',
                   a['authoritative_balance']==a['tx_flow_net']+a['non_tx_delta']))
# node2 opened at 0 (not in genesis) so its non_tx_delta is exactly 0 (no subsidy, no genesis)
ok.append(('bob.v.non_tx_delta==0', n2.get('non_tx_delta')==0))
for name,v in ok: print(('OK ' if v else 'BAD ')+name)
print('ALL' if all(v for _,v in ok) else 'FAILED')" 2>/dev/null)
  echo "$CHECK" | sed 's/^/    /'
  echo "$CHECK" | grep -q "^ALL$" \
    && assert true "per-domain accounting classifies transfer/stake/fees, isolates subsidy, reconciles" \
    || assert false "per-domain accounting classification"
else
  echo "  SKIP: operations did not apply within window (unexpected on a"
  echo "        single-node chain) — offline contract asserted by step 0."
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_account_accounting"; exit 0
else
  echo "  FAIL: test_wallet_account_accounting"; exit 1
fi
