#!/usr/bin/env bash
# S-028 — case-insensitive anon-address handling at user boundaries.
#
# Asserts:
#   1. `balance` RPC normalizes case — querying "0xABCDEF..." (uppercase)
#      returns the same balance as "0xabcdef..." (lowercase). Tests the
#      `rpc_balance` normalize-at-input path.
#   2. `send` RPC normalizes the `to` field — sending to an uppercase
#      anon address credits the same store-key as the lowercase form.
#   3. `submit_tx` REJECTS non-canonical addresses with a clear
#      diagnostic — clients must sign with the canonical lowercase form
#      because the Ed25519 signature is over signing_bytes which
#      embeds the address byte-for-byte. Mutating case server-side
#      would invalidate the signature; the strict-input approach
#      keeps store-keys unambiguous.
#
# Single-node M=K=1 — no TIME_WAIT risk.
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_anon_case
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

rm -rf $T
mkdir -p $T/n1

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init single-node chain (M=K=1) + seed an anon account ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json

# Create an anon account so we have a known anon address to query.
# S-004 closure forces --out (or --allow-plaintext-stdout) — use --out
# so the keyfile is written + the address is printed to stdout.
$DETERM account create --out $T/anon1.key 2>&1 > $T/anon1_create.out
ANON_ADDR=$(grep -oE "0x[0-9a-f]{64}" $T/anon1_create.out | head -1)
if [ -z "$ANON_ADDR" ]; then
  # Fallback: re-extract from the keyfile pubkey if the create-output
  # format doesn't print "0x...".
  ANON_ADDR=$(python -c "
import json
try:
    j = json.load(open('$T/anon1.key'))
    pk = j.get('pub_hex') or j.get('pubkey') or j.get('address','')
    if pk and not pk.startswith('0x'): pk = '0x' + pk
    print(pk)
except Exception as e:
    print('')
")
fi
echo "  generated anon address: $ANON_ADDR"
if [ -z "$ANON_ADDR" ]; then
  echo "  FAIL: couldn't generate anon address"
  cat $T/anon1_create.out | head -10
  exit 1
fi

# Build genesis with the anon account funded.
cat > $T/gen.json <<EOF
{
  "chain_id": "test-anon-case",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "initial_balances": [
    {"domain": "$ANON_ADDR", "balance": 1000000}
  ],
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

python -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 7830
c['rpc_port'] = 8830
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n1/chain.json'
c['key_path']   = '$TABS/n1/node_key.json'
c['data_dir']   = '$TABS/n1'
c['tx_commit_ms']  = 200
c['block_sig_ms']  = 200
c['abort_claim_ms']= 100
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"

$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!
sleep 2

# Wait for chain to advance past genesis.
for _ in $(seq 1 40); do
  H=$($DETERM status --rpc-port 8830 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
  [ "$H" -ge "2" ] && break
  sleep 0.5
done

echo
echo "=== 2. balance RPC: case-insensitive query returns same result ==="
# Build the uppercase variant of the anon address.
ANON_UPPER=$(echo "$ANON_ADDR" | python -c "import sys; s=sys.stdin.read().strip(); print('0x' + s[2:].upper())")
echo "  lowercase: $ANON_ADDR"
echo "  uppercase: $ANON_UPPER"

BAL_LOWER=$($DETERM balance "$ANON_ADDR" --rpc-port 8830 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(-1)")
BAL_UPPER=$($DETERM balance "$ANON_UPPER" --rpc-port 8830 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(-1)")
echo "  balance(lower)=$BAL_LOWER  balance(upper)=$BAL_UPPER"
if [ "$BAL_LOWER" = "$BAL_UPPER" ] && [ "$BAL_LOWER" = "1000000" ]; then
  assert true "balance RPC normalizes case (both queries return 1000000)"
else
  assert false "balance RPC didn't normalize case (lower=$BAL_LOWER upper=$BAL_UPPER expected 1000000)"
fi

echo
echo "=== 3. send RPC: case-insensitive 'to' lands in the canonical slot ==="
# Create a second anon account as the destination.
$DETERM account create --out $T/anon2.key 2>&1 > $T/anon2_create.out
DEST_LOWER=$(grep -oE "0x[0-9a-f]{64}" $T/anon2_create.out | head -1)
if [ -z "$DEST_LOWER" ]; then
  DEST_LOWER=$(python -c "
import json
try:
    j = json.load(open('$T/anon2.key'))
    pk = j.get('pub_hex') or j.get('pubkey') or j.get('address','')
    if pk and not pk.startswith('0x'): pk = '0x' + pk
    print(pk)
except: print('')
")
fi
DEST_UPPER=$(echo "$DEST_LOWER" | python -c "import sys; s=sys.stdin.read().strip(); print('0x' + s[2:].upper())")
echo "  destination lowercase: $DEST_LOWER"
echo "  destination uppercase: $DEST_UPPER"

# node1 sends 100 to DEST_UPPER via 'determ send'.
$DETERM send "$DEST_UPPER" 100 --fee 0 --rpc-port 8830 2>&1 | tail -1

# Wait for inclusion.
for _ in $(seq 1 30); do
  B=$($DETERM balance "$DEST_LOWER" --rpc-port 8830 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)")
  [ "$B" = "100" ] && break
  sleep 0.5
done

B_LOWER=$($DETERM balance "$DEST_LOWER" --rpc-port 8830 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)")
B_UPPER=$($DETERM balance "$DEST_UPPER" --rpc-port 8830 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)")
echo "  dest balance via lowercase query: $B_LOWER"
echo "  dest balance via uppercase query: $B_UPPER"
if [ "$B_LOWER" = "100" ] && [ "$B_UPPER" = "100" ]; then
  assert true "send to uppercase address credits canonical lowercase slot"
else
  assert false "send-to-uppercase didn't normalize (lower=$B_LOWER upper=$B_UPPER expected 100)"
fi

echo
echo "=== 4. submit_tx: non-canonical (uppercase) addresses are REJECTED ==="
# Synthesize a TRANSFER tx with uppercase-hex 'from' or 'to' and try to
# submit. Expected: server rejects with "non-canonical" diagnostic.
# (We don't sign properly — just verify the case-check fires before
# the sig-verify path. Submit a structurally-valid tx with uppercase
# anon-address `from`; the chain should reject on the S-028 gate.)
REJECT_OUT=$(python -c "
import json, socket
tx = {
    'type': 0,                # TxType::TRANSFER
    'from': '${DEST_UPPER}',
    'to':   '$ANON_ADDR',
    'amount': 0,
    'fee': 0,
    'nonce': 0,
    'payload': '',
    'sig': '00' * 64,          # 64 bytes -> 128 hex chars
    'hash': '00' * 32,         # 32 bytes -> 64 hex chars
}
req = json.dumps({'method':'submit_tx','params':{'tx': tx}})
s = socket.create_connection(('127.0.0.1', 8830))
s.sendall((req + '\n').encode())
buf = b''
while b'\n' not in buf:
    chunk = s.recv(4096)
    if not chunk: break
    buf += chunk
print(buf.decode().strip())
" 2>&1)
echo "  server reply: $(echo $REJECT_OUT | head -c 200)"
if echo "$REJECT_OUT" | grep -qi "non-canonical"; then
  assert true "submit_tx rejects non-canonical (uppercase) tx.from with clear diagnostic"
else
  assert false "submit_tx didn't reject uppercase tx.from with the expected diagnostic"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: S-028 anon-address case-normalization"; exit 0
else
  echo "  FAIL"; exit 1
fi
