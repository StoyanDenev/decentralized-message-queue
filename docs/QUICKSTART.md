# Determ Quickstart

A 5-minute walkthrough of the full Determ v1 operator workflow: build, run a 3-node cluster, send a transaction, take a snapshot, and bootstrap a fresh node from that snapshot. Cross-shard transfers + equivocation slashing are exercised by the regression tests in `tools/`.

## 1. Build

```bash
cmake -S . -B build
cmake --build build --config Release
```

Single binary: `build/Release/determ.exe` (Windows) or `build/determ` (Linux/Mac).

## 2. Run the regression suite

```bash
bash tools/test_bearer.sh                  # bearer-wallet TRANSFER round-trip
bash tools/test_bft_escalation.sh          # K-of-K → BFT fallback when stuck
bash tools/test_sharded_smoke.sh           # beacon + shard chains start independently
bash tools/test_domain_registry.sh         # DOMAIN_INCLUSION (no-stake validators)
bash tools/test_zero_trust_cross_chain.sh  # cross-chain gossip plumbing
bash tools/test_cross_shard_transfer.sh    # cross-shard TRANSFER end-to-end
bash tools/test_equivocation_slashing.sh   # equivocation closed-loop
bash tools/test_snapshot_bootstrap.sh      # fast-bootstrap from snapshot
```

All 8 should print `PASS:`.

## 3. Run a 3-node single chain by hand

```bash
DETERM=$(pwd)/build/Release/determ.exe
T=$(pwd)/quickstart
rm -rf $T && mkdir -p $T

# 3 data dirs + per-node Ed25519 keypairs.
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile web
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 \
    > $T/p$n.json
done

# Genesis: 3 creators, M=K=3, BFT escalation enabled by default.
cat > $T/gen.json <<EOF
{
  "chain_id": "quickstart",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 999}]
}
EOF
$DETERM genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)

# Wire each node's config (3-mesh, ports 7771-7773 / 8771-8773).
for n in 1 2 3; do
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain']          = 'node$n'
c['listen_port']     = 777$n
c['rpc_port']        = 877$n
c['bootstrap_peers'] = ['127.0.0.1:7771','127.0.0.1:7772','127.0.0.1:7773']
c['genesis_path']    = '$T/gen.json'
c['genesis_hash']    = '$GHASH'
c['chain_path']      = '$T/n$n/chain.json'
c['key_path']        = '$T/n$n/node_key.json'
c['data_dir']        = '$T/n$n'
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
done

# Start all three.
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &

sleep 15
$DETERM status --rpc-port 8771   # height should be > 1
```

Stop the cluster with `kill %1 %2 %3` when done.

## 4. Inspect the chain

```bash
$DETERM status --rpc-port 8771                 # head, role, epoch, mempool, ...
$DETERM chain-summary --rpc-port 8771 --last 5 # recent blocks compact
$DETERM show-block 5 --rpc-port 8771           # full block JSON
$DETERM validators --rpc-port 8771             # registered validator pool
$DETERM committee --rpc-port 8771              # current epoch's K committee
$DETERM show-account treasury --rpc-port 8771  # account state (balance + nonce)
```

## 5. Send a TRANSFER from a bearer wallet

```bash
# Generate a bearer wallet (random Ed25519 key + 0x-prefixed address).
$DETERM account create --out $T/alice.json
ALICE_ADDR=$(python -c "import json; print(json.load(open('$T/alice.json'))['address'])")
ALICE_PRIV=$(python -c "import json; print(json.load(open('$T/alice.json'))['privkey'])")

# Fund Alice via a TRANSFER from treasury... but wait — only registered
# domains in initial_balances have balance. Actually treasury is in
# initial_balances above. Real flow: pre-fund Alice in genesis, OR
# transfer from a node1 (creators receive subsidy + fees). For this
# quickstart, transfer from node1 (which has accumulated subsidy):
$DETERM send node1 100 --rpc-port 8771   # not directly — node1's own
                                          # priv key is in $T/n1/node_key.json
                                          # CLI authoring TRANSFERs from
                                          # registered domains is a node-
                                          # local op (not an RPC).

# Easier: from a bearer wallet that you pre-funded in initial_balances.
# Set initial_balances = [{"domain": "$ALICE_ADDR", "balance": 100}, ...]
# in genesis BEFORE step 3, then send_anon works:
$DETERM send_anon "$BOB_ADDR" 25 "$ALICE_PRIV" --rpc-port 8771
```

## 6. Snapshot create + fetch + restore

```bash
# Operator dumps the running chain's state.
$DETERM snapshot create --out $T/snap.json --rpc-port 8771

# Verify the file.
$DETERM snapshot inspect --in $T/snap.json

# Fetch the same snapshot from a remote peer over the gossip wire
# (no genesis or chain config locally — pure network client).
$DETERM snapshot fetch --peer 127.0.0.1:7771 --out $T/snap2.json

# Bootstrap a brand-new node from the snapshot (no genesis required).
mkdir -p $T/receiver
$DETERM init --data-dir $T/receiver
python -c "
import json
with open('$T/receiver/config.json') as f: c = json.load(f)
c['domain']        = 'receiver'
c['listen_port']   = 7799
c['rpc_port']      = 8799
c['snapshot_path'] = '$T/snap.json'   # ← triggers fast-bootstrap
c['chain_path']    = '$T/receiver/chain.json'
c['key_path']      = '$T/receiver/node_key.json'
c['data_dir']      = '$T/receiver'
with open('$T/receiver/config.json','w') as f: json.dump(c,f,indent=2)
"
$DETERM start --config $T/receiver/config.json > $T/receiver/log 2>&1 &
sleep 5
grep "restored from snapshot" $T/receiver/log
$DETERM status --rpc-port 8799   # head_hash matches snapshot
```

## 7. Cross-shard deployment (optional)

For a beacon + S-shard deployment, see `tools/test_cross_shard_transfer.sh` — it spins up 1 beacon + 2 shards (M=K=1), grinds bearer wallets that route to each shard, and asserts a TRANSFER from shard 0 → shard 1 credits the destination.

## 8. Submit equivocation evidence (governance)

```bash
# Synthesize off-chain via Python (Ed25519 signing) — see
# tools/test_equivocation_slashing.sh for the full template.
# Then submit:
python -c "
import socket, json
ev = json.load(open('evidence.json'))
s = socket.create_connection(('127.0.0.1', 8771))
req = json.dumps({'method':'submit_equivocation','params':{'event': ev}})
s.sendall((req + '\n').encode())
print(s.recv(4096).decode().strip())
# → {\"error\":null,\"result\":{\"accepted\":true,\"equivocator\":\"node1\",\"block_index\":1}}
"
```

The next finalized block bakes the evidence; on apply, the equivocator's stake is fully forfeited and they're deregistered from the validator pool.

## What's next

- See `README.md` §16 for the sharding architecture and stage-by-stage status.
- See `README.md` §15 for explicit non-goals (no smart contracts, no bridges, no oracles).
- See `tools/` for behavioral tests of every protocol feature.
