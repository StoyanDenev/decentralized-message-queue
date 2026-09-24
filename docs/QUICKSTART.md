# Determ Quickstart

A 5-minute walkthrough of the full Determ v1 operator workflow: build, run a 3-node cluster, send a transaction, take a snapshot, and bootstrap a fresh node from that snapshot. Cross-shard transfers + equivocation evidence are exercised by the regression tests in `tools/`.

## 1. Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target determ determ-wallet determ-light
```

Three binaries: `build/determ`, `build/determ-wallet` and `build/determ-light` on Linux/macOS, or `build/Release/determ.exe` etc. with MSVC on Windows. The node daemon is `determ`; the wallet and the light client are separate executables. Configuring fetches OpenSSL for the `determ-cryptotest` test oracle (none of the three binaries above links it); `-DDETERM_BUILD_CRYPTOTEST=OFF` skips the fetch. The C99 `determ-node` target is a separate experimental executable, not the node this walkthrough runs.

## 2. Run the regression suite

```bash
bash tools/ci_local.sh             # CMake build into build-linux/ + the FAST suite
                                   # (tools/run_all.sh, FAST=1) + the doc guards
bash tools/ci_local.sh --docs-only # the doc guards alone; builds nothing
```

`tools/ci_local.sh` exports `DETERM_BIN` / `DETERM_WALLET_BIN` / `DETERM_LIGHT_BIN`, so every test runs against the binaries it just built; a bare `tools/test_*.sh` run instead resolves the binary by `tools/common.sh` search order and can pick up a stale build. The multi-node cluster scripts below are not in the FAST suite. To run them by hand, point them at a build first:

```bash
export DETERM_BIN=$(pwd)/build-linux/determ
export DETERM_WALLET_BIN=$(pwd)/build-linux/determ-wallet
export DETERM_LIGHT_BIN=$(pwd)/build-linux/determ-light
bash tools/test_bearer.sh                  # bearer-wallet TRANSFER round-trip
bash tools/test_bft_escalation.sh          # K-of-K → BFT fallback when stuck
bash tools/test_sharded_smoke.sh           # beacon + shard chains start independently
bash tools/test_domain_registry.sh         # DOMAIN_INCLUSION (no-stake validators)
bash tools/test_zero_trust_cross_chain.sh  # cross-chain gossip plumbing
bash tools/test_cross_shard_transfer.sh    # cross-shard TRANSFER end-to-end
bash tools/test_equivocation_slashing.sh   # equivocation evidence closed loop (no L1 consequence, D4)
bash tools/test_snapshot_bootstrap.sh      # fast-bootstrap from snapshot
bash tools/test_dapp_snapshot.sh           # S-037 + S-038: DApp registry survives snapshot bootstrap
```

All 9 should print `PASS:`.

## 3. Run a 3-node single chain by hand

```bash
DETERM=$(pwd)/build/determ            # Windows: $(pwd)/build/Release/determ.exe
W=$(pwd)/build/determ-wallet          # (same Release/ prefix on Windows)
L=$(pwd)/build/determ-light
T=$(pwd)/quickstart
rm -rf $T && mkdir -p $T

# 3 data dirs + per-node Ed25519 keys. single_test is the single-chain
# profile (SINGLE role, M=K=3); the production profiles (web, cluster, ...)
# are beacon or shard roles and need a matching sharded genesis.
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 \
    > $T/p$n.json
done

# Two bearer wallets (random Ed25519 key + 0x-prefixed address): alice is
# funded at genesis, bob receives in step 5. Each file holds the private key
# in plaintext (0600 on POSIX).
$DETERM account create --out $T/alice.json
$DETERM account create --out $T/bob.json
ALICE_ADDR=$(python -c "import json; print(json.load(open('$T/alice.json'))['address'])")
BOB_ADDR=$(python -c "import json; print(json.load(open('$T/bob.json'))['address'])")

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
  "initial_balances": [
    {"domain": "treasury",    "balance": 999},
    {"domain": "$ALICE_ADDR", "balance": 100}
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)

# Wire each node's config (ports 7771-7773 gossip / 8771-8773 RPC). The
# single_test round timers are 5 ms, sized for CI; by hand, use 2 s rounds.
for n in 1 2 3; do
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain']          = 'node$n'
c['listen_port']     = 777$n
c['rpc_port']        = 877$n
c['bootstrap_peers'] = [p for p in ['127.0.0.1:7771','127.0.0.1:7772','127.0.0.1:7773']
                        if p != '127.0.0.1:777$n']
c['genesis_path']    = '$T/gen.json'
c['genesis_hash']    = '$GHASH'
c['tx_commit_ms']    = 2000
c['block_sig_ms']    = 2000
c['abort_claim_ms']  = 1000
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

`init` wrote each node's key as plaintext `node_key.json`. To keep it encrypted at rest instead (a DNK1 container, `node_key.bin`), pass `--passphrase-from file:<path>` to `init` and to `start` (see `CLI-REFERENCE.md`).

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

## 5. Send a TRANSFER

```bash
# From alice's bearer wallet (funded with 100 at genesis) to bob.
$DETERM balance $ALICE_ADDR --rpc-port 8771     # 100
ALICE_PRIV=$(python -c "import json; print(json.load(open('$T/alice.json'))['privkey'])")
$DETERM send_anon "$BOB_ADDR" 25 "$ALICE_PRIV" --rpc-port 8771
sleep 10
$DETERM balance $BOB_ADDR --rpc-port 8771       # 25

# From node1's registered domain: `send` asks the node to sign with its own key.
$DETERM send "$BOB_ADDR" 5 --rpc-port 8771
```

`send_anon` takes the private key as a positional argument, so it is visible in the process table and the shell history; the S-115 `--*-from` flags do not cover it. For keys you care about, sign offline with a keyfile instead (`determ-light verify-and-submit`, §12).

## 6. Snapshot create + fetch + restore

```bash
# Operator dumps the running chain's state. The file is the binary DSN1 record.
$DETERM snapshot create --out $T/snap.bin --rpc-port 8771

# Verify the file.
$DETERM snapshot inspect --in $T/snap.bin

# Fetch the same snapshot from a remote peer over the gossip wire
# (no genesis or chain config locally — pure network client).
$DETERM snapshot fetch --peer 127.0.0.1:7771 --out $T/snap2.bin

# Bootstrap a brand-new node from the snapshot (no genesis required).
mkdir -p $T/receiver
$DETERM init --data-dir $T/receiver --profile single_test
python -c "
import json
with open('$T/receiver/config.json') as f: c = json.load(f)
c['domain']         = 'receiver'
c['listen_port']    = 7799
c['rpc_port']       = 8799
c['snapshot_path']  = '$T/snap.bin'   # ← triggers fast-bootstrap
c['tx_commit_ms']   = 2000
c['block_sig_ms']   = 2000
c['abort_claim_ms'] = 1000
with open('$T/receiver/config.json','w') as f: json.dump(c,f,indent=2)
"
$DETERM start --config $T/receiver/config.json > $T/receiver/log 2>&1 &
sleep 5
grep "restored from snapshot" $T/receiver/log
$DETERM status --rpc-port 8799   # head_hash matches snapshot
```

The restored node holds the snapshot's state plus its tail headers (16 by default), so its `status` reports that tail's length as `height` and the tail's first header as `genesis`; the `head_hash` is the snapshot's.

## 7. Light-client trustless verification (v2.2)

Demonstrates the trustless verification chain — fetch any state from an untrusted full node, verify locally against a committee-bound root. The `determ` CLIs below compose with `determ-light verify-state-root`, which supplies the root:

```bash
# 1. Fetch a slice of block headers (Block JSON minus heavy
#    collections; light-client header-sync primitive). Start at 1:
#    genesis carries no committee signatures.
$DETERM headers --rpc-port 8771 --from 1 --count 10 > headers.json

# 2. Verify the prev_hash chain (chain-of-hashes integrity).
#    Optional --genesis-hash pins the genesis when starting at 0.
$DETERM verify-headers --in headers.json
#   → OK
#     verified 10 header(s) 1..10

# 3. Verify K-of-K committee signatures on a header (the first one in
#    headers.json). `determ validators --json` emits the {domain, ed_pub}
#    array that verify-block-sigs expects, no transformation needed.
$DETERM validators --rpc-port 8771 --json > committee.json
$DETERM verify-block-sigs --header headers.json --committee committee.json
#   → OK
#     block_index: 1
#     mode: MD (full K-of-K)
#     verified sigs: 3/3

# 4. Fetch a state-proof for an account. The state_proof RPC serves the
#    head only; the proof's "height" is the chain length, so its root is the
#    state_root of block height-1.
$DETERM state-proof --rpc-port 8771 --ns a --key treasury > proof.json
PH=$(python -c "import json; print(json.load(open('proof.json'))['height'])")

# 5. Get that block's state_root bound to the committee, then verify the
#    proof against it. --wait lets the next block arrive if needed.
STATE_ROOT=$($L verify-state-root --rpc-port 8771 --genesis $T/gen.json \
               --height $((PH - 1)) --wait 10 --json \
             | python -c "import sys,json; print(json.load(sys.stdin)['state_root'])")
$DETERM verify-state-proof --in proof.json --state-root "$STATE_ROOT"
#   → OK
#     state_root: <hex>
#     key: a:treasury
#     value_hash: <hex>
#     proof depth: N sibling hashes
```

**What this proves:**
- The full node serving the headers might be tampering with them; the chain-of-hashes check catches re-ordered/spliced headers.
- The full node might supply forged committee signatures; `verify-block-sigs` catches them by verifying against the pinned committee pubkeys.
- The full node might fabricate a state_root that's self-consistent with its tampered state; pinning `--state-root` to the committee-bound root forces the proof to verify against the *trusted* root, defeating that attack. The committee does not sign a block's `state_root` (`compute_block_digest` excludes it), so the `state_root` field of a header from `determ headers` is not trusted on its own. `verify-state-root` binds it through the committee-signed successor: it recomputes block `H`'s hash from the full block and checks it against block `H+1`'s signed `prev_hash`. For the current head there is no successor yet, which is why step 5 may need `--wait`.

The pinned committee pubkeys are the bootstrap-trust anchor: a light client obtains them from a trusted source (registry snapshot signed by the founders, baked-in genesis pubkeys, etc.) and then chains verification forward via the CLIs above.

**Snapshot-level trustless verification** complements the per-field state-proof path:

```bash
# Verify a downloaded snapshot's whole state Merkle against the committee-bound
# root at the snapshot's own height.
SNAP_H=$($DETERM snapshot inspect --in $T/snap.bin --dump \
         | python -c "import sys,json; print(json.load(sys.stdin)['block_index'])")
SNAP_ROOT=$($L verify-state-root --rpc-port 8771 --genesis $T/gen.json \
              --height $SNAP_H --wait 10 --json \
            | python -c "import sys,json; print(json.load(sys.stdin)['state_root'])")
$DETERM snapshot inspect --in $T/snap.bin --state-root "$SNAP_ROOT"
#   → snapshot OK + "trusted root: ✓ matches --state-root"
```

## 8. Cross-shard deployment (optional)

For a beacon + S-shard deployment, see `tools/test_cross_shard_transfer.sh` — it spins up 1 beacon + 2 shards (M=K=1), grinds bearer wallets that route to each shard, and asserts a TRANSFER from shard 0 → shard 1 credits the destination.

## 9. Submit equivocation evidence (forensics)

```bash
# Synthesize off-chain via Python (Ed25519 signing) — see
# tools/test_equivocation_slashing.sh for the full template.
# Then submit (the test submits to every node, so each producer holds it):
python -c "
import socket, json
ev = json.load(open('evidence.json'))
s = socket.create_connection(('127.0.0.1', 8771))
req = json.dumps({'method':'submit_equivocation','params':{'event': ev}})
s.sendall((req + '\n').encode())
print(s.recv(4096).decode().strip())
# → {\"error\":null,\"result\":{\"accepted\":true,\"block_index\":1,\"equivocator\":\"node1\",\"kind\":0}}
"
```

The next finalized block bakes the evidence as an on-chain `EquivocationEvent` record. Since 2026-09-16 (DECISION-LOG D4) the record carries **no L1 consequence** — the equivocator keeps its stake and its registry entry; the record is input to the L2 policy. Inspect it with `determ show-block <index>` or `tools/operator_equivocation_digest.sh`.

## 10. Governance: change a chain-wide parameter (A5)

Deploy a chain with `governance_mode = 1` and N founder keyholders. Then any time a quorum of keyholders agrees, they can change a whitelisted parameter mid-chain:

```bash
# Build genesis with 3 founder keyholders (use existing validator keys)
PK1=$(python -c "import json; print(json.load(open('$T/n1/node_key.json'))['pubkey'])")
PK2=$(python -c "import json; print(json.load(open('$T/n2/node_key.json'))['pubkey'])")
PK3=$(python -c "import json; print(json.load(open('$T/n3/node_key.json'))['pubkey'])")

# In your genesis JSON:
#   "governance_mode": 1,
#   "param_threshold": 3,
#   "param_keyholders": ["<PK1>", "<PK2>", "<PK3>"]

# Sign + submit a PARAM_CHANGE: MIN_STAKE = 2000 (8-byte LE)
PRIV1=$(python -c "import json; print(json.load(open('$T/n1/node_key.json'))['priv_seed'])")
PRIV2=$(python -c "import json; print(json.load(open('$T/n2/node_key.json'))['priv_seed'])")
PRIV3=$(python -c "import json; print(json.load(open('$T/n3/node_key.json'))['priv_seed'])")

$DETERM submit-param-change \
  --priv "$PRIV1" --from node1 \
  --name MIN_STAKE --value-hex "d007000000000000" \
  --effective-height 50 --fee 0 \
  --keyholder-sig "0:$PRIV1" \
  --keyholder-sig "1:$PRIV2" \
  --keyholder-sig "2:$PRIV3" \
  --rpc-port 8771
```

`--priv` has a `--priv-from <file:path|env:NAME|prompt>` twin that keeps the key off the command line; the `--keyholder-sig` values have none (S-115). After block 50 finalizes, `snapshot inspect` shows `min_stake: 2000`. Whitelist of mutable parameters: see `docs/PROTOCOL.md` §13. Off-list parameters (committee size K, sharding mode) require a new chain genesis.

### Offline / air-gapped authoring (determ-wallet)

`submit-param-change` builds, signs, and submits in one RPC call. For an air-gapped keyholder setup, `determ-wallet` (which never touches a daemon) splits the authoring into a build → lint → verify pipeline you run *before* submission:

```bash
# 1. Build the unsigned PARAM_CHANGE body + the per-keyholder signing preimage.
$W param-change-build --name MIN_STAKE --value 2000 \
   --effective-height 50 --nonce 0 --from node1 --out pc.json

# 2. LINT it before anyone signs — catches the silent-no-op trap where a
#    whitelisted numeric scalar (MIN_STAKE / SUSPENSION_SLASH / UNSTAKE_DELAY)
#    carries a value that is not exactly 8 bytes and would activate to nothing.
$W param-change-lint --tx-json pc.json
#   → verdict: EFFECTIVE          (INERT_BAD_WIDTH / UNKNOWN_NAME would warn)

# 3. Each keyholder signs pc.json's `keyholder_sig_message_hex` preimage offline
#    (an Ed25519 sig over name|value|effective_height); the (index, ed_sig)
#    pairs are assembled into the tx payload + a keyholder-pubkey file.

# 4. VERIFY the assembled K-of-K multisig offline, before it ever reaches a node.
$W param-change-verify --tx-json assembled.json \
   --keyholders keyholders.json --threshold 3
#   → PARAM-CHANGE-VERIFY: PASS
```

Lint and verify answer **different** questions: a bad-width value can carry a perfectly valid multisig (`verify` PASS) yet still silently no-op at activation (`lint` INERT_BAD_WIDTH) — run both before you submit. The runtime counterpart that audits an already-staged change on-chain is `tools/operator_param_activation_preflight.sh`.

## 11. Wallet recovery (A2)

The `determ-wallet` binary is separate from the chain daemon. Generate a recovery setup for any 32-byte secret (typically your Ed25519 seed):

```bash
# Split a seed into 3-of-5 shares with passphrase protection. The
# --*-from forms keep both secrets off the command line.
( umask 077
  printf '%s\n' 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef > seed.hex
  printf '%s\n' 'my-recovery-passphrase' > pass.txt )
$W create-recovery \
  --seed-from file:seed.hex --password-from file:pass.txt \
  -t 3 -n 5 --out wallet_backup.drs

# wallet_backup.drs is one binary DRS1 container holding all five envelopes.

# Recover any time using >=3 of the 5 guardians (indices 0-4):
$W recover \
  --in wallet_backup.drs \
  --password-from file:pass.txt \
  --guardians 0,2,4
# → 0123456789abcdef...
```

The only recovery scheme is `passphrase`. Each share is sealed under the same password (DWE2: Argon2id + AES-256-GCM), so whoever holds the file and the password recovers the seed, and the password's strength is the whole defense against offline guessing. `--scheme opaque` is rejected: the OPAQUE guardian adapter was de-scoped and deleted (DECISION-LOG 2026-07-03); `docs/proofs/WalletRecovery.md` (FA12) covers the shipped passphrase path.

## 12. Light-client workflow

The `determ-light` binary is a trust-minimized light-client wallet. Unlike `determ-wallet` (which never talks to a daemon), `determ-light` reads chain state via a daemon's RPC and locally verifies every response against a pinned genesis hash + the committee-bound `state_root`. A malicious or compromised daemon cannot serve fabricated balances, nonces, or chain history to an honest `determ-light` client — the client refuses on hash mismatch.

Reads anchored at the chain head need the head's committee-signed successor (the S-042 binding of §7); `--wait <s>` blocks up to `s` seconds for it, and without it such a read fails closed.

```bash
# Step 1: verify the daemon's chain end-to-end against the genesis pin.
# Anchors genesis, walks every header, checks K-of-K committee sigs.
$L verify-chain \
  --rpc-port 8771 --genesis $T/gen.json

# Step 2: read alice's balance trustlessly. The composite cross-checks
# the daemon's cleartext `account` reply against a Merkle state-proof
# anchored at the committee-bound state_root.
$L balance-trustless \
  --rpc-port 8771 --genesis $T/gen.json --domain $ALICE_ADDR --json --wait 10

# Step 3: send a TRANSFER end-to-end with a trustless-fetched nonce.
# Signs offline with a DAK1 keyfile, submits via the daemon's RPC.
# determ-wallet account-import writes the DAK1 file from a raw private key.
( umask 077
  python -c "import json; print(json.load(open('$T/alice.json'))['privkey'])" > $T/alice.priv )
$W account-import --priv-from file:$T/alice.priv --out $T/alice.dak
$L verify-and-submit \
  --rpc-port 8771 --genesis $T/gen.json --keyfile $T/alice.dak \
  --to $BOB_ADDR --amount 10 --fee 0 --wait 10

# Step 4 (R39+1 A3): monitor a daemon's head trust-minimized over time.
# Anchors genesis once, then re-verifies the head + K-of-K committee sigs
# every --interval seconds. One TICK line per poll; SIGINT for clean exit.
$L watch-head \
  --rpc-port 8771 --genesis $T/gen.json --interval 5 --count 10

# Step 5 (R39+2 B3): capture a verifiable header archive for audit.
# Anchors genesis, fetches + committee-sig-verifies headers [0, 10), and
# writes a self-contained archive; --include-committee-sigs keeps the
# signatures so the offline re-check can verify them too.
$L export-headers \
  --rpc-port 8771 --genesis $T/gen.json --from 0 --count 10 \
  --include-committee-sigs --out headers_archive.json

# Step 6 (R39+3 C3): re-verify the archive months later with no daemon.
# Pure offline cryptographic re-check against the pinned genesis only;
# --require-sigs fails an archive exported without signatures.
$L verify-archive \
  --in headers_archive.json --genesis $T/gen.json --require-sigs

# Step 7 (R40 D3): verified balance trajectory over a height range.
# Each sampled height's state_root is committee-verified; balance/nonce
# are Merkle-verified at head (the state_proof RPC is head-only).
$L account-history \
  --rpc-port 8771 --genesis $T/gen.json --domain treasury --from 1 --to 20 --step 5 --wait 10

# Step 8 (R40 E3): confirm a payment landed, trustlessly.
# INCLUDED / NOT-INCLUDED / UNVERIFIABLE verdict on whether tx <hex> is
# in committee-signed block <B>; recomputes tx_root from the body and
# gates on the committee-signed value (STRONG regime — no daemon trust).
# `determ show-tx <hex>` reports the block_index to pass as --height.
$L verify-tx-inclusion \
  --rpc-port 8771 --genesis $T/gen.json --tx-hash <hex> --height <B>

# Step 9 (R40 F3): anchor the committee-bound state_root at a height.
# Reports the state_root committed at <H>, bound through the committee-signed
# successor block (not daemon-asserted) and to the pinned genesis — feed it
# to verify-state-proof --state-root to verify a state field against it.
$L verify-state-root --rpc-port 8771 --genesis $T/gen.json --height 15
```

### Daemon-free verification from exported files

The steps above re-fetch from a live daemon on every run. To verify a chain segment **offline** — from a checkpoint bundle, with no daemon at verify time — export the headers + committee once, then verify the files:

```bash
# Export the inputs (the only steps that touch a daemon):
$L fetch-headers    --rpc-port 8771 --from 0 --count 50 --out headers.json
$L fetch-validators --rpc-port 8771                      --out committee.json

# Verify the whole segment with NO daemon: prev_hash continuity + every
# non-genesis block's committee signatures over its self-recomputed digest.
$L verify-chain-file --in headers.json --committee committee.json
#   → VERIFY-CHAIN-FILE: PASS

# If the committee rotated mid-segment, --committee-manifest maps inclusive
# index ranges to committee files. committee-diff tells you WHETHER two
# snapshots' signing sets differ (so you know whether one committee covers a
# span, or you must segment / use a manifest):
$L committee-diff --a committee.json --b committee_later.json
#   → SIGNING SET: IDENTICAL        (one --committee covers the span)
```

This path never calls `compute_genesis_hash`, so it is unaffected by the cross-platform genesis-hash gap; `--genesis-hash <hex>` optionally pins block 0 to a known hash.

The full subcommand surface lives in [CLI-REFERENCE.md](CLI-REFERENCE.md) §determ-light: `verify-headers`, `verify-block-sigs`, `block-verify`, `verify-state-proof`, `fetch-headers`, `fetch-validators`, `fetch-state-proof`, `verify-chain`, `verify-chain-file`, `committee-diff`, `committee-at-height`, `balance-trustless`, `nonce-trustless`, `stake-trustless`, `supply-trustless`, `sign-tx`, `submit-tx`, `verify-and-submit`, `watch-head`, `export-headers`, `verify-archive`, `account-history`, `verify-tx-inclusion`, `verify-receipt-inclusion`, `verify-state-root`, `version`.

## 13. Under-quorum merge (R4, EXTENDED mode only)

When a regional shard's validator pool drops below 2K, the protocol can absorb it into the modular-next shard's committee. v1.x is operator-driven; v1.1 will auto-detect on the beacon.

```bash
# Operator initiates a merge of shard 0 into shard 1 at height 30:
$DETERM submit-merge-event \
  --priv "$PRIV1" --from node1 \
  --event begin \
  --shard-id 0 --partner-id 1 \
  --refugee-region us-east \
  --effective-height 30 \
  --evidence-window-start 0 \
  --rpc-port 8771

# When the regional pool recovers, end the merge:
$DETERM submit-merge-event \
  --priv "$PRIV1" --from node1 \
  --event end \
  --shard-id 0 --partner-id 1 \
  --effective-height 60 \
  --evidence-window-start 0 \
  --rpc-port 8771
```

See `docs/proofs/UnderQuorumMerge.md` (FA9) for the safety argument across BEGIN/END transitions.

## What's next

- [`docs/WHITEPAPER-v1.x.md`](WHITEPAPER-v1.x.md) — standalone academic-style technical paper covering every v1.x mechanism (consensus, sharding, governance, recovery, formal verification, comparison to related work).
- `README.md` §16 — sharding architecture; §16.5/§16.7 regional + under-quorum merge.
- `README.md` §18 — governance mode (A5).
- `README.md` §18.5 — wallet recovery (A2).
- `README.md` §19 — formal verification (FA-track + FB-track).
- `README.md` §17 — explicit non-goals (no smart contracts, no bridges, no oracles).
- `tools/` — behavioral tests of the protocol features (the FAST suite runs through `tools/ci_local.sh`; `docs/README.md` has a representative table).
- `docs/proofs/` — the per-claim proof record (F0 + FA1–FA12 + FA-Apply-* + the S-item closure analyses) plus the TLA+ models; `docs/proofs/README.md` indexes every document with its status, including the withdrawn FA3 claim.
