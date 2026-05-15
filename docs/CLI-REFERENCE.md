# Determ CLI Reference

All `determ` subcommands. Run `determ --help` for the canonical built-in help.

**See also:** [`QUICKSTART.md`](QUICKSTART.md) for hands-on recipes, [`PROTOCOL.md`](PROTOCOL.md) for wire formats, [`WHITEPAPER-v1.x.md`](WHITEPAPER-v1.x.md) for the standalone technical paper.

## Node lifecycle

| Command | Purpose |
|---|---|
| `determ init [--data-dir D] [--profile P]` | Generate config + Ed25519 keypair in a fresh data dir |
| `determ start --config FILE` | Run the node daemon (foreground) |

Profiles: `cluster` (LAN), `web` (default), `regional`, `global` — differ in round timer durations (`tx_commit_ms`, `block_sig_ms`, `abort_claim_ms`).

## Inspection (block-explorer)

All inspection commands hit the running node's RPC. Default RPC port is in the node's config.

| Command | Returns |
|---|---|
| `determ status [--rpc-port N]` | Chain head, head_hash, role, shard_id, epoch_index, peer_count, mempool, mode counters + `protections` block (current state of every operator-tunable security/log flag — `rpc_localhost_only`, `rpc_hmac_auth`, `rpc_rate_limit`, `gossip_rate_limit`, `log_quiet`, `bft_enabled`, `sharding_mode`). Monitoring systems can alert on flag drift in production. |
| `determ peers [--rpc-port N]` | Connected peer addresses |
| `determ show-block <i> [--rpc-port N]` | Full block JSON at index `i` |
| `determ chain-summary [--last N] [--rpc-port N]` | Compact view of last `N` blocks (default 10) |
| `determ validators [--rpc-port N]` | Registered validator pool (domain, ed_pub, stake, active_from) |
| `determ committee [--rpc-port N]` | Current epoch's K-of-K committee (deterministic from chain state) |
| `determ show-account <addr> [--rpc-port N]` | Balance + nonce + registry record + stake for any address |
| `determ show-tx <hash> [--rpc-port N]` | Locate a tx in a finalized block (block_index + payload) |
| `determ balance <domain> [--rpc-port N]` | Balance only |
| `determ nonce <domain> [--rpc-port N]` | Next expected nonce |
| `determ stake_info <domain> [--rpc-port N]` | Locked stake + unlock_height |

## Wallet / transactions

### Anonymous bearer wallets

| Command | Purpose |
|---|---|
| `determ account create --out FILE [--allow-plaintext-stdout]` | Generate a fresh Ed25519 key + `0x`-prefixed bearer address. `--out` writes to a 0600-permissioned file. Bare `account create` (no `--out`) is refused (S-004); opt in to stdout via `--allow-plaintext-stdout`. |
| `determ account address <privkey_hex>` | Derive address from priv-key (offline, no daemon) |
| `determ send_anon <to> <amount> <privkey_hex> [--fee N] [--rpc-port N]` | Build, sign, submit a TRANSFER from a bearer wallet |

### Domain-authored (registered validator)

| Command | Purpose |
|---|---|
| `determ register --rpc-port N` | Register this node's domain (RPC host's key) |
| `determ send <to> <amount> [--fee N] [--rpc-port N]` | TRANSFER from this node's domain |
| `determ stake <amount> [--rpc-port N]` | Lock balance into stake |
| `determ unstake <amount> [--rpc-port N]` | Begin unstake (subject to UNSTAKE_DELAY) |

## Genesis tooling

| Command | Purpose |
|---|---|
| `determ genesis-tool peer-info <domain> --data-dir D --stake N` | Emit JSON snippet for `initial_creators` |
| `determ genesis-tool build <config.json>` | Compute genesis block + write `.hash` sidecar |
| `determ genesis-tool build-sharded <config.json>` | Produce 1 beacon + S shard genesis files (with shared `shard_address_salt`) |

## Snapshots (B6.basic — fast-bootstrap)

| Command | Purpose |
|---|---|
| `determ snapshot create [--out FILE] [--headers N] [--rpc-port N]` | Dump current chain state (accounts/stakes/registrants/dedup + tail headers) |
| `determ snapshot inspect --in FILE [--state-root <hex64>]` | Validate + summarize a snapshot file (round-trip via `restore_from_snapshot` — S-033 + S-038 gates fire on tampered state). Prints `block_index`, `head_hash`, `state_root`, account/stake/registrant counts, and chain parameters. Optional `--state-root` pins an externally-trusted root for trustless-fast-sync verification: prints `✓ matches --state-root` on agreement; exits non-zero with `FAIL` diagnostic if the snapshot's state_root doesn't match the supplied root (defeats a tampered snapshot pointed at a chain the operator doesn't trust). |
| `determ snapshot fetch --peer host:port --out FILE [--headers N]` | Pull a snapshot from a running node over the gossip wire |

To bootstrap from a snapshot, set `snapshot_path` in the node's `config.json` and `determ start`. The node will skip per-block replay and install state directly.

## State commitment + light-client RPC (v2.1 + v2.2)

| Command | Purpose |
|---|---|
| `determ state-root [--rpc-port N]` | Print the chain's Merkle state root + height + head_hash. Returns the live `compute_state_root()` value, which post-S-038 also matches the value stored in the head block's `state_root` field (the producer wires this on every finalized block). Operators can call this against multiple nodes to detect silent state divergence — pre-S-038 a real S-030 D1/D2 attack would manifest at the apply layer only; post-S-038, divergent nodes loud-fail at apply time with a `state_root mismatch` diagnostic before ever producing a divergent block. |
| `determ headers [--from N] [--count M] [--rpc-port P]` | Fetch a slice of block headers (Block JSON minus transactions / cross_shard_receipts / inbound_receipts / initial_state). Light-client header-sync primitive: returned headers carry committee + signatures + tx_root + delay_seed / delay_output + cumulative_rand + state_root for verify-state-proof anchoring, without the bandwidth cost of fetching every tx. Defaults: `--from 0`, `--count 16`. Server caps count at 256 (request larger → returns 256). Out-of-range `--from` returns an empty array (not an error). Returns `{headers, from, count, height}`. |
| `determ state-proof --ns {a\|s\|r\|d\|b\|k\|c} --key <name> [--rpc-port N]` | Fetch a Merkle inclusion proof for any state entry. RPC-exposed namespaces: `a` = accounts, `s` = stakes, `r` = registrants, `d` = DApp registry (v2.18, key = DApp's owning domain), `b` = abort_records (S-032), `k` = genesis-pinned constants, `c` = A1 counters (via the composite `k:c:<name>` lookup). The full ten-namespace state tree (PROTOCOL.md §4.1.1) also has `i/m/p` but those use composite keys and aren't surfaced by this RPC in v2.2. Light-client primitive: the proof verifies against the current `state_root`, which is committed into the head block's `block_hash` (compute_hash via signing_bytes; the chain's `prev_hash` chain transitively authenticates it forward). |
| `determ verify-state-proof [--in <file>] [--state-root <hex64>]` | Local light-client demonstrator: verifies a state-proof response via `crypto::merkle_verify` without trusting the responding node. Reads JSON from `--in` or stdin. Optional `--state-root <hex64>` pins an externally-trusted root (real light-client mode); without it, the proof's self-claimed root is used (self-consistency check). Prints `OK` + structured summary on success; `FAIL` + reason on tampering / mismatch. Pair with `state-proof`: `determ state-proof --ns a --key alice \| determ verify-state-proof --state-root <trusted-hex>`. |

## DApp substrate RPC (v2.18 + v2.19)

The DApp's identity is its owning domain (`tx.from` at registration). There is no separate "dapp_id" — the registered Determ domain IS the dapp identifier. CLI verbs that name a DApp use `--from <domain>` for tx-authoring and `--domain <D>` for queries.

| Command | Purpose |
|---|---|
| `determ submit-dapp-register --priv <hex> --from <domain> --service-pubkey <64hex> --endpoint-url <url> [--topics t1,t2,t3] [--retention 0\|1] [--metadata-hex <hex>] [--fee <N>] [--rpc-port N]` | Register / update a DApp on the chain. Idempotent — re-registering with the same `--from` updates the entry. `--service-pubkey` is the libsodium box pubkey used for end-to-end DAPP_CALL encryption. `--retention 0` = full retention, `1` = pruneable-after-K. |
| `determ submit-dapp-register --priv <hex> --from <domain> --deactivate [--fee <N>] [--rpc-port N]` | Deactivate the DApp owned by `--from`. Sets `inactive_from = current_height + DAPP_GRACE_BLOCKS`; in-flight calls finish within the grace window. |
| `determ submit-dapp-call --priv <hex> --from <sender> --to <dapp-domain> [--topic <T>] [--payload-hex <hex>] [--amount <N>] [--fee <N>] [--rpc-port N]` | Submit a DAPP_CALL routed to `--to`. `--topic` must match one of the DApp's registered topics (or `""`). `--payload-hex` is the application's opaque ciphertext (typically AEAD(`service_pubkey`, plaintext, nonce); ≤ 16 KB). `--amount` is an optional payment credited to the DApp's account. |
| `determ dapp-list [--prefix P] [--topic T] [--rpc-port N]` | List registered DApps. Optional `--prefix` filters by domain prefix; `--topic` keeps only DApps whose registered topic list contains a match. |
| `determ dapp-info --domain <D> [--rpc-port N]` | Per-DApp record: `domain`, `service_pubkey`, `endpoint_url`, `topics`, `retention`, `metadata`, `registered_at`, `active_from`, `inactive_from`. |
| `determ dapp-messages --domain <D> [--from <H>] [--to <H>] [--topic <T>] [--rpc-port N]` | Retrospective DAPP_CALL poll. Returns up to 256 events (`DAPP_MESSAGES_PAGE_LIMIT`) in `[from, to]` addressed to `--domain`, optionally topic-filtered. Use the response's `last_scanned + 1` as the next `--from` to paginate. |

## In-process tests (test-* CLI subcommands)

These are deterministic, network-free smoke tests embedded as CLI subcommands. They build an in-process chain + node and assert protocol invariants. Each `tools/test_*.sh` shell script invokes the corresponding `determ test-*` subcommand and asserts the result.

| Command | Purpose | Paired shell test |
|---|---|---|
| `determ test-atomic-scope` | A9 Phase 2D nested-scope rollback primitive | `tools/test_atomic_scope.sh` |
| `determ test-composable-batch` | COMPOSABLE_BATCH all-or-nothing semantics under partial failure | `tools/test_composable_batch.sh` |
| `determ test-dapp-register` | v2.18 DAPP_REGISTER apply path | `tools/test_dapp_register.sh` |
| `determ test-dapp-call` | v2.19 DAPP_CALL routing + apply path | `tools/test_dapp_call.sh` |
| `determ test-s018-json-validation` | S-018 closure: `json_require<T>` / `json_require_hex` helpers + converted `from_json` paths across `chain/block.cpp` + `node/producer.cpp` + `chain/genesis.cpp` + `net/messages.cpp` + `crypto/keys.cpp` surface clear field-name diagnostics on malformed gossip / RPC / snapshot / keyfile input (9 assertions) | `tools/test_s018_json_validation.sh` |

## Forensics / governance

| Command / RPC | Purpose |
|---|---|
| RPC `submit_equivocation { event }` | External submission of equivocation evidence (validates two-sig proof, gossips for slashing) |

There's no built-in CLI wrapper for the equivocation RPC — see `tools/test_equivocation_slashing.sh` for a Python template that synthesizes evidence and submits via raw JSON-RPC.

### Governance (A5)

| Command | Purpose |
|---|---|
| `determ submit-param-change --priv <hex> --from <domain> --name <NAME> --value-hex <hex> --effective-height <N> --keyholder-sig <idx>:<priv_hex> [--keyholder-sig ...] [--fee N] [--rpc-port N]` | Sign + submit a `PARAM_CHANGE` tx. `--name` must be on the validator whitelist (MIN_STAKE, SUSPENSION_SLASH, UNSTAKE_DELAY, bft_escalation_threshold, tx_commit_ms, block_sig_ms, abort_claim_ms, param_keyholders, param_threshold). Each `--keyholder-sig` supplies one signature; threshold must be met. Sender (`--from`) is a registered domain that pays the fee. See `tools/test_governance_param_change.sh` for an end-to-end example. |

Genesis fields enabling governance:
- `governance_mode: 0` (uncontrolled, default) or `1` (governed)
- `param_keyholders: [<hex pubkey>, ...]` (Ed25519 founder set)
- `param_threshold: <N>` (default N-of-N when keyholders are set)

### Under-quorum merge (R4)

| Command | Purpose |
|---|---|
| `determ submit-merge-event --priv <hex> --from <domain> --event {begin\|end} --shard-id N --partner-id N --effective-height N --evidence-window-start N [--refugee-region <region>] [--fee N] [--rpc-port N]` | Sign + submit a `MERGE_EVENT` tx. Requires `sharding_mode == EXTENDED`. Operator-driven for v1.x; auto-detection on the beacon is a v1.1 work item. See `tools/test_under_quorum_merge.sh`. |

Genesis thresholds:
- `merge_threshold_blocks` (default 100) — consecutive blocks of `eligible_in_region < 2K` before `MERGE_BEGIN` validates.
- `revert_threshold_blocks` (default 200) — 2:1 hysteresis on the way back.
- `merge_grace_blocks` (default 10) — gap between block height and `effective_height`.

## Common flags

- `--rpc-port N` — connect to an RPC port other than the config default (useful when running multiple nodes locally).
- `--data-dir D` — point at a non-default data directory.

## Operator config fields (`config.json`)

The node's `config.json` (generated by `determ init`) carries the runtime knobs. Live values are visible at `determ status` → `protections` block. The most operationally-relevant entries:

### Network / consensus

| Field | Default | Purpose |
|---|---|---|
| `domain` | (required) | This node's registered identity (must match a `genesis.initial_creators` entry) |
| `data_dir` | (CWD) | Root for chain.json / keyfile / snapshot output |
| `listen_port` | 7777 | Gossip listen port |
| `rpc_port` | 7778 | RPC listen port |
| `bootstrap_peers` | `[]` | Initial intra-chain peers (e.g. `["127.0.0.1:7771","127.0.0.1:7772"]`) |
| `beacon_peers` | `[]` | Cross-chain peers for SHARD-role nodes (beacon addresses) — role-filtered, isolated from `bootstrap_peers` traffic |
| `shard_peers` | `[]` | Cross-chain peers for BEACON-role nodes (shard addresses) — role-filtered |
| `m_creators` | 3 | Committee size K (genesis-pinned at chain init; per-node override rejected) |
| `k_block_sigs` | 3 | Phase-2 threshold (genesis-pinned; K = M = strong BFT, K < M = weak hybrid) |
| `bft_enabled` | true | Per-height BFT escalation after `bft_escalation_threshold` aborts |
| `bft_escalation_threshold` | 5 | Round-1 + Round-2 abort count that triggers BFT mode (governance-mutable) |
| `tx_commit_ms` / `block_sig_ms` / `abort_claim_ms` | 200/200/100 | Round timer durations |
| `chain_role` / `sharding_mode` / `shard_id` / `committee_region` | `single`/`current`/0/`""` | Sharding posture (genesis-pinned) |
| `initial_shard_count` | 1 | Number of shards S in this deployment (genesis-pinned) |
| `epoch_blocks` | 1000 | Committee re-seeding period (genesis-pinned) |
| `region` | `""` | This validator's self-declared region tag (R1 — mirrored into REGISTER payload). Must match the chain's `committee_region` to be selected for committees under EXTENDED sharding |

### RPC security (S-001 / S-014 / v2.16)

| Field | Default | Purpose |
|---|---|---|
| `rpc_localhost_only` | `true` | Bind RPC to 127.0.0.1 only (S-001) — flip to `false` ONLY with `rpc_auth_secret` set, or behind a reverse proxy with auth |
| `rpc_auth_secret` | `""` | Hex-encoded shared secret for HMAC-SHA-256 RPC auth (v2.16); empty = no auth. Generate with `openssl rand -hex 32` |
| `rpc_rate_per_sec` | 0 | RPC calls/sec per peer-IP token bucket (S-014 RPC side); 0 = disabled. Suggested external-bind: 100 |
| `rpc_rate_burst` | 0 | Bucket capacity; 0 = disabled. Suggested external-bind: 200 |

### Gossip security (S-014 / S-022 / S-026)

| Field | Default | Purpose |
|---|---|---|
| `gossip_rate_per_sec` | 0 | Inbound-message rate cap per peer-IP (S-014 gossip side); 0 = disabled. Suggested external-bind: 500 |
| `gossip_rate_burst` | 0 | Bucket capacity; 0 = disabled. Suggested external-bind: 1000 |

(S-022 per-message-type body cap and S-026 TCP keepalive are unconditional — no operator knob; see `docs/SECURITY.md` §S-022 + §S-026.)

### Operator hygiene (S-027)

| Field | Default | Purpose |
|---|---|---|
| `log_quiet` | `false` | When `true`, suppress per-block / per-bundle / per-connection diagnostic lines. WARN/ERROR diagnostics surface regardless. Production deployments wanting fewer logs set this to `true` |

### Paths

| Field | Purpose |
|---|---|
| `domain` | This node's registered identity (must match a `genesis.initial_creators` entry) |
| `genesis_path` / `genesis_hash` | Authoritative genesis file + pinned hash for eclipse defense |
| `chain_path` | On-disk chain.json — wrapped `{head_hash, blocks}` form post-S-021 |
| `key_path` | Node's Ed25519 keypair (0600 permissions) |
| `snapshot_path` | If set on a fresh node, bootstrap from this snapshot instead of replaying from genesis |
| `shard_manifest_path` | BEACON-role nodes: per-shard committee_region map (required in EXTENDED mode) |

A live readback of which protections are active is in `determ status` → `protections` (see top of this doc). Wallet keys live separately in `determ-wallet` keyfiles (encrypted at rest via v2.17 AES-256-GCM envelope; see `determ-wallet` section below).

## determ-wallet binary (A2)

Separate executable from the `determ` daemon. Secret material never enters the chain daemon's address space — by design. The wallet handles the user's Ed25519 seed and threshold recovery; the daemon never sees them.

### Primitive layers

| Command | Purpose |
|---|---|
| `determ-wallet shamir split <hex> -t T -n N` | Split a secret into N Shamir shares with threshold T. Shares print one per line as `<x_hex>:<y_hex>`. |
| `determ-wallet shamir combine <share> [<share> ...]` | Reconstruct from ≥ T shares. Returns the original secret hex. |
| `determ-wallet envelope encrypt --plaintext <hex> --password <str> [--aad <hex>] [--iters N]` | AEAD-wrap arbitrary data (AES-256-GCM, PBKDF2-HMAC-SHA-256 keying, default 600k iters). |
| `determ-wallet envelope decrypt --envelope <blob> --password <str> [--aad <hex>]` | Unwrap. Returns plaintext hex; exit code 2 on AEAD tag failure. |

### Recovery flows

| Command | Purpose |
|---|---|
| `determ-wallet create-recovery --seed <hex> --password <str> -t T -n N --out <file> [--scheme {passphrase\|opaque}]` | Persist a T-of-N recovery setup as a single JSON document. Scheme `passphrase` (default) uses PBKDF2 directly off the password; scheme `opaque` routes through the OPAQUE adapter. |
| `determ-wallet recover --in <file> --password <str> [--guardians <i,j,k,...>]` | Reconstruct the seed from ≥ T envelopes. Scheme is auto-detected from the setup. Optional pubkey checksum gate prevents silent corruption. |

### OPAQUE primitives (diagnostic)

| Command | Purpose |
|---|---|
| `determ-wallet oprf-smoke` | Smoke-test libsodium primitives (ristretto255 scalar/point ops + Argon2id). Outputs sample scalars + a blinded point + a stretched key. |
| `determ-wallet opaque-handshake --mode {register\|authenticate} --password <str> --guardian-id <0..255> [--record <hex>]` | Exercise the OPAQUE adapter directly. Currently the **development stub** adapter; the real `libopaque` integration is tracked as **v2.14** (real OPAQUE wallet recovery) in `docs/V2-DESIGN.md`. See `wallet/PHASE6_PORTING_NOTES.md` for the MSVC porting status that gates the v2.14 ship. |
| `determ-wallet version` | Print version banner including current adapter suite name. |

### Adapter status check

The wallet's `is_stub()` flag exposes whether the linked OPAQUE adapter is the development stub or the real `libopaque` implementation (v2.14). The stub is offline-grindable against a compromised guardian — see `docs/proofs/WalletRecovery.md` (FA12) for the concrete-security bounds. The v2.14 ship replaces the stub with the real construction; once that lands, this `is_stub()` returns `false` for production builds. The wallet binary's `version` command surfaces the active suite tag.

## Exit codes

- `0` — success
- `1` — parsing error, missing argument, RPC failure, or assertion failure
- `2` — cryptographic failure (AEAD tag mismatch, OPAQUE authentication rejected, recovery reconstruction failed)
