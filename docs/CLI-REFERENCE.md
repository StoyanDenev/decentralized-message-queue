# Unchained CLI Reference

All `unchained` subcommands. Run `unchained --help` for the canonical built-in help.

**See also:** [`QUICKSTART.md`](QUICKSTART.md) for hands-on recipes, [`PROTOCOL.md`](PROTOCOL.md) for wire formats, [`WHITEPAPER-v1.x.md`](WHITEPAPER-v1.x.md) for the standalone technical paper.

## Node lifecycle

| Command | Purpose |
|---|---|
| `unchained init [--data-dir D] [--profile P]` | Generate config + Ed25519 keypair in a fresh data dir |
| `unchained start --config FILE` | Run the node daemon (foreground) |

Profiles: `cluster` (LAN), `web` (default), `regional`, `global` — differ in round timer durations (`tx_commit_ms`, `block_sig_ms`, `abort_claim_ms`).

## Inspection (block-explorer)

All inspection commands hit the running node's RPC. Default RPC port is in the node's config.

| Command | Returns |
|---|---|
| `unchained status [--rpc-port N]` | Chain head, head_hash, role, shard_id, epoch_index, peer_count, mempool, mode counters |
| `unchained peers [--rpc-port N]` | Connected peer addresses |
| `unchained show-block <i> [--rpc-port N]` | Full block JSON at index `i` |
| `unchained chain-summary [--last N] [--rpc-port N]` | Compact view of last `N` blocks (default 10) |
| `unchained validators [--rpc-port N]` | Registered validator pool (domain, ed_pub, stake, active_from) |
| `unchained committee [--rpc-port N]` | Current epoch's K-of-K committee (deterministic from chain state) |
| `unchained show-account <addr> [--rpc-port N]` | Balance + nonce + registry record + stake for any address |
| `unchained show-tx <hash> [--rpc-port N]` | Locate a tx in a finalized block (block_index + payload) |
| `unchained balance <domain> [--rpc-port N]` | Balance only |
| `unchained nonce <domain> [--rpc-port N]` | Next expected nonce |
| `unchained stake_info <domain> [--rpc-port N]` | Locked stake + unlock_height |

## Wallet / transactions

### Anonymous bearer wallets

| Command | Purpose |
|---|---|
| `unchained account create --out FILE [--allow-plaintext-stdout]` | Generate a fresh Ed25519 key + `0x`-prefixed bearer address. `--out` writes to a 0600-permissioned file. Bare `account create` (no `--out`) is refused (S-004); opt in to stdout via `--allow-plaintext-stdout`. |
| `unchained account address <privkey_hex>` | Derive address from priv-key (offline, no daemon) |
| `unchained send_anon <to> <amount> <privkey_hex> [--fee N] [--rpc-port N]` | Build, sign, submit a TRANSFER from a bearer wallet |

### Domain-authored (registered validator)

| Command | Purpose |
|---|---|
| `unchained register --rpc-port N` | Register this node's domain (RPC host's key) |
| `unchained send <to> <amount> [--fee N] [--rpc-port N]` | TRANSFER from this node's domain |
| `unchained stake <amount> [--rpc-port N]` | Lock balance into stake |
| `unchained unstake <amount> [--rpc-port N]` | Begin unstake (subject to UNSTAKE_DELAY) |

## Genesis tooling

| Command | Purpose |
|---|---|
| `unchained genesis-tool peer-info <domain> --data-dir D --stake N` | Emit JSON snippet for `initial_creators` |
| `unchained genesis-tool build <config.json>` | Compute genesis block + write `.hash` sidecar |
| `unchained genesis-tool build-sharded <config.json>` | Produce 1 beacon + S shard genesis files (with shared `shard_address_salt`) |

## Snapshots (B6.basic — fast-bootstrap)

| Command | Purpose |
|---|---|
| `unchained snapshot create [--out FILE] [--headers N] [--rpc-port N]` | Dump current chain state (accounts/stakes/registrants/dedup + tail headers) |
| `unchained snapshot inspect --in FILE` | Validate + summarize a snapshot file (round-trip via `restore_from_snapshot`) |
| `unchained snapshot fetch --peer host:port --out FILE [--headers N]` | Pull a snapshot from a running node over the gossip wire |

To bootstrap from a snapshot, set `snapshot_path` in the node's `config.json` and `unchained start`. The node will skip per-block replay and install state directly.

## Forensics / governance

| Command / RPC | Purpose |
|---|---|
| RPC `submit_equivocation { event }` | External submission of equivocation evidence (validates two-sig proof, gossips for slashing) |

There's no built-in CLI wrapper for the equivocation RPC — see `tools/test_equivocation_slashing.sh` for a Python template that synthesizes evidence and submits via raw JSON-RPC.

### Governance (A5)

| Command | Purpose |
|---|---|
| `unchained submit-param-change --priv <hex> --from <domain> --name <NAME> --value-hex <hex> --effective-height <N> --keyholder-sig <idx>:<priv_hex> [--keyholder-sig ...] [--fee N] [--rpc-port N]` | Sign + submit a `PARAM_CHANGE` tx. `--name` must be on the validator whitelist (MIN_STAKE, SUSPENSION_SLASH, UNSTAKE_DELAY, bft_escalation_threshold, tx_commit_ms, block_sig_ms, abort_claim_ms, param_keyholders, param_threshold). Each `--keyholder-sig` supplies one signature; threshold must be met. Sender (`--from`) is a registered domain that pays the fee. See `tools/test_governance_param_change.sh` for an end-to-end example. |

Genesis fields enabling governance:
- `governance_mode: 0` (uncontrolled, default) or `1` (governed)
- `param_keyholders: [<hex pubkey>, ...]` (Ed25519 founder set)
- `param_threshold: <N>` (default N-of-N when keyholders are set)

### Under-quorum merge (R4)

| Command | Purpose |
|---|---|
| `unchained submit-merge-event --priv <hex> --from <domain> --event {begin\|end} --shard-id N --partner-id N --effective-height N --evidence-window-start N [--refugee-region <region>] [--fee N] [--rpc-port N]` | Sign + submit a `MERGE_EVENT` tx. Requires `sharding_mode == EXTENDED`. Operator-driven for v1.x; auto-detection on the beacon is a v1.1 work item. See `tools/test_under_quorum_merge.sh`. |

Genesis thresholds:
- `merge_threshold_blocks` (default 100) — consecutive blocks of `eligible_in_region < 2K` before `MERGE_BEGIN` validates.
- `revert_threshold_blocks` (default 200) — 2:1 hysteresis on the way back.
- `merge_grace_blocks` (default 10) — gap between block height and `effective_height`.

## Common flags

- `--rpc-port N` — connect to an RPC port other than the config default (useful when running multiple nodes locally).
- `--data-dir D` — point at a non-default data directory.

## unchained-wallet binary (A2)

Separate executable from the `unchained` daemon. Secret material never enters the chain daemon's address space — by design. The wallet handles the user's Ed25519 seed and threshold recovery; the daemon never sees them.

### Primitive layers

| Command | Purpose |
|---|---|
| `unchained-wallet shamir split <hex> -t T -n N` | Split a secret into N Shamir shares with threshold T. Shares print one per line as `<x_hex>:<y_hex>`. |
| `unchained-wallet shamir combine <share> [<share> ...]` | Reconstruct from ≥ T shares. Returns the original secret hex. |
| `unchained-wallet envelope encrypt --plaintext <hex> --password <str> [--aad <hex>] [--iters N]` | AEAD-wrap arbitrary data (AES-256-GCM, PBKDF2-HMAC-SHA-256 keying, default 600k iters). |
| `unchained-wallet envelope decrypt --envelope <blob> --password <str> [--aad <hex>]` | Unwrap. Returns plaintext hex; exit code 2 on AEAD tag failure. |

### Recovery flows

| Command | Purpose |
|---|---|
| `unchained-wallet create-recovery --seed <hex> --password <str> -t T -n N --out <file> [--scheme {passphrase\|opaque}]` | Persist a T-of-N recovery setup as a single JSON document. Scheme `passphrase` (default) uses PBKDF2 directly off the password; scheme `opaque` routes through the OPAQUE adapter. |
| `unchained-wallet recover --in <file> --password <str> [--guardians <i,j,k,...>]` | Reconstruct the seed from ≥ T envelopes. Scheme is auto-detected from the setup. Optional pubkey checksum gate prevents silent corruption. |

### OPAQUE primitives (diagnostic)

| Command | Purpose |
|---|---|
| `unchained-wallet oprf-smoke` | Smoke-test libsodium primitives (ristretto255 scalar/point ops + Argon2id). Outputs sample scalars + a blinded point + a stretched key. |
| `unchained-wallet opaque-handshake --mode {register\|authenticate} --password <str> --guardian-id <0..255> [--record <hex>]` | Exercise the OPAQUE adapter directly. Stub adapter today (Phase 5); real libopaque pending Phase 6.1 MSVC porting (see `wallet/PHASE6_PORTING_NOTES.md`). |
| `unchained-wallet version` | Print version banner including current adapter suite name. |

### Phase status check

The wallet's `is_stub()` flag exposes whether the linked OPAQUE adapter is the development stub (Phase 5) or the real libopaque implementation (Phase 6+). The stub is offline-grindable against a compromised guardian — see `docs/proofs/WalletRecovery.md` (FA12) for the concrete-security bounds and `wallet/PHASE6_PORTING_NOTES.md` for the integration status. The wallet binary's `version` command surfaces the active suite tag.

## Exit codes

- `0` — success
- `1` — parsing error, missing argument, RPC failure, or assertion failure
- `2` — cryptographic failure (AEAD tag mismatch, OPAQUE authentication rejected, recovery reconstruction failed)
