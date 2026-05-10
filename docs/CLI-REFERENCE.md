# DHCoin CLI Reference

All `dhcoin` subcommands. Run `dhcoin --help` for the canonical built-in help.

## Node lifecycle

| Command | Purpose |
|---|---|
| `dhcoin init [--data-dir D] [--profile P]` | Generate config + Ed25519 keypair in a fresh data dir |
| `dhcoin start --config FILE` | Run the node daemon (foreground) |

Profiles: `cluster` (LAN), `web` (default), `regional`, `global` — differ in round timer durations (`tx_commit_ms`, `block_sig_ms`, `abort_claim_ms`).

## Inspection (block-explorer)

All inspection commands hit the running node's RPC. Default RPC port is in the node's config.

| Command | Returns |
|---|---|
| `dhcoin status [--rpc-port N]` | Chain head, head_hash, role, shard_id, epoch_index, peer_count, mempool, mode counters |
| `dhcoin peers [--rpc-port N]` | Connected peer addresses |
| `dhcoin show-block <i> [--rpc-port N]` | Full block JSON at index `i` |
| `dhcoin chain-summary [--last N] [--rpc-port N]` | Compact view of last `N` blocks (default 10) |
| `dhcoin validators [--rpc-port N]` | Registered validator pool (domain, ed_pub, stake, active_from) |
| `dhcoin committee [--rpc-port N]` | Current epoch's K-of-K committee (deterministic from chain state) |
| `dhcoin show-account <addr> [--rpc-port N]` | Balance + nonce + registry record + stake for any address |
| `dhcoin show-tx <hash> [--rpc-port N]` | Locate a tx in a finalized block (block_index + payload) |
| `dhcoin balance <domain> [--rpc-port N]` | Balance only |
| `dhcoin nonce <domain> [--rpc-port N]` | Next expected nonce |
| `dhcoin stake_info <domain> [--rpc-port N]` | Locked stake + unlock_height |

## Wallet / transactions

### Anonymous bearer wallets

| Command | Purpose |
|---|---|
| `dhcoin account create [--out FILE]` | Generate a fresh Ed25519 key + `0x`-prefixed bearer address |
| `dhcoin account address <privkey_hex>` | Derive address from priv-key (offline, no daemon) |
| `dhcoin send_anon <to> <amount> <privkey_hex> [--fee N] [--rpc-port N]` | Build, sign, submit a TRANSFER from a bearer wallet |

### Domain-authored (registered validator)

| Command | Purpose |
|---|---|
| `dhcoin register --rpc-port N` | Register this node's domain (RPC host's key) |
| `dhcoin send <to> <amount> [--fee N] [--rpc-port N]` | TRANSFER from this node's domain |
| `dhcoin stake <amount> [--rpc-port N]` | Lock balance into stake |
| `dhcoin unstake <amount> [--rpc-port N]` | Begin unstake (subject to UNSTAKE_DELAY) |

## Genesis tooling

| Command | Purpose |
|---|---|
| `dhcoin genesis-tool peer-info <domain> --data-dir D --stake N` | Emit JSON snippet for `initial_creators` |
| `dhcoin genesis-tool build <config.json>` | Compute genesis block + write `.hash` sidecar |
| `dhcoin genesis-tool build-sharded <config.json>` | Produce 1 beacon + S shard genesis files (with shared `shard_address_salt`) |

## Snapshots (B6.basic — fast-bootstrap)

| Command | Purpose |
|---|---|
| `dhcoin snapshot create [--out FILE] [--headers N] [--rpc-port N]` | Dump current chain state (accounts/stakes/registrants/dedup + tail headers) |
| `dhcoin snapshot inspect --in FILE` | Validate + summarize a snapshot file (round-trip via `restore_from_snapshot`) |
| `dhcoin snapshot fetch --peer host:port --out FILE [--headers N]` | Pull a snapshot from a running node over the gossip wire |

To bootstrap from a snapshot, set `snapshot_path` in the node's `config.json` and `dhcoin start`. The node will skip per-block replay and install state directly.

## Forensics / governance

| Command / RPC | Purpose |
|---|---|
| RPC `submit_equivocation { event }` | External submission of equivocation evidence (validates two-sig proof, gossips for slashing) |

There's no built-in CLI wrapper for this yet — see `tools/test_equivocation_slashing.sh` for a Python template that synthesizes evidence and submits via raw JSON-RPC.

## Common flags

- `--rpc-port N` — connect to an RPC port other than the config default (useful when running multiple nodes locally).
- `--data-dir D` — point at a non-default data directory.

## Exit codes

- `0` — success
- `1` — parsing error, missing argument, RPC failure, or assertion failure
