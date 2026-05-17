# Determ CLI Reference

All `determ` subcommands. Run `determ --help` for the canonical built-in help.

**See also:** [`QUICKSTART.md`](QUICKSTART.md) for hands-on recipes, [`PROTOCOL.md`](PROTOCOL.md) for wire formats, [`WHITEPAPER-v1.x.md`](WHITEPAPER-v1.x.md) for the standalone technical paper.

## Node lifecycle

| Command | Purpose |
|---|---|
| `determ init [--data-dir D] [--profile P]` | Generate config + Ed25519 keypair in a fresh data dir |
| `determ start --config FILE` | Run the node daemon (foreground) |

Profiles: `cluster` (LAN), `web` (default), `regional`, `global`, `tactical` (mobile-unit swarm; sub-30 ms blocks), plus `*_test` variants (`single_test`, `cluster_test`, `web_test`, `regional_test`, `global_test`, `tactical_test`) with sub-30 ms timers for CI execution mirroring each prod sibling's (chain_role, sharding_mode, M, K). Differ in round timer durations (`tx_commit_ms`, `block_sig_ms`, `abort_claim_ms`) + committee size (M, K) + chain_role + sharding_mode. See `include/determ/chain/params.hpp` for the full profile-constant set.

## Inspection (block-explorer)

All inspection commands hit the running node's RPC. Default RPC port is in the node's config.

| Command | Returns |
|---|---|
| `determ status [--rpc-port N]` | Chain head, head_hash, role, shard_id, epoch_index, peer_count, mempool, mode counters + `protections` block (current state of every operator-tunable security/log flag — `rpc_localhost_only`, `rpc_hmac_auth`, `rpc_rate_limit`, `gossip_rate_limit`, `log_quiet`, `bft_enabled`, `sharding_mode`). Monitoring systems can alert on flag drift in production. |
| `determ peers [--json] [--rpc-port N]` | Connected peer addresses. Default: one host:port per line. `--json` emits the raw RPC array (`["host:port", ...]`). |
| `determ show-block <i> [--rpc-port N]` | Full block JSON at index `i` |
| `determ chain-summary [--last N] [--json] [--rpc-port N]` | Compact view of last `N` blocks (default 10). `--json` emits the raw RPC response (`{blocks: [...], height, total_supply, genesis_total, accumulated_subsidy, accumulated_inbound, accumulated_slashed, accumulated_outbound}` — the A1 unitary-supply counters). |
| `determ validators [--json] [--rpc-port N]` | Registered validator pool (domain, ed_pub, stake, active_from). Default: human-readable table. `--json` emits the raw RPC array verbatim — feeds directly into `verify-block-sigs --committee` for light-client K-of-K verification. |
| `determ committee [--json] [--rpc-port N]` | Current epoch's K-of-K committee (deterministic from chain state). `--json` flag same as for `validators` — emits the raw RPC array shape `verify-block-sigs --committee` consumes. |
| `determ show-account <addr> [--rpc-port N] [--json]` | Balance + nonce + registry record + stake for any address. Default human-readable; `--json` pass-throughs the raw RPC envelope for script consumption. Empty result → `{}` (JSON) or `(no on-chain state for X)` (human). |
| `determ show-tx <hash> [--rpc-port N] [--json]` | Locate a tx in a finalized block (block_index + payload). Default human-readable; `--json` pass-throughs the raw RPC envelope. Empty result → `{}` (JSON) or `(tx ... not found ...)` (human). |
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
| `determ snapshot inspect --in FILE [--state-root <hex64>] [--json]` | Validate + summarize a snapshot file (round-trip via `restore_from_snapshot` — S-033 + S-038 gates fire on tampered state). Prints `block_index`, `head_hash`, `state_root`, account/stake/registrant counts, and chain parameters. Optional `--state-root` pins an externally-trusted root for trustless-fast-sync verification: prints `✓ matches --state-root` on agreement; exits non-zero with `FAIL` diagnostic if the snapshot's state_root doesn't match the supplied root (defeats a tampered snapshot pointed at a chain the operator doesn't trust). Optional `--json` emits a single-line JSON object with the same data for script consumption (`{"status":"ok","block_index":N,"head_hash":"...","state_root":"...","accounts":N,...}`); error cases also emit JSON (`{"error":"cannot_open"|"invalid_state_root_length"|"state_root_mismatch"|"exception","..."}`). Useful for bootstrap-orchestrator pipelines that consume snapshot verification results. |
| `determ snapshot fetch --peer host:port --out FILE [--headers N]` | Pull a snapshot from a running node over the gossip wire |

To bootstrap from a snapshot, set `snapshot_path` in the node's `config.json` and `determ start`. The node will skip per-block replay and install state directly.

## State commitment + light-client RPC (v2.1 + v2.2)

| Command | Purpose |
|---|---|
| `determ state-root [--rpc-port N]` | Print the chain's Merkle state root + height + head_hash. Returns the live `compute_state_root()` value, which post-S-038 also matches the value stored in the head block's `state_root` field (the producer wires this on every finalized block). Operators can call this against multiple nodes to detect silent state divergence — pre-S-038 a real S-030 D1/D2 attack would manifest at the apply layer only; post-S-038, divergent nodes loud-fail at apply time with a `state_root mismatch` diagnostic before ever producing a divergent block. |
| `determ headers [--from N] [--count M] [--rpc-port P]` | Fetch a slice of block headers (Block JSON minus transactions / cross_shard_receipts / inbound_receipts / initial_state). Light-client header-sync primitive: returned headers carry committee + signatures + tx_root + delay_seed / delay_output + cumulative_rand + state_root for verify-state-proof anchoring, plus an explicit `block_hash` per header so the prev_hash chain is verifiable without re-deriving compute_hash (which needs the stripped heavy fields). Defaults: `--from 0`, `--count 16`. Server caps count at 256. Out-of-range `--from` returns an empty array (not an error). Returns `{headers, from, count, height}`. |
| `determ verify-headers [--in <file>] [--genesis-hash <hex64>] [--prev-hash <hex64>]` | Verify the prev_hash chain in a `determ headers` response. Reads JSON from `--in` or stdin. Walks consecutive header pairs and asserts `header[i].prev_hash == header[i-1].block_hash`. Optional anchors: `--genesis-hash` checks against the genesis block_hash when the slice starts at index 0; `--prev-hash` anchors a non-genesis slice (= block_hash of the block immediately before the slice). Without an anchor, the first header's prev_hash is unanchored — internal chain links still verified. Pure chain-of-hashes integrity check (does NOT verify committee signatures; use `verify-block-sigs` for that). |
| `determ verify-block-sigs --header <file> --committee <file> [--bft]` | Verify K-of-K committee Ed25519 signatures on a single block header. Reads the header from `--header` (accepts either a single-block JSON or a `determ headers` envelope — extracts the first header from envelope shape) and a committee pubkey map from `--committee` (a JSON array of `{domain, ed_pub}` entries, or `{members: [...]}` envelope shape — `determ validators --json` and `determ committee --json` both emit this shape directly). Computes `compute_block_digest(b)` over the header fields and verifies each `creators[i]`'s `creator_block_sigs[i]` against the looked-up pubkey. MD mode requires every signature; `--bft` allows up to `K - ceil(2K/3)` sentinel-zero slots. Together with `verify-headers` (chain integrity) + `verify-state-proof` (per-field state), this completes the v2.2 trustless light-client verification chain: fetch headers from any source, verify chain links + committee signatures locally, anchor state_root from a verified header, verify state-proofs against that root. |
| `determ state-proof --ns {a\|s\|r\|d\|b\|k\|c} --key <name> [--rpc-port N]` | Fetch a Merkle inclusion proof for any state entry. RPC-exposed namespaces: `a` = accounts, `s` = stakes, `r` = registrants, `d` = DApp registry (v2.18, key = DApp's owning domain), `b` = abort_records (S-032), `k` = genesis-pinned constants, `c` = A1 counters (via the composite `k:c:<name>` lookup). The full ten-namespace state tree (PROTOCOL.md §4.1.1) also has `i/m/p` but those use composite keys and aren't surfaced by this RPC in v2.2. Light-client primitive: the proof verifies against the current `state_root`, which is committed into the head block's `block_hash` (compute_hash via signing_bytes; the chain's `prev_hash` chain transitively authenticates it forward). |
| `determ verify-state-proof [--in <file>] [--state-root <hex64>]` | Local light-client demonstrator: verifies a state-proof response via `crypto::merkle_verify` without trusting the responding node. Reads JSON from `--in` or stdin. Optional `--state-root <hex64>` pins an externally-trusted root (real light-client mode); without it, the proof's self-claimed root is used (self-consistency check). Prints `OK` + structured summary on success; `FAIL` + reason on tampering / mismatch. Pair with `state-proof`: `determ state-proof --ns a --key alice \| determ verify-state-proof --state-root <trusted-hex>`. |
| `determ verify-genesis --in <file> [--expected-hash <hex64>] [--json]` | Standalone genesis.json validator. Loads, applies the same parsing + sane-bounds checks as `determ start` (LOTTERY-multiplier ≥ 2 if subsidy_mode == LOTTERY, block_subsidy / subsidy_pool_initial / zeroth_pool_initial ≤ 1e18, lottery_multiplier × block_subsidy ≤ 1e18, genesis_message ≤ 256 bytes), computes the chain-identity hash via `compute_genesis_hash`, prints a structured summary. Default output is human-readable; `--json` emits a single-line JSON object for script consumption (`{"status":"ok","genesis_hash":"...","chain_id":"...","m_creators":N,...}`). Optional `--expected-hash <hex64>` pins against an externally-trusted value — exits non-zero with a clear diagnostic when computed hash doesn't match (defeats config-rewrite attacks where a deployment template smuggles in a different chain identity). The output explicitly distinguishes operational params NOT bound to identity hash (m_creators / k_block_sigs / block_subsidy / min_stake / initial_shard_count / bft_enabled — see S-039 in `docs/SECURITY.md`) from identity-bound fields (genesis_message / committee_region), so operators can spot mismatches in unbinded fields by direct inspection. Workflows: pre-deployment validation, cross-team coordination on chain identity, cluster onboarding. |

### Complete v2.2 trustless light-client verification flow

The seven CLIs above (`state-root`, `headers`, `verify-headers`, `verify-block-sigs`, `state-proof`, `verify-state-proof`, plus `validators --json` / `committee --json` for committee pubkey export) compose into an end-to-end trustless verification pipeline. Each step verifies a different property locally without trusting the responding node, gated only by an externally-pinned `--state-root` / committee pubkey set:

```bash
# 1. Fetch recent headers (untrusted full node OK; we'll verify them).
$DETERM headers --rpc-port 8771 --from 0 --count 100 > headers.json

# 2. Verify the prev_hash chain (catches re-ordered / spliced headers).
$DETERM verify-headers --in headers.json   # OK on valid chain

# 3. Get the committee pubkeys for K-of-K signature verification.
#    For genesis-pinned light clients, the operator hard-codes this set;
#    for chains using key rotation, derive from a previously-verified
#    state-proof of the registrants_ map (namespace `r`).
$DETERM validators --rpc-port 8771 --json > committee.json

# 4. Verify K-of-K committee signatures on each header.
$DETERM verify-block-sigs --header headers.json --committee committee.json

# 5. Extract a verified state_root from one of the headers (any will do
#    since we've verified the chain links + signatures).
STATE_ROOT=$(jq -r '.headers[-1].state_root' headers.json)

# 6. Verify any state field against the pinned state_root.
$DETERM state-proof --rpc-port 8771 --ns a --key alice > proof.json
$DETERM verify-state-proof --in proof.json --state-root "$STATE_ROOT"

# 7. (Alternative for whole-state) Verify a downloaded snapshot.
$DETERM snapshot inspect --in snapshot.json --state-root "$STATE_ROOT"
```

What this proves: a malicious full node serving headers / state-proofs / snapshots is caught at one of these checks. The trust chain bottoms out at the externally-pinned committee + the chain-of-hashes link from the verified header forward; the state_root anchor defeats fabricated-root attacks; the committee-sig check defeats forged-header attacks; the prev_hash chain check defeats spliced-header attacks.

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
| `determ test-s018-json-validation` | S-018 closure: `json_require<T>` / `json_require_hex` / `json_require_array` helpers + converted `from_json` paths across `chain/block.cpp` + `node/producer.cpp` + `chain/genesis.cpp` + `net/messages.cpp` + `crypto/keys.cpp` surface clear field-name diagnostics on malformed gossip / RPC / snapshot / keyfile input (10 assertions including the new `json_require_array` "expected array, got X" path) | `tools/test_s018_json_validation.sh` |
| `determ test-merkle` | v2.1 Merkle primitives (S-035 Option 1 seed): `crypto::merkle_root` + `merkle_proof` + `merkle_verify` + `merkle_leaf_hash` + `merkle_inner_hash` over balanced + unbalanced + edge-case (empty / single-leaf) leaf sets. 12 assertions covering round-trip, tampering detection (value_hash / sibling-hash / target_index), domain separation (leaf vs inner), determinism, and sort-invariance | `tools/test_merkle.sh` |
| `determ test-committee-selection` | Committee-selection primitives (S-035 Option 1 seed): `crypto::select_m_creators` (S-020 hybrid — both rejection-sampling at 2K≤N and partial-Fisher-Yates at 2K>N branches), `select_after_abort_m`, `epoch_committee_seed`. 13 assertions covering determinism, seed-sensitivity, branch coverage at both sides of the 2K vs N threshold, edge cases (K=N, K=1), distinct-without-replacement, in-range invariant, and shard-salt sensitivity. Foundation tests for FA1 / FA2 / FA5 / FA8 | `tools/test_committee_selection.sh` |
| `determ test-shard-routing` | Cross-shard routing primitive (S-035 Option 1 seed): `crypto::shard_id_for_address` (salted SHA-256). 7 assertions covering single-shard degenerate case, determinism, in-range invariant, salt-sensitivity, distribution uniformity (chi-squared sanity on 1000 addresses × 4 shards), case-sensitivity, empty-address handling. Foundation test for FA7 cross-shard receipt atomicity — every cross-shard tx's destination is derived through this function | `tools/test_shard_routing.sh` |
| `determ test-ed25519` | Ed25519 sign/verify foundation (S-035 Option 1 seed): `crypto::sign` / `crypto::verify` / `generate_node_key`. 10 assertions covering key-shape, round-trip, tampering rejection (message / signature / pubkey), RFC-8032 determinism, empty-message edge case, distinct-key distinct-sig property, cross-key verify rejection, 4 KB long-message streaming path. Foundation test for FA1 / FA2 / FA5 / FA6 / FA7 / FA10 — every signature claim in the protocol reduces to Ed25519 EUF-CMA, so a regression here cascades across every safety theorem | `tools/test_ed25519.sh` |
| `determ test-sha256` | SHA-256 wrapper + Big-Endian encoding foundation (S-035 Option 1 seed): `crypto::sha256` + `SHA256Builder`. 10 assertions covering NIST FIPS 180-4 published test vectors (empty input, "abc", 56-byte input), `SHA256Builder` ↔ one-shot equivalence, 3-piece incremental append correctness, **Preliminaries §1.3 big-endian uint64_t / int64_t encoding** (locks in the cross-platform consensus determinism contract — a regression to little-endian would silently fork the protocol across architectures). Foundation test under every hash claim in the codebase | `tools/test_sha256.sh` |
| `determ test-anon-address` | Anon-address helpers (S-035 Option 1 seed): `is_anon_address` / `normalize_anon_address` / `parse_anon_pubkey` / `make_anon_address`. 12 assertions covering S-028 case-insensitive parsing (accepts lower/upper/mixed-case), invalid-input rejection (missing 0x, wrong length, non-hex, registered-domain name), case-normalization to canonical lowercase, round-trip via make/parse, and registered-domain pass-through. Unit-level counterpart to `tools/test_anon_address_case.sh` (which exercises the same surface end-to-end through 3-node RPC) | `tools/test_anon_address.sh` |
| `determ test-genesis-message` | `GenesisConfig::genesis_message` hash-mixing contract (S-035 Option 1 seed). 10 assertions covering the three contract rules: (1) default-skips-mix (backward-compat invariant — pre-message genesis files retain byte-identical chain hashes), (2) custom value (including explicit empty string) yields distinct chain hash, (3) 256-byte size cap with JSON-load validation. Plus determinism, JSON round-trip, absent-key default-fallback, and boundary acceptance. Locks in the operator-facing inscribed-message feature against regressions that would either silently break existing chain identity OR allow chain-identity collisions | `tools/test_genesis_message.sh` |
| `determ test-state-root` | `Chain::compute_state_root()` commitment algebra (S-035 Option 1 seed). 13 assertions over the S-033 / v2.1 state-Merkle surface: determinism (two identical Chains → identical roots — the K-of-K consensus precondition); purity (10 sequential calls on an unmodified Chain return the same hash); non-zero baseline (default Chain has non-zero root because the "k:" namespace always emits leaves); per-field sensitivity for every public `set_*()` that maps into a k:-namespace leaf (block_subsidy, min_stake, subsidy_pool_initial, lottery_jackpot_multiplier, subsidy_mode, shard_routing count+id+salt); invertibility (change-then-revert returns to the original root — no hidden mutation state); cross-namespace distinction (two different mutations produce two different alternate roots — no accidental collisions); order independence (setter call order doesn't affect root — leaves sorted internally). Foundation-level counterpart to network-level `tools/test_state_root.sh` (multi-node RPC) and `tools/test_dapp_snapshot.sh` (S-037 + S-038 snapshot-restore contract) | `tools/test_state_root_unit.sh` |
| `determ test-block-rand` | V8 randomness primitives (S-035 Option 1 seed): `compute_delay_seed` (Phase-1 inputs commitment), `compute_block_rand` (Phase-2 output), `proposer_idx` (BFT-mode designated proposer), `required_block_sigs` (MD vs BFT quorum), `count_round1_aborts` (suspension + escalation tally). 21 assertions: determinism + every-input-field sensitivity for both hash functions + creator_dh_inputs / ordered_secrets ORDER sensitivity (the committee-selection-order contract that pairs Phase-1 commits with Phase-2 reveals — without this, a malicious gather could reorder reveals to bias future randomness); domain separation between compute_delay_seed and compute_block_rand; proposer_idx in-range invariant + abort-rotation mechanism + empty-committee short-circuit; required_block_sigs golden vectors for MD = K and BFT = ceil(2K/3) (K = 1..12); count_round1_aborts round-2 filter. FA1 / FA5 / FA8 foundation — every future committee derives from compute_block_rand → epoch_committee_seed → select_m_creators | `tools/test_block_rand.sh` |
| `determ test-rate-limiter` | S-014 token-bucket rate limiter (S-035 Option 1 seed): `net::RateLimiter` — the shared helper used identically by RpcServer and GossipNet. 16 assertions: default-disabled bypass, configure(0,0) explicit-disable, configure(>0,>0) enables + getter round-trip, first-touch starts FULL (legitimate callers don't get hit cold), burst exhaustion (4th consume fails at burst=3 same-instant), per-key independence (exhausting key A doesn't throttle key B — the central security property), reconfigure-takes-effect-on-next-consume, refill timing (100ms sleep at rate=20/s yields ≥1 new token), burst-cap invariant (long sleep at high rate does NOT exceed burst — defeats overflow attacks), 100-distinct-keys-each-consume-2 scale check. Unit-level counterpart to `tools/test_rpc_rate_limit.sh` + `tools/test_gossip_rate_limit.sh` (which exercise the same algebra end-to-end via wire) | `tools/test_rate_limiter.sh` |
| `determ test-block-digest` | `compute_block_digest` — the FA1 signature target at Phase-2 of K-of-K consensus (S-035 Option 1 seed). 19 assertions covering both contracts: (a) INCLUSION list — every field in compute_block_digest changes the digest when mutated (index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer, creators, creator_tx_lists, creator_ed_sigs, creator_dh_inputs); (b) EXCLUSION list (S-030 D2 fence) — fields NOT in compute_block_digest MUST NOT change it (delay_output + creator_dh_secrets + cumulative_rand are Phase-2-reveal; abort_events + equivocation_events + timestamp are v2.7 F2 territory; state_root is apply-time-gated via S-033 + S-038; partner_subset_hash for R4 Phase 3 merge). Locks the digest at exactly the surface FA1 / S-030 D2 / v2.7 F2 assume. Cross-reference: `docs/proofs/S030-D2-Analysis.md` §1 + `docs/proofs/F2-SPEC.md` §1 | `tools/test_block_digest.sh` |
| `determ test-block-hash` | `Block::signing_bytes()` + `Block::compute_hash()` — the FA1 chain-anchor identity (S-035 Option 1 seed). compute_hash binds EVERY consensus-relevant field of the block, including Phase-2-reveal fields and apply-time-recomputed fields, so its output becomes the prev_hash on every subsequent block. 16 assertions: determinism + purity (3); field-sensitivity for timestamp, delay_output, creator_dh_secrets, cumulative_rand, creator_block_sigs (5); zero-skip backward-compat for partner_subset_hash (R4 Phase 3) and state_root (S-033) — both fields contribute to the hash ONLY when non-zero, preserving byte-identical hashes for pre-feature blocks (5); creators[] ORDER sensitivity + S-030 D2 mitigation at chain-anchor level (two same-digest blocks differing in equivocation_events still have different hashes) + abort_events event_hash binding (3) | `tools/test_block_hash.sh` |
| `determ test-binary-codec` | Wire-format codec (A3 / S8) + S-022 cap table (S-035 Option 1 seed). 35 assertions across four blocks: (a) JSON envelope (v0) round-trip for HELLO + STATUS_REQUEST + TRANSACTION — types and payloads preserved byte-for-byte; (b) binary envelope (v1) round-trip for STATUS_RESPONSE + CONTRIB via both `Message::serialize_binary` + `Message::deserialize` (format-detecting) and direct `encode_binary` / `decode_binary`, plus `is_binary_envelope` detection contract (returns true on binary, false on JSON); (c) malformed-input rejection (garbage bytes; truncated valid JSON); (d) S-022 per-MsgType `max_message_bytes` golden vectors for all enumerated MsgType variants (16 MB tier: SNAPSHOT_RESPONSE / CHAIN_RESPONSE; 4 MB tier: BLOCK / BEACON_HEADER / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE / HEADERS_RESPONSE; 1 MB tier: HELLO / CONTRIB / BLOCK_SIG / ABORT_CLAIM / ABORT_EVENT / EQUIVOCATION_EVIDENCE / TRANSACTION / STATUS_REQUEST / STATUS_RESPONSE / GET_CHAIN / SNAPSHOT_REQUEST / HEADERS_REQUEST + default-tight 1 MB fence for future MsgType additions). Locks the wire format + cap table against silent regression at both the encode/decode asymmetry and S-022 boundary | `tools/test_binary_codec.sh` |
| `determ test-wire-types` | Block-internal wire types JSON round-trip + S-018 strict-rejection (S-035 Option 1 seed). 39 assertions covering `CrossShardReceipt` (FA7 / V12 source-side receipt — 10 fields), `AbortEvent` (FA3 abort certificate — 4 fields), `EquivocationEvent` (FA6 slashing evidence — 8 fields), `GenesisAlloc` (chain-identity allocation — 5 fields incl. R1 empty-region backward-compat). Plus S-018 strict-rejection lock-in for all four types: missing required field throws with a clear field-name diagnostic; wrong-length hex throws too. CrossShardReceipt::from_json was hardened in the same commit (previously permissive via `j.value()` defaults; now uses `json_require` / `json_require_hex` to match the rest of the S-018 surface) — defense in depth at the parse layer even though receipts are also bound into the parent block's signing_bytes via K-of-K | `tools/test_wire_types.sh` |
| `determ test-transaction` | `Transaction::signing_bytes` + `compute_hash` + Ed25519 sign/verify + JSON round-trip (S-035 Option 1 seed). 28 assertions: signing_bytes determinism + per-field sensitivity (8 core fields) + sig/hash EXCLUSION (would be circular — sender signs over their OWN signing bytes); compute_hash == SHA-256(signing_bytes) golden contract; Ed25519 sign + tampered-tx-fails verification round-trip; full JSON round-trip for TRANSFER + type-preservation round-trip for each of 9 enum variants (REGISTER through DAPP_CALL); S-018 strict-rejection (missing 'amount' + wrong-length 'sig' hex); unique-tx-identity contract (txs differing in nonce alone have distinct compute_hash — the mempool-dedup foundation) | `tools/test_transaction.sh` |
| `determ test-merge-event-codec` | `MergeEvent::encode` / `::decode` (R4 under-quorum merge wire format; S-035 Option 1 seed). 19 assertions: BEGIN + END round-trips with empty-region preservation, size invariant (encode size = 26 + region_len), decode rejection paths (too-short payload, invalid event_type > 1, region_len > 32 cap, size mismatch), determinism + per-field sensitivity, maximum-region (32 bytes) round-trip. Locks in the canonical-binary wire format that drives cross-shard merge coordination — a regression here would diverge the apply path across shards | `tools/test_merge_event_codec.sh` |
| `determ test-consensus-msgs` | ContribMsg + BlockSigMsg + AbortClaimMsg + commitment-hash helpers (S-035 Option 1 seed). 28 assertions: `make_contrib_commitment` determinism + per-input sensitivity + critical tx_hashes ORDER sensitivity (the sorted-ascending contract — wrong order produces commit that doesn't match peers); `make_abort_claim_message` determinism + per-input sensitivity (including round — defeats Phase-1 vs Phase-2 replay); domain separation between contrib commit and abort claim hash (no cross-domain collision); full JSON round-trip for all three message types (15 fields total); make_contrib produces a sig that verifies under signer's pubkey via real Ed25519 | `tools/test_consensus_msgs.sh` |
| `determ test-tx-root` | `compute_tx_root` — the K-committee union-of-tx-hashes commitment (S-035 Option 1 seed). 10 assertions: union semantics ({A,B} ∪ {B,C} == {A,B,C}, NOT intersection {B}), dedup across lists, list permutation invariance (which member proposes what doesn't affect the canonical root), empty inner list invariance, sensitivity to added tx. The FA2 censorship-resistance primitive — a regression to intersection semantics (S-025 deleted; commented out in producer.cpp) would silently let one member exclude txs | `tools/test_tx_root.sh` |
| `determ test-genesis` | `compute_genesis_hash` + `make_genesis_block` — chain-identity origin (S-035 Option 1 seed). 19 assertions: determinism + chain_id sensitivity; **lock-in of S-039 diagnostic-UX gap** (m_creators / k_block_sigs / block_subsidy / min_stake / initial_shard_count / bft_enabled are NOT bound into the hash — two operators with mismatched configs at same chain_id get cryptic consensus failures rather than a "config mismatch" diagnostic; fix is wire-compat break, deferred); fields that ARE bound (shard_id, chain_role, suspension_slash + merge_threshold_blocks when non-default, genesis_message, committee_region when non-empty); make_genesis_block invariants (index 0, prev_hash zero, compute_hash matches compute_genesis_hash); JSON round-trip preserves identity hash; oversized genesis_message rejected | `tools/test_genesis.sh` |
| `determ test-envelope` | `wallet/envelope.hpp` AES-256-GCM + PBKDF2-HMAC-SHA-256 AEAD wrapping primitive (A2 Phase 2 wallet recovery share envelopes + S-004 option 2 passphrase-encrypted keyfiles; S-035 Option 1 seed). 27 assertions across four blocks: (1) encrypt/decrypt round-trip with matching pw + AAD; (2) envelope shape (salt >= 16B, nonce == 12B, ciphertext == pt_size + 16B GCM tag, pbkdf2_iters + aad round-trip); (3) AEAD safety properties (wrong-pw / empty-pw / mismatched-AAD / tampered-ct / tampered-tag all fail; fresh salt + nonce per encryption guarantee distinct ciphertexts from same plaintext+passphrase — defeats artifact-correlation attacks); (4) serialize / deserialize canonical hex round-trip + bad-input rejection (garbage, truncated); (5) edge cases (empty plaintext yields 16B tag-only ciphertext; empty AAD round-trips). A regression here would silently weaken every encrypted wallet artifact | `tools/test_envelope.sh` |
| `determ test-resolve-fork` | `Chain::resolve_fork` — S-029 BFT-mode fork-choice rule (S-035 Option 1 seed). 10 assertions covering the documented decision priority: (1) heaviest sig set wins (counts non-zero `creator_block_sigs` entries — sentinel-zero slots in BFT mode don't count toward weight); (2) tie → fewer `abort_events` wins; (3) tie → smallest block_hash (lexicographic, deterministic across peers). Plus edge cases: identical blocks return first arg (final-tie deterministic); zero-sigs case still resolves without crash; sentinel-zero handling; abort-tie-break beats hash-tie-break (priority order). A regression would either let the wrong block win (peers diverge on canonical tip → FA1 violation) or make resolution non-deterministic across nodes | `tools/test_resolve_fork.sh` |
| `determ test-shamir` | Shamir's Secret Sharing over GF(2^8) (wallet/shamir.cpp, A2 Phase 1 wallet recovery primitive; S-035 Option 1 seed). 18 assertions covering: T-of-N reconstruction (3-of-5 round-trip, all 10 subsets verified, T+1 works, T-1 doesn't); share-shape invariants (distinct x-coordinates, no x=0 since Lagrange evaluates at x=0, y-size matches secret size, two independent splits produce different polynomial coefficients); degenerate thresholds (T=1 single-share, T=N all-shares-required); empty-secret edge case (split produces empty-y shares; combine rejects with nullopt per documented behavior); invalid-input rejection (threshold=0 / threshold > share_count / empty share list / duplicate x / mismatched y-sizes). A regression here would either weaken the threshold (information leak with < T shares) or break wallet recovery | `tools/test_shamir.sh` |
| `determ test-random-state` | Random-state primitives in `crypto/random.cpp` — `compute_dh_output` (2-share fold) + `compute_dh_output_m` (M-share fold) + `update_random_state` (per-block chain) + `compute_abort_hash` + `chain_abort_hash` (S5 anti-cartel defense) + `genesis_random_state` (block-0 seed). 27 assertions: determinism + argument-order sensitivity + per-input sensitivity for each function. Critical: the aborting_node sensitivity assertion in `compute_abort_hash` locks the S5 anti-cartel-navigation defense — committee re-selection after an abort must depend on WHO aborted, so an attacker can't pre-plan abort sequences to navigate into a favorable committee. The committee-selection-order contract for `compute_dh_output_m` matches the same invariant in test-block-rand's compute_delay_seed/compute_block_rand assertions (foundation layer below those higher-level helpers) | `tools/test_random_state.sh` |
| `determ test-snapshot-defense` | S-018 defense-in-depth lock-in for `Chain::restore_from_snapshot` (S-035 Option 1 seed). 11 assertions verifying that every optional collection field (accounts / stakes / registrants / applied_inbound_receipts / merge_state / abort_records / dapp_registry / pending_param_changes) throws a clean S-018 diagnostic naming the field when sent as a scalar / number / object instead of an array. Baseline (minimal valid snapshot) loads cleanly; backward-compat case (empty optional fields) still loads. Snapshots arrive via SNAPSHOT_RESPONSE gossip (16 MB cap — only unbounded-tier channel) so wrong-type rejection at the parse layer is the attack-facing diagnostic | `tools/test_snapshot_defense.sh` |
| `determ test-encoding` | `types.hpp` encoding helpers (S-035 Option 1 seed). 23 assertions covering `to_hex` (bytes-to-hex, lowercase, leading-zero preservation, templated overload for Hash/Signature), `from_hex` (case-insensitive parse via std::stoul base-16; rejects odd length), `from_hex_arr<N>` (length-checked array form; rejects short + long inputs), `to_string(ChainRole)` (single/beacon/shard), `to_string(ShardingMode)` (none/current/extended), cross-helper round-trip (Hash → to_hex → from_hex_arr<32> preserves 32 bytes), determinism (no internal-state leak from std::ostringstream), and `now_unix()` post-2017 sanity. **Foundation under every hex serialization** in the codebase — Block JSON, Transaction sig, Merkle leaf hashing, RPC output, snapshot format, light-client headers all transit through these helpers | `tools/test_encoding.sh` |
| `determ test-chain-helpers` | `Chain` read-side API surface (S-035 Option 1 seed). 23 assertions covering `balance` / `next_nonce` / `stake` (locked + `_lockfree` variants used by concurrent RPC handlers); `height` / `empty` / `head_hash`; `shard_count` / `my_shard_id` / `shard_salt` / `is_cross_shard` (single-shard degenerate case + multi-shard local/remote distribution); operator-tunable setter round-trips (`set_block_subsidy` / `set_min_stake` / `set_suspension_slash` / `set_unstake_delay`); A1 supply counters all zero on default chain. Locks safety-critical defaults: `balance(unknown)==0` (defeats accidental crediting on read), `next_nonce(unknown)==0` (first tx uses nonce 0), `shard_count==1` (default = single-shard, is_cross_shard==false unconditionally) | `tools/test_chain_helpers.sh` |
| `determ test-json-validate` | S-018 foundation helpers (`json_validate.hpp`) direct unit test (S-035 Option 1 seed). 24 assertions covering all three helpers (`json_require<T>`, `json_require_hex`, `json_require_array`) — happy paths + every error path. Locks the error-message contract that operators rely on for triage of malformed gossip / RPC inputs: missing field error contains field name + "S-018" prefix + "missing" keyword; wrong type error contains field name + "wrong type" + nlohmann detail; wrong hex length error explicitly states "expected N chars, got M chars" counts; wrong array type error states observed type ("got string" / "got object"). Empty array accepted (size=0 valid). Field-name uniqueness verified with unusual identifier chars. Foundation under every S-018-hardened from_json in the codebase | `tools/test_json_validate.sh` |
| `determ test-block-roundtrip` | `Block::to_json` / `Block::from_json` full field-set round-trip (S-035 Option 1 seed). 41 assertions covering minimal block (required fields), block with transactions, full K-of-K committee block (creators + creator_tx_lists + creator_ed_sigs + creator_dh_inputs + creator_dh_secrets + creator_block_sigs + tx_root + delay_seed + delay_output), BFT-mode block (consensus_mode + bft_proposer), block with abort_events / equivocation_events / cross_shard_receipts (V12) + inbound_receipts (V13) / initial_state (genesis), zero-skip fields (state_root + partner_subset_hash OMITTED from JSON when zero, PRESENT when non-zero), and the CRITICAL `compute_hash` invariance through JSON round-trip (gossip sender + receiver MUST compute the same block_hash or the prev_hash chain breaks) | `tools/test_block_roundtrip.sh` |
| `determ test-config-roundtrip` | `Config::to_json` / `Config::from_json` — operator config save+reload round-trip (S-035 Option 1 seed). 47 assertions covering default Config round-trip (every documented default — listen_port=7777, rpc_port=7778, rpc_localhost_only=true [S-001 secure default], bft_enabled=true, etc.), custom Config full-field round-trip across all 32 operator-tunable fields (ports / peers / rate-limits / regions / sharding mode / governance flags / timing knobs), empty-JSON → defaults path (permissive contract intentional for operator-facing config), and enum integer encoding for chain_role + sharding_mode. Permissive design preserved: missing optional fields silently default rather than throw (strict S-018 rejection reserved for wire-format peer messages) | `tools/test_config_roundtrip.sh` |
| `determ test-tx-binary-codec` | Transaction binary codec round-trip (S-035 Option 1 seed). 24 assertions covering the v1 binary wire-format path for TRANSACTION MsgType (`encode_tx_frame` / `decode_tx_frame` exercised via the public `encode_binary` / `decode_binary` Message-level API). **S-002 critical path**: amount/fee/nonce live in the FIXED 4×32-byte slot area (not the trailer); pre-S-002 closure the decoder dropped these during binary transit, letting corrupted txs into the mempool. Covers TRANSFER full round-trip + S-002 sig-verify invariant (compute_hash unchanged through binary transit) + distinct-tx-distinct-frames + trailer-overflow path for >32-byte payloads + every TxType discriminator + boundary values (zero + UINT64_MAX). Cross-reference: `docs/proofs/S002-Mempool-Sig-Verify.md` | `tools/test_tx_binary_codec.sh` |

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
