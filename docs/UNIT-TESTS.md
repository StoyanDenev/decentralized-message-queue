# Unit Tests — Coverage Map + Extension Guide

This document is the comprehensive reference for the in-process unit-test
seed that closes S-035 Option 1. It explains the strategy, lists what is
covered, what is not yet covered, and how to add new tests.

**Cross-references:**
- `SECURITY.md` §S-035 — finding registration + status table
- `README.md` §"Behavioral test suite" — representative-tests table
- `CLI-REFERENCE.md` §"S-035 Option 1 seed" — per-subcommand surface
- `tools/run_all.sh` — `FAST=1` short-circuit for in-process subset
- `tools/common.sh` — path-portability layer (Option 3)

---

## 1. Strategy: `determ test-*` subcommands

Rather than introducing a separate test binary (gtest / Catch2 / doctest), 
each unit test is a subcommand of the main `determ` binary. Calling
`determ test-FEATURE` runs an in-process unit test, prints `PASS`/`FAIL`
lines per assertion, then exits with status 0 (all pass) or 1 (any fail).

Each subcommand has a paired shell wrapper at `tools/test_FEATURE.sh`
that invokes the subcommand and translates its output into the
existing `tools/run_all.sh` summary infrastructure (final-line `PASS:`/
`FAIL:` markers per the existing test convention).

### Why this approach (vs gtest)

| Constraint | Implication |
|---|---|
| MVP timeline; no CI runner committed | Adding gtest + CMake + a CI workflow is its own multi-day project; defers value. |
| Codebase is small (~17 KLOC) | Bespoke test commands are not significantly more code than gtest fixtures would be. |
| Tests must run on Windows + Linux + Mac | A single binary is portable by construction; gtest needs CMake target consistency. |
| Existing test infrastructure (`tools/test_*.sh`, `run_all.sh`) is mature | Reusing it avoids a parallel suite. |
| Cryptographic primitives are pure functions | They lend themselves to direct calls from main.cpp without fixtures. |

The trade-off is that a future migration to gtest is the operator's
choice — the assertions themselves are gtest-ready (each is a single
`check(cond, msg)` call analogous to `EXPECT_TRUE` / `ASSERT_TRUE`), so
the migration would be mechanical when the operator commits to CI.

### Output format

```
=== <surface name> ===
  PASS: <assertion description>
  PASS: <assertion description>
  ...
  PASS: <feature> all assertions
  PASS: <feature> unit test
```

(or `FAIL:` substituted for failed assertions + a non-zero exit.) The
`PASS: <feature> all assertions` line is the canonical aggregate
result; the wrapper's `PASS: <feature> unit test` translates it for
`tools/run_all.sh`.

### `FAST=1` mode

`FAST=1 bash tools/run_all.sh` short-circuits to just the in-process
subset (network-free, <12s end-to-end). Useful for tight iteration
during development. Each new test wrapper must be added to the
`ONLY_PATTERN` regex in `run_all.sh` so `FAST=1` picks it up.

---

## 2. Current coverage map

50 subcommands; 1113 assertions; runs in <26s with no flakes.

### 2.1 Cryptographic primitives

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-sha256` | SHA-256 wrapper + `SHA256Builder` (10 assertions): NIST FIPS 180-4 published test vectors (empty input, "abc", 56-byte input exercising the >55-byte padding path), `SHA256Builder` ↔ one-shot equivalence, multi-piece incremental append correctness, **Preliminaries §1.3 big-endian uint64_t / int64_t encoding** that every signing-bytes / compute-block-digest / merkle-leaf-hash path depends on for cross-platform protocol determinism. | `tools/test_sha256.sh` | all hash claims |
| `determ test-ed25519` | Ed25519 sign/verify + `generate_node_key` (10 assertions): key-shape, sign+verify round-trip, tampered-message rejection, tampered-signature rejection, wrong-pubkey rejection, RFC-8032 determinism (same key+msg → same sig), empty-message edge case, distinct-key distinct-sig, cross-key verify rejection, 4 KB long-message streaming. Every signature claim in the protocol reduces to Ed25519 EUF-CMA. | `tools/test_ed25519.sh` | FA1 / FA2 / FA5 / FA6 / FA7 / FA10 |
| `determ test-merkle` | v2.1 Merkle primitives (10 assertions): `merkle_root` + `merkle_proof` + `merkle_verify` + `merkle_leaf_hash` + `merkle_inner_hash` over balanced + unbalanced + edge-case (empty / single-leaf) leaf sets. Round-trip, tampering detection (value_hash / sibling-hash / target_index), domain separation (leaf vs inner), determinism, sort-invariance. | `tools/test_merkle.sh` | FA1 |
| `determ test-committee-selection` | `crypto::select_m_creators` (S-020 hybrid: both rejection-sampling at 2K≤N AND partial-Fisher-Yates at 2K>N branches), `select_after_abort_m`, `epoch_committee_seed` (13 assertions): determinism, seed-sensitivity, branch coverage at both sides of the 2K vs N threshold, edge cases (K=N, K=1), distinct-without-replacement, in-range invariant, shard-salt sensitivity. | `tools/test_committee_selection.sh` | FA1 / FA2 / FA5 / FA8 |
| `determ test-shard-routing` | `crypto::shard_id_for_address` (salted SHA-256) (7 assertions): single-shard degenerate case, determinism, in-range invariant, salt-sensitivity, distribution uniformity (chi-squared sanity on 1000 addresses × 4 shards), case-sensitivity, empty-address handling. | `tools/test_shard_routing.sh` | FA7 |
| `determ test-anon-address` | Anon-address helpers (12 assertions): `is_anon_address` / `normalize_anon_address` / `parse_anon_pubkey` / `make_anon_address`. S-028 case-insensitive parsing (accepts lower / upper / mixed-case), invalid-input rejection, case-normalization to canonical lowercase, round-trip, registered-domain pass-through. | `tools/test_anon_address.sh` | wallet (S-028) |
| `determ test-encoding` | `types.hpp` foundation encoding helpers (23 assertions): `to_hex` (bytes-to-hex with leading-zero preservation + templated Hash/Signature overload), `from_hex` (case-insensitive parse via std::stoul base-16; rejects odd length), `from_hex_arr<N>` (length-checked array form; rejects short + long inputs), `to_string(ChainRole)` (single/beacon/shard), `to_string(ShardingMode)` (none/current/extended), cross-helper round-trip (Hash → to_hex → from_hex_arr<32> preserves 32 bytes), determinism (no std::ostringstream state leak), `now_unix()` post-2017 sanity. **Foundation under every hex serialization** in the codebase. | `tools/test_encoding.sh` | wire format foundation |
| `determ test-json-validate` | S-018 foundation helpers in `json_validate.hpp` direct unit test (24 assertions): `json_require<T>` / `json_require_hex` / `json_require_array` happy paths + every error path. Locks operator-facing error-message contract (missing-field "S-018" prefix + field name; wrong-type field name + "wrong type"; wrong-hex-length explicit "expected N / got M" counts; wrong-array-type observed-type detail; empty array accepted as size=0). Foundation under every S-018-hardened from_json — Transaction / Block / AbortEvent / EquivocationEvent / GenesisAlloc / CrossShardReceipt / ContribMsg / BlockSigMsg / AbortClaimMsg + gossip envelope dispatchers all transit through these helpers. | `tools/test_json_validate.sh` | S-018 |

### 2.2 Chain commitment + identity

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-genesis-message` | `GenesisConfig::genesis_message` hash-mixing contract (10 assertions): backward-compat default-skips-mix invariant, custom-yields-distinct-hash, empty-string-distinct-from-default, determinism under override, JSON round-trip, absent-key default-fallback, size cap enforcement (256B max), boundary acceptance. Locks operator-facing inscribed-message feature against silent regressions that would either break existing chain identity or allow chain-identity collisions. | `tools/test_genesis_message.sh` | chain identity |
| `determ test-state-root` | `Chain::compute_state_root()` commitment algebra (13 assertions): determinism (K-of-K consensus precondition), purity (no internal-state leak between calls), non-zero baseline (k: leaves always present), per-field sensitivity for every public `set_*()` that maps into a k:-namespace leaf, invertibility (change-then-revert returns to original root), cross-namespace distinction (no accidental collisions), order independence (setter call order doesn't affect root — leaves sorted internally). S-033 / v2.1 / S-037 / S-038 surface. | `tools/test_state_root_unit.sh` | FA1 (state commitment) |
| `determ test-block-digest` | `compute_block_digest` (FA1 Phase-2 signature target) (19 assertions): INCLUSION contract (every digested field — index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer, creators, creator_tx_lists, creator_ed_sigs, creator_dh_inputs — changes the digest when mutated) + EXCLUSION contract (S-030 D2 / Phase-2-reveal / v2.7 F2 territory fields MUST NOT change the digest: delay_output, creator_dh_secrets, cumulative_rand, abort_events, equivocation_events, state_root, partner_subset_hash, timestamp). "Fences" the digest at exactly the surface FA1 / S-030 D2 / v2.7 F2 assume. | `tools/test_block_digest.sh` | FA1 (signature target) |
| `determ test-block-hash` | `Block::signing_bytes()` + `Block::compute_hash()` — FA1 chain-anchor identity (16 assertions). compute_hash binds EVERY consensus-relevant field of the block including Phase-2-reveal fields and apply-time-recomputed state_root, so its output becomes prev_hash on every subsequent block. Covers determinism + purity, field-sensitivity for timestamp / delay_output / creator_dh_secrets / cumulative_rand / creator_block_sigs, zero-skip backward-compat for partner_subset_hash (R4 Phase 3) and state_root (S-033) — both bound only when non-zero so pre-feature blocks retain byte-identical hashes, creators[] ORDER sensitivity, and S-030 D2 chain-anchor distinction (two same-digest blocks differing in equivocation_events have different compute_hash outputs). | `tools/test_block_hash.sh` | FA1 (chain identity) |
| `determ test-genesis` | `compute_genesis_hash` + `make_genesis_block` — chain identity origin (22 assertions). Locks in chain_id sensitivity + the **S-039 diagnostic-UX gap** (m_creators / k_block_sigs / block_subsidy / min_stake / initial_shard_count / bft_enabled NOT bound into hash → discovered during test authoring; fix is wire-compat break, deferred to coordinated migration). Fields that ARE bound: shard_id, chain_role, suspension_slash + merge_threshold_blocks (when non-default), genesis_message, committee_region (when non-empty). make_genesis_block invariants (index 0, prev_hash zero, compute_hash matches). JSON round-trip preserves identity hash; oversized genesis_message rejected. **S-018 defense-in-depth lock-in** — wrong-type rejection on `initial_creators` / `initial_balances` / `param_keyholders` collection fields (genesis is operator-edited; a typo making any of these scalar/object now throws clean field-name diagnostic instead of opaque nlohmann error). | `tools/test_genesis.sh` | chain identity + S-039 + S-018 |
| `determ test-chain-helpers` | `Chain` read-side API surface (23 assertions): `balance` / `next_nonce` / `stake` (locked + `_lockfree` variants used by concurrent RPC handlers); `height` / `empty` / `head_hash`; `shard_count` / `my_shard_id` / `shard_salt` / `is_cross_shard` (single-shard degenerate case + multi-shard distribution); operator-tunable setter round-trips (`set_block_subsidy` / `set_min_stake` / `set_suspension_slash` / `set_unstake_delay`); A1 supply counters all zero on default chain. Locks safety-critical defaults: `balance(unknown)==0` (defeats accidental crediting on read), `next_nonce(unknown)==0` (first tx uses nonce 0), `shard_count==1` (single-shard ⇒ is_cross_shard==false unconditionally). | `tools/test_chain_helpers.sh` | FA1 / state view |
| `determ test-snapshot-defense` | S-018 defense-in-depth lock-in for `Chain::restore_from_snapshot` wrong-type collection rejection (12 assertions). Every optional collection field (accounts / stakes / registrants / applied_inbound_receipts / merge_state / abort_records / dapp_registry / pending_param_changes / headers) throws clean S-018 diagnostic naming the field when sent as scalar/number/object instead of array. Baseline (minimal valid snapshot) loads cleanly; backward-compat case (empty optional fields) still loads. Snapshots arrive via SNAPSHOT_RESPONSE gossip (16 MB cap — only unbounded-tier channel) so wrong-type rejection at the parse layer is the attack-facing diagnostic. | `tools/test_snapshot_defense.sh` | S-018 |
| `determ test-block-roundtrip` | `Block::to_json` / `Block::from_json` full field-set round-trip (41 assertions). Block transits through JSON at every gossip hop, every chain.json save/load, every snapshot tail-header save/restore. Covers minimal block, block with transactions, K-of-K committee block (creators + creator_tx_lists + creator_ed_sigs + creator_dh_inputs + creator_dh_secrets + creator_block_sigs + tx_root + delay_seed + delay_output), BFT-mode block, block with abort_events / equivocation_events / cross_shard_receipts (V12) + inbound_receipts (V13) / initial_state (genesis), zero-skip fields (state_root + partner_subset_hash backward-compat), and the **CRITICAL `compute_hash` invariance through JSON round-trip** — sender and receiver MUST compute the same block_hash or the prev_hash chain breaks. | `tools/test_block_roundtrip.sh` | wire format |
| `determ test-config-roundtrip` | `Config::to_json` / `Config::from_json` — operator config save+reload (47 assertions). All 32 operator-tunable fields (ports / peers / rate-limits / regions / sharding mode / governance flags / timing knobs) round-trip; default Config preserves documented defaults; empty-JSON → defaults path (permissive contract — operators expect a config missing optional fields to load with defaults rather than throw); enum integer encoding for chain_role + sharding_mode. Without round-trip stability, operators' saved configs would silently revert fields on reload, breaking their intent without a visible error. | `tools/test_config_roundtrip.sh` | operator UX |
| `determ test-tx-binary-codec` | Transaction binary codec round-trip — v1 binary wire-format path for TRANSACTION MsgType (24 assertions). **S-002 critical path**: amount/fee/nonce live in the FIXED 4×32-byte slot area (not the trailer); pre-S-002-closure the decoder dropped these during binary transit, letting corrupted txs into mempool. Covers TRANSFER full round-trip + S-002 sig-verify invariant (compute_hash unchanged through binary transit — the precondition for admission-side sig verification) + trailer-overflow for >32-byte payloads + every TxType discriminator + boundary values (zero + UINT64_MAX). Exercised via the public `encode_binary` / `decode_binary` Message-level API. Cross-reference: `docs/proofs/S002-Mempool-Sig-Verify.md`. | `tools/test_tx_binary_codec.sh` | S-002 / wire format |
| `determ test-chain-append` | `Chain::append` + `head` + `at` + `head_hash` mutation invariants (16 assertions). Chain::append is the public mutation entry point — every block transitions through it (apply path during sync, replay during chain.json load, tentative-chain compute_state_root during finalize). Covers empty-Chain rejection paths (head / head_hash / at(0) throw with clear messages), genesis-like first append, second append with correct prev_hash, **prev_hash continuity invariant** (wrong prev_hash throws 'prev_hash mismatch' — the central chain-integrity invariant), 5-block chain consistency, and **prev_hash transitivity** (every block's prev_hash matches the prior block's compute_hash — the chain-anchor invariant that makes prev_hash a tamper-evident link). | `tools/test_chain_append.sh` | FA1 / chain integrity |
| `determ test-state-types` | Chain state struct defaults + UINT64_MAX sentinel semantics (30 assertions). AccountState (2) + StakeEntry (5) + RegistryEntry (7) + DAppEntry (12) defaults; plus cross-struct sentinel consistency (3): StakeEntry.unlock_height, RegistryEntry.inactive_from, and DAppEntry.inactive_from all share UINT64_MAX as the "active until apply-path event sets a concrete height" sentinel. Apply paths compare these against block.index uniformly across all three types — divergent sentinels would break comparison semantics. A regression to a zero default would cause every fresh stake to look immediately unlockable + every fresh registrant to look immediately deregistered. | `tools/test_state_types.sh` | FA3 / state semantics |
| `determ test-validator-config` | `BlockValidator` public configuration API + `validate()` genesis short-circuit (16 assertions). Default-construct + all 11 public setters (K / M / BFT enable / escalation / epoch / shard_id / committee_region / sharding_mode / governance_mode / param_keyholders / param_threshold) across documented value ranges + **validate() genesis short-circuit invariant** (blocks at index 0 return OK regardless of validator config — genesis trust anchored in pinned genesis hash, not signature checks). The check_* helpers are private; network-level integration tests exercise the full validate path. | `tools/test_validator_config.sh` | FA1 / operator config |
| `determ test-timing-profiles` | `TimingProfile` constants from `chain/params.hpp` — operator-facing deployment posture (54 assertions). All 5 production profiles (cluster=BEACON/CURRENT/M=K=3, web=SHARD/EXTENDED/M=3,K=2, regional=SHARD/CURRENT/M=5,K=4, global=BEACON/EXTENDED/M=7,K=5, tactical=SHARD/EXTENDED/M=K=3) + their round-timer values (50/200/300/600/20 ms tx_commit). Plus all 6 `*_test` profiles' parity invariant: each mirrors its prod sibling's M/K/role/mode, differing only in sub-30ms test timers so CI exercises the same code paths a production deployment would. Test/prod separation invariant locked (TEST_TX_COMMIT_MS < 30 < PROFILE_CLUSTER = 50). | `tools/test_timing_profiles.sh` | operator config |
| `determ test-params-constants` | `chain/params.hpp` protocol-level constants — deployment-critical defaults (16 assertions). MIN_STAKE=1000 + UNSTAKE_DELAY=1000 + SUSPENSION_SLASH=10 (stake-economy); REGISTER payload geometry (PUBKEY_SIZE=32, REGION_MAX=32, MIN_SIZE=32, MAX_SIZE=65); TRANSFER_PAYLOAD_MAX=128 (A4 memo cap); ZEROTH_ADDRESS (E1 NEF pool's low-order curve25519 pseudo-account); cross-arithmetic invariants (SUSPENSION_SLASH × 100 == MIN_STAKE — 100 baked aborts zero a minimally-staked validator; the BFT-safety economic accounting). Every chain whose genesis doesn't override inherits these defaults — silent change would shift behavior across deployments without an error. | `tools/test_params_constants.sh` | operator economy |
| `determ test-supply-invariant` | Chain A1 unitary supply read API + `expected_total` formula (16 assertions). A1 invariant: `live_total_supply() == expected_total()` where `expected_total = genesis + subsidy + inbound - slashed - outbound`. Locks: default-Chain zero state for all 5 counters, formula's arithmetic shape (defends against sign-flip / field-reorder regressions), pure-function determinism, and **setter independence** (operator-tunable config setters don't affect expected_total — formula depends only on the 5 named counters). Apply-path mutations are exercised by the network-level test_a1_unitary_*.sh suite; this unit test pins the read-side contract in <1s. | `tools/test_supply_invariant.sh` | A1 unitary supply |
| `determ test-enum-values` | Protocol-level enum integer encodings — wire-format discriminator lock-in (46 assertions). Every value of TxType (TRANSFER=0..DAPP_CALL=10, 11 variants), MsgType (HELLO=0..HEADERS_RESPONSE=18, 19 variants), ConsensusMode (MUTUAL_DISTRUST=0, BFT=1), ChainRole (SINGLE=0..SHARD=2), ShardingMode (NONE=0..EXTENDED=2), InclusionModel (STAKE/DOMAIN=0/1) + sizeof invariants for all 6 enums (uint8_t wide). **Every enum integer is on the wire** — Transaction::signing_bytes prepends `static_cast<uint8_t>(type)`, compute_block_digest binds consensus_mode, MsgType is the gossip envelope type byte. A reorder of any slot silently forks the wire format without an operator-visible error. | `tools/test_enum_values.sh` | wire format |
| `determ test-block-accessors` | chain::Block default-construction + field accessor invariants + value preservation (36 assertions). Block is the central wire structure — every gossip hop transits a Block, every chain.json save/load serializes blocks, every snapshot tail-header is a Block. Locks default values across all scalar fields (10), collection fields (14), and zero-skip backward-compat fields (state_root + partner_subset_hash). Plus field-assignment preservation (transactions push_back / creators order / parallel committee-aligned vectors / BFT mode + proposer / state_root non-zero exactness) and compute_hash determinism + sensitivity to index change. Default-construction invariants are protocol-critical: partial Block construction during apply paths must not expose half-initialized garbage. | `tools/test_block_accessors.sh` | wire format / state |
| `determ test-make-block-sig` | `make_block_sig` Phase-2 BlockSigMsg producer — third K-of-K consensus message production helper alongside `make_contrib` + `make_abort_claim` (15 assertions). Data-field preservation (block_index / signer / delay_output / dh_secret); central sign/verify contract (sig verifies under signer's pubkey over block_digest); tampered-digest rejection (post-collection digest-swap defense); cross-signer distinctness (K threshold is K *distinct* sigs); key binding (signer A's sig doesn't verify under signer B's pubkey); RFC 8032 determinism (defends against future nondeterministic-Ed25519 regressions); sig-domain documentation (sig binds to block_digest only). | `tools/test_make_block_sig.sh` | FA1 / Phase-2 sig |
| `determ test-domain-separation` | Cross-cutting non-collision invariant across every protocol commitment hash (20 assertions). Pairwise non-collision across 9 commitments (compute_block_digest / make_contrib_commitment / make_abort_claim_message / compute_delay_seed / compute_block_rand / compute_tx_root / compute_genesis_hash / Transaction::compute_hash / Block::compute_hash); S-033/S-038 state_root exclusion-fence proofs (state_root mutation leaves compute_block_digest unchanged AND changes Block::compute_hash); determinism sanity (cross-checks non-collision comes from distinct inputs, not internal state). A cross-domain collision would enable cross-protocol replay attacks. | `tools/test_domain_separation.sh` | domain separation / FA1 |
| `determ test-tx-signing-bytes` | `Transaction::signing_bytes` byte-layout invariant via golden vectors (40 assertions). Locks the exact wire-format layout: type byte at offset 0, from + to strings each null-terminated, amount/fee/nonce each 8 bytes BIG-ENDIAN at offsets [3..10] / [11..18] / [19..26], payload at offset 27 (plus from/to length). Default Transaction → exactly 27 zero bytes. Concrete golden vectors (amount=1 → [0,0,0,0,0,0,0,1] LSB-at-byte-10; amount=0x0102030405060708 → BE pattern). A regression in any byte ordering or BE-vs-LE encoding would silently break sig verification across versions. | `tools/test_tx_signing_bytes.sh` | wire format / FA1 |
| `determ test-merge-event-bytes` | `MergeEvent::encode` byte-layout invariant via golden vectors (48 assertions). Locks the exact R4 under-quorum-merge wire format: event_type at offset 0 (BEGIN=0x00, END=0x01); shard_id 4 bytes LITTLE-ENDIAN at offsets [1..4]; partner_id 4 bytes LE at offsets [5..8]; effective_height 8 bytes LE at offsets [9..16]; evidence_window_start 8 bytes LE at offsets [17..24]; region_len byte at offset 25; region utf-8 bytes at offsets [26..]. Total size = 26 + region_len. **Critical endian-contrast invariant** — MergeEvent uses LE (native memory layout for x86/ARM wire targets), Transaction uses BE (cross-platform hash-input convention per Preliminaries §1.3). A regression flipping endianness would silently fork the apply path across shards during under-quorum-merge events. | `tools/test_merge_event_bytes.sh` | R4 / FA8 |
| `determ test-make-genesis-block` | `make_genesis_block` invariants — the bootstrap contract for every chain instance (34 assertions). Structural defaults (index=0, prev_hash=zero, timestamp=0, empty transactions + 4 committee-aligned vectors, tx_root=zero); creators[] sorted ALPHABETICALLY regardless of cfg insertion order (deterministic byte-equal genesis across nodes from different `determ init` invocations); initial_state populated from initial_creators preserving domain + ed_pub + stake + region; initial_balances merge semantics (matching-domain balance ADDS to existing entry's balance — in-place merge, no duplicate entry; non-matching domain creates new entry with stake=0 + ed_pub=zero — pure-balance recipients like faucet / treasury / pre-mine allocations); determinism (same GenesisConfig → byte-identical Block on every call — critical for cross-node genesis agreement). | `tools/test_make_genesis_block.sh` | chain bootstrap / FA1 |
| `determ test-pending-param-changes` | `Chain::stage_param_change` + `pending_param_changes()` — A5 Phase 2 governance staging primitive (13 assertions). Default-empty contract; single stage (map size 1, key matches, bucket size 1, name + value byte-for-byte preserved); two entries at SAME height (vector push_back preserves insertion order — the deterministic-apply contract within a height bucket); three entries at DIFFERENT heights (std::map sorted-by-key iteration → ascending activation order); empty-value vector valid (delete-param sentinel form); 256-byte value round-trips intact; Chain-instance independence (no static state leak between chains). Read-write surface tested without the apply path — paired end-to-end via `tools/test_governance.sh`. | `tools/test_pending_param_changes.sh` | A5 governance |
| `determ test-merge-state` | Chain merge-state read API + R4 governance threshold setters (14 assertions). Default-empty `merge_state()`; `is_shard_merged()` returns false with `out_partner` unmodified; `is_shard_merged(0, nullptr)` permissive null pointer; `shards_absorbed_by()` empty vector on empty map; the three R4 threshold setters (`merge_threshold_blocks=100`, `revert_threshold_blocks=200` for 2× hysteresis, `merge_grace_blocks=10`) round-trip; setters independent; `MergePartnerInfo` default `partner_id=0` + empty `refugee_region` (R1 global pool). | `tools/test_merge_state.sh` | R4 / governance |
| `determ test-chain-apply-block` | `Chain::append` / `apply_transactions` — central state-transition function under every block-application path (28 assertions across 8 sub-cases). Genesis bootstrap (8): accounts + stakes + registrants populated from `initial_state`; alice has registry from `initial_creators`, bob has none from `initial_balances` zero-ed_pub merge; A1 baseline. Empty-block apply (1). TRANSFER apply (5): local debit + credit + nonce++ with fee routed to creator; bad nonce + insufficient balance silently-skip. STAKE apply (2): stake locked via 8-byte LE payload + balance debited. REGISTER apply (5): seed TRANSFER funds carol, then REGISTER creates RegistryEntry with `active_from = height + derive_delay`. prev_hash continuity (2): wrong prev_hash throws + apply rollback. A1 invariant sequence (4): invariant holds across genesis + empty + TRANSFER + STAKE. **Implementation note (in the wrapper)**: every block with fee-charging txs must set `b.creators` non-empty or apply throws an A1 violation that, uncaught, terminates with STATUS_STACK_BUFFER_OVERRUN. | `tools/test_chain_apply_block.sh` | central apply path |
| `determ test-snapshot-roundtrip` | `Chain::serialize_state` + `Chain::restore_from_snapshot` round-trip — the snapshot wire format used by `determ snapshot create/inspect/fetch`, SNAPSHOT_RESPONSE gossip, and the S-037/S-038 closure path (15 assertions). Basic round-trip (version=1, block_index + head_hash reflect tip); account/stake/registry state (balance, next_nonce, stake locked, registrant ed_pub + region R1); A1 invariants (5 counters preserved + invariant holds); 4 genesis-pinned constants; **central S-033/S-037/S-038 contract — `compute_state_root` preserved**; rejection paths (unsupported version + non-object + legacy minimal snapshot); determinism (2 restores → same state_root, critical for cross-node bootstrap agreement). | `tools/test_snapshot_roundtrip.sh` | snapshot / S-033 / S-037 / S-038 |
| `determ test-state-proof` | `Chain::state_proof` — v2.2 light-client Merkle inclusion-proof primitive (12 assertions). Inclusion + verify (8): proof returned, key preserved, `crypto::merkle_verify` accepts under root, tampering rejected (value_hash + sibling-hash + target_index + cross-proof-swap = the malicious-server defense surface). Non-membership (1): absent key returns nullopt (sorted-leaves design contract). Determinism + state-root consistency (3): byte-identical across calls + post-TRANSFER value_hash changes AND new proof verifies under new state_root. Network-level `tools/test_state_proof.sh` exercises the RPC path; this is the in-process foundation. | `tools/test_state_proof_unit.sh` | v2.2 light-client |
| `determ test-abort-event-apply` | Apply-side handling of `AbortEvent` — rev.8 Phase-1 suspension slashing (13 assertions across 6 blocks). Phase-1 slashing (stake reduced by SUSPENSION_SLASH=10); S-032 abort_records cache populated (count + last_block); Phase-2 NO-slashing contract (timing-skew aborts on healthy creators don't slash); aborted-without-stake DOMAIN_INCLUSION mode (records still tracked); stake exhaustion (51 aborts × 10 slash → floors at 0, no negative); A1 invariant (accumulated_slashed += SUSPENSION_SLASH; live decreases by exactly that). Mirrors registry.cpp's suspension policy; required for BFT-mode safety. | `tools/test_abort_event_apply.sh` | FA6 / SUSPENSION_SLASH / S-032 |
| `determ test-equivocation-apply` | Apply-side handling of `EquivocationEvent` — FA6 full equivocation slashing + deregistration (10 assertions across 5 blocks). Full stake forfeiture (entire locked → 0); registry deactivation (inactive_from = b.index+1, harsher than SUSPENSION_SLASH since equivocation is deliberate double-sign); robustness on ghost equivocator (no crash on missing stake/registry); A1 invariant (accumulated_slashed += full forfeit); determinism (two chains see same equivocation → same `compute_state_root`). Dual mechanism (stake forfeit + deregistration) unifies STAKE_INCLUSION and DOMAIN_INCLUSION — neither leaves equivocator able to rejoin without registering fresh domain. | `tools/test_equivocation_apply.sh` | FA6 / equivocation slashing |

### 2.3 Randomness + consensus arithmetic + tx-root

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-block-rand` | V8 randomness primitives (21 assertions): `compute_delay_seed` (Phase-1 inputs commitment), `compute_block_rand` (Phase-2 output), `proposer_idx` (BFT-mode designated proposer), `required_block_sigs` (MD vs BFT quorum), `count_round1_aborts` (suspension + escalation tally). Determinism + every-input-field sensitivity + creator_dh_inputs / ordered_secrets ORDER sensitivity (the committee-selection-order contract pairing Phase-1 commits with Phase-2 reveals — without this, a malicious gather could reorder reveals to bias future randomness), domain separation between the two hash functions, proposer_idx in-range invariant + abort-rotation mechanism + empty-committee short-circuit, required_block_sigs golden vectors for MD = K and BFT = ceil(2K/3) (K = 1..12), count_round1_aborts round-2 filter. | `tools/test_block_rand.sh` | FA1 / FA5 / FA8 |
| `determ test-tx-root` | `compute_tx_root` — K-committee union-of-tx-hashes commitment (10 assertions). Union semantics ({A,B} ∪ {B,C} == {A,B,C}, NOT intersection {B}), dedup, list permutation invariance, within-list order invariance, empty inner list invariance, sensitivity to added tx. **The FA2 censorship-resistance primitive** — regression to intersection (note S-025 deletion: intersection variant was removed) would silently let one member exclude txs. | `tools/test_tx_root.sh` | FA2 (censorship) |
| `determ test-random-state` | Random-state primitives in `crypto/random.cpp` — `compute_dh_output` (2-share fold) + `compute_dh_output_m` (M-share fold, current path) + `update_random_state` (per-block chain) + `compute_abort_hash` + `chain_abort_hash` (S5 anti-cartel — abort-dependent re-selection so attackers can't pre-plan abort sequences) + `genesis_random_state` (block-0 seed). 27 assertions: determinism + argument-order sensitivity + per-input sensitivity for each function. **Foundation layer below** test-block-rand's compute_delay_seed / compute_block_rand. The committee-selection-order contract for compute_dh_output_m + the aborting_node sensitivity in compute_abort_hash are the key invariants — without them, attackers could either reorder reveals or plan abort sequences to bias future selection. | `tools/test_random_state.sh` | V8 / S5 anti-cartel |

### 2.4 Consensus message surface

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-transaction` | `Transaction::signing_bytes` + `compute_hash` + Ed25519 sign/verify + JSON round-trip (28 assertions). signing_bytes determinism + per-field sensitivity for all 8 core fields, sig/hash EXCLUSION (would be circular — sender signs over their OWN signing bytes), compute_hash == SHA-256(signing_bytes) golden contract, real Ed25519 sign + tampered-tx-fails-verify round-trip, full JSON round-trip for TRANSFER + type-preservation for all 9 other TxType variants, S-018 strict-rejection, unique-tx-identity contract. | `tools/test_transaction.sh` | tx-level FA1 + S-018 |
| `determ test-merge-event-codec` | `MergeEvent::encode` / `::decode` (R4 under-quorum merge wire format; 19 assertions). BEGIN + END round-trips with empty-region preservation, size invariant, decode rejection paths (too-short / invalid event_type / region_len > 32 / size mismatch), determinism + per-field sensitivity, maximum-region (32 bytes) round-trip. | `tools/test_merge_event_codec.sh` | R4 / FA8 |
| `determ test-consensus-msgs` | ContribMsg + BlockSigMsg + AbortClaimMsg + their commitment-hash helpers (`make_contrib_commitment` + `make_abort_claim_message`); 28 assertions. Per-helper determinism + per-input sensitivity (including tx_hashes ORDER for contrib — sorted-ascending contract); round sensitivity in abort claim (defeats Phase-1 vs Phase-2 replay); domain separation between commitment hashes; full JSON round-trip for all three message types; make_contrib produces a sig that verifies under signer's pubkey via real Ed25519. | `tools/test_consensus_msgs.sh` | FA1 (consensus messages) |

### 2.5 Network surface

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-rate-limiter` | `net::RateLimiter` token bucket (S-014 surface — the shared helper used identically by RpcServer and GossipNet) (16 assertions): default-disabled bypass, configure(0,0) explicit-disable, configure(>0,>0) enables + getter round-trip, first-touch FULL invariant (legitimate callers don't get hit cold), burst exhaustion (4th consume fails at burst=3 same-instant), per-key independence (exhausting key A doesn't throttle key B — the central security property), reconfigure semantics, refill timing (100ms sleep at rate=20/s yields ≥1 new token), burst-cap invariant (long sleep at high rate does NOT exceed burst — defeats slow-leak attacks), 100-distinct-keys-at-scale. Unit-level counterpart to wire-level `test_rpc_rate_limit.sh` + `test_gossip_rate_limit.sh`. | `tools/test_rate_limiter.sh` | S-014 |
| `determ test-binary-codec` | Wire-format codec (A3 / S8 closure: JSON envelope v0 + binary envelope v1 + format-detecting dispatcher) + S-022 per-MsgType cap table (35 assertions): JSON envelope round-trip across HELLO + STATUS_REQUEST + TRANSACTION (with type + payload byte-for-byte preservation); binary envelope round-trip across STATUS_RESPONSE + CONTRIB via both `Message::serialize_binary` + `Message::deserialize` (format-detecting) and direct `encode_binary` / `decode_binary`; `is_binary_envelope` format-detection contract (returns true on binary magic byte, false on JSON `{`); malformed-input rejection (garbage bytes + truncated valid JSON); `max_message_bytes` golden vectors for all 19 enumerated MsgType variants (16 MB tier: SNAPSHOT_RESPONSE / CHAIN_RESPONSE; 4 MB tier: BLOCK / BEACON_HEADER / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE / HEADERS_RESPONSE; 1 MB tier: HELLO / CONTRIB / BLOCK_SIG / ABORT_CLAIM / ABORT_EVENT / EQUIVOCATION_EVIDENCE / TRANSACTION / STATUS_REQUEST / STATUS_RESPONSE / GET_CHAIN / SNAPSHOT_REQUEST / HEADERS_REQUEST + default-tight 1 MB fence for future MsgType additions — defeats new types slipping past the S-022 boundary). | `tools/test_binary_codec.sh` | A3 / S8 / S-022 |
| `determ test-wire-types` | Block-internal wire types JSON round-trip + S-018 strict-rejection (39 assertions). Covers `CrossShardReceipt` (FA7 / V12 source-side receipt — 10 fields), `AbortEvent` (FA3 abort certificate — 4 fields + claims subtree), `EquivocationEvent` (FA6 slashing evidence — 8 fields), `GenesisAlloc` (chain-identity allocation — 5 fields including R1 empty-region backward-compat + zero-stake legacy). S-018 strict-rejection lock-in for all four: missing required field throws with field-name diagnostic; wrong-length hex throws via `json_require_hex` length check. `CrossShardReceipt::from_json` was hardened in the same commit that shipped this test (previously permissive via `j.value()` defaults — defense-in-depth gap closed; now uses `json_require` / `json_require_hex` to match the rest of the S-018 surface). | `tools/test_wire_types.sh` | FA7 / V12 / FA3 / FA6 / S-018 |

### 2.6 Wallet / key surface

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-envelope` | `wallet/envelope.hpp` AES-256-GCM + PBKDF2-HMAC-SHA-256 AEAD wrapping primitive (A2 Phase 2 wallet recovery share envelopes + S-004 option 2 passphrase-encrypted keyfiles; 27 assertions). Encrypt/decrypt round-trip + envelope shape (salt + nonce + tag sizes); AEAD safety properties (wrong-pw / empty-pw / mismatched-AAD / tampered-ct / tampered-tag all fail; fresh salt + nonce per encryption → distinct ciphertexts from same plaintext+passphrase — defeats artifact-correlation attacks); serialize/deserialize canonical hex round-trip with bad-input rejection; empty-plaintext + empty-AAD edge cases. A regression here would silently weaken at-rest security for every encrypted wallet artifact. | `tools/test_envelope.sh` | A2 / S-004 |
| `determ test-shamir` | Shamir's Secret Sharing over GF(2^8) (`wallet/shamir.cpp`; A2 Phase 1 wallet recovery primitive; 18 assertions). T-of-N reconstruction (3-of-5 round-trip; all C(5,3) = 10 subsets verified; T+1 also works; T-1 doesn't reconstruct — the information-theoretic security property); share-shape invariants (distinct x-coordinates; no x=0 since Lagrange evaluates at x=0; y-size matches secret; fresh polynomial per split — two independent splits produce different shares); degenerate thresholds (T=1 = every share is the secret; T=N = all shares required); empty-secret edge case (split produces empty-y shares; combine rejects with nullopt per documented behavior); invalid-input rejection (threshold=0, threshold > share_count, empty share list, duplicate x, mismatched y-sizes). Unit-level counterpart to the network-level `test_wallet_shamir.sh` (wallet-binary CLI smoke test); both lock in the A2 Phase 1 primitive at different layers. | `tools/test_shamir.sh` | A2 Phase 1 |

### 2.7 Fork resolution

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-resolve-fork` | `Chain::resolve_fork` (S-029 BFT-mode fork-choice rule; 10 assertions). When two K-of-K-signed blocks are observed at the same height (only possible in BFT mode where the gather-quorum is ceil(2K/3) rather than K, so signature subsets can differ), resolve_fork picks the canonical tip deterministically: (1) heaviest sig set wins (max non-zero `creator_block_sigs`); (2) tie → fewer `abort_events` wins; (3) tie → smallest block_hash (lexicographic, deterministic across peers). Plus edge cases: identical blocks return first arg, zero-sigs still resolves without crash, sentinel-zero handling in BFT mode (zeros don't count toward weight), abort-tie-break beats hash-tie-break. A regression would either silently let the wrong block win (FA1 violation: peers diverge on canonical tip) or make resolution non-deterministic across nodes. | `tools/test_resolve_fork.sh` | S-029 / FA1 |

---

## 3. What's not yet covered (extension targets)

### 3.1 Cryptographic / consensus surfaces

| Surface | Function(s) | Why high value | Effort |
|---|---|---|---|
| Equivocation event verification | `validator::check_equivocation_events` | FA6 closure surface | ~1d (requires partial NodeRegistry fixture) |
| Bounded mempool | `Node::mempool_admit_check` / `mempool_make_room_for` (S-008) | Admission/eviction policy invariants | ~1d (needs partial Node fixture) |
| AbortClaimMsg verification | `validator::verify_abort_claim` | FA3 surface | ~½d |
| genesis_from_config end-to-end | full initial_state install + chain state seeding | Identity hash + seeded-state contract | ~½d (now that `test-genesis` covers compute_genesis_hash) |
| S-039 fix (operational params binding) | bind m_creators / k_block_sigs / etc. into compute_genesis_hash | Diagnostic-UX gap closure — fix is wire-compat break needing coordinated migration | ~½d code + coordinated rollout |
| Param-change application | `Chain::apply_param_change` (A5 governance) | governance correctness | ~1d |

### 3.2 Mid-level invariants

| Surface | Why | Effort |
|---|---|---|
| `Chain::append` validation paths | Locks chain-level acceptance/rejection invariants | ~1-2d (golden-block fixtures) |
| Abort-tally semantics | FA3 surface | ~½d |
| Fork resolution | S-029 surface | ~1d |
| Wallet keyfile encryption | A2 surface | ~1d |

### 3.3 Deterministic-simulation framework (Option 2)

A separate, larger investment. Would let us script Byzantine actors,
network partitions, clock skew, and verify global safety/liveness
invariants over many randomized executions. Estimated 3-4 weeks. Not
gated by Option 1 progress.

---

## 4. How to add a new unit test

### 4.1 Add the subcommand to `src/main.cpp`

Pick a feature name. The convention is hyphenated:
`test-<noun-phrase>`, e.g., `test-block-codec`.

Add a block in `src/main.cpp`:

```cpp
if (cmd == "test-FEATURE") {
    using namespace determ;
    // additional namespaces as needed
    int fail = 0;
    auto check = [&](bool cond, const char* msg) {
        if (cond) std::cout << "  PASS: " << msg << "\n";
        else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
    };

    // ... assertions ...

    std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
              << ": FEATURE " << (fail == 0 ? "all assertions" : "had failures")
              << "\n";
    return fail == 0 ? 0 : 1;
}
```

### 4.2 Add the wrapper at `tools/test_<feature>.sh`

```bash
#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for FEATURE.
# <one-paragraph description of the surface + safety motivation>
#
# <assertion-by-assertion enumeration>
#
# Run from repo root: bash tools/test_<feature>.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== <one-line surface description> ==="
OUT=$($DETERM test-FEATURE 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: FEATURE all assertions"; then
  echo ""
  echo "  PASS: FEATURE unit test"
  exit 0
else
  echo ""
  echo "  FAIL: FEATURE had assertion failures"
  exit 1
fi
```

### 4.3 Add to `FAST=1` regex in `tools/run_all.sh`

```bash
ONLY_PATTERN='test_(atomic_scope|...|FEATURE)\.sh$'
```

(Plus the comment-block enumeration above the regex.)

### 4.4 Add to `determ help` output

In `src/main.cpp` around the existing `determ test-*` help block, add a
two-line row describing the feature.

### 4.5 Add to docs

- `docs/CLI-REFERENCE.md`: row in the §"S-035 Option 1 seed" table.
- `docs/README.md`: row in the representative-tests table.
- `docs/SECURITY.md` §S-035: row in the surface/FA-track/assertions
  table; bump the headline assertion count.
- `docs/UNIT-TESTS.md` (this file): row in §2 corresponding to the
  surface category.
- Bump test counts in `docs/README.md` headline, `docs/QUICKSTART.md`
  §"Project layout", and `docs/WHITEPAPER-v1.x.md` abstract.

### 4.6 Verify

```bash
# Rebuild
cmake --build build --config Release --target determ

# Run just the new test
build/Release/determ.exe test-FEATURE  # Windows
build/determ test-FEATURE               # Linux/Mac

# Run the full FAST suite
FAST=1 bash tools/run_all.sh
```

### 4.7 Commit

Following the existing in-repo convention:

```
S-035 Option 1 seed: `determ test-FEATURE` — <one-line description>

<body explaining what the surface is, why it matters, and what the
assertions cover>

<files list>

Verified: FAST=1 suite N/N PASS in <Ts>.
```

### 4.8 Byte-layout golden-vector pattern

Three existing tests lock the exact byte layout of wire-format payloads via concrete golden vectors rather than just sensitivity assertions:

- **`test-tx-signing-bytes`** — `Transaction::signing_bytes` (40 assertions)
- **`test-merge-event-bytes`** — `MergeEvent::encode` (48 assertions)
- **`test-block-rand`** (partial) — `compute_delay_seed` / `compute_block_rand` field-ordering

Use this pattern when a new wire-format surface enters the codebase. Sensitivity tests catch "this field changes the output" regressions but miss "the byte position of this field shifted by N" or "endianness flipped from BE to LE" regressions. A clean BE-vs-LE flip would still pass every sensitivity assertion but silently fork the protocol across versions.

**Recipe:**

1. **Pick a minimal input** with default values for every field except the one(s) under test. The output should be a known byte sequence (usually all-zero or a specific small pattern).

2. **Assert the byte at each significant offset.** For example, if `amount` lives at offset 19 in `signing_bytes` as big-endian u64:
   ```cpp
   Transaction t; t.amount = 1;
   auto sb = t.signing_bytes();
   check(sb[19] == 0 && sb[20] == 0 && /* ... */ && sb[26] == 1,
         "amount=1: BE u64 at offsets [19..26], LSB at 26");
   ```

3. **Pick a non-zero pattern** like `0x0102030405060708` that uniquely identifies each byte position. The assertion verifies every byte:
   ```cpp
   t.amount = 0x0102030405060708ULL;
   sb = t.signing_bytes();
   check(sb[19] == 0x01 && sb[20] == 0x02 && /* ... */ && sb[26] == 0x08,
         "amount=0x0102030405060708: BE byte pattern at [19..26]");
   ```

4. **Combined-field golden vector.** A single Transaction / MergeEvent with EVERY field non-default; one omnibus assertion verifies every byte position together. Catches subtle field-reorder regressions that single-field tests might miss.

5. **Endian contrast (when applicable).** Document the BE vs LE choice in the test's comment header. Transaction uses BE (cross-platform hash-input convention per Preliminaries §1.3); MergeEvent uses LE (native memory layout for x86/ARM wire targets). Locking the EXACT byte position via golden vector is the only mechanism that catches a silent endian-flip.

This pattern is mechanical to extend: any new wire-format type with documented byte positions gains a paired `test-<feature>-bytes` test alongside its sensitivity test.

---

## 5. Test discipline

These conventions distinguish a useful unit test from one that rots:

1. **One surface, one test.** Each subcommand covers a single API surface
   (one class, one set of free functions). Resist mixing.

2. **Deterministic inputs.** No `time()`, `random()`, or filesystem-dependent
   state in assertion inputs. Reproducibility across runs is the contract.

3. **Document the EXCLUSION list when relevant.** For functions where
   "fields A and B affect output, but C does not" is part of the design
   (compute_block_digest, signing_bytes), assertions must cover BOTH
   sides. Silent drift across the inclusion/exclusion boundary is a
   common regression source.

4. **Cover ORDER sensitivity where it matters.** Reordering items in
   committee-selection-order or sorted-leaves contexts is a tempting
   "harmless refactor" that breaks consensus. Lock it in.

5. **Cover backward-compat / zero-skip semantics.** Many fields are
   bound into hashes ONLY when non-zero (state_root, partner_subset_hash,
   genesis_message, region). The zero-skip is a backward-compat
   invariant; tests must include `zero == default` AND `non-zero changes
   output` assertions.

6. **Cross-reference the spec.** Every test description in this doc and
   in the wrapper's header comment should cite the relevant proof
   (FA-track), security finding (S-XXX), or design doc (proofs/SPEC.md)
   so future contributors understand why each assertion exists.

7. **Cap each subcommand at <5s.** Long-running tests belong in the
   network-level `tools/test_*.sh` corpus; the in-process subset's value
   is that `FAST=1` is fast enough to run after every save during
   development.
