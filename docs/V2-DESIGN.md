# Determ v2 — Design space

This document scopes the v2 design changes that would make Determ a complete "every base-layer concern handled" protocol. v1.x is feature-complete on its narrow scope (fork-free L1 payment + identity with mutual-distrust safety). v2 closes the structural gaps that v1.x's design intent intentionally deferred.

The intent is not "Ethereum but better" — Determ stays in its lane: a payment + identity chain, no contract VM, no smart-contract execution layer. v2 makes that lane self-sufficient at any scale rather than expanding it.

**Status:** design space only. No code in this document. Each section names the change, its motivation, the implementation sketch, the cost estimate, and which existing v1.x open finding(s) it closes.

---

## Theme 1 — Trust minimization

### v2.1 — State Merkle root in every block

**Motivation.** Closes S-033 (no cryptographic state commitment) and S-012 (snapshot bootstrap trust). Today, a new node bootstrapping from a snapshot trusts the snapshot provider's word. There's no in-block commitment to state-after-apply, so any tampering with the snapshot is undetectable until the receiver applies a subsequent block and trips a derived-state mismatch.

Without state commitment, several capabilities are structurally impossible: light clients cannot verify account balances, cross-shard receipts cannot carry inclusion proofs against the destination's state, audit-grade compliance tools cannot independently verify any chain state without re-executing every block.

**Mechanism.** After every block applies, compute `state_root = MerkleRoot(canonical_state)` where `canonical_state` is the byte-canonical serialization of `accounts_`, `stakes_`, `registrants_`, `applied_inbound_receipts_`, `pending_param_changes_`, `merge_state_` in a fixed order. Include `state_root` in `Block.signing_bytes()` so it's bound by the K-of-K committee signatures.

Validator: re-derives `state_root` post-apply and rejects on mismatch with `block.state_root`. Snapshot: includes the head's `state_root`; receiver re-derives `MerkleRoot(snapshot.state)` and rejects on mismatch.

**Tree shape.** Sparse Merkle tree over fixed-length keys (32-byte hashes of account addresses, validator domain names, etc.). Hash function: SHA-256, matching the rest of the protocol. Tree depth: 256 (fits all 32-byte keys). Inclusion proofs: O(log N) sibling hashes.

**Cost.** Multi-week. Block format change → not backward-compatible → new chain identity (or a flag-day upgrade with explicit migration). The Merkle re-derivation adds ~50-200ms per block at H=10k mature chain; A9 overlay model (v2.4 below) makes this concurrent with the next block's apply, so the latency cost is amortizable.

**Closes:** S-033, S-012, enables v2.2 + v2.3 + v2.7.

### v2.2 — Light-client headers

**Motivation.** With state Merkle roots, external observers can verify chain state without storing the full chain. Today's options are "run a full node" or "trust an RPC provider." Neither is acceptable for permissionless DApp deployment.

**Mechanism.** A light client downloads only block headers (~500 bytes each) plus the chain's K-of-K committee state at each epoch boundary. To verify any account balance: ask any peer for the Merkle proof against the current head's `state_root`, verify the proof matches the header's committed root, done.

Header sync is `O(H)` with small constants. State proofs are `O(log N)`. Both are tiny compared to full-node `O(H · T)` replay.

**Cost.** Medium. Header-only-sync protocol message (new `MsgType::HEADERS_REQUEST`/`HEADERS_RESPONSE`), CLI for `determ light-status` / `determ light-balance`, documentation of trust model (still trusts the committee's signature, not the RPC provider). ~1 week.

**Closes:** A class of DApp deployment models v1.x can't support.

### v2.3 — Trustless fast sync

**Motivation.** Today's `snapshot fetch + restore` requires trusting the snapshot source. With state Merkle roots, fast sync becomes trustless: download the latest snapshot, verify its `state_root` against the head's committee-signed header.

**Mechanism.** Receiver verifies `MerkleRoot(snapshot.accounts ∪ snapshot.stakes ∪ ...) == snapshot.head.state_root`. If yes, install state directly; if no, reject. No need for the receiver to fetch any additional block.

**Cost.** Trivial complement to v2.1. ~50 LOC in `Chain::restore_from_snapshot`.

**Closes:** S-012 fully (replaces today's `head_hash` sanity check with cryptographic verification).

---

## Theme 2 — Scale & concurrency

### v2.4 — Atomic block apply via overlay/delta state (A9)

**Motivation.** Closes S-031's remaining gap. Today, every state mutation goes through one global `state_mutex_` (shared_mutex post-S-031-partial). Long-running writes (`chain.save()` fsync, registry rebuild, snapshot serialization) block all readers during the operation.

**Mechanism.** Introduce an `Overlay` / `Delta` state type wrapping the existing `std::map`s. `apply_transactions` runs on an overlay:

```cpp
Overlay overlay = base_state.snapshot();
for (auto& tx : block.transactions) {
    try { apply_to(overlay, tx); }
    catch { return REJECT; }
}
base_state.commit(overlay);
```

Commit is atomic: either all of the block's mutations land or none. Reads against `base_state` proceed against an immutable snapshot while apply mutates the overlay in the background — concurrent with the writer.

**Side benefits.**
- Validator and producer use the same code path with a `dry_run = true` flag — eliminates validate-vs-apply divergence (S-030 D1 closure).
- Batch primitive becomes a small addition: `Transaction.batch_id: u32` (0 = no batch). Apply path tracks per-batch sub-overlays; if any batch member fails, the whole batch's slot is discarded while other batches in the block still apply.

**Cost.** 3-5 days dedicated work. Refactor every state mutator (transfer, stake, unstake, register, deregister, receipt-bake) to operate on `Overlay`. Snapshot/restore preserves the apply-atomicity property (snapshot taken at block boundary, never mid-block).

**Closes:** S-031 fully, S-030 D1, partial relief for S-016 (inbound-receipts non-determinism), S-018 (JSON parsing under lock).

### v2.5 — Registry cache + persistence (S-032 closure)

**Motivation.** Closes S-032. Already-recommended audit fix. Outlined in detail in `SECURITY.md` and the recent analysis. **Targeted for v1.5 ahead of full v2** because it's a pure runtime refactor with no wire-format change.

**Mechanism.** Cache `registry_view_` on `Chain`. Update incrementally in `apply_transactions` for REGISTER/STAKE/UNSTAKE/DEREGISTER and the equivocation-slashing path. Persist in snapshot. Replace 8 call sites of `build_from_chain` with `chain.registry_view()`.

**Cost.** 1-2 days. Audit's Option 1 + Option 2.

**Closes:** S-032. Quadratic-in-height per-block cost becomes constant.

### v2.6 — Gossip broadcast out of lock

**Motivation.** `rpc_submit_tx` and several other write sites broadcast via gossip while holding `unique_lock<shared_mutex>`. The tx is already in `tx_store_` at broadcast time — the lock could be released. ~10 LOC.

**Cost.** Half day.

**Closes:** Remaining piece of S-031 not handled by v2.4.

---

## Theme 3 — Cryptographic hardening

### v2.7 — F2 view reconciliation (S-030 D2 closure)

**Motivation.** Closes S-030 D2 — the one-block window where two K-of-K-signed instances can share a digest but differ in evidence/receipt lists. Today, the `prev_hash` chain at N+1 closes the window, but inside it honest nodes can apply divergent state and re-sync after the mismatch.

**Mechanism.** Phase-1 view reconciliation. Each member's `ContribMsg` (Phase 1 commit) includes a hash of their view of:
- `equivocation_events` pool
- `inbound_receipts` pool
- `abort_events` from local observation
- `partner_subset_hash` if in a merge

The K signed Phase-1 commits canonicalize via a reconciliation rule (intersection / union / threshold — design choice). Phase-2 signatures cover the reconciled canonical lists (via `compute_block_digest` extended with these fields).

**Reconciliation rule trade-off:**
- **Intersection** (events all K members report) — conservative, biases against slashing inclusion under gossip lag.
- **Union** (any member's report) — aggressive, biases toward inclusion, requires validator to verify every reported event is independently valid.
- **Threshold** (≥ M of K report) — middle ground.

**Cost.** 1-2 days. Wire-format change to `ContribMsg`. Validator re-derivation logic. Documented reconciliation rule.

**Closes:** S-030 D2 fully. FA1's "≤ 1 block instance per digest" becomes literally provable, removing the footnote on the headline safety claim.

### v2.8 — Post-quantum signature migration

**Motivation.** Ed25519's quantum-vulnerability is well-understood: Shor's algorithm breaks discrete-log signatures in polynomial time on a sufficiently large quantum computer. Current consensus is that production-relevant quantum computers are 10-20 years away; v2 should be ready before then rather than emergency-patching after.

**Mechanism.** Replace Ed25519 with a NIST-PQ-finalist signature: **Dilithium** (preferred — lattice-based, NIST PQC standardization track) or **Falcon** (smaller signatures, more complex implementation). Both have stable C reference implementations.

Transition path:
1. **Dual-key registration.** Validators register both Ed25519 and Dilithium pubkeys. Phase 1 publishes commitments for both. Phase 2 reveals + signs with both.
2. **Tag per-block which signature scheme is canonical.** Pre-flag-day: Ed25519. Post-flag-day: Dilithium. Block format carries `consensus_signature_scheme: u8`.
3. **At flag-day height H**, the canonical scheme switches. All committee signatures use Dilithium from height H onward.

Wallet recovery (A2) similarly: dual-derived seed (Ed25519 + Dilithium private keys both derived from the same 32-byte master seed via HKDF labels).

**Cost.** 1-2 weeks. Dilithium reference impl integration (libdilithium or pqclean). Block format change. Genesis schema update. Migration path documentation. Bandwidth impact: Dilithium signatures are ~2.5 KB vs Ed25519's 64 bytes — block size grows substantially. Worth it for chain longevity.

**Closes:** None of today's open findings (Ed25519 is fine today). Closes the future-attack vector that would otherwise require an emergency hard fork.

---

## Theme 4 — Liveness & randomness

### v2.9 — Distributed VRF for committee selection

**Motivation.** Today, committee selection is deterministic from `cumulative_rand` (which is itself the K-of-K commit-reveal output). This is unbiased in steady state but offers no liveness benefit when a committee member silently aborts — the K-of-K MD path stalls until BFT escalation kicks in.

A threshold VRF (e.g., BLS-DKG with t-of-K signers) provides randomness with `t < K` participants. Even if `K - t` members are silent, the t honest members can complete the randomness round.

**Trade-off:** introduces BLS (pairing-friendly curves) into Determ's cryptographic stack — currently SHA-256 + Ed25519 only. The "two primitives only" minimalism is a design value; BLS doubles the audit surface.

**Recommendation:** defer to v2.x or v3. The K-of-K commit-reveal + BFT escalation tandem is working; the marginal liveness gain isn't worth the cryptographic-stack expansion.

**Status.** Considered, deprioritized. Listed for completeness; not on the v2 roadmap.

### v2.10 — Threshold randomness aggregation

**Motivation.** Similar problem as v2.9, different solution. Instead of BLS, use SHA-256 commit-reveal but aggregate `secrets` only from the t-of-K members who reveal. Under K-of-K stall, `delay_output` is still computed deterministically from the available reveals.

**Mechanism.** Modify Phase-2 finalize: instead of `delay_output = SHA-256(delay_seed ‖ secret_1 ‖ … ‖ secret_K)`, use `delay_output = SHA-256(delay_seed ‖ sort(revealed_secrets))`. As long as `t ≥ K/3 + 1`, the output is unbiasable by the silent K-t members (their commits were already published in Phase 1; they just didn't reveal).

**Cost.** ~1 week. Validator path change, signing-bytes change. Composes with existing FA3 proof — the information-theoretic argument extends to t-of-K naturally.

**Closes:** None of today's findings. Improves liveness under partial committee silence without the v2.9 BLS dependency.

### v2.11 — Auto-detection beacon-side trigger (R4 v1.1)

**Motivation.** R4 ships in v1.x with operator-driven `MERGE_EVENT` submission via `determ submit-merge-event`. Production deployments want auto-detection: beacon observes `eligible_in_region(s) < 2K` over `merge_threshold_blocks` and no `SHARD_TIP_s` arrival → emits `MERGE_BEGIN` autonomously.

**Mechanism.** Beacon maintains a per-shard observation window. State machine: NORMAL → STRESS_CANDIDATE (after first observation) → STRESS_TRIGGER (after threshold) → emits MERGE_BEGIN. Symmetric for revert with hysteresis.

S-036 witness-window historical validation closes here: the beacon's emitted `evidence_window_start` is verifiable by any other node re-deriving the observation history from previously-finalized blocks. Combined with the existing committee-signature ratification of MERGE_EVENT, a captured-beacon attack cannot manufacture an unwarranted merge without lying about historical content that's independently verifiable.

**Cost.** 2-3 days. Beacon-side state machine, integration with the existing R4 apply path, integration test.

**Closes:** R4's v1.1 follow-on, partial S-036 closure (full closure needs on-chain SHARD_TIP records, separate item).

---

## Theme 5 — Composability

### v2.12 — Cross-shard atomic primitives

**Motivation.** Today's cross-shard transfer is two-phase: source debits, beacon relays, destination credits. Source-debit and destination-credit are temporally decoupled (FA7 covers safety). For some use cases (cross-shard atomic swaps, DEX matching across shards) operators want all-or-nothing semantics.

**Mechanism.** New tx type `CROSS_SHARD_SWAP`: carries a `(src_action, dst_action, timeout_height)` tuple. Source-shard apply locks the input; destination-shard apply commits the output. Beacon coordinates the two-phase commit. If the destination fails to commit by `timeout_height`, source unlocks.

This is a 2PC layered on the existing receipt mechanism. Doesn't change FA7's existing atomicity properties; adds an explicit-rollback primitive for use cases that need it.

**Cost.** 1 week. New tx types, two-shard coordination, timeout-refund path, integration tests.

**Closes:** A class of DApp deployment models that need atomic cross-shard transactions.

### v2.13 — Fair-ordering primitive

**Motivation.** Determ's union-tx-root means inclusion is collaborative (FA2), but the *ordering* within a block is producer-chosen. For DEX deployments, MEV-extractive orderings (frontrun, sandwich) are possible at the committee level.

**Mechanism.** Per-block commit-reveal on tx ordering. Phase-1 commits include a hash of the producer's intended tx ordering. Phase-2 reveals the ordering. The block's canonical ordering is derived from the K revealed orderings via a fair-aggregation rule (e.g., random-shuffle seeded by `cumulative_rand`, or Aequitas-style intersection ordering).

**Cost.** Multi-week. Validator change, ordering-rule design (which is itself a hard problem — see Aequitas, Themis literature).

**Status.** Considered, deprioritized — fair ordering is an open research area. Not on the v2 roadmap; flagged for future protocol families built on Determ.

---

## Theme 6 — Wallet & operator UX

### v2.14 — Real OPAQUE wallet recovery (A2 Phase 6.1)

**Motivation.** v1.x ships the wallet's OPAQUE adapter as a stub (Argon2id directly). The stub is offline-grindable from any single compromised guardian. Real OPAQUE (libopaque + liboprf, integrated correctly with Windows MSVC) closes this.

**Mechanism.** Vendor libopaque + liboprf with MSVC-compatible source patches (replace C99 VLAs with `_alloca`/`alloca` wrappers; the existing `wallet/PHASE6_PORTING_NOTES.md` documents the patches needed). Replace `opaque_adapter.cpp`'s stub with calls to libopaque. The recovery flow (`create_opaque`, `recover`) is unchanged — Phase 7 already routes through the adapter.

**Cost.** 1-2 days dedicated MSVC porting work, or pivot to opaque-ke (Rust) with FFI bindings.

**Closes:** A2 Phase 6 from v1.x.

### v2.15 — Wallet HD derivation + multi-sig

**Motivation.** A single Ed25519 seed per wallet is BIP-32 stone-age. Real wallets use hierarchical derivation (BIP-32/BIP-44) so one master seed manages many addresses with deterministic recovery. Multi-sig (M-of-N approval per tx) is table-stakes for any meaningful business deployment.

**Mechanism.** HD derivation via HKDF-SHA-256 over the seed (Ed25519 doesn't have a standardized HD scheme like secp256k1's BIP-32; SLIP-0010 covers Ed25519 specifically). Multi-sig as a wallet-side construct: a tx is the aggregation of M Ed25519 signatures over the same payload; the chain treats it as a single tx with M sigs in a witness list.

**Cost.** 1 week wallet-side. Chain-side: optional witness-list extension to `Transaction` (backward-compat by default size 0). Hardware-wallet integration follows naturally.

**Closes:** UX gap for enterprise / consortium deployments.

### v2.16 — Internal RPC authentication (S-001 internal)

**Motivation.** v1.x landed localhost-only RPC bind as default. Remaining gap: multi-tenant hosts where multiple processes share loopback.

**Mechanism.** Mandatory HMAC-SHA-256 token middleware. Token generated at first start, stored at `{data_dir}/rpc_token` with 0600 permissions. Every RPC call carries `X-Determ-Auth: <token>` header (over the existing JSON-line transport — add to the request envelope, not the body). Server compares constant-time.

**Cost.** Half day. Token gen + verification + CLI `determ status` etc. need to pass the token from `{data_dir}/rpc_token` automatically.

**Closes:** S-001 fully.

### v2.17 — Passphrase-encrypted keyfiles (S-004 option 2)

**Motivation.** v1.x landed no-stdout default + 0600 perms (S-004 option 1). Remaining: encryption at rest. The wallet binary's `envelope.cpp` already implements AES-256-GCM + PBKDF2-HMAC-SHA-256; main.cpp can call into it.

**Mechanism.** `determ account create --passphrase` prompts (or reads from env var) for a passphrase, runs the seed through `envelope::encrypt`, writes the envelope blob to disk. `determ account address` and any other consumer prompts to decrypt before use.

**Cost.** Half day. The crypto is already shipped; the work is wiring + CLI UX + env-var override for unattended scripts.

**Closes:** S-004 option 2.

---

## Cumulative v2 closes

| Open finding | Closure path |
|---|---|
| S-001 internal | v2.16 |
| S-002 — already closed in v1.x | — |
| S-003 — already closed in v1.x | — |
| S-004 — option 1 in v1.x, option 2 in v2.17 | v2.17 |
| S-007 — already closed in v1.x | — |
| S-008 unbounded memory | bounded by v2.5's registry cache + future tx mempool cap |
| S-010 sybil under-priced MIN_STAKE | operator parameter; v2 docs guidance |
| S-011 abort-claim cartel | v2 docs (mitigated by stake economics today) |
| S-012 snapshot trust | v2.3 |
| S-030 D1 (validate-apply divergence) | v2.4 |
| S-030 D2 (block_digest coverage) | v2.7 |
| S-031 full | v2.4 + v2.6 |
| S-032 registry rebuild | v2.5 (recommended landing in v1.5) |
| S-033 no state commitment | v2.1 |
| S-036 witness-window | v2.11 |

Roughly 12 of the 24 currently-open findings close in v2. The rest are operator-policy concerns or design choices that v2 doesn't change.

---

## Total v2 effort

| Layer | Work | Estimate |
|---|---|---|
| Trust minimization (v2.1–v2.3) | State Merkle root + light clients + trustless fast sync | 4-6 weeks |
| Scale & concurrency (v2.4–v2.6) | A9 overlay, registry cache, gossip-out-of-lock | 1 week (registry cache lands in v1.5) + 1 week |
| Cryptographic hardening (v2.7–v2.8) | F2 view reconciliation, Dilithium migration | 2-3 weeks |
| Liveness (v2.10, v2.11) | Threshold randomness aggregation, beacon auto-detect | 1.5 weeks |
| Composability (v2.12) | Cross-shard atomic primitives | 1 week |
| Wallet/operator (v2.14–v2.17) | OPAQUE port, HD derivation, RPC auth, encrypted keyfiles | 2 weeks |

**Total: 12-16 weeks** for a single coordinated v2 release. Or, broken into rolling releases:
- **v1.5** (registry cache): 1 week — ships ahead of any other v2 work
- **v1.6** (gossip-out-of-lock + light-RPC auth): 1 week
- **v2.0** (state Merkle root + A9 overlay + trustless fast sync): 6-8 weeks — the "complete platform" release
- **v2.1** (F2 view reconciliation + auto-merge): 3 weeks — closes the FA1 footnote and the R4 v1.1
- **v2.2** (Dilithium migration): 1-2 weeks — long-runway crypto-agility
- **v2.3** (wallet HD + atomic cross-shard + encrypted keyfiles): 3 weeks — DApp-readiness

---

## What v2 explicitly does NOT add

The non-goals from v1.x stand. v2 does not add:

- **Smart-contract execution layer** (EVM, WASM). Determ stays in its "narrow base-layer" lane. Contracts belong on layered protocols, not the base chain.
- **Off-chain storage** (IPFS-like integration).
- **Cross-chain bridges as a base-layer primitive**. The cross-shard atomic primitive (v2.12) is intra-Determ; external-chain bridges remain application-layer.
- **Oracle networks**.
- **ZK / shielded transactions**. Anonymous bearer wallets remain the privacy story.

These are intentional design choices, not v2 backlog. A different protocol that wants any of them should fork Determ or build a layer on top, not push it into the base.

---

## Compatibility & migration

v2 is not backward-compatible at the block format level (state Merkle root, Dilithium signatures, F2 ContribMsg view-hashes all change wire format). The migration path:

1. **Genesis flag-day**: new chains start at v2 from day one. Existing v1.x chains have two options:
2. **Hard fork at height H**: existing chain coordinates an upgrade with all validators upgrading binaries at the same height. Pre-H blocks use v1.x format; post-H blocks use v2 format. Old binaries can replay pre-H but not validate post-H.
3. **Or stay on v1.x**: v1.x continues to be supported indefinitely. v2 is a new chain identity for deployments that need its features.

Most deployments will pick option 1 (fresh genesis with v2). Established v1.x chains coordinating an upgrade pick option 2 with a multi-month deprecation notice.

---

## Why this scope

Five thematic clusters address every structurally significant open issue:
- **Trust minimization** = the standard L1 feature gap (state commitment, light clients).
- **Scale & concurrency** = production-deployment scalability (registry, overlay, gossip).
- **Cryptographic hardening** = audit-grade rigor (F2 closes the FA1 footnote) + future-proofing (Dilithium).
- **Liveness** = silent-committee-member tolerance without BFT-escalation cost.
- **Composability** = cross-shard primitives + wallet UX for real deployments.

What's deliberately not in scope: smart contracts, oracles, bridges, ZK. Each would be a coherent direction but moves Determ out of its lane. v2 doubles down on the lane.

After v2, Determ is a "complete" base-layer L1 with no internal limitations. Whether anything is built on top is up to operators; the base protocol is self-sufficient.
