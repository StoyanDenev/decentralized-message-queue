# Determ v2 — Design space

This document scopes the v2 design changes that would make Determ a complete "every base-layer concern handled" protocol. v1.x is feature-complete on its narrow scope (fork-free L1 payment + identity with mutual-distrust safety). v2 closes the structural gaps that v1.x's design intent intentionally deferred.

The intent is not "Ethereum but better" — Determ stays in its lane: a payment + identity chain, no contract VM, no smart-contract execution layer. v2 makes that lane self-sufficient at any scale rather than expanding it.

**Status:** design + partial implementation. Document captures the design space; multiple themes have shipping code in tree. Each section names the change, its motivation, the implementation sketch, the cost estimate, and which existing v1.x open finding(s) it closes; design and code may have diverged for items currently shipping.

**Per-item status (audit against current `git log`):**

| Item | Status | Notes |
|---|---|---|
| v2.1 State Merkle root | ✅ shipped | `compute_state_root()` + Block.state_root + verification on apply/restore |
| v2.2 Light-client headers / state_proof RPC | ✅ shipped foundation | SMT inclusion-proof RPC + CLI; full light-client header-sync remains |
| v2.3 Trustless fast sync | ✅ shipped | state_root verified on snapshot restore |
| v2.4 Atomic block apply (A9) | ✅ shipped | A9 Phase 1-2D + COMPOSABLE_BATCH tx |
| v2.5 Registry cache (S-032) | ✅ shipped | Cached registry view; S-032 closed |
| v2.6 Gossip broadcast out of lock | ✅ shipped | All 5 broadcast sites release unique_lock before broadcast |
| v2.7 F2 view reconciliation | ⏳ not started | S-030 D2 closure |
| v2.8 Post-quantum signature migration (Dilithium) | ⏳ not started | NH4 prerequisite |
| v2.9 Distributed VRF for committee selection | ⏳ not started | |
| v2.10 Threshold randomness aggregation | 🔥 **active** | Promoted to defeat residual selective-abort attack. See plan.md A11 for active task brief |
| v2.11 Auto-detection beacon-side trigger (R4 v1.1) | ⏳ not started | |
| v2.12 Cross-shard atomic primitives | ⏳ not started | |
| v2.13 Fair-ordering primitive | 🔒 deferred (research) | Open research area; not on v2 critical path |
| v2.14 Real OPAQUE wallet recovery | ⏳ not started | |
| v2.15 Wallet HD derivation + multi-sig | ⏳ not started | |
| v2.16 Internal RPC authentication (S-001) | ✅ shipped | HMAC-SHA-256 + localhost-only default |
| v2.17 Passphrase-encrypted keyfiles (S-004) | ✅ shipped | AES-256-GCM envelope |
| v2.18 DAPP_REGISTER tx + on-chain DApp registry | ✅ shipped | Theme 7 substrate |
| v2.19 DAPP_CALL tx + payload routing | ✅ shipped | Theme 7 substrate |
| v2.20 Streaming subscription RPC | ⚠️ partial | Polling shipped; full streaming pending |
| v2.21+ DApp ecosystem items | 🔒 deferred | See V2-DAPP-DESIGN.md |
| v2.22 Confidential transactions (Bulletproofs) | ⏳ not started | Theme 8 |
| v2.23 Cross-chain bridge (IBC-style) | ⏳ not started | Theme 8 |
| v2.24 Audit / compliance hooks | ⏳ not started | Theme 8 |

**Shipped: 10. Active: 1 (v2.10). Partial: 1 (v2.20). Outstanding: 10. Deferred: 2 (v2.13, v2.21+).**

For the live shipped-items list, run `git log --oneline | grep -iE 'v2\\.'` — the table above is best-effort accurate as of this revision.

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

### v2.7 — F2 view reconciliation (S-030 D2 full closure)

**Motivation.** Closes S-030 D2 at the consensus layer. D2 is the structural property that two K-of-K-signed block instances can share a digest but differ in evidence/receipt lists — the digest covers a strict subset of block fields.

**Current state (post-S-033, partial closure).** S-033's state_root binding into `Block::signing_bytes` indirectly closes D2 at the apply layer: divergent evidence/receipt lists produce different post-apply states, hence different state_roots, hence apply-time rejection on any honest node. Two K-of-K-signed instances can still both circulate on the gossip layer (their signatures over `compute_block_digest` are both valid), but only one apply-validates. Honest-majority deployments are functionally complete; a fully-Byzantine committee minting two instances remains a residual consensus-layer gap.

**v2.7's value-add over S-033.** Closes the consensus-layer gap directly: signatures gather only around one canonical view, so two instances cannot both be K-of-K-signed in the first place. For permissionless deployments wanting the literal "≤ 1 finalized K-of-K signature gathering per height," this is the structural fix.

**Mechanism.** Phase-1 view reconciliation. Each member's `ContribMsg` (Phase 1 commit) includes a hash of their view of:
- `equivocation_events` pool
- `inbound_receipts` pool
- `abort_events` from local observation
- `partner_subset_hash` if in a merge

The K signed Phase-1 commits canonicalize via a reconciliation rule (intersection / union / threshold — design choice, see `F2-SPEC.md` for per-field analysis). Phase-2 signatures cover the reconciled canonical lists (via `compute_block_digest` extended with these fields).

**Open design questions before implementation.** The prior in-tree attempt at a naive extension broke the equivocation-slashing regression test under gossip-async view divergence (`docs/proofs/S030-D2-Analysis.md` §2). A second attempt requires resolving:
1. Per-field reconciliation rule (different rules for evidence vs receipts)
2. Pool snapshot timing semantics
3. Wire format for view hashes (full list vs Merkle root)
4. Phase-1 commit binding scope (combined vs per-field)
5. Phase-2 signature semantics under union rule (binding evidence Phase-1 didn't see)
6. Timestamp inclusion (in v2.7 scope or separate)
7. Validator-side reconciliation caching
8. Monitoring metrics for view-divergence rate
9. FA1 proof update

See `docs/proofs/F2-SPEC.md` for resolutions / recommendations on each.

**Cost.**
- Specification: half day (resolve the 9 design questions; write `F2-SPEC.md`).
- Implementation given a final specification: 1-2 days.
- Wire-format change to `ContribMsg`. Validator re-derivation logic. Reconciliation rule(s) documented.

**Closes:** S-030 D2 fully (consensus-layer). FA1's "≤ 1 block instance per digest" becomes literally provable at the consensus layer, not just at apply. Removes the partial-closure footnote (Safety.md §5.3).

**Comparison with S-033 (currently shipped, partial closure):**

| Property | S-033 (apply-layer) | v2.7 F2 (consensus-layer) |
|---|---|---|
| Two K-of-K instances can exist on the wire | Yes (one fails apply) | No (signatures don't gather) |
| Threat model coverage | Honest-majority committees | Permissionless, including 2-instance Byzantine committees |
| Cost | Shipped | 1-2 days + specification |
| Wire format | None (state_root field added) | ContribMsg extension (wire bump) |

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

### v2.10 — Threshold randomness aggregation 🔥 active

**Status: promoted to active A-track** (plan.md A11). The mechanism described below has been **revised** from the earlier "aggregate-revealed-subset" approach to a stronger **t-of-K threshold-signature** scheme. The revision is motivated by a residual selective-abort attack the simpler approach didn't defeat.

**Motivation.** Determ's current commit-reveal randomness leaves a residual selective-abort attack: a committee member can decline to reveal in Phase 2, forcing a re-run with different randomness. The adversary computes what `delay_output` would be (they have all K-1 commits + their own committed secret), and selectively aborts when the outcome is unfavorable.

Defenses today (`SUSPENSION_SLASH = 10` per abort + BFT escalation) make the attack economically costly but allow **statistical bias** by paying stake per unfavorable round. For high-value randomness-dependent outcomes (committee rotation per epoch, future-block randomness used in fair-ordering DApps), the residual bias matters.

**Earlier (now-deprecated) approach: aggregate-revealed-subset.** Compute `delay_output = SHA-256(delay_seed ‖ sort(revealed_secrets))` from the t members who revealed. This addresses K-of-K liveness stall but does NOT defeat selective abort — the silent K-t members still influence randomness by choosing whether to reveal (the aggregate depends on the revealed subset). Rejected in favor of true threshold signatures.

**Current (active) mechanism: t-of-K threshold signatures.** Each committee member generates a `partial_sig_i = sign(secret_share_i, beacon_seed ‖ height)` using a t-of-K threshold-signature scheme (BLS12-381 or equivalent). Any `t = ceil(2K/3)` partial signatures combine into the SAME canonical `R = combine(partial_sig_{i1}, …, partial_sig_{it})`. The combined signature `R` replaces today's `delay_output`.

**Critical property.** Any `t` partial signatures produce the SAME `R`. A withholding adversary doesn't change `R` — the other `K-t` members' partials are sufficient. Selective abort becomes ineffective for biasing randomness.

| Today (commit-reveal) | After v2.10 (threshold) |
|---|---|
| Adversary withholding their secret aborts the round | Adversary withholding their partial sig does nothing — other t members suffice |
| Adversary chooses to reveal/abort based on whether R favors them | Adversary cannot prevent R; their choice is irrelevant |
| Bias possible by paying SUSPENSION_SLASH per abort | Bias requires controlling ≥ K-t+1 members — standard Byzantine bound |

**Cost.** ~1 week per plan.md A11 cost estimate. Foundation: vendored threshold-signature library (BLS12-381 reference impl or alternate, ~2-3 days). Integration with existing commit-reveal phases (~2-3 days). DKG (distributed key generation) tooling for genesis-time threshold-key setup (~1 day). Tests + docs (~1-2 days).

**Wire-format implications.** `creator_dh_secrets` becomes `creator_partial_sigs`. Not backward-compatible with v1 chains — flag-day upgrade required.

**Composes with v2.9** (distributed VRF): VRF unbiasability + threshold randomness aggregation together close the entire randomness attack surface. Either alone is good; both together is best.

**Closes:** residual selective-abort bias in randomness (the only remaining randomness-bias vector after commit-reveal closed the broader class). Strengthens FA3 information-theoretic argument from "K-of-K commit-reveal" to "t-of-K threshold aggregation," which is the strongest possible bound (matches Byzantine takeover threshold).

Full task brief: `plan.md` §A11.

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

## Theme 7 — Application layer (DApp support)

Determ stays a payment + identity chain. The application layer makes that
trust anchor usable by off-chain DApps without expanding the protocol into
a smart-contract platform. Two primitives: a DApp registry (analogous to
the validator registry) and a `DAPP_CALL` message-tx type. DApp logic
itself runs off-chain on operator-controlled nodes; the chain provides
ordered, authenticated message delivery + stable user identity.

Full design: [`V2-DAPP-DESIGN.md`](V2-DAPP-DESIGN.md). Summary:

### v2.18 — `DAPP_REGISTER` tx + on-chain DApp registry

**Motivation.** Stable, on-chain DApp identity. Clients can look up a DApp's `service_pubkey` and `endpoint_url` from the chain instead of trusting external directories.

**Mechanism.** New `TxType::DAPP_REGISTER` (op = create/update/deactivate) + new `dapp_registry_` member on Chain. Mirror of the existing `registrants_` pattern; same lazy-snapshot + state-root integration story. Anti-spam: DApp domain must have ≥ `DAPP_MIN_STAKE` locked.

**Cost.** ~2 days. Tx type + state field + RPC `dapp_info` + lazy-snapshot + state-root wiring.

**Closes:** none directly — enables Theme 7's downstream items.

### v2.19 — `DAPP_CALL` tx + payload routing

**Motivation.** Authenticated message delivery from users to DApps. Payload opaque to chain (the DApp interprets); routing by recipient domain.

**Mechanism.** New `TxType::DAPP_CALL` carrying `to` (DApp domain), `amount` (optional payment), and an opaque ciphertext payload. Validator: rejects calls to inactive/missing DApps + enforces payload-size cap. Apply: TRANSFER-like credit of `amount` to recipient; payload itself does not mutate state (just sits in the block).

**Cost.** ~2 days. Tx type + validator gate + apply path + wallet CLI (`determ dapp-call`).

**Closes:** none directly — first application of the Theme-7 substrate.

### v2.20 — Streaming subscription RPC

**Motivation.** DApp nodes need a live tail of `DAPP_CALL` events as blocks finalize. Polling `dapp_messages` is wasteful at high rates.

**Mechanism.** New `dapp_subscribe(domain, topic?)` RPC — newline-JSON streaming over the existing RPC socket. Per-block hook fires after the async-save worker, filters DAPP_CALLs by recipient, emits to matching subscribers. Bounded per-subscriber queue with disconnect-on-overflow.

**Cost.** ~3 days. Per-block subscriber-broadcast hook + bounded queue management + integration with existing RPC session lifecycle.

**Closes:** none — operational improvement for DApp node implementers.

### v2.21+ deferred

- DApp SDK + reference implementation (ecosystem)
- Cross-shard DApp routing (depends on regional-sharding completion)
- DApp slashing (proof-of-misbehavior tx types)
- DApp upgrade flows (service_pubkey rotation with grace period)

Full roadmap, open design questions, and economic model: [`V2-DAPP-DESIGN.md`](V2-DAPP-DESIGN.md). The companion doc also covers the **Direct-to-DApp delivery pattern** (V2-DAPP-DESIGN.md §10) — an off-chain message delivery pattern using the on-chain DApp registry for endpoint discovery + libsodium sealed-box for confidentiality. Fully implementable today on the v2.18 substrate; no new protocol code required.

---

## Theme 8 — Privacy & interop (god-protocol completeness for Determ's lane)

Determ stays in its lane (payment + identity). But "best-in-class at that lane" requires two primitives v1.x + Themes 1-7 do not yet provide: **confidential transactions** and **cross-chain bridge**. Both are necessary for Determ to serve real-world payment use cases (where amounts shouldn't be public by default) and for the ecosystem to interoperate with other chains' user bases.

### v2.22 — Confidential transactions (Pedersen commitments + Bulletproofs)

**Motivation.** Today every TRANSFER amount is public on-chain. For payment use cases — payroll, vendor payments, B2B settlement, retail — this is incompatible with normal commercial confidentiality. The alternative (every user using a mixer DApp) doesn't compose with audit-grade compliance.

**Mechanism.** Replace TRANSFER's clear-text `amount: u64` with a Pedersen commitment `C = aG + bH` where `a` is the amount and `b` is a blinding factor. Sender attaches a Bulletproof range-proof that `0 <= a <= 2^64` (so amounts can't underflow), and a balance-conservation proof binding inputs and outputs. Recipient learns `a` via a Diffie-Hellman handshake with the sender's view key.

Optional view-key disclosure: account holders can publish a per-account or per-block view key that lets a designated auditor decrypt amounts. Solves the regulated-counterparty problem without forcing global transparency.


**Cost.** 2-3 months. Bulletproofs implementation (curve25519 + range-proof aggregation) + view-key key-derivation + wallet integration + RPC schema. Sender + receiver code paths. Audit-mode docs.

**Closes:** new capability (no existing finding). Enables real-world payment use cases that today need a separate privacy chain.

### v2.23 — Cross-chain bridge (IBC-style light-client verification)

**Motivation.** Determ exists in a multi-chain world. Today a Determ deployment is an island — no value or message can flow to/from Ethereum, Cosmos, Bitcoin, or other Determ deployments without trusted intermediaries (centralized exchanges, custodial bridges). Both options break Determ's mutual-distrust trust model.

**Mechanism.** IBC-style: each side runs a light client of the other side. Sender chain locks the asset and emits a proof. Receiver chain verifies the proof against the sender's committee signatures (already authenticated via state_root from v2.1). Asset materializes as a wrapped representation on the receiver side; unwrap by reversing the flow.

Phasing:
- **Determ-to-Determ** (multi-deployment): native, light-client verification against the other deployment's manifest + state_root + committee history. ~1 month.
- **Determ-to-Cosmos**: implement IBC light-client spec on the Determ side. ~2 months.
- **Determ-to-Bitcoin**: SPV-style. Verify UTXO inclusion via Merkle proofs. ~2 months.
- **Determ-to-Ethereum**: defer until SNARK-of-Ethereum-light-client tooling matures (~6+ months).

**Cost.** 1-2 months for first bridge (Determ↔Determ). 2-3 months for IBC. 6+ months for Ethereum.

**Closes:** new capability. Determ becomes a payment rail other ecosystems can use rather than a walled garden.

### v2.24 — Audit / compliance hooks

**Motivation.** Privacy by default (v2.22) needs an explicit opt-in for regulated deployments to expose amounts/parties to designated auditors (KYC/AML/tax authorities). Without this, Determ is unusable for any payment business with counterparty-disclosure obligations.

**Mechanism.** Per-account `audit_view_key`: a Diffie-Hellman public key whose holder can decrypt the account's amounts. Genesis-pinned default (`""` = no auditor). Optionally rotatable via REGISTER-style tx jointly signed by the audit-key-holder and the account holder. Audit-mode operators run a special node that consumes the audit log + auditor view keys + produces compliance reports.

**Cost.** 2-3 weeks. Audit-key field on accounts + view-key handshake + audit-mode RPC + auditor-tooling reference impl.

**Closes:** removes the "Determ is unusable for regulated payments" objection. Composes cleanly with v2.22's privacy.

---

## God-protocol framing for Determ

Determ explicitly does NOT aspire to be a "do-everything" chain. The competitive landscape (Ethereum, Cosmos, Polkadot, Aptos, Sui) saturates that space.

The achievable, defensible framing is:

> **Determ = the protocol that's so good at payment + identity that every other DApp use case is built on top of it as a Theme-7 DApp, not as a contract on a contract-VM chain.**

Under this framing, "god protocol" means **best-in-class at the narrow scope, not biggest-feature-set across all scopes**. The work to close the remaining gap:

| Capability | Today | After |
|---|---|---|
| Sub-100ms regional finality | Tactical=40ms; web=200ms | Same; already best-in-class |
| Horizontal scale | Beacon caps ~20-50 shards | v2 beaconless removes the cap |
| Confidential amounts | None | v2.22 Pedersen + Bulletproofs |
| Account abstraction | Single Ed25519 | v2.14 OPAQUE recovery + v2.15 HD + multi-sig |
| Quantum resistance | Ed25519 | v2.8 Dilithium |
| Cross-chain interop | None | v2.23 IBC bridge (Determ↔Determ first; Cosmos second) |
| Compliance / audit | None | v2.24 view-key disclosure |
| Fair ordering | None | Deferred (research; v2.13 noted) |
| DApp surface | None today | Themes 7 + v2.22/23/24 give the substrate |

Total work to close: **~12-18 months focused engineering beyond what's already in V2-DESIGN.md** (themes 1-7 land in ~12-16 weeks per existing estimate; theme 8 + DApp ecosystem maturation add ~6-12 more months).

### What this is NOT

- Not a contract VM. DApps run off-chain on operator nodes (Theme 7 substrate); Determ provides ordered authenticated message delivery + identity + payments + integrity.
- Not stateless validation. Determ's state is small enough that full-node operation is feasible on commodity hardware.
- Not a DA layer. Not a rollup substrate. Not a generalized computation platform.
- Not Ethereum-tier completeness. Different protocol family.

### Why this is achievable

Each theme is independently estimable, has a clear deliverable, and composes with the others. There's no research-grade unknown remaining (fair ordering and Ethereum-bridge SNARK are explicitly deferred). The ~12-18 month path is engineering, not research.

The result is **a payment + identity protocol that's complete enough for any commercial use case** (privacy, audit, cross-chain, quantum-resistance) without expanding into territory better-served by other chains.

---

## Cumulative v2 closes

| Finding | Closure path | Status |
|---|---|---|
| S-001 (RPC auth) | v2.16 HMAC-SHA-256 + localhost-only default | ✅ shipped |
| S-002 (mempool sig-verify) | v1.x sig-verify on gossip + RPC paths | ✅ shipped |
| S-003 (timestamp window) | ±30s window align | ✅ shipped |
| S-004 (plaintext keys) | option 1 (0600 + no-stdout) + option 2 (v2.17 AES-256-GCM envelope) | ✅ shipped |
| S-007 (overflow) | checked_add_u64 on credit paths | ✅ shipped |
| S-008 (unbounded mempool) | MEMPOOL_MAX_TXS + fee-priority eviction + per-sender quota | ✅ shipped |
| S-010 (sybil) | operator parameter; v2 docs guidance | ⏳ open (design item) |
| S-011 (abort-claim cartel) | v2 docs (mitigated by stake economics today) | ⏳ open (design item) |
| S-012 (snapshot trust) | v2.1 state_root + v2.3 snapshot verification | ✅ shipped |
| S-030 D1 (validate-apply) | v2.1 state_root indirect closure (via signing_bytes + apply-time check) | ✅ effective |
| S-030 D2 (block_digest) | v2.1 state_root partial closure + v2.7 F2 for full | 🟠 partial |
| S-031 (global mutex) | v2.4 A9 + v2.5 + v2.6 + async chain.save | ✅ shipped (all 6 layers) |
| S-032 (registry rebuild) | v2.5 incremental cache | ✅ shipped |
| S-033 (no state commitment) | v2.1 Merkle root + Block.state_root | ✅ shipped |
| S-036 (witness-window) | v2.11 beacon-side auto-detect | ⏳ open |

**Findings closure status:** 12 fully closed in-session + 1 partially closed (S-030) + 3 still open (S-010, S-011, S-036 — all design items or operator-policy, not shipped-code attack surface). The "12 of 24 close in v2" original target has been substantially overshot in-session.

---

## Total v2 effort

Layer-level estimates with shipped vs remaining split:

| Layer | Work | Total estimate | Shipped (in-tree) | Remaining |
|---|---|---|---|---|
| Trust minimization (v2.1–v2.3) | State Merkle root + light clients + trustless fast sync | 4-6 weeks | ✅ all 3 shipped (foundation; full header-only-sync flow still pending) | ~1 week (light-client header sync flow) |
| Scale & concurrency (v2.4–v2.6) | A9 overlay, registry cache, gossip-out-of-lock | 2 weeks | ✅ all 3 shipped (A9 Phase 1-2D, registry cache, gossip-out-of-lock) | 0 |
| Cryptographic hardening (v2.7–v2.8) | F2 view reconciliation, Dilithium migration | 2-3 weeks | F2 spec'd in F2-SPEC.md, code not started; Dilithium not started | 2-3 weeks |
| Liveness (v2.10, v2.11) | Threshold randomness aggregation 🔥 active, beacon auto-detect | 1.5 weeks | 0 (v2.10 promoted to active A11) | 1.5 weeks |
| Composability (v2.12) | Cross-shard atomic primitives | 1 week | 0 (foundation: A9 Phase 2D atomic_scope shipped; cross-shard 2PC pending) | 1 week |
| Wallet/operator (v2.14–v2.17) | OPAQUE port, HD derivation, RPC auth, encrypted keyfiles | 2 weeks | ✅ v2.16 + v2.17 shipped; v2.14 + v2.15 not started | ~1 week |
| Application layer (v2.18–v2.20) | DApp substrate (registry + call + RPC + polling) | (was implicit, now itemized) ~1 week | ✅ v2.18 + v2.19 shipped, v2.20 polling shipped (streaming pending) | ~3 days for streaming |
| **Privacy & interop (v2.22–v2.24)** | **Confidential tx + cross-chain bridge + audit hooks** | **3-5 months** | 0 | 3-5 months |

**Themes 1-7 status:** ~6 weeks of work remaining (vs 12-16 weeks at start of session). Major absorbed: v2.1, v2.2 (foundation), v2.3, v2.4 (full A9), v2.5, v2.6, v2.16, v2.17, v2.18, v2.19, v2.20 polling.

**Total to complete v2 with Theme 8:** ~4-6 months from current state (down from 6-9 months estimate at the start of v2 work).
