# Determ v2 — Design space

This document scopes the v2 design changes that would make Determ a complete "every base-layer concern handled" protocol. v1.x is feature-complete on its narrow scope (fork-free L1 payment + identity with mutual-distrust safety). v2 closes the structural gaps that v1.x's design intent intentionally deferred.

The intent is not "Ethereum but better" — Determ stays in its lane: a payment + identity chain, no contract VM, no smart-contract execution layer. v2 makes that lane self-sufficient at any scale rather than expanding it.

**Status:** design + partial implementation. Document captures the design space; multiple themes have shipping code in tree. Each section names the change, its motivation, the implementation sketch, the cost estimate, and which existing v1.x open finding(s) it closes; design and code may have diverged for items currently shipping.

**Per-item status (audit against current `git log`):**

| Item | Status | Notes |
|---|---|---|
| v2.1 State Merkle root | ✅ shipped | `compute_state_root()` + Block.state_root + verification on apply/restore |
| v2.2 Light-client headers / state_proof RPC | ✅ shipped (complete) | Complete trustless-verification chain: `state_proof` RPC + `verify-state-proof` CLI with `--state-root` pin + `snapshot inspect --state-root` + `headers` RPC (Block JSON minus heavy collections, plus explicit per-header `block_hash`) + `determ headers` CLI (with both `--rpc-port` AND `--peer host:port` fetch paths) + **gossip-layer HEADERS_REQUEST / HEADERS_RESPONSE wire messages** (MsgType 17/18 — light clients peer directly with full nodes without RPC binding; envelope byte-identical to the RPC version) + `verify-headers` (chain integrity via prev_hash links) + `verify-block-sigs` (K-of-K committee Ed25519 verification against `compute_block_digest`). Sorted-leaves construction; SMT migration would be future for non-membership proofs. **v2.2 has no outstanding asks.** |
| v2.3 Trustless fast sync | ✅ shipped | state_root verified on snapshot restore |
| v2.4 Atomic block apply (A9) | ✅ shipped | A9 Phase 1-2D + COMPOSABLE_BATCH tx |
| v2.5 Registry cache (S-032) | ✅ shipped | Cached registry view; S-032 closed |
| v2.6 Gossip broadcast out of lock | ✅ shipped | All 5 broadcast sites release unique_lock before broadcast |
| v2.7 F2 view reconciliation | ⏳ spec resolved, implementation pending | S-030 D2 closure. F2-SPEC.md per-field rules formalized: union (+V11) for evidence, union (+V10) for aborts, intersection for inbound_receipts, deterministic for the rest. ~3-4d to ship from spec-review acceptance |
| v2.8 Post-quantum signature migration (Dilithium) | ⏳ not started | NH4 prerequisite |
| v2.9 Distributed VRF for committee selection | ⏳ not started | |
| v2.10 Threshold randomness aggregation | 🔥 **active** | Promoted to defeat residual selective-abort attack. DKG spec resolved per Option C (epoch-boundary trustless DKG + PSS refresh + FROST-Ed25519 on curve25519 family) in `docs/proofs/v2.10-DKG-SPEC.md`; cost revised to ~3 weeks. See plan.md A11 for active task brief |
| v2.11 Auto-detection beacon-side trigger (R4 v1.1) | ⏳ not started | |
| v2.12 Cross-shard atomic primitives | ⏳ not started | |
| v2.13 Fair-ordering primitive | 🔒 deferred (research) | Open research area; not on v2 critical path |
| v2.14 Real OPAQUE wallet recovery | ⏳ not started | |
| v2.15 Wallet HD derivation + multi-sig | ⏳ not started | |
| v2.16 Internal RPC authentication (S-001) | ✅ shipped | HMAC-SHA-256 + localhost-only default |
| v2.17 Passphrase-encrypted keyfiles (S-004) | ✅ shipped | AES-256-GCM envelope |
| v2.18 DAPP_REGISTER tx + on-chain DApp registry | ✅ shipped | Theme 7 substrate |
| v2.19 DAPP_CALL tx + payload routing | ✅ shipped | Theme 7 substrate |
| v2.20 Streaming subscription RPC | ⚠️ partial (spec resolved) | Polling shipped; full streaming pending. Spec resolved in §v2.20 below: `dapp_subscribe(domain, topic?, since?)` newline-JSON streaming with bounded per-subscriber queue, kill-on-backpressure semantics, catch-up replay window, heartbeat cadence, per-IP rate-limit via existing `net::RateLimiter` |
| v2.21+ DApp ecosystem items | 🔒 deferred | See V2-DAPP-DESIGN.md |
| v2.22 Confidential transactions (Bulletproofs) | ⏳ spec resolved, implementation pending | Theme 8. **MODERN crypto profile only** (unavailable in FIPS profiles: `tactical` + `cluster`). Option C resolved in `v2.22-PRIVACY-SPEC.md`: per-epoch HKDF view-key derivation, Bulletproofs over secp256k1 via libsecp256k1-zkp, ephemeral X25519 DH for amount handshake, dual-mode audit disclosure. ~2.5-3 months to ship from spec-review acceptance |
| v2.23 Cross-chain bridge (IBC-style) | ⏳ not started | Theme 8 |
| v2.24 Audit / compliance hooks | ⏳ not started | Theme 8. Simplified post-v2.22 spec — most infrastructure delivered by v2.22; v2.24 reduces to `audit_view_master_pk` field + `ROTATE_AUDIT_KEY` tx + reference tool. ~1-2 weeks |
| v2.25 Distributed identity provider (DSSO) | ⏳ not started | Theme 9. Mutual-distrust IdP framework with T-OPAQUE replacing the original SRP primitive; depends on v2.10 + v2.14 |
| v2.26 On-chain key rotation | ⏳ not started | Theme 9. ROTATE_KEY tx + rotation-aware sig verification; enables wallet-key churn without re-registration; precondition for v2.25 production |

**Shipped: 10. Active: 1 (v2.10). Partial: 1 (v2.20). Outstanding: 12. Deferred: 2 (v2.13, v2.21+).**

For the live shipped-items list, run `git log --oneline | grep -iE 'v2\\.'` — the table above is best-effort accurate as of this revision.

---

## Theme 1 — Trust minimization

### v2.1 — State Merkle root in every block

**Motivation.** Closes S-033 (no cryptographic state commitment) and S-012 (snapshot bootstrap trust). Today, a new node bootstrapping from a snapshot trusts the snapshot provider's word. There's no in-block commitment to state-after-apply, so any tampering with the snapshot is undetectable until the receiver applies a subsequent block and trips a derived-state mismatch.

Without state commitment, several capabilities are structurally impossible: light clients cannot verify account balances, cross-shard receipts cannot carry inclusion proofs against the destination's state, audit-grade compliance tools cannot independently verify any chain state without re-executing every block.

**Mechanism (shipped).** After every block applies, compute `state_root = MerkleRoot(canonical_state)` where `canonical_state` is the ten-namespace leaf set from `Chain::build_state_leaves` (a / s / r / d / i / b / m / p / k / c — see PROTOCOL.md §4.1.1 for the full namespace table including the d:-namespace v2.18 DApp registry). Include `state_root` in `Block.signing_bytes()` so it's bound by the K-of-K committee signatures.

Producer: `Node::try_finalize_round` populates `body.state_root` via a tentative-chain dry-run between `build_body` and `apply_block_locked + gossip.broadcast` (this wiring is the S-038 closure that activates the gate; pre-S-038 the producer never populated the field and the gate was dormant). Validator: re-derives `state_root` post-apply and rejects on mismatch with `block.state_root`. Snapshot: includes the head's `state_root`; receiver re-derives `MerkleRoot(snapshot.state)` and rejects on mismatch.

**Tree shape.** Sorted-leaves balanced binary Merkle tree (`src/crypto/merkle.cpp::merkle_root`), NOT a sparse Merkle tree. Leaves are SHA-256(0x00 ‖ key_len_BE ‖ key ‖ value_hash); inner nodes are SHA-256(0x01 ‖ left ‖ right). Leaves sorted lex by key; tree depth `O(log N)` where N is the number of populated state entries. Inclusion proofs: `O(log N)` sibling hashes (exposed via `state_proof` RPC, v2.2).

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

**Motivation.** Closed S-032. Already-recommended audit fix. Outlined in detail in `SECURITY.md` and the recent analysis. Shipped as part of the v2 foundation (no wire-format change required — pure runtime refactor).

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

**Mechanism.** Phase-1 view reconciliation with **per-field heterogeneous rules** (Option D). Each member's `ContribMsg` (Phase 1 commit) embeds both per-field Merkle-root hashes AND the actual lists for three pool-fed fields. The K signed Phase-1 commits canonicalize per-field via the rules below; Phase-2 signatures cover the reconciled canonical lists.

| Field | Reconciliation rule | Why this rule |
|---|---|---|
| `equivocation_events` | **Union** (with per-event V11 verifiability check) | Slashing-bearing; censorship-resistance principle ("one honest observer suffices") applies. Each event is cryptographically self-verifiable via V11 (two conflicting sigs over different digests), so union doesn't expand attack surface. |
| `abort_events` | **Union** (with per-event V10 verifiability check) | Same as equivocation. Aborts are individually verifiable; any single observer suffices. V10 bounds over-inclusion. |
| `inbound_receipts` | **Intersection** | Credit-bearing; conservative posture. Only credit when ALL K members independently observed the receipt — reduces double-credit risk if a cross-shard relay is partially corrupted. |
| `cross_shard_receipts` | Deterministic from accepted txs | No reconciliation needed; pure function of in-block TRANSFERs. Validator re-derives and checks. |
| `partner_subset_hash` | Deterministic from merge state | Computed identically on every honest node from `merge_state` at this height. No view divergence possible. |
| `timestamp` | Assembler-proposes, members-bound-check ±30s | Assembler proposes a value at Phase 1→2 boundary; members verify against their local `±30s` window before signing Phase-2. Out-of-window → round aborts and re-runs. |

**Status: spec resolved, awaiting review and implementation.** `docs/proofs/F2-SPEC.md` contains the formal resolutions for all 9 historical open design questions (per-field rules, pool snapshot timing, wire format, Phase-1 binding scope, Phase-2 signature semantics under union, timestamp inclusion, validator-side caching, monitoring metrics, FA1 proof update). The prior in-tree attempt at a naive extension broke equivocation-slashing under gossip-async (`docs/proofs/S030-D2-Analysis.md` §2); F2-SPEC's per-field rules + per-event V11 re-verifiability constraint address the failure mode directly.

**Resolved sub-questions, summary:**
1. Per-field rule: per-field heterogeneous (table above). ✅
2. Pool snapshot timing: each member snapshots at their own Phase-1 commit instant; no coordinated snapshot. ✅
3. Wire format: per-field Merkle root (32B) + full list per member in `ContribMsg`; suggested cap 64 events per type per member. ✅
4. Phase-1 commit binding: `make_contrib_commitment` extended with three new view roots; single Ed25519 sig binds all three. ✅
5. Phase-2 sig semantics: Phase-2 signs over the reconciled canonical lists, not any member's individual view. Members may sign over evidence they didn't personally observe, but each event must individually pass V10/V11 verification. ✅
6. Timestamp inclusion: in v2.7 scope (assembler-proposes-members-bound-check). ✅
7. Validator-side caching: none in initial ship (K × pool-size work is bounded constant). ✅
8. Monitoring metrics: 4 counters/gauges (`f2_view_divergence_count`, `f2_round_aborts_attributed_to_view_drift`, `f2_canonical_list_size_per_field`, `f2_evidence_inclusion_latency_blocks`). ✅
9. FA1 proof update: textual only (no structural proof change); D2 footnote removed from `Safety.md` §5.3; "≤ 1 block instance per height" replaces "≤ 1 digest per height + footnote." ✅

See `docs/proofs/F2-SPEC.md` for the full per-question rationale, wire-format details, implementation work units, regression-test plan, and rollback plan.

**Cost (revised, spec already in tree).**
- Specification: **shipped** (F2-SPEC.md exists; review pending).
- Implementation: 1-2 days focused work given the spec.
- Testing: 0.5-1 day for the 5 regression test cases.
- Migration tooling + genesis update: 0.5 day.
- Documentation refresh (Safety.md §5.3 D2 footnote removal, S030-D2-Analysis.md status update): 0.5 day.
- **Total to ship: ~3-4 days from spec-review acceptance.**

Wire-format change to `ContribMsg` (3 new hashes + 3 new lists). Validator re-derivation logic. Reconciliation rule(s) formalized in F2-SPEC.md.

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

**Current (active) mechanism: t-of-K threshold signatures.** Each committee member generates a `partial_sig_i = sign(secret_share_i, beacon_seed ‖ height)` using a t-of-K threshold-signature scheme (FROST-Ed25519 on curve25519 family, or equivalent). Any `t = ceil(2K/3)` partial signatures combine into the SAME canonical `R = combine(partial_sig_{i1}, …, partial_sig_{it})`. The combined signature `R` replaces today's `delay_output`.

**Critical property.** Any `t` partial signatures produce the SAME `R`. A withholding adversary doesn't change `R` — the other `K-t` members' partials are sufficient. Selective abort becomes ineffective for biasing randomness.

| Today (commit-reveal) | After v2.10 (threshold) |
|---|---|
| Adversary withholding their secret aborts the round | Adversary withholding their partial sig does nothing — other t members suffice |
| Adversary chooses to reveal/abort based on whether R favors them | Adversary cannot prevent R; their choice is irrelevant |
| Bias possible by paying SUSPENSION_SLASH per abort | Bias requires controlling ≥ K-t+1 members — standard Byzantine bound |

**DKG design: Option C — epoch-boundary trustless DKG with proactive refresh.** v2.10's threshold signatures require each committee member to hold a share of a threshold private key. The shares are generated and refreshed via per-epoch FROST-Ed25519 DKG (on the curve25519 family via libsodium); no trusted dealer; new validators acquire shares natively via the next epoch's DKG round; share refreshes preserve forward secrecy.

| DKG sub-decision | Resolved choice | Why |
|---|---|---|
| Ceremony placement | **Epoch-boundary runtime DKG** | Supports permissionless validator rotation natively; reuses existing epoch-boundary sync point |
| Trust model | **Trustless (no dealer)** | Matches K-of-K mutual-distrust posture; trusted dealer reintroduces operator privilege |
| Rotation support | **Native via per-epoch DKG** | New validators acquire shares in next epoch's ceremony; departing validators simply don't participate |
| Share refresh | **Proactive secret sharing (PSS)** in membership-unchanged case; fresh DKG on committee change | Forward secrecy at zero cost when membership stable; clean transition when committee changes |
| Threshold scheme | **Ed25519 / ristretto255 (curve25519 family)** | Already vendored via libsodium; preserves "two primitives" design value (SHA-256 + curve25519 family); no new pairing-friendly curve added to audit surface; shared with v2.22 (Bulletproofs/curve25519) and v2.25 (T-OPRF/ristretto255) |
| DKG protocol | **FROST-Ed25519 (RFC 9591, May 2024)** | IETF-standardized; tolerates ⌊(K-1)/3⌋ malicious participants during ceremony; production reference impl in zcash/frost-ed25519 |
| Per-profile timing | **R=5 blocks at tactical/cluster, R=3 at web/regional/global** | Sized to absorb network jitter while staying ≤5% of epoch duration |

See `docs/proofs/v2.10-DKG-SPEC.md` for the full design specification, protocol description, wire-format details, implementation work units, failure-mode handling, regression-test plan, and rollback plan.

**Cost (revised after DKG spec).** ~3-4 weeks focused work. The prior "~1 week" estimate implicitly assumed Option B (genesis-time static DKG), which would compromise the mutual-distrust property v2.10 is meant to deliver. Option C breakdown:

| Sub-component | Effort |
|---|---|
| FROST-Ed25519 primitives on libsodium | 2-3 days |
| FROST-Ed25519 DKG protocol | 1-1.5 weeks |
| Epoch-boundary orchestration | 3-5 days |
| Threshold-signature integration | 3-5 days |
| Failure-mode handling | 3-5 days |
| Regression tests | 3-5 days |
| Migration tooling | 2-3 days |
| Documentation refresh | 2-3 days |

The 3-4x expansion vs. the prior estimate is the cost of delivering v2.10's threat-model property under genuine mutual distrust. Alternatives (genesis-time static, or trusted-dealer) ship faster but compromise the property.

**Wire-format implications.** `creator_dh_secrets` becomes `creator_partial_sigs` (per the v2.10 design). Three new gossip-layer message types for the DKG ceremony (`DKGCommitMsg`, `DKGShareMsg`, `DKGComplaintMsg`). Three new on-chain block fields (`epoch_public_key`, `dkg_status`, `dkg_excluded`). Not backward-compatible with v1 chains — flag-day upgrade required.

**Composes with v2.9** (distributed VRF): VRF unbiasability + threshold randomness aggregation together close the entire randomness attack surface. Either alone is good; both together is best. v2.9 itself would build on the same Ed25519 + DKG infrastructure shipped here.

**Cascades to downstream items.** The curve25519-family DKG infrastructure shipped for v2.10 is a **shared foundation** for the threshold-cryptography layer of v2 + Theme 9, all on the unified curve family (no new pairing-friendly curve added):
- **v2.25 T-OPAQUE OPRF** (Theme 9 DSSO) uses ristretto255 — same curve family as v2.10's FROST-Ed25519 (Ed25519 signatures + ristretto255 generic ECC are presentations of the same curve). Reuses the per-epoch share-distribution infrastructure. Without v2.10's DKG, T-OPAQUE has no trust-minimized share-distribution path.
- **v2.22 confidential transactions** (Theme 8) uses Bulletproofs on curve25519 (dalek-cryptography reference impl, the original Bulletproofs target). Same curve family; shared libsodium primitives.
- **v2.9 distributed VRF** (deferred) is natural follow-on once DKG infrastructure exists.

**Closes:** residual selective-abort bias in randomness (the only remaining randomness-bias vector after commit-reveal closed the broader class). Strengthens FA3 information-theoretic argument from "K-of-K commit-reveal" to "t-of-K threshold aggregation," which is the strongest possible bound (matches Byzantine takeover threshold).

Full task brief: `plan.md` §A11. Full DKG specification: `docs/proofs/v2.10-DKG-SPEC.md`.

### v2.11 — Auto-detection beacon-side trigger (R4 v1.1)

**Problem statement.** R4 v1.0 ships the under-quorum-merge mechanism (`MergeEvent`, `Chain::merge_state_`, `refugee_region` cascade) but leaves the *triggering decision* to a human operator. Today an operator who notices that shard `s`'s eligible-region pool has dropped below `2K` runs `determ submit-merge-event --begin --shard s --partner p --region R --effective-height H --evidence-window-start W`, the beacon's K-committee co-signs the resulting `MERGE_EVENT` tx, and the merge cascade applies. This is fine for testbeds and supervised deployments but unworkable in production for three reasons:

1. **Reaction latency.** A shard with `eligible_in_region(s) = 1.6K` and a missed `SHARD_TIP_s` lives in degraded-quorum state continuously. The longer the operator takes to notice (minutes at best for a paged-in human, hours for an unmanned regional deployment), the longer that shard runs with a quorum gap. Under FA1 the shard still satisfies its safety conditions (committee selection just picks from the smaller pool); under FA5 the liveness slack thins until a single additional drop tips into `< K` and the shard stalls until merge.
2. **Operator-trust singleton.** Whoever runs `submit-merge-event` becomes the de-facto authority for "is this shard merged or not?" The committee co-signs the resulting block, but the *origination* of the decision is a human acting outside the chain's mutual-distrust posture. A misconfigured wallet, a stale dashboard, or a compromised operator key (subject to S-001 / S-004 mitigations) can issue merges that aren't substantively justified.
3. **No witness-window provenance.** The `evidence_window_start` field on the `MergeEvent` is a hint about which historical blocks justify the merge — but in v1.0 there's no chain-side check that `evidence_window_start` is consistent with the historical record. An operator who submits `evidence_window_start = H - merge_threshold_blocks` for an actually-healthy shard merges that shard anyway because the committee signs the block, not the historical claim. S-036 (partial Low/Op) captures this gap.

v2.11 replaces the human-as-trigger with a deterministic beacon-side state machine that observes the chain's already-public state (`registrants_`, `SHARD_TIP_*` arrivals, per-shard tx-flow) and emits `MERGE_BEGIN` autonomously when its derivable triggering predicate fires.

**Mechanism — beacon-side observation FSM.** Each shard `s` tracked by the beacon has a `MergeMonitor[s]` per-shard observation block:

```cpp
struct MergeMonitor {
    enum class State : uint8_t {
        NORMAL,
        STRESS_CANDIDATE,
        STRESS_CONFIRMED,
        MERGE_PENDING,
        MERGED,
        RECOVERY_CANDIDATE,
        RECOVERY_CONFIRMED,
    };
    State        state{State::NORMAL};
    uint64_t     state_entered_height{0};   // beacon block index of last state change
    uint64_t     observation_window_start{0}; // running count anchor
    uint32_t     consecutive_stress_blocks{0};
    uint32_t     consecutive_recovery_blocks{0};
    uint32_t     last_eligible_count{0};
    uint64_t     last_shard_tip_height{0};
    PartnerHint  pending_partner{};         // resolved at MERGE_PENDING entry
};
```

State machine, evaluated once per beacon block as part of the beacon-side tick (between `BlockValidator::validate_block` and `Chain::apply_block_locked`):

| From | To | Trigger | Action |
|---|---|---|---|
| `NORMAL` | `STRESS_CANDIDATE` | First block with `eligible_in_region(s) < 2K` OR `head_height - last_shard_tip_height > shard_tip_grace_blocks` | Record `observation_window_start = head_height`; `consecutive_stress_blocks = 1` |
| `STRESS_CANDIDATE` | `STRESS_CONFIRMED` | `consecutive_stress_blocks >= stress_confirm_blocks` (default 25) | Lock the candidate; begin partner resolution |
| `STRESS_CONFIRMED` | `MERGE_PENDING` | `consecutive_stress_blocks >= merge_threshold_blocks` (default 100; genesis-pinned) AND partner-resolution returned a valid `(partner_id, region)` pair | Emit `MERGE_BEGIN` candidate; queue `MERGE_EVENT` tx for next beacon block |
| `MERGE_PENDING` | `MERGED` | The beacon's next block applies and contains the `MERGE_EVENT` tx (validator path runs S-036 historical check + K-committee co-signs) | `state_entered_height = H_merge` |
| `STRESS_CANDIDATE`, `STRESS_CONFIRMED` | `NORMAL` | `eligible_in_region(s) >= 2K` for `stress_reset_blocks` (default 10) consecutive blocks | Clear monitor; reset counts |
| `MERGED` | `RECOVERY_CANDIDATE` | First block with `eligible_in_region(s) >= 2K + recovery_hysteresis` (default `2K + K/2`) | `consecutive_recovery_blocks = 1` |
| `RECOVERY_CANDIDATE` | `RECOVERY_CONFIRMED` | `consecutive_recovery_blocks >= recovery_confirm_blocks` (default 200; deliberately longer than `merge_threshold_blocks`) | Emit `MERGE_END` candidate |
| `RECOVERY_CANDIDATE` | `MERGED` | `eligible_in_region(s) < 2K + recovery_hysteresis` at any block | Reset; stay merged |
| `RECOVERY_CONFIRMED` | `NORMAL` | The beacon's next block applies and contains the matching `MERGE_END` tx | Clear monitor |

The `stress_confirm_blocks` intermediate state acts as cheap noise rejection (block-rate fluctuation, transient peer churn, a single dropped `SHARD_TIP_s`) before committing to the heavier full-threshold count. Hysteresis on the recovery side (`recovery_hysteresis = K/2` extra eligible nodes; `recovery_confirm_blocks > merge_threshold_blocks` so revert requires more confidence than merge) is asymmetric on purpose: under-quorum merges should be cheap to enter (closing a real liveness gap) but harder to leave (avoid flapping back into the same trouble that triggered the original merge).

**Partner-resolution algorithm.** When `STRESS_CONFIRMED` enters with a verified count gap, the beacon resolves `partner_id` deterministically from the chain's public state:

1. **Candidate pool.** All currently-NORMAL shards with `eligible_in_region(p) >= 3K` (≥1K headroom over the bare-minimum committee size).
2. **Region affinity.** Prefer a partner sharing the refugee's region if any candidate qualifies. Falls back to a different region as the merge cascade is region-agnostic at apply time (`refugee_region` carries the original region forward through `merge_state_`).
3. **Tie-breaker.** Among qualifying candidates, pick the partner with smallest `(headroom_to_cap, partner_id)` lex tuple where `headroom_to_cap = max_eligible_per_shard - eligible_in_region(p)`. This load-balances merges across the partner pool over time.
4. **No-candidate fallback.** If no shard meets the headroom requirement, the monitor stays in `STRESS_CONFIRMED` and the beacon emits an operational alert (`MergeMonitor::no_partner_available` counter). Operator falls back to manual `submit-merge-event` with policy override. This is the only path that retains the operator-as-trigger gate, and only for the worst-case "everyone's stressed" scenario.

The candidate evaluation runs entirely against `Chain::registrants_` + `Chain::merge_state_` + the beacon's local `MergeMonitor[*]` table — all deterministic from already-public chain state. Any honest node re-deriving the partner pick from the chain's history at the merge height arrives at the same `(partner_id, region)` pair; this is what makes the historical-witness check (below) cryptographically meaningful instead of just informational.

**S-036 historical-witness check.** The validator gate currently inferred by `BlockValidator::validate_block` checks that the `MergeEvent` payload is internally well-formed (region length cap, event_type discriminant, partner != shard, etc.). v2.11 extends this with a *historical* check: given the `evidence_window_start` field on the event, the validator re-derives the beacon's monitor state from blocks in `[evidence_window_start, effective_height)` and confirms the trigger predicate would have fired. Specifically:

```cpp
bool BlockValidator::validate_merge_event_historical(
    const MergeEvent& ev,
    const ChainHistoryReadHandle& hist) const
{
    if (ev.event_type == MergeEvent::BEGIN) {
        // Replay the monitor FSM over [evidence_window_start, effective_height).
        // For each beacon block H in the window:
        //   - reconstruct eligible_in_region(ev.shard_id) at H from chain state at H
        //   - reconstruct last SHARD_TIP_{ev.shard_id} height observed at H
        //   - step the MergeMonitor FSM
        // Accept iff the FSM reaches STRESS_CONFIRMED at or before effective_height
        // AND consecutive_stress_blocks >= merge_threshold_blocks at effective_height.
        // The partner-resolution algorithm is re-run; ev.partner_id must match.
        return replay_monitor_reaches_pending(ev, hist);
    } else {
        // Symmetric replay for MERGE_END: monitor must be RECOVERY_CONFIRMED
        // at or before effective_height.
        return replay_monitor_reaches_recovery(ev, hist);
    }
}
```

This closes S-036 *fully* for `MERGE_EVENT` issuance (the original S-036 partial was about the witness window for evidence inclusion; here the witness window is what the FSM observed, and the chain re-derives the FSM transitions from finalized chain state alone). A captured-beacon adversary that submits a `MERGE_BEGIN` against an actually-healthy shard fails this check at validator time on every honest node; the K-committee will not co-sign a block whose `MERGE_EVENT` tx fails validate. The historical replay is `O(merge_threshold_blocks)` per `MERGE_EVENT` — at default 100 blocks this is negligible compared to per-block apply cost.

**Wire-format additions.** None to existing structs. `MergeEvent` keeps its current shape (`event_type`, `shard_id`, `partner_id`, `effective_height`, `evidence_window_start`, `merging_shard_region` — already includes the field S-036 historical replay reads). v2.11 adds:

| New surface | Location | Purpose |
|---|---|---|
| `MergeMonitorState` (per-shard runtime struct) | `include/determ/node/beacon.hpp` (new file, ~200 LOC) | Beacon-side FSM state; NOT chain state; not serialized into snapshot |
| `mergemonitor_status` RPC | `src/node/node.cpp` | Operator visibility: returns current state, consecutive counts, observation window |
| Config knobs: `stress_confirm_blocks`, `recovery_hysteresis`, `recovery_confirm_blocks`, `stress_reset_blocks`, `shard_tip_grace_blocks` | `include/determ/chain/genesis.hpp::GenesisConfig` + `Chain` mirrors | Genesis-pinned; reuse pattern from `merge_threshold_blocks` (already shipped) |
| `BlockValidator::validate_merge_event_historical` | `include/determ/chain/validator.hpp` + impl | The S-036 replay check |
| `ChainHistoryReadHandle` | `include/determ/chain/chain.hpp` | Read-only handle exposing block-N state-snapshot reconstruction for the historical replay; reuses existing block index + accounts_at_height accessors |

The new config knobs default to the values listed in the FSM table above. Genesis-pinned so all nodes agree on triggering thresholds — required for the historical replay to be deterministic across observers.

**Apply-path integration.** Functions extended (no rewrites):

- `Node::on_beacon_tick` — new hook fired once per beacon block, before `enqueue_save`. Iterates all tracked shards, calls `MergeMonitor::step()`, queues `MERGE_EVENT` txs for next block on `MERGE_PENDING` / `RECOVERY_CONFIRMED` transitions.
- `MergeMonitor::step` — pure function over (current state, per-block chain observation, FSM constants). Deterministic; reproducible by replay tooling.
- `BlockValidator::validate_block` — extended with a single new call into `validate_merge_event_historical` for every `MERGE_EVENT` tx in the block.
- `Chain::apply_transactions` — unchanged. The `MergeEvent` apply path was already shipped in R4 v1.0; v2.11 changes only the *origination* path and the *validation* gate, not the *application* path. The merge cascade itself (refugee assignment, partner committee expansion via `partner_subset_hash`) is unchanged.
- `Chain::serialize_state` / `restore_from_snapshot` — unchanged. `MergeMonitor` is per-node runtime state (like the mempool, like subscriber lists from v2.20). Nodes restarting reconstruct their monitor state by replaying the last `2 × merge_threshold_blocks` of chain history; an interim short window in `NORMAL` is harmless because the merge state itself lives in `merge_state_` (already in snapshot).

**Threat model.** What the primitive defeats and what it introduces:

| Attack | v2.11 defense | New surface introduced |
|---|---|---|
| **Slow human-operator reaction** (degraded-quorum shard runs for minutes/hours while operator notices) | Deterministic FSM fires at exactly `merge_threshold_blocks` after stress entry; no human in the loop | None |
| **Operator-as-trigger compromise** (a misconfigured wallet or captured operator key issues a merge against a healthy shard) | Validator-side historical replay rejects any `MERGE_EVENT` whose FSM trajectory doesn't reach `MERGE_PENDING` over `[evidence_window_start, effective_height)`. Committee cannot co-sign an invalid `MERGE_EVENT` because validate fails. | None — strictly removes the operator from the originating path |
| **False-positive merge** (transient peer churn / network partition triggers stress; merge fires; merge survives the recovery delay; system suffers a non-justified consolidation) | `stress_confirm_blocks` noise-rejection layer + `merge_threshold_blocks` confirmation requirement + `recovery_hysteresis` asymmetric revert (easier to enter, harder to leave); FSM is conservative on entry, conservative on exit. Operator monitoring via `mergemonitor_status` RPC sees the candidate state and can intervene with manual override (a `MergeEvent` with an `operator_override` flag bypasses the historical replay — gated behind explicit config + per-event audit log). | Operator-override path is a controlled escape valve; documented as a break-glass; logs every override into a chain-event journal |
| **False-negative miss** (real liveness failure goes undetected because the beacon's own observation history was corrupted by a captured-beacon attack) | The FSM observes already-public chain state (`registrants_`, last-applied-block tx-flow). A captured beacon that lies about its observation history will produce a `MergeEvent` whose historical replay fails on every honest node — the captured beacon cannot single-handedly issue merges. For an UNDETECTED-and-real failure (the beacon is captured AND the captured beacon refuses to issue merge), the K-committee can still issue `MERGE_EVENT` collectively via the existing operator path; v2.11 is additive, not replacing | The captured-beacon "refuse to act" path is fundamentally a liveness concern; mitigated by the operator-override path remaining available |
| **Captured-beacon issues bogus partner pick** (beacon issues `MERGE_BEGIN` with a `partner_id` that doesn't match the deterministic resolution algorithm; perhaps to load a specific partner with extra refugee traffic) | Validator-side historical replay re-runs the partner-resolution algorithm and confirms the emitted `partner_id` matches the deterministic pick. Any partner-pick deviation fails validate | None |
| **Flapping attack** (adversary creates oscillating eligible-count just above/below `2K` boundary to force repeated merge / revert cascades) | Asymmetric hysteresis (`recovery_confirm_blocks = 200` vs `merge_threshold_blocks = 100`; `recovery_hysteresis = K/2` extra eligible required for revert); any flap completes at most one cycle per `~300 blocks` even in worst case. Per-shard merge cap (proposed `MAX_MERGE_EVENTS_PER_SHARD_PER_EPOCH = 4`) caps total flap rate per epoch | One new config knob (the per-epoch cap); easy operator tuning |
| **Cross-shard cascading merge** (one stress event creates a real refugee load on partner, partner becomes stressed, beacon merges partner too, cascade propagates) | The partner-resolution algorithm filters candidates to `eligible_in_region(p) >= 3K` (1K headroom). A partner whose own eligible count is borderline is never selected. If the eligible pool is so thin that no candidate qualifies, monitor stalls in `STRESS_CONFIRMED` and operator alert fires — better to surface the systemic failure than to propagate the cascade | The "no partner available" stall is a deliberate fail-safe; operator escalation path preserved |
| **MERGE_EVENT timing manipulation** (adversary aligns `effective_height` with a block whose evidence window happens to cover a misleading slice of history) | `evidence_window_start` is constrained to `effective_height - merge_threshold_blocks - stress_confirm_blocks` (i.e., the actual window required to reach `MERGE_PENDING` from `NORMAL`); any narrower window fails replay, any wider window is rejected as out-of-spec. Validator-side gate enforced via `validate_merge_event_historical`. | None |

**Effort estimate.** ~5-7 engineering days (revised from the prior ~2-3 day estimate after spelling out the historical-replay check):

| Sub-component | Effort |
|---|---|
| `MergeMonitor` struct + FSM transitions (pure function) | 1 day |
| `Node::on_beacon_tick` hook + per-block step integration | 0.5 day |
| Partner-resolution algorithm | 0.5 day |
| `BlockValidator::validate_merge_event_historical` (the S-036 closure) | 1 day |
| `ChainHistoryReadHandle` for read-only historical state reconstruction | 1 day |
| `mergemonitor_status` RPC + CLI verb (`determ mergemonitor`) | 0.5 day |
| Genesis config knobs (5 new fields) + propagation through `GenesisConfig`/`Chain` | 0.5 day |
| Regression tests: stress-fires, hysteresis revert, partner resolution, historical-replay rejection of bogus event, flap suppression, no-partner stall, operator-override audit | 1-1.5 days |
| Documentation refresh (PROTOCOL.md §6.4 R4 substrate, SECURITY.md §S-036 closure, README.md §10.8) | 0.5-1 day |

The expansion vs. the prior ~2-3 day estimate is the cost of doing the S-036 closure properly (deterministic historical replay rather than informational-only `evidence_window_start`). The cheaper version that ships only the FSM without the validator-side replay closes the latency problem but leaves the operator-trust-singleton problem open — not a v2.11-complete posture.

**Dependencies.**

- **R4 v1.0 substrate** — ✅ shipped. `MergeEvent` struct, `Chain::merge_state_`, `refugee_region` cascade, `partner_subset_hash` committee expansion all in tree.
- **v2.1 state Merkle root** — ✅ shipped. `merge_state_` already contributes to state_root via the `m:` namespace. v2.11 reads `merge_state_` but doesn't extend its serialization.
- **v2.4 A9 atomic_scope** — ✅ shipped. `MERGE_EVENT` apply already runs inside `atomic_scope`; v2.11 doesn't change this.
- **No dependency on v2.7 F2 (view reconciliation).** `MERGE_EVENT` originates from the beacon, not from cross-shard receipts; the F2 per-field rules don't apply to MERGE_EVENT-bearing blocks.
- **No dependency on v2.10 (threshold randomness).** The FSM is deterministic from public chain state; no randomness consumed.
- **No dependency on Phase D Beaconless v2.** v2.11 is explicitly a *beacon-side* auto-detect; under Beaconless v2 (Phase D) the equivalent function is the per-shard SHARD_TIP observation + Merritt-witness affidavits design (`docs/proofs/Beaconless-v2-SPEC.md` D.5). v2.11 ships first because it lands within Phase A and gives the beacon-mediated topology a complete merge-detection story years before Phase D ships.

**Cross-references.**

- R4 v1.0 substrate: `include/determ/chain/block.hpp::MergeEvent` (line 321); `Chain::merge_state_` (`include/determ/chain/chain.hpp::merge_state_`, line 598); `Chain::merge_threshold_blocks_` (line 592, default 100, genesis-pinned).
- S-036 (witness-window partial): `SECURITY.md` §S-036. v2.11 promotes this from Low/Op-partial to Low/Op-closed for the EXTENDED-mode merge path. The original S-036 broad scope (evidence inclusion windows for evidence/abort txs) is closed separately via the `evidence_window_start <= b.index` past-bound shipped in-session.
- FA8 regional sharding proof: `docs/proofs/RegionalSharding.md`. v2.11's deterministic-FSM trigger preserves all FA8 invariants — the merge cascade itself is unchanged; only the *trigger* is rewired.
- FA9 under-quorum-merge proof: `docs/proofs/UnderQuorumMerge.md`. v2.11 extends FA9's coverage from "operator-issued merges" to "beacon-FSM-issued merges with operator-override fallback"; the safety argument is unchanged.
- `MergeEvent` apply path (R4 v1.0): `src/chain/chain.cpp::apply_merge_event` (via `apply_transactions` dispatch). v2.11 does not modify this function.
- `tools/test_under_quorum_merge.sh` (R4 v1.0 regression): v2.11 adds a sibling `tools/test_merge_autodetect.sh` covering the FSM scenarios.
- Phase D Beaconless v2 spec: `docs/proofs/Beaconless-v2-SPEC.md` §D.5 — the post-beacon equivalent of v2.11; same FSM shape, different witness distribution (per-shard SHARD_TIP observation instead of beacon-side observation).
- `CLI-REFERENCE.md` `determ submit-merge-event`: the operator-override CLI verb remains shipped as the break-glass path.

**Open design questions.**

1. **Operator-override audit channel.** The break-glass `submit-merge-event --operator-override` path bypasses `validate_merge_event_historical`. Should it require a separate `OperatorOverride` event tx (with its own audit semantics) instead of riding on the existing `MergeEvent` envelope with a flag? Default position: in-band flag for v2.11.0 (simpler validator code path); separate tx for v2.11.1 if real deployments demand explicit audit-trail separation.
2. **FSM constants: per-shard or chain-wide?** Today `merge_threshold_blocks` is chain-wide (single `GenesisConfig` field). Some deployments may want different thresholds per shard (e.g., a tactical-profile regional shard tolerates shorter windows than a global-profile shard). Default position: chain-wide in v2.11.0; per-shard override in v2.11.1 if deployment feedback demands it. Adding per-shard config later is backward-compatible (default to chain-wide value).
3. **Should the FSM observe across `MERGE_EVENT` boundaries?** When shard `s` was previously merged into `p` and recovered via `MERGE_END`, the next stress event starts from `NORMAL` with no memory of the prior cycle. An attacker who knows this could trigger an artificial revert (e.g., a brief eligible-count bump past `2K + recovery_hysteresis`) just to reset the counter. Default position: yes, the per-shard FSM is memoryless across cycles by design; the per-shard merge-event cap (`MAX_MERGE_EVENTS_PER_SHARD_PER_EPOCH = 4`) bounds the worst case. Revisit if real deployments exhibit the pattern.
4. **Cross-region partner preference: hard rule or soft preference?** The partner-resolution algorithm currently *prefers* a same-region partner but *falls back* to a different region if none qualifies. A stricter alternative would refuse merges that cross region boundaries — operationally cleaner but creates more "no partner available" stalls. Default position: soft preference; document the cross-region merge as a known operational signal that the region's deployment is under-provisioned and should be expanded.
5. **Should `MergeMonitor` state surface via state_root?** Today the proposal is "no" — `MergeMonitor` is per-node runtime state, like the mempool. An adversary node could lie about its own monitor state without consequence because what counts at validate time is the historical replay against finalized chain blocks, not the live monitor. If a future requirement (e.g., interactive light-client merge-monitoring) needs cryptographic commitment to the monitor state, a v2.11.1 extension can lift it into the `m:` namespace alongside `merge_state_`. Defer until needed.
6. **Composition with v2.7 F2.** F2 ships reconciled lists for `evidence_window_start` and friends, but the `MergeEvent`'s `evidence_window_start` is producer-set (whoever assembled the block emitted the field), not member-set. F2 doesn't touch the path. Confirmed via the field's lifecycle: producer queries `MergeMonitor[s].observation_window_start` at block-assembly time; this value rides in the block; validators re-derive against the historical record. No F2 reconciliation needed.

**Cost.** ~5-7 days. See effort table above. Net new RPC surface is one verb; net new node state is one per-shard FSM map; net new validator gate is one historical-replay function; net new threat surface is the operator-override break-glass which carries its own audit constraints.

**Closes:** R4 v1.1 follow-on (auto-detect was R4's deferred half); S-036 fully for the `MERGE_EVENT` issuance path (deterministic-replay validation closes the original "informational `evidence_window_start`" gap). Removes the operator-as-trigger trust singleton from the under-quorum-merge mechanism. Composes with the existing K-committee co-sign requirement: the FSM proposes, the committee ratifies, no single party originates.

---

## Theme 5 — Composability

### v2.12 — Cross-shard atomic primitives

**Problem statement.** Today's cross-shard transfer is fire-and-forget: source-shard apply debits the sender, beacon relays the receipt to the destination, destination-shard apply credits the recipient. Apply at source and apply at destination are independent atomic operations separated by the `CROSS_SHARD_RECEIPT_LATENCY = 3` block latency window. FA7 covers safety (no double-spend, no lost credit) and the temporal decoupling is benign for one-shot transfers: at worst the sender debits and the recipient credits some blocks later — both legs eventually land.

The decoupling breaks down for use cases that need **conditional, joint settlement** of two paired actions:

- **Cross-shard atomic swaps.** Alice on shard 0 owes Bob 100 DCH; Bob on shard 1 owes Alice an off-chain asset. Either both settle or neither — a half-settled swap leaves one party out-of-pocket.
- **Cross-shard DEX matching.** Order book on shard 0 matches a sell against a buy on shard 1. The match is only legitimate if both legs apply; one leg landing alone leaves the order book inconsistent.
- **Cross-shard escrow with deadline.** Funds locked on shard 0 should release to shard 1 iff the destination accepts within a deadline, else refund to source.

v1.x has no primitive for these patterns. Users would have to build them as a two-step protocol (debit at source → if-credit-lands-then-do-X) with off-chain compensating-action logic for the failure modes — fragile, and incompatible with the chain's mutual-distrust posture (the off-chain compensator becomes a trust singleton).

**Mechanism (sketch).** Layer a two-phase commit (2PC) on top of the existing receipt machinery. The primitive is a new `TxType::CROSS_SHARD_SWAP` carrying `(src_action, dst_action, timeout_height, swap_id)` where:

- `src_action` describes the source-shard leg: subject account, debit amount, optional payload.
- `dst_action` describes the destination-shard leg: subject account, credit amount, optional payload.
- `timeout_height` is the destination-shard height by which the swap must commit; after this, the source-side lock unwinds.
- `swap_id = SHA-256(src_action ‖ dst_action ‖ timeout_height ‖ submitter_nonce)` — collision-resistant unique identifier, used by both sides to correlate the two halves.

The flow:

1. **PREPARE at source.** Submitter posts the `CROSS_SHARD_SWAP` to the source shard. Source-shard apply moves `src_action.amount` from the submitter's account into a per-swap `locked_pool_` entry keyed by `swap_id`. The submitter's nonce advances. The fee is charged now. Source-shard apply emits a `SwapPrepareReceipt` to the destination (analogous to today's `CrossShardReceipt` but carrying the swap_id + dst_action + timeout instead of a plain credit instruction).
2. **PREPARE relay.** Beacon (in v1.x sharding topology) or destination's light-client mesh (post-Phase-D Beaconless v2) relays the receipt to the destination shard. Receipt admission rules are identical to today's `inbound_receipts_eligible_for_inclusion` — 3-block latency + intersection-of-K-views in F2 mode.
3. **COMMIT at destination.** When the destination shard's apply path sees the `SwapPrepareReceipt`, it admits it into a per-destination `pending_swaps_` table keyed by `swap_id`. The destination's recipient (named in `dst_action.subject`) can then submit a follow-up `CROSS_SHARD_SWAP_COMMIT` tx referencing `swap_id` within `[receipt_admit_height, timeout_height]`. Destination-shard apply emits the credit and a `SwapCommitReceipt` back to source.
4. **FINALIZE at source.** Source-shard apply consumes the `SwapCommitReceipt`, removes the `locked_pool_[swap_id]` entry, marks the swap finalized.
5. **TIMEOUT path.** If destination-shard height passes `timeout_height` with no `CROSS_SHARD_SWAP_COMMIT` against the swap, destination apply emits a `SwapTimeoutReceipt`. Source apply, on receiving it, refunds the locked amount back to the submitter's account and removes `locked_pool_[swap_id]`. The fee already paid is not refunded — same model as a failed `COMPOSABLE_BATCH` inner tx (submitter paid for block space).

The destination-side recipient can also actively decline via `CROSS_SHARD_SWAP_ABORT` (carries swap_id + the recipient's signature over an abort intent). Destination apply emits an immediate `SwapTimeoutReceipt` without waiting for the block-height deadline — same source-side handling.

**Wire-format changes.**

| Slot | Use | Notes |
|---|---|---|
| `TxType::CROSS_SHARD_SWAP = 11` | Source-side PREPARE | Carries `(src_action, dst_action, timeout_height, swap_id)`. Submitter signs. |
| `TxType::CROSS_SHARD_SWAP_COMMIT = 12` | Destination-side COMMIT | Carries `swap_id`. Destination recipient signs. Apply path enforces the recipient's identity matches `dst_action.subject` from the pending swap entry. |
| `TxType::CROSS_SHARD_SWAP_ABORT = 13` | Destination-side ABORT | Carries `swap_id`. Destination recipient signs. Optional fast-path for cancellation. |
| `struct SwapPrepareReceipt` | Wire receipt, src → dst | Sibling of `CrossShardReceipt`; carries swap_id + dst_action + timeout_height. |
| `struct SwapCommitReceipt` | Wire receipt, dst → src | Carries swap_id + final-state attestation. |
| `struct SwapTimeoutReceipt` | Wire receipt, dst → src | Carries swap_id + timeout or abort reason. |

The three new TxType slots reuse the existing tx envelope (sig, nonce, fee, payload). The three new receipt structs reuse the existing receipt envelope plumbing (binary codec + JSON, beacon relay path, F2 reconciliation).

State additions on Chain: `std::map<SwapId, LockedSwap> locked_pool_` (source-side) and `std::map<SwapId, PendingSwap> pending_swaps_` (destination-side). Both contribute new state_root namespace leaves — proposed `l:` (locked) and `g:` (pending, since `p:` is already taken by payloads). Both are pruned on swap finalization or timeout.

**Apply-path changes.** Functions extended (no rewrites):

- `BlockValidator::validate_tx` — three new branches for the new tx types; shape/sig/timeout-range checks; reject `CROSS_SHARD_SWAP_COMMIT` and `CROSS_SHARD_SWAP_ABORT` if `swap_id` not in `pending_swaps_`.
- `Chain::apply_transactions` — three new branches; source-side debit-into-lock for PREPARE; destination-side credit-out-of-pending for COMMIT; timeout sweep at start of each block (any swap whose `timeout_height` is now in the past gets a `SwapTimeoutReceipt` queued for outbound).
- `Chain::serialize_state` / `restore_from_snapshot` — `locked_pool_` and `pending_swaps_` added to the snapshot tail and the state_root leaf set.
- `Chain::atomic_scope` (v2.4 A9 substrate) — the source-side debit-into-lock and the destination-side credit-out-of-pending each run inside `atomic_scope` so the per-block-half is atomic. The two halves remain temporally decoupled (3-block latency, by design); the swap as a whole is atomic via the explicit lock + timeout + refund machinery, not via a global cross-shard transaction lock.

**Backward-compat story.** Pure addition; no existing tx behavior changes. v1.x nodes can coexist on the same chain only at heights below the activation flag — they reject the new tx types with "unknown TxType" (existing behavior for any TxType > 10). Activation is a coordinated flag-day height + genesis-pinned constant `cross_shard_swap_active_from_height`. Nodes running v1.x continue to validate blocks up to that height; from the height onward, they must upgrade. Operators who never use `CROSS_SHARD_SWAP` see no change beyond the version bump.

Snapshot interop: snapshots from a v2.12-active node include the new state namespaces; v1.x nodes reject such snapshots (state_root won't validate with their narrower leaf set — already enforced by S-033's state_root gate). No silent corruption path.

**Threat model.** What the primitive defeats:

- **Half-settled swap.** Single-leg apply (source debits, destination never credits, or vice versa) is structurally impossible. Source can't apply credit without destination's COMMIT; destination can't apply credit without a `SwapPrepareReceipt` matching a real source-side lock.
- **Off-chain compensator trust.** The chain itself handles the rollback path via `timeout_height` + `SwapTimeoutReceipt`. No third-party trustee needed.
- **Race-condition double-spend.** The submitter's funds are debited at PREPARE time; the submitter cannot also spend those funds elsewhere because they're physically removed from `account_state_` and held in `locked_pool_`. Re-submission of the same swap_id is rejected (the swap_id is in `locked_pool_` until finalized or timed-out).

New attack surface introduced:

- **Griefing via dangling locks.** A submitter who picks a long `timeout_height` ties up their own funds — only their funds, no shared resource. Cap: enforce `timeout_height - current_height ≤ MAX_SWAP_TIMEOUT_BLOCKS` (proposed 10,000 blocks ≈ several hours at web profile). Self-griefing only, but the cap prevents misconfigured wallets from creating effectively permanent locks.
- **Destination-shard censorship of COMMIT.** If the destination shard's K-committee censors a particular `CROSS_SHARD_SWAP_COMMIT`, the swap times out and refunds — the source-side submitter loses the fee + the opportunity cost of the lock, but not the principal. FA2 (collaborative inclusion) bounds the censorship to (Q-1)-of-K conjunction, same as any other tx; not new attack surface.
- **swap_id collision attack.** `swap_id` includes the submitter's nonce in its preimage, so a single submitter cannot create a collision against their own prior swaps. A cross-submitter collision would require finding a SHA-256 collision (V-3 assumption); not new attack surface.
- **Timeout-window manipulation.** Destination-shard clock divergence from source-shard clock could affect the timeout judgment. Resolved by anchoring `timeout_height` to the **destination shard's** block index (not the source's, not wall-clock time), and by reusing the existing ±30s timestamp window for any timestamp-based assertions inside `dst_action`. This is the same anchor the existing receipt mechanism uses.
- **Cascading swap deadlock.** Two swaps that mutually depend (swap A's COMMIT requires funds locked in swap B) are not deadlocked because both swaps' source-side debits already happened — COMMIT only needs the swap_id to be in `pending_swaps_`, not any external balance check. The destination recipient can COMMIT or ABORT independently per swap.

**Effort estimate.** ~1.5 weeks focused work (revised from prior ~1 week estimate after spelling out the wire format):

| Sub-component | Effort |
|---|---|
| Three new TxType slots + binary codec + JSON | 2 days |
| Three new receipt structs + receipt-relay plumbing | 2 days |
| Source-side PREPARE apply path + `locked_pool_` | 1 day |
| Destination-side COMMIT/ABORT apply paths + `pending_swaps_` | 1 day |
| Timeout-sweep apply hook + outbound receipt emission | 1 day |
| State-root namespace integration + snapshot serialize/restore | 1 day |
| Validator gates + activation-height flag | 0.5 day |
| Regression tests (happy-path, timeout, abort, snapshot round-trip) | 2 days |
| Documentation refresh (PROTOCOL.md tx-type table + receipt table) | 1 day |

**Dependencies.**

- **v2.4 (A9 overlay/atomic_scope)** — ✅ shipped. The per-half atomicity rides on `Chain::atomic_scope`.
- **v2.1 (state Merkle root)** — ✅ shipped. The new `locked_pool_` and `pending_swaps_` namespaces contribute to state_root via the existing leaf-builder pattern; without v2.1 there's no integrity check on the per-swap state.
- **v2.7 (F2 view reconciliation)** — recommended but not strictly required. The new receipts inherit the same intersection-rule treatment v1.x receipts already get (credit-bearing → intersection-of-K-views). F2 tightens the rule; v2.12 works under either the v1.x latency-based admission or F2 intersection.
- **No dependency on v2.10 (threshold randomness)** — the swap primitive is deterministic in the receipt-admission rules; no randomness consumed.
- **No dependency on v2.22 (confidential tx)** — orthogonal. Future composition: a `CROSS_SHARD_SWAP` could carry Pedersen-committed amounts under v2.22's view-key infrastructure, but that's a v2.22-era extension, not a v2.12 dependency.

**Cross-references.**

- FA7 cross-shard receipt atomicity proof: `docs/proofs/CrossShardReceipts.md`. v2.12 extends FA7's scope from "one-shot credit" to "joint debit + conditional credit + timeout refund." The proof structure is unchanged — same source-side debit-then-emit-receipt invariant, same destination-side admit-then-credit invariant — just applied to three new receipt types instead of one.
- A9 atomic_scope: `include/determ/chain/chain.hpp::atomic_scope` (and v2.4 above). Per-half atomicity ride-along.
- Existing cross-shard receipt struct: `include/determ/chain/block.hpp::CrossShardReceipt` (line 339). v2.12's three new receipt structs follow the same shape.
- COMPOSABLE_BATCH precedent: `TxType::COMPOSABLE_BATCH = 8` (line 108). Same "fee charged regardless of inner success" semantics; same `atomic_scope` host.
- Receipt-admission latency constant: `CROSS_SHARD_RECEIPT_LATENCY = 3` (referenced in S-016 closure narrative in MEMORY.md; v2.12 reuses unchanged).
- Sharding topology: works under both v1.x BEACON-mediated sharding and post-Phase-D Beaconless v2 light-client mesh. The wire surface is the same; only the relay-layer changes.

**Closes.** A class of DApp deployment models that need atomic cross-shard transactions (atomic swaps, cross-shard DEX matching, cross-shard escrow with deadline). Strictly additive — no v1.x finding closure depends on v2.12. Enables the application layer to build conditional-settlement protocols without a trusted off-chain compensator.

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

**Problem statement.** Today every account in Determ is a single Ed25519 keypair stored in a single keyfile under `{data_dir}/wallet/<domain>.key` (or anon-address equivalent). Two structural gaps follow:

1. **Single-seed account sprawl.** A user who wants ten distinct identities — one per RP, one per role, one per persona — needs ten independently-generated keyfiles, each with its own passphrase, backup story, and recovery surface. The wallet does not derive child keys from a master seed; there is no BIP-32-class hierarchy. Every key is its own root.
2. **Single-signature transaction model.** `Transaction::sig` is one Ed25519 signature over `signing_bytes()`. There is no per-tx multi-signature primitive — every tx is authorized by exactly one signer. Business deployments that require M-of-N approval (treasury operations, custodial sweeps, joint-account control) must wrap that policy off-chain, which reintroduces a trust singleton (whoever holds the post-policy signing key). The `COMPOSABLE_BATCH` (TxType=8) pattern at `include/determ/chain/block.hpp:108` mentions "Multi-sig parallel approval (M signers act independently, commit iff all M land in the batch)" as a workaround, but it has three structural defects for first-class multi-sig:
   - Each inner tx still has a single signer and a single nonce — the M-of-N is encoded at the batch envelope, not at the account level.
   - The submitter relayer becomes the policy enforcer; the chain has no native concept of "this account requires M signatures."
   - There is no on-chain expression of the policy itself — observers cannot tell that a given account is multi-sig-controlled until they see a representative batch in flight.

v2.15 closes both gaps as one coherent extension to the wallet substrate + a narrow, additive change to `Transaction`.

**Mechanism — Part 1: HD derivation (SLIP-0010-Ed25519).** Ed25519 has no standardized BIP-32 because the underlying scheme requires hashing to scalar with a specific reduction modulo `l` (the curve order). The de-facto standard for HD-Ed25519 is **SLIP-0010** (used by Ledger, Trezor, modern hardware wallets) — HKDF-SHA-512 over a master seed yields a 32-byte child key + 32-byte chain code at each derivation step. Derivation is **hardened-only** for Ed25519 (the soft-derivation path is not safe on Ed25519 because the curve's small subgroup attacks make non-hardened paths leak parent secrets given enough child observations). The derivation path follows BIP-44's structure: `m / purpose' / coin_type' / account' / change' / index'` where Determ would request a `coin_type` registration with SLIP-0044 (proposed slot: 0x80000ded for "Determ"; pending registry application).

Wallet-side layout under `{data_dir}/wallet/`:
- `master.seed.enc` — 32-byte master seed, AES-256-GCM-encrypted under the wallet passphrase (same envelope as v2.17 keyfile encryption).
- `accounts.json` — manifest of derived accounts: `[{path: "m/44'/Determ/0'/0'/0'", domain: "alice.determ", anon_addr: null, ...}, ...]`. Authenticated by `master.seed.enc`'s passphrase-derived MAC tag (so the manifest cannot be silently swapped under the user).
- `<domain>.key` keyfiles become **derived state**, not authoritative. `determ wallet show-key <domain>` re-derives on demand; the keyfile is a cache. Loss of `accounts.json` is recoverable as long as the user remembers their derivation paths or accepts a bounded path-space scan.

**Mechanism — Part 2: On-chain multi-sig.** The chain-side addition is a single optional field on `Transaction` and one new tx type to declare the policy:

- **`Transaction::aux_sigs: std::vector<AuxSig>`** — backward-compat empty by default. When non-empty, the tx is a multi-sig authorization: `sig` is the primary signer's Ed25519 signature; each `AuxSig = { signer_pubkey: PubKey32, ed_sig: Signature64 }` is a co-signer's signature over the same `signing_bytes()`. Validator collects pubkeys, checks against the on-chain policy.
- **`TxType::MULTISIG_POLICY = 14`** — declares "this account requires M-of-N signatures from this pubkey set." Payload: `[op: u8][threshold_m: u8][signer_count_n: u8][n × PubKey32]`. `op` is `0=set, 1=remove`. The account's primary Ed25519 key (the original REGISTER key) signs the policy declaration in the outer envelope. Once set, the account `multisig_policy_` map entry on `Chain` keys the validator into multi-sig-required mode for all subsequent outgoing txs from that account.

**Wire-format changes.**

| Slot | Use | Notes |
|---|---|---|
| `TxType::MULTISIG_POLICY = 14` | Policy set/remove | Outer sig is the account's primary REGISTER key. Policy takes effect at `apply_height + MULTISIG_POLICY_DELAY` (proposed 10 blocks — provides time to revert if the policy itself is hostile/erroneous). |
| `Transaction::aux_sigs` (new optional field) | M-of-N co-signatures | Backward-compat: serialized only when non-empty; absent in binary codec means single-sig (old behavior). |
| `struct AuxSig { PubKey32 signer; Signature64 sig; }` | Wire shape | 96 bytes per co-signer. Cap: `MAX_MULTISIG_SIGNERS = 16` (matches enterprise treasury norms; bounds block-size growth). |
| `struct MultiSigPolicy { threshold_m: u8; signers: vector<PubKey32>; effective_height: u64; }` | Chain-state shape | Stored in `multisig_policies_` keyed by account address. Contributes to state_root via new namespace `s:` for "signing policy" (note `s:` is currently `r:` for registrants? — verify against §4.1.1; new namespace letter to be assigned at integration time). |

The HD layer is **purely wallet-side** — no wire-format change. The chain sees only the resulting derived public keys when each child account does its own REGISTER (or appears as a TRANSFER subject).

**Apply-path integration.**

- `BlockValidator::validate_tx` (src/node/validator.cpp): for any tx with non-empty `aux_sigs`, look up `multisig_policies_[tx.from]`. If absent → reject (the policy slot must exist before aux_sigs are accepted; prevents stray multi-sig spam against non-multisig accounts). If present, verify each `AuxSig`'s `ed_sig` against `signing_bytes()` under the corresponding `signer_pubkey`. Require ≥ `policy.threshold_m` distinct valid pubkeys (each pubkey counted once; duplicates rejected). The primary `sig` field still must verify — it carries the same role as today but counts toward the threshold only if `tx.from`'s primary pubkey is itself in `policy.signers`.
- `Chain::apply_transactions` (src/chain/chain.cpp): for `TxType::MULTISIG_POLICY`, after shape/threshold sanity (`1 ≤ threshold_m ≤ signer_count_n ≤ MAX_MULTISIG_SIGNERS`, no duplicate signers, primary REGISTER key signed the outer envelope), insert into `multisig_policies_[tx.from]` with `effective_height = current_height + MULTISIG_POLICY_DELAY`. Pre-effective-height txs continue to validate under single-sig rules (the policy is **queued, not retroactive**). For `op=1` (remove), the same delay applies — prevents an attacker who briefly compromises one signer from instantly disabling the policy.
- `Chain::serialize_state` / `restore_from_snapshot`: `multisig_policies_` added to the snapshot tail and state_root leaf set under the new namespace.
- `Chain::atomic_scope` (v2.4 A9 substrate): the policy installation runs inside `atomic_scope`; if any sibling tx in the same block rolls back, the policy installation rolls back too.

**Interaction with v2.26 ROTATE_KEY.** Multi-sig accounts cannot use the single-key `ROTATE_KEY` path verbatim — that would let any one signer rotate the policy's primary key and effectively unilaterally take over the account. Resolution: when `multisig_policies_[tx.from]` exists, the `ROTATE_KEY` tx itself must carry `aux_sigs` satisfying the same M-of-N threshold (i.e., the policy gates its own rotation, not just normal txs). v2.26's apply path checks `multisig_policies_` and dispatches accordingly. Documented in `docs/V2-DESIGN.md` §v2.26 cross-reference; spec lives here.

**Threat model.** What the primitive defeats:

- **Single-signer compromise.** With an M-of-N policy and M ≥ 2, compromise of any single signer's key does not authorize any outgoing tx. The attacker must compromise ≥ M signers (or M-1 and own the primary). Standard multi-sig security argument.
- **Custodian unilateral action.** A multi-account treasury where M=3 of N=5 includes signers from three independent operational silos cannot be drained by any single silo. The chain enforces the threshold; no off-chain trust.
- **Account-derivation collision.** HD derivation is hardened-only on Ed25519, so a child key compromise does not leak the master seed or sibling keys. Each derived account is cryptographically independent of every sibling.
- **Wallet backup brittleness.** Today, losing any keyfile loses that account permanently. With HD, losing the wallet's keyfile cache is recoverable from the master seed + derivation path; only loss of the master seed itself is terminal.

New attack surface introduced:

- **Policy install griefing.** An attacker who briefly compromises a primary REGISTER key can install a hostile multi-sig policy, then the policy itself locks out the legitimate owner. Defense: the `MULTISIG_POLICY_DELAY = 10` block window provides a revert period — the legitimate owner, on detecting the install, can submit a competing `MULTISIG_POLICY` with `op=1` (remove) under the same single-sig authority before the policy activates. Once active, removal also requires meeting the threshold (intentional — symmetric to install).
- **Threshold-signer collusion.** If M signers collude, they can drain the account. This is inherent to M-of-N; the cure is choosing N from independent trust silos and choosing M large enough that collusion is operationally difficult. Chain enforces the math; operational selection is off-chain.
- **AuxSig replay across forks.** `signing_bytes()` already binds `chain_id` + nonce + tx_hash precursor fields; co-signer signatures are bound to the same envelope. Cross-fork replay is bounded by `chain_id` exactly as for single-sig.
- **Block-size amplification.** A maximally-multisig tx (M=N=16 signers) adds `16 × 96 = 1536 bytes` of co-signatures. With `MAX_BLOCK_TXS` capped at the existing constant, worst-case block growth is bounded; size cap stays within the existing block-body budget. Quantified in the effort table — no change to existing block-size limits needed.
- **HD-master-seed compromise.** Compromise of `master.seed.enc` plus passphrase leaks every derived account simultaneously. This is strictly *equivalent* to today's threat (compromise of all keyfiles + their passphrases) — the master seed concentrates the key material, but the user's existing passphrase already protects an analogous concentration. The master.seed is encrypted with the same AES-256-GCM envelope shipped under v2.17 (S-004 closure), so the cryptographic envelope is identical.
- **Derivation-path-only enumeration.** An attacker who steals only `accounts.json` (no master seed) sees the derivation paths but not the keys — they can confirm which paths the user has derived but cannot impersonate. Equivalent threat to learning a user's account namespace today; no new exposure.

**Effort estimate.** ~2 weeks focused work:

| Sub-component | Effort |
|---|---|
| SLIP-0010-Ed25519 derivation in wallet (`wallet/hd.cpp` new) | 2 days |
| Wallet HD account manifest + CLI verbs (`hd-init`, `hd-derive`, `hd-show`) | 2 days |
| `Transaction::aux_sigs` field + binary codec + JSON | 1 day |
| `TxType::MULTISIG_POLICY` apply path + validator gates | 2 days |
| `multisig_policies_` state + state_root namespace + snapshot integration | 1 day |
| Wallet-side multi-sig CLI (`policy-set`, `policy-remove`, `cosign`) | 2 days |
| v2.26 `ROTATE_KEY` interaction (multi-sig-gated rotation) | 1 day |
| Hardware-wallet integration outline (Ledger/Trezor SLIP-0010 wire) | 1 day |
| Regression tests (HD derive, M-of-N happy + threshold-fail + duplicate-signer + replay) | 2-3 days |
| Documentation refresh (PROTOCOL.md tx-type table + wallet docs) | 1 day |

**Dependencies.**

- **v2.17 (passphrase-encrypted keyfiles)** — ✅ shipped. The HD master seed reuses the AES-256-GCM envelope.
- **v2.4 (A9 atomic_scope)** — ✅ shipped. Policy install rides inside `atomic_scope` so block-level rollback is clean.
- **v2.1 (state Merkle root)** — ✅ shipped. The new `multisig_policies_` namespace integrates via the existing leaf-builder pattern.
- **v2.26 (ROTATE_KEY)** — coupled. The multi-sig policy must gate `ROTATE_KEY` for multi-sig accounts; the two should ship in adjacent releases, or v2.15 ships with a documented gap that v2.26 closes. Recommended: v2.15 ships the policy + aux_sigs; v2.26 ships ROTATE_KEY with the multi-sig gate already wired in. Avoids a window where a multi-sig account exists but key rotation has not absorbed the policy check.
- **No dependency on v2.10 (threshold randomness)** — multi-sig at the application layer is independent of consensus-layer randomness.
- **No dependency on v2.22 (confidential tx)** — orthogonal; future composition (a confidential multi-sig tx) is natural but not a v2.15 requirement.

**Cross-references.**

- `include/determ/chain/block.hpp:60` — current "no per-tx multisig" comment becomes stale; v2.15 ships the primitive.
- `include/determ/chain/block.hpp:77` — COMPOSABLE_BATCH "Multi-sig parallel approval" workaround is superseded; v2.15 provides the native primitive. COMPOSABLE_BATCH remains useful for other patterns (atomic swaps, bundled transfers).
- `include/determ/chain/block.hpp:205` — `struct Transaction` extended with `aux_sigs` field.
- v2.4 atomic_scope (this document) — host for the policy-install rollback path.
- v2.17 keyfile encryption envelope (this document) — reused for `master.seed.enc`.
- v2.26 ROTATE_KEY (this document) — must absorb the multi-sig gate when both ship.
- SLIP-0010 spec: https://github.com/satoshilabs/slips/blob/master/slip-0010.md (Ed25519 derivation).
- SLIP-0044 coin-type registry: https://github.com/satoshilabs/slips/blob/master/slip-0044.md (Determ coin-type assignment pending).
- BIP-32 / BIP-44 path conventions: https://en.bitcoin.it/wiki/BIP_0032, https://en.bitcoin.it/wiki/BIP_0044.

**Open questions.**

1. **SLIP-0044 coin-type slot.** Determ should request a coin-type registration before v2.15 ships to avoid path-collision with other chains' wallets. Application is mechanical (PR against the SLIP-0044 registry); the slot value affects every Determ HD wallet's derivation paths permanently.
2. **Anon-address support in HD.** Anon addresses are SHA-256 hashes of pubkeys (not the pubkeys themselves). HD derivation works on the pubkey layer; anon-address derivation is a 1-step downstream operation. Confirmed compatible, but the wallet UX needs to be explicit ("derive new anon address" vs "derive new registered domain").
3. **Hardware-wallet integration scope.** Ledger and Trezor both already implement SLIP-0010-Ed25519 for other chains (Solana, Cardano, Algorand). Determ-specific app would reuse the existing primitives — engineering, not protocol design. Scope: ~2 weeks per device, out of v2.15's critical path.
4. **Policy-update threshold escalation.** Should a policy `op=set` that *changes* an existing policy (vs. creating one fresh) require the existing policy's threshold rather than the primary key alone? Recommended: yes, symmetric to ROTATE_KEY's multi-sig gate. Filed as a sub-decision; resolved at integration time.
5. **Recovery story for lost master seed.** v2.14 OPAQUE wallet recovery is per-account today; extending to recover the master seed requires either (a) the seed itself participates in the OPAQUE recovery flow, or (b) accept that lost master seed is terminal (users keep an offline backup, same as Bitcoin BIP-39 seed phrases). Recommended (b); standard practice; out of v2.15's scope but worth noting.

**Closes:** UX gap for enterprise / consortium deployments. The single-keyfile-per-account model becomes the wallet's degenerate case (HD wallet with a single derived account); the multi-sig model becomes available natively without the COMPOSABLE_BATCH workaround. Strictly additive — no v1.x finding closure depends on v2.15. Enables business-grade treasury operations, joint accounts, and inheritance/recovery flows that today require off-chain trust singletons.

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

### v2.20 — Streaming subscription RPC — ⚠️ partial (polling shipped, streaming pending)

**Status.** v2.19 shipped the **polling** subset under the `dapp_messages` RPC (retrospective query with `from_height` / `to_height` / `topic` filters, 256-event pages). The **streaming** subset documented below is the remaining ~3 days of work.

**Problem statement.** Polling `dapp_messages` has three intrinsic costs that scale poorly past moderate event rates:

1. **Wasted RPC trips.** Each poll is a full request/response round trip (HMAC verify on the request envelope, JSON decode, full read-lock acquisition against the tx index, JSON encode of the empty/sparse result, response framing). For a DApp that processes ~10 events/sec the floor is ~1 Hz polling; for a DApp at ~100 events/sec the polling cadence pushes into ~10 Hz and dominates the node's RPC capacity even when the chain is otherwise idle.
2. **Time-to-deliver lag bound by poll period.** A DApp that polls every 1s sees, on average, 500 ms of delivery latency over and above the block-finality latency. For tactical-profile deployments (20 ms blocks) the chain-side latency is sub-block-time; the polling layer doubles it.
3. **Backfill ambiguity at the poll boundary.** Polling clients must reconcile "did I see all events for block H?" via `from_height = last_scanned + 1` and rely on the chain's finalization barrier. Late-arriving txs (in F2 mode, when reconciliation extends the inbound-receipt window) can perturb the per-block tx index. The polling client doesn't see this; the streaming model can emit per-tx events with explicit `block_index` + `tx_index` + `seq` keys that the subscriber can use for idempotent dedup.

The streaming primitive collapses the round-trip into a single long-lived connection with per-event push, eliminates the polling-period contribution to delivery latency, and exposes explicit ordering keys.

**Mechanism (sketch).** A new `dapp_subscribe(domain, topic?, since?)` RPC opens a persistent TCP connection that the node holds open across block boundaries. The connection multiplexes server-pushed events (block-finality notifications, matching DAPP_CALL events, heartbeats, error frames). Newline-delimited JSON, one frame per line. The subscriber may close at any time; the node disconnects on backpressure violation or shutdown.

The wire flow:

```
DApp client                     Determ node
   │                                 │
   │   dapp_subscribe(domain="ex.io",│
   │                  topic="bid",   │
   │                  since=H_start) │
   ├────────────────────────────────>│
   │                                 │  validate domain in dapp_registry_;
   │                                 │  if since < current head - SUBSCRIBE_BACKLOG_MAX_BLOCKS, reject;
   │                                 │  allocate Subscriber{queue, filter, seq=0};
   │                                 │
   │   {"event":"subscribed",        │
   │    "domain":"ex.io",            │
   │    "topic":"bid",               │
   │    "since":H_start,             │
   │    "head":H_now,                │
   │    "subscriber_id":"a3...",     │
   │    "seq":0}                     │
   │<────────────────────────────────│
   │                                 │  catch-up phase: iterate dapp_messages index
   │                                 │  from H_start to H_now, emit matching events
   │                                 │
   │   {"event":"dapp_call",         │
   │    "block_index":H,             │
   │    "tx_index":I,                │
   │    "seq":N,                     │
   │    "from":"...","to":"ex.io",   │
   │    "amount":0,"payload":"..."}  │
   │<────────────────────────────────│
   │                                 │  (repeat for each historical match)
   │                                 │
   │   {"event":"live",              │
   │    "block_index":H_now,         │
   │    "seq":N}                     │
   │<────────────────────────────────│  catch-up complete; transition to live tail
   │                                 │
   │                                 │  per-block hook fires after enqueue_save
   │   {"event":"dapp_call",         │
   │    "block_index":H_now+1,...}   │
   │<────────────────────────────────│
   │                                 │
   │   {"event":"heartbeat",         │
   │    "block_index":H,             │
   │    "seq":N,                     │
   │    "ts":1700000000}             │  every HEARTBEAT_INTERVAL_BLOCKS even if no matches
   │<────────────────────────────────│
   │                                 │
   │  ...                            │
   │                                 │
   │   {"event":"error",             │
   │    "code":"backpressure",       │
   │    "queued":1024,"limit":1024}  │  emitted just before forced close
   │<────────────────────────────────│
   │                                 │  node closes socket; client must redial
```

**Wire-format additions.** None at the consensus / gossip layer. All changes are within the RPC envelope already defined by §10.x of `PROTOCOL.md`. Three new event-frame schemas:

| Frame | Direction | When emitted | Payload shape |
|---|---|---|---|
| `subscribed` | server → client | Once per successful `dapp_subscribe` call | `{domain, topic, since, head, subscriber_id, seq}` |
| `dapp_call` | server → client | Per matching DAPP_CALL in any finalized block | `{block_index, tx_index, seq, from, to, amount, payload, sig}` |
| `live` | server → client | Transition marker between catch-up replay and live tail | `{block_index, seq}` |
| `heartbeat` | server → client | Every `HEARTBEAT_INTERVAL_BLOCKS` (default 50) even with no matches | `{block_index, seq, ts}` |
| `error` | server → client | Just before forced disconnect | `{code ∈ {backpressure, shutdown, invalid_arg, rate_limited}, ...}` |
| `close` | client → server (optional) | Voluntary graceful unsubscribe | `{subscriber_id}` — server flushes pending frames then closes |

Per-subscriber state on `Node`: `struct Subscriber { uint64_t id; std::string domain; std::optional<std::string> topic; std::deque<EventFrame> queue; uint64_t seq; uint64_t bytes_buffered; std::chrono::steady_clock::time_point last_send; asio::ip::tcp::socket socket; }`. The `subscribers_` map is keyed by `subscriber_id` and protected by a dedicated `std::mutex subscribers_mutex_` (separate from `state_mutex_` to keep the per-block fan-out off the hot consensus path).

**Apply-path integration.**

Touch list (files in `src/node/`, no `src/chain/` changes — this is purely an RPC-layer feature):

| File | Function | Change |
|---|---|---|
| `include/determ/node/node.hpp` | `class Node` | Add `subscribers_` map + `subscribers_mutex_`; declare `rpc_dapp_subscribe`, `on_block_finalized_for_subscribers`, `enqueue_subscriber_event`, `kill_subscriber` |
| `src/node/node.cpp` | RPC dispatch table | Register `dapp_subscribe` handler (singleton — does NOT return after first response; holds the socket) |
| `src/node/node.cpp` | new `rpc_dapp_subscribe(socket, params)` | Validate domain (must be in `dapp_registry_` and not `inactive_from ≤ head`); validate `topic` shape if present; validate `since` is within `[head - SUBSCRIBE_BACKLOG_MAX_BLOCKS, head]`; allocate Subscriber; emit `subscribed` frame; spawn catch-up replay; on completion emit `live` frame and add to live `subscribers_` set |
| `src/node/node.cpp` | new `on_block_finalized_for_subscribers(const Block&)` | Called from the existing per-block hook (currently calls `enqueue_save`); iterates `block.transactions`; for each `DAPP_CALL` tx checks subscriber filters; for each match calls `enqueue_subscriber_event` |
| `src/node/node.cpp` | new `enqueue_subscriber_event(Subscriber&, EventFrame)` | Appends to `Subscriber::queue` under `subscribers_mutex_`; checks `queue.size() < SUBSCRIBER_QUEUE_MAX` and `bytes_buffered < SUBSCRIBER_BYTES_MAX`; on overflow emits `error{code=backpressure}` synchronously, marks for kill, returns. Triggers async-write worker if not already running for this subscriber |
| `src/node/node.cpp` | new `subscriber_write_worker(Subscriber&)` | Single producer/single consumer pattern; pulls from queue, writes to socket via asio `async_write`; on write error calls `kill_subscriber`; on empty queue parks awaiting next `enqueue_subscriber_event` |
| `src/node/node.cpp` | new `kill_subscriber(uint64_t id, std::string_view reason)` | Emits final `error` frame (best-effort, single sync write with 50 ms timeout), closes socket, removes from `subscribers_` |
| `src/node/node.cpp` | new periodic timer `heartbeat_tick` | Every `HEARTBEAT_INTERVAL_BLOCKS` blocks (or `HEARTBEAT_INTERVAL_SECS` for the secs fallback), emits `heartbeat` to every live subscriber |
| `src/node/node.cpp` | `enqueue_save` block hook (existing) | Add a synchronous call to `on_block_finalized_for_subscribers` after `enqueue_save` enqueues (NOT after the async worker actually persists; the subscriber stream is decoupled from disk persistence on purpose — subscribers see the chain's logical state) |
| `tools/test_dapp_subscribe.sh` | new | Regression: subscribe, observe heartbeat, submit DAPP_CALL, verify event arrives; backpressure path; reconnect-after-disconnect via `since` |

Constants (proposed defaults; genesis-pinned with v2.X.2 governance-mutability):

| Constant | Default | Purpose |
|---|---|---|
| `SUBSCRIBER_QUEUE_MAX` | 1024 | Per-subscriber event-count ceiling before backpressure-kill |
| `SUBSCRIBER_BYTES_MAX` | 16 MiB | Per-subscriber byte-buffer ceiling (covers very large `DAPP_CALL` payloads — small-event count cap dominates for normal traffic) |
| `SUBSCRIBER_MAX_PER_NODE` | 256 | Global ceiling on concurrent subscribers; rejects new `dapp_subscribe` calls with `error{code=rate_limited}` past this |
| `SUBSCRIBE_BACKLOG_MAX_BLOCKS` | 10 000 | How far back `since` can reach; older requires `dapp_messages` polling first |
| `HEARTBEAT_INTERVAL_BLOCKS` | 50 | Heartbeat cadence in chain-block units (preferred — chain-time aligns to consensus, not wall-clock) |
| `HEARTBEAT_INTERVAL_SECS` | 30 | Wall-clock fallback for low-block-rate profiles |

Per-IP and per-RPC-token rate-limiting: the existing `net::RateLimiter` (S-014, `include/determ/net/rate_limiter.hpp`) is extended with a "long-lived connection" bucket that counts a subscription as a fixed weight (e.g., 100 token units consumed at subscribe; +1 per event delivered). Prevents a single client from exhausting `SUBSCRIBER_MAX_PER_NODE`.

**Backpressure semantics.** Three escalation tiers:

1. **Soft buffering.** Normal operation; events queued and drained at socket-write speed. Single subscriber can absorb burst spikes up to `SUBSCRIBER_QUEUE_MAX` events or `SUBSCRIBER_BYTES_MAX` bytes.
2. **Backpressure-kill (hard).** Either ceiling exceeded → emit final `error{code=backpressure, queued, limit}` frame, force-close socket, remove subscriber. Client redials with `since = last_observed_block_index`. The decision is deterministic and per-subscriber; one slow subscriber cannot affect any other.
3. **Global rate-limit.** Past `SUBSCRIBER_MAX_PER_NODE` concurrent subscriptions, `dapp_subscribe` requests fail with `error{code=rate_limited}`. Operator can raise via config.

Rationale for kill-on-overflow vs. drop-on-overflow: subscribers reading `block_index` + `seq` keys want a contiguous stream. Silently dropping events makes the stream unreliable; subscribers can't tell whether `seq` jumped because the chain was idle (legitimate) or because the node dropped frames (silent corruption). Forcing reconnect-via-`since` keeps the contract clean: the client always knows exactly where they stand.

**Multi-topic dispatch.** `topic` filter is single-string match against the DAPP_CALL payload preamble (v2.19's existing topic-routing convention). A subscriber may open multiple parallel subscriptions to combine filters; the chain does NOT support an inline OR-list because (a) per-subscription accounting stays simple, (b) the cost of a second TCP connection is negligible vs. introducing list-filter validation surface, (c) it preserves the "one subscriber = one filter" invariant that makes the dispatch loop trivial. The dispatch loop is `O(|subscribers|)` per finalized block in the worst case (every subscriber matches); for `SUBSCRIBER_MAX_PER_NODE = 256` this is dominated by the socket-write cost, not the filter check.

**Threat model.**

| Attack | v2.20 defense | New surface introduced |
|---|---|---|
| **Slow-subscriber DoS** (open a subscription, then never read; force node to buffer events forever) | `SUBSCRIBER_QUEUE_MAX` + `SUBSCRIBER_BYTES_MAX` per-subscriber ceilings; backpressure-kill on overflow. Single misbehaving subscriber's footprint is bounded; node-wide buffering is `SUBSCRIBER_MAX_PER_NODE × SUBSCRIBER_BYTES_MAX = 4 GiB` worst-case (operator can tune). | None — strictly improves on a naive unbounded-buffer implementation |
| **Connection-flood DoS** (open `SUBSCRIBER_MAX_PER_NODE` subscriptions from one client to lock out others) | Per-IP and per-RPC-token rate-limit via existing `net::RateLimiter` extended with subscription-weight bucket; operator can also configure a per-token max-concurrent ceiling separately from the global node ceiling | One new rate-limit dimension; well-understood mitigation; reuses the post-S-014 token-bucket infrastructure |
| **Event-storm amplification** (DApp-side adversary submits many DAPP_CALLs to a popular domain; per-block hook fans out × `|subscribers_for_domain|`) | Anti-spam on the submission side is already covered by v2.19 (chain-wide `DAPP_CALL` min-fee + S-008 mempool quota); the fan-out itself is O(N) and bounded by `SUBSCRIBER_MAX_PER_NODE` — operator can lower this ceiling if their node serves many high-traffic DApps | The fan-out cost lives on the producer/finalizer's hot path; mitigation if observed: move `on_block_finalized_for_subscribers` to a dedicated worker thread, dispatching events asynchronously to subscriber queues (already the design here; reaffirm in implementation) |
| **Replay across reconnect** (client reconnects with `since = old_height`; node re-emits old events; client must dedup) | The wire contract is explicit: client uses `(block_index, tx_index, seq)` as the idempotent key. Reconnects naturally backfill; the catch-up replay is bounded by `SUBSCRIBE_BACKLOG_MAX_BLOCKS`. Clients reconnecting from too far in the past are told to polling-backfill via `dapp_messages` first | None — explicit semantics |
| **Confidentiality of DAPP_CALL payloads** | Payload bytes are opaque to the chain; encryption is sender-side (libsodium sealed-box to the DApp's `service_pubkey` per V2-DAPP-DESIGN.md §10). A subscriber reading the stream sees the same bytes as anyone reading the chain — no new disclosure path | None — surface identical to existing tx-index queries |
| **Spurious "subscribed" by impersonator** (attacker observes subscriber traffic, replays the `subscribed` frame to confuse the client) | Server-pushed frames carry the `subscriber_id` (random 16-byte token) emitted in the original `subscribed` frame; client validates `subscriber_id` matches on every subsequent frame. Also: the underlying RPC channel is HMAC-authenticated (v2.16), so a passive observer cannot inject frames | None |
| **Information leak via topic-filter probing** (attacker subscribes with various `topic` values to learn what topics a DApp uses) | DAPP_CALL topics are public chain data already (visible via `dapp_messages`); no new information leakage | None |
| **Heartbeat-as-side-channel** (timing of heartbeats reveals chain-internal block-finality cadence to an unauthenticated observer) | All subscribers are authenticated via the RPC HMAC token (v2.16); no unauthenticated observers exist. Heartbeat cadence is already public via `chain_status` RPC | None |

**Effort estimate.** ~3 engineering days remaining, broken down:

| Sub-component | Effort | Notes |
|---|---|---|
| `Subscriber` struct + `subscribers_` map + `subscribers_mutex_` | 0.5 day | Mechanical; mirrors existing per-peer struct patterns in `Node` |
| `rpc_dapp_subscribe` dispatch + frame schemas + catch-up replay | 0.5 day | Catch-up reuses existing `dapp_messages` retrospective query |
| `on_block_finalized_for_subscribers` block hook + per-subscriber filter + dispatch | 0.5 day | Single new hook point in the post-`enqueue_save` codepath |
| `subscriber_write_worker` + backpressure check + `kill_subscriber` | 0.5 day | asio async_write; one worker per subscriber socket |
| Heartbeat timer + `heartbeat_tick` | 0.25 day | Single periodic asio timer |
| Per-IP rate-limit integration (extend `net::RateLimiter`) | 0.25 day | Reuse token-bucket; add subscription-weight class |
| Regression: `tools/test_dapp_subscribe.sh` (subscribe, heartbeat, deliver, backpressure, reconnect) | 0.5 day | Five scenarios; mirrors `tools/test_dapp_call.sh` shape; uses two daemons and a subscriber harness |
| CLI: `determ dapp-subscribe --domain D [--topic T] [--since H]` | 0.25 day | Thin wrapper; mostly stdin/stdout passthrough of newline-JSON |
| Documentation: PROTOCOL.md §10.2 (RPC list), V2-DAPP-DESIGN.md Phase 7.4 status flip, CLI-REFERENCE.md verb | 0.25 day | Small touch-ups |
| **Total** | **~3 engineering days** | Single-developer estimate; +0.5 day if the rate-limit extension needs its own test |

**Dependencies.**

- **v2.18 DAPP_REGISTER** — ✅ shipped. Required to resolve the `domain` argument against `dapp_registry_`.
- **v2.19 DAPP_CALL** — ✅ shipped. Required for the events themselves; v2.20 reuses the per-block tx iteration already present.
- **v2.16 RPC HMAC auth (S-001)** — ✅ shipped. Required for subscriber authentication; v2.20 reuses the existing token-verify path on the initial `dapp_subscribe` request.
- **S-014 per-peer-IP token bucket** — ✅ shipped (`net::RateLimiter`). Extended here with a subscription-weight class.
- **v2.4 A9 atomic apply / `atomic_scope`** — ✅ shipped. The per-block hook fires after the atomic-apply commit; subscribers see logically-finalized state.
- **v2.20 polling subset (`dapp_messages`)** — ✅ shipped. Reused for the catch-up replay phase (subscriber's initial `since` window).
- **No dependency on v2.7 (F2)** — but composes cleanly: F2's intersection-rule for inbound receipts does not affect DAPP_CALL inclusion (DAPP_CALLs are pool-fed at submission, not inbound from another shard); subscriber stream is unaffected by F2's wire change.
- **No dependency on v2.10 (threshold randomness)** — orthogonal.

**Cross-references.**

- `V2-DAPP-DESIGN.md` §11 Phase 7.4 — Companion spec from the DApp-substrate side. This V2-DESIGN entry covers the chain/RPC-layer mechanism; the V2-DAPP entry covers the DApp-developer-facing contract.
- `PROTOCOL.md` §10.2 — RPC surface; v2.20 adds one entry to the list (`dapp_subscribe`).
- `V2-DAPP-DESIGN.md` §10 Privacy & off-chain channels — DAPP_CALL payloads are sender-encrypted via libsodium sealed-box; the streaming layer doesn't change payload confidentiality.
- `SECURITY.md` §S-014 — token-bucket rate-limit infrastructure that v2.20 extends.
- `SECURITY.md` §S-001 — HMAC RPC auth that v2.20 reuses for subscriber authentication.
- `include/determ/net/rate_limiter.hpp` — touch site for the subscription-weight class.
- `src/node/node.cpp` `enqueue_save` block hook — touch site for `on_block_finalized_for_subscribers`.
- `tools/test_dapp_call.sh` + `tools/test_dapp_messages.sh` — sibling regression patterns that `tools/test_dapp_subscribe.sh` mirrors.

**Open design questions.**

1. **Should `dapp_subscribe` accept multiple `domain` filters in one connection?** Argument for: a DApp gateway operator subscribed to N domains for relay pays N socket establishments and N HMAC verifications. Argument against: complicates per-subscriber accounting (which domain caused the backpressure?) and the dispatch loop must check N filters per event. Default position: single-domain per connection in v2.20.0; revisit in v2.20.1 if real DApp gateways demand it. The cost of N connections is negligible compared to introducing list-filter validation surface.
2. **Frame format: newline-JSON or length-prefixed binary?** Newline-JSON matches the existing RPC transport and is human-debuggable. Length-prefixed CBOR or protobuf would shave ~30 % bytes-on-wire but introduces a second serializer in the RPC path. Default position: newline-JSON for v2.20; revisit only if real deployments observe payload-size as the bottleneck.
3. **Should the streaming subset re-emit historical events on operator-initiated reorg?** Determ is fork-free at the chain layer (FA1), so genuine reorgs cannot happen — but in an EXTENDED-mode partition + merge scenario, a shard's local view of `dapp_registry_` could conceivably change after a `MERGE_END`. Default position: out of scope for v2.20; subscriber stream is a thin live-tail over the chain's monotonically-extending tx history. If a merge-induced state change retroactively invalidates an emitted event, the subscriber redials and observes the new state via catch-up. This composes with v2.11's auto-detection beacon-side trigger but does not require it.
4. **WebSocket transport in v2.20 or v2.20.1?** WebSockets are the obvious browser-facing transport but require an HTTP-upgrade handshake on top of the existing TCP socket. Default position: defer to v2.20.1; v2.20 ships raw-TCP newline-JSON for DApp-server-to-Determ-node subscriptions, which is the primary use case. Browser-side subscribers can use a thin DApp-side WebSocket gateway that itself runs as a subscriber.
5. **Per-subscriber state and its commitment.** Subscribers are NOT chain-state — they're per-node operator-facing resources. They do NOT contribute to the state_root (v2.1) or appear in snapshots (v2.3). A node restart drops all subscriptions; clients must redial. This is intentional: the streaming layer is RPC-server lifecycle, not consensus state.
6. **Composition with v2.22 confidential transactions.** If v2.22 ships per-epoch view-key derivation, DAPP_CALL payloads might carry encrypted amount commitments. The subscriber stream would deliver these as-is; subscribers responsible for their own per-epoch view-key handling (out of scope for v2.20).

**Cost.** ~3 days remaining. See effort table above. Net new RPC surface is one verb + five event frames; net new node state is one map; net new threat surface is bounded by the existing rate-limit and HMAC-auth infrastructure.

**Closes:** none directly — operational improvement for DApp node implementers. Enables the V2-DAPP §11.4-§11.7 cohort of DApp use cases (live order books, push notifications, encrypted streaming media) without polling-induced latency / RPC-trip waste.

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

**Profile applicability.** Available only in **MODERN cryptographic profile** deployments (web / regional / global timing profiles). Not available in **FIPS profile** which is bundled with `tactical` (military / defense / embedded) AND `cluster` (in-house enterprise / financial services / regulated) timing profiles — no FIPS-validated zero-knowledge range proofs exist. FIPS-profile deployments use clear-amount TRANSFER txs + v2.24 audit hooks for regulator access. Per `CRYPTO-C99-SPEC.md` §2.Q10.

**Motivation.** Today every TRANSFER amount is public on-chain. For payment use cases — payroll, vendor payments, B2B settlement, retail, regulated gambling — this is incompatible with normal commercial confidentiality. The alternative (every user using a mixer DApp) doesn't compose with audit-grade compliance.

**Mechanism.** Replace TRANSFER's clear-text `amount: u64` with a Pedersen commitment `C = aG + bH` (where `a` is the amount and `b` is a blinding factor). Sender attaches a Bulletproof range proof that `0 ≤ a < 2^64` (no underflow) and a balance-conservation proof binding inputs and outputs. Recipient learns `a` via an ephemeral Diffie-Hellman handshake against the recipient's published `view_master_pk`; per-tx amount-encryption key derives via HKDF.

**Design resolved per Option C (per-epoch automatic rotation via HKDF derivation).** Full spec: `docs/proofs/v2.22-PRIVACY-SPEC.md`. The four interlinked sub-questions are resolved as follows:

| Sub-decision | Resolved choice | Why |
|---|---|---|
| View-key rotation cadence | **Per-epoch automatic rotation via HKDF** | Bounded exposure per epoch; zero on-chain rotation cost; maps to regulator audit cadence; no rotation discipline required |
| Range-proof construction | **Bulletproofs over secp256k1** (via libsecp256k1-zkp) | Most-production-tested C99 Bulletproof implementation (~5+ years in Liquid + Grin); Bitcoin-grade audit pedigree (libsecp256k1 secures ~$1T+ value); libsodium-independent (aligns with CRYPTO-C99-SPEC.md full libsodium removal); prime-order natively; no trusted setup. Adds secp256k1 as second curve family — deliberate trade-off for libsodium independence per CRYPTO-C99-SPEC.md §2.Q1 |
| Sender-recipient handshake | **Ephemeral DH against recipient's `view_master_pk` + HKDF + XChaCha20-Poly1305 AEAD** | One-shot tx submission (no bidirectional interaction); forward secrecy via ephemeral; libsodium primitives already in tree |
| Audit integration (v2.24) | **Dual-mode disclosure: `view_master_sk` (full) or per-epoch `vk_epoch_n` (scoped)** | Master = in-house compliance; per-epoch = external regulator with bounded audit window; maps to real regulator workflows |

Each account has a long-term `view_master` keypair. Per-epoch view keys derive deterministically: `vk_epoch_n = HKDF(view_master_sk, "VK" || chain_id || account_addr || epoch_n)`. Recipients and auditors recompute the same derivation to decrypt amounts within epoch n. Compromised epoch keys expose only that epoch's amounts; subsequent epochs unaffected.

**Tx-level encryption.** Sender generates ephemeral X25519 `eph_sk`; computes shared secret `ss = X25519_dh(eph_sk, view_master_pk)`; derives `aek = HKDF-SHA-256(ss, "AMT" || epoch_n || tx_hash)`; encrypts amount as `amount_ct = XChaCha20-Poly1305(aek, amount_bytes, AAD = "TX-AMT" || tx_hash)`. Tx carries: Pedersen commitment on secp256k1 (Bulletproof-compatible), range proof, X25519 `eph_pk`, `amount_ct`. Recipient (or auditor with X25519 view-master-sk) decrypts via the same DH. Two-curve protocol: X25519 for DH (curve25519 family); secp256k1 for commitment (matches Bulletproof primitive).

**Emergency master compromise recovery.** `ROTATE_VIEW_MASTER` tx (analogous to v2.26 `ROTATE_KEY`) allows one-time recovery from catastrophic master compromise. Not for routine rotation (Option C handles routine rotation via HKDF) — only for emergency.

**Cost (refined per spec).** ~3 months focused work. Breakdown:

| Sub-component | Effort |
|---|---|
| Bulletproofs over curve25519 (vendor dalek-cryptography reference directly) | 2-3 weeks |
| Pedersen commitment integration | 2-3 weeks |
| View-master + per-epoch HKDF derivation | 2 weeks |
| Sender-recipient DH handshake (libsodium AEAD) | 1 week |
| `ROTATE_VIEW_MASTER` tx | 1 week |
| Audit-mode tooling + v2.24 integration | 2-3 weeks |
| Tests + docs | 2 weeks |
| Migration tooling | 1 week |

**Shared infrastructure savings.** libsodium already vendored (wallet/envelope.cpp + Theme-7 direct-to-DApp pattern + v2.10 DKG). Bulletproofs uses the same ristretto255 primitives. Same curve family across v2.10 (FROST-Ed25519), v2.22 (Bulletproofs/curve25519), and v2.25 (T-OPAQUE/ristretto255). One audit surface across all threshold-cryptography features.

**Composes with.**
- **v2.24 audit hooks** — concrete dual-mode disclosure mechanism (master vs per-epoch). v2.24 reduces to "add `audit_view_master_pk` field + `ROTATE_AUDIT_KEY` tx + reference auditor tool"; v2.22 provides the underlying view-key infrastructure.
- **v2.26 key rotation** — `ROTATE_VIEW_MASTER` and `ROTATE_AUDIT_KEY` follow the same pattern as v2.26 `ROTATE_KEY`; shared cooldown semantics.
- **v2.10 DKG infrastructure** — curve25519 family via libsodium already vendored; FROST-Ed25519 primitives shared.
- **v2.25 DSSO (Theme 9)** — DSSO assertions can carry encrypted account-history summaries scoped to the RP via per-tx ephemeral DH (future composition; not in v2.22's scope).

**Closes:** new capability (no existing finding). Enables real-world payment use cases that today need a separate privacy chain — including the gambling-industry deployments where high-roller bankroll confidentiality is a regulatory requirement.

**Full design spec:** `docs/proofs/v2.22-PRIVACY-SPEC.md` (resolves all 4 interlinked sub-questions; implementation work units; failure-mode handling; rollback plan; 5-point pre-implementation review checklist).

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

**Mechanism (simplified post-v2.22 spec).** v2.22 already delivers the view-key infrastructure (`view_master_pk` per account + per-epoch HKDF derivation + ephemeral-DH amount encryption). v2.24 adds:

1. **`audit_view_master_pk` field on Account** — optional; absent = no standing auditor; present = named auditor has standing pre-authorization to derive view keys via DH against the auditor's published pubkey.
2. **`ROTATE_AUDIT_KEY` tx** — analogous to v2.26 `ROTATE_KEY`; rotation cooldown applies.
3. **Audit-mode RPC** — `audit_decrypt_tx(tx_hash, vk_epoch_n) → amount` for off-chain auditor tooling.
4. **`LOG_AUDIT_ACCESS` tx** (optional) — on-chain record of disclosure events for deployments requiring auditable audit access.
5. **Reference auditor tool** — takes `view_master_sk` (or per-epoch keys) + audit-mode RPC; produces compliance reports (CSV / JSON).

Two disclosure modes (defined in v2.22 spec §2.Q4):
- **Master mode**: auditor receives `view_master_sk` — full access to all amounts to/from this account, ever. For in-house compliance officers with permanent audit relationships.
- **Per-epoch mode**: auditor receives `vk_epoch_n` for specific epochs — bounded access. For external regulators with quarterly/annual audit windows.

**Cost (reduced post-v2.22 spec).** ~1-2 weeks (vs. prior 2-3 week estimate). v2.22 delivers the view-key infrastructure; v2.24 adds the auditor-facing tx types + tooling on top.

| Sub-component | Effort |
|---|---|
| `audit_view_master_pk` field on Account + apply path | 2-3 days |
| `ROTATE_AUDIT_KEY` tx (analogous to v2.26) | 3-5 days |
| Audit-mode RPC | 2-3 days |
| `LOG_AUDIT_ACCESS` tx (optional) | 2 days |
| Reference auditor tool | 3-5 days |

**Closes:** removes the "Determ is unusable for regulated payments" objection. Composes cleanly with v2.22's privacy infrastructure — see `docs/proofs/v2.22-PRIVACY-SPEC.md` §2.Q4 + §4.6 for the integration spec.

---

## Theme 9 — Distributed identity provider (DSSO over mutual-distrust IdP)

Determ's K-of-K committee is, structurally, a mutual-distrust group of operators. The literature has a natural fit: **distributed identity-provider designs that authenticate users via a black-box augmented PAKE held in threshold form across K cooperating-but-untrusting servers**. Plugging Determ's committee into such a framework yields a federated single-sign-on (DSSO) substrate without re-introducing a centralised identity provider — which would otherwise be a structural mismatch with Determ's threat model.

The framework is exogenous; the substitution choice (and most of the engineering value-add for Determ) is **OPAQUE instead of the original-paper SRP** for the aPAKE primitive. SRP is a 2002-era PAKE designed for a single server; OPAQUE (CFRG draft, RFC 9807-track) is the modern, UC-secure aPAKE that (a) resists offline dictionary attacks against a stolen verifier, (b) hides the password from the server even in plaintext form via OPRF blinding, (c) composes naturally with threshold OPRF to distribute across K operators with a published, analysed security argument. The framework is PAKE-agnostic, so the substitution is value-additive without invalidating any of the original architectural claims.

### v2.25 — Distributed identity provider (DSSO substrate)

**Motivation.** Today there is no Determ-native authentication primitive for off-chain services. Operators wanting to use Determ identities (registered domain or anon address) as the trust anchor for an off-chain service have to roll their own challenge-response protocol against a single Determ node — which centralises trust on whichever node they happen to query. For permissionless DApp deployment the absence of a federated authentication primitive is the missing piece between "Determ as a chain" and "Determ as a usable identity substrate."

A distributed-IdP framework with the K-of-K committee as the operator group + T-OPAQUE as the PAKE gives Determ users a SIWE-class sign-in flow ("Sign-In With Determ") that:
- Authenticates the user against the chain's identity registry, not any single node.
- Never exposes the user's password or recovery secret to any single committee member.
- Survives compromise of any K−1 committee members without leaking auth material (matches the K-of-K mutual-distrust posture already used for consensus).
- Composes with v2.18 DAPP_REGISTER (the relying party publishes its identity on-chain) and v2.19 DAPP_CALL (challenges and assertions ride the existing message-routing rails).

**Mechanism.** Three layers, each independently specifiable:

1. **Distributed aPAKE.** T-OPAQUE on the K committee members. Each committee member holds an OPRF share. User-side OPAQUE registration and login follow the OPAQUE RFC except the OPRF evaluation is threshold-distributed across the committee — the user collects K (or t-of-K) blinded evaluations and recombines locally. The committee never sees the password, never sees the recovery envelope, and can't precompute a dictionary even by colluding below the threshold.

2. **Signed-assertion token format.** After OPAQUE authenticates the user-committee session, the committee co-signs (Ed25519 today; threshold-signed via v2.10 BLS once it ships) a structured assertion of the form
   ```
   { iss = chain_id, sub = user_identity, aud = rp_identity,
     iat = unix_ts,  exp = iat + ttl,
     nonce, height, state_root }
   ```
   The relying party verifies the committee signature against the on-chain committee pubkey set (resolved via v2.2 state_proof RPC), with no trust in any single Determ node. Identical role to a SIWE message or an OIDC ID token, anchored on the chain instead of a centralised IdP.

3. **Relying-party registration.** Services register as DApps via v2.18 DAPP_REGISTER. The registry record carries the RP's own identity + (optionally) a discovery URL. Users can discover RPs by querying the registry; RPs can authenticate users by emitting a challenge via v2.19 DAPP_CALL and verifying the user's signed response.

**Black-box PAKE invariant.** The framework treats the aPAKE primitive as a black box meeting the standard "authenticate password against verifier without revealing password" property. SRP and OPAQUE both nominally satisfy this; OPAQUE additionally satisfies precomputation-resistance and verifier-secrecy-against-malicious-server, which the framework's security proofs quantify over but do not depend on by name. Hence the substitution is layered cleanly: the architectural contribution survives intact, the security claims tighten.

**Dependencies.**

| Block | Status |
|---|---|
| v2.10 threshold randomness (curve25519 family + FROST-Ed25519 DKG) | 🔥 active. Provides the threshold-crypto plumbing the T-OPAQUE share-distribution layer needs. |
| v2.14 OPAQUE wallet recovery | ⏳ not started. Exercises the single-server OPAQUE primitive in production; de-risks the threshold version. |
| v2.18 DAPP_REGISTER | ✅ shipped. RP-registration channel. |
| v2.19 DAPP_CALL | ✅ shipped. Challenge / assertion delivery channel. |
| v2.26 On-chain key rotation | ⏳ not started. Without rotation, a compromised user key is irrecoverable; precondition for production DSSO. |

**Cost.** ~4-6 weeks of focused work after the precondition blocks land:

| Sub-component | Effort |
|---|---|
| T-OPRF + T-OPAQUE library (vendor + harden) | 1-2 weeks |
| Wallet-side OPAQUE flow (overlaps with v2.14 single-server scope) | 1 week |
| Server-side per-committee share storage + on-chain state binding | ~1 week |
| Signed-assertion protocol + token format | ~3-5 days |
| Reference relying-party DApp + integration test | ~3-5 days |
| Spec doc + threat-model write-up | ~3-5 days |

**Closes:** new capability — Determ becomes a usable identity-anchor for off-chain services. Removes the "log into this with my Determ identity" gap that prevents Determ from serving as a SIWE-class auth substrate.

### v2.26 — On-chain key rotation

**Problem overview.** Today the only path to retire a compromised Ed25519 key is `DEREGISTER` + re-`REGISTER` under a new domain. The chain-level effect is: (i) the old `RegistryEntry` in `Chain::registrants_` transitions to `inactive_from = inclusion_height + REGISTRATION_DELAY_WINDOW`; (ii) the associated `AccountState::unlock_height` is held at `UINT64_MAX` until `inactive_from`, then set to `inactive_from + UNSTAKE_DELAY`; (iii) the operator submits a fresh `REGISTER` under a *different* `domain` string with the new pubkey, paying the stake-cost again and losing the prior domain string forever. For three deployment classes this is structurally unacceptable:

1. **Validator operators.** A validator who must rotate must surrender their committee position for at least `REGISTRATION_DELAY_WINDOW + REGISTRATION_DELAY` blocks (the inactive_from cascade plus the new-registration delay). On regional/global profiles this is minutes; on tactical it is seconds, but compounded across rotations the operator's effective uptime drops. Worse, the rotated identity is a different domain — every external reference to `validator-7.consortium` becomes `validator-7-rotated.consortium`, breaking peer config files, monitoring dashboards, and SLA contracts that name the validator by domain.

2. **Wallet users (UX).** A user who suspects key compromise must today choose between leaving the compromised key valid for the unlock-height window (during which the attacker can drain stake + transact under the identity) or losing the entire identity by re-REGISTERing. There is no path that preserves the on-chain identity while invalidating the compromised key.

3. **DSSO production posture (v2.25).** The distributed-IdP framework anchors user identity on-chain; every relying party that has ever accepted a Determ identity assertion is keyed on `sub = user_identity`. If `user_identity` is a registered domain and the user loses control of the key, the user must abandon the identity across every RP they have ever used. The DSSO becomes a one-shot identity primitive — wallet loss equals universal logout with no recovery path. This is strictly worse than the centralized IdP it replaces (every commercial IdP supports password reset and key rotation).

v2.26 introduces an in-place key-rotation primitive that preserves the on-chain identity (domain string, REGISTER history, stake, anti-spam standing, registry slot, DApp owner-link, committee-position continuity) while retiring the old key. Rotation is structurally distinct from DEREGISTER/REGISTER — no stake unlock, no domain change, no registry-position reshuffle.

**Wire-format additions.**

New `TxType::ROTATE_KEY = 11` (next free slot after `DAPP_CALL = 10` per `include/determ/chain/block.hpp:180`). Payload (binary codec):

```
[version: u8 = 1]            # forward-compat byte, reserved 0xFF
[op: u8]                     # 0 = rotate, 1 = revoke-only (no replacement)
[new_pubkey: PubKey32]       # zero for op=1
[effective_height_delta: u16] # blocks from inclusion to activation; clamped [ROTATE_MIN_DELAY, ROTATE_MAX_DELAY]
[grace_blocks: u16]          # overlap window during which old key remains accepted; clamped [0, ROTATE_GRACE_MAX]
[reason_code: u8]            # 0=routine, 1=suspected-compromise, 2=scheduled, 3=lost-device, 4..=reserved
[old_key_sig: Signature64]   # Ed25519 over (chain_id || "ROTATE_KEY" || domain || old_pubkey || new_pubkey || effective_height || grace_blocks || reason_code || nonce)
```

The outer `Transaction::sig` is the **new** key's signature over `signing_bytes()` (proving the rotator possesses the new private key, not just its public counterpart — defeats unwitting-key-substitution attacks where an attacker chooses a `new_pubkey` they cannot sign for). The embedded `old_key_sig` proves the rotator possesses the old private key. Both signatures must verify; the validator checks the old-key signature before the outer signature so a stale `old_pubkey` is rejected before crypto-on-attacker-supplied-data work.

| New constant | Default | Notes |
|---|---|---|
| `ROTATE_MIN_DELAY` | 5 blocks | Smallest activation delay — gives observers a finalisation window to detect dueling rotations |
| `ROTATE_MAX_DELAY` | 1024 blocks | Bounds the duration of "rotation is queued" state per domain |
| `ROTATE_GRACE_MAX` | 32 blocks | Caps the overlap window during which both keys validate — prevents indefinite dual-key validity |
| `ROTATE_COOLDOWN` | 256 blocks | Minimum gap between successive rotations on the same domain — bounds griefing-via-rotation-storms |
| `ROTATE_PENDING_CAP` | 1 per domain | At most one rotation queued at any time per domain — second `ROTATE_KEY` against a pending domain rejects unless `op=1` (revoke) |

All five constants live in `include/determ/chain/params.hpp` mirrored from `GenesisConfig` (same pattern as `merge_threshold_blocks`, `REGISTRATION_DELAY_WINDOW`). Genesis-pinned so all nodes agree on rotation policy.

**Apply-path integration.**

Functions extended (no rewrites):

- `BlockValidator::validate_tx` (src/node/validator.cpp): for `TxType::ROTATE_KEY` rejects if (i) the domain is not in `Chain::registrants_` or is past `inactive_from`; (ii) `old_pubkey` (derived implicit from registry lookup, not on the wire) does not match the `RegistryEntry::ed_pub`; (iii) the embedded `old_key_sig` fails verification; (iv) a pending rotation already exists for this domain (see `pending_rotations_` below) and the current tx is not a `revoke` against that pending entry; (v) the cooldown window since the last applied rotation has not elapsed; (vi) `effective_height_delta` or `grace_blocks` are out of clamp range. Validation runs against the validator's `tentative_chain` snapshot exactly like every other validator-gated tx — the rotation predicate is deterministic against finalised state.

- `Chain::apply_transactions` (src/chain/chain.cpp): on accept, queues a `PendingRotation` entry rather than immediately mutating `RegistryEntry::ed_pub`:

```cpp
struct PendingRotation {
    PubKey   new_pubkey{};
    uint64_t effective_height{0};
    uint64_t grace_until{0};    // effective_height + grace_blocks
    uint8_t  op{0};             // 0 = rotate, 1 = revoke
    uint8_t  reason_code{0};
    uint64_t enqueued_at{0};
    uint64_t last_rotation_height{0}; // for cooldown
};
std::map<std::string /*domain*/, PendingRotation> pending_rotations_;
```

This deferred-apply pattern matches the existing `DAPP_GRACE_BLOCKS` and `REGISTRATION_DELAY_WINDOW` machinery — the on-chain effect is deterministic from current state but the **pointer flip** in `RegistryEntry::ed_pub` happens at the activation block, not the inclusion block.

- `Chain::on_block_apply_end` (the per-block tick that already handles `inactive_from` cascades and `merge_state_` finalisation): walks `pending_rotations_`. For every entry whose `effective_height == current_height`, flips `registrants_[domain].ed_pub = entry.new_pubkey` (for op=0) or marks the entry `inactive_from = current_height + 1` (for op=1 revoke). For every entry whose `grace_until == current_height`, removes the old-key dual-validity flag (see validator dual-window check below). Walking is amortised O(pending) per block; cap of 1 pending per domain × `registrants_.size()` keeps this bounded.

- `BlockValidator::validate_tx` dual-window check: between `effective_height` and `grace_until`, **both** the old key (still in `RegistryEntry::ed_pub` pre-flip, or `PendingRotation::old_pubkey` post-flip via a small `recent_rotations_` ringbuffer) and the new key validate outgoing txs from this domain. This closes the in-flight-signatures gap — a tx signed by the soon-to-be-retired key at block H lands in a block at H+3, with effective_height=H+5, and validates because the dual window is still open. After `grace_until`, only the new key validates.

- `Chain::serialize_state` / `restore_from_snapshot`: `pending_rotations_` + `recent_rotations_` ringbuffer added to the snapshot tail. New state-root namespace `o:` for "operator rotation" (lookup key: domain → serialised PendingRotation) contributes to state_root via the existing leaf-builder pattern (mirrors the v2.15 `s:` namespace addition for multi-sig policies).

- `compute_block_digest` (the signing-bytes builder): no change. ROTATE_KEY txs are ordinary `Transaction` records and ride through the existing union-tx-root + Phase-2 reveal path unmodified.

**Composition with multi-sig (v2.15).** When `multisig_policies_[domain]` exists for the rotating domain, ROTATE_KEY requires `aux_sigs` meeting the policy's threshold M-of-N — exactly per the v2.15 cross-reference. Practically: the validator gate at `validate_tx` checks `multisig_policies_[tx.from]` BEFORE running the old-key-sig check; if present and the policy threshold is not met by `aux_sigs`, reject. The `old_key_sig` embedded field then becomes one of the M required signatures (the policy's primary slot, which holds the REGISTER key). This wiring means v2.26 ships v2.15-aware from day one — there is no transient window where multi-sig accounts have an un-gated rotation path.

**Effective-height race-window timeline.** A worked example illustrates how the dual-window and grace_blocks fields interact, using the default `ROTATE_MIN_DELAY=5` and a chosen `grace_blocks=3`:

```
block H        : ROTATE_KEY included in block. pending_rotations_[domain] = { new_pubkey, effective=H+5, grace_until=H+8 }
blocks H+1..4  : Old key still authoritative. New key NOT yet valid. Anyone signing with new key is rejected.
                 In-flight txs already signed by the old key continue to be accepted normally.
block H+5      : Pointer flip in on_block_apply_end. registrants_[domain].ed_pub = new_pubkey.
                 Dual-validity window opens: both old and new key signatures validate.
blocks H+6..7  : Dual-validity. New txs SHOULD sign with new key; old in-flight txs still finalise.
block H+8      : grace_until reached. on_block_apply_end clears recent_rotations_[domain].
                 From H+8 onward, only new_pubkey validates. Old key is dead.
```

The dual-validity window exists to prevent in-flight tx rejection (txs signed at H+4, propagated through gossip, landing in block H+6). For `reason_code=1` (compromised key), operators set `grace_blocks=0` — the window collapses to a single block and the old key is dead immediately at H+5 effective. The trade-off: in-flight legitimate txs in that block die with the attacker's potential txs; operator accepts this for compromise scenarios.

**Genesis-mode bootstrap considerations.** Genesis-pinned validators (the K bootstrap validators encoded in `GenesisConfig::genesis_validators`) are a special case for v2.26:

1. **Rotation of a genesis validator's key.** Genesis validators are listed by `(domain, ed_pub)` in the genesis schema; the chain's `Chain::Chain` constructor seeds `registrants_` from this list. A rotation of a genesis validator's key flips the entry in `registrants_` per the normal apply path — the genesis schema becomes stale for fast-sync verification of the rotated validator's signature on early blocks. Resolution: fast-sync verifies signatures against `RegistryEntry::ed_pub` at the *target* block, not the genesis-pinned value, via the state-root namespace. Rotated genesis validators continue to sign blocks under their current key; the genesis schema's `ed_pub` is the *initial* value, not the eternal one.

2. **Rotation cooldown vs genesis.** A genesis validator at block 0 with cooldown=256 cannot rotate until block 256. This is intentional — the initial network must reach steady state before any genesis validator can rotate. Operators wishing to immediately rotate a genesis validator (perhaps because the genesis key was generated insecurely) must wait the cooldown, or update the genesis file pre-launch (the recommended path).

3. **All-genesis-validators-rotate scenario.** No safety concern; the K-of-K mutual-distrust posture is preserved at every block because each rotation is gated by its own old-key-sig + outer new-key-sig. The chain remains operational throughout; observers' static views of "who controls this validator slot" update at each rotation's effective height.

**Composition with v2.10 threshold randomness (DKG shares).** Validators in the committee hold per-epoch FROST-Ed25519 shares. A ROTATE_KEY on a *validator* domain has implications beyond the registry entry:

| Concern | v2.26 resolution |
|---|---|
| Active-epoch share continuity | The current epoch's DKG share is bound to the old key (the share-distribution ciphertext was encrypted to `old_pubkey`). Rotation does NOT re-derive the active share — the validator continues to use the old share until the next epoch DKG. The validator's identity in the FROST signing is the share, not the registry pubkey directly; rotation does not break in-epoch signing. |
| Next-epoch participation | At the next epoch boundary, the DKG ceremony's share-distribution targets `new_pubkey` (looked up from the now-flipped `RegistryEntry::ed_pub`). The validator participates in the next epoch under the new key with no special handling. |
| Cross-epoch rotation race | A rotation queued with `effective_height` straddling an epoch boundary (rotation activates mid-DKG) is rejected at validate-time: `effective_height < next_epoch_start || effective_height > next_epoch_start + EPOCH_LENGTH/4`. This guard widens the no-rotate window around DKG ceremonies. |
| Compromise during epoch | A validator whose old key is compromised and who rotates mid-epoch retains the compromised share for the rest of the epoch — but the share alone is useless without a quorum of other shares (the t-of-K threshold). The attacker's compromised share contributes to randomness only if they also gather t-1 other compromised shares, which is the standard t-of-K assumption. v2.26 does not weaken or strengthen this; it preserves the property. |

**Threat model.**

| Attack | v2.26 defense | New surface introduced |
|---|---|---|
| **Stolen-key drain.** Attacker exfiltrates a validator's signing key during a maintenance window. Without rotation, the operator must DEREGISTER (loses committee position) and re-REGISTER (pays stake again, loses domain string). | Operator submits ROTATE_KEY with `reason_code=1` from a backup keyfile or hardware wallet. Effective at `H + 5` (`ROTATE_MIN_DELAY`). Attacker has at most 5 blocks of post-rotation-issuance window before the new key takes effect; with grace=0 (operator preference for compromised-key case), the old key is dead at `H+5` exactly. Domain continuity preserved; stake stays staked; committee position retained. | The 5-block window (or the grace overlap if larger) is the exposure interval; smaller `ROTATE_MIN_DELAY` would shrink this but at the cost of finalisation race risk. |
| **Unwitting-key-substitution.** Attacker submits a ROTATE_KEY against a target domain, claiming a `new_pubkey` they don't actually own (perhaps a key whose private half they know is held by a victim — to redirect future txs through that victim's signing surface). | Outer `Transaction::sig` is the new key's signature over `signing_bytes()`. An attacker without the new private key cannot produce this signature; tx rejects at outer-sig verify. Standard PoP (proof-of-possession) pattern. | None — the dual-signature requirement is intrinsic. |
| **Rotation-replay across forks.** Attacker captures a valid ROTATE_KEY from a testnet or sibling chain and replays on production. | `old_key_sig` is over `chain_id || "ROTATE_KEY" || domain || ...`; chain_id binding rejects cross-chain replay (same primitive as ordinary tx replay defense per S-002 closure). | None. |
| **Rotation-griefing storm.** Attacker who has briefly compromised a key (perhaps via a stolen-but-not-yet-detected leak) rotates the domain to a key they control, then rotates again (and again) to make every observer's cache thrash. Or: legitimate-but-malicious operator rotates 1000× to bloat state. | `ROTATE_COOLDOWN = 256` blocks between successive rotations on the same domain. `ROTATE_PENDING_CAP = 1` rejects a second queued rotation. State-root and snapshot bytes for `pending_rotations_` are bounded by `registrants_.size()` (no unbounded growth via rotation history beyond the tracked ringbuffer). | Cooldown can itself be weaponised: a legitimate operator who is rotating after a compromise cannot then re-rotate within 256 blocks if they discover the new key is also compromised. Defense: ROTATE_KEY with `op=1` (revoke-only, no replacement) is exempt from cooldown — gives the operator an emergency-kill-switch path that doesn't require choosing a new key. After revoke, the domain enters `inactive_from = current_height + 1` and the operator re-REGISTERs cleanly. This is strictly worse than rotation (loses continuity) but better than running with a known-compromised key. |
| **Validator-committee disruption.** Rotation of a sitting committee member's key mid-block could break ongoing Phase-2 signatures or Phase-1 commits if the gossip layer caches keys. | Apply-path defers the pointer flip to `effective_height` (≥ `current_height + ROTATE_MIN_DELAY = 5`). Phase-2 reveals for the current block are already in flight; they reference the old key, and the old key is still authoritative for ≥ 5 more blocks. Cross-epoch-DKG races are blocked by the `effective_height` clamp above. | None — the deferred-apply pattern is structurally race-free. |
| **DSSO identity-takeover.** Attacker observes a user's signed-assertion token at some RP, then later compromises the user's key. Without rotation, attacker has indefinite identity control. | User rotates with `reason_code=1` at any RP that supports v2.26-aware re-auth. RPs that consume v2.25 assertions can check `assertion.iat < domain.last_rotation_height` and reject pre-rotation assertions (RP-side policy; chain provides the `last_rotation_height` via the existing `state_proof` RPC reading `pending_rotations_` history). RP-side enforcement; the chain provides the timestamp + verification primitives. | RP-side complexity (must track last-rotation-height per identity). Documented as the DSSO production-deployment guide; not a chain protocol concern. |
| **Rotation-as-deplatforming.** A coalition of attackers gains brief control of a domain's key (perhaps via wallet phishing) and rotates to a new key they control, locking out the legitimate owner. | The owner's only recourse is the `MULTISIG_POLICY` gate from v2.15 — if the account is multi-sig, the rotation requires M signatures and the attacker is stopped at the policy gate. For single-key accounts, the rotation completes and the legitimate owner is locked out. Defense is **operational**: v2.26 ships with a strong recommendation to enable multi-sig on any account of business or DSSO value. This is documented in `docs/V2-DESIGN.md` cross-references + a CLI warning when `determ rotate-key` is invoked on a single-sig account. | The recommendation is advisory; the chain does not forbid single-sig rotation (forbidding would block legitimate solo operators). |
| **Compromised-but-still-signing race.** Attacker has the old key; legitimate owner submits ROTATE_KEY; attacker races to submit a competing tx (drain stake, transfer funds) before `effective_height`. | The dual-window check makes both keys valid during `[effective_height, grace_until]` for incoming validation, but the rotation itself enters `pending_rotations_` at the **inclusion** block, not the effective block. Operator can submit a ROTATE_KEY with `grace_blocks=0` and `op=1` (revoke) immediately after a normal rotation if they detect attacker activity during the 5-block window. This is the second-rotate-via-revoke escape valve mentioned above. | The 5-block exposure interval remains; smaller is at the cost of network propagation safety. |

**Effort table.**

| Sub-component | Effort |
|---|---|
| `TxType::ROTATE_KEY = 11` enum slot + binary codec (`block.hpp`/`block.cpp`) | 0.5 day |
| Validator gate (`validator.cpp::validate_rotate_key`) — old-sig + new-sig PoP, cooldown, pending-cap, clamp ranges, multisig threshold | 1 day |
| `PendingRotation` struct + `pending_rotations_` field + cooldown ringbuffer | 0.5 day |
| Apply-path (`chain.cpp::apply_rotate_key` + deferred pointer flip in `on_block_apply_end`) | 1 day |
| Dual-window validator check (both keys accepted during grace) + ringbuffer of `recent_rotations_` | 0.5 day |
| Snapshot serialise/restore + new `o:` state-root namespace + leaf-builder integration | 1 day |
| Wallet CLI: `determ wallet rotate-key --from <domain> --new-key <path> [--grace <N>] [--reason <code>] [--op revoke]` + co-sign verb for multi-sig accounts | 1 day |
| Multi-sig (v2.15) gating wiring + tests | 0.5 day |
| v2.10 cross-epoch DKG guard (effective_height-vs-epoch clamp) | 0.5 day |
| Regression tests: happy-path rotation, PoP-missing reject, cooldown reject, pending-cap reject, revoke-op path, multi-sig threshold gate, dual-window in-flight tx, cross-epoch DKG guard, snapshot/restore round-trip, state-root namespace round-trip | 2 days |
| Documentation refresh (PROTOCOL.md tx-type table + apply-path §, SECURITY.md threat-model entry, README.md §10.x rotation flow, V2-DAPP-DESIGN.md DSSO production-deployment guide) | 1 day |

**Total: ~9-10 days focused work** (revised from the prior "~1 week" estimate after spelling out the dual-window + cooldown + v2.10/v2.15 composition + state-root integration).

**Dependencies.**

- **v2.15 (HD + multi-sig)** — coupled. v2.26 ships the multi-sig-gated rotation wiring from day one (avoids the transient un-gated window). v2.15 must land first or co-land; recommended order in Phase A (A.11) followed by Phase C (C.1) reflects this.
- **v2.10 (threshold randomness with DKG)** — soft dependency for validator-domain rotations. v2.26 ships without v2.10 (the cross-epoch guard becomes a no-op when DKG is not active); once v2.10 lands, the guard activates automatically. No flag-day required.
- **v2.1 (state Merkle root)** — ✅ shipped. New `o:` namespace integrates via the existing leaf-builder pattern.
- **v2.25 (DSSO)** — v2.26 is a **precondition** for v2.25's production posture per Phase C.1 sequencing. v2.25 itself does not need v2.26 to ship as a research-mode primitive, but no real RP will accept DSSO assertions without a rotation primitive in the chain.
- **v2.4 (atomic_scope)** — ✅ shipped. The `pending_rotations_` insert and the deferred pointer flip both ride inside `atomic_scope` so block-level rollback is clean.

**Cross-references.**

- `include/determ/chain/block.hpp:25` — `TxType::REGISTER = 1` and `DEREGISTER = 2`; ROTATE_KEY occupies `= 11` (next free after `DAPP_CALL = 10`).
- `include/determ/chain/chain.hpp:32` — `struct RegistryEntry { PubKey ed_pub; ... }`; the `ed_pub` field is the pointer flipped at activation.
- `include/determ/chain/chain.hpp:542` — `std::map<std::string, RegistryEntry> registrants_`; gains a sibling `std::map<std::string, PendingRotation> pending_rotations_`.
- v2.15 (this document) — multi-sig policy gates ROTATE_KEY when present.
- v2.10 (this document) — cross-epoch DKG guard composes with the rotation effective-height clamp.
- v2.25 (this document) — DSSO production posture depends on this primitive.
- SECURITY.md §S-004 (encrypted keyfiles) — the operational rotation flow assumes the new key is generated and protected via the v2.17 envelope; v2.26 does not loosen that assumption.

**Open questions.**

1. **Domain history for DSSO RPs.** Should the chain expose a per-domain rotation history via a dedicated RPC (`rotation_history domain=X`) or rely on RPs walking the block index? Recommended: a lightweight RPC backed by a per-domain head-of-history pointer in `RegistryEntry::last_rotation_height` (4 bytes added). Avoids RP-side block scanning at the cost of an extra registry field.
2. **Cooldown bypass for multi-sig accounts.** For an M-of-N account where the multi-sig threshold was already met, should `ROTATE_COOLDOWN` be lifted (the multi-sig itself proves the operator's intent, removing the griefing concern)? Recommended: no, keep cooldown — multi-sig prevents single-signer griefing but does not prevent threshold-collusion griefing.
3. **REGISTER pubkey vs DAPP_REGISTER service_pubkey rotation.** v2.26 rotates the REGISTER pubkey only. DApp `service_pubkey` (per `DAppEntry::service_pubkey` at `include/determ/chain/chain.hpp:57`) is already rotatable via a fresh `DAPP_REGISTER op=0` from the domain owner — no new primitive needed. Document the asymmetry in the V2-DAPP-DESIGN.md DSSO production-deployment guide.
4. **Hardware-wallet support for ROTATE_KEY.** Ledger/Trezor sign arbitrary Ed25519 over hashed messages; the embedded `old_key_sig` is a standard Ed25519 sign over a SHA-256-hashed envelope. Wallet UX shows "Rotate operator key for domain X to new key Y" before signing. No new device firmware required; out of v2.26's critical path.
5. **Recovery from total key loss (no old key available).** v2.26 cannot help — the embedded `old_key_sig` is unforgeable, by design. Recovery from total loss requires either (a) v2.14 OPAQUE wallet recovery (per-account recovery envelope), or (b) v2.15 multi-sig (other signers can rotate), or (c) v2.25 DSSO recovery flow (committee-assisted re-bind). v2.26 makes recovery *possible* via these paths; it does not itself recover from total loss.

**Closes.** Identity continuity for validator operators, wallet users, and DSSO identities. Unblocks v2.25's production posture per Phase C.1 sequencing. The single-key-loss = identity-loss catastrophe becomes single-key-loss = rotation-event, preserving the on-chain anchor that every downstream system depends on.

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
| Compliance / audit | None | v2.24 view-key disclosure |
| Fair ordering | None | Deferred (research; v2.13 noted) |
| DApp surface | None today | Themes 7 + v2.22/23/24 give the substrate |
| Federated authentication / DSSO | None today | Theme 9 (v2.25 + v2.26): K-of-K committee as mutual-distrust IdP with T-OPAQUE |

Total work to close: **~13-19 months focused engineering beyond what's already in V2-DESIGN.md** (themes 1-7 land in ~12-16 weeks per existing estimate; theme 8 + theme 9 + DApp ecosystem maturation add ~7-13 more months).

### What this is NOT

- Not a contract VM. DApps run off-chain on operator nodes (Theme 7 substrate); Determ provides ordered authenticated message delivery + identity + payments + integrity.
- Not stateless validation. Determ's state is small enough that full-node operation is feasible on commodity hardware.
- Not a DA layer. Not a rollup substrate. Not a generalized computation platform.
- Not Ethereum-tier completeness. Different protocol family.

### Why this is achievable

Each theme is independently estimable, has a clear deliverable, and composes with the others. There's no research-grade unknown remaining (fair ordering and Ethereum-bridge SNARK are explicitly deferred). The ~12-18 month path is engineering, not research.

The result is **a payment + identity protocol that's complete enough for any commercial use case** (privacy, audit, cross-chain, quantum-resistance) without expanding into territory better-served by other chains.

### Composing with an external zk-VM — the canonical "God Stack" pattern

Szabo's "God Protocol" requires three properties: **perfect execution** (deterministic ordering + finality), **perfect computation** (arbitrary contracts), and **perfect privacy** (mathematically hidden inputs). Determ explicitly does not pursue computation + privacy *on-chain* — it deliberately stays in its lane. But it composes cleanly with an external **zero-knowledge VM (zk-VM) as a Layer 2** to deliver all three properties as a stack.

**Architecture:**

| Layer | Role | Provides |
|---|---|---|
| **L2 — Privacy & Computation engine** (external zk-VM, e.g. RISC Zero / SP1 / zkSync / custom) | Arbitrary smart-contract execution. ZK proofs hide inputs. Batches many user transactions, produces a single succinct proof of correct execution + state transition. | Perfect computation + perfect privacy |
| **L1 — Determ v2 (Unbreakable Judge)** | The L2 submits its batch's final state root + ZK validity proof reference as a single small commitment on Determ. Determ's K-of-K committee signs the block including that commitment; cross-shard receipts route credits/debits if the L2 spans multiple L1 shards. | Perfect execution (deterministic K-of-K finality, fork-free, sub-second on tactical/web profile) |

**How the commitment lands on Determ:**

- L2 finalizes a batch → computes `(prev_state_root, new_state_root, batch_id, proof_ref)` → produces a 32-byte commitment hash.
- L2 operator submits a TRANSFER (or DAPP_CALL, depending on L2 economics) with the commitment in the **A4 TRANSFER payload** (≤128 bytes; commitment + small metadata fits comfortably).
- For DApp-aware L2s: use **DAPP_CALL** routing to a registered "L2 settlement" DApp identity (Theme 7 substrate). Allows DApp-side per-batch processing + on-chain audit trail.
- Determ K-of-K committee signs the L1 block — commitment now has L1's unconditional safety claim (§10.4).
- L2 fast-sync nodes verify the L2's claimed state by checking the L1 commitment (via v2.2 `state_proof` RPC + v2.1 Merkle state root). No need to re-execute the batch.

**Why Determ specifically fits the role of L1 judge:**

| Property | Determ delivers | Vs. alternatives |
|---|---|---|
| Deterministic finality | K-of-K signatures, no probabilistic confirmation | Better than PoW (probabilistic) and most BFT chains (slashing-conditional) |
| Sub-second finality on tactical profile (40 ms blocks) | Yes, with regional sharding | Better than Ethereum (~13s), Cosmos (~6s), Bitcoin (~10 min) |
| Censorship resistance | K-of-K mutual distrust — censorship requires ALL K to collude | Better than f<N/3 BFT chains |
| Small commitment fits on-chain | A4 128-byte TRANSFER payload + v2.18/v2.19 DAPP_CALL routing | Comparable |
| Audit trail / immutability | State Merkle root (v2.1) + light-client proofs (v2.2) — anyone can verify | Standard for modern chains |
| Cross-shard L2 batches | EXTENDED sharding + cross-shard receipts (B3) — L2 can span L1 shards | Better than monolithic L1s for horizontally-scaled L2s |
| Post-quantum future-proof | v2.8 Dilithium migration roadmap | Determ-specific advantage at PQC migration time |

**What changes about Determ to enable this — nothing.** The existing primitives (A4 TRANSFER payload, v2.18 DAPP_REGISTER, v2.19 DAPP_CALL, v2.1 state Merkle root, v2.2 state_proof RPC) are exactly the substrate a zk-VM L2 needs. Determ's "stay in its lane" framing means we don't build the zk-VM — but the protocol provides the perfect anchor for any L2 ecosystem that wants to build one against it.

**Cross-reference:**

- **TRANSFER payload (A4)** — 128 bytes is enough for `(prev_root: 32B, new_root: 32B, batch_id: 32B, proof_metadata: ~32B)`. Roomy.
- **DAPP_REGISTER (v2.18)** — register the L2's settlement endpoint as a DApp; users discover the L2 via on-chain registry.
- **DAPP_CALL (v2.19)** — fee-bearing settlement-call routing; the L2 operator pays Determ committee fees for each batch settlement.
- **State Merkle root (v2.1) + state_proof RPC (v2.2)** — L2 light clients verify the L1 commitment without trusting any RPC provider.
- **Direct-to-DApp pattern (V2-DAPP-DESIGN.md §10)** — L2 users can submit batch-precursor messages directly to the L2 sequencer off-chain, with on-chain settlement following.
- **EXTENDED sharding** — L2 settlements can use different L1 shards for different L2 tenants or regions.

**What a deploying operator must understand:**

- The L2 is operator-controlled in the sense that any zk-VM operator can submit commitments. The chain doesn't validate the L2's claimed state transition beyond checking the operator's signature on the on-chain tx. Trust in the L2's correctness comes from the ZK proof itself, which is L2-side.
- Determ provides ordering + censorship-resistance + immutable audit trail; it does NOT provide L2 correctness verification. That's the ZK proof's job.
- The L2 operator + Determ's K-of-K committee together form a meaningful trust boundary: L2 operator vouches for state transition (via ZK proof); Determ vouches for inclusion order + finality (via K-of-K). Neither can corrupt the other's domain without breaking their respective primitives.

**Status:** This is a deployment pattern, **not a Determ protocol feature**. No code change is required on Determ's side to support it. A reference L2-side zk-VM operator can be built today on the existing substrate (Theme 7 + A4 + v2.1/v2.2); the protocol provides the L1 judge role unchanged. Reference implementation is community/ecosystem work, not in Determ's core scope.

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
| S-010 (sybil) | operator stake-pricing formula + DOMAIN_INCLUSION alternative | ✅ shipped (SECURITY.md §S-010 calculator) |
| S-011 (abort-claim cartel) | S-010 stake floor + FA6 equivocation slashing bound | ✅ shipped (no code change needed; closed by economic argument + existing slashing) |
| S-012 (snapshot trust) | v2.1 state_root + v2.3 snapshot verification | ✅ shipped |
| S-030 D1 (validate-apply) | v2.1 state_root indirect closure (via signing_bytes + apply-time check) | ✅ effective |
| S-030 D2 (block_digest) | v2.1 state_root apply-layer closure (shipped) + v2.7 F2 consensus-layer closure (spec resolved in F2-SPEC.md; implementation ~3-4d) | 🟠 partial (apply-layer ✅; consensus-layer awaits F2 implementation) |
| S-031 (global mutex) | v2.4 A9 + v2.5 + v2.6 + async chain.save | ✅ shipped (all 6 layers) |
| S-032 (registry rebuild) | v2.5 incremental cache | ✅ shipped |
| S-033 (no state commitment) | v2.1 Merkle root + Block.state_root | ✅ shipped |
| S-036 (witness-window) | v2.11 beacon-side auto-detect | ⏳ open |

**Findings closure status:** 27 fully closed in-session (5 Critical + 13 High + 1 Medium [S-018] + 8 Low/Op — see SECURITY.md §1) + 1 partially closed (S-030 D2 via S-033 + S-038 apply-layer; v2.7 F2 closes at consensus layer) + 1 still partial Medium (S-016 overlaps with v2.7 F2 scope) + 1 partial Low/Op (S-036 EXTENDED-mode-only — v2.11 closes). Zero open Critical, zero open High, zero open Medium. All open High findings closed in-session via S-010 stake-pricing formula + S-011 economic-bound argument; final open Medium (S-018 JSON schema) closed via `json_require<T>` / `json_require_hex` helpers in `include/determ/util/json_validate.hpp`. The "12 of 24 close in v2" original target has been substantially overshot in-session.

---

## Total v2 effort

Layer-level estimates with shipped vs remaining split:

| Layer | Work | Total estimate | Shipped (in-tree) | Remaining |
|---|---|---|---|---|
| Trust minimization (v2.1–v2.3) | State Merkle root + light clients + trustless fast sync | 4-6 weeks | ✅ all 3 shipped (foundation; full header-only-sync flow still pending) | ~1 week (light-client header sync flow) |
| Scale & concurrency (v2.4–v2.6) | A9 overlay, registry cache, gossip-out-of-lock | 2 weeks | ✅ all 3 shipped (A9 Phase 1-2D, registry cache, gossip-out-of-lock) | 0 |
| Cryptographic hardening (v2.7–v2.8) | F2 view reconciliation, Dilithium migration | 2-3 weeks | F2 spec'd in F2-SPEC.md, code not started; Dilithium not started | 2-3 weeks |
| Liveness (v2.10, v2.11) | Threshold randomness aggregation 🔥 active (with DKG infrastructure per v2.10-DKG-SPEC.md), beacon auto-detect | ~4 weeks | 0 (v2.10 promoted to active A11) | ~4 weeks |
| Composability (v2.12) | Cross-shard atomic primitives | 1 week | 0 (foundation: A9 Phase 2D atomic_scope shipped; cross-shard 2PC pending) | 1 week |
| Wallet/operator (v2.14–v2.17) | OPAQUE port, HD derivation, RPC auth, encrypted keyfiles | 2 weeks | ✅ v2.16 + v2.17 shipped; v2.14 + v2.15 not started | ~1 week |
| Application layer (v2.18–v2.20) | DApp substrate (registry + call + RPC + polling) | (was implicit, now itemized) ~1 week | ✅ v2.18 + v2.19 shipped, v2.20 polling shipped (streaming pending) | ~3 days for streaming |
| **Privacy & interop (v2.22–v2.24)** | **Confidential tx + cross-chain bridge + audit hooks** | **3-5 months** | 0 (v2.22 spec resolved per `v2.22-PRIVACY-SPEC.md`; v2.24 scope reduced to ~1-2 weeks; curve25519-family cascade from v2.10 — libsodium already vendored) | 3-5 months |

**Themes 1-7 status:** ~6 weeks of work remaining (vs 12-16 weeks at start of session). Major absorbed: v2.1, v2.2 (foundation), v2.3, v2.4 (full A9), v2.5, v2.6, v2.16, v2.17, v2.18, v2.19, v2.20 polling.

**Total to complete v2 with Theme 8:** ~4-6 months from current state (down from 6-9 months estimate at the start of v2 work).

---

## Recommended sequencing — v2 + Theme 9

Canonical execution order for the remaining work. Sequencing reflects critical-path dependencies (precondition before consumer), risk shape (highest-uncertainty items earliest within each phase), and commercial priority (privacy unblocks the largest deployment class).

### Phase 0 — Deterministic-Simulation Framework + C99 Cryptographic Stack (~17-19 weeks, before Phase A)

Phase 0 has two parallel tracks:

**Track 1: DSF (~3-4 weeks).** Deterministic-simulation framework — virtual clock + virtual network + scriptable Byzantine actors + property checkers + 30-scenario initial set. Promoted ahead of Phase A (previously listed as a Phase D prerequisite). Provides deterministic Byzantine-bug coverage for every Phase A through D item as it lands. Subsumes A10 NH1 Stage 1 streams 1 + 2 (~3 months of work eliminated). Per `docs/proofs/DSF-SPEC.md`.

**Track 2: C99 cryptographic stack (~17-19 weeks).** Full libsodium replacement with vendored independent C99 primitives organized into modular sub-libraries. Per `docs/proofs/CRYPTO-C99-SPEC.md`. Delivers: SHA-256/SHA-512 (NIST), Ed25519 (Bernstein ref10), X25519 (curve25519-donna), ChaCha20-Poly1305 + XChaCha20 (RFC 8439), AES-256-GCM (NIST), Argon2id (P-H-C reference), secp256k1 + libsecp256k1-zkp (Bitcoin Core), FROST-Ed25519 (implemented from RFC 9591), OPRF on secp256k1 (voprf draft + RFC 9380). ristretto255 eliminated entirely. Three curves: Ed25519, X25519, secp256k1. Two underlying mathematical families (curve25519, secp256k1). Modular structure: `src/crypto/<primitive>/` with unified C99 API in `include/determ/crypto.h` + ergonomic C++ wrapper in `include/determ/crypto.hpp`.

Track 1 and Track 2 are parallel (different engineering skill sets — distributed-systems + cryptographic engineering). Both must complete before Phase A starts. Combined wall-clock = max(Track 1, Track 2) = **~17-19 weeks**.

If only one engineer is available, Track 1 (DSF) ships first as Phase A precondition; Track 2 (C99 crypto) defers to a later trigger event (NH1 Stage 2, NH4 FIPS commitment, or audit finding). The C99 crypto track is optional but recommended for libsodium-free posture + NH1/NH2/NH4 readiness from today.

**Status: spec resolved** in `docs/proofs/DSF-SPEC.md`. Virtual clock + virtual network + scriptable Byzantine actors + property checkers + 30-scenario initial set. ~3-4 weeks to ship from spec-review acceptance.

**Why before Phase A:** Phase A items most vulnerable to subtle Byzantine bugs (v2.7 F2 gossip-async, v2.10 DKG complaint-phase, v2.12 cross-shard 2PC races) are exactly what DSF excels at probing. The prior v2.7 F2 naive-fix attempt that broke equivocation-slashing tests under gossip-async would have been caught by DSF before shipping. Ship DSF first; ship every Phase A through D item with DSF coverage built in.

| Order | Item | Effort | Notes |
|---|---|---|---|
| 0.1 | Virtual-clock abstraction (`time::Clock`) | 2-3 days | Thread through Node/Validator/Producer/RPC/Gossip; mechanical refactor; production behavior unchanged |
| 0.2 | Virtual-network abstraction (`net::Transport`) | 1 week | Wrap asio in `AsioTransport`; new `VirtualTransport` with per-link drop/latency/partition control |
| 0.3 | Scenario DSL + simulator core | 3-5 days | C++ scenario classes; `Scenario::setup/run/check` lifecycle |
| 0.4 | Property checker framework | 3-5 days | FA1, A1, FA6, FA7 invariants run after every step |
| 0.5 | Random scenario generator | 3-5 days | Seeded variants; reproducibility test |
| 0.6 | Replay tooling | 2-3 days | `determ-dsf run --scenario NAME --seed HEX` |
| 0.7 | Initial 30-scenario set | 1 week | Selective-abort, equivocation, partition, cross-shard, DKG, F2, BFT escalation |
| 0.8 | CI integration + docs | 2-3 days | Add to `tools/run_all.sh`; write `docs/DSF.md` |

**Phase-0 exit criterion:** DSF running against current production code with the 30 initial scenarios; replay tooling functional; CI integration green.

### Phase A — v2-completing sprint (~8-9 weeks sequential)

Single contiguous sprint that lands v2 Themes 1-7 fully. Items inside the phase can parallelize freely; the phase boundary is the synchronization point. Revised from prior ~6-week estimate after v2.10 DKG spec (Option C) raised A.4 from ~1 week to ~3-4 weeks — the increase reflects the genuine cost of trustless per-epoch DKG with PSS refresh, which is the cost of delivering v2.10's threat-model property under mutual distrust.

Every Phase A item ships with DSF-tested behavior (Phase 0 prerequisite).

| Order | Item | Effort | Why this order |
|---|---|---|---|
| A.1 | C3 gossip-out-of-lock, C6 BFT threshold bump | ~1.5 days | Smallest items; clears C-track to "all shipped." |
| A.2 | **v2.7 F2 view reconciliation** | ~3-4 days | **PROMOTED from prior A.8.** Spec resolved (F2-SPEC.md, per-field rules per Option D); awaiting pre-implementation review of the 5 decisions called out in F2-SPEC.md §6. Closes S-030 D2 at consensus layer (currently partial closure via S-033 apply-layer). Small, high-value, fully-spec'd → land early to derisk downstream items that compose with the consensus-round wire format (v2.10 partial-sig integration, v2.22 confidential tx commitment binding). Requires DSF coverage (Phase 0); prior naive F2 attempt failed under gossip-async — DSF reproduces that pattern deterministically. |
| A.3 | R5 `tools/test_regional_shards.sh` + R6 README §17.6 + E1 NEF lottery rewrite + E9 `genesis_info` RPC | ~1 week | Bundled trivial cleanups (R-track verification gap + E1 code reconciliation + E9 follow-on). Independent of all other Phase A work. |
| A.4 | A11 / v2.10 threshold randomness aggregation (incl. DKG infrastructure) | ~3 weeks | **Theme-9 precondition + shared foundation for v2.22/v2.25.** DKG spec resolved per Option C in `docs/proofs/v2.10-DKG-SPEC.md`; cost reflects epoch-boundary trustless DKG + PSS refresh + FROST-Ed25519 on curve25519 family (libsodium already vendored). Largest single item in Phase A; land here (not earlier) so senior-engineer focus is uninterrupted by smaller items; composes with v2.7 F2 at the consensus-round seam. |
| A.5 | A2 / v2.14 OPAQUE wallet finisher | ~5-7 days | **Theme-9 precondition.** Single-server OPAQUE exercises the adapter shape T-OPAQUE will reuse. |
| A.6 | A7 randomness binding RPC + reference DApp | ~1.5 days | Unlocks fair-lottery DApp + general application-layer randomness consumption. |
| A.7 | A8 IdP-directory finisher | ~2-3 days | Builds on shipped v2.18/v2.19; light follow-on. |
| A.8 | v2.8 Dilithium PQC migration | ~1-2 weeks | Largest cryptographic surface addition; wire-format break — flag-day. |
| A.9 | v2.11 beacon-side auto-detect | ~2-3 days | Closes S-036 fully. |
| A.10 | v2.12 cross-shard 2PC | ~1 week | Builds on shipped A9 Phase 2D atomic_scope. |
| A.11 | v2.15 HD derivation + multi-sig | ~1 week | Wallet UX completer; orthogonal to consensus changes. |
| A.12 | v2.20 streaming subscription RPC | ~3 days | Final Theme-7 polish. |

**Phase-A exit criterion:** Themes 1-7 fully shipped; v2.10 + v2.14 (Theme-9 preconditions) in tree; all SECURITY.md findings closed or formally deferred.

### Phase B — Theme 8 (privacy + interop, 3-5 months, partly parallel)

Theme 8 is the largest remaining work block. Internal sequencing prioritizes the item that unblocks the largest commercial deployment class.

| Order | Item | Effort | Why this order |
|---|---|---|---|
| B.1 | v2.22 confidential transactions (per `v2.22-PRIVACY-SPEC.md`) | ~2.5-3 months | Unblocks all real-world payment use cases (B2B, payroll, retail, regulated gambling) that today need a separate privacy chain. Highest commercial leverage. Spec resolved per Option C — curve choice (curve25519 family via libsodium) cascades from v2.10. |
| B.2 (parallel with B.1) | v2.23 cross-chain bridge, Determ-to-Determ first | 1 month | Lowest-uncertainty bridge variant; uses Determ's own light-client + state_root machinery. Independent of v2.22. |
| B.3 (after B.2) | v2.23 cross-chain bridge, Cosmos IBC | 2 months | Standardized spec; deferred from B.2 to avoid blocking confidential-tx work. |
| B.4 (after B.1) | v2.24 audit / compliance hooks (per `v2.22-PRIVACY-SPEC.md` §2.Q4 + §4.6) | 1-2 weeks | **Reduced scope** post-v2.22 spec — v2.22 delivers the view-key infrastructure; v2.24 adds `audit_view_master_pk` field + `ROTATE_AUDIT_KEY` tx + reference auditor tool. Composes cleanly with v2.22's dual-mode disclosure. |

Defer indefinitely: v2.23 Bitcoin SPV bridge (2 months, low priority), v2.23 Ethereum bridge (6+ months, blocked on SNARK-of-Ethereum-light-client tooling maturity).

**Phase-B exit criterion:** Confidential payments + Determ-to-Determ + Cosmos IBC + audit hooks shipped. Determ becomes commercially deployable for regulated payment workloads.

### Phase C — Theme 9 DSSO (6-9 weeks, after preconditions land in Phase A)

Strictly sequential after Phase A. v2.26 ships first as a v2.25 prerequisite (key rotation is irrecoverable-loss mitigation for DSSO).

| Order | Item | Effort | Why this order |
|---|---|---|---|
| C.1 | v2.26 on-chain key rotation | ~1 week | Identity-continuity precondition for v2.25 production posture. |
| C.2 | v2.25 DSSO substrate — T-OPAQUE adapter | 1-2 weeks | Vendor + harden T-OPRF + T-OPAQUE library. Reuses single-server OPAQUE adapter shape from v2.14. |
| C.3 | v2.25 wallet client + committee-side share handler | ~2 weeks | Wallet side overlaps with v2.14's single-server work. |
| C.4 | v2.25 signed-assertion protocol + token format | ~1 week | JWT-compatible vs custom binary — decide at start of C.4. |
| C.5 | v2.25 reference RP DApp + integration test | ~1 week | Validates the end-to-end flow via Theme-7 DAPP_REGISTER + DAPP_CALL substrate. |
| C.6 | v2.25 spec doc + threat-model write-up | ~3-5 days | DSSO-SPEC.md, mirrors F2-SPEC.md style. |

**Phase-C exit criterion:** Determ becomes a usable federated-identity anchor for off-chain services without trust in any single Determ node.

### Phase D — Beaconless v2 architecture (~3-4 months, after Phase A/B/C ship)

The largest single architectural effort in Determ's roadmap. Removes the beacon as a special role; distributes its functions across shards via light-client mesh + replicated deployment manifest + per-shard committee log + Merkle-proof cross-shard receipts. Completes Determ's mutual-distrust posture at every architectural layer and raises horizontal-scale ceiling from ~50 to ~200-500 shards.

**Status: spec resolved per Option A** in `docs/proofs/Beaconless-v2-SPEC.md`. All 6 interlinked foundational sub-questions formally resolved (cross-shard validation architecture, trust anchor, committee continuity, cross-shard receipts, decentralized merge detection, randomness mixing). Implementation pending pre-implementation review (8-point checklist in spec §8).

**Prerequisites:**
- v2 + Theme 9 substantially shipped (Beaconless v2 builds on v2.1 state Merkle root, v2.2 light-client proofs, v2.10 FROST-Ed25519 threshold infrastructure)
- ~~Deterministic-simulation framework (S-035 Option 2)~~ — **already shipped from Phase 0** (promoted ahead of Phase A); Phase D inherits the DSF coverage built up during Phases A through C.

| Order | Item | Effort | Why this order |
|---|---|---|---|
| ~~D.0~~ | ~~DSF (S-035 Option 2)~~ | ~~3-4 weeks~~ | **Retired** — DSF shipped in Phase 0. Phase D starts directly at D.1. |
| D.1 | Light-client mesh infrastructure | 3-4 weeks | Foundational substrate; every other Beaconless v2 item builds on this. Lazy validation logic + per-source eviction. Ships with DSF coverage from Phase 0. |
| D.2 | Deployment manifest infrastructure | 2-3 weeks | Replaces beacon's trust-anchor role. K-of-K co-signing for mutations; cooldown-based default-accept prevents single-shard veto. |
| D.3 | Committee-rotation log (per shard) | 1-2 weeks | Append-only on-chain log; light-client traversal; snapshot compaction every 100 epochs. |
| D.4 | Cross-shard receipts with Merkle proofs | 2-3 weeks | Receipt format extension; source-side proof generation; receiver-side validation via light-client header. |
| D.5 | Decentralized merge-detection | 1-2 weeks | Per-shard SHARD_TIP observation + Merritt-witness affidavits. Tolerates k Byzantine shards given num_shards > k(k+1). |
| D.6 | Cross-shard randomness aggregation | 1-2 weeks | Per-epoch accumulator over threshold signatures (reuses v2.10 FROST-Ed25519). |
| D.7 | `AUTONOMOUS_SHARD` chain_role + migration | 1-2 weeks | New chain_role; per-deployment flag-day migration tooling. |
| D.8 | Tests + docs | 2 weeks | DSF-driven scenarios; integration test for 3-5 autonomous shard deployment; documentation refresh. |

**Phase-D exit criterion:** Determ deployments operate without a beacon. Mutual-distrust posture extends to every architectural layer including cross-shard coordination. Horizontal-scale ceiling raised from ~50 to ~200-500 shards via lazy validation.

### Total combined

| Phase | Window | Cumulative wall-clock |
|---|---|---|
| **Phase 0 (DSF)** | **~3-4 weeks before Phase A** | **~3-4 weeks** |
| Phase A (v2 Themes 1-7) | ~8-9 weeks | ~11-13 weeks |
| Phase B (Theme 8) | 3-5 months | ~5-7 months |
| Phase C (Theme 9) | 4-6 weeks (DKG infrastructure shared with Phase A — Theme 9 effort reduced), partially parallel with later Phase B | ~6-9 months total |
| Phase D (Beaconless v2) | **~3 months** (DSF prereq retired — already shipped in Phase 0), after Phase A/B/C | **~9-12 months total** for "Beaconless v2 complete" |

**Net savings from DSF-before-Phase-A promotion:** Outer envelope drops from ~10-13 months to ~9-12 months. Phase 0 adds ~3-4 weeks upfront, but Phase D shrinks by ~3-4 weeks (DSF retired from D.0) AND A10 NH1 Stage 1 shrinks by ~2-3 months (streams 1+2 retired post-DSF). Net: ~1 month removed from the outer envelope, plus every Phase A through D item ships with deterministic-simulation Byzantine coverage rather than integration-test-only.

Phase D is the natural "what's after v2 + Theme 9" effort. NH-track items run in parallel without gating any phase. NH1 (C99 rewrite, A10 Stage 1 entry — **reduced to streams 3+4 only after DSF promotion**, ~6 weeks instead of ~3-4 months) is a now-bounded engineering effort; NH4 (military certification) is a calendar/operator-policy track; NH5 (dynamic BFT threshold) lands at C6 in Phase A; NH6 (regulatory mapping) lands incrementally with v2.24 in Phase B.

### What is explicitly NOT in this sequencing

- **v2.13 fair ordering** — see "v2.13 fair ordering scope" below for the explicit deferral rationale.
- **v2.21+ DApp ecosystem items** — community/ecosystem track, not core protocol.
- **v3 protocol features: none planned.** After Phase D ships, the *protocol* scope is bounded — no new wire format, no new tx types, no new consensus mechanism.
- **v3 ecosystem deliverables (deferred to ecosystem timing):**
  - **Cross-deployment Federation DApp** — documented as a canonical pattern in `V2-DAPP-DESIGN.md` §14. Delivers shared identity, federated DSSO, cross-deployment audit aggregation, federation governance via the existing v2.18 / v2.19 / v2.23 / v2.25 substrate. Not on the Determ team roadmap; built by operator consortiums when a specific commercial partnership creates the need (regulated-vertical multi-jurisdiction deployments, CBDC federations, industry consortium payment rails). Estimated effort per federation: ~1.5-2 months operator-side. Multiple federation DApps can coexist with different governance / audit / identity-linking policies — the protocol doesn't pick winners.
- **v4+ candidates (out of scope; would be considered only if real deployment pressure surfaces):**
  - **Hierarchical sharding (sharding-of-sharding)** — Phase D Beaconless v2 raises the horizontal-scale ceiling to ~200-500 shards via lazy validation, exceeding every documented commercial use case. If internet-scale public deployment ever pushes past that ceiling, hierarchical sharding becomes a v4 candidate driven by real scale data. Not on the roadmap; would not be promoted speculatively.
  - **Validator portability across deployments** — would require protocol-level cross-deployment slashing economics, which break per-deployment mutual-distrust isolation. No commercial use case demands it. Would be a v4+ open question if specific deployment partnerships ever request it.

### v2.13 fair ordering — scope clarification

v2.13 is **descoped from the v2 sequencing above, but not abandoned from Determ's design space.** The distinction matters:

**Why it's not in Phase A/B/C.** Three independent reasons:
1. **Underlying problem is not load-bearing for Determ's stated scope.** Fair ordering exists to mitigate producer-level MEV (frontrunning, sandwich attacks). MEV is a real concern for DEXes and order-book applications — neither of which is a Determ-native use case. Payment + identity workloads do not exhibit the MEV-extractable patterns fair ordering targets. The cost/benefit ratio is wrong for v2.
2. **The solution is open research, not engineering.** Fair-ordering rules (Aequitas, Themis, Pompē, etc.) are active research areas with no consensus on the right primitive. Implementing v2.13 means picking a rule that may be obsolete by ship date. By contrast, every other v2 item has a known-correct mechanism; only the engineering remains.
3. **Implementation cost is multi-week on top of solving the rule.** Per-block commit-reveal on tx ordering, Phase-1 + Phase-2 binding of ordering hashes, fair-aggregation rule integration — this is consensus-layer work as heavy as v2.7 F2 or v2.10 threshold randomness, with the additional cost of solving an open-research design question first.

**Why it's not permanently out of scope.** Determ's protocol shape is compatible with adding fair ordering later as a Theme. The mechanism would extend `ContribMsg` (Phase-1) with a tx-ordering hash and `compute_block_digest` with the canonical ordering rule — a wire-format change but not a structural rearchitecture. If Determ ever serves a DEX-class workload, or if the fair-ordering research consolidates on a canonical primitive, v2.13 can be reopened.

**Reframing.** The honest position is:
- **In scope as a capability** Determ could deliver under its existing protocol shape.
- **Out of scope for v2** because the use cases that need it are not currently Determ-native and the solution is not engineering-ready.
- **Tracked indefinitely deferred** rather than rejected. Flagged for future protocol families built on Determ, or for a v3-class effort once the research consolidates.

This is the same disposition Bitcoin takes toward smart-contract execution: not "we will never do this" but "this is not what we are optimizing for in this protocol generation, and the cost of doing it now is higher than the benefit." That framing preserves both the design's narrow lane (payment + identity) and the option to expand later without breaking changes.
