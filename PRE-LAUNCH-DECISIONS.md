# v1.1 Pre-Launch Decision Register

> Working decision-support doc (not canonical). One row per open item across all four categories,
> each with what it is, why it matters, the real options, a recommendation, and a blank for your call.
> Source of truth for the underlying facts: `docs/SECURITY.md`, `docs/proofs/DECISION-LOG.md`,
> `docs/proofs/v2.22-PRIVACY-SPEC.md`, `docs/ROADMAP.md`.

**Context.** Zero open Critical/High findings. This is last-mile *decisions* and *hardening*, not firefighting.
Several items below already have a spec-recommended answer — for those the real action is **ratify + build**, not decide from scratch.

> **STATUS: CLOSED 2026-07-09.** All 17 items decided by the owner in a one-by-one review (largest-unmitigated-surface-first order). Per-item decisions are recorded in the "Your call" column and in a **Decision** line under each item body; the decided execution plan replaces the batching sketch at the end.

**At-a-glance**

| # | Item | Category | My recommendation | Your call |
|---|------|----------|-------------------|-----------|
| A1 | CT view-key cadence | Decide (spec-recommended) | Ratify Option C, build | **CLOSED 2026-07-09: Option C ratified — per-epoch HKDF derivation, build** |
| A2 | CT audit integration | Decide (spec-recommended) | Ratify dual-mode, build minimal first | **CLOSED 2026-07-09: (a) build FULL; first DApp = fair-lottery Liberty Bell slot remake** |
| A3 | Confidential light-read RPC | Decide (genuinely open) | Ship minimal (inclusion-only) now | **CLOSED 2026-07-09: (b) build FULL client-side verification before launch** |
| A4 | S-048 fork recovery | Decide (owner-gated) | Wire head-reorg pre-launch | **CLOSED 2026-07-09: (a) wire resolve_fork + bounded one-block head-reorg pre-launch — owner sign-off GRANTED** |
| A5 | PQ anon-address format | Decide (consequential) | Decide now — it's permanent | **CLOSED 2026-07-09: (a) build hash-based (Option A) PQ anon-address now** |
| A6 | `signature_form` discriminator | Decide | Confirm SHIP, cover Ed25519+ML-DSA | **CLOSED 2026-07-09: (a) SHIP, enum covers Ed25519 K-of-K + ML-DSA** |
| A7 | RingCT wiring | Decide | Keep deferred (library-only) | **CLOSED 2026-07-09: moot — library removed under B2; re-add = normal reviewed feature if ever required** |
| A8 | Hierarchical sharding | Decide | Leave v4 | **CLOSED 2026-07-09: not needed — DROPPED (not parked); flat ceiling is the design limit** |
| B1 | One-file-per-block storage | Simpler | Do it pre-launch | **CLOSED 2026-07-09: (a) do it pre-launch** |
| B2 | Purge unwired crypto (FROST/RingCT) | Simpler | Remove unless a DApp needs them | **CLOSED 2026-07-09: (a) remove BOTH (FROST + ring-sig library); audit docs stay as design record** |
| B3 | Rewrite v2.22 spec | Simpler | Rewrite before building against it | **CLOSED 2026-07-09: rewrite — as a step toward ONE consolidated design doc (all docs except README), 100% provable security** |
| B4 | Vestigial reserved bits | Simpler | Audit pre-genesis | **CLOSED 2026-07-09: (a) pre-genesis audit, keep-only-with-named-future** |
| C2 | Adversarial FA/DSF sweep | Reliable | Run full sweep pre-mainnet | **CLOSED 2026-07-09: (a) full adversarial-schedule sweep pre-mainnet** |
| D1 | Shielded-pool audit + beta | Secure | Audit + flag-gate + soak | **CLOSED 2026-07-09: (a)+(b) audit + flag-gate** |
| D2 | Constant-time re-probe | Secure | Extend probe to wired path | **CLOSED 2026-07-09: (a) extend ct-timing-probe to integrated CT + PQ paths** |
| D3 | S-036 SHARD_TIP | Secure | Close only if launching EXTENDED | **CLOSED 2026-07-09: launch posture = EXTENDED → build SHARD_TIP (v2.11), close S-036 pre-launch** |
| D4 | Start closed beta | Secure | Start staged beta now | **CLOSED 2026-07-09: (b) wait for feature-complete, then single soak** |

(S-048 and the storage refactor each serve two categories; listed once, cross-referenced.)

---

## A. Not yet decided

### A1. Confidential-tx view-key rotation cadence
**What it is.** How the per-account "view key" (which lets a recipient/auditor decrypt hidden amounts) rotates over time.
**Why it matters.** It sets the blast radius of a leaked view key and how clean regulator disclosure is. It's permanent once accounts exist.
**Status.** *Already recommended in spec (Option C):* per-epoch automatic derivation, `vk_epoch_n = HKDF(view_master_sk, "VK"||chain_id||addr||epoch_n)`. Bounded per-epoch exposure, zero on-chain cost, maps to quarterly/annual audit windows, no "forgot to rotate" failure mode. Alternatives (genesis-pinned, per-account-tx, per-tx, hybrid) are laid out and rejected.
**Options.** (a) **Ratify Option C and build it.** (b) Pick a different cadence (revisit the rejected ones). (c) Defer the whole view-key layer post-launch — ship confidential amounts with no auditability first.
**Recommendation.** (a). The spec reasoning is sound and it's zero-on-chain-cost. Only choose (c) if launch deployments have no audit requirement.
**Decision (owner, 2026-07-09).** (a): Option C ratified — per-epoch automatic HKDF derivation (`vk_epoch_n = HKDF(view_master_sk, "VK"||chain_id||addr||epoch_n)`). Build against the B3-rewritten spec.

### A2. Confidential-tx audit integration (composes with v2.24)
**What it is.** How a compliance officer / regulator gets scoped access to an account's hidden amounts.
**Why it matters.** This is the difference between "usable by regulated operators (gambling, B2B, banks)" and "privacy-only." It's the main reason to build the view-key layer at all.
**Status.** *Already recommended in spec:* dual-mode — **master** (`view_master_sk`, full history) or **per-epoch** (`vk_epoch_n`, one audit window); optional baked-in `audit_view_master_pk` (v2.24) with `ROTATE_AUDIT_KEY`; optional `LOG_AUDIT_ACCESS` on-chain trail. All reuse the A1 HKDF derivation — no new primitive.
**Options.** (a) **Build full** (master + per-epoch + LOG_AUDIT_ACCESS). (b) **Build minimal** (master + per-epoch disclosure only; defer LOG_AUDIT_ACCESS + baked-in audit key). (c) Defer auditability entirely post-launch.
**Recommendation.** (b) for launch, (a) if a regulated deployment (D.1 gambling, D.2 B2B) is in the first wave. The on-chain audit-trail bells are add-on and can follow.
**Decision (owner, 2026-07-09).** (a): build FULL — master + per-epoch disclosure + on-chain `LOG_AUDIT_ACCESS` trail + baked-in `audit_view_master_pk` with `ROTATE_AUDIT_KEY` (v2.24 composition). Trigger condition confirmed: the regulated-gambling deployment IS the first wave — **the FIRST DApp is a provably-fair lottery remake of the Liberty Bell slot machine** (owner requirement, 2026-07-09). That DApp's fairness/audit story consumes exactly this layer: verifiable randomness for the reels, confidential stakes/payouts, and scoped regulator disclosure via the view-key hierarchy.

### A3. Confidential light-read RPC
**What it is.** How a light client reads confidential state. The daemon's cleartext-balance cross-check no longer applies to hidden value, so there's a gap in trustless reads.
**Why it matters.** Light-client verifiability is a core Determ property; confidential amounts partially break it unless a new read path exists.
**Status.** Genuinely open — "TBD, to be designed against `light/trustless_read.cpp`'s state-proof path." The doc's "honest limit": a light client can still verify commitment *inclusion* in `state_root`; it just can't cross-check a cleartext balance.
**Options.** (a) **Ship minimal now** — light client verifies commitment inclusion in the committee-signed `state_root`, trusts committee for validity (same trust root as today, just no cleartext cross-check). (b) **Build full** — light client also verifies range/balance proofs itself. (c) Defer any confidential light-read post-launch.
**Recommendation.** (a). It preserves the committee-signature trust root and is small; (b) is a nice post-launch upgrade.
**Decision (owner, 2026-07-09).** (b): build FULL before launch — the light client verifies commitment inclusion in the committee-signed `state_root` AND verifies the range/balance proofs itself (client-side verification in `determ-light`, against `light/trustless_read.cpp`'s state-proof path). Substantial client build item added to the pre-beta critical path; fits the Liberty Bell DApp posture (players are light-client users who should not trust the committee for CT validity).

### A4. S-048 — fork-recovery wiring (owner-gated) *(also a reliability item)*
**What it is.** The abort-vs-finalize race can leave one node on a validly-signed *minority* same-height block. `resolve_fork` already computes the deterministic winner, but it isn't wired into the node, and sync is append-only — so that node can't reorg back onto the canonical chain.
**Why it matters.** Cluster liveness is fine (the majority keeps finalizing). This is *node-local* self-healing: a stuck node currently needs an operator resync. Under no-migrations, a consensus-path change is far cheaper to make before launch.
**Options.** (a) **Wire `resolve_fork` + a bounded head-reorg** into the sync/gossip path (the real fix; consensus architecture). (b) **Accept operational recovery** (resync from snapshot) as the v1.1 answer and document it. (c) Ship (b) now, do (a) as a fast-follow.
**Recommendation.** (a) pre-launch if you can afford the consensus review; otherwise (c). Avoid leaving it purely operational long-term.
**Decision (owner, 2026-07-09).** (a): owner sign-off granted for the consensus-architecture change — wire `resolve_fork` + a bounded ONE-block head-reorg (state rollback + replacement) into the sync/gossip path, pre-launch. Rationale ratified: safety already holds (depth-1, frozen, deterministic winner specified); the change is capped by the depth-1 bound; the deterministic S-048 repro harness gates it; the D4 feature-complete beta then soaks the REAL recovery path; unblocks the loss-liveness gate. Full consensus review + FA-harness gate required before merge.

### A5. PQ anon-address format
**What it is.** On-chain post-quantum signatures (ML-DSA / `PQ_TRANSFER`) reopened the previously-frozen "Ed25519-only" anonymous-address format (owner decision 2026-07-04). The address-derivation formula for PQ keys (Option A, hash-based) is pending.
**Why it matters.** The address format is **permanent under no-migrations** — genesis is your only chance to get it right. If PQ addresses ship later without the slot reserved now, you're stuck.
**Options.** (a) **Decide + build the PQ address format now** so `PQ_TRANSFER` is fully usable and the format is frozen correctly. (b) Keep `PQ_TRANSFER` as bearer-only, defer anon-PQ-address. (c) Defer on-chain PQ entirely, re-freeze Ed25519-only.
**Recommendation.** (a) if you're committed to launching with on-chain PQ; (c) if PQ can wait — but decide deliberately, because the freeze is forever.
**Decision (owner, 2026-07-09, joint with A6).** (a): on-chain PQ is a launch capability. Build the hash-based (Option A) PQ anon-address derivation now so `PQ_TRANSFER` is fully usable, and freeze the format at genesis. Adds the PQ-address build item to the pre-beta critical path.

### A6. `signature_form` discriminator (§7.1 / 7.5.1)
**What it is.** A 1-byte/block enum tagging the block-signature scheme (so BLS aggregation or PQ block sigs can be added additively). Decided "SHIP" in the §7.5 sweep, then reopened as an "open question" under the FROST-removal cascade; now relevant again with on-chain PQ reopened (A5).
**Why it matters.** It's the forward-compat slot for ever changing block-sig schemes. Getting its value set wrong (or omitting forms) forecloses future sig schemes permanently.
**Options.** (a) **Confirm SHIP** with the enum covering Ed25519 (K-of-K) + ML-DSA forms (aligns with A5). (b) Narrow to Ed25519-only (simpler, forecloses PQ/BLS block sigs). (c) Keep reserved, unused.
**Recommendation.** (a), and decide it *together with* A5 — they're the same PQ question at the block-sig layer.
**Decision (owner, 2026-07-09, joint with A5).** (a): confirm SHIP. The `signature_form` enum covers Ed25519 (K-of-K) + ML-DSA forms at genesis, keeping PQ/BLS block-sig evolution additive.

### A7. RingCT (input-unlinkability) wiring
**What it is.** Ring-signature primitives (LSAG/CLSAG/RingCT-compose) shipped as **library-only**; wiring them into consensus (to hide *which input* is spent — graph privacy) was deferred by owner decision 2026-07-07 ("adds a decoy-selection footgun, no concrete near-term requirement").
**Why it matters.** It's the difference between amount-privacy (shipped) and full graph-privacy (Monero-style). Wiring it is multi-week and consensus-critical.
**Options.** (a) **Keep deferred** — library stays, wire when a real requirement appears. (b) Wire it into consensus for launch. (c) Remove the library too (drop the permanent audit surface — see B2).
**Recommendation.** (a) unless graph-privacy is a stated launch requirement. This is the disciplined stance you already took.
**Decision (owner, 2026-07-09, joint with B2).** Moot: the ring-signature library is REMOVED under B2(a). Graph-privacy is not a launch requirement; if it ever becomes one, re-adding the primitives is a normal reviewed feature (git history + the §3.23/§3.23c audit docs preserve the design record).

### A8. Hierarchical sharding
**What it is.** "Sharding of sharding" to scale past the ~200–500-shard flat ceiling. Needs a hierarchical VRF; parked as a v4 candidate.
**Why it matters.** It's the only path past the flat ceiling — but that ceiling already exceeds every documented commercial use case.
**Options.** (a) **Leave v4**, demand-driven. (b) Start design now if you anticipate internet-scale public deployment.
**Recommendation.** (a). Don't build speculative scale.
**Decision (owner, 2026-07-09).** "No need of sharding of sharding" — DROPPED, not merely parked as v4. The flat ~200–500-shard ceiling is the design limit; remove the v4 candidate from the roadmap (consistent with the B3 shrink-to-one-doc directive: no aspirational surface).

---

## B. Could be simpler

### B1. One-file-per-block storage *(also a reliability item)*
**What it is.** Replace the monolithic `chain.json` (rewritten whole on every save — O(N) under the global mutex) with `chain/blocks/{index}.json` (append-only, never rewritten) + an incrementally-updated `state.json`.
**Why it matters.** Makes `save()` O(1), removes a global-mutex offender (a reliability/throughput risk under load), makes old blocks prunable, and sets up future page-replication. No protocol change, so no migration constraint — you can do it anytime.
**Options.** (a) **Do it pre-launch** (~1–2 days). (b) Defer post-launch (safe — it's not consensus).
**Recommendation.** (a). Cheap, and it's your clearest simpler-*and*-more-reliable win.
**Decision (owner, 2026-07-09).** (a): do it pre-launch. `save()` O(1), global-mutex offender removed before the beta loads it, blocks prunable. The D4 single-soak beta then exercises the real storage layer.

### B2. Purge unwired crypto (FROST + RingCT)
**What it is.** FROST and the RingCT ring-signature primitives sit in-tree with **no consensus consumer**. Under no-migrations, every retained primitive is permanent audit surface.
**Why it matters.** You already deleted secp256k1, the Z_p* backend, and libsodium on exactly this "no consumer" logic. Consistency says apply the same razor — unless a concrete DApp justifies keeping them.
**Options.** (a) **Remove both** (smallest audit surface). (b) Keep both as documented library primitives (audit-history value; current stance). (c) Keep one, remove the other.
**Recommendation.** (a) if no near-term DApp needs threshold sigs or ring sigs; otherwise (b) with an explicit "why retained" note. This is a code/audit-surface call, not a protocol one.
**Decision (owner, 2026-07-09, joint with A7).** (a): remove BOTH FROST and the RingCT/LSAG/CLSAG library from the tree — the secp256k1/Z_p*/libsodium razor applied consistently. Git history preserves the code; the audit/proof docs stay as design record. Removal gated like every deletion: build + FAST both platforms + dependency ratchet + goldens byte-identical.

### B3. Rewrite the v2.22 privacy spec
**What it is.** The spec is largely a **SUPERSEDED** design layer (secp256k1 wire formats, ristretto, libsodium) carrying a "don't read below as current" banner over the as-built P-256 shielded pool.
**Why it matters.** You're about to implement the view-key/audit layer *against this spec*. A stale spec is a landmine for that work and for future implementers/auditors.
**Options.** (a) **Rewrite to the as-built P-256 design** before building A1/A2. (b) Leave the banner (cheaper now, riskier later).
**Recommendation.** (a). Low effort, high clarity payoff, and the timing is right.
**Decision (owner, 2026-07-09) — scope WIDENED.** Rewrite v2.22 to the as-built P-256 design, but as a step toward the stated END GOAL: **consolidate the entire documentation corpus (everything except README) into ONE design doc, with 100% provable security** — every claim in the surviving doc verified/proof-backed, nothing aspirational. This extends the standing KISS directive (shrink docs/code; small green verified surface beats large aspirational one) from per-doc trimming to full-corpus consolidation. The v2.22 rewrite is the first consolidation increment, not a standalone doc.

### B4. Audit vestigial reserved discriminator bits
**What it is.** Reserved-but-unused schema slots (e.g., `POLICY_TIER_BONDS_ENABLED` bit 3) get locked into the wire format forever under no-migrations.
**Why it matters.** Genesis is your last chance to change them. Carrying dead optionality forever is permanent complexity; removing a slot you'll later want is permanent regret.
**Options.** (a) **Pre-genesis audit** of every reserved discriminator — keep only those with a plausible future. (b) Keep all reserved (max optionality, more permanent surface).
**Recommendation.** (a). A short housekeeping pass with outsized permanence.
**Decision (owner, 2026-07-09).** (a): pre-genesis audit of every reserved discriminator; keep only slots with a plausible, NAMED future use, one-line rationale per keep/drop in the schema doc.

---

## C. Could be more reliable

### C1. Wire S-048 → see **A4** (same item; primarily a reliability fix).

### C2. Run the adversarial virtual-time FA/DSF sweep
**What it is.** The new in-process FA4 / DSF harness runs seeded Byzantine consensus traces. It already surfaced S-047 (one-shot-broadcast wedge, fixed) and S-048 (fork recovery). Adversarial-schedule (virtual-time) traces are the remaining slice.
**Why it matters.** Two real liveness bugs in its first outing means more edge cases likely lurk. Crucially, the tooling now exists — this is *running* it, not building it.
**Options.** (a) **Run the full adversarial-schedule sweep before mainnet.** (b) Run a bounded subset, lean on beta for the rest. (c) Defer to beta.
**Recommendation.** (a). Cheapest pre-mainnet reliability insurance you have now.
**Decision (owner, 2026-07-09).** (a): run the FULL adversarial-schedule sweep before mainnet declaration. Composes with A4 (the deterministic S-048 repro validates the reorg fix) and feeds the D4 feature-complete definition. Prerequisite: the remaining deterministic-scheduler increments (DeterministicSchedulerDesign.md 2-5, incl. the now-relevant Node no-self-thread mode).

### C3. Storage refactor → see **B1** (also removes a global-mutex reliability offender).

---

## D. Could be more secure

### D1. Adversarially audit + beta-soak the shielded pool — **#1 security item**
**What it is.** SHIELD / UNSHIELD / CONFIDENTIAL_TRANSFER + the nullifier set are brand-new consensus code touching the ledger's value-conservation invariant (fund-loss / hidden-inflation class), landed days ago.
**Why it matters.** The `MAINNET_READINESS` "confidential-amount apply path: zero bugs for N days" window can't even start until this code stabilizes. This is the surface where a bug is worst.
**Options.** (a) **Dedicated adversarial audit** (nullifier double-spend, balance conservation via commitment algebra, range-proof verify identical at validate *and* apply) + DSF/FA scenarios + beta soak before it's hot on mainnet. (b) **Flag-gate it** — confidential-tx type disablable per deployment (v2.22 §6 rollback), so mainnet can launch without CT hot and enable it once soaked. (c) Gate the whole mainnet declaration on the CT zero-bug window.
**Recommendation.** (a) + (b) together: audit hard, and ship behind a flag so launch date isn't hostage to CT maturity.
**Decision (owner, 2026-07-09).** (a)+(b): dedicated adversarial audit (nullifier double-spend, commitment-algebra conservation, range-proof verify parity at validate+apply) + DSF/FA scenarios + beta soak, AND confidential-tx ships behind a per-deployment disable flag (v2.22 §6 rollback) so mainnet launch is decoupled from CT maturity.

### D2. Re-probe constant-timeness on the integrated path
**What it is.** The range provers were constant-time-hardened in isolation (07-06). A timing leak *anywhere* in the wired shielded-pool signing path (or the new PQ path) leaks the hidden amount.
**Why it matters.** Constant-timeness doesn't compose automatically — integration can reintroduce data-dependent branches, defeating the whole point of hiding the amount.
**Options.** (a) **Extend the `ct-timing-probe` harness** to the integrated shielded-pool + PQ paths. (b) Rely on the isolated-prover hardening.
**Recommendation.** (a). Low effort, and you already have the probe harness.
**Decision (owner, 2026-07-09).** (a): extend `ct-timing-probe` to the integrated shielded-pool signing path + the PQ (ML-DSA) path, with empirical measurements. Folds into the D1 audit scope.

### D3. Close S-036 (on-chain SHARD_TIP)
**What it is.** In EXTENDED (regional) sharding mode, a beacon can fabricate a `MERGE_BEGIN` evidence window within the shipped bounds. Full closure needs on-chain SHARD_TIP records (tracked as v2.11).
**Why it matters.** Only relevant if you launch with EXTENDED regional sharding. It's a non-issue for SINGLE / non-EXTENDED deployments.
**Options.** (a) **Build SHARD_TIP** and close it (if EXTENDED is in the launch posture). (b) Leave partial (if launch is non-EXTENDED). (c) Restrict launch to non-EXTENDED sharding.
**Recommendation.** Decide your launch sharding posture first; then (a) or (b) falls out. Don't launch EXTENDED with this open.
**Decision (owner, 2026-07-09).** Launch sharding posture = **EXTENDED** → (a): build on-chain SHARD_TIP records (v2.11) and close S-036 before launch. This adds a consensus-adjacent build item to the pre-beta critical path (with A1-A3, A4, B1) and pulls the T-001..T-004 EXTENDED operator trade-offs into the launch documentation surface.

### D4. Start the closed beta
**What it is.** No closed beta has begun. Per `MAINNET_READINESS`, beta is open-ended and convergence-gated (bug-discovery rate → 0), not a fixed calendar window.
**Why it matters.** It's the single biggest security gap overall — nothing new has soaked under real conditions. And since it's convergence-gated, starting sooner shortens calendar-to-mainnet.
**Options.** (a) **Start a staged beta now** on the feature-complete-minus-CT-view-key surface, fold CT in as it lands. (b) Wait for full feature-complete, then beta (later start, cleaner single soak). (c) Substrate-first beta, CT beta when ready.
**Recommendation.** (a) or (c). Start the soak clock early; the shielded pool (D1) can join behind its flag when audited.
**Decision (owner, 2026-07-09).** (b): wait for full feature-complete, then run one clean beta soak of the final surface. Consequence accepted: the convergence clock starts later, so the remaining build items (A1-A3 CT layer, A4 if wired, B1) become the critical path to beta start — finish them promptly.

---

## Register CLOSED — 2026-07-09 (all 17 items decided by owner)

### The decided execution plan

**Beta model (D4):** ONE clean soak at full feature-complete — so everything below is on the critical path to beta start.

**Build items (pre-beta critical path):**
1. **B2 purge** — delete FROST + RingCT/LSAG/CLSAG libraries (quick, shrinks the audit surface everything else gets audited against).
2. **B3 spec rewrite** — v2.22 → as-built P-256, as increment 1 of the **one-consolidated-design-doc / 100%-provable-security** program (all docs except README).
3. **B4 reserved-bit audit** — pre-genesis keep-only-with-named-future pass.
4. **B1 storage refactor** — one-file-per-block + incremental state.json.
5. **A1+A2 CT view-key/audit layer, FULL** — per-epoch HKDF (Option C) + master/per-epoch disclosure + `LOG_AUDIT_ACCESS` + baked-in audit key w/ `ROTATE_AUDIT_KEY`.
6. **A3 light-read, FULL** — client-side range/balance-proof verification in determ-light.
7. **A5+A6 PQ freeze** — hash-based PQ anon-address + `signature_form` enum {Ed25519 K-of-K, ML-DSA} at genesis.
8. **A4 S-048 head-reorg** (owner sign-off granted) — wire `resolve_fork` + bounded one-block reorg; consensus review + deterministic-repro gate.
9. **D3 SHARD_TIP (v2.11)** — launch posture is EXTENDED, so S-036 closes pre-launch.

**Verification items (pre-mainnet):**
- **D1** — adversarial shielded-pool audit; CT ships behind a per-deployment flag.
- **D2** — extend `ct-timing-probe` to the integrated CT + PQ paths.
- **C2** — full adversarial-schedule FA/DSF sweep (needs the remaining deterministic-scheduler increments).

**Dropped/removed:** A7 RingCT wiring (library removed under B2), A8 hierarchical sharding (dropped outright — flat ceiling is the design limit).

**First DApp (owner requirement):** a provably-fair lottery remake of the **Liberty Bell slot machine** — consumes the CT + audit + light-verification stack end-to-end.
