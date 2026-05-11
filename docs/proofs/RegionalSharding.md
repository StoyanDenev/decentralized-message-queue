# FA8 — Regional sharding corollary

This document proves that **regional sharding** (EXTENDED mode with `committee_region` pinning per shard) preserves all per-property guarantees of FA1 (Safety), FA4 (Liveness), FA6 (Equivocation Slashing), and FA7 (Cross-shard receipts) without modification to their cryptographic or quorum arguments.

Regional sharding is a deployment optimization: each shard's committee is drawn only from validators whose `region` tag matches the shard's `committee_region`. This narrows the latency envelope within a committee (intra-region RTTs), allowing faster block times per shard without sacrificing global decentralization. The question the proof answers: **does this filter break any prior soundness or liveness theorem?** Answer: no, provided the pinned pool retains enough honest validators.

**Companion documents:** `Preliminaries.md` (F0); `Safety.md` (FA1); `Liveness.md` (FA4); `EquivocationSlashing.md` (FA6); `CrossShardReceipts.md` (FA7).

---

## 1. The regional filter

`NodeRegistry::eligible_in_region(region)` (`src/node/registry.cpp`):

```
if (region == "") return full_pool;       // pre-R1 behavior
return [e ∈ full_pool : e.region == region];
```

Every committee-selection call site (validator.cpp, node.cpp) passes its shard's `committee_region` to `eligible_in_region` before invoking the deterministic committee selector. The selector is unchanged: it takes a sorted pool, applies stake-weighted Fisher-Yates with the per-epoch seed, and returns K members.

**Definitions.**

- `Pool_s ⊆ V` = full validator set with `region == committee_region(s)` at the relevant epoch boundary.
- `F_s ⊆ Pool_s` = Byzantine validators within `Pool_s`.
- `K_s` = committee size at shard `s` (default = global K from genesis).
- Committee `C_s,h ⊆ Pool_s` of size `K_s` selected by `select_committee_from(Pool_s, seed_s,h, K_s)`.

The selector is the same deterministic function from F0 §6; only its input domain changes.

---

## 2. Theorem statements

**Theorem T-8 (Per-shard safety under regional pinning).** For any shard `s ∈ S`, under:

- **(A1) EUF-CMA** + **(A3) SHA-256 CR** (F0 §2)
- **(H1) Honest behavior** restricted to `Pool_s`
- **(R-safety)** `Pool_s \ F_s ≠ ∅` for every epoch (at least one honest validator in the region's pool)

every finalized block on shard `s` satisfies FA1's safety property — at most one digest finalizes per height — with bound `≤ 2⁻¹²⁸ · K_s` per attempted fork.

**Theorem T-8a (Per-shard liveness under regional pinning).** For any shard `s`, under:

- T-8's assumptions
- **(R-liveness)** `|Pool_s| ≥ K_s` and the honest fraction within `Pool_s` is `≥ p_honest_s`

shard `s` finalizes at least one block within `R(p_honest_s)` rounds in expectation, where `R(·)` is FA4's geometric bound applied to the regional pool.

**Theorem T-8b (Slashing and cross-shard mechanisms commute with regional pinning).** FA6 (T-6) and FA7 (T-7, T-7') hold for every shard `s` under T-8's hypothesis, without modification to their proofs.

**Corollary T-8.1 (Latency advantage is free).** Reducing shard `s`'s block timer to the regional RTT envelope does not change T-8 / T-8a / T-8b. The proofs depend on quorum structure and cryptographic assumptions, not on the wall-clock duration of round timers.

---

## 3. Proof sketch — why regional pinning doesn't affect the proofs

The full FA1, FA4, FA6, FA7 proofs are not re-derived here. We show that each proof's argument applies *verbatim* once `Pool_s` substitutes for the global pool `V`.

### 3.1 FA1 (Safety) survives substitution

FA1's T-1 proof structure:

1. **Committee determinism** (L-1.1): committee selection is a pure function of `(pool_view, seed)`.
2. **`signing_bytes` injectivity** (L-1.2): block-bytes encoding distinguishes any two distinct blocks.
3. **Pigeonhole on K-of-K** (L-1.3): two distinct finalized digests at height `h` would force at least one validator to sign both, which honest validators don't do.

All three lemmas are agnostic to which set the committee is drawn from. L-1.1 holds because `eligible_in_region` is deterministic. L-1.2 is purely about block encoding. L-1.3's pigeonhole: under K-of-K (MD mode), two distinct digests at `h` require K signatures each; if `Pool_s \ F_s ≠ ∅`, every K-subset of `Pool_s` contains at least one honest member, who signs at most one digest by H2. Forging the second signature is `≤ 2⁻¹²⁸` per attempt under A1.

For BFT-mode (FA5), the threshold is `f_s < K_s,eff / 3` on the *committee* (not the pool). Since committees are drawn from `Pool_s`, the operational requirement is that `Pool_s` has a sufficient honest fraction that random committee selection yields `f_committee < K_s,eff / 3` with overwhelming probability — exactly FA5's assumption, with `V` replaced by `Pool_s`. ∎

### 3.2 FA4 (Liveness) survives substitution

FA4's T-4 argument uses three properties of the eligible pool:

- **Adequate size**: `|Pool| ≥ K` so a committee can be drawn.
- **Honest fraction**: at least `p_honest · K` honest members per committee in expectation.
- **Round-1 success probability**: geometric distribution over rounds.

Under R-liveness (`|Pool_s| ≥ K_s` and bounded honest fraction), all three hold with `Pool` ← `Pool_s`. The expected-rounds bound is the same; only the constants change to reflect the smaller pool. ∎

**Caveat.** If R-liveness fails — e.g., `Pool_s` shrinks below `K_s` due to deregistrations or slashing — shard `s` stalls. This is a deployment concern, not a soundness regression. The protocol can mitigate via under-quorum merge (R4, pending), regional rebalancing (R5, pending), or operator action.

### 3.3 FA6 (Equivocation slashing) survives substitution

T-6's proof is a direct reduction to EUF-CMA: honest validator `v_i ∈ Pool_s \ F_s` cannot have two signatures over distinct digests at the same `(h, round)`. The argument is *per-validator*, not per-pool. Regional pinning narrows which `v_i`s are eligible at `s`; it doesn't weaken the EUF-CMA bound against any individual `v_i`.

Cross-shard slashing (T-6.1) routes through the beacon's committee derivation. The beacon's view of `Pool_s` at the equivocation epoch is reconstructible from beacon-anchored pool state plus the shard manifest's `committee_region` for `s` — exactly what `node.cpp::on_shard_tip` already does (line 1206–1213). ∎

### 3.4 FA7 (Cross-shard receipts) survives substitution

T-7's proof depends on:

- **V12/V13 validator checks** (L-7.1, L-7.2): structural, independent of pool.
- **Source-side K-of-K verification on receipt admission** (L-7.4): K signatures from `C_src,h_src ⊆ Pool_src`. The receipt verifier (`node.cpp::on_cross_shard_receipt_bundle`) reconstructs `Pool_src` from the beacon-anchored registry, filtered by `shard_committee_regions_[src_shard]`.

If the receiver mis-identifies `Pool_src` (e.g., uses the wrong region filter), it would fail to verify signatures and reject the receipt — a *liveness* problem for the receipt, not a safety problem (no fabrication can succeed). The beacon's shard manifest (R2) is the trust anchor that prevents region-tag confusion. ∎

---

## 4. Conditions for regional pinning to be safe vs. dangerous

### 4.1 Safe regimes

- **`Pool_s` large with high honest fraction**: T-8 / T-8a hold; the only effect of pinning is *better latency* per shard.
- **`Pool_s` small but homogeneously honest** (e.g., a corporate consortium running a regional shard): safe under H1 with `F_s = ∅`.

### 4.2 Dangerous regimes (operator beware)

- **`Pool_s` falls below `K_s`**: shard stalls. The startup gate (A6) catches some cases by refusing to launch with `|Pool_s| < K_s`; runtime erosion through deregistration is not yet handled.
- **`Pool_s` has high Byzantine fraction**: if `|F_s| / |Pool_s|` exceeds the BFT threshold, FA5 escalation cannot save the shard. The slashing path (FA6) still catches equivocators with cryptographic certainty, but liveness is lost.
- **Adversarial region tagging**: if an adversary registers many validators with a fake region tag to dilute `Pool_s` (and `F_s / Pool_s` rises), regional pinning concentrates the attack. Mitigation: require an out-of-band attestation for region claims (R6+ design item; not yet implemented).

### 4.3 What the proof does NOT cover

- **Cross-region attack resistance**: a coordinated adversary placing validators in every region to satisfy F_s thresholds on every shard simultaneously. T-8 handles each shard locally; a global-adversary analysis is out of scope (similar caveat applies to non-regional sharding too).
- **Optimal region partitioning**: how operators should partition validators into regions for minimum latency × maximum fault tolerance. This is a deployment/operations question, not a theorem.
- **Region migration**: a validator moving from `region_A` to `region_B` between epochs. The current implementation re-evaluates `eligible_in_region` per epoch boundary; the corollary holds at each epoch independently.

---

## 5. Implementation cross-reference

| Component | Source |
|---|---|
| Per-validator region tag (REGISTER tx payload) | `src/chain/chain.cpp::apply_transactions` REGISTER branch |
| Per-shard `committee_region` (genesis / manifest) | `src/chain/genesis.cpp::GenesisConfig` |
| Region-filtered eligible pool | `src/node/registry.cpp::eligible_in_region` |
| Validator-side region filter | `src/node/validator.cpp` (lines 69, 178) |
| Producer-side region filter | `src/node/node.cpp::next_committee_for_height` (line 1850, 1944) |
| Beacon-side shard-region view | `src/node/node.cpp::on_shard_tip` (line 1206–1213) |
| Shard manifest (R2 fail-closed under EXTENDED+BEACON) | `src/main.cpp` startup gate; `tools/test_shard_manifest.sh` |

A reviewer can confirm regional pinning is sound by:

1. Reading `eligible_in_region`: it is a deterministic projection, no randomness, no state.
2. Confirming every committee-selection call site funnels through `eligible_in_region` with the correct `committee_region` argument.
3. Confirming the beacon's view (`shard_committee_regions_`) is populated from the same manifest source as the shards' own configs.

---

## 6. Conclusion

T-8 / T-8a / T-8b together establish that regional sharding is a **transparent specialization** of the global protocol: the cryptographic and quorum-structural arguments of FA1, FA4, FA5, FA6, FA7 all apply with `Pool_s` substituted for `V`. The substitution is safe iff `Pool_s` retains the assumed honest fraction and minimum size at each epoch.

The corollary T-8.1 is the practical payoff: a shard can run its block timer at intra-region latency (e.g., 50ms within a continent) without weakening any global property. Inter-shard communication still travels global RTTs, but it travels in `cross_shard_receipts`, not in the round-1/round-2 timing critical path.

The remaining gaps (under-quorum merge in R4, region-claim attestation in R6+) are deployment-time concerns; they do not undermine the per-property proofs.
