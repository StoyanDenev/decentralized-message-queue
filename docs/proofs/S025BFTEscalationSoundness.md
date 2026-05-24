# S025BFTEscalationSoundness — BFT-mode 4-gate escalation trigger soundness composition

This document is the analytic composition theorem covering the 4-gate predicate that drives Determ's K-of-K → BFT-mode escalation at `src/node/node.cpp:773-780`. The four gates — (1) `cfg_.bft_enabled` (chain-level config from genesis), (2) `total_aborts >= cfg_.bft_escalation_threshold` (sustained abort rate observed within the current height's pre-finalize state), (3) `avail_domains.size() < k_target` (eligible pool is below the genesis-pinned full committee size), and (4) `avail_domains.size() >= k_bft` with `k_bft = (2K + 2) / 3` (eligible pool is at or above the smaller BFT-shrunk committee size) — must all hold simultaneously for `Node::check_if_selected` to flip the round into `ConsensusMode::BFT`. The validator at `src/node/validator.cpp:240-244` (per-event abort-cert reconstruction) and `src/node/validator.cpp:389-401` (block-sig branch) mirrors the same 4-gate semantics so that producer-validator divergence cannot break consensus. The proof composes the four gates against four adversary families — `A_premature` (force escalation early), `A_late` (force escalation late), `A_pool_forge` (forge the pool size to bypass gate 3), `A_quorum_skip` (escalate below the BFT viability floor and bypass R7 under-quorum merge) — and pins the safety + liveness preservation that BFT mode achieves once the predicate fires.

The proof exists because the FA1 K-of-K safety proof (`Safety.md`) and the FA5 BFT-mode conditional-safety proof (`BFTSafety.md`) cover the two endpoints — full-K consensus and BFT-shrunk consensus respectively — but neither formalizes the *transition predicate* itself. The 4-gate trigger is the load-bearing decision that determines which proof's hypotheses are in scope for any given block. Escalating too early collapses unconditional FA1 safety onto conditional FA5 safety without operational necessity; escalating too late collapses FA4 liveness because the chain stalls indefinitely with no recovery. The trigger predicate must reject both modes of failure and steer the chain precisely between the two regions of the operational envelope.

**Companion documents.** `Preliminaries.md` (F0 notation; H1–H4 honest-validator assumptions; §3 committee-selection contract); `Safety.md` (FA1 K-of-K K-mode unconditional safety theorem); `BFTSafety.md` (FA5 BFT-mode conditional-safety theorem under `f_h < |K_h|/3`); `Liveness.md` (FA4 escalation-driven liveness restoration); `CommitteeSelection.md` (FA1+FA8 K-of-K parent proof); `S020CommitteeSelection.md` (S-020 hybrid Fisher-Yates uniformity inside the chosen committee size); `S024EpochBlocks.md` (S-024 epoch-cadence + PARAM_CHANGE composition for `bft_escalation_threshold`); `S036UnderQuorumMerge.md` (R7 under-quorum merge — the recovery path when gate 4 fails); `RegionalSharding.md` (FA8 region-aware overlay; pool composition under R4 + R7); `EquivocationSlashing.md` (FA6 slashing recovery the BFT path leans on); `GovernanceParamChange.md` (A5 PARAM_CHANGE pipeline for `bft_escalation_threshold` mid-chain mutation); `docs/PROTOCOL.md` §5.3 (BFT escalation gate wire specification); `docs/SECURITY.md` §S-030 + §S-035 for the closure context of the abort-driven escalation surface; `docs/V2-DESIGN.md` §v2.10 for the threshold-randomness composition that will harden the within-BFT proposer election but leaves the 4-gate trigger semantics intact.

---

## 1. Introduction

### 1.1 The K-of-K mode and its liveness vulnerability

Determ's MUTUAL_DISTRUST consensus mode (the protocol's default) requires all K committee members to participate in each block. The producer's contribution-gathering phase (`Node::start_contrib_phase` at `src/node/node.cpp:815`) collects K ContribMsgs from the K-tuple committee; the block-signature phase (`Node::start_block_sig_phase`) collects K BlockSigMsgs over the canonical `compute_block_digest(B)`. The validator's V8 check (`BlockValidator::check_block_sigs` MUTUAL_DISTRUST branch at `src/node/validator.cpp:403-407`) demands `required_block_sigs(MUTUAL_DISTRUST, K) = K` non-zero signatures.

The unconditional safety property follows from FA1 / `Safety.md` T-1: under (A1) Ed25519 EUF-CMA + (A2) SHA-256 collision resistance + the H1 honest-validator assumption that *at least one* committee member follows the protocol, any two valid K-of-K blocks at the same height have signed the same digest (by pigeonhole on the K-cardinality + the honest member's H2 single-digest-per-height behavior). Safety is unconditional given ≥1 honest member in committee. The catch: the chain stops finalizing if *any* one of the K members silently fails to participate. There is no recovery from within K-of-K — the protocol issues `AbortClaimMsg` events against the silent member (`src/node/node.cpp` abort-claim path) and reseats the committee for the next attempt, but if the underlying liveness deficit persists (e.g., the pool is too small to reseat with K honest members), the chain stalls.

The shipped recovery mechanism has two layers. The first is R7 under-quorum-merge (`S036UnderQuorumMerge.md`) — when the per-shard pool drops below a configurable trigger threshold for `merge_threshold_blocks` blocks, the shard merges into a partner so the partner's committee absorbs the refugees. That mechanism handles the *persistent* under-quorum case at the shard layer.

The second is *BFT-mode escalation* — the within-shard recovery for transient under-quorum-or-abort regimes. Where R7 reaches across shard boundaries, BFT-mode escalation shrinks the committee within the same shard from K to `k_bft = ⌈2K/3⌉` and switches the validator's V8 quorum requirement from "all K" to "Q-of-k_bft" with `Q = ⌈2 · k_bft / 3⌉`. Within `k_bft − Q` slot positions, sentinel-zero signatures are permitted (the slot is filled but unsigned). The block can finalize with the smaller committee actually participating, restoring liveness.

The trade is the unconditional safety property: under FA5 / `BFTSafety.md` T-5 (the BFT-mode conditional safety), the block is safe only when `f_h < |K_h|/3` within the smaller `K_h`. At K=3 this collapses to `f_h = 0` (one Byzantine breaks safety); at K=6 it tolerates `f_h ≤ 1`; at K=9 it tolerates `f_h ≤ 1`; at K=12 it tolerates `f_h ≤ 2`. Operators who deploy at K=3 inherit a strict no-Byzantine safety floor for BFT-mode blocks; operators who deploy at K ≥ 6 gain Byzantine tolerance proportional to their committee sizing.

### 1.2 The 4-gate predicate as a transition policy

The escalation predicate at `src/node/node.cpp:773-780` reads:

```cpp
size_t total_aborts = current_aborts_.size();
size_t k_bft = (2 * cfg_.k_block_sigs + 2) / 3;     // ceil(2K/3)
size_t k_use = k_target;
chain::ConsensusMode round_mode = chain::ConsensusMode::MUTUAL_DISTRUST;
if (avail_domains.size() < k_target
    && cfg_.bft_enabled
    && total_aborts >= cfg_.bft_escalation_threshold
    && avail_domains.size() >= k_bft) {
    k_use      = k_bft;
    round_mode = chain::ConsensusMode::BFT;
}
```

The four conditions of the `if` are the four gates this proof formalizes. The order in source is `pool < k_target` AND `bft_enabled` AND `total_aborts >= threshold` AND `pool >= k_bft`; for clarity in the proof we re-order to a topical sequence:

- **Gate 1 (`bft_enabled`):** chain-level policy from `GenesisConfig::bft_enabled` (default `true`), mirrored at `cfg_.bft_enabled` at node-start (`src/node/node.cpp:155-156`). When `false`, the chain runs strictly K-of-K and accepts the liveness risk; under-quorum scenarios fall back to R7 only or the operator restoring nodes.
- **Gate 2 (`total_aborts >= bft_escalation_threshold`):** observed *sustained* abort signal. `current_aborts_` is the in-memory list of `AbortEvent` records the node has gathered for the *current* height attempt; aborts accumulate as the producer fails to gather K ContribMsgs and K BlockSigMsgs from a stable committee. The default `bft_escalation_threshold = 5` (`src/chain/genesis.cpp:173`; also `src/node/node.cpp:88`) requires five round-1 or round-2 aborts before escalation; operator profiles can tune higher (longer patience) or lower (faster reaction).
- **Gate 3 (`pool < k_target`):** the eligible-pool size at this height is below the genesis-pinned committee size `K = cfg_.k_block_sigs` (and `k_target` after R4 region-aware filtering). The pool count `avail_domains.size()` is built from the regional-eligibility view (`registry.eligible_in_region(committee_region_)`), extended by R4 partner-subset under R7 (`shards_absorbed_by(shard_id_)`), and reduced by `excluded` aborters. When the count is `< K`, K-of-K cannot form by definition (insufficient eligible signers).
- **Gate 4 (`pool >= k_bft`):** the same pool is at or above the BFT-shrunk floor `k_bft = ⌈2K/3⌉`. Below this floor, BFT-mode cannot form either — the SMALLER committee is also under-staffed. The proper recovery in that regime is R7 under-quorum merge (`S036UnderQuorumMerge.md`), not BFT escalation. Gate 4 is the protocol's "BFT viability check"; when it fails, the round abstains from finalizing and the R7 trigger fires (`src/node/node.cpp:781` short-circuit `return`).

### 1.3 The producer-validator-mirror invariant

The 4-gate predicate is computed in two places: the producer side (`Node::check_if_selected` at `src/node/node.cpp:773-780`) and the validator side at `src/node/validator.cpp:240-244` (within per-event abort-cert reconstruction). Both must agree on the predicate's truth value at every event step; any divergence would yield a block whose `consensus_mode` field disagrees with the validator's view, and the validator's V8 / V9 checks reject it.

The mirror is byte-for-byte: same `bft_enabled_` flag value (mirrored via `set_bft_enabled` in the producer-to-validator handoff at `src/node/node.cpp:175`); same `bft_escalation_threshold_` value (mirrored via `set_bft_escalation_threshold`); same K (via `k_block_sigs_`); same `k_bft` formula `(2K + 2) / 3`; same pool composition (regional filter + R7 stress branch); same `total_aborts` count (the `b.abort_events.size()` at block-validation time matches the `current_aborts_.size()` at production time because the block carries the full abort history).

The byte-for-byte mirror is itself a proof obligation (T-5 below pins it formally). PARAM_CHANGE through A5 governance can mutate `bft_escalation_threshold` mid-chain — the staged-activation pipeline (`Chain::stage_param_change` + `Chain::activate_pending_params`) ensures both producer and validator see the same effective value at the same height. `bft_enabled` is genesis-pinned (no mid-chain mutation supported in v1.x) so the producer and validator agree from chain birth.

### 1.4 What the proof DOES and DOES NOT cover

**In scope:**

- T-1 through T-4: per-gate semantics — each gate independently must hold for escalation to be sound.
- T-5: composition — the conjunction of all four gates is necessary and sufficient for sound escalation; partial conjunctions break.
- T-6: safety preservation — once the 4-gate predicate fires, FA5 safety hypotheses are guaranteed to be in scope (BFT-mode blocks are exactly the blocks under FA5's hypothesis space).
- T-7: liveness restoration — once the 4-gate predicate fires, BFT-mode finalization makes progress under FA5's quorum semantics with bounded latency.
- A1 through A4: four adversary families and how the gates defeat each.
- L-1 through L-8: per-gate lemmas that compose into the theorems.
- F-1 through F-3: tuning recommendations + pool-recovery semantics + operator misconfiguration considerations.

**Out of scope (delegated to companion proofs):**

- FA1 K-of-K safety once K-of-K is in effect (`Safety.md`).
- FA5 BFT-mode conditional safety once BFT-mode is in effect (`BFTSafety.md`).
- FA4 liveness across both modes (`Liveness.md`).
- FA6 equivocation slashing as backing for the FA5 recovery path (`EquivocationSlashing.md`).
- FA8 regional-sharding pool composition that feeds `avail_domains` (`RegionalSharding.md`).
- R7 under-quorum merge as the fallback when gate 4 fails (`S036UnderQuorumMerge.md`).
- S-020 hybrid Fisher-Yates uniformity inside the K or `k_bft` committee selection (`S020CommitteeSelection.md`).
- A5 PARAM_CHANGE staged-activation for `bft_escalation_threshold` (`GovernanceParamChange.md`).
- v2.10 threshold-randomness composition for the BFT-mode within-committee proposer election (`V2-DESIGN.md` §v2.10).

---

## 2. Theorems

### T-1 (Gate 1 — `bft_enabled` Soundness)

**Setup.** Let `cfg.bft_enabled ∈ {false, true}` be the chain-level config field installed at genesis (`GenesisConfig::bft_enabled`, default `true`) and mirrored at node-start to `Node::cfg_.bft_enabled` and `BlockValidator::bft_enabled_`. The genesis JSON binds `bft_enabled` into the canonical genesis hash (per S-018 chain-id binding) so that two operators running the same chain agree on the value by the genesis-hash gate at startup.

**Theorem.** Escalation soundness requires `cfg.bft_enabled = true`. When `cfg.bft_enabled = false`, the predicate at `src/node/node.cpp:775` short-circuits and the round stays in MUTUAL_DISTRUST regardless of gates 2/3/4. The chain accepts the liveness risk of being unable to form K-of-K and inherits the R7 under-quorum merge mechanism as the sole recovery path.

**Proof.** Direct from the AND-short-circuit at the producer (`src/node/node.cpp:775`) and the validator (`src/node/validator.cpp:240`: `&& bft_enabled_`). If `bft_enabled = false`, no BFT-mode block can be produced (producer skips the BFT branch) and no BFT-mode block can be validated (validator rejects with "BFT block but bft_enabled=false at genesis" at `src/node/validator.cpp:396-397`). The chain operates strictly in MUTUAL_DISTRUST; under-quorum scenarios that would otherwise have escalated instead stall until R7 merge fires (after `merge_threshold_blocks` consecutive sub-quorum blocks) or the operator restores nodes.

The genesis-hash binding closes the cross-operator-disagreement attack: two nodes with different `bft_enabled` values would compute different genesis hashes and would refuse to join the same chain at startup. ∎

### T-2 (Gate 2 — Abort-Threshold Soundness)

**Setup.** Let `total_aborts = |current_aborts_|` (producer) or `|b.abort_events|` (validator) be the count of abort events at the current height pre-finalize (producer) or recorded in the block under validation (validator). Let `bft_escalation_threshold ∈ uint32_t` be the genesis-pinned threshold (default 5, configurable per profile via `GenesisConfig::bft_escalation_threshold`). The threshold is mirrored into `cfg_.bft_escalation_threshold` and `BlockValidator::bft_escalation_threshold_`.

**Theorem.** Escalation soundness requires `total_aborts >= cfg.bft_escalation_threshold`. This rejects "immediate escalation" attacks where an adversary tries to flip to BFT mode without the chain having actually experienced sustained K-of-K failure. The threshold provides operator-tunable patience: too low (e.g., `1`) lets transient single-validator hiccups trigger escalation; too high (e.g., `100`) lets the chain stall for a long sequence of aborts before recovering.

**Proof.** Direct from the AND-conjunct at the producer (`src/node/node.cpp:776`: `&& total_aborts >= cfg_.bft_escalation_threshold`) and the validator (`src/node/validator.cpp:241`: `&& i >= bft_escalation_threshold_` in the per-event reconstruction; and `src/node/validator.cpp:398-401` in the block-sig branch). If `total_aborts < threshold`, the producer cannot escalate; if a block carries `consensus_mode = BFT` but `b.abort_events.size() < threshold`, the validator rejects with the explicit error message "BFT block with insufficient aborts (X < Y)". The gate is enforced on both sides.

The `AbortEvent` mechanism guarantees that `total_aborts` increases by 1 only when an M-1 quorum of committee members co-signs an `AbortClaimMsg` (verified at `src/node/validator.cpp:266-289`). An adversary cannot unilaterally inflate the abort count without forging M-1 signatures, which is bounded by Ed25519 EUF-CMA at `≤ 2⁻¹²⁸` per attempt. The threshold gate is therefore sound against the adversarial abort-injection model. ∎

**Worked example.** With `threshold = 5`, three transient aborts (a producer pause, a peer disconnect, a brief network split) do not escalate. By the fifth sustained abort, the chain has spent ~5 × `tx_commit_ms + block_sig_ms + abort_claim_ms` wallclock time (e.g., 5 × ~10s = ~50s on regional profile) in unsuccessful K-of-K attempts; this is operationally enough to confirm that K-of-K is not making progress, so the escalation fires. Threshold = 1 would have escalated after the first transient abort, undesirably converting MD safety into BFT safety; threshold = 50 would have stalled the chain for ~10 minutes before any recovery.

### T-3 (Gate 3 — Pool-Insufficiency Soundness)

**Setup.** Let `avail_domains` be the producer's eligible-pool view at the current height after applying the regional filter and the R4/R7 partner-subset extension and removing aborted nodes. Let `k_target` be the genesis-pinned target committee size (typically `k_target = K = cfg_.k_block_sigs` in single-shard mode, or `k_target = cfg_.k_block_sigs` adjusted for the regional partner-subset under R4). The validator's reconstruction at `src/node/validator.cpp:113-117` builds the same pool view from the registry.

**Theorem.** Escalation soundness requires `|avail_domains| < k_target`. This rejects escalation when K-of-K is *still feasible* — i.e., the pool is large enough to form a full K-committee but the producer is failing to gather signatures for some other reason. Escalating in that case would prematurely convert unconditional FA1 safety into conditional FA5 safety without operational necessity.

**Proof.** Direct from the AND-conjunct at the producer (`src/node/node.cpp:774`: `if (avail_domains.size() < k_target` ...). The pool view `avail_domains.size()` is computed from the registry's eligible-in-region pool minus aborted-this-height domains; with `|avail_domains| >= K`, the protocol can still pick a K-tuple uniformly via S-020 hybrid Fisher-Yates (`crypto::select_m_creators`) and run K-of-K. The escalation predicate's short-circuit at `src/node/node.cpp:774` prevents BFT mode in that regime.

When `|avail_domains| >= K` but the chain is still aborting, the abort-event mixing into the committee-selection seed (`src/node/node.cpp:791-793`: `rand = SHA256Builder{}.append(rand).append(ae.event_hash).finalize()` for each abort) re-rotates the committee to skip the failed members. This is the FA3 selective-abort recovery — within K-of-K, persistent aborters are rotated out and the round retries with a fresh K-tuple. Only when the rotation exhausts the pool (|pool| < K) does gate 3 fire.

Forgery attack: the adversary tries to make the producer see `|avail_domains| < K` when it actually equals K, to force premature escalation. The pool is computed from the registry — an authoritative chain-state view. The adversary cannot reduce the registry's eligible-in-region count without deregistering a real validator (which costs the validator's stake) or planting a fake AbortEvent (which requires forging M-1 signatures, bounded by EUF-CMA at `≤ 2⁻¹²⁸`). The gate is sound. ∎

**Worked example.** With K=5 and a pool of 6 eligible validators: a single validator goes silent and gets aborted. `|avail_domains| = 5 = K`. Gate 3 does NOT fire — K-of-K can still form. A second validator goes silent. `|avail_domains| = 4 < K = 5`. Gate 3 fires; combined with gates 1+2+4, escalation engages with `k_bft = ⌈10/3⌉ = 4`, and the committee shrinks to 4 with `Q = ⌈8/3⌉ = 3`.

### T-4 (Gate 4 — BFT-Viability Soundness)

**Setup.** Let `k_bft = (2K + 2) / 3` (the integer-arithmetic equivalent of `⌈2K/3⌉` used at `src/node/node.cpp:771` and `src/node/validator.cpp:98`). Let `|avail_domains|` be the same pool view as in T-3.

**Theorem.** Escalation soundness requires `|avail_domains| >= k_bft`. This rejects escalation when even the BFT-shrunk committee is not viable — i.e., the pool is too small to form `k_bft` signers. In that regime, the proper recovery is R7 under-quorum merge (`S036UnderQuorumMerge.md`), not BFT escalation. The 4-gate predicate's gate 4 explicitly abstains from BFT in that case and lets R7 fire instead.

**Proof.** Direct from the AND-conjunct at the producer (`src/node/node.cpp:777`: `&& avail_domains.size() >= k_bft`). If the pool is below `k_bft`, the predicate fails and the round stays in MUTUAL_DISTRUST briefly, then the `if (avail_domains.size() < k_use) return;` short-circuit at `src/node/node.cpp:781` makes the round abort (the local node simply does not produce contribs). After `merge_threshold_blocks` such failures accumulate, the operator-monitored beacon side initiates R7's MERGE_BEGIN event (per `S036UnderQuorumMerge.md`), the partner shard absorbs the refugees, and the merged shard resumes K-of-K operation with the combined pool.

The validator side mirrors at `src/node/validator.cpp:242`: `&& avail.size() >= k_bft` in the per-event reconstruction. A block claiming `consensus_mode = BFT` with `|avail_domains| < k_bft` at the producer time would have a pool history that the validator cannot reproduce — the validator's check_creator_selection (`src/node/validator.cpp:96-132`) computes the expected committee from the registry + abort history, and would yield a different K-tuple than the block claims, causing V7 (creator selection) to fail.

The adversarial case: the adversary tries to flip into BFT mode below the `k_bft` floor to avoid R7 (perhaps to keep the shard nominally independent while the captured-pool partner absorbs it). Gate 4 rejects this at the producer; the validator's mirror rejects the resulting block. The composition with R7 closes the recovery surface — when gate 4 abstains, R7 takes over. ∎

**Worked example.** With K=6 and `k_bft = (12 + 2) / 3 = 4`: pool drops from 6 to 5 (gate 3 fails, no escalation needed); pool drops to 4 (gate 3 fires, gate 4 satisfied at exactly the floor, escalation to BFT with `k_bft = 4` committee and `Q = ⌈8/3⌉ = 3`); pool drops to 3 (gate 4 fails, escalation abstains, R7 fires after the merge threshold).

### T-5 (Gate-Conjunction Composition — Necessary and Sufficient)

**Theorem.** Define the 4-gate predicate `E(h)` at height `h` as:

```
E(h) ≡ cfg.bft_enabled
       AND total_aborts(h) >= bft_escalation_threshold
       AND |avail_domains(h)| < k_target(h)
       AND |avail_domains(h)| >= k_bft
```

where `total_aborts(h) = |current_aborts_at(h)|` (producer) or `|b.abort_events|` (validator); `avail_domains(h)` is the regional-filtered eligible pool minus excluded aborters; `k_target(h)` is the genesis-K (or R4-shrunk variant); `k_bft = (2K + 2) / 3`. Then BFT-mode escalation at height `h` is sound if and only if `E(h)` holds.

**Proof.**

*Necessity* (E(h) is required). By T-1 through T-4, each gate individually must hold for soundness:
- ¬ gate 1: the chain runs strict MUTUAL_DISTRUST; any BFT block is rejected by V8.
- ¬ gate 2: the chain has not experienced sustained K-of-K failure; escalating prematurely converts FA1 unconditional safety into FA5 conditional safety without operational necessity.
- ¬ gate 3: K-of-K is still feasible; escalating prematurely makes the same trade without necessity.
- ¬ gate 4: even BFT is not viable; the proper recovery is R7 merge.

Each failure of a single gate falls outside the soundness envelope.

*Sufficiency* (E(h) implies soundness). When E(h) holds:
- Gate 1 ensures the chain's policy admits BFT.
- Gate 2 ensures the operational necessity has been confirmed (sustained abort signal).
- Gate 3 ensures K-of-K is genuinely infeasible (pool below K).
- Gate 4 ensures BFT is genuinely viable (pool at or above `k_bft`).

The producer flips to BFT mode (`k_use = k_bft, round_mode = ConsensusMode::BFT`). The validator's V8 BFT branch (`src/node/validator.cpp:395-401`) re-checks gates 1 and 2 (`bft_enabled_` + `total_aborts >= bft_escalation_threshold_`) before applying the BFT `Q = ⌈2 k_bft / 3⌉` quorum check; the per-event abort-cert reconstruction at `src/node/validator.cpp:240-244` re-checks all four gates at each abort step. Both sides agree on the predicate's truth value at every event because they evaluate the same formula against the same inputs (genesis-pinned `bft_enabled`, mirrored `bft_escalation_threshold`, deterministic `k_bft = (2K + 2) / 3`, registry-derived `avail_domains`, abort-event-counted `total_aborts`).

Once flipped, FA5's safety hypothesis space is in scope: the block carries `consensus_mode = BFT`, the committee has size `|K_h| = k_bft`, the validator enforces `|S(B)| >= Q`, and the FA5 T-5 theorem holds under `f_h < |K_h|/3`. Once flipped, FA4's liveness hypothesis space is also in scope: the round can finalize with `|K_h| − Q` sentinel positions absorbing further silent members, restoring bounded-time progress. ∎

### T-6 (Safety Preservation)

**Theorem.** When E(h) holds and the round produces a valid BFT-mode block `B` at height `h`, FA5 T-5's safety hypothesis (B1: `f_h < |K_h|/3` within the BFT committee + B2: equivocation slashing enforced) is the precise hypothesis under which safety holds. The 4-gate trigger does not weaken FA5; it only places the chain into FA5's scope.

**Proof.** Per FA5 / `BFTSafety.md`:
- A1 (Ed25519 EUF-CMA) is independent of the trigger.
- A2 (SHA-256 collision resistance) is independent of the trigger.
- B1 (`f_h < |K_h|/3` within the BFT committee `K_h` of size `k_bft`) depends only on the committee selection, which uses the same S-020 hybrid Fisher-Yates that selects the K-of-K committee in MUTUAL_DISTRUST mode (just with a smaller target size). The honest-validator distribution in the pool transfers to the smaller committee with the same uniformity guarantee (`S020CommitteeSelection.md` T-1).
- B2 (equivocation slashing) is independent of the trigger; the FA6 slashing pipeline operates regardless of consensus mode.

The 4-gate trigger therefore preserves FA5's safety surface exactly. There is no path from E(h) to a BFT-mode block under conditions weaker than FA5 expects, because:
- The validator's BFT branch (`src/node/validator.cpp:395-401`) rechecks gates 1 + 2.
- The validator's per-event reconstruction (`src/node/validator.cpp:240-244`) rechecks all four gates.
- The block's `consensus_mode` field is signed into `compute_block_digest` (per `src/node/producer.cpp::compute_block_digest`: `h.append(static_cast<uint8_t>(b.consensus_mode))`), so any mismatch between mode and the producer's view causes V8 to reject. ∎

### T-7 (Liveness Restoration)

**Theorem.** When E(h) holds and the round flips to BFT mode, FA4 / `Liveness.md` L-4.3's BFT-mode finalize condition becomes operative: the round finalizes with `|S(B)| >= Q` signatures from the `k_bft`-committee, where `Q = ⌈2 k_bft / 3⌉`. The remaining `k_bft − Q` slots accommodate sentinel-zero signatures for silent members. Bounded-time progress is restored.

**Proof.** Per FA4 / `Liveness.md` L-4.3: under the BFT-mode finalize condition, the round finalizes at most `tx_commit_ms + block_sig_ms + abort_claim_ms` wallclock time after the producer issues its Phase-1 contrib (the same timing budget as MUTUAL_DISTRUST mode, but with relaxed quorum so it actually succeeds). The K-shrink from K to `k_bft` reduces the cardinality the producer needs to gather signatures from; the Q-shrink from k_bft to Q within that smaller committee further relaxes the requirement to `⌈2 k_bft / 3⌉` non-zero signatures.

Operational example at K=6: under MUTUAL_DISTRUST the producer needs 6/6 signatures from a 6-member committee. Under BFT (after E(h) fires): 3/4 signatures from a 4-member committee. The 4-member committee is selected from the pool (size now `< K = 6` and `>= k_bft = 4`), so the smaller committee picks honestly-distributed members; under the FA5 B1 hypothesis (`f_h ≤ 1` at K=6), the 3/4 quorum has at least 2 honest signers, which suffices for FA5's L-5.1 quorum intersection.

The sustained abort rate diminishes once BFT escalation engages: members previously aborting because the K-of-K threshold could not be met now sign the BFT-mode block (their participation satisfies the lower quorum). The chain resumes block production at the genesis-pinned cadence with `current_aborts_` clearing on each finalized BFT block. ∎

**Combined T-5 + T-6 + T-7.** Sound escalation (T-5) preserves safety (T-6) and restores liveness (T-7). The 4-gate predicate is a transition policy that moves the chain from one operational regime to another without breaking the safety/liveness composition; it does not introduce a new safety condition or a new liveness condition; it places the chain into the scope of the appropriate already-proved theorem (FA1 vs FA5 + FA4).

---

## 3. Adversary model

The adversary model A1 through A4 partitions the attack surface for the 4-gate predicate. Each adversary attempts to break one of the four soundness conditions; the gates compose to defeat each.

### A1 — `A_premature` (force premature escalation)

**Goal.** Flip the chain into BFT mode while K-of-K is still feasible, in order to downgrade safety from FA1 unconditional to FA5 conditional.

**Capability.** The adversary controls up to `f < N/3` validators in the pool (or, in the worst case, has captured a small operator's network so they appear to "abort" maliciously). They cannot forge ed25519 signatures (bounded by A1 EUF-CMA at `≤ 2⁻¹²⁸`) and cannot manipulate the registry directly (registry state is consensus-derived).

**Attack vector.** Two sub-paths:
- A1a: inject fake `AbortEvent`s to inflate `total_aborts` above the threshold. Defeated by V10 (abort-cert validator at `src/node/validator.cpp:172-298`) — every AbortEvent requires an M-1 quorum of valid AbortClaimMsg signatures; the adversary cannot synthesize them without ed25519 forgery.
- A1b: induce real aborts on adversary-controlled validators to inflate the count. Defeated by gate 3 — the pool size remains `>= K` if the adversary-controlled validators are the only aborters, so K-of-K is still feasible and gate 3 short-circuits the predicate. The adversary cannot escalate without also reducing the pool below K.

**Disposition.** Defeated by gate 2 + gate 3 conjunction. ∎

### A2 — `A_late` (force late escalation)

**Goal.** Prevent the chain from escalating despite a sustained K-of-K failure, to keep the chain stalled.

**Capability.** Same as A1 — bounded-stake adversarial validators + network manipulation. The adversary cannot mutate genesis fields after chain birth.

**Attack vector.** Two sub-paths:
- A2a: tamper with `cfg.bft_escalation_threshold` post-genesis to a very high value (e.g., `UINT32_MAX`). Defeated by the A5 PARAM_CHANGE pipeline — mutations require operator-co-signed PARAM_CHANGE transactions through the M-of-N keyholder gate (`Chain::stage_param_change` at `src/chain/chain.cpp:212-217`). The adversary would need a quorum of keyholders' signatures, which is outside their adversarial budget.
- A2b: prevent `total_aborts` from incrementing by, e.g., suppressing AbortClaimMsg gossip. The adversary can delay individual AbortClaimMsg messages but cannot prevent all delivery in a finite synchrony model (FA0). The threshold is bounded; once enough aborts accumulate, the predicate fires.

**Disposition.** The attack is bounded by the operator-chosen `bft_escalation_threshold`. An honest operator picks a value small enough that the chain escalates within an operational time budget but large enough that transient failures don't trigger. F-1 below discusses tuning guidance. ∎

### A3 — `A_pool_forge` (gate-3 bypass via pool-size manipulation)

**Goal.** Make the producer see `|avail_domains| < K` when it actually equals K (force premature escalation by faking pool exhaustion).

**Capability.** Same as A1 + A2.

**Attack vector.** Two sub-paths:
- A3a: inject fake `register` / `deregister` transactions to reduce the registry's eligible-in-region count. Defeated by the registry's authoritative apply (`src/chain/chain.cpp::apply_transactions` REGISTER/UNREGISTER cases) — registry mutations require valid sigs over canonical tx bodies, bounded by ed25519 EUF-CMA.
- A3b: forge `AbortEvent`s against honest validators (so they appear in `excluded` set, reducing `|avail_domains|`). Defeated by V10 same as A1a — abort-cert validation rejects unsigned/wrong-signed AbortClaimMsgs.

**Disposition.** Defeated by FA1 K-of-K integrity + V10 abort-cert validation. The producer cannot fake the pool size below the actual count without forging consensus state. ∎

### A4 — `A_quorum_skip` (gate-4 bypass attempting sub-`k_bft` BFT)

**Goal.** Escalate to BFT mode even when the pool is too small to form `k_bft` signers, i.e., bypass R7's recovery path to keep the shard nominally independent (perhaps to delay a merge with an unfriendly partner).

**Capability.** Same as A1-A3 + the adversary controls the producer's network (a partition or routing attack that hides the true pool size locally).

**Attack vector.** The adversary tries to flip `current_round_mode_ = BFT` and produce a block with `|creators| < k_bft`. The block must satisfy:
- V7 (creator selection): the validator reconstructs the committee from the registry + aborts. If `|avail_domains| < k_bft` per the validator's view, the committee selection yields fewer than `k_bft` indices and V7's `if (avail_domains.size() < m)` check at `src/node/validator.cpp:118-119` rejects.
- V8 (block sigs): for `consensus_mode = BFT` with `m < k_bft`, the validator's `bool bft_ok = (b.consensus_mode == ConsensusMode::BFT) && (m == k_bft)` check at `src/node/validator.cpp:101` rejects because `m ≠ k_bft`.

**Disposition.** Defeated by gate 4 + V7 + V8. The producer-validator mirror at gate 4 means any locally-faked pool size diverges from the registry's authoritative count, and the block is rejected. R7 fires as the proper recovery. ∎

---

## 4. Lemmas

### L-1 (Gate 1 enforcement: producer + validator + V8 redundancy)

The `bft_enabled` flag is checked at three sites: the producer's escalation predicate at `src/node/node.cpp:775`, the validator's per-event reconstruction at `src/node/validator.cpp:240`, and the validator's V8 BFT branch at `src/node/validator.cpp:396-397`. Any flag mismatch between producer and validator is caught at any of the three sites. The triple redundancy is intentional — the V8 branch independently checks `bft_enabled_` so that even if the per-event reconstruction logic has a future bug, a `bft_enabled = false` chain cannot accept any BFT block.

### L-2 (Gate 2 admissibility: `total_aborts` is monotone-bounded)

Within a single height attempt (the producer's `current_aborts_`), `total_aborts` can only increase across abort events. Each AbortEvent is rooted in an M-1 quorum of AbortClaimMsg signatures (V10), so the count cannot be unilaterally inflated. The validator's per-event reconstruction at `src/node/validator.cpp:222-244` walks the block's `abort_events` in order, advancing the abort count `i` and rechecking the predicate at each step. The block's `abort_events.size()` at validation time equals the producer's `current_aborts_.size()` at the moment of finalization because the block carries the full abort history.

### L-3 (Gate 3 admissibility: `|avail_domains|` is a deterministic function of registry + aborts)

The pool view `avail_domains` is computed identically on producer (`src/node/node.cpp:752-761`) and validator (`src/node/validator.cpp:111-117`). Both compute `registry.eligible_in_region(committee_region_)` (R2 regional filter), extend by `shards_absorbed_by(shard_id_)` (R7 partner extension), and remove `excluded` aborters. The output is bit-identical between producer and validator given the same registry state and abort history. There is no producer-validator divergence to exploit.

### L-4 (Gate 4 admissibility: `k_bft` is a deterministic function of K)

`k_bft = (2K + 2) / 3` is integer arithmetic; it is the canonical integer-rounding-up formula for `⌈2K/3⌉`. Producer (`src/node/node.cpp:771`) and validator (`src/node/validator.cpp:98`, `:218`) compute the identical value. There is no producer-validator divergence.

### L-5 (Gate-conjunction necessity)

If any of the four gates fails, the predicate fails. The AND-short-circuit at the producer (`src/node/node.cpp:774-777`) means no BFT-mode block is produced. The triple-check at the validator (per-event reconstruction at `src/node/validator.cpp:239-242`; V7 creator selection size check at `src/node/validator.cpp:96-107`; V8 BFT branch threshold check at `src/node/validator.cpp:395-401`) means no BFT-mode block is accepted. The conjunction is necessary at both ends.

### L-6 (Gate-conjunction sufficiency)

When all four gates hold, the producer escalates and the validator agrees (per L-1 through L-4 admissibility lemmas). The block carries `consensus_mode = BFT` and `|creators| = k_bft`. The validator's V7 check accepts because `m = k_bft == (2K + 2) / 3`; V8 accepts under the BFT branch with `required = ⌈2 k_bft / 3⌉` non-zero signatures; subsequent V9 / V11 / V12 / V13 checks operate identically to MUTUAL_DISTRUST mode (the committee subset just happens to be smaller). The conjunction is sufficient at both ends.

### L-7 (Safety hypothesis transfer)

When E(h) holds and the round flips to BFT, the resulting block falls under FA5's hypothesis space:
- B1 (`f_h < |K_h|/3`) is independent of the 4-gate predicate; it depends on the adversary's stake distribution and the committee selection (S-020 uniformity).
- B2 (slashing enforced) is independent of the 4-gate predicate; it depends on the FA6 pipeline being operational.

The 4-gate trigger does not weaken these hypotheses; it places the chain into the regime where these hypotheses are the operative safety conditions. No additional hypothesis is imported.

### L-8 (Liveness hypothesis transfer)

Symmetric to L-7: when E(h) holds and the round flips to BFT, FA4's bounded-time-progress hypothesis becomes operative. The round finalizes in at most `tx_commit_ms + block_sig_ms + abort_claim_ms` time with the relaxed `Q-of-k_bft` quorum. The 4-gate trigger does not weaken the liveness hypothesis; it makes the relaxed quorum the operative finalize condition.

---

## 5. Cross-references

| Companion | Role in the composition |
|---|---|
| `Preliminaries.md` (F0) | H1–H4 honest-validator assumptions; §2.1 SHA-256; §2.2 ed25519 EUF-CMA; §3 committee-selection contract; §4–§5 validation rule names V7/V8/V9. |
| `Safety.md` (FA1) | K-of-K unconditional safety under H1. The 4-gate trigger preserves FA1 when E(h) is false (no escalation, K-of-K stays in scope). |
| `BFTSafety.md` (FA5) | BFT-mode conditional safety theorem under `f_h < |K_h|/3` + slashing. The 4-gate trigger places the chain into FA5's hypothesis space when E(h) is true. |
| `Liveness.md` (FA4) | Liveness across both modes; L-4.3 BFT-mode finalize condition. T-7 above is the trigger-side preservation of FA4. |
| `CommitteeSelection.md` (FA1+FA8) | K-of-K parent proof for the committee selection that the 4-gate trigger does not modify. |
| `S020CommitteeSelection.md` (S-020) | Hybrid Fisher-Yates uniformity inside the K or `k_bft` committee selection — the smaller `k_bft` committee inherits the same uniformity guarantee. |
| `S024EpochBlocks.md` (S-024) | Epoch-cadence + PARAM_CHANGE composition. `bft_escalation_threshold` is mutable mid-chain via the same PARAM_CHANGE pipeline that mutates `epoch_blocks`. |
| `S036UnderQuorumMerge.md` (R7) | Under-quorum merge mechanism. Gate 4 abstains when `|avail_domains| < k_bft`, deferring to R7. |
| `RegionalSharding.md` (FA8) | Region-aware overlay; the pool composition that feeds `avail_domains`. |
| `EquivocationSlashing.md` (FA6) | The slashing recovery the FA5 conditional-safety proof leans on. The 4-gate trigger does not alter FA6's hypothesis space. |
| `GovernanceParamChange.md` (A5) | PARAM_CHANGE pipeline that staged-activates `bft_escalation_threshold` mutations. The genesis-pinned `bft_enabled` is NOT mutable via PARAM_CHANGE in v1.x. |
| `docs/PROTOCOL.md` §5.3 | BFT escalation gate wire specification — the four gates are documented at the protocol-spec level. |
| `docs/SECURITY.md` §S-030, §S-035 | Closure context for the abort-driven escalation surface; the 4-gate trigger is the production code's resolution. |
| `docs/V2-DESIGN.md` §v2.10 | Future threshold-randomness composition for the BFT-mode within-committee proposer election — keeps the 4-gate trigger semantics intact, refines the within-BFT seed entropy. |

---

## 6. Findings

### F-1 — Gate-2 threshold tuning per operator profile

The default `bft_escalation_threshold = 5` (`src/chain/genesis.cpp:173`) sits at the middle of the operationally-sound regime. Profile-specific tuning recommendations:

| Profile | Block cadence | Recommended threshold | Worst-case stall time |
|---|---|---|---|
| `tactical` | 20 ms blocks | 3 | ~3 × 0.05 s = ~0.15 s |
| `single_test` | 50 ms blocks | 5 (default) | ~5 × 0.125 s = ~0.6 s |
| `regional` | 300 ms blocks | 5 (default) | ~5 × 0.75 s = ~4 s |
| `global` | 600 ms blocks | 5 (default) | ~5 × 1.5 s = ~7.5 s |
| Operator-tuned high-availability | varies | 2-3 | minimized stall |
| Operator-tuned safety-priority | varies | 10-20 | accepts longer stall to avoid escalation under intermittent network issues |

The "worst-case stall time" is the wallclock duration the chain may spend in MUTUAL_DISTRUST mode while accumulating the threshold count of aborts before escalating. Operators choosing a high value accept that the chain may stall longer; operators choosing a low value accept that transient hiccups (e.g., a single 1-second peer disconnect) can flip blocks into BFT mode. Most operators leave the default.

### F-2 — Gate-3 pool-recovery semantics (current: BFT mode persists for the round)

When the predicate fires and the round flips to BFT, the round produces a BFT-mode block. The *next* round (height h+1) re-evaluates the predicate from scratch — if the pool has recovered (a validator returned online, or aborts have cleared), the predicate may evaluate to `false` and the next block runs in MUTUAL_DISTRUST.

Current behavior: `current_round_mode_` is reset to `MUTUAL_DISTRUST` at the start of each new round attempt (`src/node/node.cpp:773-779` re-initializes `round_mode = ConsensusMode::MUTUAL_DISTRUST` before the predicate check). The mode is per-round, not per-epoch — pool recovery at height h+1 immediately returns the chain to K-of-K. This is intentional for operational simplicity; an alternative design where BFT mode persists for the entire epoch was considered but rejected because it would unnecessarily extend the FA5 conditional-safety regime past its operational need.

No "sticky BFT" mode exists in v1.x. The 4-gate predicate is reevaluated every round, giving the chain fine-grained control over when to drop back into the stronger FA1 safety regime.

### F-3 — Operator misconfiguration considerations

The 4-gate predicate has four operator-tunable inputs (`bft_enabled`, `bft_escalation_threshold`, `k_block_sigs` indirectly through `k_target`, and the `k_bft` formula which is fixed). Misconfiguration scenarios:

- **`bft_enabled = false` + small pool:** the chain stalls indefinitely under pool exhaustion below K with no recovery from BFT escalation. The operator inherits R7 under-quorum merge as the sole recovery path (which has its own threshold cadence) or must manually restore validators. This is a *deliberate* operator choice for chains where the FA1 unconditional safety is non-negotiable; it is documented at `docs/PROTOCOL.md` §5.3 + `docs/SECURITY.md` §S-030.
- **`bft_escalation_threshold = 0`:** the predicate fires on the first abort, immediately escalating to BFT mode at the first sign of K-of-K trouble. Operators should pick at least 1 to require evidence of *sustained* failure; the default of 5 gives reasonable headroom. The validator does NOT reject `threshold = 0` blocks (such a block would have `total_aborts ≥ 0` trivially satisfied) — the genesis JSON loader accepts any `uint32_t` value; operator discipline is the only guard. T-2 above formalizes the threshold's role but does not pin a minimum value.
- **`bft_escalation_threshold = UINT32_MAX`:** the predicate effectively never fires; the chain stalls indefinitely under sustained K-of-K failure. Same operator-discipline issue as the previous bullet.
- **`k_block_sigs = 1` or `k_block_sigs = 2`:** `k_bft = (2K + 2) / 3 = (4) / 3 = 1` for K=1 and `(6) / 3 = 2` for K=2. The escalation is degenerate (BFT committee size equals K committee size); the predicate cannot fire because gate 3 (`|pool| < K`) and gate 4 (`|pool| >= k_bft = K`) are mutually exclusive (the pool cannot be both `< K` AND `>= K`). At small K, BFT escalation is not a useful recovery mechanism; R7 merge is the only path.
- **`k_block_sigs = 3`:** `k_bft = 2`; the predicate can fire when the pool is exactly 2 (escalation to BFT with `Q = ⌈4/3⌉ = 2` — but `2 = k_bft`, so all 2 must sign, which is degenerate). At K=3, BFT mode is operationally identical to a K=2 K-of-K mode under FA5's `f_h = 0` floor.
- **`k_block_sigs >= 6`:** the BFT mechanism is non-degenerate and provides genuine Byzantine tolerance. K=6 (`k_bft = 4`, `Q = 3`) tolerates `f_h ≤ 1`; K=9 (`k_bft = 6`, `Q = 4`) tolerates `f_h ≤ 1`; K=12 (`k_bft = 8`, `Q = 6`) tolerates `f_h ≤ 2`.

Operators picking K should size for both the FA1 safety floor and the FA5 Byzantine tolerance they desire. K=3 is acceptable for low-adversary deployments; K=6+ is recommended for any chain expecting non-trivial Byzantine threat. The 4-gate trigger's correctness does not depend on K, but its operational usefulness scales with K above 3.

---

## 7. Test surface

The 4-gate predicate is exercised by both an integration test (full chain across multiple nodes, real escalation under induced failure) and an in-process unit test (closed-form arithmetic of the `required_block_sigs` quorum formula).

### 7.1 `tools/test_bft_escalation.sh` (integration)

Three-node mesh with K=3, `bft_enabled = true`, `bft_escalation_threshold = 1` (lowered from the default 5 to accelerate test time). The script:
1. Starts three nodes, builds genesis, configures peers.
2. Polls until the chain advances past block 3 in MUTUAL_DISTRUST mode (pre-kill height).
3. Kills node3 (one of the three committee members).
4. Polls for up to 30s for a BFT-mode block to appear (`consensus_mode = 1` in the chain JSON).
5. PASS if at least one BFT-mode block is produced; the `bft_proposer` is one of the live nodes (node1 or node2).
6. PASS if K-of-K aborts then escalates to BFT with `k_bft = 2`, `Q = 2`.

Exercises the 4-gate predicate end-to-end: gate 1 (`bft_enabled = true`), gate 2 (`total_aborts ≥ 1`), gate 3 (`|avail_domains| = 2 < K = 3`), gate 4 (`|avail_domains| = 2 ≥ k_bft = 2`). All four gates fire; the round flips to BFT; the FA5 hypothesis space is in scope; the chain finalizes a BFT block.

### 7.2 `tools/test_required_block_sigs.sh` (unit)

Closed-form arithmetic of the `required_block_sigs(mode, committee_size)` function in 14 assertions across 11 scenarios. Verifies:
- `MD(k) == k` for k in {1, 2, 3, 5, 9}
- `BFT(1) == 1`, `BFT(2) == 2` (degenerate)
- `BFT(3) == 2`, `BFT(4) == 3`, `BFT(5) == 4`, `BFT(6) == 4`, `BFT(7) == 5`, `BFT(9) == 6` (the concrete `⌈2k/3⌉` values from the FA5 worked examples)
- Invariant: `BFT(k) ≤ MD(k)` for all `k ∈ [1, 16]` — BFT can never require MORE signatures than MD (would defeat the escalation's purpose)
- Determinism: pure function (same inputs → same output)

Defends against drift in the formula that would either over-tighten (liveness break — escalation can't actually fire) or under-tighten (safety break — BFT quorum too small for `f < N/3` safety). The in-process invocation is `determ test-required-block-sigs`.

### 7.3 In-process round-trip coverage

The producer-validator-mirror invariant (L-1 through L-4 admissibility lemmas + T-5 composition) is exercised by every in-process test that produces a BFT-mode block — the producer's `Node::check_if_selected` and the validator's `BlockValidator::check_creator_selection` + `check_block_sigs` run in the same process and must agree at every step. Any divergence would be caught by V7 or V8 failing on the producer-emitted block.

The PARAM_CHANGE pipeline for `bft_escalation_threshold` mutation is covered by `tools/test_param_change_threshold.sh` (the A5 governance integration test) — the staged-activation ensures producer and validator agree on the post-activation value at the same height.

---

## 8. References

The BFT-mode escalation mechanism in Determ is a per-round application of the standard Byzantine-fault-tolerance literature combined with the protocol's K-of-K core. The key external references:

- Castro, M. & Liskov, B. (1999). "Practical Byzantine Fault Tolerance." OSDI '99 — the `Q = ⌈2f + 1 / 3⌉` quorum arithmetic in modern BFT systems. Determ's BFT mode uses the corresponding `Q = ⌈2 k_bft / 3⌉` form on a shrunk committee `k_bft = ⌈2K / 3⌉`.
- Lamport, L., Shostak, R., & Pease, M. (1982). "The Byzantine Generals Problem." ACM TOPLAS 4(3) — the foundational impossibility result and the `f < N/3` Byzantine fraction bound that FA5 / `BFTSafety.md` invokes.
- Bracha, G. & Toueg, S. (1985). "Asynchronous Consensus and Broadcast Protocols." JACM 32(4) — the underlying asynchronous-system safety reasoning that supports the per-round trigger semantics.
- Dwork, C., Lynch, N., & Stockmeyer, L. (1988). "Consensus in the Presence of Partial Synchrony." JACM 35(2) — the partial-synchrony model that frames Determ's `tx_commit_ms` / `block_sig_ms` / `abort_claim_ms` timing budget.
- Castro, M. (2001). "Practical Byzantine Fault Tolerance." Ph.D. thesis, MIT — the detailed treatment of view changes and the threshold logic that informs Determ's 4-gate predicate design.

The Determ-specific composition — the 4-gate predicate as an atomic transition policy that places the chain into one of two already-proved safety regimes (FA1 or FA5) — is, to the authors' knowledge, novel in the literature on hybrid K-of-K / BFT consensus systems. The mechanism is closer in spirit to the "view change" of PBFT than to the "round change" of HotStuff or the "epoch advance" of Tendermint, but it is rooted in a sustained-abort-rate observation rather than a leader-timeout observation. The composition is documented here for the first time as a formal soundness theorem.

---

## 9. Conclusion

The 4-gate predicate at `src/node/node.cpp:773-780` is the load-bearing transition policy that determines which of Determ's two proved safety regimes (FA1 unconditional K-of-K or FA5 conditional BFT) is in scope at any given block height. The four gates — `bft_enabled` + `total_aborts ≥ threshold` + `|pool| < K` + `|pool| ≥ k_bft` — must hold simultaneously for sound escalation; partial conjunctions break in characteristic ways defeated by the adversary model A1 through A4. The producer-validator mirror at three checkpoints (per-event reconstruction + creator-selection size check + V8 BFT branch threshold) ensures byte-for-byte agreement between block production and block validation.

Once the predicate fires (T-5), the chain transitions to BFT mode, the FA5 safety hypothesis space becomes operative (T-6), and the FA4 liveness condition is restored under the relaxed `Q-of-k_bft` quorum (T-7). The transition does not introduce a new safety or liveness condition; it places the chain into the scope of the appropriate already-proved theorem. When the predicate fails to fire (E(h) false), the chain stays in MUTUAL_DISTRUST and remains under FA1's unconditional safety guarantee.

Operator tuning of the threshold (F-1) and pool-recovery semantics (F-2) shape the operational behavior but do not affect the soundness theorems. Misconfigurations (F-3) impose operational risk on the deploying operator but do not break the chain's safety or liveness in the formal sense — they only widen or narrow the operational regime in which the 4-gate predicate makes the chain progress.

The proof composes with FA1, FA4, FA5, FA6, FA8, S-020, S-024, and S-036 to give Determ's full transition-policy story: every block is either an MD-mode block (FA1 in scope), a BFT-mode block (FA5 in scope), a no-progress no-block (R7 about to fire per `S036UnderQuorumMerge.md`), or a refugee-shard block under the R7 merge mechanism. The 4-gate predicate is the explicit Boolean function that decides which category each height attempt lands in.
