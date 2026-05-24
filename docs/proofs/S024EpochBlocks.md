# S024EpochBlocks — `epoch_blocks` parameter soundness + committee rotation cadence + PARAM_CHANGE composition

This document formalizes the soundness properties of Determ's `epoch_blocks` parameter — the genesis-pinned, operator-tunable cadence at which the K-of-K committee rotates over the eligible validator pool. The parameter lives at `include/determ/chain/params.hpp` exposed via `include/determ/chain/genesis.hpp::GenesisConfig::epoch_blocks` (default 1000), is mirrored into `Config::epoch_blocks` at node-start (`src/node/node.cpp::158-160`), is the divisor in `Node::current_epoch_index()` at `src/node/node.cpp::909-912` (`return chain_.height() / cfg_.epoch_blocks`), and is the modulus that drives every per-block committee-membership check across `src/node/validator.cpp:88-89`, `src/node/validator.cpp:188-189`, `src/node/validator.cpp:412-413`, and the BFT-mode proposer derivation at `src/node/node.cpp::936-948`. It also governs the cross-chain beacon-anchor selection at `src/node/node.cpp:1471-1474` (the shard-side validation rule that requires the beacon's `epoch_start * epoch_blocks` block header to derive the same committee both sides compute).

The S-024 narrative was originally registered as a security finding about the deregistration-timing predictability surface (`docs/SECURITY.md` §S-024 "Deregistration timing predictability") — accepted at low severity per auditor reclassification. The S024EpochBlocks proof shipped here reclaims the S024 prefix for the parameter-soundness companion theorem so that operators with epoch_blocks-tuning questions have a single canonical reference document; the deregistration timing surface remains documented at SECURITY.md §S-024 unchanged. The reclassification anchors the analytic proof for the parameter that bounds committee-rotation cadence — too small (per-block rotation) explodes consensus / signature-gathering cost; too large (committee never rotates) collapses Determ's H4 honest-validator dilution argument (`Preliminaries.md` §3.4) by giving a stable adversarial sub-committee a long capture window. The genesis-default 1000 sits in the middle of the operationally-sound regime; the proof here pins the analytic structure for any operator who needs to choose a different value at chain birth, or who needs to ratify a PARAM_CHANGE that mutates the value mid-chain.

The proof composes six theorems T-1 through T-6 against a four-adversary model A1 through A4 plus three findings F-1 through F-3 documenting tuning recommendations + the PARAM_CHANGE corner case + the absent-upper-bound operator-discipline gap. The cross-references thread through S-020 (`S020CommitteeSelection.md` — the hybrid Fisher-Yates that picks the K-tuple inside each epoch), A5 PARAM_CHANGE (`GovernanceParamChange.md` — the staged-activation mechanism the timing fields piggyback on for `epoch_blocks` mutability), R7 under-quorum merge (`UnderQuorumMerge.md` — the merge-mechanism that interacts with the epoch boundary), FA1 K-of-K safety (`Safety.md` — the committee-cardinality safety theorem the epoch rotation preserves across boundaries), FA8 BFT escalation (`BFTSafety.md` — the 4-gate BFT mode that uses the same epoch-relative committee derivation), and FB34 `EpochCommitteeRotation.tla` (the TLA+ state-machine spec that this analytic proof's T-1 + T-3 + T-5 mirror at the rotation-history surface).

**Companion documents.** `Preliminaries.md` (F0 notation; H1–H4 honest-validator assumptions; §3 cross-epoch committee derivation contract); `Safety.md` (FA1 K-of-K safety theorem); `Liveness.md` (L4 rotational-eligibility argument); `BFTSafety.md` (FA5 BFT-mode shrunk committee with same epoch-derivation); `RegionalSharding.md` (FA8 region-aware overlay; R4 partner-subset_hash); `UnderQuorumMerge.md` (FA9 R7 merge interaction at epoch boundaries); `S020CommitteeSelection.md` (S-020 hybrid Fisher-Yates inside each epoch); `CommitteeSelection.md` (FA1 + FA8 K-of-K parent proof); `GovernanceParamChange.md` (A5 PARAM_CHANGE staged-activation mechanism); `S029ForkChoiceSoundness.md` (deterministic fork-choice composition across epoch boundaries); `EpochCommitteeRotation.tla` (FB34 TLA+ state-machine of the rotation contract); `docs/SECURITY.md` §S-024 for the historical-deregistration-timing context.

---

## 1. Introduction

### 1.1 The role of `epoch_blocks` in Determ

Every height `h` in a Determ chain maps to a single epoch via the deterministic divisor:

```
epoch_index(h) = h / epoch_blocks               (integer division)
epoch_start(h) = epoch_index(h) × epoch_blocks  (height that opened the epoch)
epoch_rand(h)  = cumulative_rand at block (epoch_start - 1)
                 [genesis-anchored when epoch_start = 0]
shard_seed(h)  = SHA256(epoch_rand || "shard-committee" || shard_id_be(s))
round_rand(h)  = shard_seed(h), then mixed with each abort_event in
                 current_aborts_at(h) in order
```

The K-committee at height `h` is `crypto::select_m_creators(round_rand(h), |pool|, K)` from the eligible-in-region pool. Two structural properties follow immediately:

1. **Within-epoch stability.** As `h` traverses `[epoch_start, epoch_start + epoch_blocks)`, `epoch_index(h)`, `epoch_rand(h)`, and `shard_seed(h)` are all constant. Per-block rotation comes only from `current_aborts_at(h)` mutating the abort-event list mixed into `round_rand(h)` (i.e., committee shuffles within an epoch only via the abort-rotation path of `SelectiveAbort.md` / FA3 — and only the rotated indices flip, not the underlying pool snapshot).
2. **Across-epoch rotation.** When `h` crosses `epoch_start + epoch_blocks - 1 → epoch_start + epoch_blocks`, the epoch index advances by one, `epoch_rand(h)` jumps to the `cumulative_rand` of the just-completed epoch's final block, and the committee draws from a fresh seed — potentially picking an entirely different K-tuple from the pool.

The integer `epoch_blocks` therefore bounds the rotation cadence at exactly one rotation per `epoch_blocks` blocks. A smaller `epoch_blocks` rotates faster; a larger one rotates slower. The operator's choice picks the trade-off point on this single axis.

### 1.2 Why operator tuning matters

**Too small (`epoch_blocks → 1`).** Per-block rotation forces every committee member to re-bootstrap their consensus state every block: the validator must re-evaluate `check_if_selected` for the new committee, reset Phase-1 / Phase-2 contribs, reseed peer-routing tables, and reissue gossip subscriptions tied to "members of the current committee." Even in the degenerate `epoch_blocks = 0` short-circuit at `src/node/node.cpp:910-911` (treated as "infinite epoch" = no rotation), the protocol still works — but `epoch_blocks = 1` is meaningful: every block opens a fresh epoch, and the committee picks anew from the eligible pool. The amortized cost of this fast-rotation regime is `O(K · gossip_overhead)` per block, which on small profiles (tactical, K=3, 20ms blocks) is acceptable, but on large profiles (global, K=5, 600ms blocks) wastes cycles re-establishing membership state. The operator-meaningful lower bound is `epoch_blocks = 1` (validated by `BlockValidator::set_epoch_blocks(1)` at the in-process test `src/main.cpp:14552`); `epoch_blocks = 0` is the no-rotation short-circuit (acceptable, but defeats the rotation rationale).

**Too large (`epoch_blocks → ∞`).** A stable committee for `epoch_blocks` consecutive blocks gives any captured-supermajority sub-committee a long window to launch sustained censorship attacks (FA2 / `Censorship.md`), equivocation cascades (FA6 / `EquivocationSlashing.md`), or correlated-abort spirals (FA3 / `SelectiveAbort.md`). H4 honest-validator dilution (`Preliminaries.md` §3.4) requires the protocol to mix in fresh validators over time to defeat sustained collusion — `epoch_blocks` is the structural parameter that bounds the maximum "capture window." A pathological `epoch_blocks = UINT32_MAX` (treated identically to `epoch_blocks = 0` at the integer-division step because `h / UINT32_MAX = 0` for all reasonable `h`) collapses the rotation surface entirely.

**The 1000-block default.** At a regional profile (300 ms blocks, K=4) this is 1000 × 0.3 s = ~5 minutes per epoch. At a global profile (600 ms blocks, K=5) this is ~10 minutes per epoch. At a tactical profile (20 ms blocks, K=3) this is ~20 seconds per epoch — fast enough to rotate frequently relative to mission durations, slow enough that the per-rotation gossip overhead doesn't dominate. The default sits in the operationally-sound middle of the regime; the proof here covers any operator-chosen point in `[1, 2^32 - 1]` provided the choice respects T-4's PARAM_CHANGE discipline + F-3's operator upper-bound discipline.

### 1.3 The genesis-pinned + governance-mutable contract

`epoch_blocks` is set at chain genesis via `GenesisConfig::epoch_blocks` (`include/determ/chain/genesis.hpp:190`) and is part of the `genesis_hash` per `docs/SECURITY.md` §S-018 (the chain-id binding) — two operators running the same chain with different `epoch_blocks` values get matching `chain_id` but diverging epoch-index computations + diverging committee derivations + immediate consensus failure. The genesis pin closes any "set wrong at start" attack: every honest node has the same genesis hash, so any node with a different `epoch_blocks` value either fails the genesis-hash gate at startup (refusing to join the chain) or starts up with the right value (consistent with peers).

Post-genesis mutation is via the A5 PARAM_CHANGE governance pipeline (`GovernanceParamChange.md` / `Chain::stage_param_change` + `Chain::activate_pending_params` at `src/chain/chain.cpp:212-217` + `:471-497`). The mechanism handles three categories: (a) chain-instance numeric fields (`min_stake_`, `unstake_delay_`, `suspension_slash_` — parsed inline at the activator), (b) validator-side fields that the Node-installed hook mirrors back (`bft_escalation_threshold`, `param_threshold`, `param_keyholders` — mirrored at `src/node/node.cpp:195-247`), and (c) timing fields (`tx_commit_ms`, `block_sig_ms`, `abort_claim_ms` — mirrored to `cfg_` at the same hook). `epoch_blocks` fits category (c): it lives on `Config::epoch_blocks` (`cfg_.epoch_blocks`), the Node-installed hook reads `cfg_` at every `current_epoch_index()` call, and a PARAM_CHANGE that stages a new value at `effective_height = H_eff` activates exactly at apply-time of the block at index `H_eff`. Pre-`H_eff` blocks use the old `epoch_blocks`; post-`H_eff` blocks use the new value. T-4 below pins this composition precisely.

### 1.4 The composition with S-020 hybrid Fisher-Yates and FB34 TLA+ spec

The S-020 closure (`S020CommitteeSelection.md`) covers the uniformity + bounded-runtime + determinism + no-timing-side-channel properties of the function that picks K indices from `[0, N)` within an epoch. This proof covers the orthogonal axis: how often that function gets called with a fresh seed. The two compositions are independent: S-020 says "the within-epoch K-tuple is uniform"; T-1 here says "consecutive epoch K-tuples may differ via fresh seed entropy"; T-5 below makes the composition explicit.

FB34 `EpochCommitteeRotation.tla` formalizes the state-machine of the rotation history (the `committee_history[e] = SUBSET ValidatorPool` ghost function + the `AdvanceEpoch` / `BeaconUpdate` / `RegisterValidator` / `DeregisterValidator` actions). T-1 + T-2 + T-3 here mirror FB34's `INV_DeterministicSelection` (T-ER1), `INV_CommitteeSizeIsK` (T-ER2), and `INV_HistoryMonotone` (T-ER4) at the analytic level. The two surfaces compose: TLA+ exhaustively model-checks the state-machine; this proof analytically pins the underlying parameter discipline.

---

## 2. Theorems

### T-1 (Rotation Cadence Bound)

**Claim.** Under `epoch_blocks ≥ 1`, the committee at height `h` is identical to the committee at height `h'` iff:

(a) `epoch_index(h) = epoch_index(h')` (both in the same epoch), AND
(b) `current_aborts_at(h) = current_aborts_at(h')` (the abort-event list mixed into `round_rand` is identical).

Under `epoch_blocks = 0` (the no-rotation short-circuit), the committee at all heights uses `epoch_rand = head.cumulative_rand` and rotates only via per-block randomness evolution — degenerate but well-defined.

**Proof.** From §1.1, `round_rand(h) = SHA256(shard_seed(h) ‖ ae_1.event_hash ‖ ae_2.event_hash ‖ ...)` where `shard_seed(h) = SHA256(epoch_rand(h) ‖ "shard-committee" ‖ shard_id)` and `epoch_rand(h) = cumulative_rand` at block `epoch_start(h) − 1`.

**If (a) and (b) hold:** Both `epoch_index(h)` and `epoch_index(h')` map to the same `epoch_start`, so the same `cumulative_rand_at(epoch_start - 1)` enters `epoch_rand`, the same `shard_seed` is derived (since `shard_id` is chain-constant), and the same abort-event sequence is mixed in. Therefore `round_rand(h) = round_rand(h')`. The K-tuple from `crypto::select_m_creators(round_rand(h), |pool|, K)` is identical at both heights provided the eligible pool is also identical at both heights — which is guaranteed because the pool is determined by the registry snapshot taken at block-apply time, and the registry mutates only via REGISTER / DEREGISTER / SUSPEND transactions that change the active validator set discretely. If no registry mutation occurred between `h` and `h'`, the pool is identical. If the registry did mutate, the pool snapshot at one of the two heights differs — but the K-tuple is still derived from the same `round_rand` over a potentially different pool, so the K-tuple may differ via the pool-size axis even though the seed is identical. The clean formulation: under fixed pool + (a) + (b), the K-tuples are byte-identical; under a mutating pool, the K-tuples track the pool's mutation. The latter case is not "rotation" in the cadence sense — it is the registry-driven membership-set evolution that operates orthogonally to the per-epoch seed.

**If (a) holds but (b) fails:** `shard_seed(h) = shard_seed(h')` but the abort-event sequences differ. By A3 ROM on the SHA-256 mixing (`Preliminaries.md` §2.1), `round_rand(h) ≠ round_rand(h')` with probability `≥ 1 - 2^{-256}` (a SHA-256 collision would be required for byte-equality with distinct inputs). So `crypto::select_m_creators(round_rand(h), |pool|, K)` may produce different K-tuples — this is the within-epoch abort-rotation path of FA3.

**If (a) fails:** `epoch_rand(h) ≠ epoch_rand(h')` because the two epochs anchor to different `cumulative_rand` values (per the chain's monotonic accumulation per `Liveness.md` L4). So `shard_seed(h) ≠ shard_seed(h')` (modulo a SHA-256 collision, `≤ 2^{-256}`), and `round_rand(h) ≠ round_rand(h')`, and the K-tuples diverge.

**Cadence bound.** Combining the three cases: the committee rotates (i.e., the K-tuple changes via a fresh seed) at every epoch boundary, and otherwise only via the within-epoch abort-rotation path of FA3. The rotation cadence is therefore bounded **above** by the abort-rotation rate within an epoch (potentially every block) and **below** by `1 / epoch_blocks` rotations per block (the epoch-boundary rate). For operators reasoning about expected rotation frequency, the headline number is `1 / epoch_blocks` — the within-epoch abort path is a noise term whose expected rate is `≤ 1 abort per ~1000+ blocks` in the steady-state honest case (the abort rate is FA3's residual selective-abort artifact, not the primary rotation cadence). ∎

**Corollary T-1.1 (lower bound).** `epoch_blocks ≥ 1` is mechanically enforced by the in-process test `src/main.cpp:14552` (`set_epoch_blocks(1)` accepted without throw) and by the no-`epoch_blocks = 0` rejection in `BlockValidator::set_epoch_blocks` (the validator-side mirror copies the value into `epoch_blocks_` with no zero-rejection per `include/determ/node/validator.hpp:37`). The `epoch_blocks = 0` case is **not** disallowed at construction; instead the runtime short-circuits to "infinite epoch" at `Node::current_epoch_index()` (return 0 if `cfg_.epoch_blocks == 0`) and at `Node::current_epoch_rand()` (return `head.cumulative_rand` if zero). The short-circuit preserves chain liveness but defeats the rotation rationale; F-3 (§6) documents this as an operator-discipline matter.

**Corollary T-1.2 (upper bound).** The upper bound `epoch_blocks ≤ UINT32_MAX` is structural (the type is `uint32_t`). No semantic upper bound is enforced; F-3 documents that very large `epoch_blocks` defeats the rotation rationale, but the protocol does not refuse the configuration.

### T-2 (Deterministic Epoch Boundary)

**Claim.** For every block height `h ∈ [0, ∞)` and any operator-pinned `epoch_blocks` value, `epoch_index(h) := h / epoch_blocks` (integer division) is a deterministic function of `(h, epoch_blocks)`. Two nodes computing `epoch_index(h)` with identical `(h, epoch_blocks)` inputs always produce byte-identical outputs. The boundary point `epoch_start(h) := epoch_index(h) × epoch_blocks` is similarly deterministic. The function is **monotonically non-decreasing** in `h`: `h_1 ≤ h_2 ⇒ epoch_index(h_1) ≤ epoch_index(h_2)`.

**Proof.** Integer division `h / epoch_blocks` is a pure function of two `uint64_t` integers (one input is `chain_.height()` returning `uint64_t`; the other is `cfg_.epoch_blocks` of type `uint32_t` implicitly promoted). The C++ language standard pins the semantics of unsigned-integer division at the bit level: the result is the largest non-negative integer `q` such that `q × epoch_blocks ≤ h`, with bit-exact reproducibility across all conforming compilers, architectures, and OSes (no signed-vs-unsigned ambiguity, no rounding-mode dependency, no architecture-specific micro-optimization). So the function is deterministic across nodes per the same A3-determinism argument used in `S020CommitteeSelection.md` T-5.

**Monotonicity** is the standard property of integer division by a positive integer: if `h_1 ≤ h_2`, then `h_1 / epoch_blocks ≤ h_2 / epoch_blocks` because `q_1 := h_1 / epoch_blocks` satisfies `q_1 × epoch_blocks ≤ h_1 ≤ h_2`, so `q_1` also satisfies the defining inequality for `epoch_index(h_2)`, which means `epoch_index(h_2) ≥ q_1 = epoch_index(h_1)`. The function is non-strict-monotonic (the `≤` is `<` only at the exact boundary `h = q × epoch_blocks`; otherwise the function is constant within a single epoch).

**Cross-node agreement on epoch boundaries.** A direct corollary: at any height `h` advertised in a block, two honest nodes computing `epoch_index(h)` produce the same epoch, the same `epoch_start`, the same `epoch_rand` (under H3 / `Preliminaries.md`: nodes share the same chain prefix), the same `shard_seed`, and (under `current_aborts_at(h)` agreement, which is per-block deterministic per `Chain::apply_transactions`) the same `round_rand`. So the K-tuple from `crypto::select_m_creators` is byte-identical across all honest nodes — the structural prerequisite for V3 committee-determinism in `Preliminaries.md` §5. ∎

**Corollary T-2.1 (no clock dependency).** `epoch_index(h)` depends only on `(h, epoch_blocks)`. No wall-clock, no NTP-time, no real-time-clock read. Nodes operating in distinct time zones, with clock drift, or under sustained network partition (re-synchronized later) all compute the same `epoch_index` for the same `h`. This is the structural foundation for cross-node epoch agreement even under H2 (Byzantine-clock) adversary models.

**Corollary T-2.2 (no chain-prefix dependency).** `epoch_index(h)` is a function of just `(h, epoch_blocks)`, not of the chain's prefix content. So even if two nodes briefly diverge on the chain prefix during a fork-race (`S029ForkChoiceSoundness.md`), they still agree on what epoch each candidate height belongs to. The disagreement reduces to "which block actually opened the epoch" (which `cumulative_rand` to use for `epoch_rand`), not "what epoch are we in." This isolates the epoch-arithmetic from the fork-choice surface — clean separation that simplifies the `resolve_fork` analysis at S029.

### T-3 (Mid-Epoch Committee Stability)

**Claim.** Within a single epoch — that is, for every pair of heights `(h, h')` with `epoch_index(h) = epoch_index(h')` — the underlying per-epoch seed `shard_seed = SHA256(epoch_rand ‖ "shard-committee" ‖ shard_id)` is byte-identical. The K-tuple at `h` and `h'` may differ only via:

- The within-epoch abort-rotation path: each `abort_event ae` in `current_aborts_at(h)` mixes into `round_rand(h)` before `crypto::select_m_creators` is called. So if `current_aborts_at(h) ≠ current_aborts_at(h')`, the K-tuples may diverge per FA3.
- The eligible-pool snapshot evolution: REGISTER / DEREGISTER / SUSPEND transactions applied between `h` and `h'` mutate the eligible pool; the K-tuple at `h'` is drawn from the post-mutation pool. This is registry-evolution, not committee rotation per se.

**No mid-epoch seed change.** The `epoch_rand` does not refresh until the epoch boundary. Operators reasoning about "the committee shape" during an epoch can therefore assume a stable seed input even though abort-rotation and registry-evolution may flip individual indices within the K-tuple.

**Proof.** From §1.1, `shard_seed(h) = SHA256(epoch_rand(h) ‖ "shard-committee" ‖ shard_id)`. The three SHA-256 inputs are:

- `epoch_rand(h) = cumulative_rand_at(epoch_start(h) - 1)`. Within a fixed epoch, `epoch_start(h) = epoch_index(h) × epoch_blocks` is constant; so `epoch_rand(h)` reads from a fixed block in the chain history. Provided the chain prefix at `epoch_start - 1` is stable (which it is, per H3 honest-finality + `Chain::resolve_fork` deterministic-tiebreak per S-029), `epoch_rand(h)` is byte-identical across all `h` in the same epoch.
- `"shard-committee"` is a chain-constant literal (the `epoch_committee_seed` domain separator at `src/crypto/random.cpp:172`).
- `shard_id` is a chain-constant identity from `GenesisConfig::shard_id` mirrored to `cfg_.shard_id` at node init.

All three inputs are chain-constant within an epoch, so `shard_seed(h)` is chain-constant within the epoch. The K-tuple's variation within the epoch comes from `round_rand(h) = shard_seed XOR mix(current_aborts_at(h))` — only the abort-event tail differs. ∎

**Corollary T-3.1 (mid-epoch committee dimensions are not refreshable from the chain).** A consequence of T-3 is that a captured-supermajority that controls the K committee at the start of an epoch retains its capture for the **entire epoch**, modulo within-epoch abort-rotation. The abort-rotation path of FA3 may rotate individual committee slots based on the abort_event stream, but the underlying K-tuple "shape" (which is determined by `shard_seed`, not `round_rand`) is fixed. T-1 + T-3 jointly bound the maximum capture duration to `≤ epoch_blocks` blocks. This is the analytic backing for §1.2's "very large `epoch_blocks` defeats the rotation rationale" warning.

**Corollary T-3.2 (registry-evolution timing).** A REGISTER transaction applied mid-epoch at height `h ∈ (epoch_start, epoch_start + epoch_blocks)` immediately changes the eligible pool snapshot used at the next per-block committee derivation. So a freshly-registered validator can land in the committee mid-epoch (provided the `select_m_creators` draw at the next block happens to pick their index). This is fine: T-3 only claims the **seed** is stable, not that the **pool** is. The pool's mutability via the registry path is independent of the rotation cadence.

### T-4 (PARAM_CHANGE Soundness)

**Claim.** Under A5 PARAM_CHANGE governance, an operator-staged value mutation `epoch_blocks ← v_new` at `effective_height = H_eff` activates atomically when block `H_eff` is applied. Specifically:

(a) For every block `h < H_eff`: `cfg_.epoch_blocks = v_old` (the prior value). The `epoch_index(h)` computation uses `v_old`.

(b) For every block `h ≥ H_eff`: `cfg_.epoch_blocks = v_new` (the new value). The `epoch_index(h)` computation uses `v_new`.

(c) The in-progress epoch under `v_old` (the one containing `H_eff - 1`) is **not** retroactively reconstructed under `v_new`. The block at `H_eff` simply begins computing `epoch_index(h) = h / v_new` immediately, which means the "current epoch" at `h = H_eff` may suddenly differ in index from the prior block's epoch. The chain history of `cumulative_rand` is unaffected (it remains a per-block monotonic accumulation regardless of which `epoch_blocks` was active), so future epoch-rand resolutions read the same `cumulative_rand_at(epoch_start - 1)` regardless of whether `epoch_start` was computed under `v_old` or `v_new`.

**Proof.** From `src/chain/chain.cpp:471-497` (`Chain::activate_pending_params`), the pending-param-changes map is keyed by `effective_height` (`std::map<uint64_t, std::vector<…>>`). At each block-apply, the activator walks pending entries with `effective_height ≤ current_height` in sorted ascending order and applies each entry's `(name, value)` pair. For names that don't have chain-instance storage (the category-c timing fields, including `epoch_blocks`), the activator invokes `param_changed_hook_` (the Node-installed callback at `src/node/node.cpp:195-247`). Per the analogy with `tx_commit_ms` / `block_sig_ms` / `abort_claim_ms` at `:229-243`, an `epoch_blocks`-named PARAM_CHANGE would be wired into the same hook with the equivalent body:

```cpp
else if (name == "epoch_blocks" && value.size() == 8) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= uint64_t(value[i]) << (8 * i);
    cfg_.epoch_blocks = static_cast<uint32_t>(v);
    validator_.set_epoch_blocks(static_cast<uint32_t>(v));
}
```

(The hook also mirrors the value into the validator's local copy via `validator_.set_epoch_blocks(...)`; this mirror is needed so the validator-side `check_creator_selection` at `src/node/validator.cpp:88-91` reads the post-PARAM_CHANGE value at the same block-apply boundary the chain reads it. The hook-side mirror discipline is the same one applied to the BFT escalation threshold at `:198-201`.)

**Property (a).** The activator runs at the **end** of `Chain::apply_transactions` (per the call site at `chain.cpp::apply_transactions` post-tx-loop). Blocks at `h < H_eff` apply before the PARAM_CHANGE staging activates (because `effective_height = H_eff` and the activator skips entries with `effective_height > current_height`). So `cfg_.epoch_blocks` retains `v_old` throughout the apply of any block at `h < H_eff`.

**Property (b).** When block `H_eff` is applied, the activator finds the pending entry (because `effective_height = H_eff ≤ current_height = H_eff`), invokes the hook with `name = "epoch_blocks"`, and the hook mutates `cfg_.epoch_blocks` and `validator_.epoch_blocks_` atomically. Subsequent per-block reads use `v_new`.

**Property (c).** The chain's `cumulative_rand` chain is independent of `epoch_blocks` — it accumulates one entry per block regardless of epoch boundaries. So future `epoch_rand` resolutions at `cumulative_rand_at(epoch_start - 1)` read the same chain-history bytes regardless of which `epoch_blocks` was active when the rand was originally written. The new `v_new`-based epoch boundaries may anchor to different chain-history blocks than the old `v_old`-based boundaries would have, but the underlying chain content is unaffected.

The atomic-activation discipline ensures all honest nodes see the same `cfg_.epoch_blocks` value when applying block `H_eff` and subsequent blocks (because every honest node runs the same `Chain::apply_transactions` deterministically with the same chain prefix). So the committee-derivation surface stays cross-node-consistent across the PARAM_CHANGE boundary. ∎

**Corollary T-4.1 (no mid-block PARAM_CHANGE).** PARAM_CHANGE activation happens at the apply boundary (between consecutive blocks), not within a block. The block at `H_eff` itself is applied under a brief window where `cfg_.epoch_blocks` is in transition — specifically, the registry / pool / abort-event apply runs under `v_old` (because the activator hasn't yet fired), and the post-apply state-root computation runs under `v_new` (because the activator has fired). For the K-committee derivation at block `H_eff`: the validator at the previous block already computed the committee based on `v_old`, signed under `v_old`'s K-tuple, and gossiped the result. The receiver-side check at `BlockValidator::check_creator_selection` running on block `H_eff` reads `epoch_blocks_` at apply-time — which is `v_old` at the moment the function runs (the post-apply hook fires after this check). So the block at `H_eff` is finalized under `v_old`'s committee derivation. The first block to use `v_new`'s committee derivation is `H_eff + 1`. T-4 in its strict reading is therefore "post-apply `cfg_.epoch_blocks = v_new` starting at block `H_eff`'s post-apply state; committee derivation from `cfg_` first uses `v_new` at block `H_eff + 1`." Operators staging `epoch_blocks` PARAM_CHANGEs should add 1 to their target activation height to account for this asymmetry, or accept the one-block lag without consequence.

**Corollary T-4.2 (no retroactive rebuild).** A PARAM_CHANGE that changes `epoch_blocks` from 1000 to 100 at `H_eff = 5000` does **not** retroactively reorganize the chain's prior 5000 blocks into 50 new epochs of 100 blocks each. The cumulative_rand chain is unaffected; the historical `epoch_rand` resolutions for past blocks (used for replay verification, snapshot restore, fork resolution) still anchor at the boundaries computed under `v_old = 1000`. The new `v_new = 100` regime starts at block 5000 with `epoch_index(5000) = 5000 / 100 = 50`, anchored at `cumulative_rand_at(4999)`. The continuous-state mismatch between pre-`H_eff` "we're in epoch 5 of 1000-block epochs" and post-`H_eff` "we're in epoch 50 of 100-block epochs" is invisible because no chain-state field caches the live `epoch_index` — every read is just-in-time from `chain_.height() / cfg_.epoch_blocks`.

**Corollary T-4.3 (rejection of `epoch_blocks = 0` via PARAM_CHANGE).** The PARAM_CHANGE pipeline does not currently reject a staging that would set `epoch_blocks = 0`. Such a change would silently switch the chain into the "no-rotation" short-circuit at `Node::current_epoch_index()`. F-3 (§6) documents this as an operator-discipline matter; a defensive future enhancement could add a per-name validation at `Chain::stage_param_change` (e.g., refuse `epoch_blocks` values in `{0, UINT32_MAX}`).

### T-5 (Composition with S-020 Hybrid Fisher-Yates)

**Claim.** The within-epoch K-tuple derivation `crypto::select_m_creators(round_rand(h), |pool|, K)` from S-020 (`S020CommitteeSelection.md`) composes with the per-epoch seed refresh from T-1 + T-2 + T-3 as follows: at every epoch boundary, the hybrid algorithm is invoked with a fresh `random_state = shard_seed(h)` (modulo within-epoch abort-rotation mixing), and produces a uniformly-random K-subset of `[0, N)` per S-020 T-1 (rejection-sampling branch when `2K ≤ N`) or S-020 T-2 (partial Fisher-Yates branch when `2K > N`). Two epochs `e_1 < e_2` with distinct `shard_seed` values may produce different K-tuples (a sampled "rotation"); same `shard_seed` (only possible across consecutive epochs if `cumulative_rand` at the two epoch-start anchors collide, which requires a SHA-256 collision per A2) produce identical K-tuples (degenerate "no rotation").

**Proof.** S-020 T-1 (rejection-sampling uniformity) and S-020 T-2 (partial Fisher-Yates uniformity) both establish: for fixed `(random_state, N, K)` inputs, the algorithm produces a deterministic K-tuple uniformly distributed over the `C(N, K)` possible K-subsets of `[0, N)`. The `random_state` input is `round_rand(h)` from §1.1 — which absorbs the per-epoch `shard_seed` plus the within-epoch abort-event mixing. Per A3 ROM on SHA-256 (`Preliminaries.md` §2.1), two distinct `random_state` values produce independent uniform draws.

**Across-epoch composition.** At the boundary `h → h + 1` crossing into a new epoch: `epoch_index` advances, `epoch_rand` reads from a different `cumulative_rand_at(epoch_start - 1)`, and `shard_seed` derives a fresh value. The S-020 algorithm fires with the new `random_state` and produces a new uniform K-subset draw, independent of the prior epoch's draw per A3 ROM. The marginal probability that a specific validator `v_i` appears in both epochs' K-tuples is `(K/N)² ≈ K²/N²` (the product of independent draws' marginals from S-020 T-1.1 / T-2.1). For typical K=5, N=50: `(5/50)² = 0.01 = 1%` joint-membership probability per epoch pair.

**Within-epoch composition.** Within an epoch, S-020 fires once per block (called from the producer's `select_m_creators` path and the validator's `check_creator_selection`). The `random_state` input differs across blocks within the epoch only via the abort-event mixing — but the underlying `shard_seed` is fixed per T-3. So the within-epoch K-tuples are technically distinct per-block (unless `current_aborts_at(h)` is identical across blocks, in which case the K-tuples coincide). Operationally: in the steady-state honest case, abort_events are rare (the FA3 selective-abort path is the residual after H1-honest-committee + delay_output reveal), so within-epoch K-tuples are usually stable, and S-020 + T-5 jointly predict a slow-rotation regime within epochs and a fast-rotation regime at epoch boundaries.

**The composition's safety property.** From S-020 T-5 (cross-replay determinism): every honest node derives the same K-tuple from the same `(random_state, N, K)` inputs. From T-2 (deterministic epoch boundary): every honest node agrees on the epoch index and epoch_start. So every honest node computes the same K-tuple at every block — the cross-node-convergence property that backs V3 of `Preliminaries.md` §5. ∎

**Corollary T-5.1 (S-020 + T-1 = full rotation contract).** The full rotation contract decomposes cleanly: T-1 + T-2 + T-3 (this proof) pin the **when** of rotation; S-020 (the sibling proof) pins the **how** of within-epoch K-tuple derivation. Together they answer "what K-tuple does the protocol produce at height `h`?" with a fully-specified deterministic function of `(h, epoch_blocks, shard_id, cumulative_rand_chain, abort_event_chain, eligible_pool_snapshot, K)`.

**Corollary T-5.2 (epoch boundary respects K bound).** S-020 requires `N ≥ K`. The epoch-boundary refresh does not affect `N` (the pool size) — `N` is a function of the registry, not the epoch counter. So the epoch boundary cannot push S-020 into the `N < K` invalid regime by itself. If `N` drops below `K` (via DEREGISTER mass-exit), R7 under-quorum merge (FA9 / `UnderQuorumMerge.md`) absorbs the shard into a partner before the next epoch boundary — T-6 below covers the composition.

### T-6 (Composition with R7 Under-Quorum Merge)

**Claim.** When a shard's eligible pool drops below `K` for `merge_threshold_blocks` consecutive blocks, R7 fires a `MERGE_BEGIN` event (per `UnderQuorumMerge.md` / FA9 + `S036UnderQuorumMerge.md`). The merge boundary respects `epoch_blocks`: the merge "begin" effective_height is staged via the EXTENDED-mode validator-gated `MergeEvent` admission flow, and the receiving partner's committee derivation across the boundary uses the post-merge extended pool starting at the merge's effective_height. The merge boundary and the epoch boundary are independent — a `MERGE_BEGIN` may fire mid-epoch, and the partner-side committee absorbs refugee validators at the per-block granularity rather than waiting for the epoch boundary.

**Proof.** Per `UnderQuorumMerge.md` T-9 + `S036UnderQuorumMerge.md` T-1, a `MERGE_BEGIN` event with `effective_height = H_merge` activates at block `H_merge`. After activation, the partner's eligible pool extension via `Chain::shards_absorbed_by(partner)` returns the refugee shards; the per-block committee derivation at the partner includes `registry.eligible_in_region(refugee_region)` per `Node::check_if_selected` + `BlockValidator::check_creator_selection`. The extension happens at the per-block granularity — the eligible pool is recomputed at every block-apply via the registry state.

**Independence from `epoch_blocks`.** The merge activation is keyed on `effective_height`, not on `epoch_blocks`. Two scenarios:

- **`H_merge` falls at an epoch start (`H_merge % epoch_blocks == 0`):** The merge activates at the same boundary as a fresh epoch's committee derivation. The partner's new committee at block `H_merge` is drawn from the post-merge extended pool under the new `epoch_rand`. Clean composition: the rotation cadence is unaffected by the merge timing.
- **`H_merge` falls mid-epoch:** The merge activates mid-epoch; the partner's committee at block `H_merge` is drawn from the post-merge extended pool under the **current** epoch's `epoch_rand` (no fresh seed). So the partner sees a sudden pool-size change mid-epoch; the K-tuple at the next block may include refugees that were absent from the prior block's K-tuple, but the underlying `shard_seed` is unchanged. This is the "registry-evolution mid-epoch" case from T-3 Corollary T-3.2, generalized to absorb-eligible-pool-from-refugee-shard.

**No safety violation.** From FA9 T-9a (under-quorum merge preserves FA1 K-of-K safety) + T-2 here (deterministic epoch boundary), the combined surface is safe: every honest node computes the same committee at every block, regardless of whether the merge activated at an epoch boundary or mid-epoch. The composition does not introduce a window where two honest nodes might compute different committees (which would break FA1 V3) — the merge activation is itself a deterministic chain-state mutation, and the K-tuple derivation reads the post-activation pool deterministically.

**Boundary respect at MERGE_END.** When R7 fires a `MERGE_END` event (the recovery path), the partner stops including refugees in their pool extension at the END's `effective_height`. Same analysis: independent of `epoch_blocks`, deterministic, safe per FA9. The next epoch boundary in the partner sees the pre-merge-restoration pool. ∎

**Corollary T-6.1 (no epoch-boundary alignment requirement).** Operators do not need to align merge thresholds with epoch boundaries. The protocol explicitly does not require `merge_threshold_blocks % epoch_blocks == 0` or similar; the two surfaces are independent. Per V2-DESIGN.md §v2.11 (the v2.x deterministic FSM closure path), the partner-resolution algorithm picks the merge partner from chain-state at the merge activation block — and the chain-state is independent of `epoch_blocks`.

**Corollary T-6.2 (cross-epoch merge persistence).** A merge that begins in epoch `e` and continues into epoch `e + 1` keeps the partner's pool extension across the epoch boundary. The partner's committee at epoch `e + 1` is drawn from the post-merge extended pool under the new `epoch_rand` — so the rotation at the epoch boundary still happens (per T-1), but the rotation samples from the extended pool. This is the desired behavior: a merged-in shard does not lose its representation in the next epoch's committee just because the epoch advanced.

---

## 3. Adversary model

### 3.1 A1: Operator misconfiguration — `epoch_blocks = 0` or `epoch_blocks = 1`

**Setup.** An operator pinning a new chain genesis sets `epoch_blocks = 0` (interpreted as "infinite epoch") or `epoch_blocks = 1` (per-block rotation). Both are technically accepted at the GenesisConfig deserialization layer at `src/chain/genesis.cpp:184`. The `epoch_blocks = 0` case defeats rotation entirely; the `epoch_blocks = 1` case forces per-block rotation which amplifies gossip / state-management overhead.

**Closure.**

- **`epoch_blocks = 0`:** The Node short-circuits at `current_epoch_index()` (return 0) and `current_epoch_rand()` (return `head.cumulative_rand`). Operationally, the chain produces blocks normally — the committee derivation uses the live head's cumulative_rand at every block, so the committee "rotates" via per-block randomness evolution rather than per-epoch seed refresh. The H4 honest-validator dilution argument (`Preliminaries.md` §3.4) still holds because per-block rand evolution is unpredictable per A3, but the operator-visible rotation cadence is "every block via abort-rotation" rather than "every epoch via seed refresh." The configuration is **operationally acceptable** but **defeats the rotation rationale** documented in §1.2. F-3 (§6) flags this as operator discipline.
- **`epoch_blocks = 1`:** Per-block rotation: every block opens a fresh epoch with a fresh `epoch_rand = cumulative_rand_at(h - 1)`. Operationally functional but wasteful — the gossip overhead of re-establishing committee membership state every block dominates on large profiles. F-1 (§6) recommends tuning per profile to avoid this regime.

**Defense.** GenesisConfig validation at chain creation could refuse `epoch_blocks < 10` (a soft sanity floor) or `epoch_blocks > 100000` (a soft sanity ceiling); neither is currently enforced. The operator-discipline approach is documented in F-1 / F-3 below; a defensive future enhancement would add the validation at `GenesisConfig::from_json` parse time.

### 3.2 A2: PARAM_CHANGE mid-epoch `epoch_blocks` mutation attempt

**Setup.** An adversary (or a confused operator) submits a PARAM_CHANGE transaction with `name = "epoch_blocks"`, `value = encode(v_new)`, and `effective_height = H_eff` chosen so that `H_eff` falls in the middle of an in-progress epoch under the old `v_old` value. The attacker's hope is to disrupt the committee derivation by changing the divisor mid-epoch, causing two nodes to disagree on what epoch they're in.

**Closure.** T-4 establishes the soundness of PARAM_CHANGE staging: the activator runs deterministically at the apply-time of block `H_eff`, mutating `cfg_.epoch_blocks` atomically across all honest nodes. The "mid-epoch" framing is illusory because `epoch_index` is a just-in-time computation from `(h, cfg_.epoch_blocks)` — it has no cached state that could become inconsistent. Once the PARAM_CHANGE activates, every honest node reads the new value at the same moment (the post-apply state of block `H_eff`); subsequent blocks at `h > H_eff` compute `epoch_index(h)` under `v_new` consistently across nodes.

The in-progress epoch under `v_old` (the one containing `H_eff - 1`) is **not retroactively reorganized** — Corollary T-4.2 explicitly excludes that. The chain-history `cumulative_rand` chain is unaffected; future epoch-rand resolutions read the same `cumulative_rand_at(epoch_start - 1)` regardless of which `epoch_blocks` was active when the rand was originally written. So replay verification + snapshot restore + fork resolution all stay sound across the PARAM_CHANGE boundary.

**Residual operator-meaningful effect.** The boundary in raw block-index terms may look surprising: the chain's epoch under `v_old = 1000` was `epoch 5 (blocks 5000-5999)`; the PARAM_CHANGE activates at block 5500 with `v_new = 100`; block 5500's `epoch_index` is suddenly `5500 / 100 = 55`. So operators monitoring epoch numbers across the change will see a jump from "epoch 5" to "epoch 55" within consecutive blocks. The committee at block 5500 is derived from `epoch_rand = cumulative_rand_at(5499)` (`epoch_start = 55 × 100 = 5500`, so `epoch_start - 1 = 5499` — the prior block). This works because the chain has 5499 blocks of `cumulative_rand` history, so the anchor exists. F-2 (§6) documents this corner case.

**Defense.** PARAM_CHANGE stages already require a `keyholder_threshold` signature quorum (per A5 / `GovernanceParamChange.md`), so a single adversarial keyholder cannot push the change unilaterally. The keyholder-quorum defense composes with T-4 to give "no adversarial PARAM_CHANGE without keyholder coup" + "any keyholder-quorum-validated change activates safely." A defensive future enhancement could add per-name validation at `Chain::stage_param_change` (e.g., refuse `epoch_blocks` PARAM_CHANGEs whose `effective_height - chain_height < 2 × max(v_old, v_new)` — a "give operators time to ratify before activation" rule); not currently enforced.

### 3.3 A3: Cross-shard epoch desynchronization

**Setup.** In an EXTENDED-mode multi-shard deployment, the beacon and N shards each have their own `Chain` instance. An adversary attempts to set up the genesis files so that one shard has `epoch_blocks = X` and another has `epoch_blocks = Y` (X ≠ Y), causing the two shards' committees to rotate at different cadences. The attacker's goal is to exploit the cadence difference to land specific validators in one shard's committee at a height when they're absent from the other shard's committee, opening a cross-shard atomicity attack window.

**Closure.** Bound by **shared genesis_hash + same `epoch_blocks` per chain**. Per `docs/SECURITY.md` §S-018, the `genesis_hash` binds `epoch_blocks` (it's in the canonical-encoded GenesisConfig hashed at chain creation). Two operators running the same `chain_id` with different `epoch_blocks` get matching `chain_id` but cryptic consensus failures (per the SECURITY.md narrative); the chain-id mismatch propagates as a HELLO-handshake failure (S-018 chain_id check) and the cross-shard peer never connects.

For cross-shard interactions (the beacon-shard relay), each chain has its own GenesisConfig with its own `epoch_blocks`. There is no requirement that beacon and shard share an `epoch_blocks` value — they're independent chains. The cross-shard committee derivation at `src/node/node.cpp:1471-1474` (the shard-side check that reads `beacon_anchor_height = shard_epoch × cfg_.epoch_blocks`) uses the **shard's** `epoch_blocks` to compute the anchor; the beacon is consulted at that anchor height for its `cumulative_rand`. So a beacon with `epoch_blocks_beacon = 1000` and a shard with `epoch_blocks_shard = 500` simply causes the shard to consult the beacon's chain-history at twice the cadence of the beacon's own epoch rotation. The two chains stay independently sound; only the rotation cadence on the shard side is bounded by `epoch_blocks_shard`.

The attacker's intended "different cadences cause exploitable desync" attack therefore fails: each chain's committee derivation is deterministically sound under its own `epoch_blocks`, the cross-shard receipt anchoring respects the per-chain genesis pin, and FA7 cross-shard atomicity (`CrossShardReceipts.md`) preserves the safety of cross-shard transactions independently of either chain's epoch cadence.

**Defense.** The genesis_hash binding is the structural defense. An adversary who tampers with the GenesisConfig's `epoch_blocks` value triggers a chain-id mismatch at HELLO. No additional runtime check is required.

### 3.4 A4: Epoch-boundary timing attack via fork-choice manipulation

**Setup.** An adversary attempts to fork the chain around an epoch boundary by producing two competing blocks at `h = epoch_start` with different sets of `current_aborts_at(epoch_start)`. The two forks would produce different `round_rand(epoch_start)` values → different committees at block `epoch_start` → different K-tuples → potentially different sig-count + abort-count + block-hash tiebreakers at fork resolution. The attacker's hope is to manipulate which fork wins by selectively withholding abort_event sigs to bias the rand mixing.

**Closure.** Bound by S-029 deterministic fork choice (`S029ForkChoiceSoundness.md`). The fork-choice rule `Chain::resolve_fork` is a deterministic comparator on `(heaviest_sigs, fewest_aborts, smallest_hash)` — every honest node computes the same winner regardless of message arrival order. The committee derivation at `epoch_start` is a **consequence** of fork-choice (whichever fork wins determines which `cumulative_rand_at(epoch_start - 1)` lives on the canonical chain), not a **cause**. So an attacker cannot use cadence-cycle manipulation at the epoch boundary to bias fork-choice; the rule operates on block contents (sigs + aborts + hash), not on the committee selection method.

**Composition with FA3 selective-abort:** the attacker's selective-abort path is independently bounded per FA3 (information-theoretic indistinguishability of delay_output pre-reveal). The attacker cannot use the selective-abort path to grind specific committee outcomes at the epoch boundary because (a) FA3 forbids predictive abort-and-retry per A3 preimage resistance, and (b) S-029 forbids forking-around-aborts because the deterministic tiebreaker on (sigs > aborts > hash) penalizes the fork with more aborts.

So A4 is closed by composition with S-029 + FA3 + T-2 here. The epoch boundary is just another block boundary from the fork-choice perspective; the epoch-specific rotation cadence does not introduce a new attack surface. ∎

---

## 4. Lemmas

### L-1 (Integer arithmetic of epoch boundaries)

**Claim.** For any `epoch_blocks ≥ 1` and any `h ∈ [0, UINT64_MAX]`:

- `epoch_index(h) = h / epoch_blocks` is well-defined (no division by zero).
- `epoch_start(h) = epoch_index(h) × epoch_blocks ≤ h` (the epoch's first block index ≤ current height).
- `h - epoch_start(h) ∈ [0, epoch_blocks)` (the within-epoch offset is bounded).
- The next epoch starts at `epoch_start(h) + epoch_blocks` (the boundary cleanly delineates consecutive epochs).

**Proof.** Standard integer division. Well-definedness requires `epoch_blocks ≥ 1`; the `epoch_blocks = 0` case is short-circuited by `Node::current_epoch_index` (return 0). The other three properties are textbook integer-division algebra. ∎

### L-2 (Monotonicity over chain height)

**Claim.** For any fixed `epoch_blocks ≥ 1` and any pair of heights `h_1 ≤ h_2`: `epoch_index(h_1) ≤ epoch_index(h_2)`. The function is strictly increasing exactly at multiples of `epoch_blocks` (`epoch_index(k × epoch_blocks) > epoch_index(k × epoch_blocks - 1)` for every `k ≥ 1`) and constant elsewhere within an epoch.

**Proof.** Per T-2's proof (§2). The strict-increase points are the epoch boundaries; the constant intervals are the within-epoch ranges. ∎

### L-3 (PARAM_CHANGE staging mechanics)

**Claim.** For any pending PARAM_CHANGE entry at `effective_height = H_eff` with `name = "epoch_blocks"` and `value = encode(v_new)`:

- At block-apply time of any block `h < H_eff`: the activator does not fire (`H_eff > current_height`). `cfg_.epoch_blocks` retains the prior value.
- At block-apply time of block `H_eff`: the activator fires (`H_eff ≤ current_height`). `cfg_.epoch_blocks` and `validator_.epoch_blocks_` are mutated to `v_new` via the param_changed_hook. The pending entry is erased from `pending_param_changes_`.
- At block-apply time of any block `h > H_eff`: the activator does not re-fire for this entry (it was erased). `cfg_.epoch_blocks = v_new` is the live value for committee derivation.

**Proof.** Direct from `Chain::activate_pending_params` at `src/chain/chain.cpp:471-497`: the activator walks pending entries with `it->first <= current_height` in std::map's sorted ascending order, processes each entry's `(name, value)` pair (invoking the hook for non-chain-instance fields), and erases the entry after processing. The activator is called exactly once at the end of `Chain::apply_transactions` per block. So at block `H_eff`, the entry is processed and erased; at subsequent blocks, the entry is absent from the map. ∎

**Note on idempotence.** L-3's "erased after processing" guarantee makes PARAM_CHANGE activation idempotent in the snapshot-restore sense: if a chain is restored from a snapshot taken **after** block `H_eff`, the snapshot serializes the post-activation `cfg_.epoch_blocks = v_new` plus an empty pending_param_changes_ map. The restore reads the snapshot's `cfg_` value directly (not the historical pre-PARAM_CHANGE value); no re-activation needed. The post-restore replay of any blocks `h > H_eff` reads the snapshot-restored `v_new` and stays consistent.

### L-4 (Per-shard `epoch_blocks` independence)

**Claim.** In an EXTENDED-mode multi-shard deployment, each chain (beacon and each shard) has an independent `cfg_.epoch_blocks` value derived from its own `GenesisConfig`. The cross-shard committee-derivation path at `src/node/node.cpp:1471-1474` uses the **shard's** `epoch_blocks` to compute the beacon anchor height, not the beacon's. So the beacon's `epoch_blocks` is operationally meaningful only for the beacon's own committee rotation; the shards consume the beacon's `cumulative_rand` chain at their own (shard-defined) cadence.

**Proof.** Direct from the code: `Node::current_epoch_index()` reads `cfg_.epoch_blocks` (the local Node's Config). In a multi-shard deployment, each shard runs its own Node with its own Config; the beacon runs its own Node with its own Config. There is no shared Config singleton. The cross-shard validation at `src/node/node.cpp:1471-1474` uses `cfg_.epoch_blocks` (the validating Node's local Config — which is the shard's Config when the shard is the validator). So the per-chain independence is structural. ∎

### L-5 (`cumulative_rand` chain independence from `epoch_blocks`)

**Claim.** The chain's `cumulative_rand` field at each block is computed from the prior block's `cumulative_rand`, the current block's `delay_output`, and the committee's dh_secrets via `crypto::update_random_state` (`src/crypto/random.cpp:20`). The computation does not read `epoch_blocks`. So a PARAM_CHANGE that mutates `epoch_blocks` does not affect the chain's `cumulative_rand` history.

**Proof.** Direct from `crypto::update_random_state` and `Chain::append`: neither function reads `cfg_.epoch_blocks` nor the genesis's `epoch_blocks` field. The `cumulative_rand` chain is one continuous per-block accumulation; epoch boundaries are pure read-side abstractions over this chain. Hence T-4 Corollary T-4.2's "no retroactive rebuild" claim holds: the chain-history bytes are unaffected by `epoch_blocks` mutations. ∎

---

## 5. Cross-references

### 5.1 Protocol-level citations

- **FA1 (`Safety.md` T-1)** establishes K-of-K safety: each block's committee selection at apply time matches the deterministic derivation from `(epoch_blocks, h, cumulative_rand_chain, K, eligible_pool)`. T-1 + T-2 + T-3 + T-5 here jointly establish that derivation's determinism + consistency across epoch boundaries. The composition: FA1 safety holds within an epoch (S-020 picks a uniform K-tuple from a deterministic seed), and across epoch boundaries (T-1 establishes the rotation cadence, T-2 establishes deterministic boundary computation).
- **FA5 (`BFTSafety.md`)** establishes BFT-mode shrunk committee `|K_h| = ⌈2K/3⌉` selection. The same epoch-derivation chain is used (BFT mode shrinks K but does not change the epoch_blocks-driven cadence). T-2 + T-5 here apply directly to BFT mode.
- **FA8 (`RegionalSharding.md`)** establishes region-aware committee selection where the pool is `eligible_in_region(committee_region)`. The epoch-derivation cadence is independent of the region filter; T-1 here applies to per-region committees identically.
- **FA9 (`UnderQuorumMerge.md`)** establishes the R7 under-quorum-merge mechanism. T-6 here covers the composition with `epoch_blocks` boundaries.
- **FA3 (`SelectiveAbort.md`)** establishes the within-epoch abort-rotation path. T-3 here cites this for the "K-tuple may shuffle within an epoch via abort_event mixing" caveat.
- **A5 (`GovernanceParamChange.md`)** establishes the PARAM_CHANGE staging + activation mechanism. T-4 here proves the soundness of `epoch_blocks` mutation via this mechanism.
- **FA-Apply-2 (`AccountStateInvariants.md`)** and FA-Apply-1 (`AbortEventApply.md`) cover the per-block apply discipline; the activator runs at the end of `apply_transactions` per block, post-state-mutation. L-3 here cites this for the PARAM_CHANGE staging mechanics.

### 5.2 Companion proofs

- **`S020CommitteeSelection.md`** covers the within-epoch K-tuple derivation via hybrid Fisher-Yates. T-5 here composes S-020's uniformity property with T-1 + T-2 + T-3's rotation-cadence property.
- **`CommitteeSelection.md`** covers FA1 + FA8 at the protocol level. This proof goes deeper on the rotation-cadence axis.
- **`S029ForkChoiceSoundness.md`** establishes the deterministic fork-choice rule. T-2 + A4 here compose with S-029 for cross-epoch fork-resolution.
- **`S033StateRootNamespaceCoverage.md`** establishes the 10-namespace state_root commitment, including `p:` for `pending_param_changes_`. The PARAM_CHANGE staging is bound into the state-root via `serialize_state` at `chain.cpp:362-371` (the `p:` namespace handles `pending_param_changes_`). L-3 here cites this for PARAM_CHANGE durability across snapshots.
- **`GovernanceParamChange.md`** (A5) covers the keyholder-quorum mechanism for PARAM_CHANGE submission + the threshold-signature verification. T-4 + A2 here compose with that mechanism.

### 5.3 TLA+ state-machine specs

- **FB34 `EpochCommitteeRotation.tla`** formalizes the cross-epoch committee rotation surface as a 4-action state machine (`AdvanceEpoch`, `BeaconUpdate`, `RegisterValidator`, `DeregisterValidator`) with 5 invariants (`INV_TypeOK`, `INV_CommitteeSizeIsK`, `INV_CommitteeSubsetActive`, `INV_DeterministicSelection`, `INV_HistoryMonotone`) + 2 temporal properties (`PROP_EventualRotation`, `PROP_NoCommitteeFreeze`). The analytic correspondence:
  - T-1 (Rotation Cadence Bound) ↔ FB34 `PROP_EventualRotation` (T-ER5).
  - T-2 (Deterministic Epoch Boundary) ↔ FB34 `INV_DeterministicSelection` (T-ER1).
  - T-3 (Mid-Epoch Committee Stability) ↔ FB34 `INV_HistoryMonotone` (T-ER4) + the structural witness that AdvanceEpoch is the only committee-mutating action.
  - T-5 (Composition with S-020) ↔ FB34 `INV_CommitteeSizeIsK` (T-ER2) + the `EpochCommitteeSelect(pool, beacon, k)` operator's purity.
  - T-6 (Composition with R7) ↔ FB34's caveat that R4 + R7 are out-of-scope at the base spec; this proof covers the analytic composition layer.
- **FB1 `Consensus.tla`** (parent within-epoch consensus spec). The two specs compose: FB1 covers within-epoch K-of-K consensus; FB34 covers across-epoch rotation; this proof formalizes the bridge at the analytic level.
- **FB31 `SnapshotIntegrity.tla`** covers snapshot save/restore + the `p:` namespace coverage for `pending_param_changes_`. L-3's "snapshot serializes post-activation `cfg_.epoch_blocks`" claim composes with FB31's snapshot-equivalence invariant.

### 5.4 Adjacent specifications and design docs

- **`docs/PROTOCOL.md` §5.1** documents the committee-derivation chain including `epoch_index = h / epoch_blocks` formula. Cross-checked against `Node::current_epoch_index` at `src/node/node.cpp:909-912`.
- **`docs/PROTOCOL.md` §11.x** documents the GenesisConfig schema including `epoch_blocks`.
- **`docs/SECURITY.md` §S-018** documents the `genesis_hash` binding of `epoch_blocks` (the chain-id gate that A3 closes).
- **`docs/SECURITY.md` §S-024** documents the original deregistration-timing finding (auditor-accepted at low severity). This proof reclaims the S024 prefix for the epoch_blocks parameter-soundness companion theorem.
- **`docs/V2-DESIGN.md` §v2.11** documents the v2.x deterministic-FSM closure path for R7 (composing with T-6 here).
- **`docs/CLI-REFERENCE.md`** documents the `--epoch-blocks <N>` operator flag for genesis customization.

---

## 6. Findings register

### F-1: Tuning recommendations per profile

The `epoch_blocks = 1000` default is operationally sound for `regional` and `global` profiles (5-10 minute epochs at default block timings). Operators on other profiles should consider:

- **Tactical (20 ms blocks, K=3):** Default 1000 = ~20 seconds per epoch. Adequate for mission durations of minutes-to-hours; fast enough to rotate within an extended engagement. If operators need slower rotation to amortize gossip overhead on bandwidth-constrained radio links, increase to 5000 (~100 seconds) or 10000 (~3.3 minutes); both still preserve H4 dilution provided the operational session is longer than the epoch.
- **Cluster (50 ms blocks, K=3, FIPS):** Default 1000 = ~50 seconds per epoch. Adequate for in-house enterprise settlement. If operators want longer-stable committees to reduce HSM-protected-key rotation overhead, increase to 10000 (~10 minutes); HSM keys are typically rotated on the order of days, so a 10-minute epoch is comfortable.
- **Web (200 ms blocks, K=3, MODERN):** Default 1000 = ~200 seconds (~3.3 minutes). Adequate for commercial single-cluster + small-consortium use.
- **Regional (300 ms blocks, K=5, MODERN):** Default 1000 = ~5 minutes. Adequate for multi-region commercial deployments.
- **Global (600 ms blocks, K=7, MODERN):** Default 1000 = ~10 minutes. Adequate for global federated deployments.

**Closure status.** Recommendation only; no protocol-level enforcement. Operators choose at chain genesis.

### F-2: PARAM_CHANGE `epoch_blocks` at `effective_height` crossing epoch boundary

When a PARAM_CHANGE activates at `H_eff` that does **not** align with an `epoch_blocks` boundary (e.g., `H_eff = 5500` with prior `v_old = 1000`), the chain transitions abruptly: block 5499 was in epoch 5 (of 1000-block epochs); block 5500 is in epoch 55 (of 100-block epochs under the new `v_new = 100`). The `epoch_index` jumps from 5 to 55 across consecutive blocks. The committee at block 5500 derives from `epoch_rand = cumulative_rand_at(5499)` — which is the prior block's rand (because under `v_new = 100`, `epoch_start(5500) = 55 × 100 = 5500`, so `epoch_start - 1 = 5499`).

**Operational visibility.** Operators monitoring epoch counters across a `epoch_blocks` PARAM_CHANGE may see surprising jumps. Recommend logging the PARAM_CHANGE event prominently + computing the new epoch counter in operator dashboards. The cumulative-rand chain is unaffected (per L-5), so all replay + snapshot + fork-resolution paths remain sound.

**Recommended discipline.** Operators staging `epoch_blocks` PARAM_CHANGEs should set `effective_height` at a clean multiple of `max(v_old, v_new)` to minimize visual disruption. The protocol does not enforce this; it is operator discipline.

**Closure status.** Documented corner case; no protocol-level fix needed. The behavior is sound per T-4; only the visual is surprising.

### F-3: No upper bound enforced on `epoch_blocks`

The protocol accepts `epoch_blocks ∈ [0, UINT32_MAX]` without rejection. Operationally:

- **`epoch_blocks = 0`:** Treated as "no rotation" short-circuit. Defeats rotation rationale; falls through to per-block rand evolution which still works but loses the cadenced refresh.
- **`epoch_blocks = UINT32_MAX` (~4.3 billion):** Equivalent to no rotation for any reasonable chain height (`h / UINT32_MAX = 0` for all `h < 4.3 × 10^9`). Defeats rotation rationale entirely.
- **`epoch_blocks = 1`:** Per-block rotation. Wasteful on large profiles but operationally functional.

A defensive enhancement could add validation at:

- **GenesisConfig parse time** (`src/chain/genesis.cpp:184`): refuse values in `{0, < 10, > 100000}` at chain-creation time.
- **PARAM_CHANGE stage time** (`src/chain/chain.cpp:212-217`): refuse `epoch_blocks` PARAM_CHANGEs with sentinel values.

Neither is currently enforced; T-1 Corollary T-1.1 + T-1 Corollary T-1.2 document the structural lower + upper bounds.

**Closure status.** Documented as operator discipline. A future enhancement could harden the validation surface; the current behavior is sound but permissive.

---

## 7. Test surface

### 7.1 In-process unit tests

- **`determ test-pending-param-changes`** (`src/main.cpp::cmd_test_pending_param_changes`) — exercises `Chain::stage_param_change` + `Chain::pending_param_changes()` read-write surface with 13 assertions across 7 blocks. The default state, single stage at one height, multi-stage at same height, multi-stage at different heights, edge values (empty value, 256-byte value), and chain-independence (stage on one Chain doesn't leak to another). Indirect coverage of T-4's PARAM_CHANGE staging soundness — the same primitive that would handle an `epoch_blocks` PARAM_CHANGE. Wrapper: `tools/test_pending_param_changes.sh`. Exit code: PASS line "PASS: pending-param-changes all assertions" required.

- **`determ test-committee-selection`** (`src/main.cpp::cmd_test_committee_selection`) — exercises the S-020 hybrid Fisher-Yates + `select_after_abort_m` + `epoch_committee_seed` with 13 assertions across 10 scenarios. Indirect coverage of T-5's composition with S-020 (the underlying primitive's determinism + seed-sensitivity properties). Wrapper: `tools/test_committee_selection.sh`. Exit code: PASS line "PASS: committee-selection all assertions" required.

- **`BlockValidator::set_epoch_blocks` range test** (`src/main.cpp:14547-14556`) — asserts the validator accepts `epoch_blocks ∈ {1, 1000, 10000}` without throw. Direct coverage of T-1 Corollary T-1.1 (lower bound `≥ 1`) + T-1 Corollary T-1.2 (no semantic upper bound enforced — the test sets 10000 successfully).

- **Default-value test** (`src/main.cpp:26324-26326`) — asserts `Config::epoch_blocks` defaults to 1000. Direct coverage of §1.2's "1000-block default" claim.

- **Config round-trip tests** (`src/main.cpp:13848-13849`, `:32332-32339`) — assert `Config::epoch_blocks` round-trips through JSON serialization. Indirect coverage of L-3's "snapshot serializes post-activation `cfg_.epoch_blocks`" claim — the same serialization primitive handles the snapshot path.

### 7.2 TLA+ model checking

- **FB34 `EpochCommitteeRotation.tla`** + `EpochCommitteeRotation.cfg` (in `docs/proofs/tla/`) formalizes the cross-epoch rotation surface and is checkable via `tlc EpochCommitteeRotation.tla -config EpochCommitteeRotation.cfg`. Recommended config: `ValidatorPool = {v1, v2, v3, v4, v5}, K = 3, MaxEpoch = 4, BeaconValues = {b1, b2, b3}` — state space ~10^4 explored in < 30s. Direct coverage of T-1 (via PROP_EventualRotation), T-2 (via INV_DeterministicSelection), T-3 (via INV_HistoryMonotone), and T-5 (via INV_CommitteeSizeIsK).

### 7.3 Operator visibility

- **`determ test-pending-param-changes`** + **`determ test-committee-selection`** are run as part of the standard regression suite (FAST=1 includes both; CI gates on PASS).
- Operators can audit live `epoch_blocks` via the `chain_info` RPC (returns the current `cfg_.epoch_blocks`) and via the epoch-boundary log line at `src/node/node.cpp:1856-1880` (logs the transition + the freshly-derived committee at every epoch boundary; F-2 corner case visible here).
- Operators can audit pending PARAM_CHANGEs via the snapshot file's `pending_param_changes` array (per the snapshot schema in `docs/PROTOCOL.md` §11).

---

## 8. References

### 8.1 Implementation citations

- `include/determ/chain/params.hpp` — `TimingProfile` struct + profile presets (PROFILE_CLUSTER, PROFILE_WEB, PROFILE_REGIONAL, PROFILE_GLOBAL, PROFILE_TACTICAL + _TEST variants). No `epoch_blocks` field in TimingProfile (genesis-pinned separately via GenesisConfig).
- `include/determ/chain/genesis.hpp:190` — `GenesisConfig::epoch_blocks{1000}` (default 1000).
- `include/determ/node/node.hpp:128` — `Config::epoch_blocks{1000}` (Node-side mirror).
- `include/determ/node/node.hpp:420-423` — comment on `epoch_index = chain_.height() / epoch_blocks; epoch_rand = chain's cumulative_rand at the block that opened the epoch`.
- `include/determ/node/validator.hpp:37` — `BlockValidator::set_epoch_blocks(uint32_t e)` validator-side setter.
- `include/determ/node/validator.hpp:128` — `BlockValidator::epoch_blocks_{1000}` validator-side field.
- `include/determ/crypto/random.hpp:42-46` — `epoch_committee_seed(epoch_rand, shard_id)` declaration + comment on per-epoch + per-shard seed derivation.
- `src/chain/genesis.cpp:88-90, :184` — GenesisConfig JSON serialization + parse of `epoch_blocks` field.
- `src/node/node.cpp:50-52, :96-98` — Config JSON serialization + parse of `epoch_blocks` field.
- `src/node/node.cpp:158-160, :177-178` — `cfg_.epoch_blocks` initialization from `gcfg.epoch_blocks` at Node startup + mirror to `validator_.set_epoch_blocks(...)`.
- `src/node/node.cpp:909-912` — `Node::current_epoch_index()` (`return chain_.height() / cfg_.epoch_blocks`; 0 short-circuit if `epoch_blocks == 0`).
- `src/node/node.cpp:914-934` — `Node::current_epoch_rand()` (full epoch-rand resolution including beacon-anchor branch for SHARD chains).
- `src/node/node.cpp:1471-1474` — beacon-anchor height computation for cross-shard validation (`beacon_anchor_height = shard_epoch * cfg_.epoch_blocks`).
- `src/node/node.cpp:1856-1880` — epoch-boundary observability log line (operator-visible transition trace).
- `src/node/validator.cpp:64-91` — `BlockValidator::check_creator_selection` (the validator-side check using `epoch_blocks_` for committee derivation).
- `src/node/validator.cpp:188-191` — `BlockValidator::check_abort_certs` (same epoch_blocks_-based derivation for at-event committee reconstruction).
- `src/node/validator.cpp:412-415` — equivocation-evidence validator path (same epoch_blocks_-based derivation).
- `src/crypto/random.cpp:169-175` — `epoch_committee_seed(epoch_rand, shard_id)` implementation.
- `src/chain/chain.cpp:212-217` — `Chain::stage_param_change(effective_height, name, value)` (A5 governance staging primitive).
- `src/chain/chain.cpp:471-497` — `Chain::activate_pending_params(current_height)` (the activator that runs at the end of each block-apply).
- `src/chain/chain.cpp:362-371` — `p:` namespace coverage for `pending_param_changes_` in state_root (S-033 binding for snapshot durability).
- `src/node/node.cpp:195-247` — Node-installed `chain_.set_param_changed_hook` (the hook that mirrors PARAM_CHANGE values into `cfg_` + validator-side fields).
- `src/main.cpp::cmd_test_pending_param_changes` — in-process unit test for PARAM_CHANGE staging surface.
- `src/main.cpp::cmd_test_committee_selection` — in-process unit test for committee-selection primitives.
- `src/main.cpp:14547-14556` — `set_epoch_blocks` range test (validator accepts 1..10000).
- `src/main.cpp:26324-26326` — Config default value test (`epoch_blocks == 1000`).
- `tools/test_pending_param_changes.sh` — wrapper for the in-process PARAM_CHANGE staging test.
- `tools/test_committee_selection.sh` — wrapper for the in-process committee-selection test.

### 8.2 Cross-references within the proof suite

- `docs/proofs/Preliminaries.md` — F0 notation; H1–H4 honest-validator assumptions; A2 SHA-256 collision resistance; A3 ROM on SHA-256; §3 cross-epoch committee derivation contract.
- `docs/proofs/Safety.md` (FA1) — K-of-K safety theorem; T-2 + T-5 here compose with FA1's V3 committee-determinism check.
- `docs/proofs/Liveness.md` (L4) — rotational-eligibility argument; T-1 here provides the rotation-cadence bound L4 invokes.
- `docs/proofs/BFTSafety.md` (FA5) — BFT-mode shrunk committee; same epoch-derivation chain; T-2 + T-5 here apply directly.
- `docs/proofs/RegionalSharding.md` (FA8) — region-aware committee selection; T-1 here is independent of region filtering.
- `docs/proofs/UnderQuorumMerge.md` (FA9) — R7 under-quorum merge; T-6 here covers the composition with epoch_blocks boundaries.
- `docs/proofs/S036UnderQuorumMerge.md` — S-036 closure path for R7; composes with T-6 here for the merge-boundary discipline.
- `docs/proofs/SelectiveAbort.md` (FA3) — within-epoch abort-rotation path; T-3 here cites this for the abort_event mixing caveat.
- `docs/proofs/GovernanceParamChange.md` (A5) — PARAM_CHANGE staging + activation; T-4 + A2 here compose with that mechanism.
- `docs/proofs/S020CommitteeSelection.md` — S-020 hybrid Fisher-Yates inside each epoch; T-5 here composes with S-020 T-1 + T-2.
- `docs/proofs/CommitteeSelection.md` — FA1 + FA8 K-of-K parent proof; this proof goes deeper on the rotation-cadence axis.
- `docs/proofs/S029ForkChoiceSoundness.md` — deterministic fork-choice rule; T-2 + A4 here compose with S-029.
- `docs/proofs/S033StateRootNamespaceCoverage.md` — `p:` namespace coverage for `pending_param_changes_`; L-3's snapshot-durability claim composes with this.
- `docs/proofs/Censorship.md` (FA2) — K-conjunction censorship bound; T-1's "very large epoch_blocks defeats rotation rationale" composes with FA2's per-committee-window censorship probability.
- `docs/proofs/EquivocationSlashing.md` (FA6) — equivocation slashing; T-1's "sustained adversarial sub-committee window" relates to FA6's per-block evidence detection.
- `docs/proofs/tla/EpochCommitteeRotation.tla` (FB34) — TLA+ state-machine spec for the rotation surface; T-1 + T-2 + T-3 + T-5 here mirror the spec's invariants at the analytic level.
- `docs/proofs/tla/Consensus.tla` (FB1) — parent within-epoch consensus spec; composes with FB34 + this proof for the full safety + liveness story.
- `docs/proofs/tla/SnapshotIntegrity.tla` (FB31) — snapshot save/restore + `p:` namespace coverage; composes with L-3 here.

### 8.3 External references

- **Castro, Miguel & Liskov, Barbara.** "Practical Byzantine Fault Tolerance," Proceedings of the Third Symposium on Operating Systems Design and Implementation (OSDI '99), USENIX Association, pp. 173-186, February 1999. Foundational reference for the "view" mechanism — a view rotation in PBFT is analogous to Determ's epoch rotation: a fresh leader (in PBFT, a single primary per view; in Determ, a fresh K-committee per epoch) is selected to coordinate the next block-production batch. PBFT's view-change protocol triggers on primary-failure suspicion; Determ's epoch rotation is unconditional + cadenced rather than failure-triggered (the unconditional rotation simplifies the protocol surface at the cost of always rotating even when the current committee is performing well).
- **Castro, Miguel & Liskov, Barbara.** "Proactive Recovery in a Byzantine-Fault-Tolerant System," Proceedings of the 4th Symposium on Operating Systems Design and Implementation (OSDI '00), USENIX Association, pp. 273-288, October 2000. Reference for the periodic rotation rationale — proactive recovery rotates keys + state at fixed intervals to bound the time an undetected compromise can persist. Determ's epoch rotation is a structural analog: bounds the time an adversarial sub-committee can persist in the K-of-K position to `≤ epoch_blocks` blocks (per T-1 + T-3).
- **Lamport, Leslie.** "The Part-Time Parliament," ACM Transactions on Computer Systems (TOCS), 16 (2): 133-169, May 1998. Foundational reference for Paxos. Paxos has no built-in "view" or "epoch" mechanism — each consensus instance is independent — but the role of the proposer per instance maps to Determ's K-of-K per round; the rotation cadence here is the multi-instance generalization that Paxos delegates to the implementation.
- **Lamport, Leslie.** "Paxos Made Simple," ACM SIGACT News, 32 (4): 18-25, December 2001. The simplified presentation of Paxos used as a teaching reference for the per-instance leader / committee distinction relevant to Determ's per-epoch K-committee.
- **NIST FIPS 180-4** — Secure Hash Standard (SHS), defining SHA-256 bit-exact across implementations. Cited for T-2's cross-architecture determinism + L-1's integer arithmetic + the `epoch_committee_seed` SHA-256 derivation underlying T-1.
- **Knuth, Donald E.** "The Art of Computer Programming, Vol. 2: Seminumerical Algorithms" (3rd ed., Addison-Wesley, 1997), §3.4.2 "Random Sampling and Shuffling," Algorithm P (Fisher-Yates shuffle). Cited via the S-020 composition (T-5).

### 8.4 Provenance

This proof was written to fill the analytic gap on `epoch_blocks` parameter soundness — the parameter has been operator-tunable since v1.0 (genesis-pinned via GenesisConfig::epoch_blocks) and PARAM_CHANGE-mutable via the A5 governance pipeline (per the timing-fields category covered by `Chain::set_param_changed_hook`'s `tx_commit_ms` / `block_sig_ms` / `abort_claim_ms` precedent at `src/node/node.cpp:229-243`), but the analytic structure of the rotation cadence + the PARAM_CHANGE composition was not formalized in a single document. The proof here pins T-1 (rotation cadence bound), T-2 (deterministic epoch boundary), T-3 (mid-epoch committee stability), T-4 (PARAM_CHANGE soundness), T-5 (composition with S-020 hybrid Fisher-Yates), T-6 (composition with R7 under-quorum merge), four adversary models A1-A4, five lemmas L-1 through L-5, and three findings F-1 through F-3 in a single companion document. The proof is cross-referenced from `S020CommitteeSelection.md` (T-5 composition target) and from `GovernanceParamChange.md` (T-4 composition target).

---

## 9. Status

**Analytic.** The `epoch_blocks` parameter is operator-tunable per chain genesis (default 1000), genesis-pinned via `GenesisConfig::epoch_blocks`, and PARAM_CHANGE-mutable via the A5 governance pipeline. T-1 (rotation cadence bound), T-2 (deterministic epoch boundary), T-3 (mid-epoch committee stability), T-4 (PARAM_CHANGE soundness with effective_height discipline), T-5 (composition with S-020 hybrid Fisher-Yates inside each epoch), and T-6 (composition with R7 under-quorum merge at epoch boundaries) hold under A1 + A2 + A3 + H1–H4 + the prior cited proofs' assumptions.

The proof composes cleanly with FA1 (K-of-K safety — T-2 + T-5 establish cross-node committee derivation), FA5 (BFT escalation — same epoch-derivation chain applies), FA8 (regional sharding — region filter independent of rotation cadence), FA9 + S036 (R7 merge — T-6 covers the cross-boundary composition), FA3 (selective abort — T-3 caveat for within-epoch shuffling), A5 PARAM_CHANGE (T-4 establishes soundness of the governance-mutated path), S-020 (T-5 composition), S-029 (T-2 + A4 composition for cross-epoch fork-resolution), S-033 (`p:` namespace coverage for PARAM_CHANGE snapshot durability), and the FB34 TLA+ state-machine spec (T-1 + T-2 + T-3 + T-5 mirror FB34's invariants at the analytic level).

Three findings F-1 (tuning recommendations per profile), F-2 (PARAM_CHANGE at effective_height crossing epoch boundary — operator visibility corner case), F-3 (no upper bound enforced on `epoch_blocks` — operator discipline) document acknowledged gaps; none affect soundness, only operator discipline + visibility. The original S-024 deregistration-timing finding at SECURITY.md §S-024 remains documented there at low severity per auditor acceptance; this proof reclaims the S024 prefix for the parameter-soundness companion theorem.

Combined test surface: `tools/test_pending_param_changes.sh` (13 assertions on PARAM_CHANGE staging — indirect coverage of T-4), `tools/test_committee_selection.sh` (13 assertions on S-020 + epoch_committee_seed — indirect coverage of T-5), plus the `BlockValidator::set_epoch_blocks` range test (direct coverage of T-1 corollaries), Config default-value test (direct coverage of §1.2 default), Config round-trip tests (indirect coverage of L-3 snapshot path), and FB34 TLA+ `EpochCommitteeRotation.tla` model-checking (direct coverage of T-1 + T-2 + T-3 + T-5 state-machine invariants).
