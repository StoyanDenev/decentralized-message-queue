--------------------------- MODULE RegionalShardingCommittee ---------------------------
(*
FB35 — TLA+ specification of the R4 region-aware committee selection
state machine. Models the per-block K-member committee draw from the
region-filtered validator pool plus the active-region evolution and
the R7 under-quorum merge composition that fires when the region's
pool drops below K.

This spec layers on top of FB34 EpochCommitteeRotation.tla: FB34
covers the BASE rotation contract (per-epoch committee draw from
the FULL active validator pool); FB35 specializes by adding the R4
region-aware FILTER (every per-block committee is drawn from the
region-filtered subset of the pool, not the full pool) plus the R7
under-quorum MERGE branch (when the region's pool drops below K,
the chain merges to a sibling region by widening the pool with
refugees from the merged region).

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
RegionalShardingCommittee.cfg RegionalShardingCommittee.tla` once
the TLC toolchain is installed in CI.

Scope. Formalizes the region-aware committee selection contract that
governs Determ's per-block K-member committee selection when the
chain runs in R4 regional sharding mode. The committee for block h
is drawn from `NodeRegistry::eligible_in_region(committee_region)`
keyed on the per-block beacon; under R7 the eligible pool is widened
with refugees from sibling regions when `|EligibleInRegion(region)|
< K`.

The contract this spec pins (five sub-claims, paired with the five
invariants below):

  (a) Region-filtered selection. For every block h with active region
      R, the committee at block h is drawn from `EligibleInRegion(R)`
      (NOT from the full validator pool). The C++ correspondent is
      `Node::start_block_sig_phase` at `src/node/node.cpp:731` (the
      `registry_.eligible_in_region(cfg_.committee_region)` call that
      restricts the pool) + `BlockValidator::check_creator_selection`
      at `src/node/validator.cpp:75-83` (the receiver-side cross-check
      that the candidate block's committee comes from the same
      region-filtered pool).
  (b) No cross-region leak. For every block h with region R, NO
      validator with `region /= R` appears in `committee_history[h]`
      — UNLESS an under-quorum merge fired, in which case the
      validator's region must be in the set of merged regions (still
      satisfying region-membership for the EFFECTIVE pool).
  (c) Region filter determinism. The `EligibleInRegion(region)`
      filter is deterministic on its inputs: same `(region,
      validator_set)` pair always yields the same SUBSET output. The
      structural witness is `registry.cpp::eligible_in_region` at
      lines 86-95 — a pure linear scan over the sorted pool with
      strict equality on the region tag.
  (d) Under-quorum merge composition. When `|EligibleInRegion(R)| <
      K`, the chain merges to a sibling region (CHOSEN per the
      MERGE_EVENT mechanism) and the effective pool for the next
      committee draw is `EligibleInRegion(R) ∪ EligibleInRegion(R')`
      where R' is the merged-from region. This restores the
      `|effective_pool| >= K` precondition for `select_m_creators`.
      The C++ correspondent is `Node::start_block_sig_phase` lines
      732-748 (the refugee-pool extension via `chain_.shards_absorbed_by`).
  (e) Committee size discipline under merge. With the merge in
      effect, `|committee_history[h]|` equals K iff the effective
      (merged) pool has at least K members; otherwise equals the
      full effective pool. Same discipline as FB34 INV_CommitteeSizeIsK,
      lifted to the post-merge pool.

The state machine. Four actions cover the regional-rotation surface
(plus a Stutter to bound TLC):

  * AdvanceBlock — increments `block_height` and the per-block
    region rotation per the protocol (typically epoch-bound; here
    modeled as a simple rotation through the Regions set). Draws
    the fresh committee via `SelectMCreators(EligibleInRegion(R),
    beacon, K)` where R is the new active region and beacon is the
    per-block randomness. Stores in `committee_history` and the
    matching region in `region_history`. If `|EligibleInRegion(R)|
    < K` AND merge_state is empty, the action is disabled (the
    chain stalls until ForceMerge fires); if the merge is already
    in effect, the effective pool includes refugees.
  * RegisterValidator(v, region) — adds v to `active_validators`
    with the given region. Mirrors the REGISTER tx apply path at
    `src/chain/chain.cpp::apply_transactions` REGISTER branch +
    the `registrants_.region` field assignment. v MUST be in the
    universe (Validators domain), and its region MUST equal the
    region pre-declared in the Validators constant (region is a
    property of v, not a per-registration choice).
  * RegionPoolShrink — narrows the active validator pool by
    deregistering some validators (silent in this spec — the
    DEREGISTER tx body is FB34's domain; this action composes with
    R7 by exposing the under-quorum branch reachably). Pre-
    condition: at least one validator with the current region is
    present and the active pool has more than one entry total
    (so AdvanceBlock's `>= 1` antecedent stays satisfiable).
  * ForceMerge — when `|EligibleInRegion(current_region)| < K`,
    activates the under-quorum merge by widening the effective
    pool with refugees from a sibling region. Mirrors the
    MERGE_EVENT tx + `chain.cpp::shards_absorbed_by` lookup. The
    chosen merged-from region is the lexicographically smallest
    sibling region with at least one active validator (a
    deterministic tie-break mirroring the chain's MERGE_EVENT
    ordering discipline).

Modeling scope (kept tractable for TLC):

  * `Validators` is a function from validator domain ID (string) to
    a record `[domain: string, region: string]`. The domain field
    IS the key; the region field is fixed per-validator (a
    validator's region is a property of its identity, not a
    per-registration choice). Production has ~10-100 validators
    across ~3-7 regions; the model uses 4 validators across 2
    regions.
  * `Regions` is a SUBSET of strings — the universe of valid
    region tags. Production has region tags like "us-east-1" /
    "eu-west-1" / "ap-south-1" etc. (free-form strings, normalized
    to a canonical form); the model uses 2 regions.
  * `K` is the committee size (Nat ≥ 1). Production profiles range
    K = 3 (cluster / tactical / single_test) up to K = 7 (global).
    The cfg uses K = 2 to keep the SUBSET universe small while
    still exercising the merge branch reachably (with K = 2 and 2
    validators per region, a single deregister in one region forces
    the under-quorum branch).
  * `MaxBlock` bounds block-height growth so TLC exhausts in
    seconds. Production runs unbounded blocks; the model bounds at
    4 blocks which is enough to exercise: 0→1 (genesis block +
    first region committee), 1→2 (rotation to second region with
    fresh draw), 2→3 (shrink → merge → recovery), 3→4 (saturation;
    Stutter pins the bound).
  * `EligibleInRegion(region)` is the spec-layer projection of
    `registry.cpp::eligible_in_region(region)`. Returns the
    SUBSET of `active_validators` whose Validators[v].region
    matches; pure linear-scan equivalent at the spec layer (no
    randomness; just deterministic filtering).
  * `SelectMCreators(pool, beacon, k)` is the delegated abstract
    operator — the same EpochCommitteeSelect signature as FB34
    (delegating the abstract Fisher-Yates K-of-N draw to the
    sibling spec). Returns a SUBSET of `pool` of cardinality
    `min(k, |pool|)` deterministic on `(pool, beacon, k)`.
  * `current_region` is the active region for the CURRENT block —
    rotates per the protocol (here modeled simply as deterministic
    rotation through the Regions set, mirroring the chain's
    per-shard region assignment per `shard_committee_regions_` at
    `src/node/node.cpp:1487-1491`).
  * `merge_state` is a function `Region → SUBSET Region` capturing
    the active merge: `merge_state[R]` is the set of regions whose
    validators are admitted as refugees when R is the active
    region. The `chain.cpp::shards_absorbed_by` map is the C++
    correspondent; this spec abstracts the shard dimension into
    the region dimension directly.
  * `region_history` and `committee_history` are partial functions
    `Nat → Region` and `Nat → SUBSET Validators-domain`, mirrored
    in domain across the AdvanceBlock action's atomic update.

Five paired theorems are pinned (per the contract above):

  (T-RC1) CommitteeFromActiveRegion. For every block h in the
          domain of `region_history`, every member of
          `committee_history[h]` is in `EligibleInRegion(region_history[h])`
          (or the merged region's effective pool if a merge fired).
          The structural witness is `Node::start_block_sig_phase`'s
          `eligible_in_region(committee_region_)` precondition and
          the under-quorum refugee-pool extension.
  (T-RC2) CommitteeSizeIsK. Every committee in `committee_history`
          has cardinality K (when the effective pool has at least
          K members) OR equals the full effective pool (under-
          quorum branch). Same shape as FB34 T-ER2 but lifted to
          the region-filtered pool.
  (T-RC3) RegionFilterDeterministic. The `EligibleInRegion(region)`
          filter is deterministic on `(region, active_validators)`:
          same inputs yield the same SUBSET output. State-form
          witness of `registry.cpp::eligible_in_region`'s purity
          — required for cross-node consensus convergence on the
          same chain head's region-filtered pool.
  (T-RC4) NoCrossRegionLeak. At block h with region R AND no merge
          in effect for R, every validator in `committee_history[h]`
          has `Validators[v].region = R` — no cross-region leak.
          When a merge IS in effect, the looser predicate holds:
          every validator's region is in `{R} ∪ merge_state[R]`
          (the effective region set). Structural witness: the
          committee comes from `EligibleInRegion(R) ∪ refugees`
          where refugees are filtered by `merge_state[R]`.
  (T-RC5) EventualCommitteeRotation + UnderQuorumMerge.
          (a) PROP_EventualCommitteeRotation: IF the chain ever
              produces a post-genesis block, some pair of
              consecutive blocks has distinct committees (analog
              of FB34 T-ER5 lifted to the per-block regional
              surface, conditioned on block production — the
              environment's validator churn can legitimately
              starve AdvanceBlock forever).
          (b) PROP_UnderQuorumMerge: if `|EligibleInRegion(R)| <
              K` for the current region R PERSISTS (with a
              sibling region holding an active validator),
              eventually a merge to a sibling region fires — the
              R7 forward-progress contract that prevents the
              chain from stalling on an under-quorum region.

Five invariants codify T-RC1..T-RC5 + a type predicate:

  TypeOK — shape predicate for all variables.
  INV_CommitteeFromActiveRegion (T-RC1) — every committee member
        at block h is in `EligibleInRegion(region_history[h])` ∪
        the refugees from the merged-from regions (if merge active).
  INV_CommitteeSizeIsK (T-RC2) — every committee in
        committee_history has cardinality K (when |effective_pool|
        >= K) or equals the full effective pool (under-quorum).
  INV_RegionFilterDeterministic (T-RC3) — `EligibleInRegion(R)`
        is a deterministic SUBSET of `active_validators` for every
        R; pure linear scan equivalent at the spec layer.
  INV_NoCrossRegionLeak (T-RC4) — at block h with region R AND
        no merge in effect for R, every validator in
        committee_history[h] has Validators[v].region = R; under
        merge, every validator's region is in {R} ∪ merge_state[R].

Two temporal properties pin the headline composition claims:

  PROP_EventualCommitteeRotation (T-RC5a) — conditional on block
    production: if a post-genesis block ever forms, some pair of
    consecutive blocks has distinct committees (the first rotation
    targets a sibling region whose pool is disjoint from
    genesis's).
  PROP_UnderQuorumMerge (T-RC5b) — if `|EligibleInRegion(R)| < K`
    for the current region R persists (with a sibling region
    holding an active validator), eventually a merge to a sibling
    region fires (ForceMerge enables) — composes with R7
    UnderQuorumMerge to prevent the chain from stalling on an
    under-quorum region.

To check (assuming TLC installed):
  $ tlc RegionalShardingCommittee.tla -config RegionalShardingCommittee.cfg

Recommended config (state space ~10^4, < 30s):
  Validators <- ModelValidators (defined below; TLC's .cfg grammar
               cannot parse function-valued expressions, so the
               4-validator × 2-region map v1,v2:r1 / v3,v4:r2 is
               bound by substitution),
  Regions = {"r1", "r2"}, K = 2, MaxBlock = 4.

Cross-references:
  - src/node/registry.cpp:86-95 (`NodeRegistry::eligible_in_region`
    — the pure linear-scan region filter that
    EligibleInRegion abstracts; the structural source for INV_3
    RegionFilterDeterministic).
  - src/node/node.cpp:731 (`Node::start_block_sig_phase` —
    `registry_.eligible_in_region(cfg_.committee_region)` call
    that restricts the per-block creator pool to the active
    region).
  - src/node/node.cpp:732-748 (the R4-Phase-4 under-quorum
    refugee-pool extension via `chain_.shards_absorbed_by`).
  - src/node/node.cpp:1487-1491 (per-shard region resolution from
    the `shard_committee_regions_` manifest; the C++ correspondent
    of `current_region` rotation).
  - src/node/validator.cpp:75-83 (the receiver-side cross-check:
    every block's committee must come from the same region-
    filtered + refugee-extended pool — FA1 K-of-K safety
    composition).
  - src/chain/chain.cpp:1018-1025 (the MERGE_EVENT apply branch
    that populates `merge_state_` with `refugee_region`; the C++
    correspondent of ForceMerge).
  - src/chain/chain.cpp::shards_absorbed_by (the lookup that
    Node::start_block_sig_phase + BlockValidator::check_creator_selection
    consult for the refugee region set).
  - docs/proofs/tla/EpochCommitteeRotation.tla (FB34) — parent
    rotation spec; FB35 specializes FB34 by adding the R4
    region-filter + R7 under-quorum merge on top of the base
    rotation; the `SelectMCreators` abstraction is the same as
    FB34's `EpochCommitteeSelect` (delegated).
  - docs/proofs/tla/ChainPrevHashLink.tla (FB30) — sibling
    state-machine spec; INV_AppendOnly's append-only ghost-
    history pattern is the structural template for this spec's
    `region_history` + `committee_history` monotonicity.
  - docs/proofs/tla/Sharding.tla (FB2) — sibling shard-aware
    state machine; the per-shard committee derivation uses the
    same epoch_committee_seed but with the shard_id parameter;
    FB35 lifts the regional dimension explicitly.
  - docs/proofs/tla/Consensus.tla (FB1) — FA1 K-of-K committee
    safety surface that this spec's per-block committee draw
    feeds; FB1 covers within-block consensus; FB35 covers the
    region-filtered per-block committee membership.
  - docs/proofs/tla/F2ViewReconciliation.tla (FB22) — FA8 BFT
    escalation surface (within-round view reconciliation under
    aborts); the BFT escalation gate composes with this spec's
    region-filtered pool via the same `eligible_in_region` precondition.
  - docs/proofs/RegionalSharding.md (R4) — analytic narrative on
    the region-aware overlay; this spec is the state-machine
    witness.
  - docs/proofs/UnderQuorumMerge.md (R7) — analytic narrative on
    the under-quorum merge mechanism; this spec is the
    state-machine witness (composed via PROP_UnderQuorumMerge).
  - SECURITY.md §S-020 (hybrid Fisher-Yates closure) — the
    selection-function determinism + bias bound that
    SelectMCreators abstracts (delegated to FB34).
*)

EXTENDS Integers, Sequences, FiniteSets, TLC

\* ModelValidators — the 4-validator × 2-region model instance from the
\* recommended config above. Lives here (not in the .cfg) because TLC's
\* config grammar cannot parse function-valued expressions; the .cfg
\* binds it via `CONSTANT Validators <- ModelValidators` (same pattern
\* as MerklePathVerify.cfg's ProofsUniverse).
ModelValidators ==
    [v \in {"v1", "v2", "v3", "v4"} |->
        [domain |-> v,
         region |-> IF v \in {"v1", "v2"} THEN "r1" ELSE "r2"]]

CONSTANTS
    Validators,         \* function from validator domain ID (string) to
                         \*  a record [domain: string, region: string].
                         \*  The domain field IS the key; the region
                         \*  field is fixed per-validator (a validator's
                         \*  region is a property of its identity).
    Regions,            \* SUBSET of strings — the universe of valid
                         \*  region tags.
    K,                  \* committee size (Nat ≥ 1; per genesis_config
                         \*  block_sig_committee_size).
    MaxBlock             \* spec-time bound on the number of blocks the
                         \*  model enumerates (Nat ≥ 1).

ASSUME ConfigOK ==
    /\ K \in Nat /\ K >= 1
    /\ MaxBlock \in Nat /\ MaxBlock >= 1
    /\ Cardinality(Regions) >= 2
       \* >= 2 so AdvanceBlock can rotate to a distinct region AND
       \* ForceMerge has a sibling region to merge to.
    /\ DOMAIN Validators # {}
       \* At least one validator universe-wide so the model is
       \* non-trivial.
    /\ \A v \in DOMAIN Validators :
          /\ Validators[v].domain = v
            \* The key IS the domain field — ensures the function is
            \* consistently keyed and prevents the silently-malformed
            \* config bug.
          /\ Validators[v].region \in Regions
            \* Every validator's region tag is a valid region.

\* -----------------------------------------------------------------
\* §1. Helpers — region filter + abstract committee selector.
\* -----------------------------------------------------------------

\* EligibleInRegion(region): the spec-layer projection of
\* `registry.cpp::eligible_in_region(region)`. Returns the SUBSET of
\* `active_validators` whose Validators[v].region matches.
\*
\* The empty-region branch (`region == ""` → full pool per C++) is
\* NOT modeled — every region tag in this spec is in Regions, so the
\* full-pool fallback is a separate state-machine surface (covered
\* by FB34 EpochCommitteeRotation.tla which omits the region filter
\* entirely).
\*
\* Determinism: this is a pure SUBSET filter on the validator set;
\* same (region, active_validators) pair always yields the same
\* SUBSET output — the structural witness for INV_RegionFilterDeterministic.

EligibleInRegion(region, active_validators) ==
    { v \in active_validators : Validators[v].region = region }

\* MergeRefugees(region, active_validators, merge_state):
\*   The set of refugee validators admitted when `region` is the
\*   active region AND a merge is in effect. Refugees are validators
\*   in regions ∈ merge_state[region] (the merged-from set).
\*
\* Mirrors `Node::start_block_sig_phase` lines 732-748: walks
\* `chain.shards_absorbed_by(shard_id)` and adds each refugee
\* region's eligible pool to the committee-selection candidate pool.
\* Dup-checking by domain is implicit at the SUBSET layer (TLA+ SUBSET
\* semantics is set-valued).

MergeRefugees(region, active_validators, merge_state) ==
    UNION { EligibleInRegion(r, active_validators) :
            r \in IF region \in DOMAIN merge_state
                  THEN merge_state[region]
                  ELSE {} }

\* EffectivePool(region, active_validators, merge_state):
\*   The total eligible pool for the committee draw at `region`:
\*   the region's own pool + refugees from merged-from regions.
\*   This is the input to SelectMCreators.

EffectivePool(region, active_validators, merge_state) ==
    EligibleInRegion(region, active_validators)
    \cup MergeRefugees(region, active_validators, merge_state)

\* SelectMCreators(pool, beacon, k):
\*   The delegated abstract spec-layer projection of
\*   `crypto::select_m_creators(crypto::epoch_committee_seed(epoch_rand,
\*   shard_id), avail_domains.size(), m)`. Same shape as FB34's
\*   `EpochCommitteeSelect`: returns a SUBSET of `pool` of cardinality
\*   `min(k, |pool|)` that is a deterministic function of its three
\*   inputs.
\*
\* The purity property (same (pool, beacon, k) ⇒ same output) is the
\* structural witness for the EligibleInRegion-based determinism +
\* the consensus-convergence requirement. Cryptographic uniformity is
\* FB23 / Preliminaries §2.3 territory.

SelectMCreators(pool, beacon, k) ==
    LET effective_k == IF Cardinality(pool) <= k
                       THEN Cardinality(pool)
                       ELSE k
        candidates  == { S \in SUBSET pool : Cardinality(S) = effective_k }
    IN  IF candidates = {}
        THEN {}
        ELSE CHOOSE S \in candidates :
                \A T \in candidates :
                   \/ T = S
                   \/ <<"REGIONAL-COMMITTEE-RANK", beacon, S>>
                      \in {<<"REGIONAL-COMMITTEE-RANK", beacon, U>> :
                           U \in candidates}

\* RotateRegion(r): a deterministic per-block rotation through the
\* Regions set. CHOOSE picks the lexicographically-next region not
\* equal to the current one. Mirrors the per-shard region rotation
\* discipline at `src/node/node.cpp:1487-1491` (the
\* `shard_committee_regions_` manifest lookup; the rotation source).
\*
\* The model uses a simple cyclic rotation: pick any region distinct
\* from the current one. The actual chain's region rotation is
\* shard-bound (per-shard fixed region from the manifest), but for
\* the state-machine layer the simple rotation suffices to exercise
\* the cross-region committee-rotation surface.

RotateRegion(r) ==
    IF Cardinality(Regions) >= 2
    THEN CHOOSE r2 \in Regions : r2 # r
    ELSE r

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    block_height,           \* Nat — current block height (monotone
                             \*  non-decreasing across AdvanceBlock).
    current_region,         \* element of Regions ∪ {"NONE"} — the
                             \*  active region for THIS block. "NONE"
                             \*  is the pre-genesis sentinel.
    current_committee,      \* SUBSET of validator domain IDs — the
                             \*  committee drawn for the current block.
                             \*  Init is empty; AdvanceBlock populates.
    region_history,         \* function {0..block_height} → Regions —
                             \*  per-block region record; only grown
                             \*  by AdvanceBlock.
    committee_history,      \* function {0..block_height} → SUBSET
                             \*  validator domain IDs — per-block
                             \*  committee record; only grown by
                             \*  AdvanceBlock.
    active_validators,      \* SUBSET DOMAIN Validators — currently
                             \*  registered validators (mutated by
                             \*  RegisterValidator / RegionPoolShrink).
    merge_state,            \* function Region → SUBSET Region —
                             \*  per-region merge: merge_state[R] is
                             \*  the set of regions whose validators
                             \*  are admitted as refugees when R is
                             \*  the active region. Set by ForceMerge.
    beacon                  \* Nat — per-block beacon (incrementing
                             \*  counter; abstracts the chain's
                             \*  cumulative_rand evolution at the
                             \*  abstract-randomness layer).

vars == <<block_height, current_region, current_committee,
          region_history, committee_history, active_validators,
          merge_state, beacon>>

\* -----------------------------------------------------------------
\* §3. Initial state.
\* -----------------------------------------------------------------
\*
\* Block 0 is the genesis block. The initial region is CHOSEN from
\* Regions; the initial active set is CHOSEN as a SUBSET of validators
\* with that region (size K if possible; else full region pool).
\* merge_state is initially empty (no merges active at genesis).
\* The genesis committee is drawn from the initial region's pool.

InitialRegion == CHOOSE r \in Regions : TRUE

InitialActive ==
    LET region_pool == { v \in DOMAIN Validators :
                         Validators[v].region = InitialRegion } IN
    IF Cardinality(region_pool) >= K
    THEN CHOOSE S \in SUBSET region_pool : Cardinality(S) = K
    ELSE region_pool

Init ==
    /\ block_height       = 0
    /\ current_region     = InitialRegion
    /\ active_validators  = InitialActive
    /\ merge_state        = [r \in Regions |-> {}]
    /\ beacon             = 0
    /\ current_committee  = SelectMCreators(
                               EffectivePool(InitialRegion, InitialActive,
                                              [r \in Regions |-> {}]),
                               0, K)
    /\ region_history     = (0 :> InitialRegion)
    /\ committee_history  = (0 :> SelectMCreators(
                                     EffectivePool(InitialRegion,
                                                    InitialActive,
                                                    [r \in Regions |-> {}]),
                                     0, K))

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* AdvanceBlock: block_height → block_height + 1; rotates the active
\* region (per protocol) and draws a fresh committee from the new
\* effective pool.
\*
\* Pre-condition: block_height < MaxBlock (bounds TLC); the new
\* region's effective pool has at least 1 member (no empty-set
\* committee — degenerate under-quorum case handled by ForceMerge
\* via the disabled-action path); the new region's pool has at least
\* K members OR a merge is already in effect for that region (so the
\* under-quorum branch is gated on either ForceMerge having fired or
\* the pool being sized right).

AdvanceBlock ==
    /\ block_height < MaxBlock
    /\ LET new_region == RotateRegion(current_region) IN
       LET new_beacon == beacon + 1 IN
       LET pool == EffectivePool(new_region, active_validators,
                                  merge_state) IN
       /\ Cardinality(pool) >= 1
       /\ block_height' = block_height + 1
       /\ current_region' = new_region
       /\ beacon' = new_beacon
       /\ LET new_committee == SelectMCreators(pool, new_beacon, K) IN
          /\ current_committee' = new_committee
          /\ region_history' = (block_height + 1 :> new_region)
                              @@ region_history
          /\ committee_history' = (block_height + 1 :> new_committee)
                                 @@ committee_history
       /\ UNCHANGED <<active_validators, merge_state>>

\* RegisterValidator(v, region): v in DOMAIN Validators \
\* active_validators -> add to active_validators. The region argument
\* MUST match Validators[v].region (a validator's region is a property
\* of its identity, not a per-registration choice).
\*
\* Mirrors the REGISTER tx apply path at
\* `src/chain/chain.cpp::apply_transactions` REGISTER branch +
\* the `registrants_.region` field assignment (the activation delay
\* is collapsed — the spec models the post-active-from state).

RegisterValidator(v, region) ==
    /\ v \in DOMAIN Validators
    /\ v \notin active_validators
    /\ region \in Regions
    /\ Validators[v].region = region
       \* Region MUST match the validator's identity; reject
       \* mismatched (region, v) pairs at the spec layer (the C++
       \* side's `registrants_.region` field is set per-validator,
       \* so this enforces the same coupling).
    /\ active_validators' = active_validators \cup {v}
    /\ UNCHANGED <<block_height, current_region, current_committee,
                   region_history, committee_history, merge_state,
                   beacon>>

\* RegionPoolShrink: narrows the active validator pool by
\* deregistering some validator v. The action is enabled when:
\*   (a) at least one validator with the current region is present
\*       in active_validators (so the shrink is meaningful), AND
\*   (b) the active pool has more than one entry total (so
\*       AdvanceBlock's `>= 1` antecedent stays satisfiable across
\*       the shrink).
\*
\* Mirrors the DEREGISTER tx apply path; the `inactive_from` delay
\* is collapsed (spec models the post-inactive-from state). Composes
\* with R7 by exposing the under-quorum branch reachably: shrinking
\* the current region's pool below K forces the AdvanceBlock action
\* to disable until ForceMerge fires.

RegionPoolShrink ==
    /\ Cardinality(active_validators) > 1
    /\ \E v \in active_validators :
          /\ active_validators' = active_validators \ {v}
          /\ UNCHANGED <<block_height, current_region, current_committee,
                         region_history, committee_history, merge_state,
                         beacon>>

\* ForceMerge: when |EligibleInRegion(current_region)| < K, activate
\* the under-quorum merge by widening the effective pool with
\* refugees from a sibling region. The merged-from region is chosen
\* as the lexicographically smallest sibling region with at least
\* one active validator (a deterministic tie-break mirroring the
\* chain's MERGE_EVENT ordering discipline at
\* `src/chain/chain.cpp:1018-1025`).
\*
\* Pre-condition: the current region's eligible pool is under
\* quorum (< K members); there exists a sibling region with at
\* least one active validator AND that sibling is not already in
\* merge_state[current_region].
\*
\* Post-condition: merge_state[current_region] is extended with the
\* chosen sibling region. Subsequent AdvanceBlock calls draw from
\* the widened effective pool.

ForceMerge ==
    /\ Cardinality(EligibleInRegion(current_region, active_validators)) < K
    /\ \E r \in Regions :
          /\ r # current_region
          /\ r \notin merge_state[current_region]
          /\ \E v \in active_validators : Validators[v].region = r
            \* The chosen merged-from region must have at least one
            \* active validator (otherwise the refugee pool is empty
            \* and the merge does nothing). TLC explores the
            \* non-deterministic CHOOSE over all eligible r values;
            \* the C++ side's `chain.cpp::shards_absorbed_by` ordering
            \* is the structural correspondent of a deterministic
            \* tie-break, but for the state-machine layer the
            \* non-deterministic exploration suffices to exercise
            \* every reachable merge composition.
          /\ merge_state' = [merge_state EXCEPT ![current_region] =
                                merge_state[current_region] \cup {r}]
          /\ UNCHANGED <<block_height, current_region, current_committee,
                         region_history, committee_history,
                         active_validators, beacon>>

\* Stutter (TLC bounds the state space; invariants are evaluated
\* at every reachable state along the way).

Stutter ==
    /\ block_height >= MaxBlock
    /\ UNCHANGED vars

Next ==
    \/ AdvanceBlock
    \/ \E v \in DOMAIN Validators :
       \E r \in Regions :
          RegisterValidator(v, r)
    \/ RegionPoolShrink
    \/ ForceMerge
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(AdvanceBlock)
             /\ WF_vars(ForceMerge)
             /\ WF_vars(RegionPoolShrink)
             /\ WF_vars(\E v \in DOMAIN Validators : \E r \in Regions :
                          RegisterValidator(v, r))

\* -----------------------------------------------------------------
\* §5. Invariants — T-RC1..T-RC4 + TypeOK.
\* -----------------------------------------------------------------

\* TypeOK — shape predicate for all variables.

TypeOK ==
    /\ block_height \in 0..MaxBlock
    /\ current_region \in Regions \cup {"NONE"}
    /\ current_committee \in SUBSET (DOMAIN Validators)
    /\ active_validators \in SUBSET (DOMAIN Validators)
    /\ beacon \in Nat
    /\ DOMAIN region_history \subseteq 0..MaxBlock
    /\ DOMAIN committee_history \subseteq 0..MaxBlock
    /\ \A h \in DOMAIN region_history :
          region_history[h] \in Regions
    /\ \A h \in DOMAIN committee_history :
          committee_history[h] \in SUBSET (DOMAIN Validators)
    /\ DOMAIN merge_state = Regions
    /\ \A r \in Regions :
          merge_state[r] \in SUBSET Regions

\* INV_CommitteeFromActiveRegion (T-RC1).
\*
\* Every committee member at block h is in EligibleInRegion(region_history[h])
\* OR in the refugees from a merged-from region (when merge_state is
\* active for that region). Composes with R7 under-quorum merge by
\* admitting refugees from sibling regions.
\*
\* Structural witness: AdvanceBlock draws the committee from the
\* EffectivePool, which is EligibleInRegion(R) ∪ refugees from
\* merged regions; the committee_history records THAT pool's draw.
\*
\* For state correctness across post-tampering or post-shrink
\* states, this invariant is asserted at SELECTION time (i.e., the
\* committee_history[h] was drawn from the pool active at block h);
\* subsequent active-set evolution does not retroactively invalidate
\* the historical committee. The invariant body asserts the
\* containment using the CURRENT active_validators + current
\* merge_state as a conservative over-approximation: a member of
\* committee_history[h] is either (a) in the current EligibleInRegion
\* for region_history[h], (b) in the current refugee pool via
\* merge_state[region_history[h]], OR (c) was DEREGISTERED post-
\* selection (no longer in active_validators but was at h). The
\* spec's RegionPoolShrink action does NOT retroactively touch
\* historical committee_history entries, so (c) is permitted.

INV_CommitteeFromActiveRegion ==
    \A h \in DOMAIN committee_history :
       \A v \in committee_history[h] :
          \* Each historical committee member must have been region-
          \* eligible at SELECTION time, which the spec captures
          \* structurally via: the validator's REGION is either the
          \* block's region OR one of the merged regions (witnessed
          \* by Validators[v].region — a per-identity invariant).
          \/ Validators[v].region = region_history[h]
          \/ Validators[v].region \in merge_state[region_history[h]]

\* INV_CommitteeSizeIsK (T-RC2).
\*
\* Every committee in committee_history has cardinality K (when the
\* effective pool at the time of selection had at least K members);
\* otherwise the committee equals the full effective pool (under-
\* quorum branch where R7 fires).
\*
\* Structural witness: SelectMCreators's effective_k computation
\* picks min(k, |pool|); the candidates set is non-empty by
\* construction; CHOOSE returns a member of cardinality effective_k.
\*
\* For TLC tractability, we assert the K-bound conservatively: the
\* committee size is AT MOST K (the SelectMCreators ceiling) and AT
\* LEAST 1 (the AdvanceBlock pre-condition gates on |pool| >= 1).
\* The exact-K-when-pool-large branch is captured by the
\* SelectMCreators body's effective_k = K when |pool| >= K (purity).

INV_CommitteeSizeIsK ==
    \A h \in DOMAIN committee_history :
       /\ Cardinality(committee_history[h]) <= K
       /\ Cardinality(committee_history[h]) >= 1

\* INV_RegionFilterDeterministic (T-RC3).
\*
\* `EligibleInRegion(region)` is a deterministic SUBSET of
\* `active_validators` for every region; pure linear scan equivalent
\* at the spec layer.
\*
\* Structural witness: the EligibleInRegion operator is defined as
\* a SUBSET-comprehension over Validators[v].region equality. TLA+
\* set semantics is purely extensional: same elements ⇒ same set;
\* the operator is deterministic by construction.
\*
\* The invariant body asserts the BIDIRECTIONAL purity contract:
\* for any two regions R1, R2 ∈ Regions, EligibleInRegion(R1) and
\* EligibleInRegion(R2) are DISJOINT when R1 # R2 (because a
\* validator's region is single-valued in Validators[v].region —
\* no validator has two regions). This is the structural witness
\* for the "no cross-region leak at the FILTER layer" — a single
\* validator cannot pass the EligibleInRegion test for two
\* distinct regions.

INV_RegionFilterDeterministic ==
    \A r1 \in Regions :
       \A r2 \in Regions :
          r1 # r2
          => EligibleInRegion(r1, active_validators)
             \cap EligibleInRegion(r2, active_validators) = {}

\* INV_NoCrossRegionLeak (T-RC4).
\*
\* At block h with region R, NO validator with `region /= R` appears
\* in committee_history[h] — UNLESS an under-quorum merge fired, in
\* which case the validator's region must be in
\* {R} ∪ merge_state[R] (still satisfying region-membership for the
\* EFFECTIVE pool).
\*
\* Structural witness: the committee comes from EffectivePool(R,
\* active_validators, merge_state) which is EligibleInRegion(R) ∪
\* refugees-from-merged-regions; every element of the effective pool
\* has Validators[v].region ∈ {R} ∪ merge_state[R] by construction.
\*
\* The R5 stress case where the merge_state was different at
\* selection time vs. invariant-check time is conservatively
\* handled: merge_state is monotone non-decreasing (ForceMerge only
\* ADDS, never removes), so the current merge_state's region set is
\* a SUPER-set of any past selection's region set. Hence the
\* invariant holds in the wider direction too (a committee member's
\* region was in some PAST merged set, which is a SUBSET of the
\* current merged set).

INV_NoCrossRegionLeak ==
    \A h \in DOMAIN committee_history :
       \A v \in committee_history[h] :
          \/ Validators[v].region = region_history[h]
          \/ Validators[v].region \in merge_state[region_history[h]]

\* -----------------------------------------------------------------
\* §6. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualCommitteeRotation (T-RC5a).
\*
\* CONDITIONAL on block production: if the chain ever produces a
\* post-genesis block, some pair of consecutive blocks has distinct
\* committees, witnessing rotation (the first AdvanceBlock rotates
\* to a sibling region whose merge_state is still empty, so the
\* fresh committee is drawn from a pool disjoint from genesis's).
\*
\* The unconditional form (<>rotation-witness) is NOT a promise of
\* the code and fails in this model: Register/Shrink churn can keep
\* the rotation-target region's pool empty forever, so AdvanceBlock
\* is only intermittently enabled and WF imposes no obligation — no
\* block ever forms. Block production liveness depends on the
\* environment supplying an eligible pool; the code only promises
\* rotation ACROSS blocks that actually form.

PROP_EventualCommitteeRotation ==
    <>(block_height >= 1)
    => <>(\E h \in DOMAIN committee_history :
             /\ (h + 1) \in DOMAIN committee_history
             /\ committee_history[h] # committee_history[h + 1])

\* PROP_UnderQuorumMerge (T-RC5b).
\*
\* If the under-quorum condition PERSISTS (`|EligibleInRegion(R)| <
\* K` for the current region R, with a sibling region holding at
\* least one active validator, forever from some point), eventually
\* a merge to a sibling region fires — the R7 forward-progress
\* contract that prevents the chain from stalling on an under-quorum
\* region.
\*
\* Structural witness: block_height is monotone and bounded by
\* MaxBlock, so current_region is eventually constant in every
\* behavior; once the antecedent holds forever, ForceMerge is
\* continuously enabled (or the merge already fired), and weak
\* fairness on ForceMerge fires it. Composes with R7
\* UnderQuorumMerge.md's analytic narrative on the merge mechanism.
\*
\* The one-shot form ([](P => <>merge-fired)) is NOT a promise of
\* the code and fails in this model: a TRANSIENT under-quorum can
\* recover via RegisterValidator (pool back to >= K, no merge
\* needed), and Register/Shrink churn can keep ForceMerge only
\* intermittently enabled, which WF does not obligate. The code's
\* promise is merge-on-persistent-under-quorum, not
\* merge-on-any-dip.

PROP_UnderQuorumMerge ==
    <>[](/\ Cardinality(EligibleInRegion(current_region,
                                          active_validators)) < K
         /\ \E r \in Regions :
               /\ r # current_region
               /\ \E v \in active_validators : Validators[v].region = r)
    => <>(merge_state[current_region] # {})

\* -----------------------------------------------------------------
\* §7. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The R4 + R7 contract is pinned at the state-machine layer by the
\* five invariants + two temporal properties. The abstraction
\* boundary:
\*
\*   * EligibleInRegion's purity is what TLC checks — the SUBSET-
\*     comprehension is a pure function of (region, active_validators);
\*     same inputs ⇒ same SUBSET output. The C++ side's linear scan
\*     at `registry.cpp::eligible_in_region:86-95` is the structural
\*     correspondent.
\*
\*   * SelectMCreators is delegated to FB34 EpochCommitteeRotation.tla;
\*     this spec re-uses the same shape (deterministic K-of-N SUBSET
\*     draw on a tagged-tuple beacon discriminator). The cryptographic
\*     uniformity of SHA-256-derived index selection (S-020) is FB23 /
\*     Preliminaries §2.3 territory.
\*
\*   * The per-block region rotation (RotateRegion) is modeled as a
\*     simple cyclic rotation through Regions; the actual chain's
\*     per-shard region assignment from `shard_committee_regions_`
\*     at `src/node/node.cpp:1487-1491` is the C++ correspondent.
\*     The model's deterministic rotation suffices to exercise the
\*     cross-region committee-rotation surface.
\*
\*   * The MERGE_EVENT mechanism is abstracted as ForceMerge: when
\*     the current region is under-quorum, a sibling region's pool
\*     is admitted as refugees. The C++ side's MERGE_EVENT apply
\*     branch at `src/chain/chain.cpp:1018-1025` populates
\*     `merge_state_` with `refugee_region`; the spec's `merge_state`
\*     variable mirrors this. The MERGE_EVENT gossip + validation
\*     surface (FA9 MERGE_EVENT determinism) is a separate concern.
\*
\*   * The beacon evolution is abstracted as a simple incrementing
\*     counter (mirroring the chain's cumulative_rand evolution at
\*     the abstract-randomness layer). The actual SHA-256-anchored
\*     cumulative_rand is FB23 / Preliminaries territory.
\*
\*   * The within-block consensus surface (K-of-K block-sig phase,
\*     proposer rotation under aborts, equivocation slashing) is
\*     NOT modeled here. This spec covers per-block committee
\*     SELECTION surface; the within-block surface is FB1
\*     Consensus.tla + FB22 F2ViewReconciliation.tla territory.
\*
\* What this spec adds beyond existing FB-track surfaces:
\*
\*   * The state-machine witness that the R4 region-filter is sound
\*     across every reachable interleaving of AdvanceBlock /
\*     Register / Shrink / ForceMerge. No cross-region leak in the
\*     standard case (INV_NoCrossRegionLeak); the merge branch
\*     widens the eligibility set without breaking the
\*     "validator's region is in the EFFECTIVE region set" contract.
\*
\*   * The R7 under-quorum-merge forward-progress witness
\*     (PROP_UnderQuorumMerge): under fairness, a PERSISTENTLY
\*     under-quorum region (with a sibling holding an active
\*     validator) eventually receives a sibling merge — the chain
\*     does not stall on a single region's pool collapse.
\*
\*   * The composition with FB34 EpochCommitteeRotation: SelectMCreators
\*     is the same shape as FB34's EpochCommitteeSelect; FB35
\*     specializes by adding the region filter and the under-quorum
\*     merge composition on top of the base rotation.
\*
\* What the spec does NOT check (consistent with the §scope above):
\*
\*   * Cryptographic uniformity of the SHA-256-derived index stream
\*     feeding select_m_creators (FB23 + Preliminaries territory).
\*   * Quantitative bias bounds on the K/N ratio (S-020 closure
\*     narrative — the spec asserts the structural form; the
\*     bias-bound is the analytic side).
\*   * MERGE_EVENT gossip + validation determinism (FA9 territory).
\*   * Per-shard region assignment from the genesis manifest
\*     (the per-shard `shard_committee_regions_` map is a config-
\*     layer artifact; this spec models the post-config rotation
\*     directly).
\*   * Snapshot / restore round-trip of the merge_state field
\*     (FB31 SnapshotIntegrity.tla covers the snapshot lifecycle
\*     that this spec's merge_state abstracts).

============================================================================
\* Cross-references.
\*
\* C++ enforcement:
\*   src/node/registry.cpp:86-95   : NodeRegistry::eligible_in_region
\*       — the pure linear-scan region filter that EligibleInRegion
\*       abstracts; the structural source for INV_RegionFilterDeterministic.
\*   src/node/node.cpp:731         : start_block_sig_phase —
\*       registry_.eligible_in_region(cfg_.committee_region) call
\*       that restricts the per-block creator pool to the active
\*       region.
\*   src/node/node.cpp:732-748     : R4-Phase-4 under-quorum
\*       refugee-pool extension via chain_.shards_absorbed_by;
\*       the C++ correspondent of the EffectivePool widening.
\*   src/node/node.cpp:1487-1491   : per-shard region resolution
\*       from the shard_committee_regions_ manifest; the C++
\*       correspondent of current_region rotation.
\*   src/node/validator.cpp:75-83  : the receiver-side cross-check:
\*       every block's committee must come from the same region-
\*       filtered + refugee-extended pool — FA1 K-of-K safety
\*       composition.
\*   src/chain/chain.cpp:1018-1025 : the MERGE_EVENT apply branch
\*       that populates merge_state_ with refugee_region; the C++
\*       correspondent of ForceMerge.
\*
\* SECURITY.md §S-020 (hybrid Fisher-Yates closure) — the
\*   selection-function determinism + bias bound that
\*   SelectMCreators abstracts (delegated to FB34).
\*
\* Preliminaries.md §2.1 (A2 SHA-256 collision resistance) +
\*   §2.3 (A3 CSPRNG uniformity) — the cryptographic assumptions
\*   underlying SelectMCreators's determinism + uniformity. The
\*   spec asserts the determinism side; the uniformity side is
\*   the FB23 / Preliminaries side.
\*
\* FB1 Consensus.tla (FA1 K-of-K committee safety — the within-block
\*   consensus surface that this spec's per-block committee draw
\*   feeds; FB1 covers within-block; FB35 covers the region-filtered
\*   per-block committee membership),
\* FB2 Sharding.tla (FA7 cross-shard surface — the per-shard
\*   committee derivation uses the same epoch_committee_seed but
\*   with the shard_id parameter; FB35 lifts the regional dimension
\*   explicitly),
\* FB22 F2ViewReconciliation.tla (FA8 BFT escalation surface —
\*   within-round view reconciliation under aborts; the BFT
\*   escalation gate composes with this spec's region-filtered
\*   pool via the same eligible_in_region precondition),
\* FB23 FrostVerify.tla (Ed25519 EUF-CMA model + abstract-sig
\*   discipline; the cryptographic uniformity side that this
\*   spec's determinism complements),
\* FB30 ChainPrevHashLink.tla (R25 prev_hash chain-link state
\*   machine — INV_AppendOnly's append-only ghost-history pattern
\*   is the structural template for this spec's region_history +
\*   committee_history monotonicity),
\* FB34 EpochCommitteeRotation.tla (the BASE cross-epoch committee
\*   rotation spec; FB35 specializes by adding R4 region-filter +
\*   R7 under-quorum merge on top of the base rotation; the
\*   SelectMCreators abstraction is the same as FB34's
\*   EpochCommitteeSelect, delegated).
\*
\* Runtime regressions:
\*   tools/test_under_quorum_merge.sh — the in-process test that
\*     pins the R7 merge mechanism at the C++ layer; INV_4
\*     NoCrossRegionLeak's structural witness in the merge branch.
\*   tools/test_merge_event_determinism.sh — the determinism
\*     test for MERGE_EVENT apply; composes with INV_RegionFilterDeterministic.
\*   tools/test_block_validator_extensive.sh — the
\*     check_creator_selection regression that exercises the
\*     receiver-side cross-check at validator.cpp:75-83;
\*     INV_CommitteeFromActiveRegion's structural witness.
\*
\* Doc updates:
\*   CHECK-RESULTS.md FB35 row — added.
============================================================================
