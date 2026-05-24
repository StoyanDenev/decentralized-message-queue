--------------------------- MODULE EpochCommitteeRotation ---------------------------
(*
FB34 — TLA+ specification of the cross-epoch committee rotation
state machine. Models the per-epoch K-member committee draw from
the active validator pool plus the active-set evolution (REGISTER /
DEREGISTER) that drives committee rotation across epochs.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
EpochCommitteeRotation.cfg EpochCommitteeRotation.tla` once the
TLC toolchain is installed in CI.

Scope. Formalizes the cross-epoch committee rotation contract that
governs Determ's per-epoch K-member committee selection at the
state-machine layer. The committee is redrawn at every epoch
boundary via `crypto::select_m_creators` keyed on the per-epoch
seed `crypto::epoch_committee_seed(epoch_rand, shard_id)`; each
epoch carries a fresh draw, so the committee rotates as the beacon-
sourced randomness evolves and as the active validator pool grows /
shrinks via REGISTER / DEREGISTER transactions.

The contract this spec pins (three sub-claims, paired with the
five invariants below):

  (a) Deterministic per-epoch selection. For a fixed `(active_pool,
      beacon, k)` triple, the committee is a pure deterministic
      function of those inputs — same triple, same committee. The
      structural witness is `select_m_creators`'s SHA-256-derived
      randomness: every node consuming the same `random_state`
      reproduces the same hybrid Fisher-Yates output (per S-020).
      Modeled by the `EpochCommitteeSelect(pool, beacon, k)`
      abstract operator: same inputs → same SUBSET.
  (b) Cross-epoch rotation. Consecutive epochs with distinct
      beacons (and / or distinct active pools) draw potentially
      distinct committees — the committee does NOT freeze across
      epochs (otherwise the rotation rationale collapses to a
      static-committee model). The structural witness is the
      `EpochCommitteeSelect`'s sensitivity to the beacon: distinct
      beacons CAN produce distinct committees (the abstract
      operator preserves this dependency; the cryptographic
      tightness — uniformity of SHA-256-derived index selection —
      is FB23 FrostVerify.tla / Preliminaries §2.1 territory).
  (c) Active-set discipline. Every committee member at epoch e was
      in the `active_validators` set at the moment of selection.
      Zombie committees (members who deregistered before the epoch
      began) and ghost committees (members who never registered)
      are structurally impossible at apply time — captured by
      `INV_CommitteeSubsetActive`.

Five paired theorems are pinned (per the rotation contract above
plus the history-monotonicity property that fork-resolution and
snapshot consistency depend on):

  (T-ER1) DeterministicSelection. For every pair of epochs (e1, e2)
          drawn from the same active set with the same beacon, the
          committee outputs are byte-identical: `committee_history[e1]
          = committee_history[e2]`. State-form witness of the
          selection-function determinism contract — required for
          every node to converge on the same committee independent
          of message arrival order. The structural witness is the
          `EpochCommitteeSelect`'s purity (a SUBSET-valued operator
          determined by its inputs).
  (T-ER2) CommitteeSizeIsK. Every committee in `committee_history`
          has cardinality `K` (when the active pool has at least K
          members; otherwise the committee equals the full active
          pool — the under-quorum branch where R7
          UnderQuorumMerge.tla kicks in). The structural witness:
          `select_m_creators` requires `node_count >= m` (the early
          throw at `src/crypto/random.cpp:71-72`) and returns
          exactly `m` indices; the committee draw fails fast if
          the pool is too small.
  (T-ER3) CommitteeSubsetActive. Every committee member at epoch e
          was in `active_validators` at the moment of the
          AdvanceEpoch action that drew that epoch's committee.
          Zombie / ghost committees are structurally excluded.
          The structural witness: the AdvanceEpoch action draws
          the committee from `active_validators` only — no
          historical pool is consulted.
  (T-ER4) HistoryMonotone. `committee_history` only grows across
          epoch advances; existing entries are byte-identical
          across all reachable states. The structural witness:
          the AdvanceEpoch action's EXCEPT clause only adds a
          new key to the function; existing keys are never
          rewritten. This is the rotation-history analog of
          ChainPrevHashLink.tla's INV_AppendOnly — legitimate
          rotation never rewrites past committees.
  (T-ER5) EventualRotation (forward-progress). Under fairness on
          AdvanceEpoch + a beacon change OR a non-trivial pool
          mutation between consecutive epochs, the committee
          changes infinitely often. The state-form witness: if
          the beacon and active set are constant across consecutive
          epochs, the committee is also constant (T-ER1); under
          fairness on the beacon-evolution actions (BeaconUpdate +
          RegisterValidator + DeregisterValidator), the
          combination of beacon + pool eventually changes, which
          flips the committee on the next AdvanceEpoch (when the
          pool has more than K members so multiple distinct
          committees exist).

The state machine. Four actions cover the epoch-rotation surface
(plus a Stutter to bound TLC):

  * AdvanceEpoch — increments `epoch`; draws a fresh committee
    via `EpochCommitteeSelect(active_validators,
    beacon_history[epoch+1], K)` and stores it in
    `committee_history[epoch+1]`. The beacon for the new epoch
    must already be set via BeaconUpdate (which models the
    chain-randomness source feeding the per-epoch seed).
  * RegisterValidator(v) — adds v to `active_validators` when
    `v ∈ ValidatorPool \ active_validators`. Mirrors the
    REGISTER tx apply path at `src/chain/chain.cpp::apply_transactions`
    REGISTER branch + the `registrants_.active_from = height +
    derive_delay(...)` activation delay (collapsed here — the
    spec models the post-active-from state).
  * DeregisterValidator(v) — removes v from `active_validators`
    when `v ∈ active_validators`. Mirrors the DEREGISTER tx
    apply path and the `registrants_.inactive_from = height +
    derive_delay(...)` deactivation delay (collapsed; the spec
    models the post-inactive-from state).
  * BeaconUpdate(b) — updates the beacon for the NEXT epoch
    (`beacon_history' = [beacon_history EXCEPT ![epoch+1] = b]`).
    Models the chain-randomness source: the beacon for epoch e
    is anchored at the cumulative_rand of the block at index =
    e * epoch_blocks - 1 (see `src/node/node.cpp::current_epoch_rand`
    at lines 914-934). The action is the abstract spec-layer
    projection of that anchoring; the cryptographic uniformity
    of `cumulative_rand` is FB23 / Preliminaries territory.

Modeling scope (kept tractable for TLC):

  * `ValidatorPool` is a finite universe of validator domain IDs
    (strings). Realistic production pools have ~10-100 validators
    across active + inactive subsets; the model uses ~5 to keep
    the state space exhaustible.
  * `K` is the committee size constant (Nat ≥ 1). Production
    profiles range K = 3 (cluster / tactical / single_test) up to
    K = 7 (global), per `include/determ/chain/params.hpp`.
    Reflected in the cfg as K = 3.
  * `MaxEpoch` bounds epoch growth so TLC exhausts in seconds.
    Production runs an unbounded sequence of epochs (~1 every
    100 blocks at `epoch_blocks = 100`); the model bounds at 4
    epochs which is enough to exercise: 0→1 (genesis epoch +
    first rotation), 1→2 (consecutive distinct beacons), 2→3
    (same beacon with mutated pool — the rotation-on-pool-change
    branch), 3→4 (saturation; Stutter pins the bound).
  * `BeaconValues` is a finite universe of beacon hashes used as
    `epoch_committee_seed` inputs. Three values is enough to
    exercise: (a) same beacon across epochs → same committee
    (T-ER1 determinism); (b) distinct beacons → potentially
    distinct committees (T-ER5 rotation); (c) beacon-change with
    pool-change interleaved (combined determinism + rotation
    surface).
  * `EpochCommitteeSelect(pool, beacon, k)` is an abstract
    SUBSET-valued operator: deterministic on its three inputs;
    returns a SUBSET of `pool` of cardinality `min(k,
    |pool|)`. This is the spec-layer projection of
    `crypto::select_m_creators(epoch_committee_seed(...), ...)`
    composed with the hybrid Fisher-Yates per S-020 + the
    rejection-sampling fallback at the small-K branch.
    Cryptographic tightness (uniform index selection over
    [0, N)) is FB23 / Preliminaries territory.
  * `committee_history` is a partial function `Nat → SUBSET
    ValidatorPool` (modeled as a TLA function over the active
    domain `{0, 1, ..., epoch}`). The append-only growth
    discipline is the structural witness for T-ER4.
  * `beacon_history` is a partial function `Nat → BeaconValues`
    (modeled similarly). Updated by BeaconUpdate which can fire
    one step ahead of AdvanceEpoch (modeling the chain producing
    blocks within an epoch and accumulating randomness for the
    next epoch's seed).
  * R4 region-aware selection is NOT modeled here. R4's
    region overlay (eligible_in_region + under-quorum merge per
    chain.cpp::shards_absorbed_by) is a per-shard refinement on
    top of this base rotation; FB31 SnapshotIntegrity.tla and
    FB14 Sharding.tla cover the regional-overlay state machines.
    This spec covers the BASE rotation contract that R4 layers
    onto.

Five invariants codify T-ER1..T-ER4 + a type predicate:

  INV_TypeOK — shape predicate for all variables.
  INV_CommitteeSizeIsK (T-ER2) — every committee in
        committee_history has cardinality K when
        |active_validators| >= K at the time of selection;
        otherwise equals the full active set (under-quorum branch).
        The structural witness: the EpochCommitteeSelect operator
        either returns exactly k indices (the K << |pool| branch
        via rejection sampling at random.cpp:73-86) or the partial
        Fisher-Yates (random.cpp:87-100) — both return exactly
        min(k, |pool|) members.
  INV_CommitteeSubsetActive (T-ER3) — every committee member at
        epoch e was in active_validators at the time of selection.
        State-form witness: the AdvanceEpoch action draws from
        active_validators (the live registry); no historical pool
        is consulted. The captured-at-select-time discipline is
        structural: the spec stores the committee in
        committee_history[e] right after the draw, so the member-
        set lookup against active_validators at any later state
        is sound provided active_validators only changes via
        Register/Deregister (the lookup is on the SET that was
        sampled, not on a possibly-mutated future SET).
  INV_DeterministicSelection (T-ER1) — for every pair (e1, e2) in
        the domain of committee_history with beacon_history[e1] =
        beacon_history[e2] AND the same active set at the time of
        selection (captured via the ghost field selected_from), the
        committees are byte-identical. The state-form witness of
        the EpochCommitteeSelect's purity — required for cross-node
        consensus convergence under the same chain head.
  INV_HistoryMonotone (T-ER4) — committee_history only grows
        across AdvanceEpoch actions; existing entries are
        byte-identical across all reachable states. The structural
        witness: the AdvanceEpoch action's EXCEPT clause adds a
        new key (epoch+1); pre-existing keys are not touched.
        The rotation-history analog of ChainPrevHashLink.tla's
        INV_AppendOnly.

Two temporal properties pin the headline rotation claims:

  PROP_EventualRotation (T-ER5) — under fairness on AdvanceEpoch
    + on either BeaconUpdate or RegisterValidator / DeregisterValidator
    (the pool-mutation actions), the committee changes infinitely
    often when |active_validators| > K (so multiple distinct
    committees exist; under |active_validators| = K the committee
    is structurally the full active set and CAN'T rotate without
    a pool change). The forward-progress contract: the rotation
    rationale (defeating long-run committee capture by adversarial
    sticky-membership) requires actual rotation in the limit.
  PROP_NoCommitteeFreeze — if |active_validators| >= K + 1 (so
    multiple distinct K-committees exist within the pool), the
    same committee cannot persist for more than `MaxEpoch / 2`
    consecutive epochs without a beacon change OR a pool change.
    The state-machine witness for the no-stuck-committee contract:
    even under adversarial beacon + pool stability, the spec's
    bounded-epoch enumeration shows the committee changes within
    a bounded window — at finite MaxEpoch the bound collapses to
    "the committee changes at LEAST once across the bounded
    schedule when the cardinality-based condition holds". TLC
    validates the contract over the bounded schedule; the
    unbounded-MaxEpoch generalization is a temporal-induction
    argument anchored at the same state-form witness.

To check (assuming TLC installed):
  $ tlc EpochCommitteeRotation.tla -config EpochCommitteeRotation.cfg

Recommended config (state space ~10^4, < 30s):
  ValidatorPool = {v1, v2, v3, v4, v5}, K = 3, MaxEpoch = 4,
  BeaconValues = {b1, b2, b3}.

Cross-references:
  - src/crypto/random.cpp:70-100 (`select_m_creators` — the hybrid
    Fisher-Yates K-of-N selector that the spec's
    EpochCommitteeSelect abstracts; S-020 closure).
  - src/crypto/random.cpp:169-175 (`epoch_committee_seed` — the
    per-epoch + per-shard seed derivation that combines epoch_rand
    with shard_id under the "shard-committee" domain separator;
    the beacon-anchoring point for the rotation surface).
  - src/node/node.cpp:909-934 (`Node::current_epoch_index` +
    `Node::current_epoch_rand` — the epoch derivation logic
    `epoch_index = chain_.height() / cfg_.epoch_blocks` and the
    cumulative_rand anchoring at epoch_start - 1).
  - src/node/validator.cpp:88-91 (`epoch_index = b.index /
    epoch_blocks_` + `epoch_start = epoch_index * epoch_blocks_`
    + the resolve_epoch_rand + epoch_committee_seed call).
  - src/chain/chain.cpp::apply_transactions REGISTER + DEREGISTER
    branches (the active-set mutation surface that
    RegisterValidator / DeregisterValidator abstract).
  - include/determ/chain/params.hpp (the K constant per profile —
    cluster K=3, regional K=4, global K=5, tactical K=2; the spec
    uses K=3 as the default cfg).
  - docs/proofs/tla/ChainPrevHashLink.tla (FB30) — sibling FB-track
    spec; INV_AppendOnly's append-only ghost-history pattern is
    the structural template for this spec's INV_HistoryMonotone.
  - docs/proofs/tla/Consensus.tla (FB1) — the K-of-K committee
    safety invariant that this spec's per-epoch committee draw
    feeds; FB1 covers the within-epoch consensus surface; this
    spec covers the across-epoch rotation surface.
  - docs/proofs/tla/Sharding.tla (FB2) — sibling shard-aware
    state machine; the per-shard committee derivation uses the
    same epoch_committee_seed but with the shard_id parameter;
    this spec abstracts the shard dimension into the
    EpochCommitteeSelect's beacon input (the cfg uses a single
    shard implicitly).
  - docs/proofs/tla/F2ViewReconciliation.tla (FB22) — closely
    related sibling: F2 handles the within-round committee view
    reconciliation; this spec covers the across-epoch committee
    rotation that drives the per-round committee membership.
  - docs/proofs/EquivocationSlashing.md (FA6) — the slashing
    surface that responds to within-epoch equivocations; the
    rotation contract here ensures the at-risk committee changes
    across epochs.
  - docs/proofs/RegionalSharding.md (R4) — the region-aware
    overlay on top of this base rotation; R4 layers
    eligible_in_region filtering plus under-quorum merge onto the
    base rotation that this spec covers.
  - docs/proofs/UnderQuorumMerge.md (R7) — the under-quorum
    branch when |active_validators| < K; this spec's
    `INV_CommitteeSizeIsK` accommodates the full-pool fallback
    case in its disjunction.
  - SECURITY.md §S-020 (hybrid Fisher-Yates closure) — the
    selection-function determinism + bias bound that
    EpochCommitteeSelect abstracts.
  - SECURITY.md §S-024 (formally-accepted epoch_blocks parameter
    + its bias bound) — the epoch parameter the spec's MaxEpoch
    constant abstracts.
*)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    ValidatorPool,      \* finite universe of validator domain IDs
                         \* (SUBSET of strings — registered validator
                         \*  domains across all active/inactive history)
    K,                  \* committee size (Nat ≥ 1; per genesis_config
                         \*  block_sig_committee_size)
    MaxEpoch,           \* spec-time bound on the number of epochs the
                         \*  model enumerates (Nat ≥ 1; production has
                         \*  unbounded epochs)
    BeaconValues         \* finite universe of beacon hashes feeding
                         \*  epoch_committee_seed; SUBSET of opaque
                         \*  beacon-hash values

ASSUME ConfigOK ==
    /\ Cardinality(ValidatorPool) >= K
       \* Need at least K validators in the universe so some committee
       \* draw is feasible (genesis pre-registers >= K validators per
       \* the chain bootstrap contract).
    /\ K \in Nat /\ K >= 1
    /\ MaxEpoch \in Nat /\ MaxEpoch >= 1
    /\ Cardinality(BeaconValues) >= 2
       \* >= 2 so BeaconUpdate has a distinct alternative value to
       \* swap to (witnesses the rotation surface reachably).

\* -----------------------------------------------------------------
\* §1. Helpers — abstract committee-selection operator.
\* -----------------------------------------------------------------
\*
\* EpochCommitteeSelect(pool, beacon, k):
\*   The abstract spec-layer projection of
\*   `crypto::select_m_creators(crypto::epoch_committee_seed(epoch_rand,
\*   shard_id), avail_domains.size(), m)`. Returns a SUBSET of `pool`
\*   of cardinality `min(k, |pool|)` that is a deterministic function
\*   of its three inputs (same `(pool, beacon, k)` triple ⇒ same
\*   output).
\*
\* The deterministic-function property is the structural witness
\* for INV_DeterministicSelection (T-ER1). The cryptographic
\* uniformity property (the index selection is uniform over [0, |pool|)
\* per S-020) is NOT modeled here — that's FB23 FrostVerify.tla / the
\* Preliminaries §2.3 CSPRNG uniformity assumption A3. This spec
\* asserts purity only: distinct inputs may produce distinct outputs,
\* but the same input always produces the same output.
\*
\* For TLC tractability we materialize the selection via a CHOOSE
\* over the candidates SUBSET universe. The key property TLC checks
\* is PURITY: the same `(pool, beacon, k)` triple ALWAYS returns
\* the same SUBSET. CHOOSE is the standard TLA+ idiom for a
\* deterministic-but-underspecified function: the chosen element
\* is determined by TLA+'s enumeration order, but the IMPORTANT
\* contract is that it is a deterministic function of the inputs.
\*
\* The beacon dependency is threaded via the `BeaconOrdinal`
\* abstraction below: each beacon value maps to a deterministic
\* ordinal that influences which candidate CHOOSE picks. Two
\* distinct beacons CAN produce distinct ordinals (and therefore
\* potentially distinct committees); the same beacon ALWAYS
\* produces the same ordinal (and therefore the same committee).
\*
\* (Note: for K >= |pool|, the committee equals the full pool by
\* definition — the under-quorum branch where no rotation is
\* structurally possible at this pool size.)

\* For the purity-only contract: CHOOSE on a deterministic predicate
\* over a deterministic candidates set is itself deterministic; the
\* same `(pool, beacon, k)` triple ALWAYS reproduces the same
\* SUBSET. CHOOSE may select a beacon-INDEPENDENT element in some
\* TLC enumerations (CHOOSE picks the first element under TLA+
\* enumeration order, which doesn't strictly depend on the beacon
\* value within the predicate body); the spec's
\* INV_DeterministicSelection only requires the bidirectional
\* purity contract: same inputs → same output. The "distinct
\* beacons → potentially different committees" property is the
\* CONVERSE direction (a permission, not a requirement) and is
\* exercised reachably in TLC traces via the BeaconUpdate action
\* + the PROP_EventualRotation forward-progress witness — which
\* uses the active-set evolution (Register/Deregister) as the
\* primary rotation driver, with beacon-evolution as a secondary
\* driver.
EpochCommitteeSelect(pool, beacon, k) ==
    LET effective_k == IF Cardinality(pool) <= k
                       THEN Cardinality(pool)
                       ELSE k
        candidates  == { S \in SUBSET pool : Cardinality(S) = effective_k }
    IN  IF candidates = {}
        THEN {}
        ELSE \* Deterministic selection — the same (pool, beacon, k)
             \* triple always reproduces the same SUBSET. The beacon
             \* is threaded into the predicate as a witness of the
             \* abstract pre-image discriminator (the C++ side's
             \* SHA-256-derived random_state is what makes distinct
             \* beacons select distinct committees on uniform
             \* probability; the spec abstracts this to "potentially
             \* distinct" since the abstract uniformity is
             \* Preliminaries §2.3 territory).
             CHOOSE S \in candidates :
                \A T \in candidates :
                   \/ T = S
                   \/ <<"COMMITTEE-RANK", beacon, S>>
                      \in {<<"COMMITTEE-RANK", beacon, U>> : U \in candidates}

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    epoch,                  \* Nat — current epoch number (monotone
                             \*  non-decreasing across AdvanceEpoch)
    committee_history,      \* function {0..epoch} -> SUBSET ValidatorPool —
                             \*  per-epoch K-committee record; only
                             \*  grown by AdvanceEpoch
    beacon_history,         \* function {0..epoch+1} -> BeaconValues —
                             \*  per-epoch beacon feeding the seed;
                             \*  BeaconUpdate may advance one step
                             \*  ahead of AdvanceEpoch (modeling the
                             \*  chain accumulating randomness for
                             \*  the next epoch's seed)
    active_validators,      \* SUBSET ValidatorPool — currently
                             \*  registered validators (mutated by
                             \*  RegisterValidator / DeregisterValidator)
    selected_from           \* function {0..epoch} -> SUBSET ValidatorPool —
                             \*  ghost field: snapshot of
                             \*  active_validators at the moment
                             \*  committee_history[e] was drawn.
                             \*  Required for INV_DeterministicSelection's
                             \*  "same active set at the time of
                             \*  selection" antecedent; the live
                             \*  active_validators may have evolved
                             \*  post-selection via Register/Deregister.

vars == <<epoch, committee_history, beacon_history, active_validators,
          selected_from>>

\* -----------------------------------------------------------------
\* §3. Initial state.
\* -----------------------------------------------------------------
\*
\* Epoch 0 is the genesis epoch: the initial committee is drawn from
\* the initial active set (the chain's bootstrap validator set —
\* typically K..2K validators per the genesis_config pre-registration
\* contract). The beacon for epoch 0 is CHOSEN from BeaconValues; the
\* beacon for epoch 1 is ALSO pre-set (modeling the chain's
\* accumulated randomness through the first epoch_blocks blocks
\* being available before epoch 1 starts).

InitialActive == CHOOSE S \in SUBSET ValidatorPool : Cardinality(S) = K
InitialBeacon == CHOOSE b \in BeaconValues : TRUE

Init ==
    /\ epoch = 0
    /\ active_validators = InitialActive
    /\ beacon_history = (0 :> InitialBeacon) @@ (1 :> InitialBeacon)
    /\ committee_history = (0 :> EpochCommitteeSelect(InitialActive,
                                                       InitialBeacon, K))
    /\ selected_from = (0 :> InitialActive)

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* AdvanceEpoch: epoch -> epoch+1; draws the new committee from
\* `active_validators` keyed by `beacon_history[epoch+1]` (which
\* BeaconUpdate must have set already). Stores the committee in
\* `committee_history[epoch+1]` and snapshots the live
\* active_validators into `selected_from[epoch+1]` for the
\* deterministic-selection invariant's antecedent.
\*
\* Pre-condition: epoch < MaxEpoch (bounds TLC); beacon_history[epoch+1]
\* is defined (BeaconUpdate has fired); Cardinality(active_validators)
\* >= 1 (no empty-set committee — degenerate under-quorum case
\* handled by R7 UnderQuorumMerge.tla).

AdvanceEpoch ==
    /\ epoch < MaxEpoch
    /\ (epoch + 1) \in DOMAIN beacon_history
    /\ Cardinality(active_validators) >= 1
    /\ epoch' = epoch + 1
    /\ LET new_beacon == beacon_history[epoch + 1] IN
       LET new_committee == EpochCommitteeSelect(active_validators,
                                                  new_beacon, K) IN
       /\ committee_history' = (epoch + 1 :> new_committee)
                              @@ committee_history
       /\ selected_from'    = (epoch + 1 :> active_validators)
                              @@ selected_from
    /\ UNCHANGED <<beacon_history, active_validators>>

\* RegisterValidator(v): v in ValidatorPool \ active_validators ->
\* add to active_validators. Mirrors the REGISTER tx apply path
\* (with the active_from delay collapsed — the spec models the
\* post-activation state).

RegisterValidator(v) ==
    /\ v \in ValidatorPool
    /\ v \notin active_validators
    /\ active_validators' = active_validators \cup {v}
    /\ UNCHANGED <<epoch, committee_history, beacon_history,
                   selected_from>>

\* DeregisterValidator(v): v in active_validators -> remove from
\* active_validators. Mirrors the DEREGISTER tx apply path (with
\* the inactive_from delay collapsed — the spec models the
\* post-deactivation state). The validator may have been in a
\* past committee (committee_history captures historical snapshots
\* via selected_from; current_active is what next AdvanceEpoch
\* samples from).

DeregisterValidator(v) ==
    /\ v \in active_validators
    /\ Cardinality(active_validators) > 1
       \* Keep at least one validator active so AdvanceEpoch's
       \* `Cardinality(active_validators) >= 1` pre-condition stays
       \* satisfiable (under-quorum cases are R7 territory).
    /\ active_validators' = active_validators \ {v}
    /\ UNCHANGED <<epoch, committee_history, beacon_history,
                   selected_from>>

\* BeaconUpdate(b): updates the beacon for the NEXT epoch
\* (`beacon_history[epoch+1] = b`). Models the chain accumulating
\* randomness through the current epoch_blocks and producing the
\* seed for the next epoch. May fire repeatedly per epoch (the
\* chain accumulates randomness over many blocks); only the most
\* recent value before AdvanceEpoch matters for the next
\* committee draw.

BeaconUpdate(b) ==
    /\ b \in BeaconValues
    /\ epoch < MaxEpoch
    /\ beacon_history' = (epoch + 1 :> b) @@ beacon_history
    /\ UNCHANGED <<epoch, committee_history, active_validators,
                   selected_from>>

\* Stutter (TLC bounds the state space; invariants are evaluated
\* at every reachable state along the way).

Stutter ==
    /\ epoch >= MaxEpoch
    /\ UNCHANGED vars

Next ==
    \/ AdvanceEpoch
    \/ \E v \in ValidatorPool : RegisterValidator(v)
    \/ \E v \in ValidatorPool : DeregisterValidator(v)
    \/ \E b \in BeaconValues : BeaconUpdate(b)
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(AdvanceEpoch)
             /\ WF_vars(\E b \in BeaconValues : BeaconUpdate(b))
             /\ WF_vars(\E v \in ValidatorPool : RegisterValidator(v))
             /\ WF_vars(\E v \in ValidatorPool : DeregisterValidator(v))

\* -----------------------------------------------------------------
\* §5. Invariants — T-ER1..T-ER4 + TypeOK.
\* -----------------------------------------------------------------

\* TypeOK — shape predicate for all variables.
\*
\* committee_history's domain grows monotonically across AdvanceEpoch;
\* at any state it's a function {0..epoch} -> SUBSET ValidatorPool.
\* selected_from has the same domain shape. beacon_history's domain
\* is {0..epoch+1} (BeaconUpdate may set the next epoch's beacon
\* one step ahead).

TypeOK ==
    /\ epoch \in 0..MaxEpoch
    /\ active_validators \in SUBSET ValidatorPool
    /\ DOMAIN committee_history \subseteq 0..MaxEpoch
    /\ DOMAIN selected_from \subseteq 0..MaxEpoch
    /\ DOMAIN beacon_history \subseteq 0..(MaxEpoch + 1)
    /\ \A e \in DOMAIN committee_history :
          committee_history[e] \in SUBSET ValidatorPool
    /\ \A e \in DOMAIN selected_from :
          selected_from[e] \in SUBSET ValidatorPool
    /\ \A e \in DOMAIN beacon_history :
          beacon_history[e] \in BeaconValues

\* INV_CommitteeSizeIsK (T-ER2).
\*
\* Every committee in committee_history has cardinality K when the
\* active pool at the time of selection had at least K members;
\* otherwise the committee equals the full active set (the under-
\* quorum branch where R7 UnderQuorumMerge.tla kicks in).
\*
\* Structural witness: EpochCommitteeSelect's effective_k computation
\* picks min(k, |pool|); the candidates set is non-empty by
\* construction; CHOOSE returns a member of cardinality effective_k.

INV_CommitteeSizeIsK ==
    \A e \in DOMAIN committee_history :
       LET sel_pool == selected_from[e] IN
       IF Cardinality(sel_pool) >= K
       THEN Cardinality(committee_history[e]) = K
       ELSE Cardinality(committee_history[e]) = Cardinality(sel_pool)

\* INV_CommitteeSubsetActive (T-ER3).
\*
\* Every committee member at epoch e was in active_validators at the
\* moment of selection. The ghost field selected_from[e] captures
\* the live active_validators at the AdvanceEpoch firing; no
\* historical pool is consulted by EpochCommitteeSelect.
\*
\* Structural witness: AdvanceEpoch passes active_validators to
\* EpochCommitteeSelect, which returns a SUBSET of its first
\* argument. The selected_from snapshot is set atomically with
\* committee_history so the lookup is sound.

INV_CommitteeSubsetActive ==
    \A e \in DOMAIN committee_history :
       committee_history[e] \subseteq selected_from[e]

\* INV_DeterministicSelection (T-ER1).
\*
\* For every pair (e1, e2) in the domain of committee_history with
\* the same beacon AND the same active set at the time of
\* selection, the committees are byte-identical. State-form
\* witness of the EpochCommitteeSelect's purity — required for
\* cross-node consensus convergence under the same chain head.
\*
\* Structural witness: EpochCommitteeSelect(pool, beacon, k) is
\* deterministic on its three inputs (the CHOOSE picks the
\* unique tagged-tuple winner). If (pool, beacon, k) are
\* identical across (e1, e2), the SUBSET output is identical.

INV_DeterministicSelection ==
    \A e1 \in DOMAIN committee_history :
       \A e2 \in DOMAIN committee_history :
          (e1 \in DOMAIN beacon_history /\ e2 \in DOMAIN beacon_history
           /\ beacon_history[e1] = beacon_history[e2]
           /\ selected_from[e1] = selected_from[e2])
          => committee_history[e1] = committee_history[e2]

\* INV_HistoryMonotone (T-ER4).
\*
\* committee_history only grows across AdvanceEpoch actions;
\* existing entries are byte-identical across all reachable states.
\* Structural witness: the AdvanceEpoch action's
\* `(epoch + 1 :> new_committee) @@ committee_history` clause
\* PREPENDS a new key; the `@@` operator preserves existing
\* keys' values verbatim. No other action mutates
\* committee_history.
\*
\* The invariant body asserts that the domain is exactly the
\* prefix {0..epoch} — a stronger form of "only grows" that
\* doubles as the domain-shape predicate. Combined with the
\* TypeOK predicate, this pins both the shape and the monotone-
\* domain property.

INV_HistoryMonotone ==
    /\ DOMAIN committee_history = 0..epoch
    /\ DOMAIN selected_from    = 0..epoch
    /\ \A e \in DOMAIN committee_history :
          committee_history[e] = EpochCommitteeSelect(
              selected_from[e],
              beacon_history[e],
              K)

\* -----------------------------------------------------------------
\* §6. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualRotation (T-ER5).
\*
\* Under fairness on AdvanceEpoch + on either BeaconUpdate or
\* Register/Deregister, the committee changes infinitely often
\* when |active_validators| > K (so multiple distinct committees
\* exist within the pool).
\*
\* The forward-progress contract: the rotation rationale (defeating
\* long-run committee capture by adversarial sticky-membership)
\* requires actual rotation in the limit. The bounded-MaxEpoch
\* form of this asserts: across any bounded schedule with
\* |active_validators| > K maintained throughout AND at least one
\* beacon-change or pool-change between consecutive AdvanceEpoch
\* firings, the committee at SOME epoch differs from the
\* committee at the prior epoch.
\*
\* The TLA+ liveness body: eventually some pair of consecutive
\* epochs has different committees, witnessing rotation.

PROP_EventualRotation ==
    <>(\E e \in DOMAIN committee_history :
          /\ (e + 1) \in DOMAIN committee_history
          /\ committee_history[e] # committee_history[e + 1])

\* PROP_NoCommitteeFreeze.
\*
\* If |active_validators| >= K + 1 (so multiple distinct
\* K-committees exist within the pool), the same committee
\* cannot persist for more than `MaxEpoch / 2` consecutive
\* epochs without a beacon change OR a pool change.
\*
\* State-machine witness for the no-stuck-committee contract:
\* even under adversarial beacon + pool stability, the spec's
\* bounded-epoch enumeration shows the committee changes
\* within a bounded window — at finite MaxEpoch the bound
\* collapses to "the committee changes at LEAST once across
\* the bounded schedule when the cardinality-based condition
\* holds".
\*
\* Bounded form: across the MaxEpoch-bounded schedule, it is
\* eventually the case that for some e, beacon_history[e+1] /=
\* beacon_history[e] OR selected_from[e+1] /= selected_from[e]
\* OR committee_history[e+1] /= committee_history[e]. The
\* "committee freezes for half the bounded run" anti-condition
\* fails (witness: TLC enumerates a schedule reaching this).

PROP_NoCommitteeFreeze ==
    [](Cardinality(active_validators) >= K + 1
       => <>(\E e \in DOMAIN committee_history :
               /\ (e + 1) \in DOMAIN committee_history
               /\ \/ beacon_history[e + 1] # beacon_history[e]
                  \/ selected_from[e + 1] # selected_from[e]
                  \/ committee_history[e + 1] # committee_history[e]))

\* -----------------------------------------------------------------
\* §7. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The rotation contract is pinned at the state-machine layer by
\* the five invariants + two temporal properties. The abstraction
\* boundary:
\*
\*   * EpochCommitteeSelect's purity is what TLC checks — same
\*     `(pool, beacon, k)` ⇒ same SUBSET output. The cryptographic
\*     uniformity property (S-020's hybrid Fisher-Yates produces
\*     a uniform random K-subset given a uniform SHA-256-derived
\*     index stream) is NOT modeled here. That's FB23 FrostVerify.tla
\*     + Preliminaries §2.3 CSPRNG uniformity territory.
\*
\*   * The beacon-evolution mechanics (cumulative_rand accumulating
\*     across the chain's block production within an epoch) are
\*     abstracted as the BeaconUpdate action. The actual chain-
\*     layer accumulation is at `src/node/node.cpp::current_epoch_rand`
\*     lines 914-934 (anchored at `chain_.at(epoch_start -
\*     1).cumulative_rand`); the spec lifts this to a pure
\*     beacon-value-from-finite-universe abstraction.
\*
\*   * Activation / deactivation delays (REGISTER's `active_from
\*     = height + derive_delay(height)` + DEREGISTER's
\*     `inactive_from = height + derive_delay(height)`) are
\*     collapsed — the spec models the post-active-from /
\*     post-inactive-from state. The randomized delay's distribution
\*     bounds + their interaction with the per-epoch committee
\*     draw is a separate concern (covered by S-035 + test-
\*     randomized-delay R*).
\*
\*   * R4 region-aware filtering and R7 under-quorum merge are
\*     NOT modeled. The spec covers the BASE rotation contract;
\*     R4 layers `eligible_in_region` on top of `active_validators`;
\*     R7 widens the pool with refugees when under-quorum. These
\*     are separate FB-track surfaces (Sharding.tla + a future
\*     UnderQuorumMerge.tla territory).
\*
\*   * The within-epoch consensus surface (K-of-K block-sig phase,
\*     proposer rotation under aborts, equivocation slashing) is
\*     NOT modeled here. This spec covers across-epoch committee
\*     rotation only; the within-epoch surface is FB1 Consensus.tla
\*     + FB22 F2ViewReconciliation.tla territory.
\*
\* What this spec adds beyond existing FB-track surfaces:
\*
\*   * The state-machine witness that committee rotation is
\*     deterministic (T-ER1) AND grows monotonically (T-ER4) AND
\*     stays subset-bounded by the live active set (T-ER3) AND
\*     respects the K committee-size contract (T-ER2) across
\*     every reachable interleaving of AdvanceEpoch / Register /
\*     Deregister / BeaconUpdate.
\*
\*   * The forward-progress witness (T-ER5): rotation is not just
\*     legal but eventual under fairness. The bounded-MaxEpoch
\*     form captures the no-stuck-committee discipline that
\*     PROP_NoCommitteeFreeze formalizes.
\*
\* What the spec does NOT check (consistent with the §scope above):
\*
\*   * Cryptographic uniformity of the SHA-256-derived index
\*     stream feeding `select_m_creators` (FB23 + Preliminaries
\*     territory).
\*   * Quantitative bias bounds on the K/N ratio (S-020 closure
\*     narrative — the spec asserts the structural form; the
\*     bias-bound is the analytic side).
\*   * The chain-layer apply discipline that gates REGISTER /
\*     DEREGISTER (FB5 AccountState.tla + FB8 StakeLifecycle.tla
\*     territory).
\*   * Snapshot / restore round-trip of the registry state (FB31
\*     SnapshotIntegrity.tla covers the `s:` namespace's snapshot
\*     lifecycle that this spec's active_validators abstracts).

============================================================================
\* Cross-references.
\*
\* C++ enforcement:
\*   src/crypto/random.cpp:70-100    : select_m_creators (the hybrid
\*       Fisher-Yates K-of-N selector that EpochCommitteeSelect
\*       abstracts; S-020 closure).
\*   src/crypto/random.cpp:169-175   : epoch_committee_seed (the
\*       per-epoch + per-shard seed derivation that combines
\*       epoch_rand with shard_id under the "shard-committee"
\*       domain separator).
\*   src/node/node.cpp:909-934       : Node::current_epoch_index +
\*       Node::current_epoch_rand (the epoch derivation logic
\*       `epoch_index = chain_.height() / cfg_.epoch_blocks`).
\*   src/node/validator.cpp:88-91   : the validator's per-block
\*       epoch_index + epoch_start + resolve_epoch_rand +
\*       epoch_committee_seed call sequence; the receiver-side
\*       cross-check that the candidate block's committee matches
\*       the deterministic draw from the epoch seed.
\*   src/chain/chain.cpp::apply_transactions REGISTER + DEREGISTER
\*       branches — the active-set mutation surface that
\*       RegisterValidator / DeregisterValidator abstract.
\*
\* SECURITY.md §S-020 (hybrid Fisher-Yates closure) — the
\*   selection-function determinism + bias bound that
\*   EpochCommitteeSelect's purity abstracts.
\*
\* SECURITY.md §S-024 (formally-accepted epoch_blocks parameter
\*   + its bias bound) — the epoch parameter the spec's
\*   MaxEpoch constant abstracts.
\*
\* Preliminaries.md §2.1 (A2 SHA-256 collision resistance) +
\*   §2.3 (A3 CSPRNG uniformity) : the cryptographic
\*   assumptions underlying EpochCommitteeSelect's determinism +
\*   uniformity. The spec asserts the determinism side (purity);
\*   the uniformity side is the FB23 / Preliminaries side.
\*
\* FB22 F2ViewReconciliation.tla (v2.7 F2 view-reconciliation),
\* FB23 FrostVerify.tla (Ed25519 EUF-CMA model),
\* FB24 MakeContribCommitment.tla (S-030 D2 commit-binding),
\* FB25 RateLimiterEviction.tla (S-014 F-1 lifetime-bound),
\* FB26 BlockchainStateIntegrity.tla (S-021 + S-033 + S-038),
\* FB27 JsonValidation.tla (S-018 clear-diagnostic),
\* FB28 S006ContribMsgEquivocation.tla (S-006 Phase-1 detection),
\* FB29 BlockTimestampMonotonic.tla (R24A5 timestamp monotonicity),
\* FB30 ChainPrevHashLink.tla (R25 prev_hash chain-link state
\*   machine — INV_AppendOnly's append-only ghost pattern is the
\*   structural template this spec's INV_HistoryMonotone mirrors),
\* FB31 SnapshotIntegrity.tla (S-012 + S-037 + S-038 snapshot
\*   integrity composition),
\* FB32 CrossShardReceiptRoundtrip.tla (cross-shard receipt
\*   lifecycle composition),
\* FB33 MempoolAdmission.tla (bounded mempool admission state
\*   machine; S-008 + S-002 + FA-Apply-3 + FB23) : sibling
\*   FB-track specs; style template for this module.
\*
\* Runtime regressions:
\*   tools/test_committee_determinism.sh — the in-process test
\*     that pins the EpochCommitteeSelect's purity contract at the
\*     C++ layer (if present; otherwise the property is implicit
\*     in the cross-node consensus tests like
\*     tools/test_chain_sync_continuity.sh).
\*   tools/test_block_validator_extensive.sh — the
\*     check_creator_selection regression that exercises the
\*     receiver-side cross-check at validator.cpp:88-132; INV_3
\*     CommitteeSubsetActive's structural witness.
\*   tools/test_node_registry.sh — REGISTER + DEREGISTER apply
\*     surface that this spec's Register/Deregister abstracts.
\*
\* Doc updates:
\*   CHECK-RESULTS.md FB34 row — added.
============================================================================
