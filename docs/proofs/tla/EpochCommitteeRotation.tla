--------------------------- MODULE EpochCommitteeRotation ---------------------------
(*
FB34 — cross-epoch committee rotation state machine.
REDESIGNED 2026-07-02 (was quarantined: the original abstract
EpochCommitteeSelect used a CHOOSE whose second disjunct was a
tautology, so the selector was beacon-blind — the committee could
never rotate at a fixed pool and no rotation liveness could hold.
Production IS beacon-sensitive, so the spec, not the code, was
wrong. This redesign replaces the selector with a beacon-indexed
ranked selection and restates the liveness contract honestly.)

Scope. Determ redraws the K-member block-signing committee every
epoch: `crypto::select_m_creators(seed, N, K)` derives member
indices from SHA-256 chains over the per-epoch seed
`crypto::epoch_committee_seed(epoch_rand, shard_id)`
(src/crypto/random.cpp:70-100 and :169-175), and every validator
replays the same draw to cross-check a candidate block's creators
(src/node/validator.cpp:89-132). epoch_rand is the chain's
cumulative_rand anchored at the epoch boundary
(src/node/node.cpp::current_epoch_rand), so the seed evolves as the
chain produces blocks. The active pool evolves via REGISTER /
DEREGISTER (src/chain/chain.cpp::apply_transactions).

The abstraction (spec-layer projection of select_m_creators):

  EpochCommitteeSelect(pool, beacon, k) ==
      the (beacon % n)-th k-subset of pool under a fixed total
      order on subsets, where n = #k-subsets of pool.

  * The fixed total order is the binary-encoding order
    (S < T iff max of the symmetric difference lies in T —
    equivalent to comparing Sum{2^v : v in S}). Any fixed order
    works; this one needs no recursion.
  * Beacons are modeled as naturals 1..MaxBeacon — the injective
    beacon->index map the abstraction needs. Production's beacon
    is a 256-bit hash; distinct hashes give independent draws.
    The model keeps MaxBeacon <= K+1 <= n so distinct beacons
    always give DISTINCT indices ("fresh seed => fresh draw").
    In production a fresh seed repeats a committee with
    probability 1/n per pair — below this abstraction's floor;
    the model's injective regime is the deterministic projection
    of that quasi-uniformity (S-020), not a claim of certainty
    about any single pair of real seeds.
  * Determinism: the operator is a pure function of (pool,
    beacon, k) — the CHOOSE has a unique satisfying subset
    (ranks are injective), so TLC's choice is forced.
  * Beacon-sensitivity is MACHINE-CHECKED at startup by the
    named ASSUME BeaconSensitivity below: every pool with more
    than one K-subset has two beacons selecting different
    committees. (The original spec's selector failed exactly
    this; the ASSUME makes a regression impossible to miss.)

State machine (four actions):

  * AdvanceEpoch — epoch+1; draws committee_history[epoch+1] =
    EpochCommitteeSelect(active_validators, beacon, K), snapshots
    beacon_history / selected_from. Guard `beacon #
    beacon_history[epoch]`: production's consecutive epoch seeds
    differ (cumulative_rand accumulates one SHA-256 fold per
    block across the ~epoch_blocks blocks between boundaries;
    equality would be a SHA-256 collision — excluded by
    Preliminaries A2). Guard `Cardinality(active_validators) > K`
    pins the modeled regime (below).
  * BeaconAdvance — beacon := (beacon % MaxBeacon) + 1. The
    chain-randomness accumulator, lifted to a cycling counter so
    TLC's state space stays finite. Beacon REUSE across
    non-adjacent epochs is a deliberate artifact: it makes
    INV_DeterministicSelection's antecedent reachable (two epochs
    with the same (pool, beacon) must repeat the committee).
  * RegisterValidator(v) / DeregisterValidator(v) — REGISTER /
    DEREGISTER with activation/deactivation delays collapsed
    (post-active_from / post-inactive_from state). No fairness:
    pool churn is adversarial.

Modeled regime — |active_validators| >= K+1 throughout (Init
starts at K+1; Deregister keeps >= K+1). Rationale:
  * |pool| = K: the K-subset is unique — committee = full pool,
    rotation structurally impossible, and the code claims none.
    Nothing to check beyond determinism, which the >= K+1 regime
    already pins.
  * |pool| < K: select_m_creators THROWS (random.cpp:71-72) and
    the validator fail-closes ("insufficient eligible nodes",
    validator.cpp:119-120). The pre-redesign spec's under-quorum
    branch (committee = full active set when |pool| < K)
    CONTRADICTED the code — the code never returns an undersized
    committee; R7 under-quorum merge widens the pool instead.
    That branch is DELETED, and T-ER2 is restated as the
    unconditional |committee| = K the code actually guarantees
    whenever it returns at all.

Contract pinned (T-ER1..T-ER5):

  (T-ER1) INV_DeterministicSelection — same (pool, beacon) at two
          epochs => identical committees. Cross-node convergence:
          every node replaying the same seed + registry gets the
          same committee (validator.cpp:126 recompute).
  (T-ER2) INV_CommitteeSizeIsK — every recorded committee has
          cardinality exactly K (restated; see regime note).
  (T-ER3) INV_CommitteeSubsetActive — committee members were in
          the active set snapshot at draw time (ghost field
          selected_from). No zombie / ghost committees.
  (T-ER4) INV_HistoryMonotone — committee/beacon/selected_from
          histories have domain exactly 0..epoch, and every
          recorded committee equals the selector replayed on its
          recorded inputs (the spec-level analog of the
          receiver-side cross-check at validator.cpp:126-132;
          also pins append-only immutability: an overwritten
          entry could no longer match its recorded inputs while
          all invariants held earlier).
  (T-ER5) PROP_EventualRotation — RESTATED. Honest form: in any
          fair behavior whose active pool NEVER changes, some
          pair of consecutive epochs has distinct committees
          ([](pool = InitialActive) => <>rotation). Fairness:
          SF(AdvanceEpoch) (epoch boundaries recur; SF because
          the cycling beacon transiently disables the freshness
          guard) + WF(BeaconAdvance) (the chain keeps producing
          blocks). Why conditional on a quiet pool: with
          adversarial REGISTER/DEREGISTER timing the committee
          can be held constant at this abstraction (alternate
          pools in which the same subset ranks at the alternating
          beacon indices) — and in production, rotation under
          adversarial churn is likewise only probabilistic
          (S-020 bias-bound territory), so an unconditional
          liveness claim would over-promise. The beacon-driven
          claim the code DOES make — a static pool cannot freeze
          the committee — is exactly the conditional form.

  PROP_NoCommitteeFreeze (pre-redesign) — DELETED. Rationale: its
  "same committee for more than MaxEpoch/2 epochs implies a
  beacon/pool change" bound was not a claim the code makes (the
  real no-freeze guarantee is probabilistic), and its TLC
  encoding was unfalsifiable at the old beacon-blind selector.
  Its honest content is split across ASSUME BeaconSensitivity
  (the selector cannot ignore the beacon) and the restated
  PROP_EventualRotation (a static pool cannot freeze the
  committee).

Not modeled (unchanged from the original scope): cryptographic
uniformity of the SHA-256 index stream (Preliminaries A3 / S-020
bias bound), per-block within-epoch replay and abort-mixed rand
(FB1 Consensus.tla), R4 region overlay + R7 under-quorum merge,
registration delay distribution (S-035), snapshot lifecycle of the
registry (FB31).

To check:
  $ bash tools/test_tla_model_check.sh --only EpochCommitteeRotation
  (or: tlc -deadlock -config EpochCommitteeRotation.cfg
       EpochCommitteeRotation.tla)

Cross-references:
  - src/crypto/random.cpp:70-100  select_m_creators (hybrid
    rejection-sampling / partial-Fisher-Yates selector; S-020).
  - src/crypto/random.cpp:169-175 epoch_committee_seed.
  - src/node/node.cpp:909-934     current_epoch_index /
    current_epoch_rand (beacon anchoring).
  - src/node/validator.cpp:89-132 receiver-side replay of the
    draw (the T-ER4 replay conjunct's ground truth).
  - src/chain/chain.cpp::apply_transactions REGISTER/DEREGISTER.
  - include/determ/chain/params.hpp (K per profile; cfg uses K=3).
  - docs/proofs/tla/Consensus.tla (FB1, within-epoch surface),
    F2ViewReconciliation.tla (FB22), ChainPrevHashLink.tla (FB30,
    append-only ghost-history pattern INV_HistoryMonotone mirrors).
  - docs/proofs/UnderQuorumMerge.md (R7) — owns |pool| < K.
  - SECURITY.md S-020 (selector determinism + bias bound),
    S-024 (epoch_blocks), Preliminaries A2/A3.
*)

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    ValidatorPool,   \* finite SUBSET of Nat — validator ids
    K,               \* committee size (block_sig_committee_size)
    MaxEpoch,        \* TLC bound on epoch count (production: unbounded)
    MaxBeacon        \* beacon universe 1..MaxBeacon (production: 2^256 hashes)

ASSUME ConfigOK ==
    /\ ValidatorPool \subseteq Nat
    /\ K \in Nat /\ K >= 1
    /\ Cardinality(ValidatorPool) >= K + 1   \* multi-candidate regime
    /\ MaxEpoch \in Nat /\ MaxEpoch >= 2     \* >= 2 draws so a rotation pair exists
    /\ MaxBeacon \in Nat /\ MaxBeacon >= 2   \* freshness guard needs an alternative
    /\ MaxBeacon <= K + 1
       \* Injective beacon->index regime: every reachable pool has
       \* n = C(|pool|, K) >= C(K+1, K) = K+1 >= MaxBeacon candidate
       \* committees, so distinct beacons always map to distinct
       \* candidate indices (b % n = b for b in 1..MaxBeacon-1, and
       \* the values stay pairwise distinct mod n). This is the
       \* deterministic projection of "fresh seed => fresh draw".

\* -----------------------------------------------------------------
\* §1. Selector — beacon-indexed ranked k-subset.
\* -----------------------------------------------------------------

MaxOf(S) == CHOOSE x \in S : \A y \in S : y <= x

\* Strict total order on distinct finite sets of naturals:
\* S < T  iff  max(S symdiff T) \in T  — equivalent to comparing the
\* binary encodings Sum{2^v : v \in S}. Fixed, input-independent.
SubsetLess(S, T) ==
    LET D == (S \ T) \cup (T \ S)
    IN  /\ D # {}
        /\ MaxOf(D) \in T

\* The (beacon % n)-th k-subset of pool under SubsetLess order.
\* Pure function of (pool, beacon, k): ranks are injective, so the
\* CHOOSE has a unique satisfier. Abstracts select_m_creators(
\* epoch_committee_seed(beacon, shard), |pool|, k) — determinism and
\* beacon-sensitivity are kept; uniformity (S-020) is not modeled.
EpochCommitteeSelect(pool, beacon, k) ==
    LET ek    == IF Cardinality(pool) <= k THEN Cardinality(pool) ELSE k
        cands == { S \in SUBSET pool : Cardinality(S) = ek }
        n     == Cardinality(cands)
        idx   == beacon % n
    IN  CHOOSE S \in cands :
            Cardinality({ T \in cands : SubsetLess(T, S) }) = idx

\* Machine-checked beacon-sensitivity (requirement the original
\* beacon-blind selector failed): every pool with more than one
\* K-subset has two beacons that select different committees.
ASSUME BeaconSensitivity ==
    \A P \in SUBSET ValidatorPool :
        Cardinality(P) > K =>
            \E b1, b2 \in 1..MaxBeacon :
                /\ b1 # b2
                /\ EpochCommitteeSelect(P, b1, K) # EpochCommitteeSelect(P, b2, K)

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    epoch,              \* Nat — current epoch (monotone via AdvanceEpoch)
    beacon,             \* 1..MaxBeacon — live chain-randomness accumulator
    committee_history,  \* {0..epoch} -> SUBSET ValidatorPool — per-epoch draw
    beacon_history,     \* {0..epoch} -> 1..MaxBeacon — beacon at each draw
    active_validators,  \* SUBSET ValidatorPool — live registry
    selected_from       \* {0..epoch} -> SUBSET ValidatorPool — ghost:
                        \*   active_validators snapshot at each draw

vars == <<epoch, beacon, committee_history, beacon_history,
          active_validators, selected_from>>

\* -----------------------------------------------------------------
\* §3. Initial state — genesis epoch 0.
\* -----------------------------------------------------------------

InitialActive == CHOOSE S \in SUBSET ValidatorPool : Cardinality(S) = K + 1
InitialBeacon == 1

Init ==
    /\ epoch = 0
    /\ beacon = InitialBeacon
    /\ active_validators = InitialActive
    /\ beacon_history    = (0 :> InitialBeacon)
    /\ committee_history = (0 :> EpochCommitteeSelect(InitialActive,
                                                      InitialBeacon, K))
    /\ selected_from     = (0 :> InitialActive)

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

AdvanceEpoch ==
    /\ epoch < MaxEpoch
    /\ beacon # beacon_history[epoch]
       \* fresh seed: consecutive epoch seeds differ (A2 — equality
       \* would be a cumulative_rand SHA-256 collision)
    /\ Cardinality(active_validators) > K
       \* modeled regime (see header); code fail-fasts below K
    /\ epoch' = epoch + 1
    /\ committee_history' = committee_history
           @@ ((epoch + 1) :> EpochCommitteeSelect(active_validators,
                                                   beacon, K))
    /\ beacon_history'    = beacon_history @@ ((epoch + 1) :> beacon)
    /\ selected_from'     = selected_from  @@ ((epoch + 1) :> active_validators)
    /\ UNCHANGED <<beacon, active_validators>>

BeaconAdvance ==
    /\ beacon' = (beacon % MaxBeacon) + 1
    /\ UNCHANGED <<epoch, committee_history, beacon_history,
                   active_validators, selected_from>>

RegisterValidator(v) ==
    /\ v \in ValidatorPool \ active_validators
    /\ active_validators' = active_validators \cup {v}
    /\ UNCHANGED <<epoch, beacon, committee_history, beacon_history,
                   selected_from>>

DeregisterValidator(v) ==
    /\ v \in active_validators
    /\ Cardinality(active_validators) >= K + 2   \* stay in the >= K+1 regime
    /\ active_validators' = active_validators \ {v}
    /\ UNCHANGED <<epoch, beacon, committee_history, beacon_history,
                   selected_from>>

Next ==
    \/ AdvanceEpoch
    \/ BeaconAdvance
    \/ \E v \in ValidatorPool : RegisterValidator(v)
    \/ \E v \in ValidatorPool : DeregisterValidator(v)

\* Fairness: SF on AdvanceEpoch (epoch boundaries recur; SF, not WF,
\* because the cycling beacon transiently re-disables the freshness
\* guard) + WF on BeaconAdvance (block production continues). Pool
\* churn is left unfair — adversarial.
Spec == Init /\ [][Next]_vars
             /\ SF_vars(AdvanceEpoch)
             /\ WF_vars(BeaconAdvance)

\* -----------------------------------------------------------------
\* §5. Invariants — T-ER1..T-ER4 + TypeOK.
\* -----------------------------------------------------------------

TypeOK ==
    /\ epoch \in 0..MaxEpoch
    /\ beacon \in 1..MaxBeacon
    /\ active_validators \subseteq ValidatorPool
    /\ Cardinality(active_validators) >= K + 1   \* regime floor
    /\ DOMAIN committee_history \subseteq 0..MaxEpoch
    /\ DOMAIN beacon_history    \subseteq 0..MaxEpoch
    /\ DOMAIN selected_from     \subseteq 0..MaxEpoch
    /\ \A e \in DOMAIN committee_history :
          committee_history[e] \subseteq ValidatorPool
    /\ \A e \in DOMAIN beacon_history : beacon_history[e] \in 1..MaxBeacon
    /\ \A e \in DOMAIN selected_from : selected_from[e] \subseteq ValidatorPool

\* T-ER2 — every recorded committee has cardinality exactly K.
\* (Under-quorum fallback branch deleted: the code throws below K
\* rather than returning an undersized committee — see header.)
INV_CommitteeSizeIsK ==
    \A e \in DOMAIN committee_history :
        Cardinality(committee_history[e]) = K

\* T-ER3 — committee members were active at draw time (ghost
\* snapshot selected_from; the live set may evolve afterwards).
INV_CommitteeSubsetActive ==
    \A e \in DOMAIN committee_history :
        committee_history[e] \subseteq selected_from[e]

\* T-ER1 — same (pool, beacon) at two epochs => same committee.
\* Reachably non-trivial: the cycling beacon can repeat a value at
\* a later epoch with the pool restored (e.g. epochs 0 and 2).
INV_DeterministicSelection ==
    \A e1, e2 \in DOMAIN committee_history :
        (/\ beacon_history[e1] = beacon_history[e2]
         /\ selected_from[e1]  = selected_from[e2])
        => committee_history[e1] = committee_history[e2]

\* T-ER4 — histories cover exactly 0..epoch and every entry replays:
\* committee_history[e] equals the selector applied to its recorded
\* inputs (validator.cpp:126-132's cross-check, spec-level). The
\* replay conjunct doubles as the immutability pin: a rewritten
\* entry could no longer match its recorded inputs.
INV_HistoryMonotone ==
    /\ DOMAIN committee_history = 0..epoch
    /\ DOMAIN beacon_history    = 0..epoch
    /\ DOMAIN selected_from     = 0..epoch
    /\ \A e \in 0..epoch :
          committee_history[e] = EpochCommitteeSelect(selected_from[e],
                                                      beacon_history[e], K)

\* -----------------------------------------------------------------
\* §6. Liveness — T-ER5 (restated; see header).
\* -----------------------------------------------------------------

RotationPair ==
    \E e \in DOMAIN committee_history :
        /\ (e + 1) \in DOMAIN committee_history
        /\ committee_history[e] # committee_history[e + 1]

\* A behavior whose pool never changes must rotate: fresh beacons at
\* a fixed pool select distinct candidate indices (injective regime,
\* ConfigOK). Behaviors with pool churn make no rotation promise at
\* this abstraction (probabilistic in production — header, T-ER5).
PROP_EventualRotation ==
    [](active_validators = InitialActive) => <>RotationPair

============================================================================
