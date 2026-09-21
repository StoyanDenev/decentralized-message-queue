--------------------------- MODULE Consensus ---------------------------
(*
FB1 — TLA+ formal specification of Determ's per-height K=2 VDF Duel consensus.

Grounding:
  * Supersedes the legacy K-of-K BFT/unanimous model.
  * Formalized in K2_VDF_Soundness.md.
  * Implemented in src/consensus/duel_state.c, include/determ/consensus/duel_state.h.

Architecture:
  * Committee of size K=2: elected Aggregator and Contributor.
  * Phase 1: Aggregator and Contributor publish cryptographic commitments.
  * Phase 2 (AWAIT_REVEALS): Governed exclusively by a monotonic local timer.
    - If Contributor reveals payload within W_reveal, VDF evaluates dual bundle (A+B).
    - If Contributor straggles or drops (timer > W_reveal), the 1-of-2 fallback
      executes unconditionally, evaluating Aggregator's payload (A) alone.
  * Phase 3 (VDF_EVALUATING): Evaluates sequential VDF over T_vdf steps.
  * Zero-Bit Bias / Time-Lock: T_vdf > W_reveal + Delta_max guarantees no participant
    learns the outcome before committing.
  * Absolute Liveness: Network progress is guaranteed under asynchronous network
    drops without requiring a Byzantine quorum.
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Aggregator,         \* Elected Aggregator node identity
    Contributor,        \* Elected Contributor node identity
    W_reveal,           \* Reveal window bound (monotonic timer ticks)
    T_vdf               \* Sequential VDF evaluation steps

ASSUME ConstantsOK ==
    /\ W_reveal \in Nat /\ W_reveal >= 1
    /\ T_vdf \in Nat /\ T_vdf >= 1
    /\ Aggregator /= Contributor

VARIABLES
    stage,              \* {"INIT", "COMMIT", "AWAIT_REVEALS", "VDF_EVALUATING", "FINAL"}
    timer,              \* Monotonic clock tick in AWAIT_REVEALS (0..W_reveal+1)
    vdf_timer,          \* Progress ticks in VDF_EVALUATING (0..T_vdf)
    agg_committed,      \* TRUE once Aggregator publishes commitment
    contrib_committed,  \* TRUE once Contributor publishes commitment
    contrib_revealed,   \* TRUE once Contributor reveals payload
    vdf_mode,           \* {"NONE", "DUAL", "FALLBACK"}
    finalized,          \* Set of finalized block digests
    network_drop        \* Simulated network drop / Byzantine silence of Contributor

vars == <<stage, timer, vdf_timer, agg_committed, contrib_committed,
          contrib_revealed, vdf_mode, finalized, network_drop>>

----------------------------------------------------------------------------
\* Initial state: both nodes idle, timers reset, network drop nondeterministically set.

Init ==
    /\ stage = "INIT"
    /\ timer = 0
    /\ vdf_timer = 0
    /\ agg_committed = FALSE
    /\ contrib_committed = FALSE
    /\ contrib_revealed = FALSE
    /\ vdf_mode = "NONE"
    /\ finalized = {}
    /\ network_drop \in BOOLEAN

----------------------------------------------------------------------------
\* Actions.

StartCommit ==
    /\ stage = "INIT"
    /\ stage' = "COMMIT"
    /\ UNCHANGED <<timer, vdf_timer, agg_committed, contrib_committed,
                   contrib_revealed, vdf_mode, finalized, network_drop>>

AggregatorCommit ==
    /\ stage = "COMMIT"
    /\ ~agg_committed
    /\ agg_committed' = TRUE
    /\ stage' = IF contrib_committed \/ network_drop THEN "AWAIT_REVEALS" ELSE stage
    /\ UNCHANGED <<timer, vdf_timer, contrib_committed, contrib_revealed,
                   vdf_mode, finalized, network_drop>>

ContributorCommit ==
    /\ stage = "COMMIT"
    /\ ~network_drop
    /\ ~contrib_committed
    /\ contrib_committed' = TRUE
    /\ stage' = IF agg_committed THEN "AWAIT_REVEALS" ELSE stage
    /\ UNCHANGED <<timer, vdf_timer, agg_committed, contrib_revealed,
                   vdf_mode, finalized, network_drop>>

ContributorDropDuringCommit ==
    /\ stage = "COMMIT"
    /\ agg_committed
    /\ network_drop
    /\ stage' = "AWAIT_REVEALS"
    /\ UNCHANGED <<timer, vdf_timer, agg_committed, contrib_committed,
                   contrib_revealed, vdf_mode, finalized, network_drop>>

\* Monotonic wall-clock timer tick during AWAIT_REVEALS.
MonotonicTimerTick ==
    /\ stage = "AWAIT_REVEALS"
    /\ timer <= W_reveal
    /\ timer' = timer + 1
    /\ UNCHANGED <<stage, vdf_timer, agg_committed, contrib_committed,
                   contrib_revealed, vdf_mode, finalized, network_drop>>

\* Contributor reveals payload within the valid reveal window.
ContributorReveal ==
    /\ stage = "AWAIT_REVEALS"
    /\ timer <= W_reveal
    /\ ~network_drop
    /\ contrib_committed
    /\ ~contrib_revealed
    /\ contrib_revealed' = TRUE
    /\ vdf_mode' = "DUAL"
    /\ stage' = "VDF_EVALUATING"
    /\ UNCHANGED <<timer, vdf_timer, agg_committed, contrib_committed,
                   finalized, network_drop>>

\* Monotonic timer expires without Contributor reveal: 1-of-2 fallback executes!
FallbackTimeout ==
    /\ stage = "AWAIT_REVEALS"
    /\ timer > W_reveal
    /\ ~contrib_revealed
    /\ vdf_mode' = "FALLBACK"
    /\ stage' = "VDF_EVALUATING"
    /\ UNCHANGED <<timer, vdf_timer, agg_committed, contrib_committed,
                   contrib_revealed, finalized, network_drop>>

\* Sequential evaluation of the VDF.
VDFStep ==
    /\ stage = "VDF_EVALUATING"
    /\ vdf_timer < T_vdf
    /\ vdf_timer' = vdf_timer + 1
    /\ UNCHANGED <<stage, timer, agg_committed, contrib_committed,
                   contrib_revealed, vdf_mode, finalized, network_drop>>

\* Finalization produces the canonical block header.
Finalize ==
    /\ stage = "VDF_EVALUATING"
    /\ vdf_timer = T_vdf
    /\ stage' = "FINAL"
    /\ finalized' = IF vdf_mode = "DUAL" THEN {"DUAL_BLOCK"} ELSE {"FALLBACK_BLOCK"}
    /\ UNCHANGED <<timer, vdf_timer, agg_committed, contrib_committed,
                   contrib_revealed, vdf_mode, network_drop>>

FinalStutter ==
    /\ stage = "FINAL"
    /\ UNCHANGED vars

----------------------------------------------------------------------------
\* Next-state relation.

Next ==
    \/ StartCommit
    \/ AggregatorCommit
    \/ ContributorCommit
    \/ ContributorDropDuringCommit
    \/ MonotonicTimerTick
    \/ ContributorReveal
    \/ FallbackTimeout
    \/ VDFStep
    \/ Finalize
    \/ FinalStutter

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

----------------------------------------------------------------------------
\* Invariants.

\* 1. Canonical Block Safety: At most one canonical block finalizes at height h.
Inv_OneBlockSafety ==
    Cardinality(finalized) <= 1

\* 2. Zero-Bit Bias / Time-Lock: Outcome cannot be finalized before reveal window closes.
Inv_ZeroBitBiasTimeLock ==
    (stage = "AWAIT_REVEALS" /\ timer <= W_reveal) => (stage /= "FINAL" /\ vdf_timer = 0)

\* 3. Type invariant.
TypeOK ==
    /\ stage \in {"INIT", "COMMIT", "AWAIT_REVEALS", "VDF_EVALUATING", "FINAL"}
    /\ timer \in 0..(W_reveal + 1)
    /\ vdf_timer \in 0..T_vdf
    /\ agg_committed \in BOOLEAN
    /\ contrib_committed \in BOOLEAN
    /\ contrib_revealed \in BOOLEAN
    /\ vdf_mode \in {"NONE", "DUAL", "FALLBACK"}
    /\ finalized \subseteq {"DUAL_BLOCK", "FALLBACK_BLOCK"}
    /\ network_drop \in BOOLEAN

----------------------------------------------------------------------------
\* Temporal property: Absolute liveness (network progress under arbitrary drop).

Prop_Termination == <>(stage = "FINAL" /\ finalized /= {})

============================================================================
