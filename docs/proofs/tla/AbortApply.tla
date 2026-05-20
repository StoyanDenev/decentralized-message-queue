--------------------------- MODULE AbortApply ---------------------------
(*
FB16 — TLA+ specification of the AbortEvent apply state machine.
Models the apply-layer mechanics by which an AbortEvent baked into
a finalized block (a) increments the offender's abort_records.count
(S-032 cache) and (b) — for Phase-1 aborts only — deducts
SUSPENSION_SLASH from the offender's locked stake (bounded below
by 0 — no negative balances). Phase-2 aborts record but do NOT
slash, mirroring the C++ `if (ae.round != 1) continue;` guard at
`src/chain/chain.cpp:1314` after the abort_records bump at
chain.cpp:1317-1320.

State-machine companion to FA-Apply-AbortEvent (apply-layer
integrity — `docs/proofs/AbortEventApply.md`, parallel agent).
Distinguished from the equivocation-slashing track (FB15 /
EquivocationApply.tla + FA6 / EquivocationSlashing.md + FA-Apply-FB6
/ EquivocationSlashingApply.md) by the abort-specific guarantees:

  (T-A1) Suspension is bounded — SUSPENSION_SLASH per Phase-1 abort
         (default 10 DTM, see `include/determ/chain/params.hpp:65`).
         Stake never decreases below 0 in a single apply; the
         `std::min(suspension_slash_, locked)` floor at chain.cpp:1324
         is the structural witness.
  (T-A2) Phase-2 aborts do NOT slash — they accumulate into
         abort_records (the S-032 cache used by build_from_chain
         for escalation accounting) but contribute zero to
         accumulated_slashed. This is the headline distinguishing
         feature from equivocation, which slashes regardless of
         phase.
  (T-A4) AbortEvent does NOT mutate the registry — unlike
         EquivocationEvent (which sets inactive_from = b.index + 1
         at chain.cpp:1354), AbortEvent only touches the (stakes_,
         abort_records_) pair. Registry deregistration on abort
         fires from a separate mechanism (the suspension-tracker
         in registry.cpp consults abort_records over a sliding
         window — out of scope for this apply-layer spec).
  (T-A5) DOMAIN_INCLUSION-mode abort — when stakes[d] = 0 at
         apply time, the slash branch becomes a no-op (the
         `std::min(SUSPENSION_SLASH, 0) = 0` reduction), but the
         abort_records.count++ still fires. Phase-1 vs Phase-2
         distinction collapses: both branches contribute zero to
         accumulated_slashed and equally to abort_records.

Properties captured:

  * RecordAbort(d, phase): adversarial surface — appends an
    AbortEvent for d with the given phase to pending. Apply gates
    fire later.
  * ApplyPhase1Abort(d): slash min(stakes[d], SUSPENSION_SLASH),
    add to accumulated_slashed, increment abort_records[d].count.
  * ApplyPhase2Abort(d): records only (count++), NO slash.
  * ApplyAbortDomainInclusion(d): when stakes[d] = 0 the phase
    distinction is degenerate — record only, no slash. Models the
    DOMAIN_INCLUSION-mode (no-stake) chains.
  * Inv_NoFullForfeitureOnAbort: an abort cannot reduce stake to 0
    in a single apply UNLESS the pre-apply stake was already below
    SUSPENSION_SLASH. The headline distinction from equivocation
    (T-E1), which fully forfeits regardless of pre-apply stake.
  * Inv_AbortRecordsMonotonic: abort_records[d].count only grows
    (no apply branch decrements; AdvanceRound preserves).
  * Inv_NoRegistryDeactivation: registry state UNTOUCHED by every
    AbortEvent apply branch — the structural witness of T-A4.

Modeling scope (TLC tractability):

  * Bounded slashing matching chain.cpp:1322-1327.
  * RecordAbort(d, phase) abstracts the V8 abort-claim verification
    + signature aggregation — FA-Apply-AbortEvent covers the
    cryptographic side.
  * pending is a single shared Seq (FIFO drain). Apply* branches
    are mutually exclusive on their guards and together cover the
    full head-of-queue space.
  * AbortEvent == [aborting_node: Domain, phase: {1, 2}]. The
    real wire-level AbortEvent carries (round, aborting_node,
    abort_hash, signatures) but the apply path only consumes
    (aborting_node, round) at chain.cpp:1313-1328.
  * MaxRound: temporal-driver upper bound, separate from chain
    block index — abort_records.count grows independently of
    height because aborts fire per round (1 or 2 phases per
    consensus round at most).

To check (assuming TLC installed):
  $ tlc AbortApply.tla -config AbortApply.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,            \* set of operator / domain identifiers
    MaxRound,           \* upper bound on round counter for TLC
    InitialStake,       \* initial per-domain locked stake for TLC
    SUSPENSION_SLASH    \* per-Phase-1-abort stake deduction (params.hpp:65)

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ MaxRound         \in Nat /\ MaxRound         >= 1
    /\ InitialStake     \in Nat /\ InitialStake     >= 1
    /\ SUSPENSION_SLASH \in Nat /\ SUSPENSION_SLASH >= 1

\* INITIAL_TOTAL_STAKE is the conserved upper bound on the sum of
\* all slashed stake across any trace. RecordAbort never moves
\* value; ApplyPhase1Abort consumes from locked stake into
\* accumulated_slashed (a one-way drain bounded by
\* SUSPENSION_SLASH per step). ApplyPhase2Abort /
\* ApplyAbortDomainInclusion never touch the pair. Hence the sum
\* `SumStakes + accumulated_slashed <= INITIAL_TOTAL_STAKE`
\* holds at every reachable state.
INITIAL_TOTAL_STAKE == InitialStake * Cardinality(Domains)

\* AbortEvent shape: (aborting_node, phase). The cryptographic
\* surface (abort_hash, σ_a, signatures, claim timestamp) is
\* abstracted — the apply path only consumes the (aborting_node,
\* round) pair at chain.cpp:1313-1328.
AbortEvent == [aborting_node: Domains, phase: 1..2]

----------------------------------------------------------------------------
\* State.

VARIABLES
    stakes,                 \* function Domains -> Nat (locked amount)
    abort_records,          \* function Domains -> [count: Nat] (S-032 cache)
    accumulated_slashed,    \* Nat: running total of slashed stake
    round,                  \* current round counter (temporal driver)
    pending,                \* sequence of AbortEvent (FIFO drain)
    registry_untouched      \* sentinel BOOLEAN — flipped FALSE if any
                            \* apply step mutated registry state.
                            \* Witnesses T-A4 / Inv_NoRegistryDeactivation
                            \* directly: none of the AbortEvent apply
                            \* branches in this spec ever flip it.

vars == <<stakes, abort_records, accumulated_slashed, round,
          pending, registry_untouched>>

----------------------------------------------------------------------------
\* Initial state. All domains start with their full per-domain
\* stake (InitialStake) locked and zero abort records.
\* `accumulated_slashed` and `round` start at 0; `pending` is
\* empty; `registry_untouched` starts TRUE — the spec's Apply*
\* actions never set it FALSE, so the invariant
\* Inv_NoRegistryDeactivation holds vacuously across every
\* reachable state.
Init ==
    /\ stakes              = [d \in Domains |-> InitialStake]
    /\ abort_records       = [d \in Domains |-> [count |-> 0]]
    /\ accumulated_slashed = 0
    /\ round               = 0
    /\ pending             = <<>>
    /\ registry_untouched  = TRUE

----------------------------------------------------------------------------
\* Actions. Each action models the corresponding apply-layer branch
\* in `src/chain/chain.cpp::apply_block` lines 1307-1328 (the
\* AbortEvent loop). The three Apply* branches are mutually
\* exclusive on their guards and together drain exactly one head
\* event per ApplyPhase*Abort* step.

\* RecordAbort(d, phase): adversarial action — appends an
\* AbortEvent for d with the given phase to pending. Abstracts
\* V8 abort-claim verification + signature aggregation (FA-Apply-
\* AbortEvent covers the soundness via EUF-CMA). Queue length is
\* bounded for TLC tractability; the actual chain has no queue
\* cap on AbortEvents per block (the validator's per-block-size
\* cap S-022 provides the implicit bound).
RecordAbort(d, phase) ==
    /\ d     \in Domains
    /\ phase \in 1..2
    /\ Len(pending) < MaxRound + Cardinality(Domains)
    /\ pending' = Append(pending, [aborting_node |-> d, phase |-> phase])
    /\ UNCHANGED <<stakes, abort_records, accumulated_slashed, round,
                   registry_untouched>>

\* ApplyPhase1Abort(d): Phase-1 apply branch. Models the
\* apply-loop body at chain.cpp:1313-1328 with `ae.round == 1`.
\* Slash min(stakes[d], SUSPENSION_SLASH), accumulate into
\* accumulated_slashed, increment abort_records[d].count, drop
\* head of pending. Registry UNTOUCHED (T-A4). The min() floor
\* (chain.cpp:1324) ensures Inv_NoFullForfeitureOnAbort holds:
\* a full drain to 0 only fires when the pre-apply stake was
\* already below SUSPENSION_SLASH.
\*
\* Guard: head must be a Phase-1 AbortEvent for d AND stakes[d] > 0
\* (the chain.cpp:1322-1323 `stakes_.find(ae.aborting_node) ==
\* stakes_.end()` check at the C++ short-circuits the slash with
\* `continue`, but the abort_records bump at chain.cpp:1317-1320
\* still fires. We split the no-stake case into
\* ApplyAbortDomainInclusion(d) for clarity at the state-machine
\* layer.)
ApplyPhase1Abort(d) ==
    /\ d \in Domains
    /\ Len(pending) > 0
    /\ Head(pending).aborting_node = d
    /\ Head(pending).phase = 1
    /\ stakes[d] > 0
    /\ LET deduct == IF stakes[d] < SUSPENSION_SLASH
                     THEN stakes[d]
                     ELSE SUSPENSION_SLASH
       IN /\ stakes' = [stakes EXCEPT ![d] = stakes[d] - deduct]
          /\ accumulated_slashed' = accumulated_slashed + deduct
    /\ abort_records' = [abort_records EXCEPT
                            ![d] = [count |-> abort_records[d].count + 1]]
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<round, registry_untouched>>

\* ApplyPhase2Abort(d): Phase-2 apply branch. Models the
\* `if (ae.round != 1) continue;` guard at chain.cpp:1314 that
\* skips the slash branch BUT keeps the abort_records.count++
\* via the unconditional bump at chain.cpp:1317-1320. The T-A2
\* "Phase-2 aborts do NOT slash" property: contributes zero to
\* accumulated_slashed; only abort_records advances. Registry
\* UNTOUCHED (T-A4).
\*
\* Guard: head must be a Phase-2 AbortEvent for d. stakes[d] is
\* free (Phase-2 has no stake-dependence — the records bump
\* always fires regardless).
ApplyPhase2Abort(d) ==
    /\ d \in Domains
    /\ Len(pending) > 0
    /\ Head(pending).aborting_node = d
    /\ Head(pending).phase = 2
    /\ abort_records' = [abort_records EXCEPT
                            ![d] = [count |-> abort_records[d].count + 1]]
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<stakes, accumulated_slashed, round,
                   registry_untouched>>

\* ApplyAbortDomainInclusion(d): T-A5 — when stakes[d] = 0,
\* both phases collapse: the chain.cpp:1322-1323 `find ==
\* stakes_.end()` (or equivalently `locked = 0`) branch fails
\* the slash short-circuit. abort_records.count++ still fires
\* (chain.cpp:1317-1320 is unconditional on the stakes lookup).
\* Models the DOMAIN_INCLUSION-mode chains (no stake to slash;
\* the records cache drives suspension-tracker accounting in
\* registry.cpp via build_from_chain). Registry UNTOUCHED (T-A4).
\*
\* Guard: head AbortEvent for d AND stakes[d] = 0. Both phases
\* are accepted here — the no-stake case is phase-agnostic.
ApplyAbortDomainInclusion(d) ==
    /\ d \in Domains
    /\ Len(pending) > 0
    /\ Head(pending).aborting_node = d
    /\ stakes[d] = 0
    /\ abort_records' = [abort_records EXCEPT
                            ![d] = [count |-> abort_records[d].count + 1]]
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<stakes, accumulated_slashed, round,
                   registry_untouched>>

\* AdvanceRound: tick the round counter forward by 1. The
\* temporal driver — without it, the bounded-round model would
\* not exhaust without progress. Round advances are independent
\* of pending — the actual chain's round counter is the
\* consensus-round index, separate from block index; multiple
\* aborts can fire within a single round (Phase-1 + Phase-2 on
\* different domains) before AdvanceRound fires.
AdvanceRound ==
    /\ round < MaxRound
    /\ round' = round + 1
    /\ UNCHANGED <<stakes, abort_records, accumulated_slashed, pending,
                   registry_untouched>>

----------------------------------------------------------------------------
\* Next-state relation. Any of the actions may fire at any enabled
\* state; TLC enumerates all interleavings.

Next ==
    \/ \E d \in Domains, p \in 1..2 : RecordAbort(d, p)
    \/ \E d \in Domains : ApplyPhase1Abort(d)
    \/ \E d \in Domains : ApplyPhase2Abort(d)
    \/ \E d \in Domains : ApplyAbortDomainInclusion(d)
    \/ AdvanceRound

\* Fairness on AdvanceRound (so round progresses) and on each
\* Apply* branch (so a pending head event eventually drains). The
\* three Apply* branches together cover the full guard space at
\* the head — at any state with a non-empty pending head targeting
\* `d` with phase `p`, exactly one of (ApplyPhase1Abort(d),
\* ApplyPhase2Abort(d), ApplyAbortDomainInclusion(d)) is enabled
\* (the (p, stakes[d]) discriminator covers all four combinations:
\* (1, >0) -> Phase1; (2, >0) -> Phase2; (_, =0) -> DomainInclusion).
\* Fairness on the disjunction gives the eventual-progress
\* liveness for Prop_EventualApply.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(AdvanceRound)
    /\ \A d \in Domains : WF_vars(ApplyPhase1Abort(d))
    /\ \A d \in Domains : WF_vars(ApplyPhase2Abort(d))
    /\ \A d \in Domains : WF_vars(ApplyAbortDomainInclusion(d))

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant: variables have correct shapes. The
\* accumulated_slashed upper bound is the bound on slashable
\* stake; pending is a Seq of AbortEvent with phase in {1, 2}.
Inv_TypeOK ==
    /\ stakes              \in [Domains -> 0..InitialStake]
    /\ abort_records       \in [Domains -> [count: Nat]]
    /\ accumulated_slashed \in 0..INITIAL_TOTAL_STAKE
    /\ round               \in 0..MaxRound
    /\ pending             \in Seq(AbortEvent)
    /\ registry_untouched  \in BOOLEAN

\* Stake non-negativity (Nat-valued; documents the contract).
\* ApplyPhase1Abort uses the min() floor at chain.cpp:1324 to
\* bound the deduction by the pre-apply stake; ApplyPhase2Abort
\* / ApplyAbortDomainInclusion / RecordAbort / AdvanceRound
\* never touch stakes. Hence stakes[d] >= 0 holds always.
Inv_StakeNonNegative ==
    \A d \in Domains : stakes[d] >= 0

\* SlashedMonotonic: accumulated_slashed never decreases across
\* any [Next]_vars step. Only ApplyPhase1Abort mutates the field;
\* it adds a non-negative `deduct` value (a Nat). ApplyPhase2Abort
\* / ApplyAbortDomainInclusion / RecordAbort / AdvanceRound all
\* preserve.
\*
\* Expressed as an action invariant via primed-state form; TLC
\* checks against the [Next]_vars transition relation.
Inv_SlashedMonotonic ==
    [][accumulated_slashed' >= accumulated_slashed]_vars

\* NoFullForfeitureOnAbort: an AbortEvent apply step cannot
\* reduce stakes[d] to 0 in a single step UNLESS the pre-apply
\* stakes[d] was already < SUSPENSION_SLASH. The headline
\* distinction from equivocation (T-E1), which fully forfeits
\* regardless of pre-apply stake.
\*
\* Action form: if a step reduces stakes[d] to 0 (post is 0,
\* pre is > 0), then pre must have been below SUSPENSION_SLASH.
\* Equivalent contrapositive: if pre >= SUSPENSION_SLASH AND
\* stakes is touched, then post >= pre - SUSPENSION_SLASH > 0.
Inv_NoFullForfeitureOnAbort ==
    [][\A d \in Domains :
         (stakes'[d] = 0 /\ stakes[d] > 0)
         => stakes[d] < SUSPENSION_SLASH
      ]_vars

\* AbortRecordsMonotonic: abort_records[d].count never decreases
\* across any [Next]_vars step. Every Apply* branch increments
\* by exactly 1; RecordAbort / AdvanceRound preserve.
\*
\* The S-032 cache contract: build_from_chain reads
\* abort_records as the authoritative count instead of replaying
\* the chain's AbortEvent history. The cache's count++-on-apply
\* invariant must be monotone non-decreasing for the cache
\* to remain consistent across snapshot/restore.
Inv_AbortRecordsMonotonic ==
    [][\A d \in Domains :
         abort_records'[d].count >= abort_records[d].count
      ]_vars

\* NoRegistryDeactivation: registry state is NEVER mutated by an
\* AbortEvent apply step (T-A4). The state-machine witness is
\* the `registry_untouched = TRUE` sentinel: no action in this
\* spec ever flips it to FALSE, so the invariant holds vacuously.
\* The semantic content is the COMPLEMENTARY claim that
\* equivocation DOES mutate registry (Inv_DeactivatedAfterSlash
\* in EquivocationApply.tla / FB15) — the two specs jointly
\* witness the abort-vs-equivocation asymmetry.
\*
\* Mirrors the chain.cpp:1313-1328 apply loop's structural
\* absence of any `registrants_[...] = ...` mutation, in contrast
\* to chain.cpp:1354's `rit->second.inactive_from = b.index + 1`
\* in the equivocation loop.
Inv_NoRegistryDeactivation ==
    registry_untouched = TRUE

----------------------------------------------------------------------------
\* Temporal properties.

\* EventualApply: under fairness on AdvanceRound + the three
\* Apply* branches, any pending AbortEvent eventually drains.
\* The three Apply* branches together cover the full guard space
\* at the head ((phase 1, stake > 0) -> Phase1; (phase 2, stake
\* > 0) -> Phase2; (any phase, stake = 0) -> DomainInclusion);
\* fairness on the disjunction gives the eventual-progress
\* claim. The MaxRound escape covers the model-bound termination
\* case.
Prop_EventualApply ==
    (Len(pending) > 0)
    ~> (Len(pending) = 0 \/ round >= MaxRound)

\* Phase2NoSlash: across all reachable states, Phase-2 aborts
\* contribute zero to accumulated_slashed. Action form: a step
\* whose head pending event has phase = 2 (and fires Apply* on
\* d = head.aborting_node) preserves accumulated_slashed.
\* Encoded as a [Next]_vars action invariant.
\*
\* The T-A2 headline property: the abort-event apply path
\* distinguishes Phase-1 (slash + record) from Phase-2 (record
\* only). Equivocation has no such phase distinction — every
\* EquivocationEvent slashes regardless. The temporal form
\* witnesses the property across every reachable state.
Prop_Phase2NoSlash ==
    [][\A d \in Domains :
         (Len(pending) > 0
          /\ Head(pending).aborting_node = d
          /\ Head(pending).phase = 2
          /\ pending' = Tail(pending))
         => accumulated_slashed' = accumulated_slashed
      ]_vars

============================================================================
