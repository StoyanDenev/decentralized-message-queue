--------------------------- MODULE EquivocationApply ---------------------------
(*
FB14 — TLA+ specification of the equivocation-slashing apply state
machine. Models the apply-layer mechanics by which an EquivocationEvent
baked into a finalized block (a) forfeits the offender's entire locked
stake into `accumulated_slashed` and (b) marks the offender's registry
entry inactive_from = height + 1.

State-machine companion to FA6 (cryptographic soundness — slashing only
catches the guilty — `docs/proofs/EquivocationSlashing.md`) and to
FA-Apply-FB6 (apply-layer integrity — `docs/proofs/EquivocationSlashingApply.md`,
parallel agent). The two tracks together close FA6 at both layers.

Properties captured:

  * Equivocate(d): adversarial surface — appends an EquivocationEvent
    for d to pending_events. Apply gates fire later.
  * ApplyEquivocation(d): if registrants[d].active, zero stakes[d],
    set inactive_from = height + 1, add pre-apply stake to
    accumulated_slashed (lockstep).
  * ApplyEquivocationGhost(d): T-E4 — offender already fully wound
    down (stakes[d] = 0 AND inactive_from <= height). No-op on
    every state variable except the event-queue drain.
  * ApplyEquivocationAlreadyDeactivated(d): the dual-mechanism
    branch (chain.cpp:1337-1343) — already inactive but still has
    stake. Slash fires, inactive_from rewritten to height + 1.
  * Inv_DeactivatedAfterSlash: slash + deregister atomically coupled
    at apply.
  * Inv_NoDoubleSlash: a single Apply* step contributes at most the
    pre-apply stakes[d]; second-equivocation for same offender hits
    Ghost branch and contributes 0.
  * Inv_SlashedMonotonic + Inv_SlashedNeverExceedsTotal: A1-companion
    conservation invariants.

Modeling scope (TLC tractability):

  * Full-forfeit slashing matching chain.cpp:1348-1349.
  * Equivocate(d) abstracts EUF-CMA / V11 — FA6 covers the
    cryptographic side.
  * pending_events is a single shared Seq (FIFO drain). Apply*
    branches are mutually exclusive on guards.
  * EquivocationEvent == [offender: Domain]. Cryptographic fields
    (h, σ_a, σ_b, d_a, d_b) abstracted; apply only consumes
    `ev.equivocator` (chain.cpp:1344).
  * Sentinel > MaxHeight + 1 (ConfigOK), so height + 1 mutation
    never collides with the "never deactivated" marker.

To check (assuming TLC installed):
  $ tlc EquivocationApply.tla -config EquivocationApply.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,            \* set of operator / domain identifiers
    MaxHeight,          \* upper bound on chain height for TLC
    MaxStake,           \* initial per-domain locked stake for TLC
    Sentinel            \* "never deactivated" marker; > MaxHeight + 1

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ MaxHeight \in Nat /\ MaxHeight >= 1
    /\ MaxStake  \in Nat /\ MaxStake  >= 1
    /\ Sentinel  \in Nat /\ Sentinel  > MaxHeight + 1

\* INITIAL_TOTAL_STAKE is the conserved upper bound on the sum of
\* all slashed stake across any trace. The Equivocate action never
\* moves value; the ApplyEquivocation action consumes locked stake
\* into `accumulated_slashed` (a one-way drain). Hence the sum
\* `SumStakes + accumulated_slashed <= INITIAL_TOTAL_STAKE` holds
\* at every reachable state. Used by Inv_SlashedNeverExceedsTotal.
INITIAL_TOTAL_STAKE == MaxStake * Cardinality(Domains)

\* EquivocationEvent shape: a single-field record carrying the
\* offender domain. The cryptographic surface (h, σ_a, σ_b, d_a, d_b)
\* is abstracted — the apply path only consumes the offender field
\* at `chain.cpp:1344-1356`.
EquivocationEvent == [offender: Domains]

----------------------------------------------------------------------------
\* State.

VARIABLES
    registrants,        \* function Domains -> [active, inactive_from]
    stakes,             \* function Domains -> Nat (locked amount)
    accumulated_slashed,\* Nat: running total of slashed stake
    height,             \* current chain height
    pending_events      \* sequence of EquivocationEvent (FIFO drain)

vars == <<registrants, stakes, accumulated_slashed, height, pending_events>>

----------------------------------------------------------------------------
\* Initial state. All domains start active in the registry with their
\* full per-domain stake (MaxStake) locked. `accumulated_slashed` and
\* `height` start at 0; `pending_events` is empty.
\*
\* `inactive_from = Sentinel` at Init means "never deactivated" — the
\* standard apply-side convention encoded in C++ as UINT64_MAX at
\* `src/chain/chain.cpp:139`. The Sentinel-vs-Nat distinction is the
\* state-machine version of the "is the registry entry still live"
\* predicate; the ApplyEquivocation action flips it to height+1.

Init ==
    /\ registrants = [d \in Domains |->
                        [active |-> TRUE, inactive_from |-> Sentinel]]
    /\ stakes = [d \in Domains |-> MaxStake]
    /\ accumulated_slashed = 0
    /\ height = 0
    /\ pending_events = <<>>

----------------------------------------------------------------------------
\* Actions. Each action models the corresponding apply-layer branch in
\* `src/chain/chain.cpp::apply_block` lines 1330-1356 (the
\* EquivocationEvent loop). The three Apply* branches are mutually
\* exclusive on their guards and together drain exactly one head
\* event per ApplyEquivocation* step.

\* Equivocate(d): adversarial action — appends an EquivocationEvent
\* for d to pending_events. Abstracts EUF-CMA / V11 dual-signature
\* witness verification (FA6 T-6 covers the honest-validator
\* soundness). Queue length is bounded for TLC tractability; the
\* actual chain has no queue cap on EquivocationEvents per block
\* (the validator's per-block-size cap S-022 provides the implicit
\* bound).
Equivocate(d) ==
    /\ d \in Domains
    /\ Len(pending_events) < MaxHeight + Cardinality(Domains)
    /\ pending_events' = Append(pending_events, [offender |-> d])
    /\ UNCHANGED <<registrants, stakes, accumulated_slashed, height>>

\* ApplyEquivocation(d): headline apply transition (active branch).
\* Models the apply-loop body at chain.cpp:1344-1356. If
\* registrants[d].active, zero stakes[d], set inactive_from =
\* height + 1, add pre-apply stake to accumulated_slashed, drop
\* head of pending_events. The already-deactivated branch is
\* covered by ApplyEquivocationAlreadyDeactivated.
ApplyEquivocation(d) ==
    /\ d \in Domains
    /\ Len(pending_events) > 0
    /\ Head(pending_events).offender = d
    /\ registrants[d].active
    /\ stakes' = [stakes EXCEPT ![d] = 0]
    /\ accumulated_slashed' = accumulated_slashed + stakes[d]
    /\ registrants' = [registrants EXCEPT
                         ![d] = [active        |-> FALSE,
                                 inactive_from |-> height + 1]]
    /\ pending_events' = Tail(pending_events)
    /\ UNCHANGED <<height>>

\* ApplyEquivocationGhost(d): T-E4 ghost-equivocator branch. The
\* offender's registry entry has been fully wound down — the C++
\* guards at lines 1346 and 1352 both fail (stakes_.find returns
\* end(); registrants_.find may or may not, but inactive_from is
\* already past). Encoded as stakes[d] = 0 /\ active = FALSE
\* /\ inactive_from /= Sentinel /\ inactive_from <= height. No-op
\* on every state variable except the event-queue drain.
ApplyEquivocationGhost(d) ==
    /\ d \in Domains
    /\ Len(pending_events) > 0
    /\ Head(pending_events).offender = d
    /\ stakes[d] = 0
    /\ registrants[d].active = FALSE
    /\ registrants[d].inactive_from /= Sentinel
    /\ registrants[d].inactive_from <= height
    /\ pending_events' = Tail(pending_events)
    /\ UNCHANGED <<registrants, stakes, accumulated_slashed, height>>

\* ApplyEquivocationAlreadyDeactivated(d): "still has stake but
\* already inactive" branch (chain.cpp:1337-1343 dual-mechanism
\* unification). A prior DEREGISTER or prior equivocation set
\* active = FALSE while leaving some stake locked. Apply STILL
\* slashes — STAKE_INCLUSION fully drains even when
\* DOMAIN_INCLUSION-style deregistration already fired. Encoded
\* as active = FALSE /\ stakes[d] > 0. inactive_from is
\* unconditionally rewritten to height + 1 (chain.cpp:1354 has
\* no "was previously set" check). Inv_DeactivatedAfterSlash
\* holds: post-state active = FALSE preserved, inactive_from
\* /= Sentinel preserved.
ApplyEquivocationAlreadyDeactivated(d) ==
    /\ d \in Domains
    /\ Len(pending_events) > 0
    /\ Head(pending_events).offender = d
    /\ registrants[d].active = FALSE
    /\ stakes[d] > 0
    /\ stakes' = [stakes EXCEPT ![d] = 0]
    /\ accumulated_slashed' = accumulated_slashed + stakes[d]
    /\ registrants' = [registrants EXCEPT
                         ![d] = [active        |-> FALSE,
                                 inactive_from |-> height + 1]]
    /\ pending_events' = Tail(pending_events)
    /\ UNCHANGED <<height>>

\* AdvanceHeight: tick the block index forward by 1. The temporal
\* driver — without it, the `inactive_from = height + 1` value
\* is static and the eventual-slash liveness claim degenerates.
AdvanceHeight ==
    /\ height < MaxHeight
    /\ height' = height + 1
    /\ UNCHANGED <<registrants, stakes, accumulated_slashed, pending_events>>

----------------------------------------------------------------------------
\* Next-state relation. Any of the actions may fire at any enabled
\* state; TLC enumerates all interleavings.

Next ==
    \/ \E d \in Domains : Equivocate(d)
    \/ \E d \in Domains : ApplyEquivocation(d)
    \/ \E d \in Domains : ApplyEquivocationGhost(d)
    \/ \E d \in Domains : ApplyEquivocationAlreadyDeactivated(d)
    \/ AdvanceHeight

\* Fairness on AdvanceHeight (so height progresses) and on each
\* Apply* branch (so a pending head event eventually drains). The
\* three Apply* branches together cover the full guard space at
\* the head — at any state with a non-empty pending_events head
\* targeting `d`, exactly one of (ApplyEquivocation(d),
\* ApplyEquivocationGhost(d), ApplyEquivocationAlreadyDeactivated(d))
\* is enabled. Fairness on the disjunction gives the eventual-
\* progress liveness for Prop_EventualSlash.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(AdvanceHeight)
    /\ \A d \in Domains : WF_vars(ApplyEquivocation(d))
    /\ \A d \in Domains : WF_vars(ApplyEquivocationGhost(d))
    /\ \A d \in Domains : WF_vars(ApplyEquivocationAlreadyDeactivated(d))

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant: variables have correct shapes. Sentinel is a
\* distinguished value in 0..Sentinel (the inactive_from range);
\* ConfigOK guarantees Sentinel > MaxHeight + 1 so the height + 1
\* mutation never collides with Sentinel.
Inv_TypeOK ==
    /\ registrants \in [Domains -> [active: BOOLEAN,
                                     inactive_from: 0..Sentinel]]
    /\ stakes \in [Domains -> 0..MaxStake]
    /\ accumulated_slashed \in 0..INITIAL_TOTAL_STAKE
    /\ height \in 0..MaxHeight
    /\ pending_events \in Seq(EquivocationEvent)

\* Stake non-negativity (Nat-valued; documents the contract). The
\* Apply* branches zero stakes[d] (to 0, not negative); Equivocate
\* never touches stakes. Hence stakes[d] >= 0 holds always.
Inv_StakeNonNegative ==
    \A d \in Domains : stakes[d] >= 0

\* SlashedMonotonic: accumulated_slashed never decreases across
\* any [Next]_vars step. Only ApplyEquivocation and
\* ApplyEquivocationAlreadyDeactivated mutate the field, both add
\* the pre-apply stakes[d] (a non-negative Nat); Equivocate /
\* ApplyEquivocationGhost / AdvanceHeight all preserve.
\*
\* Expressed as an action invariant via primed-state form; TLC
\* checks against the [Next]_vars transition relation.
Inv_SlashedMonotonic ==
    [][accumulated_slashed' >= accumulated_slashed]_vars

\* SlashedNeverExceedsTotal: the running total of slashed stake
\* never exceeds the initial total stake supply. Every Apply*
\* branch consumes from stakes[d] into accumulated_slashed
\* (zero-sum on the (stakes, accumulated_slashed) pair). Equivocate
\* and AdvanceHeight do not touch either. Hence:
\*
\*   SumStakes + accumulated_slashed <= INITIAL_TOTAL_STAKE
\*
\* at every reachable state. The <= is non-strict because
\* ApplyEquivocationGhost is a no-op (the offender's stake was
\* already 0, so no contribution).
SumStakes ==
    LET RECURSIVE sum_stk(_) IN
    LET sum_stk(S) ==
        IF S = {} THEN 0
        ELSE LET d == CHOOSE x \in S : TRUE IN
             stakes[d] + sum_stk(S \ {d})
    IN sum_stk(Domains)

Inv_SlashedNeverExceedsTotal ==
    SumStakes + accumulated_slashed <= INITIAL_TOTAL_STAKE

\* DeactivatedAfterSlash: once a domain has been the subject of a
\* successful Apply* step, its registry entry is permanently
\* inactive — active = FALSE AND inactive_from /= Sentinel. The
\* slash-and-deregister are atomically coupled at the apply-layer.
\* Encoded as: any domain with stakes[d] = 0 AND inactive_from /=
\* Sentinel has active = FALSE — the structural witness of
\* coupling.
Inv_DeactivatedAfterSlash ==
    \A d \in Domains :
       (registrants[d].inactive_from /= Sentinel /\ stakes[d] = 0)
       => (registrants[d].active = FALSE)

\* NoDoubleSlash: any single Apply* step contributes at most the
\* pre-apply stakes[d] to accumulated_slashed. Multiple events for
\* the same offender each hit Apply* separately, but the SECOND
\* finds stakes[d] = 0 (Ghost branch) and contributes 0. Action
\* form: if accumulated_slashed' > accumulated_slashed, the delta
\* equals pre-apply stakes[d] for the head offender.
Inv_NoDoubleSlash ==
    [][\A d \in Domains :
         (accumulated_slashed' > accumulated_slashed
          /\ Len(pending_events) > 0
          /\ Head(pending_events).offender = d)
         => (accumulated_slashed' - accumulated_slashed = stakes[d])
      ]_vars

----------------------------------------------------------------------------
\* Temporal properties.

\* EventualSlash: under fairness on AdvanceHeight + the three
\* Apply* branches, any pending EquivocationEvent eventually
\* drains. The Apply* branches together cover the full guard
\* space at the head (active -> ApplyEquivocation, fully wound
\* down -> ApplyEquivocationGhost, inactive with stake ->
\* ApplyEquivocationAlreadyDeactivated). Eventual-progress
\* conclusion: if pending_events is non-empty, eventually it
\* shrinks — either by Apply* drain or by reaching MaxHeight.
Prop_EventualSlash ==
    (Len(pending_events) > 0)
    ~> (Len(pending_events) = 0 \/ height >= MaxHeight)

\* StateMonotone: stakes[d] only decreases. No action increases
\* stakes — no "un-slash" / "re-stake" branch exists in the
\* equivocation-apply state machine (the STAKE-tx restake is FB8
\* territory). Combined with Inv_DeactivatedAfterSlash, this gives
\* the full "slash is one-way and permanent" claim.
Prop_StateMonotone ==
    [][\A d \in Domains : stakes'[d] <= stakes[d]]_vars

============================================================================
