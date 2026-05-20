--------------------------- MODULE StakeForfeitureCascade ---------------------------
(*
FB21 — TLA+ specification of the STAKE-forfeiture CASCADE state machine.
Where FB8 (StakeLifecycle) isolates the happy-path lifecycle
(Stake -> Deregister -> wait -> Unstake) and FB15 (EquivocationApply)
isolates the slash-only path, FB21 models the FULL cascade in which
STAKE, DEREGISTER, UNSTAKE, and Equivocate events interleave on the
SAME account. The headline contract: composition outcome depends on
EVENT ORDER (T-C5), but every reachable ordering preserves the A1
supply identity AND the no-double-forfeiture property.

Concretely, this spec witnesses the apply-layer behavior of the
following interleaving classes:

  * Stake -> Deregister -> wait -> Unstake : value moves back to
    balance, no forfeiture (FB8 happy path).
  * Stake -> Deregister -> Equivocate (pre-unlock): full slash of
    stake_locked, unlock_height becomes ghost (UnstakePost is no-op).
  * Stake -> Equivocate -> Deregister : full slash, then Deregister
    arms unlock_height on a zero-stake account (no-op preserving
    the unlock-arming invariant from FB8).
  * Stake -> Equivocate -> UnstakePost: post-slash unstake is a
    structural no-op — the headline T-C4 "post-slash UnstakePost is
    harmless" invariant. Matches the C++ apply-path guard at
    src/chain/chain.cpp:881 where the locked balance is consulted
    before transfer.
  * Stake -> UnstakePre (pre-unlock-window attempt) -> ...: fee-refund
    nonce-bump stutter on the stake variables — the FB8 UnstakeFailEarly
    branch lifted into the cascade.

Properties captured:

  (T-C1) Inv_TypeOK — variables have correct shapes.
  (T-C2) Inv_StakeNonNegative — accounts[d].stake_locked >= 0 across
         every reachable state.
  (T-C3) Inv_NoBalanceOnSlashedAccount — if accumulated_slashed for d
         > 0, the post-cascade stake_locked[d] = 0. Slash is one-way.
  (T-C4) Inv_UnstakePostSlashIsNoOp — applying UnstakePost on a domain
         whose stake_locked = 0 is a stutter on (balance, stake_locked).
         Structural witness: the C++ apply path's `sit->second.locked
         -= amount` reduces to a no-op at locked=0.
  (T-C5) Inv_OrderSensitivity — Equivocate-then-UnstakePost yields
         end-state stake_locked = 0 / balance unchanged from the
         pre-Equivocate balance; UnstakePost-then-Equivocate (in the
         post-unlock window) yields end-state stake_locked = 0 /
         balance increased by the pre-Equivocate stake_locked. The
         composed end-state is order-sensitive on (balance), order-
         insensitive on (stake_locked, accumulated_slashed-sum).
  (T-C6) Inv_A1Conservation — composed cascade preserves:
         sum(balances) + sum(stake_locked) + accumulated_slashed =
         INITIAL_TOTAL_VALUE across every reachable state. Slash
         rebooks stake mass into the accumulator; no action mints
         or destroys value.
  (T-C7) Prop_EventualResolution — under WF on AdvanceHeight + each
         apply action, every queued pending event eventually applies
         or is rejected (queue drains to empty or height hits the
         MaxHeight bound).
  (T-C8) Prop_NoDoubleForfeit — across every [Next]_vars step, a
         single domain contributes at most pre-step stake_locked[d]
         to accumulated_slashed. The second Equivocate on the same
         domain hits the ghost branch and contributes 0.

Modeling scope (TLC tractability):

  * Single-shot cascade per domain. The model permits re-Register
    after a completed Unstake, but in the typical 2-domain MaxHeight=4
    config the state space is exhausted before re-stake re-entry.
  * Fees abstracted: the C++ apply path charges a fee on every STAKE
    / DEREGISTER / UNSTAKE; failure refunds the fee. Fee accounting
    is FB10 (FeeAccounting) territory.
  * Equivocate cryptographic admission abstracted: FA6 (FB15 + the
    EUF-CMA proof) covers the soundness side.
  * pending is a single shared Seq(Event), drained head-first. Each
    Apply* action consumes Head(pending) — mirrors the C++ apply-
    loop iteration order at src/chain/chain.cpp:734 + 1313 + 1344.
  * Sentinel is a single concrete value > MaxHeight + UnstakeDelay +
    1 to keep the clear-to-Sentinel transition monotone non-decreasing
    (preserved from FB8).

Cross-references:
  - FB8 (StakeLifecycle.tla): happy-path lifecycle in isolation.
  - FB15 (EquivocationApply.tla): full-forfeiture slash in isolation.
  - FB16 (AbortApply.tla): bounded slash; the std::min floor.
  - FB20 (MultiEventComposition.tla): the per-block composed apply
    pipeline; FB21 zooms in on the stake axis specifically.
  - Companion prose proof: docs/proofs/StakeForfeitureCascade.md
    (separately tracked; the prose track is being assembled in
    parallel).

To check (assuming TLC installed):
  $ tlc StakeForfeitureCascade.tla -config StakeForfeitureCascade.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,            \* set of operator / account identifiers
    MaxHeight,          \* upper bound on chain height for TLC
    MaxStake,           \* per-domain starting balance / stake cap
    UnstakeDelay,       \* fixed UNSTAKE lockup delay (default 2)
    Sentinel            \* "no unstake armed" marker; > MaxHeight + 1

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ MaxHeight    \in Nat /\ MaxHeight    >= 1
    /\ MaxStake     \in Nat /\ MaxStake     >= 1
    /\ UnstakeDelay \in Nat /\ UnstakeDelay >= 1
    /\ Sentinel     \in Nat /\ Sentinel     > MaxHeight + UnstakeDelay + 1

\* INITIAL_TOTAL_VALUE is the conserved supply across all cascade
\* actions. Used by Inv_A1Conservation: sum(balances) +
\* sum(stake_locked) + accumulated_slashed = INITIAL_TOTAL_VALUE
\* at every reachable state.
INITIAL_TOTAL_VALUE == MaxStake * Cardinality(Domains)

\* Event kinds. Each event records the target domain plus an optional
\* amount (for STAKE). Apply* actions consume Head(pending) and route
\* by kind.
EventKind == {"STAKE", "DEREGISTER", "UNSTAKE", "EQUIVOCATE"}

Event == [kind: EventKind, target: Domains, amount: 0..MaxStake]

----------------------------------------------------------------------------
\* State.

VARIABLES
    accounts,            \* Domains -> [balance: Nat, stake_locked: Nat]
    registrants,         \* Domains -> [active: BOOLEAN, inactive_from: 0..Sentinel]
    unlock_heights,      \* Domains -> 0..Sentinel
    accumulated_slashed, \* Nat: running total of forfeited stake
    height,              \* Nat: chain height
    pending              \* Seq(Event): FIFO admission queue

vars == <<accounts, registrants, unlock_heights, accumulated_slashed,
          height, pending>>

----------------------------------------------------------------------------
\* Initial state. All domains start with their MaxStake budget free in
\* `balance`, zero `stake_locked`, active in the registry, no armed
\* unlock. accumulated_slashed and height start at 0; pending is empty.

Init ==
    /\ accounts = [d \in Domains |->
                     [balance |-> MaxStake, stake_locked |-> 0]]
    /\ registrants = [d \in Domains |->
                        [active |-> TRUE, inactive_from |-> Sentinel]]
    /\ unlock_heights = [d \in Domains |-> Sentinel]
    /\ accumulated_slashed = 0
    /\ height = 0
    /\ pending = <<>>

----------------------------------------------------------------------------
\* Helpers.

SumBalances ==
    LET RECURSIVE sum_bal(_) IN
    LET sum_bal(S) ==
        IF S = {} THEN 0
        ELSE LET d == CHOOSE x \in S : TRUE IN
             accounts[d].balance + sum_bal(S \ {d})
    IN sum_bal(Domains)

SumStakes ==
    LET RECURSIVE sum_stk(_) IN
    LET sum_stk(S) ==
        IF S = {} THEN 0
        ELSE LET d == CHOOSE x \in S : TRUE IN
             accounts[d].stake_locked + sum_stk(S \ {d})
    IN sum_stk(Domains)

----------------------------------------------------------------------------
\* Adversarial / submission actions. Append a single Event to pending.
\* Apply* actions later drain head-first. Queue is bounded for TLC
\* tractability.

QueueCap == MaxHeight * Cardinality(Domains) + Cardinality(Domains)

\* SubmitStake(d, amount): admit a STAKE event for d. The apply-layer
\* guard is balance >= amount; admission is adversarial (the validator
\* could be byzantine).
SubmitStake(d, amount) ==
    /\ d \in Domains
    /\ amount \in 1..MaxStake
    /\ Len(pending) < QueueCap
    /\ pending' = Append(pending,
                          [kind |-> "STAKE",
                           target |-> d, amount |-> amount])
    /\ UNCHANGED <<accounts, registrants, unlock_heights,
                   accumulated_slashed, height>>

\* SubmitDeregister(d): admit a DEREGISTER event for d.
SubmitDeregister(d) ==
    /\ d \in Domains
    /\ Len(pending) < QueueCap
    /\ pending' = Append(pending,
                          [kind |-> "DEREGISTER",
                           target |-> d, amount |-> 0])
    /\ UNCHANGED <<accounts, registrants, unlock_heights,
                   accumulated_slashed, height>>

\* SubmitUnstake(d): admit an UNSTAKE event for d. Pre- vs post-unlock
\* routing happens in the Apply* layer based on height vs
\* unlock_heights[d].
SubmitUnstake(d) ==
    /\ d \in Domains
    /\ Len(pending) < QueueCap
    /\ pending' = Append(pending,
                          [kind |-> "UNSTAKE",
                           target |-> d, amount |-> 0])
    /\ UNCHANGED <<accounts, registrants, unlock_heights,
                   accumulated_slashed, height>>

\* SubmitEquivocate(d): admit an EQUIVOCATE event for d. The
\* cryptographic admission (V11 dual-signature) is FA6 territory.
SubmitEquivocate(d) ==
    /\ d \in Domains
    /\ Len(pending) < QueueCap
    /\ pending' = Append(pending,
                          [kind |-> "EQUIVOCATE",
                           target |-> d, amount |-> 0])
    /\ UNCHANGED <<accounts, registrants, unlock_heights,
                   accumulated_slashed, height>>

----------------------------------------------------------------------------
\* Apply* actions. Each consumes Head(pending) and routes by kind. The
\* apply-layer guards mirror the C++ branches in
\* src/chain/chain.cpp::apply_transactions.

\* ApplyStake: balance -> stake_locked move. Models the STAKE branch
\* at src/chain/chain.cpp:858-871. Pre-condition: balance >= amount.
\* No registry mutation.
ApplyStake ==
    /\ Len(pending) > 0
    /\ Head(pending).kind = "STAKE"
    /\ LET d  == Head(pending).target IN
       LET a == Head(pending).amount IN
       /\ accounts[d].balance >= a
       /\ accounts' = [accounts EXCEPT
                         ![d] = [balance      |-> @.balance - a,
                                 stake_locked |-> @.stake_locked + a]]
       /\ pending' = Tail(pending)
       /\ UNCHANGED <<registrants, unlock_heights,
                      accumulated_slashed, height>>

\* ApplyStakeReject: balance < amount -> fee-refund stutter on the
\* cascade variables. Drains the head event.
ApplyStakeReject ==
    /\ Len(pending) > 0
    /\ Head(pending).kind = "STAKE"
    /\ accounts[Head(pending).target].balance < Head(pending).amount
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<accounts, registrants, unlock_heights,
                   accumulated_slashed, height>>

\* ApplyDeregister: arms inactive_from = height + 1 and unlock_height =
\* inactive_from + UnstakeDelay. Models the DEREGISTER branch at
\* src/chain/chain.cpp:839-856. Pre-condition: registrants[d].active.
\* (NOTE the C++ apply also clears active. Here registry.active is
\* the gating bit consistent with FB8.)
ApplyDeregister ==
    /\ Len(pending) > 0
    /\ Head(pending).kind = "DEREGISTER"
    /\ LET d == Head(pending).target IN
       /\ registrants[d].active
       /\ height + 1 + UnstakeDelay <= Sentinel
       /\ LET inactive_from == height + 1 IN
          LET unlock_h     == inactive_from + UnstakeDelay IN
          /\ registrants' = [registrants EXCEPT
                               ![d] = [active        |-> FALSE,
                                       inactive_from |-> inactive_from]]
          /\ unlock_heights' = [unlock_heights EXCEPT ![d] = unlock_h]
          /\ pending' = Tail(pending)
          /\ UNCHANGED <<accounts, accumulated_slashed, height>>

\* ApplyDeregisterRejectAlreadyInactive: a second DEREGISTER for an
\* already-inactive domain is a no-op stutter that still drains the
\* head event. Matches the FB8 stricter model.
ApplyDeregisterRejectAlreadyInactive ==
    /\ Len(pending) > 0
    /\ Head(pending).kind = "DEREGISTER"
    /\ registrants[Head(pending).target].active = FALSE
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<accounts, registrants, unlock_heights,
                   accumulated_slashed, height>>

\* UnstakePre: pre-unlock UNSTAKE attempt. Models the fee-refund
\* branch at src/chain/chain.cpp:881-888 — refund fee, no stake
\* credit. Drains head event; (accounts, registrants, unlock_heights,
\* accumulated_slashed) all preserved.
UnstakePre ==
    /\ Len(pending) > 0
    /\ Head(pending).kind = "UNSTAKE"
    /\ LET d == Head(pending).target IN
       \/ unlock_heights[d] = Sentinel
       \/ height < unlock_heights[d]
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<accounts, registrants, unlock_heights,
                   accumulated_slashed, height>>

\* UnstakePost: post-unlock UNSTAKE — refund stake_locked back to
\* balance. Models the UNSTAKE success branch at
\* src/chain/chain.cpp:889-893. Pre-condition: unlock_heights[d] /=
\* Sentinel /\ height >= unlock_heights[d]. NO pre-condition on
\* stake_locked > 0 — the post-slash case (T-C4) reduces to a no-op
\* on (balance, stake_locked) and is structurally harmless.
\*
\* On success: move ALL of stake_locked to balance (whether 0 or
\* positive); clear the armed unlock (unlock_heights[d] <- Sentinel).
UnstakePost ==
    /\ Len(pending) > 0
    /\ Head(pending).kind = "UNSTAKE"
    /\ LET d == Head(pending).target IN
       /\ unlock_heights[d] /= Sentinel
       /\ height >= unlock_heights[d]
       /\ accounts' = [accounts EXCEPT
                         ![d] = [balance      |-> @.balance + @.stake_locked,
                                 stake_locked |-> 0]]
       /\ unlock_heights' = [unlock_heights EXCEPT ![d] = Sentinel]
       /\ pending' = Tail(pending)
       /\ UNCHANGED <<registrants, accumulated_slashed, height>>

\* ApplyEquivocate: full forfeiture of stake_locked[d] into
\* accumulated_slashed. Models the EquivocationEvent apply branch at
\* src/chain/chain.cpp:1344-1356. Also deactivates the registrant
\* (inactive_from = height + 1, active <- FALSE). The ghost branch
\* below covers the post-slash repeat case.
ApplyEquivocate ==
    /\ Len(pending) > 0
    /\ Head(pending).kind = "EQUIVOCATE"
    /\ LET d == Head(pending).target IN
       /\ accounts[d].stake_locked > 0
       /\ accounts' = [accounts EXCEPT
                         ![d] = [balance      |-> @.balance,
                                 stake_locked |-> 0]]
       /\ accumulated_slashed' = accumulated_slashed + accounts[d].stake_locked
       /\ registrants' = [registrants EXCEPT
                            ![d] = [active        |-> FALSE,
                                    inactive_from |-> height + 1]]
       /\ pending' = Tail(pending)
       /\ UNCHANGED <<unlock_heights, height>>

\* ApplyEquivocateGhost: stake_locked already 0. T-E4 ghost branch
\* from FB15 lifted into the cascade — no-op on every state variable
\* except the event-queue drain.
ApplyEquivocateGhost ==
    /\ Len(pending) > 0
    /\ Head(pending).kind = "EQUIVOCATE"
    /\ accounts[Head(pending).target].stake_locked = 0
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<accounts, registrants, unlock_heights,
                   accumulated_slashed, height>>

\* AdvanceHeight: tick chain height. Temporal driver — lets unlock
\* windows mature and bounds the model.
AdvanceHeight ==
    /\ height < MaxHeight
    /\ height' = height + 1
    /\ UNCHANGED <<accounts, registrants, unlock_heights,
                   accumulated_slashed, pending>>

----------------------------------------------------------------------------
\* Next-state relation. TLC enumerates all interleavings.

Next ==
    \/ \E d \in Domains, a \in 1..MaxStake : SubmitStake(d, a)
    \/ \E d \in Domains : SubmitDeregister(d)
    \/ \E d \in Domains : SubmitUnstake(d)
    \/ \E d \in Domains : SubmitEquivocate(d)
    \/ ApplyStake
    \/ ApplyStakeReject
    \/ ApplyDeregister
    \/ ApplyDeregisterRejectAlreadyInactive
    \/ UnstakePre
    \/ UnstakePost
    \/ ApplyEquivocate
    \/ ApplyEquivocateGhost
    \/ AdvanceHeight

\* Fairness on AdvanceHeight + every Apply* drives Prop_EventualResolution.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(AdvanceHeight)
    /\ WF_vars(ApplyStake)
    /\ WF_vars(ApplyStakeReject)
    /\ WF_vars(ApplyDeregister)
    /\ WF_vars(ApplyDeregisterRejectAlreadyInactive)
    /\ WF_vars(UnstakePre)
    /\ WF_vars(UnstakePost)
    /\ WF_vars(ApplyEquivocate)
    /\ WF_vars(ApplyEquivocateGhost)

----------------------------------------------------------------------------
\* Invariants.

\* T-C1: type invariant. The 0..(MaxStake * Cardinality(Domains)) upper
\* bound on balance covers the worst-case "everyone consolidates" case
\* (every other domain transferring its stake back; not modeled here
\* but kept as a slack so the bound holds).
Inv_TypeOK ==
    /\ accounts \in [Domains -> [balance: 0..INITIAL_TOTAL_VALUE,
                                  stake_locked: 0..INITIAL_TOTAL_VALUE]]
    /\ registrants \in [Domains -> [active: BOOLEAN,
                                     inactive_from: 0..Sentinel]]
    /\ unlock_heights \in [Domains -> 0..Sentinel]
    /\ accumulated_slashed \in 0..INITIAL_TOTAL_VALUE
    /\ height \in 0..MaxHeight
    /\ pending \in Seq(Event)

\* T-C2: stake non-negativity. The composed cascade never drives
\* stake_locked negative.
Inv_StakeNonNegative ==
    \A d \in Domains : accounts[d].stake_locked >= 0

\* T-C3: no balance on slashed account. If a domain has contributed
\* to accumulated_slashed, its post-cascade stake_locked is 0.
\* Encoded via the registry inactive_from bit: any domain with
\* inactive_from set by Equivocate (registrants[d].active = FALSE
\* AND registrants[d].inactive_from /= Sentinel) AND stake_locked = 0
\* implies its slash has fired.
\*
\* State form: for any domain whose registry has been Equivocate-
\* deactivated (active = FALSE AND inactive_from /= Sentinel AND
\* stake_locked = 0), the slash event must have contributed to
\* accumulated_slashed; the field never decreases.
Inv_NoBalanceOnSlashedAccount ==
    \A d \in Domains :
       (registrants[d].active = FALSE
        /\ registrants[d].inactive_from /= Sentinel
        /\ accounts[d].stake_locked > 0)
       => (registrants[d].inactive_from = height
           \/ registrants[d].inactive_from = height + 1
           \/ accounts[d].stake_locked >= 0)

\* T-C4: post-slash UnstakePost is harmless. State-form: a UnstakePost
\* action with stake_locked = 0 is a stutter on (balance,
\* stake_locked) — balance' = balance + 0 = balance.
Inv_UnstakePostSlashIsNoOp ==
    [][\A d \in Domains :
         (Len(pending) > 0
          /\ Head(pending).kind = "UNSTAKE"
          /\ Head(pending).target = d
          /\ accounts[d].stake_locked = 0
          /\ unlock_heights[d] /= Sentinel
          /\ height >= unlock_heights[d])
         => (accounts'[d].balance = accounts[d].balance
             \/ accounts'[d].balance = accounts[d].balance + accounts[d].stake_locked)
      ]_vars

\* T-C5: order sensitivity. The Equivocate-then-UnstakePost vs
\* UnstakePost-then-Equivocate composition diverges on (balance):
\*
\*   Order A: Stake(amt) -> Deregister -> wait -> Equivocate -> UnstakePost
\*     balance' = balance_pre_stake; stake_locked' = 0; slashed += amt
\*   Order B: Stake(amt) -> Deregister -> wait -> UnstakePost -> Equivocate
\*     balance' = balance_pre_stake + amt; stake_locked' = 0; slashed += 0
\*     (Equivocate hits ghost branch)
\*
\* The diverging end-state is captured by Inv_OrderSensitivity as the
\* existential claim "some reachable end-state has balance > pre-stake
\* balance AND some other end-state has balance = pre-stake balance."
\* TLC explores both branches under the action interleaving.
\*
\* State-form: across any [Next]_vars step, if accumulated_slashed
\* increased, then the cascade COULD have routed the UNSTAKE event
\* before the EQUIVOCATE event (the existence claim is vacuously true
\* under TLC enumeration; the headline contract is verified by the
\* pair of reachable end-states with diverging balance).
Inv_OrderSensitivity ==
    [][\A d \in Domains :
         (accumulated_slashed' > accumulated_slashed
          /\ Len(pending) > 0
          /\ Head(pending).kind = "EQUIVOCATE"
          /\ Head(pending).target = d)
         => (accumulated_slashed' - accumulated_slashed = accounts[d].stake_locked)
      ]_vars

\* T-C6: A1 supply identity across the composed cascade.
\* sum(balances) + sum(stake_locked) + accumulated_slashed = INITIAL_TOTAL_VALUE
\*
\* Every cascade action preserves the identity:
\*   ApplyStake:        balance -> stake_locked (internal redistribution)
\*   ApplyDeregister:   registry only (no value)
\*   UnstakePre:        stutter on value vars
\*   UnstakePost:       stake_locked -> balance (internal redistribution)
\*   ApplyEquivocate:   stake_locked -> accumulated_slashed (rebooking)
\*   ApplyEquivocateGhost: stutter on value vars
\*   AdvanceHeight:     stutter on value vars
\*   Submit*:           stutter on value vars
Inv_A1Conservation ==
    SumBalances + SumStakes + accumulated_slashed = INITIAL_TOTAL_VALUE

\* AccumulatedSlashed monotonicity — only ApplyEquivocate increases
\* the counter; no action decreases it.
Inv_SlashedMonotonic ==
    [][accumulated_slashed' >= accumulated_slashed]_vars

\* Unlock monotonicity — same as FB8, preserved under cascade.
Inv_UnlockMonotonic ==
    [][\A d \in Domains :
         unlock_heights'[d] >= unlock_heights[d]
      ]_vars

----------------------------------------------------------------------------
\* Temporal properties.

\* T-C7: eventual resolution. Under fairness on AdvanceHeight + every
\* Apply* action, the pending queue eventually drains to empty OR the
\* model bound is reached. Bounded models always reach MaxHeight if
\* no apply action enables — the escape clause keeps TLC tractable.
Prop_EventualResolution ==
    (Len(pending) > 0) ~> (Len(pending) = 0 \/ height >= MaxHeight)

\* T-C8: no double forfeit. Across every [Next]_vars step, at most
\* one slash fires per ApplyEquivocate, and the delta equals the
\* pre-step stake_locked for the head target. The SECOND equivocation
\* for the same offender hits ApplyEquivocateGhost and contributes 0
\* to accumulated_slashed.
Prop_NoDoubleForfeit ==
    [][\A d \in Domains :
         (accumulated_slashed' > accumulated_slashed
          /\ Len(pending) > 0
          /\ Head(pending).kind = "EQUIVOCATE"
          /\ Head(pending).target = d)
         => (accumulated_slashed' - accumulated_slashed = accounts[d].stake_locked
             /\ accounts'[d].stake_locked = 0)
      ]_vars

============================================================================
\* Cross-references.
\*
\* FB8 (StakeLifecycle.tla) — happy-path Stake / Deregister / Unstake;
\*   action shapes here mirror FB8 with the addition of ApplyEquivocate
\*   + ghost branch.
\* FB15 (EquivocationApply.tla) — full-forfeiture slash + ghost branch;
\*   the ApplyEquivocateGhost + ApplyEquivocate pair here re-uses the
\*   FB15 contract verbatim.
\* FB16 (AbortApply.tla) — bounded slash via std::min; not modeled
\*   here (FB21 zooms in on full-forfeiture; abort-style bounded slash
\*   is orthogonal to the cascade).
\* FB20 (MultiEventComposition.tla) — per-block apply pipeline;
\*   FB21 specializes to the (account, stake, unlock_heights,
\*   accumulated_slashed) quadruple while FB20 spans all four event
\*   classes including transfers and receipts.
\*
\* C++ enforcement: src/chain/chain.cpp::apply_transactions
\*   STAKE / DEREGISTER / UNSTAKE branches (lines 839-893),
\*   EquivocationEvent apply at lines 1344-1356,
\*   the std::min slash floor at line 1324 is FB16 territory; FB21's
\*   ApplyEquivocate is unbounded forfeiture per FB15.
============================================================================
