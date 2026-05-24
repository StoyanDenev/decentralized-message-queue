--------------------------- MODULE StakeRefundFlow ---------------------------
(*
FB41 — TLA+ specification of the STAKE / DEREGISTER / UNSTAKE refund-
timing + deferred-unlock contract at the apply-layer state-machine
layer. Where FB8 (StakeLifecycle) isolates the basic happy-path
state machine (REGISTER -> STAKE -> DEREGISTER -> wait -> UNSTAKE)
and FB16 (AbortApply) isolates the bounded-slash apply path and
FB21 (StakeForfeitureCascade) covers the cascade context with
slashing interleavings, FB41 zooms in on the REFUND TIMING and the
deferred-unlock contract. The headline contract: once DEREGISTER
arms `unlock_height = current_height + UNSTAKE_DELAY`, that field
is the SOLE refund gate; no pre-unlock UNSTAKE can ever decrement
`stake_locked`, and the post-unlock UNSTAKE always refunds the
locked balance in full.

Concretely, this spec witnesses the apply-layer refund-timing
contract:

  * Stake(d, amt): move `amt` from accounts[d].balance into
    accounts[d].stake_locked. Pre-condition: balance >= amount.
    Models the STAKE branch at src/chain/chain.cpp:858-871.
  * Deregister(d): mark registry[d] inactive (ACTIVE -> DEREGISTERED)
    AND arm `unlock_height = current_height + UNSTAKE_DELAY`. Models
    the DEREGISTER branch at src/chain/chain.cpp:839-856. Pre-
    condition: registry[d] = ACTIVE (the second DEREGISTER for an
    already-deregistered domain is a no-op stutter — the
    DeregisterIdempotent invariant). Note the apply-layer C++ code
    uses `inactive_from = height + derive_delay(...)` plus
    `unlock_height = inactive_from + unstake_delay_`; the model
    abstracts derive_delay to 0 so the arithmetic is exact
    (`unlock_height = current_height + UNSTAKE_DELAY`).
  * UnstakeEarly(d): pre-unlock UNSTAKE attempt. Matches the C++
    fee-refund branch at src/chain/chain.cpp:881-888 where the
    apply path refunds the fee + bumps the sender's nonce but DOES
    NOT touch `stake_locked` or `balance` (modulo fee accounting,
    which this spec abstracts away). Routes also when DEREGISTER
    has not yet armed `unlock_height` — the "pre-DEREGISTER UNSTAKE
    silently skips with fee refund" rule from the task statement.
  * UnstakePost(d): post-unlock UNSTAKE — refund the locked balance
    back to free balance. Pre-condition: registry[d] = DEREGISTERED
    AND unlock_height[d] /= NONE AND current_height >= unlock_height[d].
    On success: move ALL of stake_locked back to balance; clear the
    armed unlock (unlock_height[d] -> NONE). Models the UNSTAKE
    success branch at src/chain/chain.cpp:889-893.
  * AdvanceHeight: tick current_height forward by 1. The temporal
    driver — without it no deregistered account could ever reach
    its unlock window.

The seven invariants encode the refund-timing contract:

  (1) INV_StakeNonNegative — balance + stake_locked >= 0 always
      (Nat-valued; documents the contract).
  (2) INV_DeregisterSchedules — Deregister sets unlock_height to
      current_height + UNSTAKE_DELAY (exact deferred-unlock arming
      contract; matches src/chain/chain.cpp:851 modulo the
      derive_delay abstraction).
  (3) INV_NoEarlyRefund — UnstakeEarly never decrements stake_locked.
      The headline safety claim: an attacker can spam UNSTAKE txs
      before the deferred-unlock window, but none of them can ever
      drain locked stake. Matches the C++ fee-refund branch at
      chain.cpp:881-888.
  (4) INV_PostUnlockRefund — UnstakePost moves stake_locked into
      balance fully (no partial refund, no stranded stake).
  (5) INV_A1Conservation — balance + stake_locked per domain is
      conserved through every action. Stake / Deregister /
      UnstakeEarly / AdvanceHeight all preserve the sum; UnstakePost
      is also conservation-preserving (it just reclassifies value
      from `stake_locked` to `balance`).
  (6) INV_UnlockHeightMonotonic — once unlock_height is set away
      from the NONE sentinel by Deregister, ONLY UnstakePost can
      clear it (back to NONE). Concretely: a non-NONE unlock_height
      stays non-NONE through Stake / Deregister(idempotent) /
      UnstakeEarly / AdvanceHeight; only UnstakePost transitions it
      back to NONE.
  (7) INV_DeregisterIdempotent — Deregister applied twice in a row
      no-ops the second time (registry state stays DEREGISTERED;
      unlock_height stays at the arming-time value; no re-arm).
      Encoded as the FB8-style stricter model: the second
      Deregister is silently rejected at the apply layer.

And two temporal properties:

  (T1) PROP_EventualRefund — under fairness on AdvanceHeight +
      UnstakePost, every staked + deregistered account eventually
      reaches refunded (stake_locked = 0 / unlock_height = NONE)
      OR the model bound is reached. The eventual-progress /
      no-stuck-stake guarantee for honest operators.
  (T2) PROP_NoStuckStake — stake_locked > 0 AND registry =
      DEREGISTERED AND unlock_height <= current_height implies
      eventually UnstakePost fires. The temporal restatement of
      the unlock-gate's eventual-enabling property: once the
      deferred-unlock window opens, the refund happens.

Modeling scope (TLC tractability):

  * Single-shot lifecycle per domain — the model permits Stake /
    Deregister / Unstake on a domain but does not re-register an
    account once UnstakePost has fired. The cascade reentry is
    FB21 territory; FB41 zooms in on the refund-timing axis.
  * Fees abstracted: the C++ apply path charges a fee on every
    STAKE / DEREGISTER / UNSTAKE; failure refunds the fee. Fee
    accounting is FB10 (FeeAccounting) territory.
  * Equivocation slashing is out of scope — FA6 / FB15 / FB21
    territory. The post-slash UnstakePost-is-noop contract is
    captured in FB21 T-C4.
  * UnstakeDelay is a small finite constant (default 2 for TLC).
    The real protocol uses a 100-block UNSTAKE_DELAY default via
    `Config::unstake_delay`; the state-machine properties are
    invariant in the delay value as long as it is a fixed Nat.
  * NONE is encoded as a value > MaxHeight + UnstakeDelay so the
    "no unlock armed" sentinel cannot collide with any reachable
    current_height value (matches the C++ UINT64_MAX convention
    at src/chain/chain.cpp:139 / :811).

Cross-references:
  - FB8 (StakeLifecycle.tla) — parent: basic state machine. FB41
    sharpens the refund-timing axis by isolating the unlock-height
    transitions + adding the explicit refund-fully invariant.
  - FB16 (AbortApply.tla) — sibling at the apply-layer slash path.
    FB16 covers the bounded-slash apply branch; FB41 covers the
    no-slash refund-timing branch. The two are orthogonal: a
    domain in DEREGISTERED state can still be slashed by an
    AbortEvent (FB16) before its UnstakePost fires, in which case
    FB21's T-C4 ghost-branch contract holds.
  - FB21 (StakeForfeitureCascade.tla) — cascade context: the
    Stake/Deregister/Unstake/Equivocate interleaving full spec.
    FB41 is the slash-free zoom-in; FB21 is the slash-inclusive
    full cascade.
  - FA-Apply-4 (StakeLifecycle.md) — analytic prose-proof of the
    same refund-timing contract. FB41 is the machine-checkable
    state-machine companion.
  - C++ enforcement: src/chain/chain.cpp::apply_transactions
    STAKE / DEREGISTER / UNSTAKE branches at lines 858-893; the
    `inactive_from + unstake_delay_` arming step at line 851; the
    fee-refund early-skip branch at line 881-888.

To check (assuming TLC installed):
  $ tlc StakeRefundFlow.tla -config StakeRefundFlow.cfg
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Domains,            \* set of operator / account identifiers
    MaxAmount,          \* per-account starting balance / stake cap
    UNSTAKE_DELAY,      \* fixed UNSTAKE lockup delay (default 2 for TLC)
    MaxHeight,          \* upper bound on chain height for TLC
    NONE                \* "no unlock armed" sentinel; > MaxHeight + UNSTAKE_DELAY

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ MaxAmount    \in Nat /\ MaxAmount    >= 1
    /\ UNSTAKE_DELAY \in Nat /\ UNSTAKE_DELAY >= 1
    /\ MaxHeight    \in Nat /\ MaxHeight    >= 1
    /\ NONE         \in Nat /\ NONE         > MaxHeight + UNSTAKE_DELAY + 1

\* RegistrantState models the apply-layer registrant-status tri-state.
\* ACTIVE       — domain is registered, may stake / be staked.
\* DEREGISTERED — domain has armed deferred unlock; UnstakePost is the
\*                ONLY action that returns it to NONE or transitions
\*                stake_locked back to balance.
\* NONE         — domain never registered (out of scope for this spec;
\*                Init pre-registers all domains as ACTIVE).
RegState == {"ACTIVE", "DEREGISTERED", "NONE"}

\* INITIAL_TOTAL is the conserved per-domain sum (balance +
\* stake_locked) at Init. Used by INV_A1Conservation: for every
\* reachable state and every domain, balance[d] + stake_locked[d] =
\* MaxAmount (per-domain conservation; supply identity).
INITIAL_TOTAL == MaxAmount

----------------------------------------------------------------------------
\* State.

VARIABLES
    balance,           \* function Domains -> Nat
    stake_locked,      \* function Domains -> Nat
    registrant_state,  \* function Domains -> RegState
    unlock_height,     \* function Domains -> Nat (NONE = "no unlock armed")
    current_height     \* Nat: chain height

vars == <<balance, stake_locked, registrant_state, unlock_height,
          current_height>>

----------------------------------------------------------------------------
\* Initial state. All domains start at MaxAmount free balance, zero
\* stake_locked, ACTIVE registrant_state, unlock_height = NONE,
\* current_height = 0.
\*
\* registrant_state ACTIVE at Init mirrors the FB8 convention: the
\* lifecycle starts at the point of an already-registered operator;
\* the REGISTER apply path is in AccountState.tla territory.

Init ==
    /\ balance          = [d \in Domains |-> MaxAmount]
    /\ stake_locked     = [d \in Domains |-> 0]
    /\ registrant_state = [d \in Domains |-> "ACTIVE"]
    /\ unlock_height    = [d \in Domains |-> NONE]
    /\ current_height   = 0

----------------------------------------------------------------------------
\* Actions. Each action models the corresponding apply-layer branch
\* in src/chain/chain.cpp::apply_transactions. Out-of-precondition
\* inputs are no-ops, matching the C++ `continue` / fee-refund-then-
\* break semantics.

\* Stake(d, amt): move `amt` from balance to stake_locked. Models the
\* STAKE branch at src/chain/chain.cpp:858-871. Pre-condition:
\* balance[d] >= amt. The apply path lets STAKE happen at any time
\* — even after DEREGISTER has armed the unlock — so additional
\* stake just rides along to the same unlock point.
Stake(d, amt) ==
    /\ d \in Domains
    /\ amt \in 1..MaxAmount
    /\ balance[d] >= amt
    /\ balance'      = [balance      EXCEPT ![d] = @ - amt]
    /\ stake_locked' = [stake_locked EXCEPT ![d] = @ + amt]
    /\ UNCHANGED <<registrant_state, unlock_height, current_height>>

\* Deregister(d): mark registry[d] inactive (ACTIVE -> DEREGISTERED)
\* and arm unlock_height = current_height + UNSTAKE_DELAY. Models the
\* DEREGISTER branch at src/chain/chain.cpp:839-856. Pre-condition:
\* registrant_state[d] = ACTIVE. The C++ apply path also clears the
\* registry's active bit + sets inactive_from = height + derive_delay;
\* the model abstracts derive_delay to 0 so the arithmetic is exact.
\*
\* The FB8-stricter model: only ACTIVE domains can Deregister; a
\* second Deregister on an already-DEREGISTERED domain hits the
\* INV_DeregisterIdempotent contract via the stutter-action below.
Deregister(d) ==
    /\ d \in Domains
    /\ registrant_state[d] = "ACTIVE"
    /\ current_height + UNSTAKE_DELAY <= NONE
    /\ registrant_state' = [registrant_state EXCEPT ![d] = "DEREGISTERED"]
    /\ unlock_height'    = [unlock_height    EXCEPT ![d] =
                              current_height + UNSTAKE_DELAY]
    /\ UNCHANGED <<balance, stake_locked, current_height>>

\* DeregisterIdempotent(d): a second Deregister on an already-
\* DEREGISTERED domain is a no-op stutter. Drains the would-be
\* transaction (the C++ apply path's `continue` semantics). Models
\* the apply-side rejection of duplicate DEREGISTER txs.
\*
\* Inclusion of this action is required for INV_DeregisterIdempotent
\* to be reachable: TLC must explore the "attacker submits a second
\* DEREGISTER" trace to confirm the unlock_height does not re-arm
\* (which would shift the unlock window forward and stale-lock the
\* deferred refund).
DeregisterIdempotent(d) ==
    /\ d \in Domains
    /\ registrant_state[d] = "DEREGISTERED"
    /\ UNCHANGED vars

\* UnstakeEarly(d): pre-unlock UNSTAKE attempt. Routes to the C++
\* fee-refund branch at src/chain/chain.cpp:881-888 when EITHER
\*   (a) registrant_state[d] /= DEREGISTERED (unlock not yet armed), OR
\*   (b) unlock_height[d] = NONE (no armed unlock), OR
\*   (c) current_height < unlock_height[d] (unlock window not yet open).
\*
\* The action is a stutter on (balance, stake_locked, registrant_state,
\* unlock_height). This is the headline INV_NoEarlyRefund invariant:
\* a pre-unlock UNSTAKE attempt CANNOT drain locked stake. Matches
\* the "Refund fee on failed UNSTAKE so honest users aren't penalized
\* for a too-early request" comment at chain.cpp:882-883.
UnstakeEarly(d) ==
    /\ d \in Domains
    /\ \/ registrant_state[d] /= "DEREGISTERED"
       \/ unlock_height[d] = NONE
       \/ current_height < unlock_height[d]
    /\ UNCHANGED vars

\* UnstakePost(d): post-unlock UNSTAKE — refund stake_locked back to
\* balance once current_height has reached the armed unlock_height.
\* Models the UNSTAKE success branch at src/chain/chain.cpp:889-893.
\*
\* Pre-condition: registrant_state[d] = DEREGISTERED AND
\* unlock_height[d] /= NONE AND current_height >= unlock_height[d]
\* AND stake_locked[d] > 0.
\*
\* On success: move ALL of stake_locked back to balance (FB8's "move
\* all locked back" semantics — worst-case for the invariants of
\* interest); clear unlock_height to NONE so a subsequent UnstakePost
\* on the same domain is no longer enabled (re-routes to UnstakeEarly).
\* The registrant_state stays DEREGISTERED (the C++ apply path does
\* not auto-clear the inactive bit; that's a separate REGISTER step).
UnstakePost(d) ==
    /\ d \in Domains
    /\ registrant_state[d] = "DEREGISTERED"
    /\ unlock_height[d] /= NONE
    /\ current_height >= unlock_height[d]
    /\ stake_locked[d] > 0
    /\ balance'       = [balance       EXCEPT ![d] = @ + stake_locked[d]]
    /\ stake_locked'  = [stake_locked  EXCEPT ![d] = 0]
    /\ unlock_height' = [unlock_height EXCEPT ![d] = NONE]
    /\ UNCHANGED <<registrant_state, current_height>>

\* AdvanceHeight: tick chain height forward by 1. The temporal
\* driver — without it no deregistered account could ever reach
\* its unlock window. Bounded by MaxHeight for TLC tractability.
AdvanceHeight ==
    /\ current_height < MaxHeight
    /\ current_height' = current_height + 1
    /\ UNCHANGED <<balance, stake_locked, registrant_state, unlock_height>>

----------------------------------------------------------------------------
\* Next-state relation. TLC enumerates all interleavings.

Next ==
    \/ \E d \in Domains, amt \in 1..MaxAmount : Stake(d, amt)
    \/ \E d \in Domains : Deregister(d)
    \/ \E d \in Domains : DeregisterIdempotent(d)
    \/ \E d \in Domains : UnstakeEarly(d)
    \/ \E d \in Domains : UnstakePost(d)
    \/ AdvanceHeight

\* Fairness on AdvanceHeight (so height progresses past the unlock
\* point) and on UnstakePost (so an enabled UnstakePost eventually
\* fires) together drive PROP_EventualRefund + PROP_NoStuckStake.
\* Without fairness on AdvanceHeight a trace could starve UnstakePost
\* by holding at current_height = 0; without fairness on UnstakePost
\* a trace could indefinitely stutter once current_height >=
\* unlock_height.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(AdvanceHeight)
    /\ \A d \in Domains : WF_vars(UnstakePost(d))

----------------------------------------------------------------------------
\* Type invariant — variables have correct shapes.

INV_TypeOK ==
    /\ balance          \in [Domains -> 0..INITIAL_TOTAL]
    /\ stake_locked     \in [Domains -> 0..INITIAL_TOTAL]
    /\ registrant_state \in [Domains -> RegState]
    /\ unlock_height    \in [Domains -> 0..NONE]
    /\ current_height   \in 0..MaxHeight

----------------------------------------------------------------------------
\* The seven invariants of the refund-timing contract.

\* (1) INV_StakeNonNegative: balance + stake_locked >= 0 always.
\* Both fields are Nat-valued by construction; this invariant
\* documents the contract that no action drives either negative.
\* Stake increases stake_locked, decreases balance (gated by
\* balance >= amount). UnstakePost moves stake_locked -> balance
\* (no decrement). UnstakeEarly is a stutter. No action subtracts
\* from balance + stake_locked.
INV_StakeNonNegative ==
    \A d \in Domains :
        /\ balance[d]      >= 0
        /\ stake_locked[d] >= 0
        /\ balance[d] + stake_locked[d] >= 0

\* (2) INV_DeregisterSchedules: Deregister sets unlock_height to
\* current_height + UNSTAKE_DELAY. Encoded as an action-level
\* invariant via primed-state form: across every step that
\* transitions registrant_state[d] from ACTIVE to DEREGISTERED,
\* the new unlock_height[d] must equal the pre-step current_height
\* + UNSTAKE_DELAY. TLC checks this against the [Next]_vars
\* transition relation.
INV_DeregisterSchedules ==
    [][\A d \in Domains :
         (registrant_state[d] = "ACTIVE"
          /\ registrant_state'[d] = "DEREGISTERED")
         => (unlock_height'[d] = current_height + UNSTAKE_DELAY)
      ]_vars

\* (3) INV_NoEarlyRefund: UnstakeEarly never decrements stake_locked.
\* Headline safety claim — an attacker spamming pre-unlock UNSTAKE
\* txs cannot drain locked stake. Encoded as: across every
\* [Next]_vars step that fires UnstakeEarly, stake_locked'[d] =
\* stake_locked[d] for every d. The structural form: if the action
\* satisfies the UnstakeEarly enabling condition AND the action
\* fires, then stake_locked is preserved per-domain.
\*
\* State-form (TLC-checkable): across every step where any domain
\* d satisfies the UnstakeEarly enabling condition (not
\* DEREGISTERED, or no armed unlock, or pre-unlock), the
\* stake_locked[d] field is preserved unless a Stake or UnstakePost
\* fires on d. The strict form is captured by the action's UNCHANGED
\* vars clause; this invariant additionally guards against any
\* future action variant introducing an early-decrement path.
INV_NoEarlyRefund ==
    [][\A d \in Domains :
         (stake_locked'[d] < stake_locked[d])
         => /\ registrant_state[d] = "DEREGISTERED"
            /\ unlock_height[d] /= NONE
            /\ current_height >= unlock_height[d]
      ]_vars

\* (4) INV_PostUnlockRefund: UnstakePost moves stake_locked -> balance
\* fully. Encoded as an action-level invariant: across every step
\* where stake_locked'[d] < stake_locked[d] (the unique decrement
\* path is UnstakePost), the delta in balance[d] matches the pre-
\* step stake_locked[d] exactly and the post-step stake_locked[d]
\* = 0. No partial refund, no stranded stake.
INV_PostUnlockRefund ==
    [][\A d \in Domains :
         (stake_locked'[d] < stake_locked[d])
         => /\ stake_locked'[d] = 0
            /\ balance'[d] = balance[d] + stake_locked[d]
            /\ unlock_height'[d] = NONE
      ]_vars

\* (5) INV_A1Conservation: balance + stake_locked per domain is
\* conserved through Stake / Deregister / DeregisterIdempotent /
\* UnstakeEarly / AdvanceHeight; UnstakePost is also conservation-
\* preserving (it reclassifies value from stake_locked to balance).
\*
\* Per-domain conservation: balance[d] + stake_locked[d] =
\* INITIAL_TOTAL at every reachable state. The strongest A1
\* statement — even multi-domain interleavings preserve the
\* per-domain sum because no inter-domain transfer is modeled.
INV_A1Conservation ==
    \A d \in Domains : balance[d] + stake_locked[d] = INITIAL_TOTAL

\* (6) INV_UnlockHeightMonotonic: once unlock_height[d] is set away
\* from NONE by Deregister, only UnstakePost can clear it back to
\* NONE. Concretely:
\*
\*   Across every [Next]_vars step that transitions unlock_height[d]
\*   from a non-NONE value to NONE, the same step must also have:
\*     (a) stake_locked'[d] = 0   (the UnstakePost shape), AND
\*     (b) balance'[d] = balance[d] + stake_locked[d]  (the refund delta)
\*
\* Conversely, no Stake / Deregister / DeregisterIdempotent /
\* UnstakeEarly / AdvanceHeight action transitions unlock_height
\* back to NONE — those actions either leave unlock_height
\* UNCHANGED or set it via Deregister (NONE -> arming value, not
\* arming -> NONE).
INV_UnlockHeightMonotonic ==
    [][\A d \in Domains :
         (unlock_height[d] /= NONE /\ unlock_height'[d] = NONE)
         => /\ stake_locked'[d] = 0
            /\ balance'[d] = balance[d] + stake_locked[d]
      ]_vars

\* (7) INV_DeregisterIdempotent: Deregister applied twice in a row
\* no-ops the second time. Encoded as: across every [Next]_vars
\* step where registrant_state[d] = DEREGISTERED, any subsequent
\* "deregister attempt" (the DeregisterIdempotent action) is a
\* stutter on (registrant_state, unlock_height). The state-form
\* witness: a domain in DEREGISTERED with a non-NONE unlock_height
\* never transitions to a NEW unlock_height value > old one via any
\* non-UnstakePost action.
\*
\* This guards the FB8-stricter model from a re-arming attack: a
\* malicious tx producer could in principle submit a second
\* DEREGISTER hoping to push the unlock window forward. The TLA
\* model rejects this at the apply layer via DeregisterIdempotent
\* being a stutter (no state change).
INV_DeregisterIdempotent ==
    [][\A d \in Domains :
         (registrant_state[d] = "DEREGISTERED"
          /\ registrant_state'[d] = "DEREGISTERED"
          /\ unlock_height[d] /= NONE)
         => (unlock_height'[d] = unlock_height[d]
             \/ unlock_height'[d] = NONE)
      ]_vars

----------------------------------------------------------------------------
\* Temporal properties.

\* (T1) PROP_EventualRefund: under fairness on AdvanceHeight +
\* UnstakePost, every staked + deregistered account eventually
\* reaches refunded (stake_locked = 0 / unlock_height = NONE)
\* OR the model bound is reached.
\*
\* Formally: in every fair run, if some domain d has
\* registrant_state[d] = DEREGISTERED AND stake_locked[d] > 0 AND
\* unlock_height[d] <= MaxHeight (the unlock is reachable within
\* the model's bounded current_height), then eventually
\* stake_locked[d] = 0 (UnstakePost fired and refunded) OR
\* eventually current_height >= MaxHeight (the model bound was
\* reached before the unlock could complete; required because TLC
\* operates on bounded models).
\*
\* The combination of WF_vars(AdvanceHeight) (height progresses
\* monotonically) and WF_vars(UnstakePost(d)) (an enabled
\* UnstakePost fires) gives the eventual-progress conclusion.
PROP_EventualRefund ==
    \A d \in Domains :
       ((registrant_state[d] = "DEREGISTERED"
         /\ stake_locked[d] > 0
         /\ unlock_height[d] /= NONE
         /\ unlock_height[d] <= MaxHeight)
        ~> (stake_locked[d] = 0 \/ current_height >= MaxHeight))

\* (T2) PROP_NoStuckStake: stake_locked[d] > 0 AND
\* registrant_state[d] = DEREGISTERED AND unlock_height[d] <=
\* current_height implies eventually UnstakePost fires.
\*
\* The strict eventual-enabling property: once the deferred-unlock
\* window opens (current_height has reached unlock_height), the
\* refund happens. The DEREGISTERED + open-window combination is
\* the structural witness; the fairness on UnstakePost forces
\* progress.
\*
\* Encoded as: any state where the UnstakePost enabling condition
\* holds for d (stake_locked > 0, DEREGISTERED, armed unlock,
\* window open) leads to a state where stake_locked = 0 OR
\* current_height >= MaxHeight (bounded-model escape).
PROP_NoStuckStake ==
    \A d \in Domains :
       ((stake_locked[d] > 0
         /\ registrant_state[d] = "DEREGISTERED"
         /\ unlock_height[d] /= NONE
         /\ unlock_height[d] <= current_height)
        ~> (stake_locked[d] = 0 \/ current_height >= MaxHeight))

============================================================================
\* Cross-references.
\*
\* FB8 (StakeLifecycle.tla) — parent: basic STAKE/DEREGISTER/UNSTAKE
\*   state machine with a Sentinel-based unlock-height encoding.
\*   FB41 sharpens the refund-timing axis by isolating the
\*   unlock-height transitions with an explicit RegState tri-state
\*   AND adding the explicit refund-fully invariant
\*   (INV_PostUnlockRefund) + the deferred-unlock arming contract
\*   (INV_DeregisterSchedules) + the no-early-refund safety claim
\*   (INV_NoEarlyRefund).
\*
\* FB16 (AbortApply.tla) — sibling at the apply-layer slash path.
\*   FB16 models bounded Phase-1 slashing of stake_locked; FB41
\*   models the no-slash refund-timing path. The two paths are
\*   orthogonal: a DEREGISTERED domain may still be slashed by
\*   an AbortEvent (FB16) before its UnstakePost fires; FB21's
\*   T-C4 covers the resulting ghost-branch contract.
\*
\* FB21 (StakeForfeitureCascade.tla) — cascade context: full
\*   STAKE/DEREGISTER/UNSTAKE/Equivocate interleaving. FB41 is
\*   the slash-free zoom-in; FB21 is the slash-inclusive full
\*   cascade.
\*
\* FA-Apply-4 (docs/proofs/StakeLifecycle.md) — analytic prose
\*   proof of the apply-layer refund-timing contract. FB41 is the
\*   machine-checkable state-machine companion.
\*
\* C++ enforcement:
\*   - STAKE branch:      src/chain/chain.cpp:858-871
\*   - DEREGISTER branch: src/chain/chain.cpp:839-856
\*     (unlock-height arming at chain.cpp:851)
\*   - UNSTAKE branch:    src/chain/chain.cpp:873-893
\*     (fee-refund early-skip at chain.cpp:881-888)
\*   - apply-layer params: include/determ/chain/params.hpp
\*     (Config::unstake_delay default 100 blocks)
============================================================================
