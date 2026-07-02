--------------------------- MODULE StakeLifecycle ---------------------------
(*
FB8 — TLA+ specification of the STAKE / DEREGISTER / UNSTAKE state
machine. Models the apply-layer lifecycle of an operator's stake from
free balance, through locked-while-registered, through deregister-armed
delayed unlock, back to free balance.

This spec captures the invariants of Determ's stake lifecycle at the
state-machine layer, independent of consensus and signature verification:

  * STAKE moves value from `balance` to `stake_locked`; it never mints
    and never destroys (A1 conservation across STAKE).
  * DEREGISTER arms the unlock by setting `inactive_from = height + 1`
    and `unlock_height = inactive_from + UnstakeDelay`. It is the ONLY
    action that mutates `unlock_height` away from the LockedSentinel
    (and once armed, the value never decreases — see Inv_UnlockMonotonic).
  * UNSTAKE is gated by `height >= unlock_height`; pre-unlock UNSTAKE
    attempts are no-ops (matching the fee-refund branch at
    src/chain/chain.cpp:881 — refund fee, do not move value). The
    Inv_NoEarlyUnstake invariant is the headline safety claim.
  * `registry[d].active = FALSE` implies `inactive_from /= Sentinel` —
    the apply path always sets the field together with clearing active.
  * Under fairness on AdvanceHeight + Unstake, a deregistered account
    eventually completes unstaking (Prop_EventualUnstake).
  * `stake_locked` only changes via the Stake or Unstake actions —
    Deregister and AdvanceHeight never touch the locked amount
    (Prop_StakeOrUnstakeOnly).

Modeling scope (kept tractable for TLC):

  * Single-shot lifecycle: an account that re-registers after a
    completed Unstake is out of scope. The model checks the worst-case
    one-way path (Register → Stake → Deregister → wait → Unstake).
  * `UnstakeDelay` is a small finite constant (3) — the real protocol
    uses a large governance-tunable delay. The state-machine properties
    are invariant in the delay value as long as it is a fixed Nat.
  * Fees are abstracted away — the C++ apply path charges a fee on
    every STAKE / DEREGISTER / UNSTAKE; failure refunds the fee. The
    TLA model treats fee accounting as orthogonal to the lifecycle.
  * Equivocation slashing is out of scope here — FA6 / FB1 territory.
    The Slash action in AccountState.tla covers that case.
  * Sentinel is a single concrete value strictly greater than
    MaxHeight; the C++ uses UINT64_MAX. Either value is correct as long
    as it cannot collide with any reachable `height` value.

Companion prose proof: docs/proofs/StakeLifecycle.md
(separately written by a parallel agent; may not yet exist in this
worktree).

To check (assuming TLC installed):
  $ tlc StakeLifecycle.tla -config StakeLifecycle.cfg
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Domains,            \* set of account / operator identifiers
    MaxHeight,          \* upper bound on chain height for TLC
    MaxBalance,         \* initial per-account balance for TLC
    UnstakeDelay,       \* fixed UNSTAKE lockup delay (e.g., 3)
    Sentinel            \* "no unstake armed" marker; > MaxHeight

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ MaxHeight    \in Nat /\ MaxHeight    >= 1
    /\ MaxBalance   \in Nat /\ MaxBalance   >= 1
    /\ UnstakeDelay \in Nat /\ UnstakeDelay >= 1
    /\ Sentinel     \in Nat /\ Sentinel     > MaxHeight + UnstakeDelay + 1

\* INITIAL_TOTAL is the conserved supply across all Stake / Unstake
\* moves. Used by Inv_A1Conservation below. Stake and Unstake are
\* internal balance <-> stake_locked redistributions; neither mints
\* nor destroys, so the sum is invariant.
INITIAL_TOTAL == MaxBalance * Cardinality(Domains)

----------------------------------------------------------------------------
\* State.

VARIABLES
    accounts,           \* function Domains -> [balance, stake_locked]
    registry,           \* function Domains -> [active, inactive_from]
    unlock_heights,     \* function Domains -> Nat (Sentinel = "not armed")
    height              \* current chain height

vars == <<accounts, registry, unlock_heights, height>>

----------------------------------------------------------------------------
\* Initial state. All accounts start at MaxBalance with zero stake.
\* registry[d].active = TRUE models "d is registered" (the spec's
\* lifecycle starts at the point of an already-registered operator;
\* the REGISTER apply path is in AccountState.tla territory). Note
\* that registry[d].active starts TRUE so that the Deregister action
\* is enabled at Init — without this, the only reachable behavior
\* would be Stake / Unstake-on-unarmed (which is a no-op). The active
\* field's purpose is to gate Deregister, not to model the REGISTER
\* lifecycle.
\*
\* unlock_heights[d] = Sentinel at Init means "no unstake armed" —
\* the standard apply-side convention encoded in C++ as UINT64_MAX
\* at src/chain/chain.cpp:139 / :811.

Init ==
    /\ accounts = [d \in Domains |->
                     [balance |-> MaxBalance, stake_locked |-> 0]]
    /\ registry = [d \in Domains |->
                     [active |-> TRUE, inactive_from |-> Sentinel]]
    /\ unlock_heights = [d \in Domains |-> Sentinel]
    /\ height = 0

----------------------------------------------------------------------------
\* Actions. Each action models the corresponding apply-layer branch in
\* src/chain/chain.cpp::apply_transactions. The actions are total
\* relations — out-of-precondition inputs are no-ops (matching the
\* C++ `continue` / fee-refund-then-break semantics).

\* Stake(d, amount): move `amount` from accounts[d].balance to
\* accounts[d].stake_locked. Models the STAKE branch at
\* src/chain/chain.cpp:858-871.
\*
\* Pre-condition: accounts[d].balance >= amount. The C++ also requires
\* amount + fee <= balance, but we abstract fees away here.
\*
\* Note: the apply path lets STAKE happen at any time — even after
\* DEREGISTER has armed the unlock. This is deliberate: an operator
\* can top up their slashing-bond mid-deregister-window. The unlock
\* gate fires on `height >= unlock_height`, not on stake balance,
\* so additional stake just rides along to the same unlock point.
\* The model permits the same: the only Stake guard is balance.
Stake(d, amount) ==
    /\ d \in Domains
    /\ amount \in 1..MaxBalance
    /\ accounts[d].balance >= amount
    /\ accounts' = [accounts EXCEPT
                      ![d] = [balance      |-> @.balance - amount,
                              stake_locked |-> @.stake_locked + amount]]
    /\ UNCHANGED <<registry, unlock_heights, height>>

\* Deregister(d): mark registry[d] inactive (active <- FALSE) and
\* arm the unlock_height. Models the DEREGISTER branch at
\* src/chain/chain.cpp:839-856.
\*
\* The C++ uses `inactive_from = height + derive_delay(...)`; the
\* derive_delay is a randomized small delay (typically 0..2). In
\* the model we use the smallest non-trivial delay `height + 1` so
\* that the unlock_height arithmetic is exact and the model size
\* stays small.
\*
\* unlock_height is set to inactive_from + UnstakeDelay. After this
\* point the operator's stake is locked until `height` reaches the
\* unlock_height — the Unstake action's guard. The C++ apply path
\* always sets BOTH fields together (active <- FALSE implies
\* inactive_from /= Sentinel) — this gives Inv_DeregisterImpliesActiveOff.
\*
\* Pre-condition: registry[d].active. A second Deregister on an
\* already-inactive registry is a no-op at the apply layer (in the
\* C++, the second DEREGISTER tx overwrites `inactive_from` and
\* `unlock_height` to height+UnstakeDelay+1, which could in principle
\* RE-arm a later unlock. The TLA model keeps this lifecycle one-shot
\* by requiring `active = TRUE` as a guard; this is the stricter
\* model and the one Inv_UnlockMonotonic captures).
Deregister(d) ==
    /\ d \in Domains
    /\ registry[d].active
    /\ height + 1 + UnstakeDelay <= Sentinel
    /\ LET inactive_from == height + 1 IN
       LET unlock_h     == inactive_from + UnstakeDelay IN
       /\ registry' = [registry EXCEPT
                         ![d] = [active        |-> FALSE,
                                 inactive_from |-> inactive_from]]
       /\ unlock_heights' = [unlock_heights EXCEPT ![d] = unlock_h]
       /\ UNCHANGED <<accounts, height>>

\* Unstake(d): refund stake_locked -> balance once height has reached
\* the armed unlock_height. Models the UNSTAKE branch at
\* src/chain/chain.cpp:873-894.
\*
\* Pre-condition: unlock_heights[d] /= Sentinel /\ height >= unlock_heights[d]
\* /\ accounts[d].stake_locked > 0.
\*
\* On success: move all of stake_locked back to balance; clear the
\* armed unlock (unlock_heights[d] <- Sentinel) so a subsequent
\* Unstake on the same domain is a no-op. The C++ apply path
\* implements `sit->second.locked -= amount` for an amount drawn
\* from the tx payload; in the model we collapse this to a single
\* `move all locked back` step, which is the worst-case for the
\* invariants of interest.
\*
\* No early Unstake: the guard `height >= unlock_heights[d]` is the
\* enforcement point. Inv_NoEarlyUnstake is the structural invariant
\* that this guard, together with the (height >= 0)-monotonicity of
\* height under AdvanceHeight, gives the eventual-progress property
\* (Prop_EventualUnstake).
Unstake(d) ==
    /\ d \in Domains
    /\ unlock_heights[d] /= Sentinel
    /\ height >= unlock_heights[d]
    /\ accounts[d].stake_locked > 0
    /\ accounts' = [accounts EXCEPT
                      ![d] = [balance      |-> @.balance + @.stake_locked,
                              stake_locked |-> 0]]
    /\ unlock_heights' = [unlock_heights EXCEPT ![d] = Sentinel]
    /\ UNCHANGED <<registry, height>>

\* UnstakeFailEarly(d): models the "pre-unlock UNSTAKE attempt" case
\* at src/chain/chain.cpp:881-888. The C++ refunds the fee and does
\* NOT touch stake_locked or balance (modulo fee accounting, which
\* the TLA model abstracts away). This action is a stutter on the
\* lifecycle variables.
\*
\* Inclusion of this action is important for two reasons:
\*   (1) It witnesses Inv_NoEarlyUnstake: any pre-unlock attempt
\*       cannot mutate accounts or unlock_heights, which TLC checks
\*       against the (vars'-vars) delta.
\*   (2) It explores the "attacker tries to unstake early" trace,
\*       confirming that the apply path never opens an early-exit
\*       door.
UnstakeFailEarly(d) ==
    /\ d \in Domains
    /\ unlock_heights[d] /= Sentinel
    /\ height < unlock_heights[d]
    /\ UNCHANGED vars

\* AdvanceHeight: tick the block index forward by 1. This is the
\* temporal driver — without it, no Deregister state can ever
\* reach the unlock point and Unstake never enables.
AdvanceHeight ==
    /\ height < MaxHeight
    /\ height' = height + 1
    /\ UNCHANGED <<accounts, registry, unlock_heights>>

----------------------------------------------------------------------------
\* Next-state relation. Any of the lifecycle actions plus the temporal
\* driver may fire at any enabled state; TLC enumerates all interleavings.

Next ==
    \/ \E d \in Domains, amount \in 1..MaxBalance : Stake(d, amount)
    \/ \E d \in Domains : Deregister(d)
    \/ \E d \in Domains : Unstake(d)
    \/ \E d \in Domains : UnstakeFailEarly(d)
    \/ AdvanceHeight

\* Fairness on AdvanceHeight (to make sure height progresses past the
\* unlock point) and on Unstake (so that an enabled Unstake eventually
\* fires) together drive Prop_EventualUnstake. Without fairness on
\* AdvanceHeight a trace could starve Unstake by holding at height = 0;
\* without fairness on Unstake a trace could indefinitely stutter once
\* height >= unlock_height.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(AdvanceHeight)
    /\ \A d \in Domains : WF_vars(Unstake(d))

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant: variables have correct shapes.
Inv_TypeOK ==
    /\ accounts \in [Domains -> [balance: 0..INITIAL_TOTAL,
                                 stake_locked: 0..INITIAL_TOTAL]]
    /\ registry \in [Domains -> [active: BOOLEAN,
                                 inactive_from: 0..Sentinel]]
    /\ unlock_heights \in [Domains -> 0..Sentinel]
    /\ height \in 0..MaxHeight

\* Stake non-negativity (Nat-valued; documents the contract).
\* The Unstake action moves stake_locked to 0 (not negative) and the
\* Stake action only adds; no action subtracts more than the current
\* stake_locked. Hence the field is always >= 0.
Inv_StakeNonNegative ==
    \A d \in Domains : accounts[d].stake_locked >= 0

\* Balance non-negativity (Nat-valued; documents the contract).
\* The Stake action's `accounts[d].balance >= amount` guard ensures
\* the post-state balance stays in Nat. No other action decrements
\* balance.
Inv_BalanceNonNegative ==
    \A d \in Domains : accounts[d].balance >= 0

\* A1 Conservation (Stake / Unstake invariance):
\*
\*   sum(balance) + sum(stake_locked) = INITIAL_TOTAL
\*
\* Every Stake action moves `amount` from balance to stake_locked,
\* preserving the sum. Every Unstake action moves stake_locked back
\* to balance, also preserving the sum. Deregister and AdvanceHeight
\* and UnstakeFailEarly do not mutate accounts at all.
\*
\* Together with Inv_StakeNonNegative + Inv_BalanceNonNegative, this
\* is the headline A1 supply-conservation claim for the stake
\* lifecycle.
SumBalances ==
    LET RECURSIVE sum_bal(_)
        sum_bal(S) ==
        IF S = {} THEN 0
        ELSE LET d == CHOOSE x \in S : TRUE IN
             accounts[d].balance + sum_bal(S \ {d})
    IN sum_bal(Domains)

SumStakes ==
    LET RECURSIVE sum_stk(_)
        sum_stk(S) ==
        IF S = {} THEN 0
        ELSE LET d == CHOOSE x \in S : TRUE IN
             accounts[d].stake_locked + sum_stk(S \ {d})
    IN sum_stk(Domains)

Inv_A1Conservation == SumBalances + SumStakes = INITIAL_TOTAL

\* UnlockMonotonic: once unlock_heights[d] is set away from the
\* Sentinel by a Deregister, it never DECREASES across any step.
\* The ARMING step itself (Sentinel -> height+1+UnstakeDelay) is a
\* decrease under the Sentinel-is-largest encoding, so the property
\* guards on the pre-state being armed (/= Sentinel) — the formula
\* for the prose contract "once armed, the value never decreases".
\*
\* The C++ apply path arms unlock_height in DEREGISTER and clears
\* it to UINT64_MAX (the Sentinel equivalent) in UNSTAKE. The TLA
\* model uses the same "clear to Sentinel on Unstake" semantics; we
\* treat the Sentinel as the largest possible value (Sentinel >
\* MaxHeight + UnstakeDelay + 1 by ConfigOK) so that the clear-to-
\* Sentinel transition is also monotone non-decreasing.
\*
\* Expressed as an action invariant via primed-state form; TLC
\* checks against the [Next]_vars transition relation.
Inv_UnlockMonotonic ==
    [][\A d \in Domains :
         (unlock_heights[d] /= Sentinel)
         => unlock_heights'[d] >= unlock_heights[d]]_vars

\* DeregisterImpliesActiveOff: any domain whose active bit is FALSE
\* has a non-Sentinel inactive_from. The Deregister action sets both
\* fields together, and no other action touches `active` — so the
\* implication holds at every reachable state.
\*
\* This is the structural witness that the apply path always pairs
\* the two registry fields, matching the C++ requirement that the
\* CLI / RPC inspectors never see a "inactive but inactive_from is
\* Sentinel" combination (which would mean "permanently inactive,
\* no unstake ever").
Inv_DeregisterImpliesActiveOff ==
    \A d \in Domains :
       (registry[d].active = FALSE) => (registry[d].inactive_from /= Sentinel)

\* NoEarlyUnstake: no Unstake action ever succeeds at a state where
\* height < unlock_heights[d]. This is the headline safety claim of
\* the spec — an attacker cannot drain locked stake before the
\* protocol-prescribed delay has elapsed.
\*
\* State form: every domain whose stake has been moved back to balance
\* since the last Unstake either (a) had unlock_heights[d] /= Sentinel
\* AND height >= that value at the moment of the move, or (b) the
\* domain never had stake to begin with (vacuous case). We express
\* the action-level form: if accounts'[d].stake_locked < accounts[d].stake_locked,
\* then the previous-state unlock_heights[d] /= Sentinel and height
\* satisfies height >= unlock_heights[d].
Inv_NoEarlyUnstake ==
    [][\A d \in Domains :
         (accounts'[d].stake_locked < accounts[d].stake_locked)
         => /\ unlock_heights[d] /= Sentinel
            /\ height >= unlock_heights[d]
      ]_vars

\* StakeOnlyChangesViaStakeOrUnstake (action level): the only actions
\* that mutate accounts[d].stake_locked are Stake and Unstake. Encoded
\* as the contrapositive: if stake_locked'[d] /= stake_locked[d], the
\* delta is consistent with either a Stake (balance decreases, stake
\* increases by same amount) or an Unstake (balance increases by
\* stake_locked, stake_locked goes to 0).
Inv_StakeChangeOnlyViaStakeOrUnstake ==
    [][\A d \in Domains :
         (accounts'[d].stake_locked /= accounts[d].stake_locked)
         =>
         \/ \* Stake: stake increases, balance decreases by same delta
            /\ accounts'[d].stake_locked > accounts[d].stake_locked
            /\ accounts'[d].balance + accounts'[d].stake_locked
               = accounts[d].balance + accounts[d].stake_locked
         \/ \* Unstake: stake goes to zero, balance gains the amount
            /\ accounts'[d].stake_locked = 0
            /\ accounts'[d].balance
               = accounts[d].balance + accounts[d].stake_locked
      ]_vars

----------------------------------------------------------------------------
\* Temporal properties.

\* EventualUnstake: under fairness on AdvanceHeight + Unstake, a
\* deregistered account with stake_locked > 0 eventually completes
\* unstaking. This is the eventual-progress / no-stuck-stake
\* guarantee for honest operators.
\*
\* Formally: in every fair run, if some domain d has
\* unlock_heights[d] /= Sentinel AND accounts[d].stake_locked > 0,
\* then either eventually accounts[d].stake_locked = 0 (Unstake
\* fired) OR eventually height >= MaxHeight (the model bound was
\* reached before the unlock could complete; this escape is
\* required because TLC operates on bounded models).
\*
\* The combination of WF_vars(AdvanceHeight) (height progresses)
\* and WF_vars(Unstake(d)) (an enabled Unstake fires) gives the
\* eventual-progress conclusion.
Prop_EventualUnstake ==
    \A d \in Domains :
       ((unlock_heights[d] /= Sentinel
         /\ accounts[d].stake_locked > 0
         /\ unlock_heights[d] <= MaxHeight)
        ~> (accounts[d].stake_locked = 0 \/ height >= MaxHeight))

\* StakeOrUnstakeOnly (temporal): the temporal restatement of
\* Inv_StakeChangeOnlyViaStakeOrUnstake. Across every [Next]_vars
\* step, accounts[d].stake_locked changes only when the step is a
\* Stake or Unstake. Deregister, UnstakeFailEarly, and AdvanceHeight
\* MUST preserve stake_locked.
\*
\* TLC checks this as a [][...]_vars conjunction: at every step,
\* if stake_locked'[d] /= stake_locked[d], the (balance, stake_locked)
\* delta is consistent with one of the two value-moving actions.
\* Equivalent to Inv_StakeChangeOnlyViaStakeOrUnstake checked over
\* every reachable transition.
Prop_StakeOrUnstakeOnly ==
    [][\A d \in Domains :
         (accounts'[d].stake_locked /= accounts[d].stake_locked)
         =>
         \/ \* Stake-shape delta
            /\ accounts'[d].stake_locked > accounts[d].stake_locked
            /\ accounts'[d].balance + accounts'[d].stake_locked
               = accounts[d].balance + accounts[d].stake_locked
         \/ \* Unstake-shape delta
            /\ accounts'[d].stake_locked = 0
            /\ accounts'[d].balance
               = accounts[d].balance + accounts[d].stake_locked
      ]_vars

============================================================================
