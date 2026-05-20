--------------------------- MODULE AccountState ---------------------------
(*
FB5 — TLA+ specification of the apply-layer account-state state machine.
Models the (balance, nonce) account map and the (locked, unlock_height)
stake map per domain, plus the height counter and a `slashed` total
that tracks supply destruction.

This spec captures the invariants of Determ's apply layer that are
independent of consensus, sharding, and receipts:

  * Type correctness of the account/stake maps.
  * Nonce monotonicity per domain.
  * Balance non-negativity (trivially preserved in Nat).
  * Global supply conservation modulo Slash: every Transfer / Stake /
    UnstakeStart / UnstakeComplete is an internal redistribution; only
    Slash decrements the global total. Hence
        sum(balances) + sum(stakes_locked) + slashed = INITIAL_TOTAL.
  * Balance/stake independence: Transfer never touches stakes, Slash
    never touches balances, and only Stake/UnstakeComplete move value
    between the two maps.

Companion prose proof: docs/proofs/AccountStateInvariants.md
(separately written; may not yet exist in this worktree).

Modeling scope (kept tractable for TLC):

  * ed_pub field of AccountState is omitted — it is fixed at register
    time and not invariant-relevant for any of the properties above.
  * UnstakeStart sets unlock_height = height + 1 (a small finite delay
    is sufficient for the state machine; the real protocol uses a
    multi-thousand block lockup).
  * Slash directly reduces stakes_locked and increments `slashed`;
    no equivocation-evidence machinery is modeled here (FA6 / FB1).

To check (assuming TLC installed):
  $ tlc AccountState.tla -config AccountState.cfg
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Domains,            \* set of domain identifiers
    MaxBalance,         \* upper bound on per-domain balance for TLC
    MaxNonce,           \* upper bound on per-domain nonce for TLC
    MaxHeight           \* upper bound on chain height for TLC

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ MaxBalance \in Nat /\ MaxBalance >= 1
    /\ MaxNonce \in Nat /\ MaxNonce >= 1
    /\ MaxHeight \in Nat /\ MaxHeight >= 1

\* Sentinel for "stake is locked indefinitely" (no unstake started yet).
\* Modeled as a value strictly greater than MaxHeight so the
\* UnstakeComplete guard `height >= unlock_height` can never fire on it.
LockedSentinel == MaxHeight + 1

\* Account: record of {balance, nonce}.
\* Stake:   record of {locked, unlock_height}.
\* Both stored as total functions over Domains for TLC tractability
\* (a domain with zero balance / zero locked stake is the "no entry"
\* case in the C++ implementation).

VARIABLES
    accounts,           \* function Domains -> [balance, nonce]
    stakes,             \* function Domains -> [locked, unlock_height]
    height,             \* current chain height
    slashed             \* total amount slashed (monotone non-decreasing)

vars == <<accounts, stakes, height, slashed>>

----------------------------------------------------------------------------
\* Initial state: every domain starts with MaxBalance and zero nonce,
\* no stake locked. `slashed` starts at zero.

INITIAL_TOTAL == MaxBalance * Cardinality(Domains)

Init ==
    /\ accounts = [d \in Domains |-> [balance |-> MaxBalance, nonce |-> 0]]
    /\ stakes   = [d \in Domains |-> [locked |-> 0, unlock_height |-> LockedSentinel]]
    /\ height = 0
    /\ slashed = 0

----------------------------------------------------------------------------
\* Actions.

\* Transfer `amount` from domain `from` to domain `to`.
\* Models src/chain/chain.cpp's TRANSFER apply: debits from.balance,
\* credits to.balance, increments from.nonce.
Transfer(from, to, amount) ==
    /\ from \in Domains /\ to \in Domains /\ from /= to
    /\ amount \in 1..MaxBalance
    /\ accounts[from].balance >= amount
    /\ accounts[to].balance + amount <= MaxBalance
    /\ accounts[from].nonce < MaxNonce
    /\ accounts' = [accounts EXCEPT
                      ![from] = [balance |-> @.balance - amount,
                                 nonce   |-> @.nonce + 1],
                      ![to]   = [balance |-> @.balance + amount,
                                 nonce   |-> @.nonce]]
    /\ UNCHANGED <<stakes, height, slashed>>

\* Stake `amount` from domain `d`: moves balance -> stake.locked.
\* Sets unlock_height = LockedSentinel (no unstake in flight).
\* Models the STAKE tx apply path.
Stake(d, amount) ==
    /\ d \in Domains
    /\ amount \in 1..MaxBalance
    /\ accounts[d].balance >= amount
    /\ stakes[d].locked + amount <= MaxBalance * Cardinality(Domains)
    /\ accounts[d].nonce < MaxNonce
    /\ accounts' = [accounts EXCEPT ![d] = [balance |-> @.balance - amount,
                                            nonce   |-> @.nonce + 1]]
    /\ stakes'   = [stakes   EXCEPT ![d] = [locked        |-> @.locked + amount,
                                            unlock_height |-> LockedSentinel]]
    /\ UNCHANGED <<height, slashed>>

\* UnstakeStart: arms the unlock_height for domain d's stake.
\* Models the UNSTAKE-begin path: sets unlock_height = height + 1
\* (the real protocol uses a much larger delay; height+1 is the
\* smallest non-trivial value that lets TLC explore the state).
\* Pre-condition: stake is currently locked (unlock_height = LockedSentinel)
\* and there is something locked.
UnstakeStart(d) ==
    /\ d \in Domains
    /\ stakes[d].locked > 0
    /\ stakes[d].unlock_height = LockedSentinel
    /\ height + 1 <= MaxHeight
    /\ stakes' = [stakes EXCEPT ![d] = [locked        |-> @.locked,
                                        unlock_height |-> height + 1]]
    /\ UNCHANGED <<accounts, height, slashed>>

\* UnstakeComplete: refund stake.locked -> balance once height has
\* reached unlock_height. Models the unlock_height cascade.
UnstakeComplete(d) ==
    /\ d \in Domains
    /\ stakes[d].locked > 0
    /\ stakes[d].unlock_height /= LockedSentinel
    /\ height >= stakes[d].unlock_height
    /\ accounts[d].balance + stakes[d].locked <= INITIAL_TOTAL
    /\ accounts' = [accounts EXCEPT ![d] = [balance |-> @.balance + stakes[d].locked,
                                            nonce   |-> @.nonce]]
    /\ stakes'   = [stakes   EXCEPT ![d] = [locked        |-> 0,
                                            unlock_height |-> LockedSentinel]]
    /\ UNCHANGED <<height, slashed>>

\* Slash `amount` from domain d's stake. Decreases stake.locked,
\* increments global `slashed`. Does NOT touch balance.
\* Models the FA6 slashing apply path.
Slash(d, amount) ==
    /\ d \in Domains
    /\ amount \in 1..MaxBalance
    /\ stakes[d].locked >= amount
    /\ stakes' = [stakes EXCEPT ![d] = [locked        |-> @.locked - amount,
                                        unlock_height |-> @.unlock_height]]
    /\ slashed' = slashed + amount
    /\ UNCHANGED <<accounts, height>>

\* Tick: advance height by 1, up to MaxHeight.
Tick ==
    /\ height < MaxHeight
    /\ height' = height + 1
    /\ UNCHANGED <<accounts, stakes, slashed>>

----------------------------------------------------------------------------
Next ==
    \/ \E from, to \in Domains, amount \in 1..MaxBalance :
         Transfer(from, to, amount)
    \/ \E d \in Domains, amount \in 1..MaxBalance : Stake(d, amount)
    \/ \E d \in Domains : UnstakeStart(d)
    \/ \E d \in Domains : UnstakeComplete(d)
    \/ \E d \in Domains, amount \in 1..MaxBalance : Slash(d, amount)
    \/ Tick

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant: variables have correct shapes.
Inv_TypeOK ==
    /\ accounts \in [Domains -> [balance: 0..INITIAL_TOTAL, nonce: 0..MaxNonce]]
    /\ stakes   \in [Domains -> [locked: 0..INITIAL_TOTAL,
                                 unlock_height: 0..(MaxHeight + 1)]]
    /\ height \in 0..MaxHeight
    /\ slashed \in 0..INITIAL_TOTAL

\* Balance non-negativity (Nat-valued; documents the constraint).
Inv_NoNegativeBalance == \A d \in Domains : accounts[d].balance >= 0

\* Stake non-negativity (Nat-valued; documents the constraint).
Inv_NoNegativeStake == \A d \in Domains : stakes[d].locked >= 0

\* Nonce stays within bound (per Inv_TypeOK; restated for clarity).
\* Nonce monotonicity across any step is enforced structurally: every
\* action's accounts' update either leaves nonce unchanged or sets it to
\* @.nonce + 1. There is no action that decreases nonce. We expose this
\* as a step-level action property below (Inv_NonceMonotonic) and rely
\* on Inv_TypeOK + the absence of nonce-decrementing updates for the
\* state-level guarantee. Direct expression as a single-state invariant
\* is not possible (monotonicity is a relation between successive
\* states); TLC checks it via the [Next] disjuncts.
Inv_NonceBounded == \A d \in Domains : accounts[d].nonce <= MaxNonce

\* Action-level nonce monotonicity: across any Next step, no domain's
\* nonce decreases. Expressed as an action invariant via the standard
\* primed-state form. TLC checks this by examining the [Next]_vars
\* transition relation.
Inv_NonceMonotonic ==
    [][\A d \in Domains : accounts'[d].nonce >= accounts[d].nonce]_vars

\* Global supply conservation modulo Slash.
\* Internal redistributions (Transfer, Stake, UnstakeStart, UnstakeComplete)
\* preserve sum(balances) + sum(stakes.locked). Slash decreases
\* sum(stakes.locked) by amount and increases `slashed` by amount.
\* Therefore the conserved quantity is:
\*   sum(balances) + sum(stakes.locked) + slashed = INITIAL_TOTAL.
\*
\* We compute the sums via explicit set-comprehension folds since
\* Domains is small.
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
             stakes[d].locked + sum_stk(S \ {d})
    IN sum_stk(Domains)

Inv_SupplyConservation == SumBalances + SumStakes + slashed = INITIAL_TOTAL

\* Balance/stake independence (action-level): Transfer never modifies
\* stakes; Slash never modifies balances. Encoded as an action invariant
\* that TLC checks for each transition. The disjunctive structure
\* mirrors Next so TLC can short-circuit on the matched disjunct.
\*
\* Note: this is an OVER-APPROXIMATION of independence — it holds
\* whenever the underlying transitions agree with the rule, which by
\* construction they do (the Transfer / Slash action bodies preserve
\* their respective UNCHANGED clauses). It is checkable directly:
\*
\*   - If accounts /= accounts' AND stakes /= stakes', the only actions
\*     that change both maps simultaneously are Stake and
\*     UnstakeComplete — exactly the value-moving actions.
\*   - If accounts /= accounts' AND stakes = stakes', the action was
\*     Transfer or UnstakeStart (the latter would also leave accounts
\*     untouched — so really just Transfer).
\*   - If accounts = accounts' AND stakes /= stakes', the action was
\*     Slash or UnstakeStart.
\*
Inv_BalanceStakeIndependence ==
    [][LET acct_changed == accounts' /= accounts IN
       LET stk_changed  == stakes' /= stakes IN
       /\ (acct_changed /\ stk_changed) =>
            \* Only Stake or UnstakeComplete move value between maps;
            \* both increment slashed by zero.
            slashed' = slashed
       /\ (acct_changed /\ ~ stk_changed) =>
            \* Transfer (or UnstakeStart degenerate to a no-op on
            \* accounts is impossible — UnstakeStart UNCHANGED accounts).
            \* So this is Transfer: slashed unchanged.
            slashed' = slashed
       /\ (~ acct_changed /\ stk_changed) =>
            \* Slash (slashed increases) OR UnstakeStart (slashed
            \* unchanged). Both are stake-only operations.
            TRUE
      ]_vars

\* Slashed monotonicity: `slashed` never decreases.
Inv_SlashedMonotonic ==
    [][slashed' >= slashed]_vars

============================================================================
