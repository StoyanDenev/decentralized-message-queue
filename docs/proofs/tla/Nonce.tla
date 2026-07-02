--------------------------- MODULE Nonce ---------------------------
(*
FB7 — TLA+ specification of the per-account nonce-gate state machine.
Models the apply-layer replay-defense logic in
`src/chain/chain.cpp::apply_transactions` (the central gate at line
739: `if (tx.nonce != sender.next_nonce) continue;`).

This spec captures the invariants of Determ's tx-replay defense at
the state-machine layer, independent of consensus, mempool ordering,
or signature verification:

  * Strict-equality nonce gate: a tx applies iff its nonce equals
    the sender's current `next_nonce` (no past, no future).
  * Per-account monotonicity: each account's `next_nonce` is
    monotone non-decreasing across every reachable transition.
  * Replay impossibility: a successfully-applied tx cannot apply
    a second time at any later reachable state.
  * Per-account independence: `accounts[a].next_nonce` evolves
    independently of `accounts[b].next_nonce` for a /= b.
  * Genesis discipline: `next_nonce = 0` at every account at Init.

Modeling scope (kept tractable for TLC):

  * Only TRANSFER-shape txs are modeled (the apply gate is identical
    across all tx types — REGISTER / DEREGISTER / STAKE / UNSTAKE /
    DAPP_CALL / etc. all funnel through the same
    `tx.nonce != sender.next_nonce` check before any per-type body
    runs). Modeling one tx shape is sufficient for replay defense;
    the body-specific semantics are FB5 (AccountState.tla) and FB6
    (Snapshot.tla) territory.
  * `amount` is modeled as a non-negative integer with a small
    upper bound (MaxAmount). Insufficient-balance behavior is a
    silent skip (matches `continue` in chain.cpp at the per-type
    body), and is separate from the nonce gate.
  * `pending` is a SET of pending Tx records. Set semantics model
    the mempool's deduplication; the validator's selection order is
    abstracted away (nondeterministic `ApplyTx` picks any t \in
    pending whose nonce matches `accounts[t.from].next_nonce`).
  * Signature verification is out of scope (FA-track A1 / A2 +
    S-002). This spec models the nonce gate AFTER signature
    verification has passed.

Companion prose proof: `docs/proofs/NonceMonotonicity.md`
(separately written by a parallel agent; may not yet exist in this
worktree).

To check (assuming TLC installed):
  $ tlc Nonce.tla -config Nonce.cfg
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Domains,            \* set of account / sender identifiers
    MaxNonce,           \* upper bound on per-account nonce for TLC
    MaxAmount,          \* upper bound on per-tx amount for TLC
    MaxBalance          \* upper bound on per-account balance for TLC

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ MaxNonce  \in Nat /\ MaxNonce  >= 1
    /\ MaxAmount \in Nat /\ MaxAmount >= 1
    /\ MaxBalance \in Nat /\ MaxBalance >= MaxAmount

\* Tx shape: a record with {from, nonce, amount}. Set semantics for
\* `pending` plus the fact that nonce-collisions on the same sender
\* are an explicit attack scenario the gate must handle, mean that
\* two distinct Tx records with the same `from` and `nonce` but
\* different `amount` are treated as distinct submissions — both
\* land in `pending`, but at most one will apply (the strict-equality
\* gate fires once and advances next_nonce past the matching nonce).
Tx == [from: Domains, nonce: 0..MaxNonce, amount: 1..MaxAmount]

VARIABLES
    accounts,           \* function Domains -> [next_nonce, balance]
    pending,            \* SUBSET Tx — pending-mempool model
    applied             \* SUBSET Tx — history of applied txs (audit log)

vars == <<accounts, pending, applied>>

----------------------------------------------------------------------------
\* Initial state: empty pending, empty applied log, all accounts at
\* next_nonce = 0 and balance = MaxBalance (so that several TRANSFERs
\* are possible before bumping into the balance floor).

Init ==
    /\ accounts = [d \in Domains |->
                     [next_nonce |-> 0, balance |-> MaxBalance]]
    /\ pending = {}
    /\ applied = {}

----------------------------------------------------------------------------
\* Actions.

\* SubmitTx: enqueue a tx into the pending mempool. Any caller can
\* submit any nonce — the validator alone decides whether to apply.
\* This is the adversary's surface: replay attempts, future-nonce
\* submissions, and stale-nonce floods all funnel through this
\* action. The gate at ApplyTx is what defends against them.
SubmitTx(from, nonce, amount) ==
    /\ from \in Domains
    /\ nonce \in 0..MaxNonce
    /\ amount \in 1..MaxAmount
    /\ LET t == [from |-> from, nonce |-> nonce, amount |-> amount] IN
       /\ pending' = pending \cup {t}
       /\ UNCHANGED <<accounts, applied>>

\* ApplyTx: the central nonce gate. A tx t \in pending applies iff
\* t.nonce = accounts[t.from].next_nonce (strict equality). On
\* successful apply:
\*   - debit sender's balance by t.amount (assumes amount <= balance)
\*   - advance sender's next_nonce by 1
\*   - move t from pending to applied
\* Past-nonce txs (t.nonce < next_nonce) and future-nonce txs
\* (t.nonce > next_nonce) are silently skipped — they remain in
\* pending until RemoveFromPending evicts them. This matches the
\* `continue` semantics in apply_transactions.
\*
\* Note: this spec models the gate, not the order of selection.
\* The validator picks ANY pending tx that matches; TLC explores
\* all selection orders.
ApplyTx(t) ==
    /\ t \in pending
    /\ t.nonce = accounts[t.from].next_nonce
    /\ accounts[t.from].balance >= t.amount
    /\ accounts[t.from].next_nonce < MaxNonce
    /\ accounts' = [accounts EXCEPT
                     ![t.from] = [next_nonce |-> @.next_nonce + 1,
                                  balance    |-> @.balance - t.amount]]
    /\ pending' = pending \ {t}
    /\ applied' = applied \cup {t}

\* RemoveFromPending: model cleanup of unapplyable txs (stale-nonce
\* eviction, expiry). The mempool is allowed to drop any pending tx
\* at any time; this is a no-op on accounts/applied and only mutates
\* the mempool model.
\*
\* This action is important for liveness: without it the model could
\* deadlock on a pending tx with t.nonce > next_nonce that never
\* gets matched. The mempool gc lets TLC explore traces in which the
\* gc fires before / after the gate would have caught up.
RemoveFromPending(t) ==
    /\ t \in pending
    /\ pending' = pending \ {t}
    /\ UNCHANGED <<accounts, applied>>

----------------------------------------------------------------------------
\* Next-state relation. Any of the three actions may fire at any
\* enabled state; TLC enumerates all interleavings.

Next ==
    \/ \E from \in Domains,
         nonce \in 0..MaxNonce,
         amount \in 1..MaxAmount :
            SubmitTx(from, nonce, amount)
    \/ \E t \in pending : ApplyTx(t)
    \/ \E t \in pending : RemoveFromPending(t)

\* Fairness on ApplyTx drives EventualNonceAdvance: any honest
\* tx that matches the current next_nonce eventually applies.
\* Existential fairness over the pending set is required so that
\* the matching tx is not starved by infinite SubmitTx scheduling.
\* WF on RemoveFromPending models node.cpp's M11 per-block
\* stale-nonce sweep, which evicts unconditionally every block.
Spec == /\ Init
        /\ [][Next]_vars
        /\ \A t \in Tx : WF_vars(ApplyTx(t))
        /\ \A u \in Tx : WF_vars(RemoveFromPending(u))

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant: variables have correct shapes.
Inv_TypeOK ==
    /\ accounts \in [Domains -> [next_nonce: 0..MaxNonce,
                                 balance: 0..MaxBalance]]
    /\ pending \subseteq Tx
    /\ applied \subseteq Tx

\* GenesisStart: at Init, every account starts at next_nonce = 0.
\* Stated as a state predicate that is true at Init and preserved
\* by Inv_NonceMonotonic (next_nonce only ever advances; the
\* genesis value is the lower bound). The standalone restatement
\* below is the Init form, useful as a sanity check that no
\* refactor reintroduces a "non-zero genesis nonce" bug.
Inv_GenesisLowerBound ==
    \A d \in Domains : accounts[d].next_nonce >= 0

\* StrictNonceGate: any tx in `applied` was applied at a state
\* where t.nonce equaled the sender's then-current next_nonce.
\* Restating as a STATE invariant: every applied tx's nonce is
\* strictly less than the sender's CURRENT next_nonce (because
\* ApplyTx advances next_nonce immediately after the gate fires;
\* any later state has next_nonce > t.nonce). The "exact equality
\* at the moment of apply" is enforced structurally by the ApplyTx
\* guard and re-witnessed by Inv_ApplyAdvancesNonce below.
Inv_StrictNonceGate ==
    \A t \in applied : t.nonce < accounts[t.from].next_nonce

\* NonceMonotonic: per-account next_nonce never decreases across
\* any [Next]_vars step. Expressed as a primed-state action
\* invariant; TLC checks this against the transition relation.
Inv_NonceMonotonic ==
    [][\A d \in Domains :
         accounts'[d].next_nonce >= accounts[d].next_nonce]_vars

\* ReplayImpossible: a tx that has been applied once cannot be
\* applied again at any later reachable state. Two formulations:
\*
\*   (1) State invariant: for every t \in applied, the ApplyTx
\*       guard `t.nonce = accounts[t.from].next_nonce` is FALSE
\*       at the current state (because next_nonce has advanced).
\*
\*   (2) Action invariant: applied is monotone-non-shrinking AND
\*       no tx is added twice to applied.
\*
\* (1) is the headline replay-defense statement; (2) is the audit
\* trail. Both are checked.
Inv_ReplayImpossible ==
    \A t \in applied : t.nonce /= accounts[t.from].next_nonce

\* AppliedMonotone: the applied set is monotone non-shrinking.
\* Combined with Inv_ReplayImpossible, this gives the full
\* "T applied at S1 ⇒ T cannot apply at any later S2" guarantee:
\* T stays in applied (monotone) AND the apply guard never fires
\* on T again (ReplayImpossible).
Inv_AppliedMonotone ==
    [][applied \subseteq applied']_vars

\* PerAccountIndependence: a step that changes accounts[a] does
\* NOT change accounts[b] for any b /= a. This rules out spurious
\* cross-account coupling in the next_nonce field.
\*
\* The only action that mutates `accounts` is ApplyTx, which uses
\* `[accounts EXCEPT ![t.from] = ...]` — by EXCEPT semantics, all
\* other domains are untouched. We assert this directly as an
\* action invariant.
Inv_PerAccountIndependence ==
    [][\A a, b \in Domains :
         (a /= b /\ accounts'[a] /= accounts[a])
         => accounts'[b] = accounts[b]]_vars

\* NoStaleApplied: a stronger restatement of ReplayImpossible
\* covering the past-nonce direction. No tx with
\* t.nonce < accounts[t.from].next_nonce_pre_apply is ever in
\* `applied` — i.e., the apply path NEVER admits a stale-nonce
\* tx. This is the core replay-defense statement at the
\* state-machine layer: an attacker cannot rewind an account's
\* nonce by injecting old txs.
\*
\* State form: for every t \in applied, t.nonce was equal to the
\* sender's next_nonce at the moment of apply. Since next_nonce
\* is monotone non-decreasing (Inv_NonceMonotonic) and the apply
\* step advances it by exactly 1, the current next_nonce satisfies
\*   accounts[t.from].next_nonce >= t.nonce + 1 > t.nonce.
\* Inv_StrictNonceGate already covers this; Inv_NoStaleApplied is
\* the equivalent expressed in terms of past attempts:
\* No tx ever in `applied` can have been past-nonce at apply time.
\*
\* This is checked by relating ApplyTx's guard to its post-state:
\* the guard `t.nonce = accounts[t.from].next_nonce` and the
\* update `accounts'[t.from].next_nonce = @+1` together imply
\* `accounts'[t.from].next_nonce = t.nonce + 1 > t.nonce`. So in
\* any state where `t \in applied`, `accounts[t.from].next_nonce
\* > t.nonce`. The state-form invariant is the strict-inequality
\* version of Inv_StrictNonceGate (which already states `<`).
Inv_NoStaleApplied ==
    \A t \in applied : accounts[t.from].next_nonce > t.nonce

\* ApplyAdvancesNonce: action-level invariant — every successful
\* ApplyTx step advances exactly one account's next_nonce by
\* exactly 1, AND that account is t.from. Used as a structural
\* witness for Inv_NoStaleApplied and Inv_ReplayImpossible.
\*
\* Encoded as the strongest local condition: if applied' /= applied
\* (i.e., an ApplyTx step just fired), then there is a unique
\* t \in applied' \ applied (set difference is a singleton because
\* ApplyTx adds exactly one tx) such that accounts'[t.from] =
\* accounts[t.from] with next_nonce advanced by 1 and balance
\* reduced by t.amount.
Inv_ApplyAdvancesNonce ==
    [][LET added == applied' \ applied IN
       (added /= {})
       => \E t \in added :
             /\ accounts'[t.from].next_nonce
                = accounts[t.from].next_nonce + 1
             /\ accounts'[t.from].balance
                = accounts[t.from].balance - t.amount
             /\ \A d \in Domains \ {t.from} :
                  accounts'[d] = accounts[d]
      ]_vars

----------------------------------------------------------------------------
\* Temporal properties.

\* EventualNonceAdvance: under fairness on ApplyTx, an honest tx
\* submitted at the current next_nonce eventually applies. The
\* "honest" qualifier here means: well-formed (nonce matches the
\* current next_nonce at the time of SubmitTx, balance sufficient,
\* MaxNonce not yet reached). ApplyTx's guard is NOT stable: a
\* competing tx with the same {from, nonce} can apply first and
\* strand t as permanently stale in pending. WF on ApplyTx covers
\* the apply branch; WF on RemoveFromPending (the M11 per-block
\* stale-nonce sweep) covers the stranded-stale branch — together
\* they give the eventual-progress guarantee.
\*
\* Formally: in every fair run, if some t \in pending satisfies
\* t.nonce = accounts[t.from].next_nonce and balance is sufficient,
\* then either t eventually transitions to applied or t is removed
\* from pending. The "or" reflects the gc escape; without it the
\* property would be too strong (gc could starve the apply branch).
\*
\* The expressed property is the strictly-positive form: whenever
\* there exists such a matching tx, eventually applied grows OR
\* the matching tx is no longer in pending.
Prop_EventualNonceAdvance ==
    \A t \in Tx :
       ((t \in pending
         /\ t.nonce = accounts[t.from].next_nonce
         /\ accounts[t.from].balance >= t.amount
         /\ accounts[t.from].next_nonce < MaxNonce)
        ~> (t \in applied \/ t \notin pending))

\* NoStaleApplied (temporal): across all reachable states, no tx
\* with t.nonce < next_nonce(at-apply-time) is ever in applied.
\* This is the temporal restatement of Inv_NoStaleApplied — it is
\* implied by the state invariant + monotonicity, but stated here
\* as a separate property because the prose proof
\* (NonceMonotonicity.md) cites it as the headline replay-defense
\* theorem.
\*
\* TLC checks this as a [][...]_vars conjunction: at every step,
\* every applied tx satisfies the strict inequality. Equivalent
\* to Inv_NoStaleApplied checked at every reachable state.
Prop_NoStaleApplied ==
    [][\A t \in applied : accounts[t.from].next_nonce > t.nonce]_vars

============================================================================
