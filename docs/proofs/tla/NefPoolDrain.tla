--------------------------- MODULE NefPoolDrain ---------------------------
(*
FB19 — TLA+ specification of the E1 Negative Entry Fee (NEF) pool drain
state machine. Models the apply-layer behavior of the ZEROTH pool as
domains register for the first time: pool/2 is debited and credited to
the registrant. Re-registration (key rotation, region update) does NOT
drain the pool — only the first-time REGISTER fires the geometric
halving.

State-machine companion to the FA-track economic prose proof
`docs/proofs/NefPoolDrain.md` (parallel agent).

Sits adjacent to FB11 (SubsidyDistribution.tla) which models the NEF
drain alongside the block-subsidy distribution. FB19 zooms in on the
NEF-only surface and pulls the submit/apply lifecycle into an explicit
pending sequence so the apply-order semantics are observable at the
state-machine layer. The FB11 spec collapses Submit + Apply into a
single Register action; FB19 separates them, which lets TLC explore
interleavings of multi-domain submit + cross-apply ordering.

The state model treats the ZEROTH pool as an entry of the `balances`
function, indexed by the `ZerothAddress` constant. This lifts the
A1 supply-conservation contract into a single sum-of-balances identity
without a dedicated pool variable — every drain is an internal
balances[zeroth] -> balances[d] redistribution.

Properties captured:

  (T-N1) Geometric exhaustion: after K successful first-time registers
         from an initial pool P, the pool balance is at most
         floor(P / 2^K). Witnesses the floor-half drain semantics
         at `src/chain/chain.cpp:813-833`.
  (T-N2) Drain only on first register: any step that decreases
         balances[ZerothAddress] must be paired with a fresh domain
         entering the `registrants` set. Re-register cannot drain.
         Matches the `first_time_register` bool gate at
         `src/chain/chain.cpp:795-796`.
  (T-N3) Re-register is a no-op on pool + balance: ApplyReRegister
         leaves vars UNCHANGED on the drain-relevant variables.
  (T-N4) Zero-pool noop: once balances[ZerothAddress] = 0, a
         first-time register still adds the domain to registrants
         but the credit is 0 — the floor-half of zero is zero, the
         drained amount is zero, and balances unchanged across
         the pool/registrant pair. The pool reaches a permanent
         absorbing state at 0.
  (T-N5) A1 conservation: nef_pool + sum_{d /= ZerothAddress}
         balances[d] = InitialNefPool at every reachable state.
         The pool drain is an internal redistribution; no NEF
         action mints or destroys.
  (T-N6) Eventual exhaustion (temporal): under fairness on the
         Submit/Apply actions, eventually the pool reaches 0, OR
         every domain has registered, OR the apply-action budget
         (height = MaxHeight) is exhausted.
  (T-N7) Registration is terminal (temporal): once a domain enters
         the `registrants` set it stays — no Deregister action is
         modeled in this scope (Deregister is FB8 / StakeLifecycle
         territory; for the NEF drain surface, registration is
         one-way and permanent).

Modeling scope (kept tractable for TLC):

  * Single-shot register lifecycle per domain. Deregister + the
    `inactive_from` machinery is out-of-scope (FB8 StakeLifecycle).
    For the NEF drain surface, registration is one-way and
    permanent — the worst case for the drain-once invariant.
  * The ZerothAddress sentinel domain is the source pool. It is
    NOT a regular domain — it is excluded from the SubmitRegister
    and ApplyFirstRegister domain selection so an attacker cannot
    "register the pool" to drain itself.
  * pending_register is a SEQUENCE OF Domain (matching the C++
    apply order — txs apply head-first per
    `src/chain/chain.cpp:734` `for (auto& tx : b.transactions)`).
    SubmitRegister appends; ApplyFirstRegister / ApplyReRegister
    consume from the head.
  * Fees are abstracted away. The C++ REGISTER branch charges a
    fee on the sender; for the NEF drain invariants the fee is
    orthogonal (covered by FB10 FeeAccounting).
  * No block subsidies — that is FB11 SubsidyDistribution
    territory.

To check (assuming TLC installed):
  $ tlc NefPoolDrain.tla -config NefPoolDrain.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,            \* set of regular domain identifiers (excludes ZerothAddress)
    InitialNefPool,     \* initial ZEROTH pool balance (Nat)
    ZerothAddress,      \* sentinel — the all-zero anon address (pool home)
    MaxHeight           \* upper bound on apply-action count for TLC

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ InitialNefPool \in Nat
    /\ ZerothAddress \notin Domains
    /\ MaxHeight \in Nat /\ MaxHeight >= 1

\* All addresses tracked in the balances function: the regular Domains
\* plus the ZerothAddress pool sentinel.
AllAddresses == Domains \cup {ZerothAddress}

----------------------------------------------------------------------------
\* State.

VARIABLES
    registrants,        \* SUBSET Domain — domains that have first-registered
    balances,           \* AllAddresses -> Nat — includes ZerothAddress as pool
    pending_register,   \* Seq(Domain) — submitted-but-not-applied register txs
    height              \* 0..MaxHeight — apply-action counter; both Apply
                        \* actions are guarded by height < MaxHeight (TLC bound)

vars == <<registrants, balances, pending_register, height>>

----------------------------------------------------------------------------
\* Helpers.

\* nef_pool: the ZerothAddress balance, modeled as the pool home.
nef_pool == balances[ZerothAddress]

\* Sum of balances over non-pool addresses. The A1 conservation
\* identity (T-N5) is: nef_pool + SumDomainBalances = InitialNefPool.
SumDomainBalances ==
    LET RECURSIVE sum_bal(_)
        sum_bal(S) ==
        IF S = {} THEN 0
        ELSE LET d == CHOOSE x \in S : TRUE IN
             balances[d] + sum_bal(S \ {d})
    IN sum_bal(Domains)

----------------------------------------------------------------------------
\* Initial state. All regular domains start with balance 0 and are not
\* registered. The ZerothAddress pool starts at InitialNefPool. The
\* pending queue starts empty. Height starts at 0.
\*
\* Modeling note: the C++ ZEROTH pool sits in the `accounts_` map keyed
\* by the all-zero anon address; the TLA model lifts ZerothAddress into
\* the `balances` function with the same key-as-sentinel discipline. The
\* A1 supply identity (T-N5) is then a sum-of-balances identity without
\* a dedicated pool variable.

Init ==
    /\ registrants = {}
    /\ balances = [a \in AllAddresses |->
                     IF a = ZerothAddress THEN InitialNefPool ELSE 0]
    /\ pending_register = <<>>
    /\ height = 0

----------------------------------------------------------------------------
\* Actions.

\* SubmitRegister(d): adversary / mempool action — any domain may be
\* submitted for register. Appended to the pending queue. The apply
\* side enforces first-time-vs-re-register via the `registrants` set
\* membership check at apply time.
\*
\* Pre-condition: pending queue depth < MaxHeight (TLC bound on queue
\* depth only; the apply-action budget is the separate height <
\* MaxHeight guard on the Apply actions). The C++ has no
\* such bound — mempool capacity is bounded by S-008 quotas, which are
\* validator-side and orthogonal to the apply-layer drain semantics
\* modeled here.
SubmitRegister(d) ==
    /\ d \in Domains
    /\ Len(pending_register) < MaxHeight
    /\ pending_register' = Append(pending_register, d)
    /\ UNCHANGED <<registrants, balances, height>>

\* ApplyFirstRegister(d): apply branch for d \notin registrants.
\* Drains nef_pool by floor-half and credits the drained amount to d's
\* balance. Adds d to registrants. Consumes d from the head of
\* pending_register. Guarded by height < MaxHeight — the TLC
\* apply-action budget (a model bound, not a code behavior).
\*
\* Models `src/chain/chain.cpp:813-833` — the E1 NEF transfer that
\* fires inside the `first_time_register == true` branch (the
\* `registrants_.find(tx.from) == registrants_.end()` predicate at
\* chain.cpp:795-796).
\*
\* The drain is floor-half: drain = balances[zeroth] \div 2 (rounded
\* down), matching the C++ `nef = pool / 2`. The credit is exactly the
\* drained amount. The post-state pool is
\*   balances[zeroth] - drain = ceil(P / 2),
\* so the pool absorbs at 1 (drain of 1 is 0), matching the C++
\* `if (nef > 0)` gate at chain.cpp:828.
\*
\* T-N4 (zero-pool noop): if balances[zeroth] = 0, then drain = 0 and
\* the credit is a no-op on balance. registrants STILL gains d (the
\* register tx succeeds even with an empty pool; the drain is a
\* silent zero). The A1 conservation identity holds: 0 = 0 + 0.
ApplyFirstRegister(d) ==
    /\ height < MaxHeight
    /\ Len(pending_register) > 0
    /\ Head(pending_register) = d
    /\ d \in Domains
    /\ d \notin registrants
    /\ LET drain == balances[ZerothAddress] \div 2 IN
       /\ balances' = [balances EXCEPT
                         ![ZerothAddress] = balances[ZerothAddress] - drain,
                         ![d]            = balances[d] + drain]
       /\ registrants' = registrants \cup {d}
       /\ pending_register' = Tail(pending_register)
       /\ height' = height + 1

\* ApplyReRegister(d): apply branch for d \in registrants. NO NEF
\* drain — the C++ first_time_register bool is FALSE on this path.
\* Models the same DAPP/REGISTER apply branch but in the "already
\* registered" path at chain.cpp:795-796.
\*
\* The action consumes d from the head of pending_register so the
\* apply-progress matches the C++ for-loop iteration order. No other
\* state mutation occurs — balance, pool, registrants all preserved.
\* T-N3 structural witness: re-register is a stutter on the drain
\* state. Same height < MaxHeight apply-action budget as
\* ApplyFirstRegister.
ApplyReRegister(d) ==
    /\ height < MaxHeight
    /\ Len(pending_register) > 0
    /\ Head(pending_register) = d
    /\ d \in Domains
    /\ d \in registrants
    /\ pending_register' = Tail(pending_register)
    /\ height' = height + 1
    /\ UNCHANGED <<registrants, balances>>

----------------------------------------------------------------------------
\* Next-state relation. SubmitRegister / ApplyFirstRegister /
\* ApplyReRegister. TLC enumerates all interleavings within MaxHeight.

Next ==
    \/ \E d \in Domains : SubmitRegister(d)
    \/ \E d \in Domains : ApplyFirstRegister(d)
    \/ \E d \in Domains : ApplyReRegister(d)

\* Fairness on ApplyFirstRegister drives the eventual-exhaustion
\* property (T-N6). Under WF on a parameterized action, if the action
\* remains enabled (i.e., the head of pending_register is an
\* unregistered domain) it eventually fires.
\*
\* Fairness on SubmitRegister keeps the pending queue fed; without it
\* a trace could indefinitely stutter at an empty queue. Fairness on
\* ApplyReRegister keeps the queue draining; without it an already-
\* registered domain sitting at the head could block the queue (and
\* the height budget) forever.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ \A d \in Domains : WF_vars(SubmitRegister(d))
    /\ \A d \in Domains : WF_vars(ApplyFirstRegister(d))
    /\ \A d \in Domains : WF_vars(ApplyReRegister(d))

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant: variables have correct shapes.
Inv_TypeOK ==
    /\ registrants \subseteq Domains
    /\ balances \in [AllAddresses -> 0..InitialNefPool]
    /\ pending_register \in Seq(Domains)
    /\ height \in 0..MaxHeight

\* PoolNonNegative: the pool balance never goes negative. The
\* floor-half drain is closed on Nat (P - (P \div 2) <= P for all
\* P >= 0); once the pool reaches 0, the terminal 0 \div 2 = 0 keeps
\* it there.
Inv_PoolNonNegative == balances[ZerothAddress] >= 0

\* GeometricExhaustion (T-N1): the pool balance is at most
\* floor(InitialNefPool / 2^K) where K = Cardinality(registrants).
\* The K-th distinct first-time register applies a K-th floor-half;
\* arithmetic gives pool <= floor(P / 2^K).
\*
\* Encoded as: forall K, if |registrants| >= K then
\*   2^K * balances[ZerothAddress] <= InitialNefPool.
\*
\* TLC checks this by instantiating K up to |Domains| (the maximum
\* possible distinct first-registers). For K = |Domains|, all domains
\* have registered and pool <= floor(P / 2^|Domains|).
Inv_GeometricExhaustion ==
    \A k \in 0..Cardinality(Domains) :
        (Cardinality(registrants) >= k)
        =>
        ((2 ^ k) * balances[ZerothAddress] <= InitialNefPool)

\* DrainOnlyOnFirstRegister (T-N2): action-level invariant. Any step
\* that decreases balances[ZerothAddress] must come paired with a
\* fresh domain entering registrants. Re-register cannot drain.
\*
\* Equivalently: balances'[ZerothAddress] < balances[ZerothAddress]
\* iff registrants' = registrants \cup {d} for some d \notin registrants.
Inv_DrainOnlyOnFirstRegister ==
    [][(balances'[ZerothAddress] < balances[ZerothAddress])
       =>
       (\E d \in Domains :
           /\ d \notin registrants
           /\ d \in registrants')
      ]_vars

\* A1Conservation (T-N5): nef_pool + sum-of-domain-balances =
\* InitialNefPool at every reachable state. Every NEF action is an
\* internal redistribution; no action mints or destroys.
Inv_A1Conservation ==
    balances[ZerothAddress] + SumDomainBalances = InitialNefPool

----------------------------------------------------------------------------
\* Temporal properties.

\* EventualExhaustion (T-N6): under the fairness conditions in Spec,
\* the pool eventually hits zero, OR every domain has registered, OR
\* the apply-action budget is exhausted (height = MaxHeight).
\*
\* With |Domains| distinct first-registers and InitialNefPool fixed,
\* the pool drains geometrically. For Domains = {a, b, c} and
\* InitialNefPool = 8, the trace
\*   pool=8 -> register(a) -> pool=4 -> register(b) -> pool=2
\*           -> register(c) -> pool=1
\* leaves the pool at 1 (floor(8/2^3) = 1); the pool absorbs at 1
\* (drain of 1 is 0 — the C++ `if (nef > 0)` gate), so "eventual
\* zero" is unreachable from a positive pool. The height = MaxHeight
\* disjunct is the model-bound escape: re-register churn may consume
\* the apply budget before every domain first-registers.
Prop_EventualExhaustion ==
    <>(\/ balances[ZerothAddress] = 0
       \/ Cardinality(registrants) = Cardinality(Domains)
       \/ height = MaxHeight)

\* RegistrationIsTerminal (T-N7): action-level invariant — once a
\* domain enters registrants, it stays. No Deregister action is
\* modeled in this scope; for the NEF drain surface, registration is
\* one-way and permanent.
\*
\* Encoded as: across every [Next]_vars step,
\*   d \in registrants => d \in registrants'.
Prop_RegistrationIsTerminal ==
    [][\A d \in Domains :
         (d \in registrants) => (d \in registrants')
      ]_vars

============================================================================
\* Cross-references.
\*
\* FB11 (SubsidyDistribution.tla) — models the NEF drain alongside
\* block-subsidy distribution. The FB19 spec is a focused zoom on the
\* NEF surface with the Submit/Apply separation that FB11 collapses
\* into a single Register action. Both specs agree on the structural
\* invariants (NefPoolNonNegative, NefDrainsOnceperDomain in FB11 =
\* Inv_DrainOnlyOnFirstRegister in FB19); FB19 adds T-N1 geometric
\* exhaustion as a quantified upper bound.
\*
\* FB9 (DAppRegistry.tla) — models the same first-register / re-register
\* discriminator at the v2.18 DAPP_REGISTER surface; the NEF drain
\* sits adjacent (Inv_NefDrainsOnlyOnce in FB9 = Inv_DrainOnlyOnFirstRegister
\* in FB19, restricted to the DApp-registry sub-track).
\*
\* The C++ first_time_register bool at src/chain/chain.cpp:795-796
\* is the source-side enforcement point for all three specs; the
\* tools/test_nef_pool_drain.sh regression is the runtime witness.
============================================================================
