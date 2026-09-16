--------------------------- MODULE UnitarySupplyLedger ---------------------------
(*
FB46 — TLA+ specification of the A1 UNITARY-SUPPLY ledger invariant. Where
the prior economic FB-track specs each isolate ONE accumulator term —
FB10 (FeeAccounting) and FB11 (SubsidyDistribution) cover the +subsidy
mint, FB15 (EquivocationApply) and FB16 (AbortApply) cover the -slashed
burn, FB14 (CrossShardReceiptDedup) covers the +inbound credit, FB18
(CrossShardOutboundApply) covers the -outbound debit, FB19 (NefPoolDrain)
is a pure internal redistribution — this spec models the FULL SIX-TERM
supply identity as a single composed ledger, exactly as the C++
apply-path asserts it at the end of every block.

The headline contract is the post-apply assertion at
`src/chain/chain.cpp:1866-1892`:

      live_total_supply() == expected_total()

where (from `include/determ/chain/chain.hpp:590-597` + `src/chain/chain.cpp:699-704`):

      expected_total =  genesis_total
                      + accumulated_subsidy
                      + accumulated_inbound
                      - accumulated_slashed
                      - accumulated_outbound
                      - accumulated_shielded      (§3.22)

      live_total_supply =  Sum(accounts.balance)
                         + Sum(stakes.locked)

The novelty over the slice-specs is that NO prior FB spec puts all six
accumulators AND the two-component live supply (balances + locked stake)
into a single conserved identity. The slice-specs each prove their own
local conservation against a single moving term; this spec proves that
the global ledger closes when ALL SIX terms move in arbitrary
interleaving — which is what the C++ assertion actually checks, and what
a light client re-deriving total supply from the `c:` constants namespace
(genesis_total / accumulated_subsidy / accumulated_slashed /
accumulated_inbound / accumulated_outbound / accumulated_shielded at
chain.cpp:494-499 + the two cross-shard accumulators) relies on.

§3.22 SHIELDED POOL — the sixth term. SHIELD moves a public amount A out
of the transparent live sum into the confidential pool
(accumulated_shielded += A; chain.cpp:1037); UNSHIELD returns a note's
public amount to a transparent recipient (accumulated_shielded -= A;
chain.cpp:1081); CONFIDENTIAL_TRANSFER is pool->pool and lets ONLY the
public fee leave the pool back to a transparent creator balance
(accumulated_shielded -= fee; chain.cpp:1172). accumulated_shielded is
therefore the ONE TWO-DIRECTIONAL accumulator (the other four are
monotone-non-decreasing running totals). It is SUBTRACTED in
expected_total() because that value LEFT live_total_supply() but was not
burned — real supply = live_total_supply() + accumulated_shielded
(chain.hpp:585-589). It is 0 on any shield-free chain, which recovers the
classical five-term identity. The pool is SINGLE-SHARD-ONLY (a cross-shard
UNSHIELD credit is rejected at chain.cpp:1059), so it needs no cross-shard
netting (FB54 CrossShardSupplyConservation §5 lim. 7 keeps it shard-local).

The apply-layer actions modeled, each touching exactly one accumulator
(or none, for the internal-redistribution actions):

  * Transfer(from, to, amt): internal balance -> balance move. NO
    accumulator changes. The supply identity is preserved because the
    debit and credit cancel. Models the local-shard TRANSFER branch.
  * StakeLock(d, amt) / StakeUnlock(d, amt): internal balance <-> locked
    stake move. NO accumulator changes. Models the STAKE / UNSTAKE
    apply branches that shuffle value between the two live-supply
    components. Crucial for this spec because live_total_supply sums
    BOTH components — a spec that only tracked balances would miss
    that stake-lock conserves supply.
  * MintSubsidy(d, amt): credits creator balance + bumps
    accumulated_subsidy by the SAME amount. Net delta on the identity:
    +amt to LiveSupply, +amt to expected_total. Preserved. Models the
    block-subsidy mint at chain.cpp:1390-1392.
  * SlashStake(d, amt): debits locked stake + bumps accumulated_slashed
    by the SAME amount. Net delta: -amt to LiveSupply, +amt to the
    subtracted accumulated_slashed term => -amt to expected_total.
    Preserved. Models the abort suspension deduction — the only stake
    debit since D4, 2026-09-16 (equivocation debits nothing; the
    EquivocationApply model is historical, AbortApply is current).
  * InboundReceipt(d, amt): credits balance + bumps accumulated_inbound
    by the SAME amount. Net delta: +amt to LiveSupply, +amt to
    accumulated_inbound => +amt to expected_total. Preserved. Models
    the dst-side cross-shard credit at chain.cpp:1393 + the FB14
    dedup-gated apply.
  * OutboundDebit(d, amt): debits balance + bumps accumulated_outbound
    by the SAME amount. Net delta: -amt to LiveSupply, +amt to the
    subtracted accumulated_outbound term => -amt to expected_total.
    Preserved. Models the src-side cross-shard debit at chain.cpp:1394
    + the FB18 outbound emit.
  * Shield(d, amt): moves amt OUT of d's balance INTO the shielded pool.
    Debits d's balance + bumps accumulated_shielded by the SAME amount.
    Net delta: -amt to LiveSupply, +amt to the subtracted
    accumulated_shielded term => -amt to expected_total. Preserved. Models
    the SHIELD arm at chain.cpp:1037 (the public amount A leaving the
    transparent sum for the confidential pool).
  * Unshield(d, amt): moves amt from the shielded pool BACK into d's
    balance. Credits d's balance + DECREMENTS accumulated_shielded by the
    SAME amount. Net delta: +amt to LiveSupply, +amt to expected_total
    (the subtracted accumulated_shielded term shrinks). Preserved. Models
    the UNSHIELD confidential->transparent withdraw at chain.cpp:1081.
    This is the one action that DECREASES an accumulator — accumulated_-
    shielded is not monotone (see T-U3).
  * ConfidentialTransfer(d, amt): pool->pool transfer; only the public fee
    `amt` leaves the pool back to a transparent creator balance d. Same
    state-shape as Unshield (credit balance + decrement accumulated_-
    shielded) but a DISTINCT apply branch. Net delta: +amt to LiveSupply,
    +amt to expected_total. Preserved. Models the CONFIDENTIAL_TRANSFER
    fee arm at chain.cpp:1172 (the pool->creator fee move).

Properties captured:

  (T-U1) Inv_TypeOK — variables have correct shapes; every accumulator
         and balance is Nat-valued.
  (T-U2) Inv_A1UnitarySupply — THE headline. At every reachable state,
            LiveSupply = genesis_total
                       + accumulated_subsidy + accumulated_inbound
                       - accumulated_slashed - accumulated_outbound
                       - accumulated_shielded
         This is the exact `live_total_supply() == expected_total()`
         assertion lifted to the state-machine layer, composed across
         all six accumulators moving in arbitrary order.
  (T-U3) Inv_AccumulatorsMonotone — each of the FOUR monotone accumulators
         (subsidy / inbound / slashed / outbound) is monotone non-
         decreasing across every step. The C++ tracks RUNNING TOTALS
         (chain.cpp:1862-1864 are all `+=`), never resets; an apply step
         can only grow one of these four. genesis_total is fixed at load
         (chain.cpp:934) so it is monotone trivially. accumulated_shielded
         is DELIBERATELY EXCLUDED: it is the one two-directional counter
         (SHIELD `+=`, UNSHIELD / CONFIDENTIAL_TRANSFER `-=`,
         chain.cpp:1037/1081/1172), so asserting it monotone would be
         false — Unshield / ConfidentialTransfer decrement it. Its
         non-negativity (never < 0) is covered by Inv_NoNegativeUnderflow /
         Inv_TypeOK instead.
  (T-U4) Inv_NoNegativeUnderflow — LiveSupply >= 0 and the subtracted
         terms (slashed + outbound + shielded) never exceed the added
         terms, so expected_total stays in Nat. Witnesses that the
         unsigned-arithmetic identity at chain.cpp:1866-1892 cannot wrap
         (the C++ uses uint64; underflow would corrupt the assertion). The
         three-subtraction totality is the ExpectedTotalWellDefined ET-1
         domination bound `L + O + Sh <= G + S + I`.
  (T-U5) Inv_LiveDecomposition — LiveSupply = SumBalances + SumStakes;
         the two-component decomposition is exact, so a StakeLock that
         moves value from balance to stake leaves LiveSupply unchanged.
  (T-U6) Prop_SupplyAlwaysCloses — temporal restatement of T-U2 as a
         []-claim, mirroring the dual treatment in FB10 / FB11.
  (T-U7) Prop_OnlyAccountedDeltas — action-level: any change in
         LiveSupply is matched one-for-one by a change in the
         accumulator ledger (no mint or burn happens off-ledger).

Modeling scope (kept tractable for TLC):

  * Genesis supply is a fixed constant (GenesisTotal); the C++ pins it
    at load (chain.cpp:934) and never mutates it afterwards. Pre-seeded
    balances summing to GenesisTotal form the Init state.
  * The shielded pool is abstracted to its supply-bearing counter alone
    (accumulated_shielded). The commitment set, nullifiers, Pedersen
    binding and range/balance proofs (ShieldedPoolSoundness) are OUT of
    scope — this spec asserts only that whatever the shield arms move
    between the transparent live sum and the pool is conservation-neutral
    on the six-term identity. Shield's pre-condition (balance[d] >= amt)
    mirrors the S-049-checked `cost = A + fee` debit; Unshield /
    ConfidentialTransfer's pre-condition (acc_shielded >= amt) mirrors the
    Pedersen-binding guarantee that a note cannot withdraw more than it
    shielded (so accumulated_shielded never wraps below 0).
  * Amounts are bounded by MaxDelta to keep the state space finite. The
    C++ uses checked_add_u64 on every credit; overflow-checking is out
    of scope (FB-track economic specs all abstract it away).
  * The dedup / first-time-register / proportional-vs-full gating that
    decides WHETHER a given accumulator bump fires is out of scope —
    that is the slice-specs' territory (FB14 dedup, FB15/FB16 slash
    discriminator, FB19 first-register). This spec assumes the gate
    PASSED and checks that the resulting balance/stake mutation +
    accumulator bump preserve the unitary identity. Equivalently: this
    spec is the composition layer that the slice-specs feed into.
  * Fee distribution is absorbed into Transfer (fees are an internal
    balance -> creator-balance move; FB10 covers the per-creator dust
    split). The subsidy mint is modeled explicitly because it is the
    one branch that actually grows expected_total via accumulated_subsidy.
  * Height / block boundaries are abstracted into an action counter
    (steps) that bounds TLC. The C++ asserts the identity at the END of
    every block; the TLA model asserts it as a state invariant after
    every individual sub-event, which is STRICTLY STRONGER (the C++
    could in principle violate it mid-block and recover; this spec
    forbids even transient violation, matching the per-action delta
    cancellation in the apply path).

Companion prose proof: `docs/proofs/UnitarySupplyLedger.md`
(may be written by a parallel agent; may not yet exist in this worktree).

Adjacent specs: FB10 (FeeAccounting), FB11 (SubsidyDistribution),
FB14 (CrossShardReceiptDedup), FB15 (EquivocationApply),
FB16 (AbortApply), FB18 (CrossShardOutboundApply),
FB19 (NefPoolDrain), FB20 (MultiEventComposition),
FB54 (CrossShardSupplyConservation — the K-shard composition of THIS
single-shard ledger, carrying the same shard-local accumulated_shielded
term). FB46 is the six-accumulator ledger-closure layer that subsumes the
individual single-term conservation claims into the exact C++ A1
assertion. The subtractive totality of the six-term RHS (no uint64
underflow) is ExpectedTotalWellDefined ET-1..ET-4.

To check (assuming TLC installed):
  $ tlc UnitarySupplyLedger.tla -config UnitarySupplyLedger.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,            \* set of account / operator identifiers
    GenesisTotal,       \* fixed genesis_total (pinned at load, never mutated)
    MaxDelta,           \* upper bound on any single per-action amount
    MaxSteps            \* upper bound on action count for TLC

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ GenesisTotal \in Nat /\ GenesisTotal >= 1
    /\ MaxDelta     \in Nat /\ MaxDelta     >= 1
    /\ MaxSteps     \in Nat /\ MaxSteps     >= 1
    \* GenesisTotal must be evenly divisible across Domains so the Init
    \* allocation is exact (no dust left unaccounted). The .cfg picks
    \* GenesisTotal a multiple of Cardinality(Domains).
    /\ GenesisTotal % Cardinality(Domains) = 0

----------------------------------------------------------------------------
\* State.
\*
\* The live supply is split into the two components the C++
\* live_total_supply() sums: per-domain account `balance` and per-domain
\* `locked` stake. The six accumulators mirror the C++ running totals
\* at include/determ/chain/chain.hpp:889-898.

VARIABLES
    balance,                \* function Domains -> Nat (account balances)
    locked,                 \* function Domains -> Nat (staked / locked)
    acc_subsidy,            \* Nat — accumulated_subsidy running total
    acc_inbound,            \* Nat — accumulated_inbound running total
    acc_slashed,            \* Nat — accumulated_slashed running total
    acc_outbound,           \* Nat — accumulated_outbound running total
    acc_shielded,           \* Nat — accumulated_shielded (§3.22): the ONE
                            \*   two-directional counter (SHIELD +=, UNSHIELD
                            \*   / CONFIDENTIAL_TRANSFER -=). Subtracted in
                            \*   expected_total().
    steps                   \* Nat — action counter, bounds TLC

vars == <<balance, locked, acc_subsidy, acc_inbound,
          acc_slashed, acc_outbound, acc_shielded, steps>>

----------------------------------------------------------------------------
\* Helpers.

\* Sum of a Domains-indexed Nat function. Encoded as a recursive helper
\* because Naturals.tla ships no fold-over-finite-sets primitive that TLC
\* handles natively at this arity. Pattern matches FeeAccounting.tla::
\* SumBalances / StakeLifecycle.tla::SumStakes.
SumOver(f) ==
    LET RECURSIVE sum_f(_)
        sum_f(S) ==
        IF S = {} THEN 0
        ELSE LET d == CHOOSE x \in S : TRUE IN
             f[d] + sum_f(S \ {d})
    IN sum_f(Domains)

\* The two live-supply components.
SumBalances == SumOver(balance)
SumStakes   == SumOver(locked)

\* live_total_supply() — the C++ sum at chain.cpp:699-704.
LiveSupply == SumBalances + SumStakes

\* expected_total() — the C++ six-term identity at chain.hpp:590-597.
\* Written with the subtracted terms grouped so the Nat-closure is
\* explicit: the added terms (genesis + subsidy + inbound) must dominate
\* the subtracted terms (slashed + outbound + shielded). Inv_NoNegative-
\* Underflow is the witness that they do at every reachable state (the
\* ExpectedTotalWellDefined ET-1 domination bound L + O + Sh <= G + S + I).
ExpectedTotal ==
    (GenesisTotal + acc_subsidy + acc_inbound)
    - (acc_slashed + acc_outbound + acc_shielded)

----------------------------------------------------------------------------
\* Initial state. Genesis balances are pre-allocated so their sum equals
\* GenesisTotal (the C++ load path at chain.cpp:934 sets genesis_total_ =
\* gtotal = the live sum at genesis). All stake starts at zero, all six
\* accumulators (except the fixed genesis) start at zero — the shielded
\* pool is empty at genesis (accumulated_shielded_ zeroed at chain.cpp:939).
\*
\* Each domain gets an equal GenesisTotal / |Domains| slice; ConfigOK
\* enforces exact divisibility so the Init sum is exactly GenesisTotal.

Init ==
    /\ balance = [d \in Domains |-> GenesisTotal \div Cardinality(Domains)]
    /\ locked  = [d \in Domains |-> 0]
    /\ acc_subsidy  = 0
    /\ acc_inbound  = 0
    /\ acc_slashed  = 0
    /\ acc_outbound = 0
    /\ acc_shielded = 0
    /\ steps = 0

----------------------------------------------------------------------------
\* Actions. Each models an apply-layer branch. The accumulator-touching
\* actions bump exactly one running total by the same amount that the
\* live supply moves, so the identity is preserved per-action.

\* Transfer(from, to, amt): local-shard balance -> balance move. NO
\* accumulator changes. Pre-condition: sender has >= amt. The debit and
\* credit cancel, so LiveSupply and ExpectedTotal are both unchanged.
\* Models the local TRANSFER branch (fees folded in: a fee is an internal
\* move to a creator's balance, conservation-equivalent to a transfer).
Transfer(from, to, amt) ==
    /\ steps < MaxSteps
    /\ from \in Domains /\ to \in Domains /\ from /= to
    /\ amt \in 1..MaxDelta
    /\ balance[from] >= amt
    /\ balance' = [balance EXCEPT ![from] = @ - amt, ![to] = @ + amt]
    /\ UNCHANGED <<locked, acc_subsidy, acc_inbound, acc_slashed, acc_outbound, acc_shielded>>
    /\ steps' = steps + 1

\* StakeLock(d, amt): internal balance -> locked move. NO accumulator
\* changes. Pre-condition: d has >= amt free balance. LiveSupply is
\* unchanged because the value moves between the two summed components.
\* Models the STAKE apply branch — the case a balance-only spec would
\* mishandle.
StakeLock(d, amt) ==
    /\ steps < MaxSteps
    /\ d \in Domains
    /\ amt \in 1..MaxDelta
    /\ balance[d] >= amt
    /\ balance' = [balance EXCEPT ![d] = @ - amt]
    /\ locked'  = [locked  EXCEPT ![d] = @ + amt]
    /\ UNCHANGED <<acc_subsidy, acc_inbound, acc_slashed, acc_outbound, acc_shielded>>
    /\ steps' = steps + 1

\* StakeUnlock(d, amt): internal locked -> balance move (UNSTAKE post
\* unlock-height). NO accumulator changes. Pre-condition: d has >= amt
\* locked. The mirror of StakeLock; LiveSupply unchanged.
StakeUnlock(d, amt) ==
    /\ steps < MaxSteps
    /\ d \in Domains
    /\ amt \in 1..MaxDelta
    /\ locked[d] >= amt
    /\ locked'  = [locked  EXCEPT ![d] = @ - amt]
    /\ balance' = [balance EXCEPT ![d] = @ + amt]
    /\ UNCHANGED <<acc_subsidy, acc_inbound, acc_slashed, acc_outbound, acc_shielded>>
    /\ steps' = steps + 1

\* MintSubsidy(d, amt): credit d's balance by amt AND bump acc_subsidy by
\* the same amt. Net: +amt to LiveSupply, +amt to ExpectedTotal (via the
\* +acc_subsidy term). Identity preserved. Models the block-subsidy mint
\* at chain.cpp:1390-1392 collapsed to a single-creator credit (the
\* per-creator dust split is FB10/FB11 territory and is conservation-
\* neutral within the mint).
MintSubsidy(d, amt) ==
    /\ steps < MaxSteps
    /\ d \in Domains
    /\ amt \in 1..MaxDelta
    /\ balance'     = [balance EXCEPT ![d] = @ + amt]
    /\ acc_subsidy' = acc_subsidy + amt
    /\ UNCHANGED <<locked, acc_inbound, acc_slashed, acc_outbound, acc_shielded>>
    /\ steps' = steps + 1

\* InboundReceipt(d, amt): dst-side cross-shard credit. Credit d's
\* balance by amt AND bump acc_inbound by the same amt. Net: +amt to
\* LiveSupply, +amt to ExpectedTotal (via +acc_inbound). Identity
\* preserved. Models the FB14 dedup-gated apply at chain.cpp:1393 (the
\* dedup gate is assumed passed; this is the post-gate mutation).
InboundReceipt(d, amt) ==
    /\ steps < MaxSteps
    /\ d \in Domains
    /\ amt \in 1..MaxDelta
    /\ balance'     = [balance EXCEPT ![d] = @ + amt]
    /\ acc_inbound' = acc_inbound + amt
    /\ UNCHANGED <<locked, acc_subsidy, acc_slashed, acc_outbound, acc_shielded>>
    /\ steps' = steps + 1

\* OutboundDebit(d, amt): src-side cross-shard debit. Debit d's balance
\* by amt AND bump acc_outbound by the same amt. Net: -amt to LiveSupply,
\* -amt to ExpectedTotal (via the -acc_outbound term). Identity
\* preserved. Pre-condition: d has >= amt balance. Models the FB18
\* outbound emit at chain.cpp:1394 (debit-precedes-emit; here the debit
\* and the accumulator bump are atomic per the apply path).
OutboundDebit(d, amt) ==
    /\ steps < MaxSteps
    /\ d \in Domains
    /\ amt \in 1..MaxDelta
    /\ balance[d] >= amt
    /\ balance'      = [balance EXCEPT ![d] = @ - amt]
    /\ acc_outbound' = acc_outbound + amt
    /\ UNCHANGED <<locked, acc_subsidy, acc_inbound, acc_slashed, acc_shielded>>
    /\ steps' = steps + 1

\* SlashStake(d, amt): debit d's locked stake by amt AND bump acc_slashed
\* by the same amt. Net: -amt to LiveSupply (the stake leaves the live
\* pool — slashed value is BURNED, not redistributed), -amt to
\* ExpectedTotal (via the -acc_slashed term). Identity preserved.
\* Pre-condition: d has >= amt locked. Models the FA5/FA6 slash at
\* chain.cpp:1395 + the EquivocationApply / AbortApply stake debits.
SlashStake(d, amt) ==
    /\ steps < MaxSteps
    /\ d \in Domains
    /\ amt \in 1..MaxDelta
    /\ locked[d] >= amt
    /\ locked'      = [locked EXCEPT ![d] = @ - amt]
    /\ acc_slashed' = acc_slashed + amt
    /\ UNCHANGED <<balance, acc_subsidy, acc_inbound, acc_outbound, acc_shielded>>
    /\ steps' = steps + 1

\* Shield(d, amt): §3.22 SHIELD — move amt OUT of d's balance INTO the
\* shielded pool. Debit d's balance by amt AND bump acc_shielded by the
\* same amt. Net: -amt to LiveSupply, -amt to ExpectedTotal (via the
\* -acc_shielded term). Identity preserved. Pre-condition: d has >= amt
\* balance (the S-049-checked `cost = A + fee`, `sender.balance >= cost`
\* debit at chain.cpp:1025-1037). This is the ONE structurally-outbound
\* shield direction — value leaves the transparent sum for the pool.
Shield(d, amt) ==
    /\ steps < MaxSteps
    /\ d \in Domains
    /\ amt \in 1..MaxDelta
    /\ balance[d] >= amt
    /\ balance'      = [balance EXCEPT ![d] = @ - amt]
    /\ acc_shielded' = acc_shielded + amt
    /\ UNCHANGED <<locked, acc_subsidy, acc_inbound, acc_slashed, acc_outbound>>
    /\ steps' = steps + 1

\* Unshield(d, amt): §3.22b UNSHIELD — move amt from the shielded pool
\* BACK into d's balance (a note's public amount returned to a transparent
\* recipient). Credit d's balance by amt AND DECREMENT acc_shielded by the
\* same amt. Net: +amt to LiveSupply, +amt to ExpectedTotal (the
\* -acc_shielded term shrinks). Identity preserved. Pre-condition:
\* acc_shielded >= amt — the pool holds at least amt. This is the Pedersen-
\* binding guarantee (ShieldedPoolSoundness SP-7/SP-12): a note cannot
\* withdraw more than it shielded, so acc_shielded never wraps below 0
\* (chain.cpp:1067-1073/1081). The ONE action that DECREASES an accumulator.
Unshield(d, amt) ==
    /\ steps < MaxSteps
    /\ d \in Domains
    /\ amt \in 1..MaxDelta
    /\ acc_shielded >= amt
    /\ balance'      = [balance EXCEPT ![d] = @ + amt]
    /\ acc_shielded' = acc_shielded - amt
    /\ UNCHANGED <<locked, acc_subsidy, acc_inbound, acc_slashed, acc_outbound>>
    /\ steps' = steps + 1

\* ConfidentialTransfer(d, amt): §3.22c CONFIDENTIAL_TRANSFER — pool->pool
\* transfer; only the PUBLIC fee `amt` leaves the pool back to a transparent
\* creator balance d. Structurally identical to Unshield (credit d's
\* balance + decrement acc_shielded by amt) but a DISTINCT apply branch
\* (the hidden n_in->m note re-shuffle is conservation-internal to the pool
\* and invisible to the six-term supply identity — only the fee crosses the
\* transparent boundary). Net: +amt to LiveSupply, +amt to ExpectedTotal.
\* Identity preserved. Pre-condition: acc_shielded >= amt (Pedersen binding
\* bounds the fee below the pool balance; chain.cpp:1166-1172).
ConfidentialTransfer(d, amt) ==
    /\ steps < MaxSteps
    /\ d \in Domains
    /\ amt \in 1..MaxDelta
    /\ acc_shielded >= amt
    /\ balance'      = [balance EXCEPT ![d] = @ + amt]
    /\ acc_shielded' = acc_shielded - amt
    /\ UNCHANGED <<locked, acc_subsidy, acc_inbound, acc_slashed, acc_outbound>>
    /\ steps' = steps + 1

----------------------------------------------------------------------------
\* Next-state relation. All ten apply-layer actions in arbitrary
\* interleaving. TLC enumerates the composition.

Next ==
    \/ \E from, to \in Domains, amt \in 1..MaxDelta : Transfer(from, to, amt)
    \/ \E d \in Domains, amt \in 1..MaxDelta : StakeLock(d, amt)
    \/ \E d \in Domains, amt \in 1..MaxDelta : StakeUnlock(d, amt)
    \/ \E d \in Domains, amt \in 1..MaxDelta : MintSubsidy(d, amt)
    \/ \E d \in Domains, amt \in 1..MaxDelta : InboundReceipt(d, amt)
    \/ \E d \in Domains, amt \in 1..MaxDelta : OutboundDebit(d, amt)
    \/ \E d \in Domains, amt \in 1..MaxDelta : SlashStake(d, amt)
    \/ \E d \in Domains, amt \in 1..MaxDelta : Shield(d, amt)
    \/ \E d \in Domains, amt \in 1..MaxDelta : Unshield(d, amt)
    \/ \E d \in Domains, amt \in 1..MaxDelta : ConfidentialTransfer(d, amt)

\* Fairness on the accumulator-growing actions drives the
\* Prop_SupplyAlwaysCloses temporal witness (the identity holds in every
\* reachable state regardless of which actions fire). MintSubsidy +
\* InboundReceipt are the supply-growing actions; weak fairness on them
\* guarantees the model exercises the +accumulator branches rather than
\* stuttering forever on Transfer.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ \A d \in Domains, amt \in 1..MaxDelta : WF_vars(MintSubsidy(d, amt))

----------------------------------------------------------------------------
\* Invariants.

\* T-U1: Type invariant. All balances, stakes, and accumulators are
\* Nat-valued and bounded so TLC's state space is finite. The ceiling on
\* LiveSupply-bearing variables is GenesisTotal + the cumulative mintable
\* amount (subsidy + inbound) over MaxSteps actions.
Inv_TypeOK ==
    LET ceil == GenesisTotal + 2 * MaxDelta * MaxSteps IN
    /\ balance \in [Domains -> 0..ceil]
    /\ locked  \in [Domains -> 0..ceil]
    /\ acc_subsidy  \in 0..(MaxDelta * MaxSteps)
    /\ acc_inbound  \in 0..(MaxDelta * MaxSteps)
    /\ acc_slashed  \in 0..(MaxDelta * MaxSteps)
    /\ acc_outbound \in 0..(MaxDelta * MaxSteps)
    \* acc_shielded is bounded by the cumulative SHIELD-able amount: only
    \* Shield increments it (by <= MaxDelta per step, <= MaxSteps steps);
    \* Unshield / ConfidentialTransfer only decrement it. Same ceiling as
    \* the four monotone accumulators. Its >= 0 lower bound (Nat) is the
    \* Pedersen-binding pre-condition acc_shielded >= amt on every decrement.
    /\ acc_shielded \in 0..(MaxDelta * MaxSteps)
    /\ steps \in 0..MaxSteps

\* T-U2: THE headline. The six-term A1 unitary-supply identity. At every
\* reachable state, the live supply (balances + locked stake) equals the
\* genesis baseline plus the net of the five delta accumulators. This is
\* the exact `live_total_supply() == expected_total()` assertion at
\* chain.cpp:1866-1892, composed across all six accumulators moving in
\* arbitrary interleaving.
\*
\* Written with the subtracted terms (slashed + outbound + shielded) moved
\* to the LEFT so both sides are manifestly Nat-valued (no subtraction
\* crosses zero — see Inv_NoNegativeUnderflow). Adding acc_shielded to the
\* LHS is exactly folding the §3.22 -accumulated_shielded term of
\* expected_total() (chain.hpp:596) into the Nat-safe rearrangement.
Inv_A1UnitarySupply ==
    LiveSupply + acc_slashed + acc_outbound + acc_shielded
        = GenesisTotal + acc_subsidy + acc_inbound

\* T-U3: AccumulatorsMonotone (action-level). Each of the FOUR monotone
\* delta accumulators is monotone non-decreasing across every step. The C++
\* tracks RUNNING TOTALS via `+=` (chain.cpp:1862-1864); no apply action
\* ever resets or decrements them. GenesisTotal is a fixed constant and
\* is monotone trivially.
\*
\* acc_shielded is DELIBERATELY ABSENT from this property: it is the one
\* TWO-DIRECTIONAL accumulator (Shield increments, Unshield /
\* ConfidentialTransfer decrement — chain.cpp:1037/1081/1172), so a
\* `acc_shielded' >= acc_shielded` conjunct would be FALSE and TLC would
\* (correctly) report a violation. Its safety property is non-negativity
\* (0 <= acc_shielded, enforced by the acc_shielded >= amt decrement
\* pre-condition), captured by Inv_TypeOK / Inv_NoNegativeUnderflow, not
\* monotonicity.
Inv_AccumulatorsMonotone ==
    [][ /\ acc_subsidy'  >= acc_subsidy
        /\ acc_inbound'  >= acc_inbound
        /\ acc_slashed'  >= acc_slashed
        /\ acc_outbound' >= acc_outbound
      ]_vars

\* T-U4: NoNegativeUnderflow. The added terms always dominate the three
\* subtracted terms, so ExpectedTotal stays in Nat and the C++ uint64
\* subtractions at chain.cpp:1866-1892 cannot wrap. Equivalent to "burned +
\* sent-out + shielded value never exceeds genesis + minted + received-in
\* value", which holds because every SlashStake / OutboundDebit / Shield is
\* gated on a sufficient locked / balance pre-condition (you cannot slash,
\* send, or shield more than exists), and every Unshield /
\* ConfidentialTransfer is gated on acc_shielded >= amt. This is the
\* ExpectedTotalWellDefined ET-1 domination bound L + O + Sh <= G + S + I.
Inv_NoNegativeUnderflow ==
    /\ LiveSupply >= 0
    /\ GenesisTotal + acc_subsidy + acc_inbound
         >= acc_slashed + acc_outbound + acc_shielded

\* T-U5: LiveDecomposition. The live supply is EXACTLY the sum of the two
\* tracked components. A StakeLock / StakeUnlock that moves value between
\* balance and locked leaves LiveSupply unchanged — this invariant is the
\* structural witness that the decomposition is lossless (no value falls
\* between the two components).
Inv_LiveDecomposition ==
    LiveSupply = SumBalances + SumStakes

\* T-U6 / Prop_SupplyAlwaysCloses: temporal restatement of T-U2 as a
\* []-claim, mirroring the dual treatment in FB10 / FB11. Across every
\* reachable state the ledger closes.
Prop_SupplyAlwaysCloses ==
    [](LiveSupply + acc_slashed + acc_outbound + acc_shielded
        = GenesisTotal + acc_subsidy + acc_inbound)

\* T-U7 / Prop_OnlyAccountedDeltas (action-level): any change in
\* LiveSupply across a step is matched ONE-FOR-ONE by a net change in the
\* accumulator ledger. Formally, the delta of LiveSupply equals the delta
\* of (acc_subsidy + acc_inbound - acc_slashed - acc_outbound -
\* acc_shielded). Since both sides of Inv_A1UnitarySupply are preserved,
\* their deltas are equal; this property states that explicitly at the
\* action layer, ruling out any off-ledger mint or burn — a Shield that
\* moved value out of live without booking it in acc_shielded, or an
\* Unshield that credited a balance without drawing the pool down, would
\* both trip this.
\*
\* Encoded in a manifestly Nat-safe additive form (no subtraction appears
\* anywhere, so nothing can truncate at zero inside the temporal
\* operator): the change in the left-hand side of the identity
\* (LiveSupply + slashed + outbound + shielded) equals the change in the
\* right-hand accumulators (subsidy + inbound), with GenesisTotal fixed.
\* Written by moving each primed/unprimed pair to opposite sides so both
\* sides are pure sums:
\*
\*   (Live' + slashed' + outbound' + shielded') + (subsidy + inbound)
\*     = (Live + slashed + outbound + shielded) + (subsidy' + inbound')
\*
\* This is exactly "every unit that enters or leaves the live pool is
\* booked in some accumulator" — the no-off-ledger-mint-or-burn claim.
\* acc_shielded sits with the subtracted terms on the LHS: a Shield's
\* -amt to Live is matched by its +amt to shielded (LHS group fixed), and
\* an Unshield's +amt to Live is matched by its -amt to shielded.
Prop_OnlyAccountedDeltas ==
    [][ (LiveSupply' + acc_slashed' + acc_outbound' + acc_shielded') + (acc_subsidy + acc_inbound)
          = (LiveSupply + acc_slashed + acc_outbound + acc_shielded) + (acc_subsidy' + acc_inbound')
      ]_vars

============================================================================
\* Cross-references.
\*
\* FB10 (FeeAccounting.tla) / FB11 (SubsidyDistribution.tla) — model the
\* +accumulated_subsidy mint slice. FB46's MintSubsidy is the same credit;
\* FB46 additionally composes it against the five other accumulators
\* (genesis / inbound / slashed / outbound / shielded).
\*
\* FB14 (CrossShardReceiptDedup.tla) — models the +accumulated_inbound
\* credit behind a dedup gate. FB46's InboundReceipt is the post-gate
\* mutation.
\*
\* FB15 (EquivocationApply.tla) / FB16 (AbortApply.tla) — model the
\* +accumulated_slashed burn behind the slash discriminator. FB46's
\* SlashStake is the post-discriminator stake debit.
\*
\* FB18 (CrossShardOutboundApply.tla) — models the +accumulated_outbound
\* debit. FB46's OutboundDebit is the same src-side debit.
\*
\* §3.22 shielded pool — FB46's Shield / Unshield / ConfidentialTransfer
\* model the SHIELD / UNSHIELD / CONFIDENTIAL_TRANSFER arms
\* (chain.cpp:1037/1081/1172) that move value between the transparent live
\* sum and accumulated_shielded, the one two-directional accumulator.
\* ShieldedPoolSoundness (SP-7/SP-12) is the Pedersen-binding companion the
\* acc_shielded >= amt decrement pre-condition abstracts; ExpectedTotal-
\* WellDefined ET-1..ET-4 is the uint64 no-underflow totality of the
\* resulting six-term RHS.
\*
\* FB20 (MultiEventComposition.tla) — composes the four EVENT CLASSES in
\* canonical apply order; its Inv_A1Conservation is a stake-bound, not the
\* six-term supply identity. FB46 is the orthogonal composition: it
\* composes the six ACCUMULATOR TERMS into the exact
\* live_total_supply() == expected_total() ledger-closure assertion.
\*
\* FB54 (CrossShardSupplyConservation.tla) — the K-shard composition of
\* THIS single-shard ledger; carries the same shard-local acc_shielded term
\* (single-shard-only, no cross-shard netting — chain.cpp:1059).
\*
\* The C++ enforcement point is the post-apply assertion at
\* src/chain/chain.cpp:1866-1892 (live_total_supply() == expected_total(),
\* throwing the "unitary-balance invariant violated" diagnostic on
\* mismatch). The runtime witnesses are tools/test_cross_shard_supply_invariant.sh
\* and the operator_supply_check.sh read-only auditor.
============================================================================
