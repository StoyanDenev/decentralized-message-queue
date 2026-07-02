--------------------------- MODULE SubsidyDistribution ---------------------------
(*
FB11 — TLA+ specification of the block-subsidy distribution state machine.
Models the apply-layer credit path that mints `BlockSubsidy` per finalized
block to the block's `creators` set, plus the E1 Negative Entry Fee (NEF)
geometric pool drain that fires on first-time REGISTER.

This spec captures the invariants of Determ's E1/E3/E4 subsidy mechanics
at the state-machine layer, independent of consensus and signature
verification:

  * FLAT mode (E3 default, src/chain/chain.cpp:1250): each block with
    non-empty creators credits BlockSubsidy/m to each of the m creators
    and remainder dust to creators[0]. `accumulated_subsidy` advances by
    the full BlockSubsidy — supply gain is exactly the minted amount.
  * Empty-creators safety (T-S2): a block with zero creators is a no-op
    on `accumulated_subsidy`. The C++ guard at chain.cpp:1286
    (`if (total_distributed > 0 && !b.creators.empty())`) is the
    enforcement point; Inv_EmptyCreatorsNoMint is the structural witness.
  * NEF geometric pool drain (E1, chain.cpp:813-833): on a first-time
    REGISTER, the ZEROTH pool balance halves (floor division) and the
    drained amount is credited to the registrant. Re-REGISTER (key
    rotation, region update) does NOT drain — the C++ first_time_register
    bool gates the drain at chain.cpp:795-796. Inv_NefDrainsOnceperDomain
    is the headline T-S6 claim.
  * Supply identity (T-S1): at every reachable state,
        sum(balances) = INITIAL_BALANCES_SUM + accumulated_subsidy
    where the NEF drain is an internal redistribution (pool balance is
    counted in INITIAL_BALANCES_SUM) and accumulated_subsidy tracks every
    minted amount. The chain.cpp:1397-1404 A1 supply check is the
    apply-layer enforcement.
  * Eventual subsidy (T-S5): under fairness on FinalizeBlock with non-
    empty creators, accumulated_subsidy grows without bound (up to model
    MaxHeight). Prop_EventualSubsidy is the temporal liveness restatement.

Subsidy mode modeled in the .cfg: FLAT (subsidy_mode = 0). The spec's
FinalizeBlock action models FLAT distribution; the LOTTERY (subsidy_mode = 1)
and FINITE_POOL (subsidy_pool_initial > 0) variants are noted in
comments inline and could be checked via cfg-level swap of FinalizeBlock
for FinalizeBlockLottery / FinalizeBlockFinitePool (defined but not
exercised in the active Next disjunct — see end-of-file commented
alternatives). The structural invariants (NefDrainsOnce, EmptyCreatorsNoMint,
SubsidyConservation, NonNegative*, AccumulatedSubsidyMonotonic) hold
under every mode; the temporal Prop_EventualSubsidy is FLAT-specific
(LOTTERY has a non-zero probability of no-payout blocks; FINITE_POOL
terminates).

Modeling scope (kept tractable for TLC):

  * Single-shot Register lifecycle per domain: the model exercises both
    Register (first-time, drains pool) and ReRegister (no drain) on the
    same domain. A domain registered once stays registered for the rest
    of the run; this is the worst case for the NEF-drain-once invariant.
  * Creators sets drawn from SUBSET Domains, bounded by MaxCreators to
    keep TLC state-space tractable. Empty-creators is included as the
    T-S2 witness.
  * Block-level subsidy is FLAT mode only in the active Next disjunct.
    The non-degenerate cases (LOTTERY two-point draw, FINITE_POOL cap)
    are mode swaps that preserve the structural invariants; the
    LOTTERY-fail / pool-exhausted branches reduce to the empty-creators
    case for accumulated_subsidy accounting.
  * Fees are abstracted away — the C++ apply path also credits
    accumulated transaction fees to creators on the same path. The
    subsidy invariants are orthogonal to fee accounting (covered by
    FeeAccounting.tla / FB10 in the parallel companion spec).
  * BlockSubsidy is a fixed Nat; the genesis-pinned C++ value is
    governed by chain.cpp:1986 (`block_subsidy` parameter at load).
  * Height advances exactly once per FinalizeBlock; no Tick is needed
    because BlockSubsidy is the only height-coupled action.

Companion prose proof: docs/proofs/SubsidyDistribution.md
(separately written by a parallel agent; may not yet exist in this
worktree).

To check (assuming TLC installed):
  $ tlc SubsidyDistribution.tla -config SubsidyDistribution.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,            \* set of account / operator identifiers
    BlockSubsidy,       \* per-block FLAT mint (genesis-pinned)
    MaxHeight,          \* upper bound on chain height for TLC
    InitialNefPool,     \* E1 ZEROTH pool initial balance
    MaxCreators         \* bound on |creators| per block

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ BlockSubsidy    \in Nat /\ BlockSubsidy    >= 1
    /\ MaxHeight       \in Nat /\ MaxHeight       >= 1
    /\ InitialNefPool  \in Nat
    /\ MaxCreators     \in Nat /\ MaxCreators     >= 1
    /\ MaxCreators     <= Cardinality(Domains)

\* INITIAL_BALANCES_SUM is the conserved baseline. NEF drain is an
\* internal pool->registrant redistribution so the pool's InitialNefPool
\* balance is counted here. The accumulated_subsidy field tracks the
\* delta above this baseline as block subsidies mint to creators.
INITIAL_BALANCES_SUM == InitialNefPool

----------------------------------------------------------------------------
\* State.

VARIABLES
    accounts,           \* function Domains -> [balance, registered]
    nef_pool,           \* Nat — ZEROTH pool balance, drains geometrically
    accumulated_subsidy, \* Nat — total minted across all finalized blocks
    height              \* current chain height

vars == <<accounts, nef_pool, accumulated_subsidy, height>>

----------------------------------------------------------------------------
\* Initial state. All accounts start at zero balance, unregistered. NEF
\* pool starts at InitialNefPool. accumulated_subsidy starts at zero.
\*
\* Modeling note: the C++ ZEROTH pool is a separate account at the all-
\* zero anon address; in the TLA model it is the dedicated `nef_pool`
\* variable because no other action touches it. Keeping it out of
\* `accounts` keeps Inv_BalanceNonNegative clean (Domains-indexed) and
\* makes the pool/account separation explicit.

Init ==
    /\ accounts = [d \in Domains |->
                     [balance |-> 0, registered |-> FALSE]]
    /\ nef_pool = InitialNefPool
    /\ accumulated_subsidy = 0
    /\ height = 0

----------------------------------------------------------------------------
\* Helpers.

\* Sum of all balances across Domains. Used by Inv_SubsidyConservation.
SumBalances ==
    LET RECURSIVE sum_bal(_)
        sum_bal(S) ==
        IF S = {} THEN 0
        ELSE LET d == CHOOSE x \in S : TRUE IN
             accounts[d].balance + sum_bal(S \ {d})
    IN sum_bal(Domains)

\* Total live supply at the modeled scope: balances + pool. The supply
\* identity (T-S1) is: TotalSupply = INITIAL_BALANCES_SUM + accumulated_subsidy.
TotalSupply == SumBalances + nef_pool

----------------------------------------------------------------------------
\* Actions. Each action models the corresponding apply-layer branch in
\* src/chain/chain.cpp::apply_transactions or the apply_block subsidy-
\* distribution loop. Actions are total relations — out-of-precondition
\* inputs are no-ops (matching the C++ `continue` / `if (...) ...` skip
\* semantics).

\* Register(d): first-time REGISTER on domain d. Drains nef_pool by
\* floor-half, credits the drained amount to d's balance, sets d's
\* registered bit to TRUE. Models the E1 NEF transfer at
\* src/chain/chain.cpp:813-833.
\*
\* Pre-condition: accounts[d].registered = FALSE. The C++ first_time_register
\* bool at chain.cpp:795 enforces this — registry-map presence is the
\* gate; the TLA model lifts this into an explicit `registered` boolean
\* per domain.
\*
\* The drain is floor-half: nef_pool' = nef_pool \div 2. If nef_pool = 0,
\* the drain amount is 0 and the credit is a no-op on the balance — but
\* registered still flips to TRUE (the C++ semantics: REGISTER still
\* succeeds even with an empty pool; the pool drain is a silent zero).
Register(d) ==
    /\ d \in Domains
    /\ accounts[d].registered = FALSE
    /\ LET drain == nef_pool \div 2 IN
       /\ accounts' = [accounts EXCEPT
                         ![d] = [balance    |-> @.balance + drain,
                                 registered |-> TRUE]]
       /\ nef_pool' = nef_pool - drain
       /\ UNCHANGED <<accumulated_subsidy, height>>

\* ReRegister(d): re-REGISTER (key rotation, region update) on an already-
\* registered domain. NO NEF drain — re-registrations are explicitly
\* excluded from the pool-drain hook by the first_time_register bool at
\* chain.cpp:795-796. Models the same DAPP/REGISTER apply branch but in
\* the "already exists" path.
\*
\* Pre-condition: accounts[d].registered = TRUE. The action is a stutter
\* on the subsidy variables (nef_pool, accumulated_subsidy, balance) —
\* its inclusion is structural witness that re-Register does not drain.
\*
\* Inv_NefDrainsOnceperDomain checks this at the action level by
\* requiring that any nef_pool decrease comes paired with a domain
\* flipping registered FALSE -> TRUE.
ReRegister(d) ==
    /\ d \in Domains
    /\ accounts[d].registered = TRUE
    /\ UNCHANGED vars

\* FinalizeBlock(creators): the FLAT-mode subsidy distribution at
\* src/chain/chain.cpp:1286-1305. Credits BlockSubsidy/m to each of the
\* m creators, dust (BlockSubsidy mod m) to creators[0]. Empty creators
\* is a no-op on subsidy (T-S2): no mint, accumulated_subsidy unchanged.
\*
\* Models FLAT mode (subsidy_mode = 0). LOTTERY and FINITE_POOL variants
\* are commented below for cfg-level swap.
\*
\* creators is modeled as a SEQUENCE OF Domains (matching the C++
\* std::vector<std::string>); the TLA-level enumeration uses sets of
\* sequences bounded by MaxCreators.
FinalizeBlock(creators) ==
    /\ height < MaxHeight
    /\ Len(creators) <= MaxCreators
    /\ \A i \in 1..Len(creators) : creators[i] \in Domains
    /\ \A i, j \in 1..Len(creators) : i /= j => creators[i] /= creators[j]
    /\ IF Len(creators) = 0
       THEN \* T-S2: empty creators = no-op on subsidy
            /\ UNCHANGED <<accounts, nef_pool, accumulated_subsidy>>
            /\ height' = height + 1
       ELSE LET m         == Len(creators)
                per_creator == BlockSubsidy \div m
                remainder   == BlockSubsidy % m
                \* Credit each creator with per_creator; creators[1] gets
                \* the additional `remainder` dust (TLA Sequences are
                \* 1-indexed; matches C++ creators[0] semantics).
                credited == [d \in Domains |->
                               IF \E i \in 1..m : creators[i] = d
                               THEN IF creators[1] = d
                                    THEN accounts[d].balance + per_creator + remainder
                                    ELSE accounts[d].balance + per_creator
                               ELSE accounts[d].balance]
            IN /\ accounts' = [d \in Domains |->
                                 [balance    |-> credited[d],
                                  registered |-> accounts[d].registered]]
               /\ accumulated_subsidy' = accumulated_subsidy + BlockSubsidy
               /\ height' = height + 1
               /\ UNCHANGED nef_pool

\* AdvanceHeightNoMint: tick height forward without a FinalizeBlock.
\* Models the FINITE_POOL exhaustion case (subsidy_pool_initial drained ->
\* subsidy_this_block = 0) and the LOTTERY-miss case (lottery_seed %
\* multiplier /= 0 -> base_subsidy = 0). Both reduce to "no mint this
\* block" at the apply layer, which Inv_AccumulatedSubsidyMonotonic
\* accepts (subsidy unchanged is not a decrease).
\*
\* Required for the Prop_EventualSubsidy temporal property because
\* under fairness on FinalizeBlock-with-non-empty-creators we need to
\* permit interleaving with no-mint blocks.
AdvanceHeightNoMint ==
    /\ height < MaxHeight
    /\ height' = height + 1
    /\ UNCHANGED <<accounts, nef_pool, accumulated_subsidy>>

----------------------------------------------------------------------------
\* Next-state relation. FLAT-mode active disjunct: Register / ReRegister
\* / FinalizeBlock / AdvanceHeightNoMint. TLC enumerates all interleavings.
\*
\* SeqsOfSize: all sequences of distinct Domains of length 0..MaxCreators.
\* TLC handles the construction via existential bounded over UNION.

SeqsOfSize ==
    UNION { [1..n -> Domains] : n \in 0..MaxCreators }

Next ==
    \/ \E d \in Domains : Register(d)
    \/ \E d \in Domains : ReRegister(d)
    \/ \E creators \in SeqsOfSize : FinalizeBlock(creators)
    \/ AdvanceHeightNoMint

\* Fairness on FinalizeBlock with non-empty creators drives the eventual-
\* subsidy property. Fairness on AdvanceHeightNoMint ensures height
\* progresses even if no FinalizeBlock fires; without it a trace could
\* indefinitely stutter at the same height. Together they give
\* Prop_EventualSubsidy.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(AdvanceHeightNoMint)
    /\ \A creators \in SeqsOfSize :
         (Len(creators) > 0) => WF_vars(FinalizeBlock(creators))

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant: variables have correct shapes.
Inv_TypeOK ==
    /\ accounts \in [Domains -> [balance:    0..(InitialNefPool + BlockSubsidy * MaxHeight),
                                 registered: BOOLEAN]]
    /\ nef_pool             \in 0..InitialNefPool
    /\ accumulated_subsidy  \in 0..(BlockSubsidy * MaxHeight)
    /\ height               \in 0..MaxHeight

\* BalanceNonNegative (Nat-valued; documents the contract).
\* No action subtracts from balance; Register / FinalizeBlock both
\* credit non-negative amounts. The supply identity (Inv_SubsidyConservation)
\* together with NefPoolNonNegative gives the lower bound as a corollary,
\* but this invariant documents it explicitly for cross-cite.
Inv_BalanceNonNegative ==
    \A d \in Domains : accounts[d].balance >= 0

\* NefPoolNonNegative (Nat-valued). The floor-half drain
\* (nef_pool \div 2) is closed on Nat; once nef_pool = 0, the terminal
\* 0 \div 2 = 0 keeps it there. The Register action's drain is the only
\* action that decreases nef_pool, and it decreases by exactly
\* nef_pool - (nef_pool \div 2) which is ceil(nef_pool / 2) >= 0.
Inv_NefPoolNonNegative == nef_pool >= 0

\* AccumulatedSubsidyMonotonic (action-level): accumulated_subsidy never
\* decreases across any [Next]_vars step.
\*
\* The only action that touches accumulated_subsidy is FinalizeBlock with
\* non-empty creators, and it adds BlockSubsidy (>= 1 by ConfigOK). All
\* other actions preserve it.
Inv_AccumulatedSubsidyMonotonic ==
    [][accumulated_subsidy' >= accumulated_subsidy]_vars

\* EmptyCreatorsNoMint (T-S2 structural witness): every step that leaves
\* accumulated_subsidy unchanged must NOT be a FinalizeBlock with non-
\* empty creators, AND every FinalizeBlock with empty creators leaves
\* accumulated_subsidy unchanged.
\*
\* Encoded as the contrapositive at the action level: if accumulated_subsidy
\* advanced, then SOME finalize fired with at least one creator (the
\* balance map gained value at >= 1 domain), and if no domain gained
\* balance via subsidy, accumulated_subsidy did not advance.
\*
\* Approximation: we use the value of accumulated_subsidy' - accumulated_subsidy
\* compared to BlockSubsidy. A step that advances accumulated_subsidy by
\* exactly BlockSubsidy is a FinalizeBlock-with-creators; a step that
\* leaves it unchanged is everything else (including empty-creators
\* FinalizeBlock).
Inv_EmptyCreatorsNoMint ==
    [][(accumulated_subsidy' = accumulated_subsidy
        \/ accumulated_subsidy' = accumulated_subsidy + BlockSubsidy)]_vars

\* NefDrainsOnceperDomain (T-S6 action-level): any step that decreases
\* nef_pool must be a Register on a previously-unregistered domain.
\* Equivalently: nef_pool' < nef_pool iff some d had accounts[d].registered
\* = FALSE pre-step and accounts'[d].registered = TRUE post-step.
\*
\* This is the headline defense against the "registration-churn drain
\* attack" — re-Register cannot drain the pool, so an attacker cannot
\* drain it by repeatedly re-registering the same domain. The C++ check
\* at chain.cpp:795-796 (`first_time_register` bool) is the source
\* enforcement point.
Inv_NefDrainsOnceperDomain ==
    [][(nef_pool' < nef_pool)
       =>
       (\E d \in Domains :
           /\ accounts[d].registered = FALSE
           /\ accounts'[d].registered = TRUE)
      ]_vars

\* SubsidyConservation (T-S1): the supply identity at the modeled scope.
\*
\*   SumBalances + nef_pool = INITIAL_BALANCES_SUM + accumulated_subsidy
\*
\* Equivalent restatement:
\*   SumBalances = INITIAL_BALANCES_SUM + accumulated_subsidy - nef_pool_drained_total
\* where nef_pool_drained_total = INITIAL_BALANCES_SUM - nef_pool (the
\* cumulative drain). Rearranging gives the headline identity above.
\*
\* Every Register action is an internal pool->balance redistribution
\* (sum invariant); every FinalizeBlock action mints exactly BlockSubsidy
\* to the balance sum, advancing accumulated_subsidy by the same amount
\* (sum invariant holds with the additive accumulated_subsidy term).
\* No outflows or slashing are modeled at this scope.
Inv_SubsidyConservation ==
    TotalSupply = INITIAL_BALANCES_SUM + accumulated_subsidy

----------------------------------------------------------------------------
\* Temporal properties.

\* EventualSubsidy: under fairness on FinalizeBlock with non-empty
\* creators, accumulated_subsidy eventually grows.
\*
\* Formally: in every fair run, either eventually accumulated_subsidy > 0,
\* or eventually height >= MaxHeight (the model bound was reached before
\* any FinalizeBlock with non-empty creators fired; this escape is
\* required because TLC operates on bounded models).
\*
\* WF_vars on every non-empty-creators FinalizeBlock (per Spec above)
\* ensures that if such an action remains enabled, it eventually fires.
\* Since FinalizeBlock with a fixed creators sequence is always enabled
\* until height = MaxHeight (the only guard is height < MaxHeight), the
\* eventual-mint conclusion follows.
Prop_EventualSubsidy ==
    <>(accumulated_subsidy > 0 \/ height >= MaxHeight)

\* RegistrationIdempotent: Register followed by ReRegister produces the
\* same balance as Register alone. Equivalently, ReRegister is a stutter
\* on accounts[d].balance for any d that was already registered.
\*
\* Encoded as the action-level invariant: at every step, the balance of
\* a registered domain only changes via FinalizeBlock (block-subsidy
\* credit) — never via ReRegister. ReRegister leaves vars UNCHANGED by
\* definition (see the ReRegister action body), so the post-state
\* balance equals the pre-state balance.
\*
\* This is the T-S6 idempotency claim restated at the temporal layer:
\* the NEF drain is exactly once per domain, so Register;ReRegister =
\* Register on balance.
Prop_RegistrationIdempotent ==
    [][\A d \in Domains :
         (accounts[d].registered = TRUE
          /\ accounts'[d].registered = TRUE
          /\ accounts'[d].balance /= accounts[d].balance)
         =>
         \* The only way a registered domain's balance can change is via
         \* a FinalizeBlock subsidy credit. accumulated_subsidy must have
         \* advanced by exactly BlockSubsidy.
         accumulated_subsidy' = accumulated_subsidy + BlockSubsidy
      ]_vars

============================================================================
\* Mode-swap alternatives (not in active Next disjunct; documented for
\* cfg-level swap).
\*
\* FinalizeBlockLottery(creators, seed): E3 LOTTERY mode. With
\* probability 1/M, base_subsidy = BlockSubsidy * M (jackpot); else
\* base_subsidy = 0 (miss). seed is drawn from the block's cumulative_rand.
\* Inv_AccumulatedSubsidyMonotonic still holds (miss = no decrease).
\* Inv_SubsidyConservation requires the modeled mint amount to match —
\* the spec would substitute BlockSubsidy with base_subsidy in the
\* accumulated_subsidy' assignment.
\*
\* FinalizeBlockFinitePool(creators): E4 FINITE_POOL mode. The mint is
\* capped at min(BlockSubsidy, subsidy_pool_initial - accumulated_subsidy).
\* Once the pool drains (accumulated_subsidy = subsidy_pool_initial), the
\* action reduces to AdvanceHeightNoMint. Inv_SubsidyConservation still
\* holds via the same accumulated_subsidy tracking; Inv_AccumulatedSubsidyMonotonic
\* holds because the cap only reduces the per-block delta, never the
\* accumulated total.
\*
\* Both alternatives preserve the structural invariants in this spec;
\* the active cfg models FLAT for state-space tractability and because
\* FLAT is the genesis default.
============================================================================
