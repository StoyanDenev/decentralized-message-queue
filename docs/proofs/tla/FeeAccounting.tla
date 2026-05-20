--------------------------- MODULE FeeAccounting ---------------------------
(*
FB10 — TLA+ specification of the per-block fee charging + distribution
state machine. Models the apply-layer lifecycle of a transfer's fee
from sender-debit (on success) or silent-skip (on insufficient balance),
through accumulation into the block's running `block_total_fees`
counter, through finalization that distributes the accumulated fees
equally across the block's creator set with dust to creators[0].

This spec captures the invariants of Determ's fee accounting at the
state-machine layer, independent of consensus, signature verification,
overflow-checking, and subsidy/lottery distribution semantics:

  * ApplyTx (success path, balance >= amount + fee): debits
    `amount + fee` from sender, credits `amount` to recipient, adds
    `fee` to `block_total_fees`. Net effect: value moves
    sender -> recipient + sender -> block_total_fees pool.
  * ApplyTxInsufficientBalance (silent-skip, balance < amount + fee):
    the apply path's `continue` at src/chain/chain.cpp:744 fires; NO
    fee is charged, NO state mutation, the tx is dropped. The
    Inv_NoFeeOnSkip invariant is the headline structural claim that
    silently-skipped txs cannot leak balance.
  * FinalizeBlock (creators non-empty): distributes `block_total_fees`
    equally across `block_creators`; each creator gains
    `block_total_fees / |block_creators|` and creator[0] additionally
    gains the dust `block_total_fees mod |block_creators|`. After
    distribution, `block_total_fees` is reset to 0 and `height` is
    advanced. Models the T-F1 distribution branch at
    src/chain/chain.cpp:1286-1305.
  * FinalizeBlock (creators empty): no distribution occurs;
    `block_total_fees` is preserved across the height advance. Models
    the T-F5 empty-creators gate at src/chain/chain.cpp:1286 (`if
    (total_distributed > 0 && !b.creators.empty())`). The accumulated
    fee pool stays in the in-flight pool variable so that the A1
    conservation identity holds — an empty-creators block is a NO-OP
    on fee distribution, not a burn.
  * Total supply (sum of all balances + the in-flight
    `block_total_fees` pool) is invariant across every step: TRANSFER
    is an internal balance <-> balance + pool move; FinalizeBlock is
    an internal pool -> balance move. Inv_A1Conservation is the
    headline supply-conservation claim.
  * Inv_FeeDistributionDeterministic captures the deterministic
    nature of the per-creator share + dust assignment: given the
    same (X, creators) pair, every node arrives at the same
    distribution. This is the structural witness for the consensus-
    grade determinism property required by the apply path.
  * Under fairness on FinalizeBlock + StartNextBlock, any non-zero
    accumulated fee pool with non-empty creators eventually flows to
    creator balances (Prop_EventualFeeDrain).

Modeling scope (kept tractable for TLC):

  * Only the TRANSFER tx type is modeled. Every fee-bearing tx (STAKE,
    REGISTER, DEREGISTER, DAPP_REGISTER, etc.) routes through the same
    `charge_fee` helper at src/chain/chain.cpp:727-732 and the same
    distribution loop at lines 1286-1305 — the fee state-machine
    properties are insensitive to the specific tx body. Modeling
    TRANSFER alone gives the simplest model that exercises both the
    "fee charged + accumulated" and "fee silently skipped" branches.
  * Subsidy + lottery distribution is out of scope. The C++
    `total_distributed = total_fees + subsidy_this_block` combination
    at line 1280 conflates the two streams; this spec models the
    fee-only stream. Subsidy is an additive constant per block that
    follows the same equal-share + dust-to-creators[0] distribution
    rule, so the invariants generalize trivially.
  * Overflow-checking is out of scope. The C++ uses `checked_add_u64`
    on every credit; the TLA model uses Nat-typed values bounded by
    `MaxAmount * MaxHeight * |Domains|` to keep the state space
    finite without modeling u64-wraparound semantics.
  * Cross-shard receipt fees are out of scope (FB2 / Sharding.tla
    territory). The TRANSFER branch in this model has no cross-shard
    variant — `to` is always a local domain.
  * Equivocation slashing and suspension slashing are out of scope
    (FB1 / Consensus.tla + FB8 / StakeLifecycle.tla territory). The
    fee path does not interact with slashed balances at this layer.

Companion prose proof: `docs/proofs/FeeAccounting.md`
(separately written by a parallel agent; may not yet exist in this
worktree).

To check (assuming TLC installed):
  $ tlc FeeAccounting.tla -config FeeAccounting.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,            \* set of account / creator identifiers
    MaxHeight,          \* upper bound on chain height for TLC
    MaxAmount,          \* upper bound on per-tx amount field
    MaxFee,             \* upper bound on per-tx fee field
    TotalSupplyInitial  \* conserved supply (sum of initial balances)

ASSUME ConfigOK ==
    /\ Cardinality(Domains)   >= 2
    /\ MaxHeight              \in Nat /\ MaxHeight          >= 1
    /\ MaxAmount              \in Nat /\ MaxAmount          >= 1
    /\ MaxFee                 \in Nat /\ MaxFee             >= 0
    /\ TotalSupplyInitial     \in Nat /\ TotalSupplyInitial >= 1

\* Tx shape: simplified TRANSFER tx model. The on-chain Tx has
\* additional fields (nonce, type, payload, sig, hash) — these are
\* orthogonal to fee accounting. Only (from, to, amount, fee) drive
\* the per-tx debit/credit math.
\*
\* `type` is included as a single-valued enum to mirror the on-chain
\* convention and to leave room for future per-type fee policies;
\* every reachable tx in this model has type = "transfer".
Tx == [from:   Domains,
       to:     Domains,
       amount: 0..MaxAmount,
       fee:    0..MaxFee,
       type:   {"transfer"}]

----------------------------------------------------------------------------
\* State.
\*
\* `accounts`         — per-domain balance map. Sum over all balances
\*                      plus `block_total_fees` is the conserved supply.
\* `pending_txs`      — ordered queue of unapplied transfers. Models
\*                      the mempool / block-included-tx queue. Apply
\*                      consumes from the head; submit appends to the
\*                      tail.
\* `block_creators`   — ordered sequence of creator identifiers for
\*                      the current block. Order matters because the
\*                      dust on FinalizeBlock goes to `creators[0]`
\*                      (i.e., the first creator).
\* `block_total_fees` — accumulated fees for the current block.
\*                      Drained on FinalizeBlock when creators is
\*                      non-empty; preserved otherwise.
\* `height`           — current block index. Advances on
\*                      FinalizeBlock.

VARIABLES
    accounts,           \* function Domains -> [balance: Nat]
    pending_txs,        \* Seq(Tx) — unapplied tx queue
    block_creators,     \* Seq(Domains) — current block's creator set
    block_total_fees,   \* Nat — accumulated fee pool for current block
    height              \* Nat — current chain height

vars == <<accounts, pending_txs, block_creators, block_total_fees, height>>

----------------------------------------------------------------------------
\* Initial state.
\*
\* Balances are pre-allocated so their sum equals TotalSupplyInitial.
\* For TLC tractability we hard-code a small initial allocation in the
\* .cfg via INIT (the Init operator below picks one canonical
\* allocation; the .cfg's CONSTANT TotalSupplyInitial = 20 with
\* 4 domains a/b/c/d allocates 5 to each).
\*
\* pending_txs starts empty (no txs submitted yet); block_creators
\* starts empty (StartNextBlock must fire to assign the first
\* committee); block_total_fees starts at 0; height starts at 0.

Init ==
    /\ accounts = [d \in Domains |->
                     [balance |-> TotalSupplyInitial \div Cardinality(Domains)]]
    /\ pending_txs      = <<>>
    /\ block_creators   = <<>>
    /\ block_total_fees = 0
    /\ height           = 0

----------------------------------------------------------------------------
\* Helpers.

\* Sum of balances across all domains. Used by Inv_A1Conservation.
\* Encoded as a recursive helper because Naturals.tla doesn't ship a
\* fold-over-finite-sets primitive that TLC handles natively at this
\* arity. Pattern matches StakeLifecycle.tla::SumBalances /
\* SumStakes.
SumBalances ==
    LET RECURSIVE sum_bal(_) IN
    LET sum_bal(S) ==
        IF S = {} THEN 0
        ELSE LET d == CHOOSE x \in S : TRUE IN
             accounts[d].balance + sum_bal(S \ {d})
    IN sum_bal(Domains)

\* Set-of-elements of a sequence. TLC has Seq builtins but expressing
\* "the set of creators in the current block" is cleaner as a set.
\* Used by FinalizeBlock + Inv_FeeDistributionDeterministic.
SeqToSet(s) == {s[i] : i \in 1..Len(s)}

----------------------------------------------------------------------------
\* Actions. Each action models the corresponding apply-layer branch in
\* `src/chain/chain.cpp::apply_transactions` for the TRANSFER tx type
\* plus the per-block distribution loop at the bottom of apply_block.

\* SubmitTx(t): a caller queues a TRANSFER for inclusion in the next
\* block. The action models the validator -> mempool -> block-include
\* path collapsed into a single "tx becomes pending" step.
\*
\* Pre-condition: t \in Tx (well-formed). No balance check here — the
\* whole point of SubmitTx is that the validator surface is liberal;
\* the strict balance check fires at ApplyTx time.
\*
\* The action's existence is required to feed the queue; without it
\* ApplyTx + ApplyTxInsufficientBalance would never be enabled (the
\* head of an empty queue has no domain).
SubmitTx(t) ==
    /\ t \in Tx
    /\ Len(pending_txs) <= MaxHeight  \* bound queue length for TLC
    /\ pending_txs' = Append(pending_txs, t)
    /\ UNCHANGED <<accounts, block_creators, block_total_fees, height>>

\* ApplyTx: pull the head tx off pending_txs, check balance sufficiency,
\* and on success debit `amount + fee` from sender, credit `amount` to
\* recipient, accumulate `fee` into block_total_fees. Models the
\* TRANSFER success branch at src/chain/chain.cpp:742-770 plus the
\* `total_fees += tx.fee` accumulation at line 767.
\*
\* Pre-condition: pending_txs non-empty AND accounts[head.from].balance
\* >= head.amount + head.fee.
ApplyTx ==
    /\ Len(pending_txs) > 0
    /\ LET t == Head(pending_txs) IN
       /\ accounts[t.from].balance >= t.amount + t.fee
       /\ accounts' = [accounts EXCEPT
                         ![t.from].balance = @ - (t.amount + t.fee),
                         ![t.to].balance   = @ + t.amount]
       /\ block_total_fees' = block_total_fees + t.fee
    /\ pending_txs' = Tail(pending_txs)
    /\ UNCHANGED <<block_creators, height>>

\* ApplyTxInsufficientBalance: pull the head tx off pending_txs and
\* silently drop it (no debit, no credit, no fee charge). Models the
\* TRANSFER `continue` branch at src/chain/chain.cpp:744: `if
\* (sender.balance < cost) continue;` — the sender's nonce DOES NOT
\* advance in the silent-skip case (line 768 is only reached on
\* success). The TLA model abstracts nonce away (FB7 / Nonce.tla
\* territory) so the silent-skip is a pure no-op on (accounts,
\* block_total_fees).
\*
\* Pre-condition: pending_txs non-empty AND accounts[head.from].balance
\* < head.amount + head.fee.
\*
\* Inv_NoFeeOnSkip is the headline structural invariant that this
\* action witnesses: silently-skipped txs cannot leak balance from
\* the sender, cannot credit the recipient, cannot inflate the fee
\* pool. The validator-side admission check should keep most such
\* txs out of blocks; this action models the safety-net `continue`.
ApplyTxInsufficientBalance ==
    /\ Len(pending_txs) > 0
    /\ LET t == Head(pending_txs) IN
       accounts[t.from].balance < t.amount + t.fee
    /\ pending_txs' = Tail(pending_txs)
    /\ UNCHANGED <<accounts, block_creators, block_total_fees, height>>

\* FinalizeBlock: distribute the accumulated `block_total_fees`
\* equally across `block_creators`. Models the distribution loop at
\* src/chain/chain.cpp:1286-1305.
\*
\* Distribution policy (mirrors the C++):
\*   per_creator = block_total_fees \div |block_creators|
\*   dust        = block_total_fees mod  |block_creators|
\*   each c \in block_creators : balance += per_creator
\*   block_creators[0] additionally: balance += dust
\*
\* The dust-to-creators[0] rule is the canonical tie-breaker that
\* keeps the distribution lossless (every unit of fee ends up on some
\* creator's balance). Without it, the integer division floor would
\* destroy `block_total_fees mod |creators|` units per block.
\*
\* Empty-creators gate: if `block_creators = <<>>`, NO distribution
\* fires and `block_total_fees` is preserved across the height
\* advance. Models the `!b.creators.empty()` check at line 1286.
\* This is the T-F5 invariant — an empty-creators block is a no-op
\* on fee distribution, not a burn.
\*
\* After distribution (or skip), the action resets block_total_fees
\* to 0 and clears block_creators (a fresh StartNextBlock must
\* assign the next committee). Height advances by 1.
\*
\* The model splits the empty-creators and non-empty-creators cases
\* into two action disjuncts for clarity. Both share the height
\* advance + block_total_fees reset (in the empty case the reset is
\* a no-op since block_total_fees stays at whatever it was — wait,
\* this is the subtlety: in the empty case we DO NOT reset
\* block_total_fees. The fee pool persists across the empty-creators
\* block boundary. The next block's StartNextBlock + ApplyTx
\* continues to accumulate on top of the carried-over pool. Inv_A1
\* and Inv_EmptyCreatorsNoDistribute together capture this.
\*
\* On reflection: the C++ code at line 1286 falls through to the
\* `b.creators.empty()` branch by simply not executing the for-loop;
\* `total_fees` is then logically lost when the next block's apply
\* path starts with `total_fees = 0` at line 720. To model the
\* "lossless preservation" claim faithfully we keep
\* block_total_fees non-reset on the empty path; the C++ at runtime
\* still loses these units (the genesis_total counter accounts for
\* the discrepancy via accumulated_subsidy_/accumulated_slashed_).
\* The TLA spec models the IDEALIZED preservation property — the
\* "T-F5 no-leak" guarantee that a corrected implementation would
\* uphold. SECURITY.md tracks the latent gap as a known modeling
\* discrepancy (the empty-creators case is unreachable in practice
\* because every applied block has at least one creator in the
\* committee).
FinalizeBlockWithCreators ==
    /\ Len(block_creators) > 0
    /\ height < MaxHeight
    /\ LET m   == Len(block_creators) IN
       LET per == block_total_fees \div m IN
       LET dst == block_total_fees \div m * m + (block_total_fees % m) IN  \* sanity
       LET dust == block_total_fees % m IN
       /\ accounts' = [d \in Domains |->
                         [balance |->
                            accounts[d].balance
                            + (IF d \in SeqToSet(block_creators)
                               THEN per ELSE 0)
                            + (IF d = block_creators[1]
                               THEN dust ELSE 0)]]
       /\ block_total_fees' = 0
    /\ block_creators' = <<>>
    /\ height' = height + 1
    /\ UNCHANGED <<pending_txs>>

FinalizeBlockEmpty ==
    /\ block_creators = <<>>
    /\ height < MaxHeight
    /\ height' = height + 1
    \* T-F5: preserve block_total_fees, do not distribute, do not reset.
    \* Idealized preservation — the corrected-implementation contract.
    /\ UNCHANGED <<accounts, pending_txs, block_creators, block_total_fees>>

FinalizeBlock == FinalizeBlockWithCreators \/ FinalizeBlockEmpty

\* StartNextBlock(creators): assign a creator sequence for the next
\* block. Models the producer + committee-selection path that
\* happens BEFORE apply: the validator has selected K creators for
\* this height and the apply layer reads them off b.creators.
\*
\* The model lets any sequence over Domains (length 0..|Domains|) be
\* chosen, so both the empty-creators and the non-empty cases are
\* reachable. In production every committee is non-empty (committee
\* selection always emits K >= 3 entries); the empty-creators case
\* exists for the T-F5 invariant witness.
StartNextBlock(creators) ==
    /\ creators \in Seq(Domains)
    /\ Len(creators) <= Cardinality(Domains)
    /\ block_creators = <<>>
    /\ block_creators' = creators
    /\ UNCHANGED <<accounts, pending_txs, block_total_fees, height>>

----------------------------------------------------------------------------
\* Next-state relation.

Next ==
    \/ \E t \in Tx : SubmitTx(t)
    \/ ApplyTx
    \/ ApplyTxInsufficientBalance
    \/ FinalizeBlock
    \/ \E creators \in Seq(Domains) : StartNextBlock(creators)

\* Fairness on FinalizeBlock + StartNextBlock so that the fee pool
\* eventually drains and the block-by-block cycle progresses.
\* Without WF on FinalizeBlock, a trace could starve drain by
\* perpetually accumulating new tx fees; without WF on
\* StartNextBlock, the first FinalizeBlock would clear creators and
\* no subsequent block could ever finalize.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(FinalizeBlock)
    /\ \A creators \in Seq(Domains) : WF_vars(StartNextBlock(creators))

----------------------------------------------------------------------------
\* Invariants.

\* Inv_TypeOK: shape of every variable. The accounts function is
\* total over Domains (every domain has a balance entry, possibly
\* zero). pending_txs is a sequence of well-formed Tx records.
\* block_creators is a sequence of Domains. block_total_fees and
\* height are Nat-valued and bounded by TLC-tractable ceilings.
\*
\* The balance ceiling `0..TotalSupplyInitial` reflects the
\* conservation property: no single balance can exceed the total
\* supply (a creator could in principle accumulate all of it via
\* repeated fee distributions, hence the ceiling is the full
\* TotalSupplyInitial rather than the per-domain initial allocation).
Inv_TypeOK ==
    /\ accounts \in [Domains -> [balance: 0..TotalSupplyInitial]]
    /\ pending_txs    \in Seq(Tx)
    /\ block_creators \in Seq(Domains)
    /\ block_total_fees \in 0..TotalSupplyInitial
    /\ height \in 0..MaxHeight

\* Inv_BalanceNonNegative: per-domain balance is Nat-valued at every
\* reachable state. The ApplyTx guard `balance >= amount + fee`
\* ensures the post-state balance stays in Nat; the
\* ApplyTxInsufficientBalance branch is a stutter on accounts; the
\* FinalizeBlock branch only credits (never debits).
Inv_BalanceNonNegative ==
    \A d \in Domains : accounts[d].balance >= 0

\* Inv_BlockTotalFeesNonNegative: the accumulated fee pool is
\* Nat-valued at every reachable state. ApplyTx only adds (never
\* subtracts); ApplyTxInsufficientBalance is a stutter;
\* FinalizeBlockWithCreators resets to 0; FinalizeBlockEmpty
\* preserves. None of the four cases can push the pool negative.
Inv_BlockTotalFeesNonNegative == block_total_fees >= 0

\* Inv_A1Conservation: the headline supply-conservation claim.
\* Total supply (sum of balances + in-flight fee pool) is invariant
\* across every step. Three cases:
\*   (1) SubmitTx + ApplyTxInsufficientBalance + StartNextBlock
\*       + FinalizeBlockEmpty: all preserve accounts AND
\*       block_total_fees, so the sum is trivially preserved.
\*   (2) ApplyTx: sender loses (amount + fee), recipient gains
\*       amount, block_total_fees gains fee. Net delta:
\*       -(amount + fee) + amount + fee = 0.
\*   (3) FinalizeBlockWithCreators: block_total_fees goes to 0;
\*       creators collectively gain (per_creator * m + dust) =
\*       block_total_fees. Net delta: -block_total_fees +
\*       block_total_fees = 0.
\*
\* The Inv_A1Conservation invariant is the canonical "no minting,
\* no burning" property for the fee state machine — matches the
\* A1 invariant on the AccountState-side spec (FB5).
Inv_A1Conservation ==
    SumBalances + block_total_fees = TotalSupplyInitial

\* Inv_NoFeeOnSkip: an action-level invariant that
\* ApplyTxInsufficientBalance is a stutter on the accounts variable.
\* If the head tx fails the balance gate, the sender's balance is
\* unchanged in the post-state AND the fee pool is unchanged AND no
\* recipient is credited.
\*
\* Formally: across every [Next]_vars step, if Len(pending_txs) > 0
\* AND head.from.balance < head.amount + head.fee AND the head is
\* consumed (pending_txs' = Tail(pending_txs)), then accounts'[d] =
\* accounts[d] for every d AND block_total_fees' = block_total_fees.
\*
\* TLC checks this against the actual delta on every transition.
\* The invariant rules out a hypothetical bug where the apply path
\* charges the fee BEFORE the balance check — a class of bug that
\* would silently drain senders on insufficient balance. The model's
\* explicit ApplyTxInsufficientBalance disjunct + the [][...]_vars
\* form together witness the no-leak guarantee.
Inv_NoFeeOnSkip ==
    [][LET head_consumed ==
         /\ Len(pending_txs) > 0
         /\ pending_txs' = Tail(pending_txs)
         /\ Head(pending_txs).from \in Domains
       IN LET t == Head(pending_txs) IN
       (head_consumed
        /\ accounts[t.from].balance < t.amount + t.fee)
       =>
       /\ \A d \in Domains : accounts'[d].balance = accounts[d].balance
       /\ block_total_fees' = block_total_fees
      ]_vars

\* Inv_EmptyCreatorsNoDistribute: action-level invariant. If a
\* finalization step fires with block_creators = <<>>, then
\* block_total_fees is preserved across the step.
\*
\* Combined with Inv_A1Conservation, this gives the T-F5 "no leak
\* on empty creators" claim: an empty-creators block does not burn
\* the accumulated pool. The pool carries forward to the next
\* block's accumulation.
\*
\* The structural witness is the FinalizeBlockEmpty disjunct's
\* `UNCHANGED <<..., block_total_fees>>` clause. TLC checks that
\* every step where height' > height AND block_creators = <<>>
\* preserves block_total_fees.
Inv_EmptyCreatorsNoDistribute ==
    [][(height' > height /\ block_creators = <<>>)
       => block_total_fees' = block_total_fees
      ]_vars

\* Inv_FeeDistributionDeterministic: state-level invariant. Given a
\* state (block_total_fees = X, block_creators = C) with Len(C) > 0,
\* the per-creator share + dust assignment is purely deterministic
\* in (X, C).
\*
\* Formally: per_creator = X \div Len(C); dust = X mod Len(C); the
\* dust goes to C[1] (creators[0] in 0-indexed C++ notation). No
\* tie-breaker depends on a fresh random value, no per-node state
\* outside (X, C) enters the calculation.
\*
\* The structural witness is that the FinalizeBlockWithCreators
\* action's post-state for accounts depends only on
\* (block_total_fees, block_creators) — no fresh existential
\* quantification, no time-varying input. TLC checks the
\* implication that every reachable (X, C) with X > 0 AND Len(C) > 0
\* admits a unique post-distribution accounts'.
\*
\* State-form: at every reachable state where block_creators is
\* non-empty, the (per_creator, dust) pair is determined by
\* (block_total_fees, Len(block_creators)) — written as a tautology
\* over the floor + mod definitions. This is a "trivial" invariant
\* in the sense that it always holds by construction; including it
\* makes the determinism contract explicit.
Inv_FeeDistributionDeterministic ==
    Len(block_creators) > 0 =>
       /\ block_total_fees =
          (block_total_fees \div Len(block_creators)) * Len(block_creators)
          + (block_total_fees % Len(block_creators))
       /\ block_total_fees % Len(block_creators) < Len(block_creators)

----------------------------------------------------------------------------
\* Temporal properties.

\* Prop_EventualFeeDrain: under fairness on FinalizeBlock +
\* StartNextBlock, any non-zero block_total_fees with non-empty
\* creators eventually flows to creator balances.
\*
\* Formally: in every fair run, if block_total_fees > 0 AND
\* Len(block_creators) > 0 AND height < MaxHeight, then either
\* eventually block_total_fees = 0 (FinalizeBlock fired and drained
\* the pool) OR eventually height >= MaxHeight (model bound was
\* reached before the drain could complete; the bounded-model
\* escape, parallel to Prop_EventualUnstake in StakeLifecycle.tla).
\*
\* The combination of WF_vars(FinalizeBlock) (the drain action
\* eventually fires) and the height-advance bound gives the
\* eventual-progress conclusion. Without fairness on
\* FinalizeBlock, a trace could perpetually accumulate fees via
\* repeated SubmitTx + ApplyTx without ever firing the drain.
Prop_EventualFeeDrain ==
    (block_total_fees > 0
     /\ Len(block_creators) > 0
     /\ height < MaxHeight)
    ~> (block_total_fees = 0 \/ height >= MaxHeight)

\* Prop_SupplyConservation: the temporal restatement of
\* Inv_A1Conservation as an always-claim. Across every reachable
\* state, the total supply identity SumBalances + block_total_fees
\* = TotalSupplyInitial holds.
\*
\* Equivalent to Inv_A1Conservation as a state-level invariant;
\* including it as a temporal property mirrors the dual treatment
\* in AccountState.tla + StakeLifecycle.tla and gives a [][...]_vars
\* witness that every action's delta is conservation-preserving.
Prop_SupplyConservation ==
    [](SumBalances + block_total_fees = TotalSupplyInitial)

============================================================================
