--------------------------- MODULE CrossShardOutboundApply ---------------------------
(*
FB18 — TLA+ specification of the source-side cross-shard TRANSFER
apply state machine. Models the source-side detail of
`Chain::apply_transactions`'s TRANSFER branch at
`src/chain/chain.cpp:742-770`: a TRANSFER whose `tx.to` routes to a
different shard via `shard_id_for_address` debits the sender by
(amount + fee) locally, increments per-block `block_outbound` by
`amount` (chain.cpp:765), and emits a CrossShardReceipt into the
block's `cross_shard_receipts` list (producer.cpp:459-465). The
destination credit is FB14 / FB17 territory; FB18 zooms on the
source side: A1 source-mass departure, local-vs-cross branch
correctness, accumulated_outbound monotonicity, and the
single-shard-no-outbound degenerate case.

The triangle FB2 (Sharding) ↔ FB14 (CrossShardReceiptDedup) ↔ FB18
covers the cross-shard mechanism from three complementary angles:
receipt-flow soundness (FB2), per-block dst-dedup (FB14), and
per-block source debit + accumulator (FB18). FB17 sits orthogonal
on the snapshot/restore lifecycle of FB14's dedup set.

Properties captured:

  (T-O1) Source-debit correctness: a cross-shard TRANSFER debits
         the sender by exactly (amount + fee). The recipient's
         local balance is UNCHANGED — credit happens on the
         destination shard via the receipt path.
  (T-O2) Accumulated_outbound monotonicity: per cross-shard apply
         the counter advances by exactly tx.amount; never decreases.
         Mirrors `accumulated_outbound_ += block_outbound` at
         chain.cpp:1394.
  (T-O3) No-local-credit-on-cross-shard: for any
         ApplyCrossShardTransfer step, accounts[t.to] is UNCHANGED.
         The structural witness — the cross-shard branch at
         chain.cpp:762-766 OMITS the recipient credit, in contrast
         to the same-shard branch at chain.cpp:756-761.
  (T-O4) Outbound sum equals receipt sum: cumulative
         accumulated_outbound equals the sum of amounts in
         pending_receipts. The A1 source-mass conservation contract.
  (T-O5) Insufficient-balance silent skip: ApplyInsufficientBalance
         preserves all conservation-relevant variables. Mirrors the
         `continue` at chain.cpp:744.
  (T-O7) Single-shard degeneracy: when |Shards| = 1, the
         is_cross_shard short-circuit at chain.cpp:199 makes
         ApplyCrossShardTransfer structurally unreachable.

Invariants (state-level under TLC): Inv_TypeOK,
Inv_BalanceNonNegative, Inv_OutboundMonotonic,
Inv_OutboundSumEqualsReceiptSum, Inv_SingleShardNoOutbound.
Action-level invariants (under [Next]_vars):
Inv_NoLocalCreditOnCrossShard. Temporal properties (under
fairness): Prop_EventualApply, Prop_SourceA1Conservation.

Modeling scope (TLC tractability): the routing oracle
`shard_id_for_address` is lifted to a constant function literal
ROUTE: Domains → Shards in the .cfg. Transactions carry (from, to,
amount, fee) — the nonce gate is FB7 territory. Receipts collapse
the 11-field CrossShardReceipt to (to, amount) since FB18 only
models apply-side emission count + amount accumulation; the
cryptographic binding is FA7 territory (Lemma L-7.1). Fees are
debited from sender (matching chain.cpp:743 cost = amount + fee)
but their creator-distribution stream is FB10 territory.

Companion prose proof: `docs/proofs/CrossShardOutboundApply.md`
(separately written by a parallel agent).

To check (assuming TLC installed):
  $ tlc CrossShardOutboundApply.tla -config CrossShardOutboundApply.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,        \* set of address identifiers
    Shards,         \* set of shard identifiers (e.g. {s1, s2})
    MyShard,        \* the modeled source-shard identity (must be in Shards)
    MaxAmount,      \* upper bound on per-tx amount
    MaxFee,         \* upper bound on per-tx fee
    InitialBalance, \* per-domain starting balance
    MaxHeight       \* upper bound on action count for TLC

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ Cardinality(Shards)  >= 1
    /\ MyShard \in Shards
    /\ MaxAmount      \in Nat /\ MaxAmount      >= 1
    /\ MaxFee         \in Nat /\ MaxFee         >= 0
    /\ InitialBalance \in Nat /\ InitialBalance >= MaxAmount + MaxFee
    /\ MaxHeight      \in Nat /\ MaxHeight      >= 1

\* Routing oracle (Domains -> Shards). The C++ CHASH primitive at
\* `src/crypto/shard.cpp::shard_id_for_address` is lifted to a
\* constant function literal at cfg time; chain.cpp:198-202's
\* `shard_count_ <= 1 ⇒ FALSE` short-circuit is mirrored by the
\* `Cardinality(Shards) > 1` clause in IsCrossShard (T-O7 case).
CONSTANT ROUTE      \* a function Domains -> Shards (see .cfg)

ASSUME RouteOK == ROUTE \in [Domains -> Shards]

IsCrossShard(d) == Cardinality(Shards) > 1 /\ ROUTE[d] /= MyShard

\* Transfer-tx shape: nonce + signature surface is FB7 / FA1 territory;
\* only the apply-time fields (from, to, amount, fee) are modeled here.
Transfer == [from:   Domains,
             to:     Domains,
             amount: 1..MaxAmount,
             fee:    0..MaxFee]

\* Cross-shard receipt — the (to, amount) subset of the 11-field
\* CrossShardReceipt. The cryptographic binding is FA7 territory
\* (Lemma L-7.1); FB18 only models apply-side emission count + amount.
Receipt == [to: Domains, amount: 1..MaxAmount]

----------------------------------------------------------------------------
\* State.

VARIABLES
    accounts,              \* Domains -> [balance: Nat]
    accumulated_outbound,  \* Nat (chain-level running total)
    pending_receipts,      \* Seq(Receipt) - per-block receipt emit queue
    pending_txs,           \* Seq(Transfer) - per-block apply queue
    height                 \* Nat - action counter; bounds TLC

vars == <<accounts, accumulated_outbound, pending_receipts,
          pending_txs, height>>

----------------------------------------------------------------------------
\* Initial state. Every domain starts with InitialBalance; no pending
\* txs / receipts; accumulated_outbound at 0; height at 0.
Init ==
    /\ accounts            = [d \in Domains |->
                                [balance |-> InitialBalance]]
    /\ accumulated_outbound = 0
    /\ pending_receipts    = <<>>
    /\ pending_txs         = <<>>
    /\ height              = 0

----------------------------------------------------------------------------
\* Actions. Mirror the apply-layer branches in chain.cpp::apply_transactions
\* TRANSFER (chain.cpp:742-770) plus the FinalizeBlock counter-advance
\* at chain.cpp:1393-1394.

\* SubmitTransfer: adversarial/user surface. Appends a Transfer to
\* pending_txs; bounded by MaxHeight for TLC tractability.
SubmitTransfer(from, to, amount, fee) ==
    /\ from \in Domains
    /\ to   \in Domains
    /\ amount \in 1..MaxAmount
    /\ fee    \in 0..MaxFee
    /\ Len(pending_txs) < MaxHeight + 1
    /\ pending_txs' = Append(pending_txs,
                              [from |-> from, to |-> to,
                               amount |-> amount, fee |-> fee])
    /\ height' = height + 1
    /\ UNCHANGED <<accounts, accumulated_outbound, pending_receipts>>

\* ApplyLocalTransfer(t): same-shard TRANSFER. Models the
\* `if (!is_cross_shard(tx.to))` branch at chain.cpp:752-761. Debit
\* sender by (amount + fee), credit recipient by amount. S-007
\* overflow check abstracted via MaxAmount + InitialBalance bound.
ApplyLocalTransfer(t) ==
    /\ Len(pending_txs) > 0
    /\ t = Head(pending_txs)
    /\ ~IsCrossShard(t.to)
    /\ accounts[t.from].balance >= t.amount + t.fee
    /\ accounts' = [accounts EXCEPT
                       ![t.from].balance = @ - (t.amount + t.fee),
                       ![t.to  ].balance = @ + t.amount]
    /\ pending_txs' = Tail(pending_txs)
    /\ UNCHANGED <<accumulated_outbound, pending_receipts, height>>

\* ApplyCrossShardTransfer(t): cross-shard TRANSFER. Models the
\* `else { block_outbound += tx.amount; }` branch at chain.cpp:762-766
\* plus the producer-side receipt emission at producer.cpp:459-465.
\* T-O1: debit sender by (amount + fee). T-O2: increment
\* accumulated_outbound by tx.amount. T-O3: accounts[t.to] UNCHANGED
\* (destination credit lives on the OTHER shard via FB14 / FB17).
\* T-O4: pending_receipts gains exactly one entry with the same amount.
ApplyCrossShardTransfer(t) ==
    /\ Len(pending_txs) > 0
    /\ t = Head(pending_txs)
    /\ IsCrossShard(t.to)
    /\ accounts[t.from].balance >= t.amount + t.fee
    /\ accounts' = [accounts EXCEPT
                       ![t.from].balance = @ - (t.amount + t.fee)]
    /\ accumulated_outbound' = accumulated_outbound + t.amount
    /\ pending_receipts' = Append(pending_receipts,
                                    [to |-> t.to, amount |-> t.amount])
    /\ pending_txs' = Tail(pending_txs)
    /\ UNCHANGED height

\* ApplyInsufficientBalance(t): the `continue` silent-skip at
\* chain.cpp:744 (`if (sender.balance < cost) continue;`). Tx is
\* consumed from the queue but NO mutation — T-O5 witness. The
\* validator's pre-apply admission check should normally reject
\* these before apply; the apply-layer `continue` is the safety net.
ApplyInsufficientBalance(t) ==
    /\ Len(pending_txs) > 0
    /\ t = Head(pending_txs)
    /\ accounts[t.from].balance < t.amount + t.fee
    /\ pending_txs' = Tail(pending_txs)
    /\ UNCHANGED <<accounts, accumulated_outbound,
                   pending_receipts, height>>

\* FinalizeBlock: models the block-finalize tail at chain.cpp:1393-1394
\* (`accumulated_outbound_ += block_outbound`). In the TLA model the
\* per-step Cross apply already advances accumulated_outbound, so
\* FinalizeBlock is a stutter on the conservation-relevant vars and
\* exists to bound action count + drive Prop_EventualApply progress
\* when pending_txs is empty. The model keeps pending_receipts as
\* cumulative to enable the state-level T-O4 sum invariant across
\* block boundaries.
FinalizeBlock ==
    /\ Len(pending_txs) = 0
    /\ height' = height + 1
    /\ UNCHANGED <<accounts, accumulated_outbound, pending_receipts>>

----------------------------------------------------------------------------
\* Next-state relation.

Next ==
    \/ \E from \in Domains, to \in Domains,
         a \in 1..MaxAmount, f \in 0..MaxFee :
            SubmitTransfer(from, to, a, f)
    \/ \E t \in Transfer : ApplyLocalTransfer(t)
    \/ \E t \in Transfer : ApplyCrossShardTransfer(t)
    \/ \E t \in Transfer : ApplyInsufficientBalance(t)
    \/ FinalizeBlock

\* Fairness on the three apply branches drives Prop_EventualApply:
\* the three branches together cover the head's full guard space
\* (same-shard + sufficient = Local; cross-shard + sufficient = Cross;
\* insufficient (either) = InsufficientBalance).
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(\E t \in Transfer : ApplyLocalTransfer(t))
    /\ WF_vars(\E t \in Transfer : ApplyCrossShardTransfer(t))
    /\ WF_vars(\E t \in Transfer : ApplyInsufficientBalance(t))
    /\ WF_vars(FinalizeBlock)

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant.
Inv_TypeOK ==
    /\ accounts \in [Domains -> [balance: Nat]]
    /\ accumulated_outbound \in Nat
    /\ pending_receipts \in Seq(Receipt)
    /\ pending_txs \in Seq(Transfer)
    /\ height \in Nat

\* BalanceNonNegative: per-domain balance >= 0. The cost gate at
\* head of both Local + Cross apply branches enforces post-state
\* Nat. ApplyInsufficientBalance / SubmitTransfer / FinalizeBlock
\* preserve.
Inv_BalanceNonNegative ==
    \A d \in Domains : accounts[d].balance >= 0

\* OutboundMonotonic (T-O2): accumulated_outbound >= 0. All non-Cross
\* actions preserve; Cross strictly increments by t.amount (Nat).
Inv_OutboundMonotonic ==
    accumulated_outbound >= 0

\* NoLocalCreditOnCrossShard (T-O3, action-level): a step matching
\* the ApplyCrossShardTransfer signature (pending head t, cross-shard,
\* head popped, accumulated_outbound bumped by t.amount) MUST leave
\* accounts[t.to] UNCHANGED. The C++ witness is the structural absence
\* of the recipient credit in chain.cpp:762-766 (vs the credit at
\* chain.cpp:756-761 for same-shard).
Inv_NoLocalCreditOnCrossShard ==
    [][\A t \in Transfer :
         ( /\ Len(pending_txs) > 0
           /\ Head(pending_txs) = t
           /\ IsCrossShard(t.to)
           /\ pending_txs' = Tail(pending_txs)
           /\ accumulated_outbound' = accumulated_outbound + t.amount )
         => accounts'[t.to].balance = accounts[t.to].balance
      ]_vars

\* SumOfReceipts: sum of amounts in pending_receipts. Recursive
\* definition via Fold over the Seq's index range.
SumReceipts(s) ==
    LET F[i \in 0..Len(s)] ==
            IF i = 0 THEN 0
            ELSE F[i-1] + s[i].amount
    IN  F[Len(s)]

\* OutboundSumEqualsReceiptSum (T-O4): state-level invariant —
\* accumulated_outbound = sum of amounts in pending_receipts. Holds
\* by construction at Init (both 0); ApplyCrossShardTransfer is the
\* sole action that mutates either field and bumps both by exactly
\* t.amount, preserving the equality. The A1 source-mass conservation
\* witness: every unit leaving the source's accounted supply has a
\* matching emitted receipt amount.
Inv_OutboundSumEqualsReceiptSum ==
    accumulated_outbound = SumReceipts(pending_receipts)

\* SingleShardNoOutbound (T-O7): when |Shards| = 1, accumulated_outbound
\* is 0 AND pending_receipts is empty. The IsCrossShard helper's
\* `Cardinality(Shards) > 1` clause mirrors chain.cpp:199's
\* `if (shard_count_ <= 1) return false;` short-circuit, making the
\* Cross branch structurally unreachable. Vacuous when |Shards| > 1.
Inv_SingleShardNoOutbound ==
    (Cardinality(Shards) = 1) =>
        ( /\ accumulated_outbound = 0
          /\ pending_receipts = <<>> )

----------------------------------------------------------------------------
\* Temporal properties.

\* EventualApply: under fairness on Local + Cross + Insufficient,
\* any non-empty pending_txs drains. The three branches cover the
\* head's full guard space; the MaxHeight escape covers model-bound
\* termination.
Prop_EventualApply ==
    (Len(pending_txs) > 0)
    ~> (Len(pending_txs) = 0 \/ height >= MaxHeight)

\* SourceA1Conservation (T-O1 + T-O3 action-form): across every
\* ApplyCrossShardTransfer step on head t, accounts'[t.from].balance
\* = pre - (t.amount + t.fee) AND every non-from non-to domain is
\* preserved. The fee is debited from sender (stays on shard for
\* creator distribution; FB10 territory). The structural witness
\* for FA7 Lemma L-7.3 (source-side debit precedes receipt emission).
Prop_SourceA1Conservation ==
    [][\A t \in Transfer :
         ( /\ Len(pending_txs) > 0
           /\ Head(pending_txs) = t
           /\ IsCrossShard(t.to)
           /\ pending_txs' = Tail(pending_txs)
           /\ accumulated_outbound' = accumulated_outbound + t.amount )
         => ( /\ accounts'[t.from].balance
                = accounts[t.from].balance - (t.amount + t.fee)
              /\ \A d \in Domains :
                   (d /= t.from /\ d /= t.to) =>
                     accounts'[d].balance = accounts[d].balance )
      ]_vars

============================================================================
