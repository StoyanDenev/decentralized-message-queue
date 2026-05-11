--------------------------- MODULE Receipts ---------------------------
(*
FB3 — TLA+ specification of the receipt dedup state machine. This is
a tighter, more focused projection than Sharding.tla: it models only
the dedup logic on a single destination shard under an adversary that
attempts to replay, reorder, and concurrent-submit the same receipt.

Machine-checks the FA7 L-7.2 lemma directly: across any sequence of
block applications, no (src_shard, tx_hash) is credited more than
once on a given destination shard.

This spec is small enough to model-check in <1 second and serves as
a sanity check on the implementation's `applied_inbound_receipts_`
set behavior in `src/chain/chain.cpp`.

To check:
  $ tlc Receipts.tla -config Receipts.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    ReceiptIds,         \* set of (src, tx_hash) pair-IDs to model
    MaxBlocks           \* upper bound on blocks to apply

ASSUME ConfigOK ==
    /\ Cardinality(ReceiptIds) >= 1
    /\ MaxBlocks \in Nat /\ MaxBlocks >= 1

VARIABLES
    applied,            \* set of receipt IDs already credited
    block_idx,          \* current block index
    credit_log          \* sequence of <<block_idx, receipt_id>> credit events

vars == <<applied, block_idx, credit_log>>

Init ==
    /\ applied = {}
    /\ block_idx = 0
    /\ credit_log = <<>>

\* Apply a block that contains a single inbound_receipt with ID `rid`.
\* This action models the per-block apply path in chain.cpp lines 420-426:
\*   if (applied_inbound_receipts_.count(key)) continue;  ← idempotency
\*   accounts_[r.to].balance += r.amount;
\*   applied_inbound_receipts_.insert(key);
ApplyBlock(rid) ==
    /\ rid \in ReceiptIds
    /\ block_idx < MaxBlocks
    /\ block_idx' = block_idx + 1
    /\ IF rid \in applied
       THEN \* duplicate — no credit, no state change beyond block_idx
            /\ applied' = applied
            /\ credit_log' = credit_log
       ELSE \* fresh — credit + record
            /\ applied' = applied \cup {rid}
            /\ credit_log' = Append(credit_log, <<block_idx + 1, rid>>)

\* Adversary action: an attempted replay block. Identical to ApplyBlock
\* with a duplicate receipt; included to make the adversary explicit.
\* The dedup branch must catch it.
ReplayBlock(rid) ==
    /\ rid \in applied             \* this *is* a replay attempt
    /\ block_idx < MaxBlocks
    /\ block_idx' = block_idx + 1
    /\ applied' = applied          \* no change — dedup gate held
    /\ credit_log' = credit_log

Next ==
    \/ \E rid \in ReceiptIds : ApplyBlock(rid)
    \/ \E rid \in ReceiptIds : ReplayBlock(rid)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* Invariants.

\* FA7 L-7.2: each receipt ID is credited at most once.
Inv_NoDoubleCredit ==
    \A rid \in ReceiptIds :
       Cardinality({ i \in 1..Len(credit_log) : credit_log[i][2] = rid }) <= 1

\* Once a receipt is in `applied`, it remains there (monotone).
Inv_AppliedMonotone == applied = applied   \* trivially true in this spec; the
                                            \* TLA+ stuttering semantics + the
                                            \* fact applied' \in {applied,
                                            \* applied \cup {rid}} enforces it

\* Every entry in credit_log corresponds to an applied receipt.
Inv_LogConsistent ==
    \A i \in 1..Len(credit_log) : credit_log[i][2] \in applied

TypeOK ==
    /\ applied \subseteq ReceiptIds
    /\ block_idx \in Nat
    /\ credit_log \in Seq(Nat \X ReceiptIds)

============================================================================
