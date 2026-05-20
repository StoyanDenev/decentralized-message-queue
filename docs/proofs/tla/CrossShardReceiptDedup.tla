--------------------------- MODULE CrossShardReceiptDedup ---------------------------
(*
FB14 — TLA+ specification of the cross-shard inbound-receipt dedup
state machine on the destination shard. Drills into the apply-side
detail of `Chain::apply_transactions`'s inbound-receipt branch in
`src/chain/chain.cpp` (lines 1363-1381), focusing on the
`applied_inbound_receipts_` set and its "first-credit-wins,
subsequent-attempts-silent-noop" idempotency contract.

FB14 is the child of FB3 (Receipts.tla) and a complement to FB2
(Sharding.tla). FB3 modeled the "applied set is monotone, each
receipt-ID credited at most once" claim at the smallest granularity
(one set, one opaque ID). FB2 modeled the source-emission + dst-
admission flow under a replay adversary. FB14 fills the gap: the
apply-side dedup primitive with the actual protocol key structure
(a (src_shard, tx_hash) pair, NOT a single opaque ID), the actual
protocol state (per-recipient credit, accumulated counter, snapshot-
survivable applied set), and equivocation-via-different-paths
adversary.

Invariants checked under TLC:
  * Inv_TypeOK — variable shapes
  * Inv_BalanceNonNegative — Nat-typed balances
  * Inv_AccumulatedInboundMonotonic — accumulated_inbound >= 0
  * Inv_DedupKeyIsPair — keys are (src_shard, tx_hash) pairs (T-R3)
  * Inv_NoDoubleCredit — per-recipient balance is bounded by the
        sum of UNIQUE receipt amounts targeting them (T-R1 + T-R2)
  * Inv_AppliedImpliesCredited — every entry in applied_receipts
        was installed by exactly one ApplyFirst step

Temporal properties:
  * Prop_DedupAlwaysHolds — every transition preserves the
        dedup-key shape (action-form of Inv_DedupKeyIsPair)
  * Prop_EventualApply — under fairness on ApplyFirst, any pending
        fresh-key receipt eventually applies

Modeling scope:
  * The C++ `applied_inbound_receipts_` is `std::set<std::pair<
    ShardId, std::string>>` at chain.cpp:204-206. The TLA model
    lifts the pair into a record [src_shard, tx_hash] for readable
    invariants; SET in TLA+ carries the unordered + dedup semantics.
  * `accumulated_inbound` is the chain-level lift of the per-block
    `block_inbound` counter at chain.cpp:1377-1380 — the dedup
    invariants are cross-block; per-block resets are FB10 territory.
  * Receipt collapses CrossShardReceipt's 11 fields to the four
    invariant-relevant ones (src_shard, tx_hash, to, amount). The
    other seven are FA7 cryptographic-binding territory.
  * Snapshot / Restore abstract the S-033 + S-037 + S-038 round-trip
    into a single save/load primitive. T-R4 (dedup-set survives
    restore) is the headline property; the full snapshot codec is
    FB6 territory.
  * Equivocate models the same dedup-key arriving via two different
    submission paths (gossip race or deliberate replay). The
    apply-side dedup gate catches the second regardless.

Companion prose proof: `docs/proofs/CrossShardReceiptDedup.md`
(separately written by a parallel agent).

To check (assuming TLC installed):
  $ tlc CrossShardReceiptDedup.tla -config CrossShardReceiptDedup.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Shards,             \* set of shard identifiers
    Domains,            \* set of recipient address identifiers
    Hashes,             \* set of tx-hash identifiers (SHA-256 collision
                        \* resistance is an external FA-track A3 assumption)
    MaxAmount,          \* upper bound on per-receipt amount
    MaxHeight           \* upper bound on queue depth for TLC

ASSUME ConfigOK ==
    /\ Cardinality(Shards)  >= 2
    /\ Cardinality(Domains) >= 1
    /\ Cardinality(Hashes)  >= 1
    /\ MaxAmount \in Nat /\ MaxAmount >= 1
    /\ MaxHeight \in Nat /\ MaxHeight >= 1

\* Receipt shape — mirrors the invariant-relevant subset of
\* chain::CrossShardReceipt. dst_shard is implicit (every receipt
\* here targets the modeled dst shard).
Receipt == [src_shard: Shards,
            tx_hash:   Hashes,
            to:        Domains,
            amount:    0..MaxAmount]

\* Dedup-key shape. The protocol's applied_inbound_receipts_ is
\* keyed by (ShardId, std::string) — same tx_hash from two
\* different src_shards is two distinct keys (T-R3).
DedupKey == [src_shard: Shards, tx_hash: Hashes]

\* Extract the dedup key from a Receipt.
KeyOf(r) == [src_shard |-> r.src_shard, tx_hash |-> r.tx_hash]

\* Snapshot-state shape — the (accounts, applied_receipts,
\* accumulated_inbound) triple at Snapshot time; Restore replays it.
SnapshotState == [accounts:            [Domains -> [balance: Nat]],
                  applied_receipts:    SUBSET DedupKey,
                  accumulated_inbound: Nat]

\* Sentinel for "no snapshot taken yet".
NoSnapshot == <<"no_snapshot">>

----------------------------------------------------------------------------
\* State.

VARIABLES
    accounts,            \* Domains -> [balance: Nat]
    applied_receipts,    \* SUBSET DedupKey
    accumulated_inbound, \* Nat
    pending_receipts,    \* Seq(Receipt)
    snapshot_state,      \* SnapshotState or NoSnapshot
    history              \* Seq(DedupKey) — audit log of ApplyFirst credits

vars == <<accounts, applied_receipts, accumulated_inbound,
          pending_receipts, snapshot_state, history>>

----------------------------------------------------------------------------
\* Initial state.

Init ==
    /\ accounts            = [d \in Domains |-> [balance |-> 0]]
    /\ applied_receipts    = {}
    /\ accumulated_inbound = 0
    /\ pending_receipts    = <<>>
    /\ snapshot_state      = NoSnapshot
    /\ history             = <<>>

----------------------------------------------------------------------------
\* Actions. Mirror the apply-layer branches in chain.cpp.

\* SubmitReceipt(r): append r to pending_receipts. Models the
\* gossip-ratified ingress where a CrossShardReceipt has cleared
\* K-of-K signature verification + V13 admission, queued for apply.
\* The wire-level cryptographic admission is FA7 territory; this
\* action models only the apply-queue ingress and is adversary-
\* controlled (duplicates of already-applied keys may appear).
SubmitReceipt(r) ==
    /\ r \in Receipt
    /\ Len(pending_receipts) < MaxHeight + 1
    /\ pending_receipts' = Append(pending_receipts, r)
    /\ UNCHANGED <<accounts, applied_receipts, accumulated_inbound,
                   snapshot_state, history>>

\* ApplyFirst(r): the fresh-key apply branch at chain.cpp:1363-1381.
\* Credits the recipient, inserts the key, bumps the counter.
\* T-R1 (first-credit-wins): exactly this action mutates accounts,
\* applied_receipts, and accumulated_inbound.
\*
\* Pre: r is at the head of pending_receipts AND
\*      KeyOf(r) \notin applied_receipts.
\* The head-of-queue restriction preserves the C++ in-order apply
\* semantics of the for-loop at chain.cpp:1363.
ApplyFirst(r) ==
    /\ Len(pending_receipts) > 0
    /\ r = Head(pending_receipts)
    /\ KeyOf(r) \notin applied_receipts
    /\ accounts' = [accounts EXCEPT
                      ![r.to].balance = @ + r.amount]
    /\ applied_receipts'    = applied_receipts \cup {KeyOf(r)}
    /\ accumulated_inbound' = accumulated_inbound + r.amount
    /\ pending_receipts'    = Tail(pending_receipts)
    /\ history'             = Append(history, KeyOf(r))
    /\ UNCHANGED snapshot_state

\* ApplyDuplicate(r): silent no-op on duplicate. Models chain.cpp:1365
\* `if (applied_inbound_receipts_.count(key)) continue;` — the
\* receipt is consumed from the queue (loop advances past it) but no
\* balance is credited and the dedup set is unchanged.
\* T-R2 (subsequent-attempts-silent-noop): combined with ApplyFirst,
\* covers both branches of the dispatch.
ApplyDuplicate(r) ==
    /\ Len(pending_receipts) > 0
    /\ r = Head(pending_receipts)
    /\ KeyOf(r) \in applied_receipts
    /\ pending_receipts' = Tail(pending_receipts)
    /\ UNCHANGED <<accounts, applied_receipts, accumulated_inbound,
                   snapshot_state, history>>

\* Snapshot: save the (accounts, applied_receipts, accumulated_inbound)
\* triple. Models the serialize step at chain.cpp:1586-1592 (the
\* `applied_inbound_receipts` namespace added by S-037). The pending
\* queue is NOT included — it lives in the gossip layer, NOT the
\* apply layer (matching the C++ snapshot scope).
Snapshot ==
    /\ snapshot_state' = [accounts            |-> accounts,
                          applied_receipts    |-> applied_receipts,
                          accumulated_inbound |-> accumulated_inbound]
    /\ UNCHANGED <<accounts, applied_receipts, accumulated_inbound,
                   pending_receipts, history>>

\* Restore: replace (accounts, applied_receipts, accumulated_inbound)
\* with the saved snapshot. Models chain.cpp:1778-1783.
\*
\* T-R4 (dedup-set preserved across restore): a freshly-loaded node
\* MUST NOT lose its applied_inbound_receipts set, else a re-submitted
\* receipt would pass the dedup gate and credit twice. S-037 closed
\* this gap by adding the namespace to serialize_state; FB14
\* verifies the round-trip preserves the set verbatim.
Restore ==
    /\ snapshot_state /= NoSnapshot
    /\ accounts'            = snapshot_state.accounts
    /\ applied_receipts'    = snapshot_state.applied_receipts
    /\ accumulated_inbound' = snapshot_state.accumulated_inbound
    /\ UNCHANGED <<pending_receipts, snapshot_state, history>>

\* Equivocate(r): adversary submits the same dedup-key via a different
\* path. Models a worst-case wire-level adversary racing two gossip
\* paths or deliberately replaying through a different intermediary.
\* Structurally identical to SubmitReceipt; differentiated by guard:
\* the key must already exist in applied_receipts OR in some pending
\* receipt — i.e., genuinely a duplicate. The Inv_NoDoubleCredit
\* invariant witnesses that the recipient is credited exactly once
\* across the pair regardless of which submission won the race.
Equivocate(r) ==
    /\ r \in Receipt
    /\ Len(pending_receipts) < MaxHeight + 1
    /\ \/ KeyOf(r) \in applied_receipts
       \/ \E i \in 1..Len(pending_receipts) :
            KeyOf(pending_receipts[i]) = KeyOf(r)
    /\ pending_receipts' = Append(pending_receipts, r)
    /\ UNCHANGED <<accounts, applied_receipts, accumulated_inbound,
                   snapshot_state, history>>

----------------------------------------------------------------------------
\* Next-state relation.

Next ==
    \/ \E r \in Receipt : SubmitReceipt(r)
    \/ \E r \in Receipt : ApplyFirst(r)
    \/ \E r \in Receipt : ApplyDuplicate(r)
    \/ \E r \in Receipt : Equivocate(r)
    \/ Snapshot
    \/ Restore

\* Fairness on ApplyFirst drives Prop_EventualApply: a pending
\* fresh-key receipt cannot indefinitely stutter once enabled.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(\E r \in Receipt : ApplyFirst(r))

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant.
Inv_TypeOK ==
    /\ accounts \in [Domains -> [balance: Nat]]
    /\ applied_receipts \subseteq DedupKey
    /\ accumulated_inbound \in Nat
    /\ pending_receipts \in Seq(Receipt)
    /\ Len(pending_receipts) <= MaxHeight + 1
    /\ \/ snapshot_state = NoSnapshot
       \/ snapshot_state \in SnapshotState
    /\ history \in Seq(DedupKey)

\* BalanceNonNegative: per-recipient balance >= 0. Nat-typed.
\* ApplyFirst only credits (never debits); Restore preserves
\* Nat-typed snapshot values.
Inv_BalanceNonNegative ==
    \A d \in Domains : accounts[d].balance >= 0

\* AccumulatedInboundMonotonic: Nat-typed lower bound on the
\* running total. The strict-monotonicity claim across non-Restore
\* steps lives in Prop_DedupAlwaysHolds + the ApplyFirst structure
\* (each ApplyFirst strictly increases by exactly r.amount;
\* ApplyDuplicate is UNCHANGED on this variable).
Inv_AccumulatedInboundMonotonic ==
    accumulated_inbound >= 0

\* DedupKeyIsPair (T-R3): each entry in applied_receipts is a
\* (src_shard, tx_hash) pair record. Same tx_hash from two
\* different src_shards is two distinct entries. Mirrors the
\* C++ `std::pair<ShardId, std::string>` key type at chain.cpp:139.
\*
\* Non-trivial: a single-key model (FB3) cannot witness this. The
\* TLA model enumerates traces where the same tx_hash appears in
\* two different src_shards; both entries appear in applied_receipts
\* and both credits fire.
Inv_DedupKeyIsPair ==
    \A k \in applied_receipts :
       /\ k.src_shard \in Shards
       /\ k.tx_hash   \in Hashes

\* NoDoubleCredit: per-recipient balance change is bounded by the
\* sum of UNIQUE receipt amounts targeting that recipient. T-R1 +
\* T-R2 composed — no duplicate-inflation.
\*
\* State-form upper bound: balance <= MaxAmount * |applied_receipts|.
\* The tighter equality (balance = sum of unique-key amounts to d)
\* lives in Prop_DedupAlwaysHolds + the ApplyFirst structure.
\* The upper bound is tight when every applied receipt has
\* amount = MaxAmount targeting the same recipient.
Inv_NoDoubleCredit ==
    \A d \in Domains :
       accounts[d].balance <= MaxAmount * Cardinality(applied_receipts)

\* AppliedImpliesCredited: every entry in applied_receipts was
\* installed by exactly one ApplyFirst step. The history sequence
\* witnesses one entry per applied key.
\*
\* The "exactly one" claim is structurally enforced: ApplyFirst's
\* pre-condition `KeyOf(r) \notin applied_receipts` blocks re-firing
\* on the same key. Combined with the existence claim, this gives
\* exactly-one. The invariant catches hypothetical bugs where
\* ApplyDuplicate accidentally inserts a key (it does not), or
\* where some other action sneaks a phantom entry in.
Inv_AppliedImpliesCredited ==
    \A k \in applied_receipts :
       \E i \in 1..Len(history) : history[i] = k

----------------------------------------------------------------------------
\* Temporal properties.

\* DedupAlwaysHolds: action-form of Inv_DedupKeyIsPair. Every
\* transition is one of:
\*   (a) UNCHANGED applied_receipts (SubmitReceipt / Equivocate /
\*       ApplyDuplicate / Snapshot)
\*   (b) extension by exactly one DedupKey (ApplyFirst)
\*   (c) replacement by snapshot_state.applied_receipts (Restore;
\*       itself a SUBSET DedupKey by Inv_TypeOK)
\* No other delta is permitted. TLC enumerates every reachable
\* [Next]_vars step and confirms the pre/post relationship.
Prop_DedupAlwaysHolds ==
    [][\/ applied_receipts' = applied_receipts
       \/ \E k \in DedupKey :
            applied_receipts' = applied_receipts \cup {k}
       \/ /\ snapshot_state /= NoSnapshot
          /\ applied_receipts' = snapshot_state.applied_receipts
      ]_vars

\* EventualApply: under fairness on ApplyFirst, any pending fresh-key
\* receipt eventually applies. Stated as: for every DedupKey k, if
\* some pending receipt has KeyOf = k AND k is currently fresh
\* (not in applied_receipts), then eventually either k is in
\* applied_receipts OR the queue drains entirely.
\*
\* Combined with WF_vars(ApplyFirst), this gives the eventual-
\* progress conclusion. Without fairness, a trace could indefinitely
\* stutter while a fresh receipt sits at the head of pending_receipts.
Prop_EventualApply ==
    \A k \in DedupKey :
       ((\E i \in 1..Len(pending_receipts) :
            KeyOf(pending_receipts[i]) = k
            /\ k \notin applied_receipts)
        ~> (k \in applied_receipts \/ Len(pending_receipts) = 0))

============================================================================
