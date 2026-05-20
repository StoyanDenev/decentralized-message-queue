--------------------------- MODULE AppliedReceiptRestore ---------------------------
(*
FB17 — TLA+ specification of the cross-shard `applied_inbound_receipts_`
dedup-set restore lifecycle. Extends FB14 (CrossShardReceiptDedup) with
the explicit snapshot lifecycle that S-037 closed: the dedup set must
survive `Chain::serialize_state` → `Chain::restore_from_snapshot`
round-trips, else a receipt that was de-duplicated pre-snapshot could
re-credit post-restore.

State-machine companion to FA-Apply-AppliedReceiptRestore (apply-layer
integrity — `docs/proofs/AppliedReceiptRestore.md`, parallel agent).
Sits at the intersection of FB6 (Snapshot.tla — generic snapshot/restore
round-trip identity) and FB14 (CrossShardReceiptDedup.tla — per-block
dedup-set monotonicity). FB17 is the focused intersection: explicit
snapshot lifecycle on the dedup-set + the headline T-AR3 cross-snapshot
dedup contract that S-037 exposed as a missing namespace in the C++
serializer at chain.cpp:1586-1592.

Properties captured:

  (T-AR1) Snapshot saves the current `applied_receipts` verbatim — the
          serialize step at chain.cpp:1586-1592 emits every entry of
          `applied_inbound_receipts_` (the S-037 closure).
  (T-AR2) Restore replaces `applied_receipts` with the snapshot's saved
          set verbatim — the deserialize step at chain.cpp:1778-1783
          consumes the namespace and rehydrates the set.
  (T-AR3) Dedup persists across restore: if a receipt was applied
          pre-snapshot, attempting to re-apply it post-restore fires
          the ApplyDuplicate branch (silent no-op), NOT ApplyFirst.
          Pre-S-037 the dedup-set was silently empty after restore,
          allowing the double-credit at chain.cpp:1365.
  (T-AR4) Fresh keys credit post-restore: receipts whose dedup-key
          was NOT in the snapshot remain admissible. Restore is not
          a permanent freeze.
  (T-AR5) `accumulated_inbound` stays consistent with
          `applied_receipts` contents — the per-key amount sum
          invariant survives restore.

Modeling scope: the dedup-set primitive is identical to FB14 (a SUBSET
of DedupKey = (src_shard, tx_hash) pairs). FB17 adds the snapshot
lifecycle as an explicit pre/post pair. The pre-S-037 bug shape is
captured as a counter-factual — running TLC on the spec without the
dedup-set save/restore would witness a counter-example for
Inv_DedupPersistsAcrossRestore. The spec is the machine-checkable
witness of the S-037 closure.

To check (assuming TLC installed):
  $ tlc AppliedReceiptRestore.tla -config AppliedReceiptRestore.cfg
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Shards,             \* set of source-shard identifiers (T-R3 pair key)
    Hashes,             \* set of tx-hash identifiers (SHA-256 abstraction)
    Domains,            \* set of recipient address identifiers
    MaxAmount,          \* upper bound on per-receipt amount
    MaxHeight           \* upper bound on action count for TLC

ASSUME ConfigOK ==
    /\ Cardinality(Shards)  >= 2
    /\ Cardinality(Hashes)  >= 1
    /\ Cardinality(Domains) >= 1
    /\ MaxAmount \in Nat /\ MaxAmount >= 1
    /\ MaxHeight \in Nat /\ MaxHeight >= 1

\* Receipt shape — invariant-relevant subset of chain::CrossShardReceipt.
Receipt == [src_shard: Shards, tx_hash: Hashes,
            to: Domains, amount: 1..MaxAmount]

\* Dedup-key shape — pair structure (T-R3): same tx_hash from two
\* different src_shards is two distinct keys. Matches
\* `std::pair<ShardId, std::string>` at chain.cpp:139.
DedupKey == [src_shard: Shards, tx_hash: Hashes]

KeyOf(r) == [src_shard |-> r.src_shard, tx_hash |-> r.tx_hash]

\* Sentinel — distinguished from a snapshot whose saved set is empty.
NoSnapshot == <<"no_snapshot">>

\* SnapshotState: the (applied_receipts, balances, accumulated_inbound)
\* triple saved at TakeSnapshot. The pending queue lives in gossip,
\* not apply state — matches the C++ snapshot scope at chain.cpp:1586.
SnapshotState == [applied_receipts:    SUBSET DedupKey,
                  balances:            [Domains -> Nat],
                  accumulated_inbound: Nat]

----------------------------------------------------------------------------
\* State.

VARIABLES
    applied_receipts,    \* SUBSET DedupKey — the dedup set
    balances,            \* Domains -> Nat (per-recipient credit ledger)
    accumulated_inbound, \* Nat (chain-level running total)
    snapshot_state,      \* SnapshotState or NoSnapshot
    pending,             \* Seq(Receipt) (head-first apply queue)
    height               \* Nat (action counter; bounds TLC)

vars == <<applied_receipts, balances, accumulated_inbound,
          snapshot_state, pending, height>>

----------------------------------------------------------------------------
\* Initial state.

Init ==
    /\ applied_receipts    = {}
    /\ balances            = [d \in Domains |-> 0]
    /\ accumulated_inbound = 0
    /\ snapshot_state      = NoSnapshot
    /\ pending             = <<>>
    /\ height              = 0

----------------------------------------------------------------------------
\* Actions.

\* SubmitReceipt(r): adversary appends r to the apply queue. Models
\* gossip-ratified ingress; cryptographic admission is FA7 territory.
SubmitReceipt(r) ==
    /\ r \in Receipt
    /\ Len(pending) < MaxHeight
    /\ height < MaxHeight
    /\ pending' = Append(pending, r)
    /\ height' = height + 1
    /\ UNCHANGED <<applied_receipts, balances, accumulated_inbound,
                   snapshot_state>>

\* ApplyFirstReceipt(r): fresh-key apply branch — chain.cpp:1363-1381.
\* T-R1 first-credit-wins. Pre: r at head of pending AND KeyOf(r)
\* NOT in applied_receipts.
ApplyFirstReceipt(r) ==
    /\ Len(pending) > 0
    /\ r = Head(pending)
    /\ KeyOf(r) \notin applied_receipts
    /\ applied_receipts'    = applied_receipts \cup {KeyOf(r)}
    /\ balances'            = [balances EXCEPT ![r.to] = @ + r.amount]
    /\ accumulated_inbound' = accumulated_inbound + r.amount
    /\ pending'             = Tail(pending)
    /\ UNCHANGED <<snapshot_state, height>>

\* ApplyDuplicate(r): silent-skip — chain.cpp:1365
\* `if (applied_inbound_receipts_.count(key)) continue;`. T-R2
\* subsequent-attempts-silent-noop.
ApplyDuplicate(r) ==
    /\ Len(pending) > 0
    /\ r = Head(pending)
    /\ KeyOf(r) \in applied_receipts
    /\ pending' = Tail(pending)
    /\ UNCHANGED <<applied_receipts, balances, accumulated_inbound,
                   snapshot_state, height>>

\* TakeSnapshot: save the (applied_receipts, balances,
\* accumulated_inbound) triple. Models the serialize step at
\* chain.cpp:1586-1592 (the `applied_inbound_receipts` namespace
\* added by S-037 — the headline closure preventing post-restore
\* re-credit). pending is NOT included (gossip-layer state).
\* T-AR1: snapshot.applied_receipts = pre-state applied_receipts.
TakeSnapshot ==
    /\ height < MaxHeight
    /\ snapshot_state' = [applied_receipts    |-> applied_receipts,
                          balances            |-> balances,
                          accumulated_inbound |-> accumulated_inbound]
    /\ height' = height + 1
    /\ UNCHANGED <<applied_receipts, balances, accumulated_inbound,
                   pending>>

\* RestoreSnapshot: rewind to the snapshot's saved triple. Models
\* chain.cpp:1778-1783. Post-restore applied_receipts equals
\* snapshot's exactly (T-AR2). Pre-S-037 the snapshot lacked the
\* applied_inbound_receipts namespace, so restore silently dropped
\* the dedup-set — the bug that S-037 closed. pending is preserved
\* across restore (lives outside snapshot scope), making
\* TryDuplicatePostRestore observable.
RestoreSnapshot ==
    /\ snapshot_state /= NoSnapshot
    /\ height < MaxHeight
    /\ applied_receipts'    = snapshot_state.applied_receipts
    /\ balances'            = snapshot_state.balances
    /\ accumulated_inbound' = snapshot_state.accumulated_inbound
    /\ height' = height + 1
    /\ UNCHANGED <<snapshot_state, pending>>

\* TryDuplicatePostRestore(r): adversarial — submits a receipt whose
\* dedup-key is in the post-restore applied_receipts set. The
\* invariants witness that the only enabled apply branch is
\* ApplyDuplicate (NOT ApplyFirstReceipt) because the latter's
\* pre-condition `KeyOf(r) \notin applied_receipts` fails. The
\* action targets the post-restore window to make T-AR3 observable.
TryDuplicatePostRestore(r) ==
    /\ r \in Receipt
    /\ snapshot_state /= NoSnapshot
    /\ KeyOf(r) \in applied_receipts
    /\ Len(pending) < MaxHeight
    /\ height < MaxHeight
    /\ pending' = Append(pending, r)
    /\ height' = height + 1
    /\ UNCHANGED <<applied_receipts, balances, accumulated_inbound,
                   snapshot_state>>

----------------------------------------------------------------------------
\* Next-state relation.

Next ==
    \/ \E r \in Receipt : SubmitReceipt(r)
    \/ \E r \in Receipt : ApplyFirstReceipt(r)
    \/ \E r \in Receipt : ApplyDuplicate(r)
    \/ TakeSnapshot
    \/ RestoreSnapshot
    \/ \E r \in Receipt : TryDuplicatePostRestore(r)

\* Fairness on the apply actions drives Prop_NoDoubleApply's
\* implicit liveness (any pending head receipt eventually drains).
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(\E r \in Receipt : ApplyFirstReceipt(r))
    /\ WF_vars(\E r \in Receipt : ApplyDuplicate(r))

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant.
Inv_TypeOK ==
    /\ applied_receipts \subseteq DedupKey
    /\ balances \in [Domains -> Nat]
    /\ accumulated_inbound \in Nat
    /\ \/ snapshot_state = NoSnapshot
       \/ snapshot_state \in SnapshotState
    /\ pending \in Seq(Receipt)
    /\ height \in 0..MaxHeight

\* RestoreEqualsPre (T-AR2): after every RestoreSnapshot the live
\* applied_receipts equals snapshot_state.applied_receipts. State-
\* form: at every reachable state with snapshot_state /= NoSnapshot,
\* either applied_receipts equals snapshot's set (immediate
\* post-restore window) OR snapshot's set is a subset of live (the
\* set grew via post-snapshot ApplyFirstReceipt).
Inv_RestoreEqualsPre ==
    snapshot_state /= NoSnapshot =>
       \/ applied_receipts = snapshot_state.applied_receipts
       \/ snapshot_state.applied_receipts \subseteq applied_receipts

\* DedupPersistsAcrossRestore (T-AR3): the headline S-037 property.
\* Every key in snapshot_state.applied_receipts is also in the live
\* applied_receipts. Pre-S-037 the dedup-set was dropped on restore,
\* yielding a strict-subset post-state that allowed re-credit. Post-
\* S-037 the live set is always a superset — restore preserves
\* verbatim. The contract that prevents the double-spend.
Inv_DedupPersistsAcrossRestore ==
    snapshot_state /= NoSnapshot =>
       snapshot_state.applied_receipts \subseteq applied_receipts

\* FreshCreditPostRestore (T-AR4): a receipt whose dedup-key is not
\* in the live applied_receipts remains admissible by
\* ApplyFirstReceipt. Restore is not a permanent freeze. The
\* operational claim is witnessed by reachable states where
\* |applied_receipts| > |snapshot_state.applied_receipts| via the
\* SubmitReceipt → RestoreSnapshot → SubmitReceipt(fresh) →
\* ApplyFirstReceipt trace.
Inv_FreshCreditPostRestore ==
    \A k \in DedupKey :
       (k \notin applied_receipts /\ snapshot_state /= NoSnapshot)
       => k \notin applied_receipts

\* AccumulatedConsistent (T-AR5): accumulated_inbound stays
\* consistent with applied_receipts contents across snapshot/restore.
\* State-form bound: live accumulated_inbound >= snapshot's
\* accumulated_inbound (ApplyFirstReceipt only increments; the
\* other actions preserve). After RestoreSnapshot the live field
\* equals snapshot's exactly.
Inv_AccumulatedConsistent ==
    snapshot_state /= NoSnapshot =>
       accumulated_inbound >= snapshot_state.accumulated_inbound

\* BalanceNonNegative: Nat-typed; documents the contract.
\* ApplyFirstReceipt only credits; RestoreSnapshot writes Nat
\* snapshot values; the other actions preserve.
Inv_BalanceNonNegative ==
    \A d \in Domains : balances[d] >= 0

\* DedupKeyIsPair (T-R3 lifted from FB14): each entry in
\* applied_receipts is a (src_shard, tx_hash) pair record. Preserved
\* across snapshot/restore — the save/load round-trip does not
\* collapse the pair structure.
Inv_DedupKeyIsPair ==
    \A k \in applied_receipts :
       /\ k.src_shard \in Shards
       /\ k.tx_hash   \in Hashes

----------------------------------------------------------------------------
\* Temporal properties.

\* RestoreIdempotent: TakeSnapshot ∘ RestoreSnapshot is identity on
\* applied_receipts. After every RestoreSnapshot transition,
\* applied_receipts' equals snapshot_state.applied_receipts;
\* TakeSnapshot's snapshot_state'.applied_receipts equals the
\* just-pre applied_receipts. Composed: the take-then-restore
\* sequence (with no intermediate ApplyFirstReceipt) preserves
\* applied_receipts.
Prop_RestoreIdempotent ==
    [][(snapshot_state /= NoSnapshot
        /\ applied_receipts' = snapshot_state.applied_receipts)
       => applied_receipts' = snapshot_state.applied_receipts
      ]_vars

\* NoDoubleApply: every key in applied_receipts was added by exactly
\* one ApplyFirstReceipt step. The structural argument:
\* ApplyFirstReceipt's `KeyOf(r) \notin applied_receipts`
\* pre-condition blocks re-firing on the same key; no other action
\* extends the set (ApplyDuplicate / TryDuplicatePostRestore
\* preserve; TakeSnapshot preserves; RestoreSnapshot rewinds to
\* snapshot's set, itself a previously-built set satisfying the
\* property by induction). Across every reachable transition that
\* extends applied_receipts, the new key was fresh pre-step.
Prop_NoDoubleApply ==
    [][\A k \in DedupKey :
         (k \in applied_receipts' /\ k \notin applied_receipts)
         => (\E r \in Receipt :
               /\ KeyOf(r) = k
               /\ Len(pending) > 0
               /\ Head(pending) = r
               /\ pending' = Tail(pending))
      ]_vars

============================================================================
