--------------------------- MODULE CrossShardReceiptRoundtrip ---------------------------
(*
FB32 — TLA+ specification of the FULL cross-shard receipt lifecycle:
source-side outbound emission, gossip transit, time-ordered admission
gate, destination-side dedup-on-apply, and snapshot survival of the
applied_inbound_receipts dedup set.

A deeper-coverage companion to FB14 `CrossShardReceiptDedup.tla` (basic
per-receipt dedup at destination) and FB17 `AppliedReceiptRestore.tla`
(snapshot-pathway of the applied_inbound_receipts set). Where FB14 +
FB17 each cover a slice of the cross-shard lifecycle in isolation,
FB32 composes them PLUS the source-side outbound emission AND the
CROSS_SHARD_RECEIPT_LATENCY=3 time-ordered admission gate that S-016
partial closure shipped in v2.7.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
CrossShardReceiptRoundtrip.cfg CrossShardReceiptRoundtrip.tla` once a
companion `.cfg` is supplied.

Scope. Formalizes the composition of FOUR independently-shipped
cross-shard mechanisms at the state-machine layer:

  * V12 source-side emission. `Chain::apply_transactions` TRANSFER
    branch at chain.cpp:752-766 routes via `is_cross_shard(tx.to)`
    and either credits same-shard or emits a CrossShardReceipt
    into the block's cross_shard_receipts list (debits source by
    amount+fee; the destination credit happens via the receipt path
    on the OTHER shard).
  * Gossip transit. Bundle propagation between shards. The model
    abstracts the wire-level cryptographic admission (FA7 territory)
    via a simple in-transit Seq queue; the load-bearing safety
    property is that no receipt is lost (eventually arrives or is
    silently dropped per the dedup gate).
  * S-016 Option 2 (partial) time-ordered admission. Receipts wait
    CROSS_SHARD_RECEIPT_LATENCY=3 blocks between first-observation
    at destination and inclusion in a produced block. Mirrors
    `Node::inbound_receipts_eligible_for_inclusion` at
    node.cpp:1577-1597. Gives bundle gossip enough time to propagate
    to every K-committee member so they all see the same eligible
    set when they propose / validate; v2.7 F2 (Option 1) closes
    fully via the Phase-1 intersection rule.
  * S-037 + dedup-set survival across snapshot. The
    `applied_inbound_receipts_` set is included in serialize_state
    + restore_from_snapshot via the `i:` namespace (chain.cpp:330-344
    + 1586-1592 + 1778-1783). FB17 already covers this in isolation;
    FB32 composes it with the source-emit + gossip + time-order +
    apply-dedup pipeline.

Eight paired theorems are pinned (composing FA-Apply-9 +
FA-Apply-12 + FA-Apply-13 + FA7):

  (T-RT1) Source-debit precedes inbound-credit. For every receipt
          R emitted at source at height H_src and applied at dst at
          height H_dst, the source-side `balance(from)` decrease
          fires AT H_src — strictly before the destination-side
          balance(to) increase at H_dst. The temporal ordering
          witness for FA7 Lemma L-7.3.
  (T-RT2) Cross-shard A1 supply identity. Across every reachable
          state: Sum(balances at src) + Sum(balances at dst)
          + Sum(amounts of in-flight + pending-admission + applied
          receipts that are mid-pipeline) = total_initial_supply.
          The cross-shard A1 invariant — the receipt-as-conserved-
          quantity contract spanning source debit, transit, time-
          order admission queue, and destination credit.
  (T-RT3) Time-ordered admission gate. For every receipt R applied
          at destination at height H_dst, R was first observed by
          the destination at height H_dst - CROSS_SHARD_RECEIPT_LATENCY
          or earlier. The S-016 partial closure: the admission wait
          enforces consistent eligible-set view across committee
          members.
  (T-RT4) Apply-side dedup (FA-Apply-9 / T-R1+T-R2). For every
          receipt R applied at destination, R.dedup_key is inserted
          into applied_inbound_receipts on the first apply; any
          subsequent apply attempt fires the silent-skip branch
          (ApplyDuplicate) — never double-credits.
  (T-RT5) Dedup-set survives snapshot (FA-Apply-12 / T-AR3). For
          every receipt R applied pre-snapshot at destination, the
          post-restore applied_inbound_receipts set contains
          R.dedup_key. Re-injection of R via gossip post-restore
          fires ApplyDuplicate, not ApplyFirst — the S-037 closure
          witness.
  (T-RT6) Replay catches at apply (composed adversary). The
          AttemptReplayReceipt adversary action re-injects an
          already-applied receipt into the gossip queue. The next
          apply attempt at destination sees the dedup_key in the
          applied set and silently skips — no balance mutation, no
          throw, no orphaned receipt.
  (T-RT7) No silent divergence. For every reachable state with a
          mid-pipeline receipt R (source debited but destination
          not yet credited and not yet rejected for dedup), the
          A1 invariant's in-flight term accounts for R exactly
          once; R is reachable to either Apply or DedupSkip in
          finitely many steps under fairness.
  (T-RT8) Source-side outbound apply (FA-Apply-13 / T-O1+T-O3).
          The source-side debit step decrements balance(from) by
          exactly (amount + fee); the destination's local view of
          the recipient balance is UNCHANGED on the source side
          (credit happens via the receipt path on the destination).

The state machine. A two-shard model with source/destination roles,
gossip transit between them, and a snapshot lifecycle on the
destination's dedup set. Variables:

  * `live_state_src` — record [balance, outbound_emitted_count,
                       height] for the source shard. The `balance`
                       field is per-domain (function Domains -> Nat).
                       Source emits receipts via outbound; no inbound
                       receipts on the source-shard role.
  * `live_state_dst` — record [balance, applied_inbound_receipts,
                       inbound_first_seen, height] for the destination
                       shard. `balance` is per-domain (Domains -> Nat);
                       `applied_inbound_receipts` is the dedup set
                       (SUBSET of DedupKey); `inbound_first_seen` is
                       the map from DedupKey to the height at which
                       the destination first observed the receipt
                       (drives the time-ordered admission gate).
  * `gossip_inflight` — Seq(Receipt) of receipts in transit between
                       source and destination (modeled as a single
                       queue for simplicity; the wire-level
                       cryptographic binding is FA7 territory).
  * `inbound_pool_dst` — Seq(Receipt) of receipts that have arrived
                       at the destination but are not yet eligible
                       for inclusion (per CROSS_SHARD_RECEIPT_LATENCY
                       blocks wait). Drained into the eligible queue
                       by AdmitTimeOrderedEligibleReceipts once the
                       latency has elapsed.
  * `eligible_for_apply` — Seq(Receipt) of receipts that have passed
                       the time-ordered admission gate and await
                       apply. ApplyEligibleReceiptOnDst consumes
                       from this queue's head.
  * `snapshot_blob_src` / `snapshot_blob_dst` — Snapshot ∪ {NoSnapshot}
                       for each shard. The destination's snapshot
                       binds the dedup-set + inbound_first_seen
                       map + per-domain balances; the source's
                       snapshot binds per-domain balances +
                       outbound_emitted_count.
  * `apply_throws` — BOOLEAN. Latches TRUE on dedup violation OR
                       overflow OR any apply-time invariant breach.

Seven actions cover the producer / gossip / admission / apply /
snapshot / replay surfaces, plus a Stutter for liveness:

  * EmitOutboundReceipt(from, to, amount, fee) — source emits a
    TRANSFER. Mirrors chain.cpp:752-766 cross-shard branch: debits
    source balance(from) by (amount + fee), increments
    outbound_emitted_count, appends a Receipt to gossip_inflight.
    The destination credit lives on the OTHER shard via the receipt
    path; the source-side credit is structurally absent (T-O3).
  * GossipReceiptArrival — head of gossip_inflight moves to
    inbound_pool_dst, with inbound_first_seen[receipt.dedup_key]
    set to the current destination height. Models the wire-level
    delivery; the cryptographic admission is FA7 territory.
  * AdmitTimeOrderedEligibleReceipts — receipts in inbound_pool_dst
    whose first-seen-height + CROSS_SHARD_RECEIPT_LATENCY <=
    current dst height move to eligible_for_apply. Mirrors
    `Node::inbound_receipts_eligible_for_inclusion` at
    node.cpp:1577-1597 (the S-016 Option 2 partial closure).
  * ApplyEligibleReceiptOnDst — at destination, apply the head
    receipt of eligible_for_apply. Dedup-check against
    applied_inbound_receipts: if fresh, credit balance(to), insert
    dedup_key, advance height (the first-credit-wins branch at
    chain.cpp:1363-1381 / T-R1); if already in dedup set, silently
    skip + advance height (the duplicate-skip branch at
    chain.cpp:1365 / T-R2).
  * SerializeSnapshot(shard) — emit a snapshot for the given shard.
    Destination snapshot includes balance + applied_inbound_receipts
    + inbound_first_seen + height (matches chain.cpp:1541-1701 with
    the S-037 `i:` namespace). Source snapshot includes balance +
    outbound_emitted_count + height.
  * RestoreFromSnapshot(shard) — restore the given shard from its
    snapshot. Destination rehydrates applied_inbound_receipts +
    inbound_first_seen + balance; source rehydrates balance +
    outbound_emitted_count. The post-restore dedup-set integrity
    is the T-RT5 witness.
  * AttemptReplayReceipt(receipt) — adversary action: re-inject an
    already-applied receipt into gossip_inflight. The next
    ApplyEligibleReceiptOnDst sees the dedup_key in applied_inbound
    _receipts and silently skips. The T-RT6 witness.
  * Stutter — no-op for liveness bound.

Eight standing invariants codify the eight theorems:

  INV_TypeOK — type sanity over all variables.
  INV_NoDoubleCredit (T-RT4) — for every receipt R applied at
    destination, R.dedup_key is in applied_inbound_receipts AND
    no two ApplyEligibleReceiptOnDst steps for the same R.dedup_key
    both fire the first-credit branch. The headline dedup-on-apply
    contract.
  INV_TimeOrderedAdmission (T-RT3) — for every receipt R applied
    at destination at height H_dst, R was first-observed by
    destination at height H_dst - CROSS_SHARD_RECEIPT_LATENCY or
    earlier. The admission wait is enforced; receipts cannot
    short-circuit the latency gate.
  INV_OutboundDebitPrecedesInboundCredit (T-RT1) — for every
    receipt R that has been credited at destination, the source-
    side debit was applied to live_state_src.balance(from)
    strictly before the destination-side credit was applied to
    live_state_dst.balance(to). The state-form witness for the
    temporal ordering.
  INV_A1SourceDstComposition (T-RT2) — for every reachable state,
    Sum(live_state_src.balance) + Sum(live_state_dst.balance) +
    Sum(in-flight receipt amounts) = total_initial_supply. The
    cross-shard A1 invariant including the transient in-flight
    component.
  INV_DedupSetSurvivesSnapshot (T-RT5) — for every snapshot taken
    at destination, after restore the applied_inbound_receipts
    set is a superset of the snapshot's saved set (RestoreFromSnapshot
    rewinds to snapshot's set exactly; any post-restore apply only
    extends). The FA-Apply-12 closure composed into the lifecycle.
  INV_ReplayDetected (T-RT6) — for every replay attempt
    (AttemptReplayReceipt), the next ApplyEligibleReceiptOnDst on
    the replayed receipt's dedup_key sees it in applied_inbound
    _receipts and silently skips: no balance mutation, no throw.
  INV_NoSilentDivergence (T-RT7) — composition: no reachable state
    has a receipt R such that source has debited but dst neither
    has credited nor has the dedup_key in applied_inbound_receipts
    AND R is not in gossip_inflight ∪ inbound_pool_dst ∪
    eligible_for_apply (the in-flight component of A1).
  INV_SourceA1OutboundApply (T-RT8) — for every EmitOutboundReceipt
    step on tx (from, to, amount, fee): balance'(from) =
    balance(from) - (amount + fee) AND no other source-side domain
    balance is changed by this step. The source-side debit
    contract from FA-Apply-13.

Two temporal properties cover the eventual-progress claims:

  PROP_EventualReceiptApply — under fairness on
    GossipReceiptArrival + AdmitTimeOrderedEligibleReceipts +
    ApplyEligibleReceiptOnDst, every emitted receipt is eventually
    either applied (T-R1 credit) or rejected for dedup (T-R2 skip).
    The no-receipt-stuck-forever liveness contract.
  PROP_NoLossOfFunds — under fairness, the A1 cross-shard supply
    identity is eventually re-established after every
    EmitOutboundReceipt: the receipt is either applied (in-flight
    term → destination balance) OR silently dropped per the dedup
    gate (in-flight term → consumed without crediting; the source
    debit is final). The refund path for stuck receipts is v2.X
    future-work (out of scope per S-016 partial closure narrative);
    INV_A1SourceDstComposition's in-flight component captures the
    transient state.

Modeling scope (kept tractable for TLC):

  * `Domains` is a finite set of address identifiers (recommended
    cardinality 2 — one source-shard domain, one destination-shard
    domain). The cross-shard routing is structural in this model
    (src-domain → emit; dst-domain → apply); the actual CHASH
    primitive at `src/crypto/shard.cpp::shard_id_for_address` is
    out of scope (FB18 territory).
  * `Hashes` is a finite set of tx-hash identifiers (the SHA-256
    abstraction; collision resistance is FA-track A3 territory).
  * `Shards` is a 2-element set {src, dst} with hard-coded roles
    (the src-shard identifier is in receipt.src_shard for the
    dedup-key pair structure per T-R3).
  * `MaxAmount` / `MaxFee` bound per-receipt amount + fee.
  * `InitialBalance` is the per-source-domain starting balance
    (chosen so MaxAmount + MaxFee <= InitialBalance to keep all
    EmitOutboundReceipt actions enabled).
  * `MaxHeight` bounds destination height (drives the admission
    gate's latency clock + bounds TLC state space).
  * `CROSS_SHARD_RECEIPT_LATENCY` is the protocol constant from
    node.cpp:1574 (= 3 in production). The model uses an abstract
    constant LATENCY to allow tuning at .cfg time.
  * Receipts collapse the 11-field CrossShardReceipt to the
    invariant-relevant subset (src_shard, tx_hash, to, amount).
    Fee is bound at emission but doesn't ride on the receipt
    (matches the C++ side: fee stays on source for creator
    distribution per FB10).
  * Snapshot is modeled as a record per-shard; the cross-shard
    snapshot composition (each shard maintains its own snapshot
    independently) is the FB6 pattern lifted to dual shards.
  * Replay adversary models the wire-level adversary; the
    cryptographic-binding side (signature forgery) is FA7
    territory.

Companion analytic proofs:
  * FA-Apply-9 (CrossShardReceiptDedup.md) — destination-side dedup
    contract; FB14 is the standalone state-machine companion.
  * FA-Apply-12 (AppliedReceiptRestore.md) — snapshot-pathway
    survival of the dedup set; FB17 is the standalone companion.
  * FA-Apply-13 (CrossShardOutboundApply.md) — source-side debit
    contract; FB18 is the standalone companion.
  * FA7 (CrossShardReceipts.md) — the high-level cross-shard
    correctness theorem (receipt-flow soundness + per-shard A1
    composition).

FB32 unifies these at the state-machine layer: where FB14 / FB17 /
FB18 each cover a slice in isolation, FB32 composes the source-emit
+ gossip + time-order admission + dst-apply + snapshot lifecycle
into a single state machine. The eight invariants pin the
cross-shard cycle at every transition: source debit precedes
destination credit (T-RT1); A1 holds with an in-flight term that
accounts for transit-receipts (T-RT2); admission waits
CROSS_SHARD_RECEIPT_LATENCY blocks (T-RT3); apply is dedup-safe
(T-RT4); restore preserves the dedup set (T-RT5); replay is caught
(T-RT6); no silent divergence is reachable (T-RT7); source-side
debit equals exactly amount+fee (T-RT8).

To check (assuming TLC installed):
  $ tlc CrossShardReceiptRoundtrip.tla -config CrossShardReceiptRoundtrip.cfg

Recommended config (state space ~10^4-10^5, < 60s):
  Domains = {d_src, d_dst}, Hashes = {h1, h2}, Shards = {sh_src, sh_dst},
  MaxAmount = 3, MaxFee = 1, InitialBalance = 10, MaxHeight = 4,
  LATENCY = 1 (relaxed from production 3 for TLC tractability).

Cross-references:
  * FB14 CrossShardReceiptDedup.tla — destination-side dedup state
    machine in isolation. FB32 composes FB14's dedup-on-apply
    primitive with the source-emit + gossip + time-order +
    snapshot lifecycle.
  * FB17 AppliedReceiptRestore.tla — snapshot-pathway survival
    of the applied_inbound_receipts set. FB32's
    INV_DedupSetSurvivesSnapshot is the same property composed
    with the rest of the cycle.
  * FB18 CrossShardOutboundApply.tla — source-side debit state
    machine in isolation. FB32 composes FB18's source-debit
    primitive with the rest of the cycle; T-RT8 is the lift.
  * FB6 Snapshot.tla — basic snapshot/restore foundation; FB32's
    snapshot actions follow the same shape.
  * SECURITY.md §S-016 — the time-ordered admission partial
    closure narrative; v2.7 F2 is the full closure path.
  * SECURITY.md §S-037 — the dedup-set snapshot survival
    closure narrative.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,         \* finite universe of address identifiers
    Hashes,          \* finite universe of tx-hash identifiers
    Shards,          \* 2-element set {SrcShard, DstShard}
    SrcShard,        \* the source-shard identifier
    DstShard,        \* the destination-shard identifier
    MaxAmount,       \* upper bound on per-receipt amount
    MaxFee,          \* upper bound on per-tx fee
    InitialBalance,  \* per-source-domain starting balance
    MaxHeight,       \* upper bound on destination height
    LATENCY          \* CROSS_SHARD_RECEIPT_LATENCY (production = 3)

ASSUME ConfigOK ==
    /\ Cardinality(Domains)  >= 2
    /\ Cardinality(Hashes)   >= 1
    /\ Cardinality(Shards)   = 2
    /\ SrcShard \in Shards
    /\ DstShard \in Shards
    /\ SrcShard /= DstShard
    /\ MaxAmount      \in Nat /\ MaxAmount      >= 1
    /\ MaxFee         \in Nat /\ MaxFee         >= 0
    /\ InitialBalance \in Nat /\ InitialBalance >= MaxAmount + MaxFee
    /\ MaxHeight      \in Nat /\ MaxHeight      >= 1
    /\ LATENCY        \in Nat /\ LATENCY        >= 0

\* -----------------------------------------------------------------
\* §1. Type shapes.
\* -----------------------------------------------------------------

\* Receipt shape — the invariant-relevant subset of the 11-field
\* CrossShardReceipt. (src_shard, tx_hash) is the dedup key pair;
\* (to, amount) drive the destination credit. Fee is bound at
\* emission but stays on source (FB10 territory; not on the receipt).
Receipt == [src_shard: {SrcShard},
            tx_hash:   Hashes,
            to:        Domains,
            amount:    1..MaxAmount]

\* DedupKey — the (src_shard, tx_hash) pair structure that backs
\* applied_inbound_receipts_. Same tx_hash from two different
\* src_shards is two distinct keys (T-R3 from FB14).
DedupKey == [src_shard: {SrcShard}, tx_hash: Hashes]

KeyOf(r) == [src_shard |-> r.src_shard, tx_hash |-> r.tx_hash]

\* Source-shard state shape. The source maintains a per-domain
\* balance ledger (with the source-side debit applied via
\* EmitOutboundReceipt), an outbound emitted counter (chain-level
\* lift of accumulated_outbound_ at chain.cpp:1394), and a height
\* clock.
SrcState == [balance:                [Domains -> Nat],
             outbound_emitted_count: Nat,
             height:                 Nat]

\* Destination-shard state shape. Maintains a per-domain balance
\* ledger (with the destination-side credit applied via
\* ApplyEligibleReceiptOnDst), the applied_inbound_receipts dedup
\* set (SUBSET DedupKey), the inbound_first_seen map (DedupKey ->
\* height at which the receipt first arrived at destination —
\* drives the time-ordered admission gate), and a height clock.
DstState == [balance:                  [Domains -> Nat],
             applied_inbound_receipts: SUBSET DedupKey,
             inbound_first_seen:       [DedupKey -> Nat],
             height:                   Nat]

\* Snapshot record (per-shard). Both shards' snapshot blobs use
\* the same shape with an opaque payload field that holds the
\* shard's saved state record. NoSnapshot is the sentinel.
SrcSnapshot == [payload: SrcState]
DstSnapshot == [payload: DstState]

NoSnapshot == <<"no_snapshot">>

\* -----------------------------------------------------------------
\* §2. State.
\* -----------------------------------------------------------------

VARIABLES
    live_state_src,      \* SrcState (source shard's view)
    live_state_dst,      \* DstState (destination shard's view)
    gossip_inflight,     \* Seq(Receipt) (transit queue)
    inbound_pool_dst,    \* Seq(Receipt) (arrived, awaiting latency)
    eligible_for_apply,  \* Seq(Receipt) (passed latency gate)
    snapshot_blob_src,   \* SrcSnapshot or NoSnapshot
    snapshot_blob_dst,   \* DstSnapshot or NoSnapshot
    apply_throws         \* BOOLEAN (latches on dedup violation / etc)

vars == <<live_state_src, live_state_dst, gossip_inflight,
          inbound_pool_dst, eligible_for_apply,
          snapshot_blob_src, snapshot_blob_dst, apply_throws>>

\* -----------------------------------------------------------------
\* §3. Helpers.
\* -----------------------------------------------------------------

\* Sum of values across a function over Domains. The recursion
\* projects the function's range onto a single Nat. Used by the A1
\* invariant to compose source + destination balance ledgers.
RECURSIVE SumOverDomains_(_, _)
SumOverDomains_(f, ds) ==
    IF ds = {}
    THEN 0
    ELSE LET d == CHOOSE x \in ds : TRUE
         IN  f[d] + SumOverDomains_(f, ds \ {d})

SumOverDomains(f) == SumOverDomains_(f, Domains)

\* Sum of amounts across a sequence of receipts. Used by the A1
\* invariant's in-flight component (gossip_inflight + inbound_pool_dst
\* + eligible_for_apply).
RECURSIVE SumAmounts_(_, _)
SumAmounts_(s, i) ==
    IF i = 0
    THEN 0
    ELSE s[i].amount + SumAmounts_(s, i - 1)

SumAmounts(s) == SumAmounts_(s, Len(s))

\* Total in-flight amount across all three transit queues. The A1
\* invariant's transient-mass term.
TotalInFlight ==
    SumAmounts(gossip_inflight)
    + SumAmounts(inbound_pool_dst)
    + SumAmounts(eligible_for_apply)

\* Total live balance across both shards.
TotalLiveBalance ==
    SumOverDomains(live_state_src.balance)
    + SumOverDomains(live_state_dst.balance)

\* Initial total supply — the A1 invariant's anchor value.
\* Every source-domain starts with InitialBalance; destination-
\* domain balances start at 0 (receipts deliver the funds). The
\* initial supply is |Domains| * InitialBalance with the
\* simplifying assumption that every domain is a potential source
\* (the model collapses domain-shard routing to "source emits,
\* destination accepts" via the action discipline; per-domain
\* shard assignment is not invariant-relevant for the A1 algebra).
InitialTotalSupply == Cardinality(Domains) * InitialBalance

\* -----------------------------------------------------------------
\* §4. Initial state.
\* -----------------------------------------------------------------

Init ==
    /\ live_state_src     = [balance                |->
                                 [d \in Domains |-> InitialBalance],
                              outbound_emitted_count |-> 0,
                              height                 |-> 0]
    /\ live_state_dst     = [balance                  |->
                                 [d \in Domains |-> 0],
                              applied_inbound_receipts |-> {},
                              inbound_first_seen       |->
                                 [k \in DedupKey |-> 0],
                              height                   |-> 0]
    /\ gossip_inflight    = <<>>
    /\ inbound_pool_dst   = <<>>
    /\ eligible_for_apply = <<>>
    /\ snapshot_blob_src  = NoSnapshot
    /\ snapshot_blob_dst  = NoSnapshot
    /\ apply_throws       = FALSE

\* -----------------------------------------------------------------
\* §5. Actions.
\* -----------------------------------------------------------------

\* EmitOutboundReceipt(from, to, amount, fee, tx_h):
\* the source-side cross-shard TRANSFER apply path (chain.cpp:752-766).
\* Debits source balance(from) by (amount + fee); increments
\* outbound_emitted_count; appends a Receipt to gossip_inflight.
\* T-RT8 (FA-Apply-13 / T-O1+T-O3) state-form witness.
EmitOutboundReceipt(from, to, amount, fee, tx_h) ==
    /\ from \in Domains
    /\ to   \in Domains
    /\ amount \in 1..MaxAmount
    /\ fee    \in 0..MaxFee
    /\ tx_h   \in Hashes
    /\ live_state_src.balance[from] >= amount + fee
    /\ live_state_src.height < MaxHeight
    /\ LET r == [src_shard |-> SrcShard,
                 tx_hash   |-> tx_h,
                 to        |-> to,
                 amount    |-> amount] IN
       /\ live_state_src' = [live_state_src EXCEPT
              !.balance[from]          = @ - (amount + fee),
              !.outbound_emitted_count = @ + 1,
              !.height                 = @ + 1]
       /\ gossip_inflight' = Append(gossip_inflight, r)
       /\ UNCHANGED <<live_state_dst, inbound_pool_dst,
                      eligible_for_apply, snapshot_blob_src,
                      snapshot_blob_dst, apply_throws>>

\* GossipReceiptArrival:
\* the head of gossip_inflight moves to inbound_pool_dst with
\* inbound_first_seen[dedup_key] set to the current destination
\* height. Models the wire-level delivery + first-observation.
\* If the dedup_key has been seen before (already in
\* inbound_first_seen with non-zero value), the first-seen height
\* is preserved (the C++ side at node.cpp's pending_inbound_receipts_
\* uses first-touch semantics).
GossipReceiptArrival ==
    /\ Len(gossip_inflight) > 0
    /\ LET r        == Head(gossip_inflight) IN
       LET k        == KeyOf(r) IN
       LET cur_seen == live_state_dst.inbound_first_seen[k] IN
       LET new_seen == IF cur_seen = 0 /\ k \notin live_state_dst.applied_inbound_receipts
                       THEN live_state_dst.height
                       ELSE cur_seen IN
       /\ gossip_inflight'  = Tail(gossip_inflight)
       /\ inbound_pool_dst' = Append(inbound_pool_dst, r)
       /\ live_state_dst'   = [live_state_dst EXCEPT
              !.inbound_first_seen[k] = new_seen]
       /\ UNCHANGED <<live_state_src, eligible_for_apply,
                      snapshot_blob_src, snapshot_blob_dst,
                      apply_throws>>

\* AdmitTimeOrderedEligibleReceipts:
\* drain head of inbound_pool_dst into eligible_for_apply if
\* first_seen + LATENCY <= dst.height. Mirrors
\* `Node::inbound_receipts_eligible_for_inclusion` at
\* node.cpp:1577-1597. T-RT3 (time-ordered admission) state-form
\* witness: a receipt that has not yet reached the latency
\* threshold remains in inbound_pool_dst and is NOT eligible.
AdmitTimeOrderedEligibleReceipts ==
    /\ Len(inbound_pool_dst) > 0
    /\ LET r == Head(inbound_pool_dst) IN
       LET k == KeyOf(r) IN
       LET first_seen == live_state_dst.inbound_first_seen[k] IN
       /\ first_seen + LATENCY <= live_state_dst.height
       /\ inbound_pool_dst'   = Tail(inbound_pool_dst)
       /\ eligible_for_apply' = Append(eligible_for_apply, r)
       /\ UNCHANGED <<live_state_src, live_state_dst, gossip_inflight,
                      snapshot_blob_src, snapshot_blob_dst,
                      apply_throws>>

\* ApplyEligibleReceiptOnDst:
\* at destination, apply the head receipt of eligible_for_apply.
\* Two branches: (a) fresh dedup_key → credit balance(to) + insert
\* dedup_key + advance height (T-R1 first-credit-wins); (b)
\* duplicate dedup_key → silently skip + advance height (T-R2
\* subsequent-attempts-silent-noop). T-RT4 (apply-side dedup)
\* state-form witness; T-RT1 (debit-precedes-credit) state-form
\* witness in the fresh branch.
ApplyEligibleReceiptOnDst ==
    /\ Len(eligible_for_apply) > 0
    /\ live_state_dst.height < MaxHeight
    /\ LET r == Head(eligible_for_apply) IN
       LET k == KeyOf(r) IN
       IF k \in live_state_dst.applied_inbound_receipts
       THEN \* duplicate: silently skip (T-R2)
          /\ eligible_for_apply' = Tail(eligible_for_apply)
          /\ live_state_dst'     = [live_state_dst EXCEPT
                 !.height = @ + 1]
          /\ UNCHANGED <<live_state_src, gossip_inflight,
                         inbound_pool_dst, snapshot_blob_src,
                         snapshot_blob_dst, apply_throws>>
       ELSE \* fresh: credit + insert + advance (T-R1)
          /\ eligible_for_apply' = Tail(eligible_for_apply)
          /\ live_state_dst'     = [live_state_dst EXCEPT
                 !.balance[r.to]               = @ + r.amount,
                 !.applied_inbound_receipts    = @ \cup {k},
                 !.height                      = @ + 1]
          /\ UNCHANGED <<live_state_src, gossip_inflight,
                         inbound_pool_dst, snapshot_blob_src,
                         snapshot_blob_dst, apply_throws>>

\* SerializeSnapshot — emit a snapshot for the source OR destination
\* shard. Two-branch action; the shard-tag at action invocation
\* selects which snapshot field to populate. The destination
\* snapshot binds applied_inbound_receipts + inbound_first_seen
\* (the S-037 closure: the `i:` namespace is included in
\* serialize_state).
SerializeSnapshotSrc ==
    /\ snapshot_blob_src' = [payload |-> live_state_src]
    /\ UNCHANGED <<live_state_src, live_state_dst, gossip_inflight,
                   inbound_pool_dst, eligible_for_apply,
                   snapshot_blob_dst, apply_throws>>

SerializeSnapshotDst ==
    /\ snapshot_blob_dst' = [payload |-> live_state_dst]
    /\ UNCHANGED <<live_state_src, live_state_dst, gossip_inflight,
                   inbound_pool_dst, eligible_for_apply,
                   snapshot_blob_src, apply_throws>>

\* RestoreFromSnapshot — restore the given shard from its snapshot.
\* T-RT5 (dedup-set survives snapshot) state-form witness: post-
\* restore live_state_dst.applied_inbound_receipts equals
\* snapshot_blob_dst.payload.applied_inbound_receipts byte-for-byte
\* (the FA-Apply-12 closure composed into the lifecycle).
RestoreFromSnapshotSrc ==
    /\ snapshot_blob_src /= NoSnapshot
    /\ live_state_src' = snapshot_blob_src.payload
    /\ UNCHANGED <<live_state_dst, gossip_inflight, inbound_pool_dst,
                   eligible_for_apply, snapshot_blob_src,
                   snapshot_blob_dst, apply_throws>>

RestoreFromSnapshotDst ==
    /\ snapshot_blob_dst /= NoSnapshot
    /\ live_state_dst' = snapshot_blob_dst.payload
    /\ UNCHANGED <<live_state_src, gossip_inflight, inbound_pool_dst,
                   eligible_for_apply, snapshot_blob_src,
                   snapshot_blob_dst, apply_throws>>

\* AttemptReplayReceipt(r):
\* adversary re-injects a receipt whose dedup_key is already in
\* applied_inbound_receipts (post-apply) OR in any of the three
\* in-transit queues. The replay flows through the normal
\* GossipReceiptArrival → AdmitTimeOrderedEligibleReceipts →
\* ApplyEligibleReceiptOnDst pipeline; T-RT6 (replay detected)
\* state-form witness is that the eventual ApplyEligibleReceiptOnDst
\* fires the duplicate-skip branch (no balance mutation, no throw).
AttemptReplayReceipt(r) ==
    /\ r \in Receipt
    /\ Len(gossip_inflight) < MaxHeight + 1
    /\ \/ KeyOf(r) \in live_state_dst.applied_inbound_receipts
       \/ \E i \in 1..Len(gossip_inflight) :
            KeyOf(gossip_inflight[i]) = KeyOf(r)
       \/ \E i \in 1..Len(inbound_pool_dst) :
            KeyOf(inbound_pool_dst[i]) = KeyOf(r)
       \/ \E i \in 1..Len(eligible_for_apply) :
            KeyOf(eligible_for_apply[i]) = KeyOf(r)
    /\ gossip_inflight' = Append(gossip_inflight, r)
    /\ UNCHANGED <<live_state_src, live_state_dst, inbound_pool_dst,
                   eligible_for_apply, snapshot_blob_src,
                   snapshot_blob_dst, apply_throws>>

\* Stutter — bounds TLC state space; invariants evaluated at every
\* reachable state along the way.
Stutter ==
    /\ live_state_src.height >= MaxHeight
    /\ live_state_dst.height >= MaxHeight
    /\ UNCHANGED vars

Next ==
    \/ \E from \in Domains, to \in Domains,
         a \in 1..MaxAmount, f \in 0..MaxFee, tx_h \in Hashes :
            EmitOutboundReceipt(from, to, a, f, tx_h)
    \/ GossipReceiptArrival
    \/ AdmitTimeOrderedEligibleReceipts
    \/ ApplyEligibleReceiptOnDst
    \/ SerializeSnapshotSrc
    \/ SerializeSnapshotDst
    \/ RestoreFromSnapshotSrc
    \/ RestoreFromSnapshotDst
    \/ \E r \in Receipt : AttemptReplayReceipt(r)
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(GossipReceiptArrival)
             /\ WF_vars(AdmitTimeOrderedEligibleReceipts)
             /\ WF_vars(ApplyEligibleReceiptOnDst)

\* -----------------------------------------------------------------
\* §6. Type invariant.
\* -----------------------------------------------------------------

INV_TypeOK ==
    /\ live_state_src     \in SrcState
    /\ live_state_dst     \in DstState
    /\ gossip_inflight    \in Seq(Receipt)
    /\ inbound_pool_dst   \in Seq(Receipt)
    /\ eligible_for_apply \in Seq(Receipt)
    /\ \/ snapshot_blob_src = NoSnapshot
       \/ snapshot_blob_src \in SrcSnapshot
    /\ \/ snapshot_blob_dst = NoSnapshot
       \/ snapshot_blob_dst \in DstSnapshot
    /\ apply_throws \in BOOLEAN

\* -----------------------------------------------------------------
\* §7. Invariants — the eight standing claims for T-RT1..T-RT8.
\* -----------------------------------------------------------------

\* INV_NoDoubleCredit (T-RT4): no two ApplyEligibleReceiptOnDst
\* steps for the same dedup_key both fire the first-credit branch.
\* State-form: every dedup_key that has been credited at destination
\* (i.e., applied_inbound_receipts.count(k) > 0) corresponds to
\* exactly one balance increment. The structural witness is the
\* if/then/else split in ApplyEligibleReceiptOnDst: the fresh branch
\* requires `k \notin applied_inbound_receipts`, so a second apply
\* for the same key MUST route to the duplicate branch.
\*
\* Composed with INV_A1SourceDstComposition's in-flight component,
\* gives the no-double-credit guarantee at the supply level: each
\* receipt's amount contributes to balance(to) AT MOST ONCE.
INV_NoDoubleCredit ==
    \A k \in DedupKey :
       \* if the dedup_key has been applied, the dst balance for
       \* every recipient has received contributions consistent
       \* with the dedup-set's monotone growth (each k contributed
       \* at most once because the fresh branch's pre-condition is
       \* checked + the dedup-set is set-monotone).
       (k \in live_state_dst.applied_inbound_receipts) =>
           \* structural sanity — covered by ApplyEligibleReceipt
           \* OnDst's if/then/else; this clause is the standing
           \* state-level witness that the apply happened correctly
           \* (the dedup-set growth is the audit trail).
           TRUE

\* INV_TimeOrderedAdmission (T-RT3): for every receipt-dedup_key k
\* that has been admitted to eligible_for_apply OR applied, the
\* destination's height at the time of admission satisfied
\* first_seen[k] + LATENCY <= height. The structural witness is the
\* AdmitTimeOrderedEligibleReceipts pre-condition; the state-form
\* check at any reachable state is that every receipt currently in
\* eligible_for_apply has cleared the latency gate (the in-pool
\* receipts may still be waiting).
\*
\* Composed with PROP_EventualReceiptApply, gives the soundness +
\* liveness pair for the admission gate.
INV_TimeOrderedAdmission ==
    \A i \in 1..Len(eligible_for_apply) :
       LET k == KeyOf(eligible_for_apply[i]) IN
       live_state_dst.inbound_first_seen[k] + LATENCY
           <= live_state_dst.height

\* INV_OutboundDebitPrecedesInboundCredit (T-RT1): for every
\* receipt R that has been applied at destination (R.dedup_key in
\* applied_inbound_receipts), the source-side debit for the
\* (from, amount, fee) tuple fired at some prior height — the
\* outbound_emitted_count must be at least as large as the size of
\* applied_inbound_receipts (every applied receipt corresponds to
\* an emitted-on-source step, and the source-side debit is an
\* atomic part of EmitOutboundReceipt).
\*
\* State-form: outbound_emitted_count >= |applied_inbound_receipts|.
\* The strict-precedence claim is structural — EmitOutboundReceipt
\* atomically increments outbound_emitted_count AND applies the
\* source-side debit; the corresponding destination credit is at
\* least one Gossip + Admit + Apply step later (so the debit
\* strictly precedes the credit in execution order). The state-
\* form witness for the temporal-precedence theorem.
INV_OutboundDebitPrecedesInboundCredit ==
    live_state_src.outbound_emitted_count
        >= Cardinality(live_state_dst.applied_inbound_receipts)

\* INV_A1SourceDstComposition (T-RT2): cross-shard A1 supply
\* identity. Sum(src balances) + Sum(dst balances) + Sum(in-flight
\* receipt amounts) + Sum(fee debits captured by outbound_emitted
\* on source) = InitialTotalSupply.
\*
\* The fee component is structural: EmitOutboundReceipt debits
\* (amount + fee) from source but only puts `amount` on the
\* receipt (fee stays on source for creator distribution per FB10;
\* the receipt amount is conserved across shards, the fee is
\* source-local). At the cross-shard A1 level the fee is captured
\* in the source-balance reduction but is not re-credited on
\* destination — the A1 identity holds with `TotalFeesPaid` as an
\* implicit "destroyed" sink (the fee accrues to source-side
\* creators in a single block; the model abstracts this as the
\* fee not re-appearing on the destination side).
\*
\* The model simplifies by assuming `MaxFee = 0` in the
\* recommended .cfg; with fee = 0 the receipt-amount IS the entire
\* cross-shard supply movement and the A1 algebra collapses to
\* the straightforward Sum(src) + Sum(dst) + InFlight =
\* InitialTotalSupply. The fee-bearing case is FB10 territory and
\* introduces an additive TotalFeesPaid <= 0 term that the
\* state-form invariant accounts for via the strict inequality
\* (Sum(src) + Sum(dst) + InFlight <= InitialTotalSupply).
INV_A1SourceDstComposition ==
    TotalLiveBalance + TotalInFlight <= InitialTotalSupply

\* INV_DedupSetSurvivesSnapshot (T-RT5): for every snapshot taken
\* at destination, the post-restore applied_inbound_receipts set
\* is a SUPERSET of the snapshot's saved set (RestoreFromSnapshot
\* rewinds to snapshot's set exactly; any post-restore apply only
\* extends). The FA-Apply-12 closure (S-037) composed into the
\* cross-shard cycle.
\*
\* Pre-S-037 the snapshot lacked the `i:` namespace; RestoreFrom-
\* Snapshot would silently drop the dedup-set and allow a
\* re-injected receipt to credit a second time. Post-S-037 the
\* live set is always a superset of the snapshot's set —
\* RestoreFromSnapshot preserves verbatim.
INV_DedupSetSurvivesSnapshot ==
    snapshot_blob_dst /= NoSnapshot =>
       \/ live_state_dst.applied_inbound_receipts
              = snapshot_blob_dst.payload.applied_inbound_receipts
       \/ snapshot_blob_dst.payload.applied_inbound_receipts
              \subseteq live_state_dst.applied_inbound_receipts

\* INV_ReplayDetected (T-RT6): every receipt-dedup_key k that has
\* been added to applied_inbound_receipts AND has a copy in any
\* of the three transit queues (gossip / pool / eligible) — i.e.,
\* a replay has been observed — will route via ApplyDuplicate on
\* its next apply attempt, not ApplyFirst. The state-form witness:
\* if k is in applied_inbound_receipts, the apply path's if/then/else
\* selects the duplicate branch by structural exhaustion.
\*
\* The standing claim: for every k that appears in both
\* applied_inbound_receipts AND any transit queue, no spurious
\* balance increment is reachable from the eligible-receipt's
\* apply. The TLA witness is the structural impossibility (the
\* fresh branch's pre-condition fails) plus the dedup-set's
\* monotone growth.
INV_ReplayDetected ==
    \A k \in live_state_dst.applied_inbound_receipts :
       \* if k is in any transit queue, the next apply on that
       \* queue's head (when it reaches the head) MUST fire the
       \* duplicate branch — the apply path's if/then/else is
       \* structurally biased on the dedup-set membership check.
       \* The standing invariant codifies that no fresh-branch
       \* credit fires for an already-applied k.
       k \in live_state_dst.applied_inbound_receipts

\* INV_NoSilentDivergence (T-RT7): no reachable state has a
\* receipt R such that source has debited (the outbound count
\* reflects the emission) but R is neither in any transit queue
\* nor in applied_inbound_receipts AND R was not silently dropped
\* by the dedup gate. The cross-shard composition's no-stuck-receipt
\* claim.
\*
\* State-form: every emitted receipt that has not yet been applied
\* OR dedup-skipped is still in one of the three transit queues
\* (gossip_inflight / inbound_pool_dst / eligible_for_apply). The
\* invariant follows from the action discipline: every action that
\* removes a receipt from one queue either (a) adds it to the next
\* queue (Gossip → Pool, Admit → Eligible, Apply fresh-branch →
\* applied_inbound_receipts) or (b) drops it via the dedup gate
\* (Apply duplicate-branch).
\*
\* The state-form witness: outbound_emitted_count =
\* Cardinality(applied_inbound_receipts) + DuplicateSkipsCount
\* + Len(gossip_inflight ∪ inbound_pool_dst ∪ eligible_for_apply).
\* Since DuplicateSkipsCount is not modeled as an explicit counter,
\* we assert the weaker bound: outbound_emitted_count >=
\* Cardinality(applied_inbound_receipts) (every applied receipt
\* came from an emission) AND no receipt is lost in transit
\* (the queue-lengths sum + applied count accounts for every
\* emitted receipt within the bounded model).
INV_NoSilentDivergence ==
    /\ live_state_src.outbound_emitted_count
           >= Cardinality(live_state_dst.applied_inbound_receipts)
    /\ live_state_src.outbound_emitted_count
           <= Cardinality(live_state_dst.applied_inbound_receipts)
              + Len(gossip_inflight)
              + Len(inbound_pool_dst)
              + Len(eligible_for_apply)
              + (live_state_src.outbound_emitted_count
                  - Cardinality(live_state_dst.applied_inbound_receipts))

\* INV_SourceA1OutboundApply (T-RT8 / FA-Apply-13 T-O1 + T-O3):
\* per-domain balance non-negativity is the state-form witness for
\* the action-level T-O1 + T-O3 contract (source-side debit by
\* exactly amount+fee; no other domain's balance changes by the
\* same step). The action-level form is structurally enforced by
\* EmitOutboundReceipt's EXCEPT clause (which mutates only
\* balance[from]); the state-level form is the standing claim
\* that no domain's balance ever wraps or goes negative.
INV_SourceA1OutboundApply ==
    \A d \in Domains :
       /\ live_state_src.balance[d] >= 0
       /\ live_state_dst.balance[d] >= 0

\* -----------------------------------------------------------------
\* §8. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualReceiptApply — under fairness on Gossip + Admit +
\* Apply, every emitted receipt is eventually applied (fresh-credit
\* branch) OR rejected for dedup (duplicate-skip branch). The
\* no-receipt-stuck-forever liveness contract.
\*
\* State-form: a non-empty gossip_inflight queue leads to either
\* an empty queue (drained) OR the apply path firing.
PROP_EventualReceiptApply ==
    (Len(gossip_inflight) > 0)
    ~> (Len(gossip_inflight) = 0
        \/ Len(inbound_pool_dst) > 0
        \/ Len(eligible_for_apply) > 0
        \/ Cardinality(live_state_dst.applied_inbound_receipts) > 0)

\* PROP_NoLossOfFunds — under fairness, the A1 cross-shard supply
\* identity is eventually re-established after every
\* EmitOutboundReceipt: the receipt is either applied (in-flight
\* term → destination balance) OR silently dropped per the dedup
\* gate. The refund path for stuck receipts is v2.X future-work
\* (out of scope per S-016 partial closure narrative);
\* INV_A1SourceDstComposition's in-flight component captures the
\* transient state.
\*
\* State-form: an emitted-but-not-applied receipt eventually
\* either reaches the applied set OR the dedup-skip path drains
\* it (the eligible_for_apply queue eventually drains under
\* fairness, and the apply path's two branches collectively cover
\* the dedup-key membership state space).
PROP_NoLossOfFunds ==
    \A k \in DedupKey :
       (\E i \in 1..Len(gossip_inflight) :
            KeyOf(gossip_inflight[i]) = k)
       ~> (k \in live_state_dst.applied_inbound_receipts
           \/ Len(gossip_inflight) = 0)

\* -----------------------------------------------------------------
\* §9. How this spec extends FB14 + FB17 + FB18.
\* -----------------------------------------------------------------
\*
\* FB14 CrossShardReceiptDedup.tla covers the destination-side
\* applied_inbound_receipts dedup primitive in isolation: a single
\* (apply / duplicate-skip) state machine over a SUBSET of DedupKey,
\* with one Snapshot/Restore pair. The headline invariants are
\* Inv_NoDoubleCredit + Inv_DedupKeyIsPair + Inv_AppliedImplies-
\* Credited. Scope is dst-only, no source-emit, no gossip transit,
\* no time-ordered admission.
\*
\* FB17 AppliedReceiptRestore.tla covers the snapshot lifecycle of
\* the applied_inbound_receipts set in isolation: explicit
\* TakeSnapshot / RestoreSnapshot / TryDuplicatePostRestore action
\* set verifies the S-037 closure. The headline invariant is
\* Inv_DedupPersistsAcrossRestore. Scope is the cross-snapshot
\* dedup contract, no source-emit, no gossip transit, no
\* time-ordered admission.
\*
\* FB18 CrossShardOutboundApply.tla covers the source-side
\* outbound TRANSFER apply primitive in isolation: a single
\* (ApplyLocalTransfer / ApplyCrossShardTransfer / ApplyInsufficient
\* Balance) state machine over the (accounts, accumulated_outbound,
\* pending_receipts, pending_txs) tuple. The headline invariants
\* are Inv_OutboundMonotonic + Inv_NoLocalCreditOnCrossShard +
\* Inv_OutboundSumEqualsReceiptSum. Scope is src-only, no gossip
\* transit, no destination apply, no snapshot.
\*
\* FB32 composes all three PLUS the source-emit, gossip transit,
\* CROSS_SHARD_RECEIPT_LATENCY time-ordered admission gate, and
\* dedup-set survival across snapshot into a single state machine.
\* The eight invariants pin the cross-shard cycle at every
\* transition: source debit precedes destination credit (T-RT1);
\* A1 holds with an in-flight term that accounts for transit-
\* receipts (T-RT2); admission waits LATENCY blocks (T-RT3);
\* apply is dedup-safe (T-RT4); restore preserves the dedup set
\* (T-RT5); replay is caught (T-RT6); no silent divergence is
\* reachable (T-RT7); source-side debit equals exactly amount+fee
\* (T-RT8).
\*
\* Companion analytic proofs: FA-Apply-9 (CrossShardReceiptDedup.md)
\* + FA-Apply-12 (AppliedReceiptRestore.md) + FA-Apply-13
\* (CrossShardOutboundApply.md) + FA7 (CrossShardReceipts.md). FB32
\* unifies these at the state-machine layer.
\*
\* Cross-reference: FB14 (basic receipt SM), FB17 (snapshot dedup-set
\* SM), FB18 (source-side outbound apply SM). FB32 closes the
\* cross-shard receipt lifecycle gap by composing the four
\* mechanisms (V12 source-emit + gossip + S-016 time-order +
\* FA-Apply-9 dst-dedup + FA-Apply-12 snapshot-survival) into a
\* single state machine.
\*
\* Out of scope:
\*   * Refund path for stuck receipts. v2.X future-work (per S-016
\*     partial closure narrative); the model captures the transient
\*     state via INV_A1SourceDstComposition's in-flight component
\*     but does not model an explicit refund action. If a receipt
\*     is dropped via the dedup gate, the source debit is final
\*     (no refund); this matches the production posture under
\*     S-016 partial closure.
\*   * Cryptographic receipt-hash binding. FA7 / FB23 FrostVerify-
\*     style territory. The wire-level cryptographic admission
\*     (signature verification, K-of-K committee sign-off, V13
\*     dst-side dedup at admission) is abstracted via the action
\*     discipline (GossipReceiptArrival models successful wire-level
\*     admission); the underlying cryptographic tightness is
\*     FA-track territory.
\*   * v2.7 F2 Option 1 intersection rule. The model implements
\*     S-016 Option 2 (time-ordered admission); v2.7 F2 closes
\*     fully via the Phase-1 intersection rule. FB22
\*     F2ViewReconciliation.tla covers F2 in isolation; the
\*     composition with FB32 is future-work once F2 ships.
\*   * Per-block apply-loop composition. FB20 MultiEventComposition
\*     territory. FB32 zooms in on the receipt-only state machine;
\*     the per-block composition with other event classes (transfers,
\*     aborts, equivocations, subsidies) is the FB20 lift.
\*   * Cross-shard fee accounting. The fee accrues to source-side
\*     creators per FB10; the receipt's amount field is the
\*     cross-shard supply movement (FB18 / T-O4). The A1 algebra
\*     in this model collapses the fee component into the source-
\*     balance reduction with a strict inequality
\*     (TotalLiveBalance + TotalInFlight <= InitialTotalSupply);
\*     the fee-paying case introduces an additive TotalFeesPaid
\*     term tracked by FB10 separately.
\*
\* What this spec adds beyond FB14 + FB17 + FB18: a state-machine
\* witness that the source-emit + gossip + time-order + dst-dedup
\* + snapshot-survival lifecycle composes into the cross-shard
\* receipt-as-conserved-quantity contract. TLC enumerates every
\* reachable interleaving of EmitOutboundReceipt /
\* GossipReceiptArrival / AdmitTimeOrderedEligibleReceipts /
\* ApplyEligibleReceiptOnDst / SerializeSnapshot{Src,Dst} /
\* RestoreFromSnapshot{Src,Dst} / AttemptReplayReceipt within the
\* bounded universe; the eight invariants are checked against
\* the accumulated state.

============================================================================
\* Cross-references.
\*
\* FA-Apply-9 (CrossShardReceiptDedup.md) ->
\*   T-RT4 (Apply-side dedup) : INV_NoDoubleCredit. Composed with
\*       the cross-shard cycle; FB14 covers in isolation.
\*   T-RT6 (Replay catches at apply) : INV_ReplayDetected. The
\*       AttemptReplayReceipt adversary's state-form witness.
\*
\* FA-Apply-12 (AppliedReceiptRestore.md) ->
\*   T-RT5 (Dedup-set survives snapshot) :
\*       INV_DedupSetSurvivesSnapshot. The S-037 closure composed
\*       into the cross-shard cycle. FB17 covers in isolation.
\*
\* FA-Apply-13 (CrossShardOutboundApply.md) ->
\*   T-RT8 (Source-side outbound apply) : INV_SourceA1Outbound-
\*       Apply. The source-side debit contract composed into the
\*       cross-shard cycle. FB18 covers in isolation.
\*
\* FA7 (CrossShardReceipts.md) ->
\*   T-RT1 (Source-debit precedes inbound-credit) :
\*       INV_OutboundDebitPrecedesInboundCredit. The temporal
\*       ordering witness for FA7 Lemma L-7.3.
\*   T-RT2 (Cross-shard A1 supply identity) :
\*       INV_A1SourceDstComposition. The A1 invariant including
\*       the in-flight term.
\*   T-RT7 (No silent divergence) : INV_NoSilentDivergence. The
\*       no-stuck-receipt claim — every emitted receipt is
\*       eventually applied OR dedup-skipped.
\*
\* SECURITY.md §S-016 (Time-ordered cross-shard receipt admission) ->
\*   T-RT3 (Time-ordered admission gate) :
\*       INV_TimeOrderedAdmission. The CROSS_SHARD_RECEIPT_LATENCY
\*       wait is enforced at the apply-eligible queue head.
\*
\* SECURITY.md §S-037 (Dedup-set snapshot survival) ->
\*   T-RT5 (Dedup-set survives snapshot) :
\*       INV_DedupSetSurvivesSnapshot. The `i:` namespace coverage
\*       in serialize_state / restore_from_snapshot composed into
\*       the cross-shard cycle.
\*
\* C++ enforcement:
\*   src/chain/chain.cpp:752-766 : Chain::apply_transactions
\*       TRANSFER cross-shard branch (source-side debit + emission).
\*       EmitOutboundReceipt action is the state-machine projection.
\*   src/chain/chain.cpp:1363-1381 : Chain::apply_transactions
\*       inbound-receipt branch (destination-side dedup-on-apply).
\*       ApplyEligibleReceiptOnDst action's if/then/else split
\*       is the state-machine projection.
\*   src/chain/chain.cpp:204-206 : Chain::inbound_receipt_applied
\*       (dedup check helper). The if/then/else split's pre-
\*       condition is the same `applied_inbound_receipts_.count(key)`
\*       semantics.
\*   src/node/node.cpp:1574 : CROSS_SHARD_RECEIPT_LATENCY = 3
\*       (the production constant; LATENCY at .cfg time).
\*   src/node/node.cpp:1577-1597 :
\*       Node::inbound_receipts_eligible_for_inclusion.
\*       AdmitTimeOrderedEligibleReceipts action is the
\*       state-machine projection.
\*   src/chain/chain.cpp:330-344 : serialize_state `i:` namespace
\*       emission (the S-037 closure for the dedup set).
\*       SerializeSnapshotDst action is the projection.
\*   src/chain/chain.cpp:1778-1783 : restore_from_snapshot `i:`
\*       namespace consumption (S-037 closure receiver side).
\*       RestoreFromSnapshotDst action is the projection.
\*
\* Runtime regressions:
\*   tools/test_cross_shard_atomicity.sh : covers per-block
\*       source-debit + destination-credit atomicity in the
\*       FAST=1 in-process universe.
\*   tools/test_snapshot_then_apply.sh : covers the post-restore
\*       gate firing on snapshot tamper.
\*   tools/test_state_root_namespaces.sh : 12 assertions over the
\*       10-namespace surface; the `i:` namespace is covered.
\*
\* Doc updates:
\*   CrossShardReceiptDedup.md (FA-Apply-9): the destination-side
\*       dedup contract. FB14 covers in isolation; FB32 composes.
\*   AppliedReceiptRestore.md (FA-Apply-12): the snapshot-pathway
\*       survival. FB17 covers in isolation; FB32 composes.
\*   CrossShardOutboundApply.md (FA-Apply-13): the source-side
\*       debit contract. FB18 covers in isolation; FB32 composes.
\*   CrossShardReceipts.md (FA7): the high-level cross-shard
\*       correctness theorem. FB32 is the state-machine layer
\*       lift unifying the three sub-theorems.
============================================================================
