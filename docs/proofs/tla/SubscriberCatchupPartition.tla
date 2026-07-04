------------------- MODULE SubscriberCatchupPartition -------------------
(*
FB72 — TLA+ specification of the v2.20 STREAMING-SUBSCRIPTION CATCH-UP /
LIVE PARTITION: the subscribe-time delivery-space split pinned by
docs/proofs/StreamingSubscriptionSoundness.md SS-2, enforced in
src/node/node.cpp::rpc_dapp_subscribe / subscriber_session /
on_block_finalized_for_subscribers (all at HEAD). FB71
(SubscriberBackpressure.tla) already machine-checks the LIVE-TAIL
backpressure/kill protocol (SS-3); this module is its complement — the
subscribe-time PARTITION that guarantees no matching event is missed and
none is delivered twice within one connection.

The one fact this module exists to pin — the ATOMICITY CRUX (SS-2 step 1,
node.cpp:3251-3307): rpc_dapp_subscribe takes state_mutex_ SHARED and, in
ONE critical section, both (a) reads head_at_register = chain.height() = N
AND (b) inserts the subscriber into subscribers_. apply_block_locked
mutates the chain under state_mutex_ UNIQUE; shared and unique are mutually
exclusive, so NO block can be applied between the capture of N and the
register. Therefore:

  * CHAIN HEIGHT.  N = number of applied blocks == chain.height() ==
    blocks_.size(); applied blocks have indices 0..N-1 (head index N-1);
    the NEXT block to be applied gets index N.
  * CATCH-UP (subscriber_session, node.cpp:3380-3408).  Replays every
    currently-existing block with index in [since, N) = [since, regHead) —
    EXCLUSIVE of N — read from the chain, filtered by (domain, topic),
    then emits the `live` marker. In C++: `for (h = since; h < regHead)`.
  * LIVE (on_block_finalized_for_subscribers, node.cpp:3455-3507).  The
    per-block hook runs INSIDE apply_block_locked under state_mutex_
    UNIQUE, for EVERY applied block, and enqueues that block's matching
    events to every registered subscriber. Because register
    happened-before the apply of block N (shared-before-unique), block N's
    hook sees the subscriber -> block N and every later block is covered
    LIVE. Live covers [N, infinity) — INCLUSIVE of N.
  * THE PARTITION.  catch-up [since, N) UNION live [N, infinity) =
    [since, infinity); intersection EMPTY (N exclusive in catch-up,
    inclusive in live). No gap, no overlap at the boundary N. A subscriber
    sees every matching event with block_index >= since exactly once
    (per connection). THIS is SS-2 and the "no missed events" guarantee
    the streaming feature rests on.

MODEL.  A producer applies blocks (a growing chain bounded by MAX_BLOCKS);
each block index carries zero-or-one matching event, and a matching
event's identity IS its block_index (a k-event block is k back-to-back
enqueues, already covered by k single-event blocks — the FB71 device). A
subscribe action ATOMICALLY captures regHead = current height N and
registers. Catch-up replays matching indices in [since, regHead). The live
hook, for every block applied WHILE registered, enqueues that block's
matching index. `delivered` is the client's observed set (catch-up-replayed
UNION live-enqueued, drained by the writer). The whole point is that the
capture+register is ONE Next-step; the non-vacuity mutant splits it.

REQUIRED INVARIANTS (house INV_* style):

  INV_TypeOK      — typed records; head monotonicity is folded in via the
                    0..MAX_BLOCKS ranges and the reg-before-head ordering.
  INV_NoGap       — THE core partition / no-missed-events claim. For a
                    registered subscriber, in EVERY reachable state, the
                    set of matching-event indices it has been SCHEDULED to
                    receive (catch-up-replayed UNION live-enqueued)
                    contains EVERY matching index in [since, head] — no
                    matching event in range is missed. (Mutant M1 target:
                    a non-atomic capture+register drops block N.)
  INV_NoOverlap   — no matching index is BOTH catch-up-replayed AND
                    live-enqueued for the same subscriber (the boundary N
                    is covered by exactly one side) — exactly-once within
                    a connection. (Mutant M2 target: an INCLUSIVE catch-up
                    bound [since, N] double-covers N.)
  INV_HeadMonotone— fail-closed typing tie: the applied-block counter only
                    grows, regHead (once captured) never exceeds head, and
                    a registered subscriber's regHead is <= head always
                    (register happened-before every later apply).

REQUIRED TEMPORAL PROPERTY (with fairness):

  PROP_AllEventuallyDelivered — every matching event in [since, head] is
                    EVENTUALLY delivered to a live (un-terminated)
                    subscriber. WF on the catch-up and live-drain steps
                    (the writer thread is scheduled); the chain may go idle
                    (no fairness on Apply), so the property quantifies over
                    the matching events that EXIST — head is the current
                    applied height, not MAX_BLOCKS.

NON-VACUITY PROBES (falsify-on-mutant; run 2026-07-04, tla2tools v1.8.0,
java 11, scratch copies only — none ships wired in; scratch files deleted
after each run):

  M1 (capture-N and register made NON-ATOMIC — THE crux mutant): split
     Subscribe into CaptureHead (regHead' = head, phase -> "CAPTURED", NOT
     yet in the subscribers_ map) then Register (a SEPARATE Next step),
     so an Apply of block N can interleave between them. Block N is then
     NEITHER catch-up-replayed (catch-up is [since, regHead) with
     regHead = the OLD N, exclusive) NOR live-enqueued (the subscriber was
     not yet registered — phase "CAPTURED" is excluded from the live hook —
     when block N's hook ran) -> a GAP at index N. EXPECTED FALSIFIED —
     VERIFIED: INV_NoGap violated (252 distinct states; 5-state
     counterexample). The concrete gap-at-N trace TLC prints (matching={0}):
     Init(head=0) -> CaptureHead (regHead=0, phase CAPTURED) -> Apply of the
     MATCHING block 0 (live hook SKIPPED — not yet registered — liveEnq
     stays {}) -> Register (phase REGD) -> CatchUp of [0,0) = {} (replayed
     stays {}). Final: matching index 0 is in [since=0, head=1) but
     Scheduled = replayed \cup liveEnq = {} -> the missed event the
     shared-lock atomicity prevents.
  M2 (catch-up bound made INCLUSIVE [since, regHead] instead of exclusive
     [since, regHead)): block N (= regHead), once applied after register, is
     live-enqueued AND then also replayed by the inclusive catch-up ->
     double-cover at the boundary. EXPECTED FALSIFIED — VERIFIED:
     INV_NoOverlap violated (124 distinct states; 4-state counterexample).
     Trace (matching={0}): Init(head=0) -> Subscribe (regHead=0) -> Apply of
     matching block 0 (liveEnq={0}) -> CatchUp with the [0,0] inclusive
     bound (replayed={0}) -> index 0 in BOTH replayed and liveEnq. The
     N-exclusive-in-catch-up / N-inclusive-in-live boundary is load-bearing.
  M0 (reachability): probe invariant Probe_LiveBoundaryUnreachable
     (== ~(regHead captured /\ regHead \in liveEnq)) — EXPECTED FALSIFIED —
     VERIFIED (violated, 55 distinct states; 3-state counterexample):
     Subscribe at head=0 (regHead=0) then Apply of matching block 0
     live-enqueues index 0 = regHead, so the live side of the boundary N is
     genuinely reachable — INV_NoGap's live arm is not vacuously satisfied.

MODELING SCOPE / ABSTRACTION BOUNDARY (kept tractable for TLC):

  * ONE subscriber. The partition is a per-connection property; the
    per-subscriber map isolates connections. SUBSCRIBER_MAX_PER_NODE
    admission, S-001 auth, S-014 rate-limit are upstream gates (SS-5) and
    out of scope.
  * BACKPRESSURE / KILL is FB71 (SubscriberBackpressure.tla) territory and
    is OUT OF SCOPE here: this module's queue is UNBOUNDED and the
    subscriber is never killed. FB71 proves the bounded-queue kill-vs-drop
    contract; FB72 proves the partition that feeds it. The two compose:
    FB72 guarantees the SCHEDULED set is gap-free-and-disjoint; FB71
    guarantees the writer either delivers the scheduled set contiguously
    or the connection dies observably.
  * CROSS-RECONNECT at-least-once (client redials with since = last
    observed block_index; overlap deduped by (block_index, tx_index)) is a
    SEPARATE property (SS-6) — within ONE connection the guarantee is
    exactly-once + gap-free, which is what INV_NoGap /\ INV_NoOverlap pin.
  * TCP / socket framing is abstracted: the writer's drain of the
    scheduled set into `delivered` is in-order and lossless (SS-1's
    single-writer seq monotonicity is structural, proved separately; a
    write that would fail is the FB71 kill path, out of scope). `delivered`
    is a SET (identity = block_index) because dedup within a connection is
    by (block_index, tx_index) and a matching event's identity is its
    index here.
  * A matching event's identity IS its block_index (one matching event per
    block). tx_index within a block is abstracted away (a k-event block is
    k single-event blocks, per FB71).
  * `since` is fixed at 0 (subscribe-from-genesis) in the shipped .cfg: it
    is the widest catch-up window, so every [since, N) split is exercised;
    a non-zero since only shrinks the replay set and removes no partition
    shape. The since>head / backlog-window rejections (node.cpp:3261-3273)
    are upstream invalid_arg gates, out of scope.
  * The `live` marker frame and heartbeats carry no matching-event
    identity (eid absent), so they are not modeled here — this module
    tracks only the matching-event index sets whose partition is SS-2.

TYPED-SENTINEL CAUTION (a real bug that bit a sibling model): no string
sentinel is ever compared with a record via `=`. This module models the
partition with SETS of naturals (block indices) and a small record-free
control state, so every equality is Nat-vs-Nat or over a fixed small string
control domain — no cross-type equality can arise. `regHead` uses the Nat
sentinel value MAX_BLOCKS+1 for "not yet captured" (outside 0..MAX_BLOCKS,
so INV_TypeOK's range pins it and it can never masquerade as a real head).

To check (assuming TLC installed):
  $ tlc SubscriberCatchupPartition.tla -config SubscriberCatchupPartition.cfg
*)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MAX_BLOCKS   \* finite bound on applied blocks (exhibit size); the
                 \* chain grows 0..MAX_BLOCKS, each index carrying 0-or-1
                 \* matching event fixed at Init

ASSUME ConfigOK ==
    /\ MAX_BLOCKS \in Nat \ {0}

\* -----------------------------------------------------------------
\* §1. Index universe.
\* -----------------------------------------------------------------

\* Applied-block indices ever reachable: 0..MAX_BLOCKS-1 (a chain of
\* height h has indices 0..h-1). The since window is fixed at 0.
BlockIdx == 0 .. (MAX_BLOCKS - 1)
Since    == 0

\* "regHead not yet captured": a Nat OUTSIDE 0..MAX_BLOCKS so INV_TypeOK's
\* range pins it and no Nat-vs-record equality can occur (typed-sentinel
\* caution). MAX_BLOCKS+1 is one past the largest real head (MAX_BLOCKS).
NoHead == MAX_BLOCKS + 1

\* Control state of the ONE subscriber. Record-free small string domain, so
\* every state comparison is over this fixed set — never string-vs-record.
\*   "IDLE"   — not yet subscribed.
\*   "REGD"   — registered (regHead captured atomically), catch-up pending.
\*   "CAUGHT" — catch-up replay done, live marker emitted; live-only now.
Phases == {"IDLE", "REGD", "CAUGHT"}

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    head,       \* 0..MAX_BLOCKS: applied-block counter (producer clock).
                \* Applied indices are 0..head-1; next block gets index head.
    matching,   \* SUBSET BlockIdx: which block indices carry a matching
                \* event (fixed at Init; the daemon-independent chain fact).
    phase,      \* Phases: the subscriber's lifecycle position.
    regHead,    \* 0..MAX_BLOCKS or NoHead: head_at_register, captured
                \* ATOMICALLY with the register (the SS-2 crux).
    replayed,   \* SUBSET BlockIdx: matching indices catch-up has replayed
                \* (the [since, regHead) scan result).
    liveEnq,    \* SUBSC BlockIdx: matching indices the live hook enqueued
                \* (blocks applied while registered).
    delivered   \* SUBSET BlockIdx: matching indices the client has observed
                \* (the writer drains replayed \cup liveEnq into here).

vars == <<head, matching, phase, regHead, replayed, liveEnq, delivered>>

\* Matching indices that currently EXIST on the chain (applied, index < head).
MatchingBelow(h) == { i \in matching : i < h }

\* The set of matching indices SCHEDULED for the subscriber: the union of
\* the two partition halves. INV_NoGap says this covers [since, head];
\* INV_NoOverlap says the two halves are disjoint.
Scheduled == replayed \cup liveEnq

\* -----------------------------------------------------------------
\* §3. Initial state: chain empty, subscriber idle, matching set chosen.
\* -----------------------------------------------------------------
\*
\* TLC enumerates every matching \subseteq BlockIdx, so every arrangement of
\* which indices carry a matching event (including none and all) is explored
\* against every interleaving of Apply / Subscribe / CatchUp / LiveHook /
\* Drain below.
Init ==
    /\ head = 0
    /\ matching \in SUBSET BlockIdx
    /\ phase = "IDLE"
    /\ regHead = NoHead
    /\ replayed = {}
    /\ liveEnq = {}
    /\ delivered = {}

\* -----------------------------------------------------------------
\* §4. Producer: apply the next block (the chain grows).
\* -----------------------------------------------------------------
\*
\* Apply block with index `head`. If registered (REGD or CAUGHT), the live
\* hook fires INSIDE this same step — modeling that on_block_finalized_for_
\* subscribers runs under the SAME state_mutex_ UNIQUE that advances the
\* chain: the apply and the hook enqueue are one atomic transition. A
\* matching block enqueues its index; a non-matching block enqueues nothing.
Apply ==
    /\ head < MAX_BLOCKS
    /\ head' = head + 1
    /\ liveEnq' = IF /\ phase \in {"REGD", "CAUGHT"}
                     /\ head \in matching      \* this block carries a match
                  THEN liveEnq \cup {head}
                  ELSE liveEnq
    /\ UNCHANGED <<matching, phase, regHead, replayed, delivered>>

\* -----------------------------------------------------------------
\* §5. Subscribe: THE ATOMIC CAPTURE + REGISTER (SS-2 step 1).
\* -----------------------------------------------------------------
\*
\* rpc_dapp_subscribe under state_mutex_ SHARED, in ONE critical section:
\* read regHead = head (= N) AND register (phase -> REGD). This is ONE
\* Next-step, which is the whole point: an Apply cannot interleave between
\* the read of head and the register, because Apply is a DIFFERENT step and
\* TLA steps are atomic — the TLA analogue of shared-excludes-unique. The
\* M1 mutant splits this into two steps to model a non-atomic
\* read-then-register and exhibits the resulting gap.
Subscribe ==
    /\ phase = "IDLE"
    /\ regHead' = head             \* capture N ...
    /\ phase'   = "REGD"           \* ... and register, ATOMICALLY (one step)
    /\ UNCHANGED <<head, matching, replayed, liveEnq, delivered>>

\* -----------------------------------------------------------------
\* §6. Catch-up: replay matching indices in [since, regHead) — EXCLUSIVE.
\* -----------------------------------------------------------------
\*
\* subscriber_session scans blocks [since, head_at_register) directly from
\* the chain and replays the matching ones, then emits the `live` marker
\* (phase -> CAUGHT). Modeled as ONE step over the whole window: the C++
\* CHUNK loop is a refinement (each chunk reads a shared-lock snapshot of
\* immutable blocks < regHead, so chunking observes the same set); the
\* replayed set is a pure function of matching /\ [since, regHead). The
\* boundary is regHead EXCLUSIVE — `i < regHead`. (M2 flips this to `<=`.)
CatchUp ==
    /\ phase = "REGD"
    /\ replayed' = { i \in matching : Since <= i /\ i < regHead }
    /\ phase' = "CAUGHT"
    /\ UNCHANGED <<head, matching, regHead, liveEnq, delivered>>

\* -----------------------------------------------------------------
\* §7. Consumer: the writer drains the scheduled set to the client.
\* -----------------------------------------------------------------
\*
\* The single writer thread (SS-1) emits queued frames in order; here it
\* delivers scheduled-but-undelivered matching indices to the client's
\* observed set. Backpressure/kill is FB71 (out of scope): the queue is
\* unbounded and every scheduled frame is eventually delivered.
Drain ==
    /\ phase \in {"REGD", "CAUGHT"}
    /\ Scheduled \ delivered /= {}
    /\ \E i \in Scheduled \ delivered :
          delivered' = delivered \cup {i}
    /\ UNCHANGED <<head, matching, phase, regHead, replayed, liveEnq>>

\* -----------------------------------------------------------------
\* §8. Spec.
\* -----------------------------------------------------------------

Next ==
    \/ Apply
    \/ Subscribe
    \/ CatchUp
    \/ Drain

\* Fairness (liveness only; every safety invariant is fairness-independent):
\* WF on Subscribe (the client does eventually subscribe), on CatchUp (the
\* catch-up scan runs), and on Drain (the writer is scheduled and drains
\* every queued frame). No fairness on Apply — the chain may go idle, which
\* is why the temporal property quantifies over the matching events that
\* EXIST at the current head, not over MAX_BLOCKS.
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(Subscribe)
    /\ WF_vars(CatchUp)
    /\ WF_vars(Drain)

\* -----------------------------------------------------------------
\* §9. Type invariant.
\* -----------------------------------------------------------------

INV_TypeOK ==
    /\ head \in 0..MAX_BLOCKS
    /\ matching \in SUBSET BlockIdx
    /\ phase \in Phases
    /\ regHead \in (0..MAX_BLOCKS) \cup {NoHead}
    /\ replayed \in SUBSET BlockIdx
    /\ liveEnq \in SUBSET BlockIdx
    /\ delivered \in SUBSET BlockIdx
    /\ (phase = "IDLE") <=> (regHead = NoHead)   \* regHead captured iff regd
    /\ (phase = "IDLE") => (replayed = {} /\ liveEnq = {})

\* -----------------------------------------------------------------
\* §10. Safety invariants — the SS-2 partition.
\* -----------------------------------------------------------------

\* INV_NoGap — THE core no-missed-events claim. For a REGISTERED subscriber,
\* in every reachable state, every matching index that EXISTS in the window
\* [since, head] (i.e. every applied matching block at index >= since) is in
\* the scheduled set (catch-up-replayed UNION live-enqueued). No matching
\* event in range is missed. Before catch-up completes (phase = REGD) the
\* replay set is still empty, so the claim is stated for a subscriber that
\* has captured its head and whose catch-up has run (CAUGHT) — matching the
\* C++ where the client sees the `live` marker only after replay. (For REGD
\* the live half already covers [regHead, head]; the [since, regHead) half
\* is filled by CatchUp, which WF_vars(CatchUp) forces — see the temporal
\* property. The invariant below is the STEADY-STATE partition claim.)
\* M1 (non-atomic capture+register) falsifies this: block regHead is missed.
INV_NoGap ==
    (phase = "CAUGHT") =>
        \A i \in matching :
            (Since <= i /\ i < head) => i \in Scheduled

\* INV_NoOverlap — exactly-once within a connection: no matching index is in
\* BOTH partition halves. The boundary N = regHead is covered by exactly one
\* side (catch-up is [since, regHead) exclusive; live is [regHead, inf)
\* inclusive). M2 (inclusive catch-up bound) falsifies this at index regHead.
INV_NoOverlap ==
    replayed \cap liveEnq = {}

\* INV_HeadMonotone — the fail-closed typing tie: a captured regHead never
\* exceeds the current head (register happened-before every later apply, so
\* head only grows past regHead), every replayed index is strictly below
\* regHead (catch-up's exclusive bound), and every live-enqueued index is at
\* or above regHead (the hook only fires for blocks applied after register).
\* Together these pin the boundary the partition rests on.
INV_HeadMonotone ==
    /\ (regHead /= NoHead) => (regHead <= head)
    /\ \A i \in replayed : i < regHead
    /\ \A i \in liveEnq  : i >= regHead
    /\ delivered \subseteq Scheduled

\* -----------------------------------------------------------------
\* §11. Temporal property (fairness) — eventual delivery.
\* -----------------------------------------------------------------
\*
\* PROP_AllEventuallyDelivered — every matching event that exists in
\* [since, head] is EVENTUALLY delivered to the live (un-terminated)
\* subscriber. Because the chain may go idle (no fairness on Apply), this
\* quantifies over a FIXED matching index and asserts: once that index is a
\* matching applied block AND the subscriber has caught up, it is eventually
\* delivered. WF on CatchUp + Drain discharges it: catch-up fills the
\* [since, regHead) half, the live hook fills [regHead, head] as blocks
\* apply, and Drain empties the scheduled set into `delivered`.
DeliveredIdx(i) == i \in delivered

PROP_AllEventuallyDelivered ==
    \A i \in BlockIdx :
        [] ( (phase = "CAUGHT" /\ i \in matching /\ Since <= i /\ i < head)
             => <> DeliveredIdx(i) )

\* -----------------------------------------------------------------
\* §12. Non-vacuity probes (NOT in the shipped .cfg — EXPECTED
\* FALSIFIED when checked; see the header probe table, M0).
\* -----------------------------------------------------------------

\* M0: falsification exhibits a trace where a matching block applied at
\* index = regHead is live-enqueued — the live side of the boundary N is
\* genuinely reachable, so INV_NoGap's live arm is not vacuously satisfied.
Probe_LiveBoundaryUnreachable ==
    ~(regHead /= NoHead /\ regHead \in liveEnq)

=============================================================================
\* Cross-references.
\*
\* docs/proofs/StreamingSubscriptionSoundness.md SS-2 — the prose claim this
\*   module machine-checks: the catch-up/live partition [since, H) UNION
\*   [H, inf) with no gap, no overlap, resting on the atomic capture-and-
\*   register under the state shared lock (premise P-1 lock ordering + P-3
\*   apply-path totality). SS-3's contiguous-or-dead (backpressure) is the
\*   FB71 companion; SS-1's structural seq monotonicity is the single-writer
\*   abstraction this module's Drain assumes.
\*
\* C++ (HEAD): src/node/node.cpp
\*   rpc_dapp_subscribe (:3231-3316) — the shared-lock critical section that
\*     reads head_at_register = chain.height() (:3255,:3305) AND inserts into
\*     subscribers_ (:3306) atomically (the Subscribe step's crux);
\*   subscriber_session (:3318-3453) — catch-up replay of [since,
\*     head_at_register) (:3380-3408, the `h < head_at_register` exclusive
\*     bound = CatchUp's `i < regHead`) then the `live` marker (:3409-3413);
\*   on_block_finalized_for_subscribers (:3455-3507) — the per-block hook
\*     under apply_block_locked's unique lock (:3456), enqueuing matching
\*     events for every registered subscriber (Apply's live arm).
\*
\* Sibling specs:
\*   SubscriberBackpressure.tla (FB71) — the LIVE-TAIL backpressure/kill
\*     protocol (SS-3); FB72 (this module) is the SUBSCRIBE-TIME partition
\*     (SS-2) that feeds it. The two compose: FB72 pins the scheduled set is
\*     gap-free + disjoint; FB71 pins the writer delivers it contiguously or
\*     the connection dies observably.
\*   SupplyCounterRead.tla (FB70) — the typed-sentinel + small-CONSTANT +
\*     dated-non-vacuity house style this module follows.
=============================================================================
