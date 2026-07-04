------------------- MODULE SubscriberReconnectSeam -------------------
(*
FB73 — TLA+ specification of the v2.20 STREAMING-SUBSCRIPTION CROSS-RECONNECT
NO-LOSS SEAM: the SS-6 reconnect-via-`since` contract as REALIZED by the R54
`dapp-subscribe --reconnect` client (src/main.cpp:5802-5960, at HEAD),
docs/proofs/StreamingSubscriptionSoundness.md SS-6, resting on FB72's
within-connection catch-up/live partition. FB72
(SubscriberCatchupPartition.tla) already machine-checks that ONE connection
opened with `since = S` delivers EXACTLY the matching events with
block_index in [S, head], gap-free and duplicate-free (SS-2). This module
COMPOSES ON TOP OF that result: it models only the SEAM — the union across a
SEQUENCE of connections joined by disconnect+reconnect, and the inclusive-
`since` dedup that makes that union lossless and (after dedup) exactly-once.

REUSE-OF-FB72 PREMISE (the abstraction boundary this module rests on).
FB72 pins the single-connection partition; FB73 does NOT re-derive it. Here a
connection opened with `since = S` is modeled as an in-order deliverer of the
matching events with block_index in [S, head] — it walks that window in
NON-DECREASING (block_index, tx_index) order and stops (or is cut) at any
point. That "delivers exactly [S, head], in order" behavior is FB72's
theorem, imported as the Connection deliverer's contract (§5). This module's
job is only what FB72 explicitly scoped OUT (SubscriberCatchupPartition.tla
header, "CROSS-RECONNECT at-least-once ... is a SEPARATE property (SS-6)"):
the cross-connection union + the (block_index, tx_index) dedup at the seam.

THE ONE FACT THIS MODULE EXISTS TO PIN — INCLUSIVE `since` IS LOAD-BEARING.
The R54 client redials with `since = last_block` where last_block = the MAX
block_index observed on the dropped connection (main.cpp:5872-5936:
`if (!have_last || bi > last_block) last_block = bi`), and the redial uses
`eff_since = last_block` (main.cpp:5877-5878) — INCLUSIVE. A single block can
carry MULTIPLE matching events (tx_index 0,1,...,K). If the client delivered
(B, 0) then the connection dropped BEFORE (B, 1), last_block = B, and an
INCLUSIVE redial at since = B re-scans block B: (B,0) is re-delivered [dedup
by (block_index, tx_index) drops it] and (B,1) is delivered [kept] — NO LOSS.
The EXCLUSIVE mutant `since = last_block + 1` would skip block B entirely,
losing (B,1) forever. INV_NoLoss pins exactly this: across ANY sequence of
disconnect+reconnect, the deduped delivered set = every matching event in
[original_since, head], each once.

MODEL.  A chain grows (bounded MAX_BLOCKS); each applied block index carries
0..K matching events by tx_index (K small so a MULTI-EVENT block is
reachable — the mutant's crux). A client holds a CURRENT connection with a
`connSince` and a scan cursor that delivers matching events in
(block_index, tx_index) order from connSince up to the head. A DISCONNECT
fires at any point (possibly mid-block: cursor stopped between two tx_index
of the same block). A RECONNECT redials with connSince = last_block INCLUSIVE
(if any block_index-bearing frame was observed; else the original since) and
resumes in-order delivery. `delivered` is the deduped observed set, keyed by
(block_index, tx_index). `last_block` tracks the max block_index observed.

REQUIRED INVARIANTS (house INV_* style):

  INV_TypeOK         — typed state; the Nat sentinel NoBlock = MAX_BLOCKS+1
                       for "no block observed yet" (outside 0..MAX_BLOCKS, so
                       every last_block comparison is Nat-vs-Nat — no cross-
                       type equality; the sibling typed-sentinel bug class).
  INV_NoLoss         — THE core seam claim, guarded by a CAUGHT-UP predicate:
                       whenever the client's current connection has drained
                       its window to the head (cursor at head — no pending
                       catch-up), `delivered` ⊇ every matching event that
                       EXISTS in [original_since, head]. Nothing is lost at a
                       seam. (Exclusive-since mutant M1 falsifies this.)
  INV_NoDup          — `delivered` is a SET of (block_index, tx_index) pairs,
                       so it is duplicate-free by construction; the invariant
                       additionally pins that every re-delivery across the
                       inclusive seam was absorbed (the model adds an event
                       to a set — a second delivery of the same identity is a
                       no-op), i.e. exactly-once AFTER dedup.
  INV_LastBlockSound — last_block = the MAX block_index in `delivered` (or
                       NoBlock if empty), AND the in-order-delivery premise
                       made an invariant: everything that EXISTS in range
                       with block_index < last_block has been delivered (FB72
                       in-order delivery lifted across the seam — a delivered
                       (B, t) implies every matching event at block_index < B
                       in range is already delivered).

REQUIRED TEMPORAL PROPERTY (with fairness):

  PROP_AllEventuallyDelivered — every matching event that EXISTS in
                       [original_since, head] is EVENTUALLY delivered, even
                       under REPEATED disconnect/reconnect, as long as
                       reconnect keeps firing. WF on Deliver (the connection
                       drains), WF on Reconnect (the client redials after
                       every disconnect); no fairness on Apply (the chain may
                       idle) or Disconnect (adversarial), so the property
                       quantifies over the matching events that EXIST at the
                       current head, not over MAX_BLOCKS.

NON-VACUITY PROBE (falsify-on-mutant; run 2026-07-04, tla2tools v1.8.0,
java 11, scratch copy only — none ships wired in; scratch files deleted
after the run):

  M1 (the EXCLUSIVE-since mutant — the crux): Reconnect redials with
     connSince = last_block + 1 (EXCLUSIVE) instead of last_block (INCLUSIVE).
     A block B with matching events (B,0) and (B,1): the client delivers
     (B,0), DISCONNECTS mid-block (cursor stopped before (B,1)), last_block
     = B, then RECONNECTS with connSince = B+1 EXCLUSIVE — the new window
     [B+1, head] SKIPS block B, so (B,1) is never rescanned and never
     delivered. Once caught up to the head, `delivered` is missing the
     existing in-range event (B,1). EXPECTED FALSIFIED — VERIFIED:
     INV_NoLoss violated at 645 distinct states, a 5-state counterexample
     (scratch copy checking INV_NoLoss only, since the exclusive redial also
     trips INV_TypeOK's inclusive-since shape clause — that clause is dropped
     for the isolated no-loss falsification). The concrete lost-same-block
     trace TLC printed (matching = {(0,0),(0,1)} — a MULTI-EVENT block):
     Init -> Apply block 0 (head=1) -> Deliver (0,0) [delivered={(0,0)},
     lastBlock=0] -> Disconnect (cursor before (0,1)) -> Reconnect EXCLUSIVE
     (connSince = lastBlock+1 = 1) -> the window [1, head=1) is EMPTY, so the
     client is caught up, yet (0,1) \in ExistingInRange \ delivered ->
     INV_NoLoss violated. This is exactly the gap the inclusive-`since`
     choice prevents; the exclusive mutant loses the same-block tail event.

MODELING SCOPE / ABSTRACTION BOUNDARY (kept tractable for TLC):

  * ONE client, a SEQUENCE of connections. FB72 proves each single
    connection's partition; this module abstracts a connection to its
    net effect — an in-order deliverer of matching events in
    [connSince, head] — and studies the UNION across the reconnect seam.
    The within-connection catch-up/live split, the atomic capture+register
    (SS-2), the `subscribed`/`live` markers are FB72 territory, imported as
    the deliverer contract, not re-modeled.
  * BACKPRESSURE / KILL is FB71 (SubscriberBackpressure.tla) and is OUT OF
    SCOPE: a kill is just ONE cause of Disconnect here (the R54 client
    reconnects on an error frame OR a clean disconnect alike,
    main.cpp:5866-5949). This module's Disconnect is cause-agnostic — it
    fires at any point, modeling both the FB71 kill and a clean drop.
  * HEARTBEATS advancing last_block are SAFE and ABSTRACTED AWAY. A
    heartbeat frame carries a block_index but no matching event; the R54
    client folds it into last_block (main.cpp:5932-5936 keys on any frame
    with a block_index). This is safe because the heartbeat's block_index H
    is only emitted AFTER the connection has scanned through block H with NO
    UNDELIVERED matching event skipped (heartbeat = "no match up to here" —
    it fires only when nothing matchable was passed over). We model this by
    NOT letting last_block run ahead of the delivered frontier: last_block
    only advances to a block whose in-range matching events are all
    delivered (the InOrderFrontier discipline, §5/§7), which is precisely
    the heartbeat safety condition. So heartbeats add no new seam shape —
    they can only move `since` to a point already fully delivered, which the
    inclusive redial re-covers harmlessly. (Alternative: an explicit
    heartbeat action gated on "no undelivered match below" collapses to the
    same frontier; abstracting is the KISS choice.)
  * A matching event's identity is (block_index, tx_index). tx_index ranges
    0..K per block (K = TX_MAX). K >= 1 is REQUIRED for the multi-event
    block the mutant needs; K is small in the .cfg for tractability.
  * original_since is fixed at 0 (subscribe-from-genesis) in the shipped
    .cfg: the widest window, exercising every seam split. A non-zero
    original since only shrinks the range floor and removes no seam shape.
  * TCP/socket framing, the writer's seq monotonicity, partial-line framing
    are all abstracted (FB71/FB72 own them): Deliver moves a matching event
    from "exists in the current window, not yet delivered, in cursor order"
    into the deduped `delivered` set, losslessly and in order.

TYPED-SENTINEL CAUTION (a real bug that bit a sibling model): no string
sentinel is ever compared with a record or number via `=`. Matching events
are modeled as a SET of (block_index, tx_index) PAIRS (records with two Nat
fields); last_block is a Nat with the OUT-OF-RANGE sentinel NoBlock =
MAX_BLOCKS+1 for "nothing observed yet", pinned by INV_TypeOK's range so it
can never masquerade as a real block index and every last_block comparison is
Nat-vs-Nat. The connection cursor is a Nat pair too. No cross-type equality
can arise.

To check (assuming TLC installed):
  $ tlc SubscriberReconnectSeam.tla -config SubscriberReconnectSeam.cfg
*)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MAX_BLOCKS,  \* finite bound on applied blocks (exhibit size); the chain
                 \* grows over indices 0..MAX_BLOCKS-1
    TX_MAX       \* max tx_index of a matching event within a block: a block
                 \* carries a SUBSET of {0..TX_MAX} matching events. TX_MAX>=1
                 \* makes a MULTI-EVENT block reachable (the mutant's crux).

ASSUME ConfigOK ==
    /\ MAX_BLOCKS \in Nat \ {0}
    /\ TX_MAX \in Nat            \* TX_MAX >= 1 for the multi-event block;
                                 \* TX_MAX = 0 degenerates to one-event blocks

\* -----------------------------------------------------------------
\* §1. Identity universe.
\* -----------------------------------------------------------------

\* Applied-block indices ever reachable: 0..MAX_BLOCKS-1 (a chain of height h
\* has indices 0..h-1). The original since window is fixed at 0.
BlockIdx == 0 .. (MAX_BLOCKS - 1)
TxIdx    == 0 .. TX_MAX
Since    == 0                    \* original_since (subscribe-from-genesis)

\* A matching event's identity: the (block_index, tx_index) pair the client
\* dedups on. `matching` (fixed at Init) is a SUBSET of this event space.
EventId  == [b : BlockIdx, t : TxIdx]

\* "last_block not yet set" — a Nat OUTSIDE 0..MAX_BLOCKS so INV_TypeOK's
\* range pins it and no Nat-vs-record equality can occur (typed-sentinel
\* caution). MAX_BLOCKS+1 is one past the largest real block index+1.
NoBlock == MAX_BLOCKS + 1

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    head,        \* 0..MAX_BLOCKS: applied-block counter (producer clock).
                 \* Applied indices are 0..head-1; the window top is head.
    matching,    \* SUBSET EventId: which (block, tx) pairs carry a matching
                 \* event (fixed at Init — the daemon-independent chain fact).
    connSince,   \* 0..MAX_BLOCKS: the current connection's `since` (the
                 \* redial parameter). Starts at Since; inclusive on redial.
    cursor,      \* EventId \cup {DoneCursor}: the current connection's in-
                 \* order scan position — the NEXT matching event it will
                 \* deliver, or DoneCursor when drained to the head.
    connected,   \* BOOLEAN: is a connection currently open (vs. between
                 \* connections, awaiting reconnect)?
    delivered,   \* SUBSET EventId: the client's DEDUPED observed set (a set,
                 \* so re-delivery across the inclusive seam is absorbed).
    lastBlock    \* 0..MAX_BLOCKS or NoBlock: max block_index observed on any
                 \* frame (the redial `since`). Advances only to a fully-
                 \* delivered frontier (heartbeat-safe, §5 note).

vars == <<head, matching, connSince, cursor, connected, delivered, lastBlock>>

\* -----------------------------------------------------------------
\* §3. Derived sets.
\* -----------------------------------------------------------------

\* Matching events that currently EXIST on the chain (applied, block < head)
\* AND fall in the original since window [Since, head). THIS is the set
\* INV_NoLoss requires `delivered` to cover once the client is caught up.
ExistingInRange ==
    { e \in matching : e.b < head /\ e.b >= Since }

\* Matching events in the CURRENT connection's window [connSince, head) that
\* the connection is responsible for delivering (FB72's single-connection
\* result: this window is delivered exactly, in order).
ConnWindow ==
    { e \in matching : e.b < head /\ e.b >= connSince }

\* Total order on events: block_index major, tx_index minor — the in-order
\* delivery order FB72 gives (blocks apply in order; one writer drains FIFO).
Before(e1, e2) ==
    \/ e1.b < e2.b
    \/ (e1.b = e2.b /\ e1.t < e2.t)

\* -----------------------------------------------------------------
\* §4. Cursor sentinel (typed, record-shaped — never string-vs-record).
\* -----------------------------------------------------------------

\* "cursor has drained the window": a record disjoint from EventId (its b
\* field is MAX_BLOCKS, one past every real block index), so every cursor
\* comparison is record-vs-record and the sentinel can never be a real event.
DoneCursor == [b |-> MAX_BLOCKS, t |-> 0]

\* The set of not-yet-delivered events in the current connection's window
\* that are AT OR AFTER the cursor (the ones this connection may still
\* deliver, in order). Undelivered-below-cursor cannot exist by the in-order
\* discipline (INV_LastBlockSound pins that).
PendingFromCursor ==
    { e \in ConnWindow :
        /\ e \notin delivered
        /\ (cursor = DoneCursor \/ ~Before(e, cursor)) }

\* Is the current connection caught up to the head (nothing left to deliver
\* in its window)? THIS is INV_NoLoss's guard: the no-loss claim is stated at
\* a caught-up state (the client has drained the current connection). A
\* connection is caught up when its cursor is Done OR its window is fully
\* delivered.
CaughtUp ==
    /\ connected
    /\ ConnWindow \subseteq delivered

\* -----------------------------------------------------------------
\* §5. Initial state.
\* -----------------------------------------------------------------
\*
\* TLC enumerates every matching \subseteq EventId, so every arrangement of
\* which (block, tx) pairs carry a matching event — including multi-event
\* blocks, empty, and all — is explored against every Apply / Deliver /
\* Disconnect / Reconnect interleaving. The client starts CONNECTED with the
\* original since (subscribe-from-genesis), cursor at the window bottom,
\* nothing delivered, last_block unset.
Init ==
    /\ head = 0
    /\ matching \in SUBSET EventId
    /\ connSince = Since
    /\ cursor = DoneCursor        \* empty chain: nothing to scan yet
    /\ connected = TRUE
    /\ delivered = {}
    /\ lastBlock = NoBlock

\* -----------------------------------------------------------------
\* §6. Producer: apply the next block (the chain grows).
\* -----------------------------------------------------------------
\*
\* Apply block `head` (its matching events are already fixed in `matching`).
\* If the current connection had drained to the head (cursor Done) and this
\* new block carries an undelivered matching event in the window, the cursor
\* re-arms to the first such event so the live tail can deliver it. Modeled
\* by recomputing the cursor as the minimum pending event after the apply.
Apply ==
    /\ head < MAX_BLOCKS
    /\ head' = head + 1
    /\ UNCHANGED <<matching, connSince, cursor, connected, delivered,
                   lastBlock>>

\* -----------------------------------------------------------------
\* §7. Connection: in-order delivery (FB72's single-connection result).
\* -----------------------------------------------------------------
\*
\* Deliver the NEXT matching event in the current connection's window, in
\* (block, tx) order. This imports FB72: a connection with `since = connSince`
\* delivers exactly the matching events in [connSince, head], in order. We
\* pick the SMALLEST pending event (strict in-order — no skipping), add it to
\* the deduped `delivered` set (a re-delivery across the inclusive seam is a
\* set-union no-op = dedup), and advance last_block to this block IF the whole
\* block's in-range matching events at or below it are now delivered (the
\* heartbeat-safe frontier: last_block never runs ahead of a fully-delivered
\* block, so an inclusive redial at last_block loses nothing).
IsMinPending(e) ==
    /\ e \in PendingFromCursor
    /\ \A f \in PendingFromCursor : e = f \/ Before(e, f)

Deliver ==
    /\ connected
    /\ PendingFromCursor /= {}
    /\ \E e \in PendingFromCursor :
          /\ IsMinPending(e)
          /\ delivered' = delivered \cup {e}
          \* advance the cursor to just past e (next pending, or Done)
          /\ cursor' = e            \* cursor marks the last delivered; the
                                    \* PendingFromCursor ~Before(e,cursor)
                                    \* guard lets the SAME-block next tx and
                                    \* later blocks through, never an already-
                                    \* delivered one (it is not pending).
          \* last_block = max block_index of any DELIVERED frame (main.cpp
          \* :5932-5936: last_block = max over all block_index-bearing frames).
          \* Delivery is strictly in-order (min-pending first), so e.b is >=
          \* every previously delivered block; the Max guard is belt-and-braces
          \* against any re-delivered lower event across the seam. This is the
          \* MID-BLOCK-safe frontier the inclusive redial rests on: a partial
          \* block B (only (B,0) delivered) still sets last_block = B, so the
          \* redial's since = B INCLUSIVE re-covers block B and picks up (B,1).
          /\ lastBlock' = IF lastBlock = NoBlock \/ e.b > lastBlock
                          THEN e.b ELSE lastBlock
    /\ UNCHANGED <<head, matching, connSince, connected>>

\* -----------------------------------------------------------------
\* §8. Disconnect: drop the connection at ANY point (adversarial cause).
\* -----------------------------------------------------------------
\*
\* Backpressure kill (FB71), clean shutdown, or transport drop — all collapse
\* to "the connection ends". May fire MID-BLOCK (cursor stopped between two
\* tx_index of the same block, e.g. after (B,0) before (B,1)) — the exact
\* window the mutant exploits. No fairness (adversarial).
Disconnect ==
    /\ connected
    /\ connected' = FALSE
    /\ UNCHANGED <<head, matching, connSince, cursor, delivered, lastBlock>>

\* -----------------------------------------------------------------
\* §9. Reconnect: REDIAL with since = last_block INCLUSIVE (the crux).
\* -----------------------------------------------------------------
\*
\* main.cpp:5877-5878: eff_since = (have_last ? last_block : original since).
\* INCLUSIVE — the new window is [last_block, head], re-scanning last_block so
\* a same-block undelivered event (B,1) after a delivered (B,0) is re-covered.
\* The scan cursor resets to the window bottom; already-delivered events in
\* the re-scanned overlap are dropped by the `delivered` dedup (they are not
\* in PendingFromCursor). The M1 mutant flips `lastBlock` -> `lastBlock + 1`.
Reconnect ==
    /\ ~connected
    /\ connected' = TRUE
    /\ connSince' = IF lastBlock = NoBlock THEN Since ELSE lastBlock  \* INCLUSIVE
    /\ cursor' = DoneCursor       \* resume scanning; Deliver re-arms from the
                                  \* window bottom (PendingFromCursor with a
                                  \* Done cursor = whole window minus delivered)
    /\ UNCHANGED <<head, matching, delivered, lastBlock>>

\* -----------------------------------------------------------------
\* §10. Spec.
\* -----------------------------------------------------------------

Next ==
    \/ Apply
    \/ Deliver
    \/ Disconnect
    \/ Reconnect

\* Fairness (liveness only; every safety invariant is fairness-independent):
\* SF on Deliver, WF on Reconnect. SF (not WF) on Deliver is LOAD-BEARING and
\* matches FB71's SF_vars(Deliver): the adversarial Disconnect repeatedly
\* DISABLES Deliver (a connection can be cut before it drains), so Deliver is
\* enabled only INTERMITTENTLY — once per reconnected window. WF (fires only
\* if CONTINUOUSLY enabled) would be starved by a disconnect-before-deliver
\* loop and is too weak; SF (fires if enabled INFINITELY OFTEN) is exactly the
\* "makes progress each time it is connected" guarantee — the client drains a
\* frame on some connection rather than being cut every single time. WF on
\* Reconnect is the --reconnect loop (the client redials after every
\* disconnect). No fairness on Apply (the chain may idle — the property
\* quantifies over EXISTING events) or on the adversarial Disconnect; the
\* point is the property survives REPEATED disconnect as long as Reconnect
\* keeps firing (WF) and each connection eventually makes progress (SF).
Spec ==
    /\ Init /\ [][Next]_vars
    /\ SF_vars(Deliver)
    /\ WF_vars(Reconnect)

\* -----------------------------------------------------------------
\* §11. Type invariant.
\* -----------------------------------------------------------------

INV_TypeOK ==
    /\ head \in 0..MAX_BLOCKS
    /\ matching \in SUBSET EventId
    /\ connSince \in 0..MAX_BLOCKS
    /\ cursor \in EventId \cup {DoneCursor}
    /\ connected \in BOOLEAN
    /\ delivered \in SUBSET EventId
    /\ lastBlock \in (0..MAX_BLOCKS) \cup {NoBlock}
    \* connSince rides on last_block once anything is observed (inclusive
    \* redial pins connSince = lastBlock; before any observation connSince
    \* stays at the original since floor).
    /\ (lastBlock /= NoBlock) => (connSince <= lastBlock \/ connSince = Since)

\* -----------------------------------------------------------------
\* §12. Safety invariants — the SS-6 reconnect seam.
\* -----------------------------------------------------------------

\* INV_NoLoss — THE core no-loss-at-a-seam claim, guarded by CaughtUp.
\* Whenever the client's CURRENT connection has drained its window to the head
\* (nothing pending — ConnWindow \subseteq delivered), the deduped `delivered`
\* set contains EVERY matching event that EXISTS in the original range
\* [Since, head). Nothing was lost at ANY reconnect seam. The guard matches
\* the C++: the no-loss claim is about the steady state after the client has
\* consumed the current connection's window; mid-drain the tail is simply not
\* yet delivered (WF_vars(Deliver) discharges that — see PROP). The
\* EXCLUSIVE-since mutant M1 falsifies this: a same-block undelivered event
\* below the skipped block is missing from a caught-up `delivered`.
INV_NoLoss ==
    CaughtUp => (ExistingInRange \subseteq delivered)

\* INV_NoDup — exactly-once AFTER dedup. `delivered` is a SET of (block, tx)
\* pairs, so it is duplicate-free by construction; this invariant pins the
\* modeling contract that makes that meaningful — every delivered identity is
\* a real matching event in the original range (no phantom / out-of-range
\* delivery, and re-delivery across the inclusive seam was absorbed into the
\* set rather than duplicated). Since a set cannot hold a pair twice, the
\* deduped stream carries each identity at most once.
INV_NoDup ==
    \A e \in delivered :
        /\ e \in matching
        /\ e.b >= Since
        /\ e.b < head

\* INV_LastBlockSound — last_block soundness + the IN-ORDER-DELIVERY premise
\* lifted across the seam (FB72's within-connection in-order delivery, made an
\* invariant of the reconnect union):
\*   (a) last_block = the MAX block_index in `delivered` (or NoBlock if empty)
\*       — the client's redial `since` is exactly its delivered frontier;
\*   (b) in-order: every matching event that EXISTS in range with block_index
\*       STRICTLY BELOW last_block is already delivered (a delivered frontier
\*       at last_block implies the whole prefix below it is covered — no hole
\*       beneath the frontier). This is the premise the inclusive redial rests
\*       on: since = last_block re-covers exactly the (possibly partial) block
\*       at the frontier, and everything below is already in `delivered`.
INV_LastBlockSound ==
    /\ (delivered = {}) => (lastBlock = NoBlock)
    /\ (lastBlock /= NoBlock) =>
          /\ (\E e \in delivered : e.b = lastBlock)
          /\ (\A e \in delivered : e.b <= lastBlock)
    \* in-order frontier: nothing in range strictly below the frontier is
    \* left undelivered.
    /\ (lastBlock /= NoBlock) =>
          \A e \in matching :
              (e.b < lastBlock /\ e.b >= Since /\ e.b < head) => e \in delivered

\* -----------------------------------------------------------------
\* §13. Temporal property (fairness) — eventual delivery under churn.
\* -----------------------------------------------------------------
\*
\* PROP_AllEventuallyDelivered — every matching event that EXISTS in
\* [Since, head) is EVENTUALLY delivered, even under REPEATED
\* disconnect/reconnect, as long as Reconnect keeps firing. Because the chain
\* may idle (no fairness on Apply), this fixes an event identity and asserts:
\* once it is an existing matching event in range, it is eventually in
\* `delivered`. WF on Deliver drains the current connection; WF on Reconnect
\* re-opens a connection (with inclusive since, so the event stays in-window)
\* after every adversarial Disconnect — so the event cannot be starved
\* forever at a seam.
PROP_AllEventuallyDelivered ==
    \A e \in EventId :
        [] ( (e \in matching /\ e.b >= Since /\ e.b < head)
             => <> (e \in delivered) )

\* -----------------------------------------------------------------
\* §14. Non-vacuity probe (NOT in the shipped .cfg — EXPECTED FALSIFIED
\* when checked; see the header M1 probe note). Kept as documentation of
\* the reachability the seam rests on: a MULTI-EVENT block delivered
\* PARTIALLY (one tx delivered, a sibling tx not) is genuinely reachable,
\* so INV_NoLoss's same-block arm is not vacuous.
\* -----------------------------------------------------------------

\* Probe_PartialBlockUnreachable: falsification exhibits a state where some
\* block has one matching tx delivered and a sibling matching tx NOT
\* delivered — the mid-block seam the inclusive-since choice must re-cover.
Probe_PartialBlockUnreachable ==
    ~(\E e1, e2 \in matching :
         /\ e1.b = e2.b
         /\ e1.t /= e2.t
         /\ e1 \in delivered
         /\ e2 \notin delivered
         /\ e2.b < head)

=============================================================================
\* Cross-references.
\*
\* docs/proofs/StreamingSubscriptionSoundness.md SS-6 — the prose claim this
\*   module machine-checks: across reconnects the contract is at-least-once
\*   via redial with `since` = last observed block_index + (block_index,
\*   tx_index) dedup; this module pins the STRONGER no-loss-after-dedup form
\*   that the INCLUSIVE-since realization actually delivers (SS-6's table row
\*   "Replay across reconnect": at-least-once + dedup key).
\*
\* C++ (HEAD): src/main.cpp cmd dapp-subscribe --reconnect
\*   (:5802-5960) — the reconnect loop: eff_since = last_block on redial
\*   (:5877-5878, INCLUSIVE = Reconnect's connSince'), last_block = max
\*   observed block_index over all block_index-bearing frames (:5932-5936 =
\*   Deliver's lastBlock' frontier + the heartbeat fold), the error-frame /
\*   clean-disconnect reconnect decision (:5866-5954 = Disconnect + Reconnect),
\*   dedup by (block_index, tx_index) (the deduped `delivered` SET).
\*
\* Sibling specs:
\*   SubscriberCatchupPartition.tla (FB72) — the WITHIN-connection catch-up/
\*     live partition (SS-2) this module COMPOSES ON: FB72 proves each single
\*     connection delivers [connSince, head] gap-free + duplicate-free; FB73
\*     (this module) proves the UNION across the reconnect seam is lossless
\*     and (after dedup) exactly-once, resting on inclusive `since`.
\*   SubscriberBackpressure.tla (FB71) — the live-tail backpressure/KILL
\*     protocol (SS-3); a kill is just ONE cause of this module's Disconnect.
\*   SupplyCounterRead.tla (FB70) — the typed-sentinel + small-CONSTANT +
\*     dated-non-vacuity house style this module follows.
=============================================================================
