----------------------- MODULE SubscriberBackpressure -----------------------
(*
FB71 — TLA+ specification of the v2.20 STREAMING-SUBSCRIPTION per-subscriber
queue / backpressure / KILL-ON-OVERFLOW protocol: the live-tail half of the
`dapp_subscribe` RPC pinned by docs/V2-DESIGN.md "v2.20 — Streaming
subscription RPC" (the wire contract of record). The C++ surface
(rpc_dapp_subscribe / on_block_finalized_for_subscribers /
enqueue_subscriber_event / subscriber_write_worker / kill_subscriber,
src/node/node.cpp touch list in the design entry) is PENDING at authoring
time — this module is the PRE-IMPLEMENTATION design pin; thread the code
line references into this header when v2.20 ships, the same way the
shipped-read specs carry main.cpp anchors.

Three parties interact around ONE subscriber's bounded FIFO frame queue:

  PRODUCER — the per-block hook (fires inside apply_block_locked, under
             state_mutex_, for every applied block on all 3 apply paths).
             Per subscriber it (a) enqueues a matching dapp_call frame,
             (b) maintains the block-based heartbeat counter (blocks since
             the LAST ENQUEUED frame; on reaching HEARTBEAT_BLOCKS it
             enqueues a heartbeat frame through the SAME bounded enqueue,
             then resets), and (c) on a would-overflow enqueue KILLS the
             subscriber — kill-on-overflow, NOT drop-oldest: killed flag +
             reason "backpressure" set atomically, the overflowing frame is
             NOT enqueued, and if the writer thread sits inside a blocking
             socket write the socket is closed to break it. Every enqueued
             frame carries eid, the monotone per-connection generation
             index (model bookkeeping standing in for the frame identity
             (block_index, tx_index) the client dedups on).
  CONSUMER — the single writer thread (ONE per subscriber): dequeues the
             head frame into an in-flight slot (wip), performs the blocking
             socket write, and assigns the wire `seq` AT WRITE TIME —
             single-writer discipline, so seq monotonicity (+1 per frame
             from the subscribed frame's seq 0) is structural. On observing
             killed from PARKED it abandons any queued frames, emits the
             BEST-EFFORT final error{code=backpressure} frame (single sync
             write, may fail — modeled as a nondeterministic outcome) and
             closes the socket; a write broken by the producer's socket
             close fails without delivering, and the error frame then has
             no socket to go out on.
  CLIENT   — adversarial: may stop reading at any moment (the blocking
             write then wedges: writerState WRITING -> STUCK) and may
             resume. Its observed stream is `delivered` — the subscribed
             frame (seq 0) followed by whatever full frames the writes
             completed.

Safety claims (the kill-vs-drop contract):

  INV_TypeOK           — typed state, wip/writerState discipline.
  INV_BoundedQueue     — Len(queue) <= QUEUE_MAX in EVERY reachable state,
                         including the overflow-handling state itself (the
                         kill is atomic with the refused enqueue; the queue
                         never holds the overflowing frame).
  INV_NoSilentGap      — THE core claim. The client-observed stream is
                         gap-free in BOTH keys, always: wire seq is exactly
                         0,1,2,... in delivery order (seqCtr = frames
                         delivered, each frame's seq = its position), and
                         the delivered DATA frames (dapp_call/heartbeat)
                         carry eids 1..k — a CONTIGUOUS PREFIX of the
                         generated event sequence. No alive-qualification
                         is needed because kill TRUNCATES the stream rather
                         than perforating it: a would-be gap implies the
                         subscriber was killed first, and after kill no
                         data frame is ever delivered. Drop-oldest would
                         instead deliver around the dropped frame — a
                         mid-stream eid gap on a live connection (mutant
                         M1 falsifies exactly this).
  INV_KillOnOverflow   — (i) the overflow event always lands in the killed
                         /\ reason="backpressure" state (never handled by
                         dropping); (ii) frame conservation while alive: as
                         long as ~killed, EVERY generated frame is in
                         exactly one of {delivered data, wip, queue} — no
                         frame silently vanishes from an un-killed
                         subscriber. Frames abandoned at kill time are the
                         reconnect-via-since window, not silent loss.
  INV_KilledFailClosed — fail-closed shutdown shape: an error frame is
                         TERMINAL (nothing is ever delivered after it, in
                         particular no dapp_call/heartbeat), an error frame
                         implies killed /\ writer DEAD, DEAD implies
                         killed, and the socket is only ever closed as part
                         of a kill.

Temporal claims (fairness: WF on the writer's own steps — the thread is
scheduled; SF on Deliver — a write with a reading client completes if given
infinitely many chances; WF on ClientResume — a liveness-only modeling
assumption that the client does not stall FOREVER; every safety invariant
above is fairness-independent):

  PROP_KilledEventuallyDead    — a killed subscriber's writer always
                                 reaches DEAD (removal): from PARKED via
                                 the best-effort-error exit, from a broken
                                 in-flight write via the write failure.
  PROP_PendingDeliveredOrKilled — every generated frame that reaches the
                                 queue/wip is eventually DELIVERED or the
                                 subscriber is KILLED first. The kill
                                 disjunct is the point: a bounded queue
                                 cannot promise unconditional delivery;
                                 the contract is deliver-or-demonstrably-
                                 kill, never silent drop. This is the
                                 liveness face of kill-vs-drop.
  PROP_StuckWriteBroken        — the stuck-writer case: once a kill fires
                                 while the writer is STUCK in a blocking
                                 write, the socket close breaks the write
                                 and the writer reaches DEAD — it does not
                                 stay STUCK forever holding the thread.

NON-VACUITY PROBES (falsify-on-mutant; re-run 2026-07-03, tla2tools v1.8.0,
java 11, scratch copies only — none of these ships wired in; scratch files
deleted after each run):

  M1 (kill-on-overflow replaced by drop-oldest): swap OverflowKill for the
     in-module DropOldest body in BoundedEnqueue. EXPECTED FALSIFIED —
     VERIFIED: INV_KillOnOverflow violated (12 distinct states). TLC
     reports the conservation arm first: a would-overflow enqueue that
     drops the head instead of killing leaves killed = FALSE with a frame
     gone, which INV_KillOnOverflow's "overflow => killed, and no live
     drop" clause catches before the delivered-order INV_NoSilentGap gap
     can manifest downstream. Either way the drop-oldest mutant is caught:
     the kill-on-overflow rule is load-bearing.
  M2 (bound check removed): BoundedEnqueue mutated to unconditional
     EnqueueFrame. EXPECTED FALSIFIED — VERIFIED: INV_BoundedQueue
     violated (12 distinct states): matching blocks push Len(queue) past
     QUEUE_MAX = 2 with the writer unscheduled.
  M0a (reachability): probe invariant Probe_KilledStuckUnreachable
     (== ~(killed /\ writerState = "STUCK")). EXPECTED FALSIFIED —
     VERIFIED: violated (272 distinct states). TLC exhibits the stall ->
     STUCK -> overflow-kill trace, so the stuck-writer kill path
     PROP_StuckWriteBroken speaks about is genuinely reachable, not
     vacuously satisfied.
  M0b (reachability): probe invariant Probe_ErrorFrameUnreachable
     (== no error frame ever delivered). EXPECTED FALSIFIED — VERIFIED:
     violated (29 distinct states): the best-effort final error frame is
     deliverable (kill with the writer PARKED, socket still open), so
     INV_KilledFailClosed's error-terminal arm is not vacuous.

Modeling scope / abstraction boundary (kept tractable for TLC):

  * ONE subscriber. The design isolates subscribers by construction (one
    queue + one writer thread each; "one slow subscriber cannot affect
    any other"), so the per-subscriber protocol IS the unit of proof.
    The global SUBSCRIBER_MAX_PER_NODE=256 admission cap and the S-014
    rate-limit / S-001 HMAC auth gate in front of the subscribe (plus the
    invalid_arg / rate_limited one-line rejections) are upstream of the
    streaming layer and out of scope here.
  * Socket/TCP is abstracted to a MAY-STALL CHANNEL: a blocking write
    completes iff the client is reading and the socket is open; a client
    that stops reading wedges the write (STUCK); closing the socket from
    the producer side fails the in-flight write WITHOUT delivering its
    frame. The close-vs-inflight-write race is collapsed conservatively:
    reality may still deliver the already-buffered frame, but that frame
    is the next contiguous eid (FIFO), so every invariant would survive
    the optimistic outcome too. Partial lines are not frames (newline-
    JSON framing) — delivery is all-or-nothing per frame.
  * SUBSCRIBER_BYTES_MAX (16 MiB) is abstracted to FRAME COUNT: QUEUE_MAX
    models whichever of the two ceilings bites first (count-only
    abstraction, per the FB71 brief). The C++ must apply both checks in
    the same enqueue; the kill shape is identical.
  * Catch-up replay of [since, H) and the subscribed/live gap-freedom
    partition are OUT OF SCOPE — this module starts at the moment the
    subscriber is registered (delivered is seeded with the subscribed
    frame, seq 0) and models the LIVE TAIL only. The replay-union-hook
    no-gap-no-overlap obligation is a separate module's territory.
  * Heartbeats: the block-based counter (blocks since last enqueued
    frame, threshold HEARTBEAT_BLOCKS) is modeled; the 30s wall-clock
    condvar-timeout fallback for idle chains is untimed territory and is
    abstracted away (it enqueues through the same bounded path, so it
    adds no new kill shape).
  * Kill reasons: backpressure is the ONLY modeled kill source; shutdown
    is operationally identical (same kill routine, different code) and
    invalid_arg / rate_limited never reach the streaming layer.
  * Blocks stop at MAX_BLOCKS (finite exhibit) and the hook skips killed
    subscribers (post-kill blocks cannot change subscriber state, so
    modeling them would only add stutter).
  * seq is per-connection; reconnect (client redials with since = last
    observed block_index, fresh sid, seq restarts at 0) is a NEW instance
    of this very model — dedup across reconnect rides on frame identity,
    which eid stands in for.

To check (assuming TLC installed):
  $ tlc SubscriberBackpressure.tla -config SubscriberBackpressure.cfg
*)

EXTENDS Naturals, Sequences

CONSTANTS
    QUEUE_MAX,        \* per-subscriber frame-count ceiling: the clamped
                      \* min(queue_max request, SUBSCRIBER_QUEUE_MAX), >= 4
                      \* in production (floor); small here for tractability
    MAX_BLOCKS,       \* finite bound on applied blocks (exhibit size)
    HEARTBEAT_BLOCKS  \* heartbeat_blocks after clamp [1,10000]

ASSUME ConfigOK ==
    /\ QUEUE_MAX \in Nat \ {0}
    /\ MAX_BLOCKS \in Nat \ {0}
    /\ HEARTBEAT_BLOCKS \in Nat \ {0}
    /\ MAX_BLOCKS >= QUEUE_MAX + 2     \* stuck-writer overflow reachable:
                                       \* wip + full queue + one more frame
    /\ HEARTBEAT_BLOCKS <= MAX_BLOCKS  \* heartbeat frames reachable

\* -----------------------------------------------------------------
\* §1. Frame universe.
\* -----------------------------------------------------------------

DataKinds == {"dapp_call", "heartbeat"}   \* hook-generated, eid-carrying
WireKinds == DataKinds \cup {"subscribed", "error"}

\* Queued/in-flight frames: kind + generation index. block_index / tx_index /
\* tx_hash / payload are abstracted into eid (the client's dedup identity).
Frames == [kind : DataKinds, eid : 1..MAX_BLOCKS]

\* Client-observed frames: wire seq attached at write time. eid 0 is the
\* typed sentinel for the non-data frames (subscribed, error).
DFrames == [kind : WireKinds, eid : 0..MAX_BLOCKS, seq : 0..(MAX_BLOCKS + 1)]

\* Typed record sentinel for "writer holds no in-flight frame". A string
\* sentinel ("NONE") makes TLC hard-error the moment INV_TypeOK evaluates
\* wip = NoFrame with wip holding a record (string-vs-record equality is a
\* runtime error, not FALSE — the house typed-sentinel-mismatch bug class).
\* This record shares Frames' domain {kind, eid} but with an impossible
\* kind ("none" \notin DataKinds) and impossible eid (0 \notin 1..MAX_BLOCKS),
\* so it is disjoint from Frames and every wip comparison is record-vs-record.
NoFrame == [kind |-> "none", eid |-> 0]

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    blk,           \* 0..MAX_BLOCKS: applied-block counter (producer clock)
    hbCnt,         \* blocks since the last ENQUEUED frame (heartbeat ctr)
    eidCtr,        \* last generated frame eid (monotone, 0 = none yet)
    queue,         \* Seq(Frames): the bounded per-subscriber FIFO
    wip,           \* Frames \cup {NoFrame}: the writer's in-flight frame
    seqCtr,        \* next wire seq to assign (single-writer, write time)
    delivered,     \* Seq(DFrames): the client-observed stream
    killed,        \* TRUE once the subscriber is killed
    reason,        \* "NONE" | "backpressure": why killed
    overflowed,    \* history flag: a would-overflow enqueue happened
    writerState,   \* "PARKED" | "WRITING" | "STUCK" | "DEAD"
    clientReading, \* adversarial client currently draining the socket?
    socketClosed   \* socket force-closed (kill path)

vars == <<blk, hbCnt, eidCtr, queue, wip, seqCtr, delivered,
          killed, reason, overflowed, writerState, clientReading,
          socketClosed>>

InWrite == writerState \in {"WRITING", "STUCK"}

IsData(f) == f.kind \in DataKinds
DataDelivered == SelectSeq(delivered, IsData)

\* -----------------------------------------------------------------
\* §3. Initial state: subscriber just registered, subscribed frame
\* (seq 0) already on the wire, writer parked, client reading.
\* -----------------------------------------------------------------

Init ==
    /\ blk = 0 /\ hbCnt = 0 /\ eidCtr = 0
    /\ queue = << >> /\ wip = NoFrame
    /\ seqCtr = 1
    /\ delivered = << [kind |-> "subscribed", eid |-> 0, seq |-> 0] >>
    /\ killed = FALSE /\ reason = "NONE" /\ overflowed = FALSE
    /\ writerState = "PARKED"
    /\ clientReading = TRUE
    /\ socketClosed = FALSE

\* -----------------------------------------------------------------
\* §4. Producer: the per-block hook + the bounded enqueue.
\* -----------------------------------------------------------------

\* OverflowKill — the enqueue found the queue at capacity: kill-on-overflow.
\* Atomic with the refused enqueue (the hook holds the subscriber lock):
\* the overflowing frame is NOT enqueued, killed+reason set, and if the
\* writer sits inside a blocking write the socket is closed to break it.
OverflowKill ==
    /\ killed'       = TRUE
    /\ reason'       = "backpressure"
    /\ overflowed'   = TRUE
    /\ socketClosed' = (socketClosed \/ InWrite)
    /\ UNCHANGED <<queue, eidCtr, hbCnt>>

\* EnqueueFrame — room available: append with the next generation index and
\* reset the heartbeat counter (any enqueued frame resets it).
EnqueueFrame(kind) ==
    /\ queue'  = Append(queue, [kind |-> kind, eid |-> eidCtr + 1])
    /\ eidCtr' = eidCtr + 1
    /\ hbCnt'  = 0
    /\ UNCHANGED <<killed, reason, overflowed, socketClosed>>

\* DropOldest — the M1 MUTANT body (drop-oldest instead of kill): NOT
\* referenced by Next. Kept in-module so the recorded non-vacuity mutant is
\* a one-token swap inside BoundedEnqueue (see the header probe table).
\* Never wire it in: it is the exact behavior the contract forbids.
DropOldest(kind) ==
    /\ queue'  = Append(Tail(queue), [kind |-> kind, eid |-> eidCtr + 1])
    /\ eidCtr' = eidCtr + 1
    /\ hbCnt'  = 0
    /\ UNCHANGED <<killed, reason, overflowed, socketClosed>>

\* BoundedEnqueue — enqueue_subscriber_event's shape. M1 mutant: OverflowKill
\* -> DropOldest(kind). M2 mutant: drop the bound test (always EnqueueFrame).
BoundedEnqueue(kind) ==
    IF Len(queue) = QUEUE_MAX THEN OverflowKill ELSE EnqueueFrame(kind)

\* HookBlockMatch — an applied block carries a DAPP_CALL matching this
\* subscriber's (domain, topic) filter: enqueue a dapp_call frame. One
\* matching event per block suffices: a k-event block is k back-to-back
\* hook enqueues, already covered by k matching single-event blocks.
HookBlockMatch ==
    /\ ~killed
    /\ blk < MAX_BLOCKS
    /\ blk' = blk + 1
    /\ BoundedEnqueue("dapp_call")
    /\ UNCHANGED <<wip, seqCtr, delivered, writerState, clientReading>>

\* HookBlockNoMatch — an applied block with no matching event: bump the
\* heartbeat counter; on reaching HEARTBEAT_BLOCKS enqueue a heartbeat
\* frame THROUGH THE SAME BOUNDED PATH (a heartbeat can be the overflow
\* trigger too) and reset.
HookBlockNoMatch ==
    /\ ~killed
    /\ blk < MAX_BLOCKS
    /\ blk' = blk + 1
    /\ IF hbCnt + 1 >= HEARTBEAT_BLOCKS
       THEN BoundedEnqueue("heartbeat")
       ELSE /\ hbCnt' = hbCnt + 1
            /\ UNCHANGED <<queue, eidCtr, killed, reason, overflowed,
                           socketClosed>>
    /\ UNCHANGED <<wip, seqCtr, delivered, writerState, clientReading>>

\* -----------------------------------------------------------------
\* §5. Consumer: the single writer thread.
\* -----------------------------------------------------------------

\* WriterWake — parked writer, un-killed, frame available: dequeue the head
\* into the in-flight slot and enter the blocking write. A killed writer
\* never starts a new data write (it takes WriterKillExit instead).
WriterWake ==
    /\ writerState = "PARKED"
    /\ ~killed
    /\ queue /= << >>
    /\ wip'   = Head(queue)
    /\ queue' = Tail(queue)
    /\ writerState' = "WRITING"
    /\ UNCHANGED <<blk, hbCnt, eidCtr, seqCtr, delivered, killed, reason,
                   overflowed, clientReading, socketClosed>>

\* Deliver — the in-flight write completes (client reading, socket open):
\* the frame reaches the client carrying the wire seq assigned HERE, at
\* write time, by this single thread — seq monotonicity is structural.
\* Covers both WRITING and STUCK (a stalled client that resumed reading
\* lets the wedged write finish).
Deliver ==
    /\ InWrite
    /\ clientReading
    /\ ~socketClosed
    /\ wip /= NoFrame
    /\ delivered' = Append(delivered,
                           [kind |-> wip.kind, eid |-> wip.eid,
                            seq |-> seqCtr])
    /\ seqCtr' = seqCtr + 1
    /\ wip'    = NoFrame
    /\ writerState' = "PARKED"
    /\ UNCHANGED <<blk, hbCnt, eidCtr, queue, killed, reason, overflowed,
                   clientReading, socketClosed>>

\* WriterStall — the adversarial client stopped reading: the blocking
\* write wedges (kernel buffers full). The thread is now STUCK.
WriterStall ==
    /\ writerState = "WRITING"
    /\ ~clientReading
    /\ ~socketClosed
    /\ writerState' = "STUCK"
    /\ UNCHANGED <<blk, hbCnt, eidCtr, queue, wip, seqCtr, delivered,
                   killed, reason, overflowed, clientReading, socketClosed>>

\* WriteBroken — the kill path closed the socket under the in-flight
\* write: the write fails WITHOUT delivering (the wip frame is part of the
\* reconnect-via-since window), the best-effort final error frame has no
\* socket to go out on, the writer exits. One atomic step: fail + exit.
WriteBroken ==
    /\ InWrite
    /\ socketClosed
    /\ wip' = NoFrame
    /\ writerState' = "DEAD"
    /\ UNCHANGED <<blk, hbCnt, eidCtr, queue, seqCtr, delivered, killed,
                   reason, overflowed, clientReading, socketClosed>>

\* WriterKillExit — a PARKED writer observes killed: abandon any queued
\* frames, emit the BEST-EFFORT final error frame (nondeterministic
\* outcome: the single sync write may succeed while the socket is open, or
\* fail — timeout on a stalled client, or socket already gone), close the
\* socket, exit. The error frame, when delivered, is the connection's LAST
\* frame and carries the next wire seq.
WriterKillExit ==
    /\ writerState = "PARKED"
    /\ killed
    /\ writerState'  = "DEAD"
    /\ socketClosed' = TRUE
    /\ \/ /\ ~socketClosed   \* error frame got out before the close
          /\ delivered' = Append(delivered,
                                 [kind |-> "error", eid |-> 0,
                                  seq |-> seqCtr])
          /\ seqCtr' = seqCtr + 1
       \/ UNCHANGED <<delivered, seqCtr>>   \* best-effort write failed
    /\ UNCHANGED <<blk, hbCnt, eidCtr, queue, wip, killed, reason,
                   overflowed, clientReading>>

\* -----------------------------------------------------------------
\* §6. The adversarial client.
\* -----------------------------------------------------------------

ClientStall ==
    /\ clientReading
    /\ writerState /= "DEAD"
    /\ clientReading' = FALSE
    /\ UNCHANGED <<blk, hbCnt, eidCtr, queue, wip, seqCtr, delivered,
                   killed, reason, overflowed, writerState, socketClosed>>

ClientResume ==
    /\ ~clientReading
    /\ writerState /= "DEAD"
    /\ clientReading' = TRUE
    /\ UNCHANGED <<blk, hbCnt, eidCtr, queue, wip, seqCtr, delivered,
                   killed, reason, overflowed, writerState, socketClosed>>

\* -----------------------------------------------------------------
\* §7. Spec.
\* -----------------------------------------------------------------

Next ==
    \/ HookBlockMatch \/ HookBlockNoMatch
    \/ WriterWake \/ Deliver \/ WriterStall \/ WriteBroken \/ WriterKillExit
    \/ ClientStall \/ ClientResume

\* Fairness: WF on the writer's own steps (the thread is scheduled and a
\* failed write returns); SF on Deliver (a write that is given infinitely
\* many chances against a reading client completes — SF, not WF, because a
\* stall/resume-toggling client enables it only intermittently); WF on
\* ClientResume (liveness-only assumption: the client does not stall
\* FOREVER — safety holds without it). No fairness on the hook (the chain
\* may go idle) or on the adversarial ClientStall.
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(WriterWake)
    /\ SF_vars(Deliver)
    /\ WF_vars(WriteBroken)
    /\ WF_vars(WriterKillExit)
    /\ WF_vars(ClientResume)

\* -----------------------------------------------------------------
\* §8. Type invariant.
\* -----------------------------------------------------------------

INV_TypeOK ==
    /\ blk    \in 0..MAX_BLOCKS
    /\ hbCnt  \in 0..(HEARTBEAT_BLOCKS - 1)
    /\ eidCtr \in 0..MAX_BLOCKS
    /\ queue  \in Seq(Frames)
    /\ wip    \in Frames \cup {NoFrame}
    /\ seqCtr \in 1..(MAX_BLOCKS + 2)
    /\ delivered \in Seq(DFrames)
    /\ killed \in BOOLEAN /\ overflowed \in BOOLEAN
    /\ reason \in {"NONE", "backpressure"}
    /\ writerState \in {"PARKED", "WRITING", "STUCK", "DEAD"}
    /\ clientReading \in BOOLEAN /\ socketClosed \in BOOLEAN
    /\ (InWrite => wip \in Frames)             \* in a write iff holding one
    /\ (writerState \in {"PARKED", "DEAD"} => wip = NoFrame)

\* -----------------------------------------------------------------
\* §9. Safety invariants — the kill-vs-drop contract.
\* -----------------------------------------------------------------

\* INV_BoundedQueue — the queue NEVER exceeds the cap, including in the
\* overflow-handling state itself: the kill is atomic with the refused
\* enqueue, so no state holds QUEUE_MAX+1 frames "briefly". (M2 target.)
INV_BoundedQueue == Len(queue) <= QUEUE_MAX

\* INV_NoSilentGap — the client-observed stream is contiguous in both
\* keys, in every reachable state (kill truncates, never perforates):
\*   (a) the stream opens with the subscribed frame, exactly once;
\*   (b) wire seq is the delivery position: frame i carries seq i-1, and
\*       the single writer's counter equals the frames written — seq
\*       0,1,2,... with no hole and no repeat;
\*   (c) the data frames carry eids 1..k in order: a contiguous PREFIX of
\*       the generated event sequence — no generated frame was skipped
\*       under a frame that was delivered after it. (M1 target.)
INV_NoSilentGap ==
    /\ delivered /= << >>
    /\ delivered[1].kind = "subscribed"
    /\ \A i \in 2..Len(delivered) : delivered[i].kind /= "subscribed"
    /\ seqCtr = Len(delivered)
    /\ \A i \in 1..Len(delivered) : delivered[i].seq = i - 1
    /\ \A i \in 1..Len(DataDelivered) : DataDelivered[i].eid = i

\* INV_KillOnOverflow — overflow is handled by KILL, never by dropping:
\*   (a) the overflow event always lands in killed + reason=backpressure
\*       (same atomic state — there is no overflowed-but-alive state);
\*   (b) frame conservation while alive: every generated frame sits in
\*       exactly one of delivered-data / wip / queue. A silent drop while
\*       ~killed breaks the count (drop-oldest mutant M1 falsifies this
\*       arm too). Frames pending at kill time are abandoned WITH the
\*       kill visible — that is the reconnect-via-since contract.
INV_KillOnOverflow ==
    /\ overflowed => (killed /\ reason = "backpressure")
    /\ ~killed =>
         eidCtr = Len(DataDelivered)
                  + (IF wip = NoFrame THEN 0 ELSE 1)
                  + Len(queue)

\* INV_KilledFailClosed — fail-closed shutdown shape: the error frame is
\* TERMINAL (no frame of any kind after it — in particular a killed
\* subscriber never delivers another dapp_call/heartbeat after the final
\* error frame), an error frame implies the kill already happened and the
\* writer is gone, DEAD implies killed, and the socket is only ever
\* closed as part of a kill.
INV_KilledFailClosed ==
    /\ \A i \in 1..Len(delivered) :
          delivered[i].kind = "error" =>
              /\ i = Len(delivered)
              /\ killed
              /\ writerState = "DEAD"
    /\ (writerState = "DEAD") => killed
    /\ ~killed => ~socketClosed

\* -----------------------------------------------------------------
\* §10. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_KilledEventuallyDead — a killed subscriber is eventually removed:
\* the writer reaches DEAD (via WriterKillExit from PARKED, or via the
\* socket-close-broken write from WRITING/STUCK).
PROP_KilledEventuallyDead == killed ~> (writerState = "DEAD")

PendingEid(e) ==
    \/ \E i \in 1..Len(queue) : queue[i].eid = e
    \/ (wip /= NoFrame /\ wip.eid = e)

DeliveredEid(e) ==
    \E i \in 1..Len(delivered) :
        delivered[i].eid = e /\ IsData(delivered[i])

\* PROP_PendingDeliveredOrKilled — a live subscriber with a queued frame
\* eventually gets it delivered, unless the subscriber is killed first.
\* The kill disjunct is load-bearing: a bounded queue cannot promise
\* unconditional delivery; what the protocol promises is deliver-or-
\* demonstrably-kill — never a silent drop (the liveness face of
\* INV_NoSilentGap / INV_KillOnOverflow).
PROP_PendingDeliveredOrKilled ==
    \A e \in 1..MAX_BLOCKS :
        PendingEid(e) ~> (DeliveredEid(e) \/ killed)

\* PROP_StuckWriteBroken — the stuck-writer case: once the kill fires with
\* the writer STUCK in a blocking write, the socket close breaks the write
\* and the writer exits — it does not stay STUCK forever. (The kill sets
\* socketClosed atomically whenever the writer is in-write, so WriteBroken
\* is continuously enabled from that point; WF discharges it.)
PROP_StuckWriteBroken ==
    (killed /\ writerState = "STUCK") ~> (socketClosed /\ writerState = "DEAD")

\* -----------------------------------------------------------------
\* §11. Reachability probes (NOT in the shipped .cfg — EXPECTED
\* FALSIFIED when checked; see the header probe table, M0a/M0b).
\* -----------------------------------------------------------------

\* M0a: falsification exhibits a trace reaching killed + STUCK — the
\* stuck-writer kill path is live, PROP_StuckWriteBroken is not vacuous.
Probe_KilledStuckUnreachable == ~(killed /\ writerState = "STUCK")

\* M0b: falsification exhibits a delivered error frame — the best-effort
\* final error frame can actually go out (kill with the writer PARKED and
\* the socket still open), INV_KilledFailClosed's terminal arm is live.
Probe_ErrorFrameUnreachable ==
    \A i \in 1..Len(delivered) : delivered[i].kind /= "error"

=============================================================================
\* Cross-references.
\*
\* docs/V2-DESIGN.md "v2.20 — Streaming subscription RPC" (~:1158-1342) —
\*   the wire contract this module pins: frame schemas + seq/sid contract,
\*   Subscriber struct + subscribers_ map sketch, enqueue_subscriber_event
\*   bounded-enqueue + backpressure-kill semantics, kill_subscriber's
\*   best-effort final error frame, the kill-vs-drop rationale paragraph
\*   ("Backpressure semantics", tier 2), constants table
\*   (SUBSCRIBER_QUEUE_MAX=1024, SUBSCRIBER_BYTES_MAX=16MiB,
\*   SUBSCRIBER_MAX_PER_NODE=256, SUBSCRIBE_BACKLOG_MAX_BLOCKS=10000,
\*   HEARTBEAT_INTERVAL_BLOCKS=50, HEARTBEAT_INTERVAL_SECS=30).
\*
\* C++ (PENDING at authoring): src/node/node.cpp rpc_dapp_subscribe /
\*   on_block_finalized_for_subscribers / enqueue_subscriber_event /
\*   subscriber_write_worker / kill_subscriber per the design touch list;
\*   thread the line anchors into this header when v2.20 ships, and stand
\*   up tools/test_dapp_subscribe.sh as the runtime regression twin
\*   (subscribe, heartbeat, deliver, backpressure-kill, reconnect-via-
\*   since — the five scenarios named in the design entry).
\*
\* Out-of-scope gates this module sits BEHIND (own specs/controls):
\*   RpcHmacAuth.tla (S-001 request auth), RpcAdmissionOrdering.tla +
\*   S-014 RateLimiter (admission before the socket handoff),
\*   BoundedMempoolAdmission.tla / WireFrameCap.tla — the house bounded-
\*   resource siblings this spec's INV_BoundedQueue follows in style.
\*
\* Sibling liveness/teardown specs: TcpKeepaliveReap.tla (reaping a dead
\*   peer), NefPoolDrain.tla (bounded-pool drain) — same
\*   kill-then-eventually-collect shape as PROP_KilledEventuallyDead.
=============================================================================
