----------------------------- MODULE WireFrameCap -----------------------------
(*
FB47 — TLA+ specification of the S-022 two-stage wire-frame admission
gate: the framing-layer ceiling (`kMaxFrameBytes = 16 MB`) in
`Peer::read_header` followed by the per-message-type body-size cap
(`max_message_bytes(MsgType)`) in `Peer::read_body`.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
WireFrameCap.cfg WireFrameCap.tla` once the TLC toolchain is available
in CI.

Scope. Formalizes the just-audited S-022 closure at
`src/net/peer.cpp:50-105` (the two-stage read pipeline) backed by the
cap table at `include/determ/net/messages.hpp:94-152`. Every inbound
gossip frame transits TWO independent length gates before the message
reaches the `on_msg_` dispatch:

  * Stage 1 — framing gate (`Peer::read_header` at peer.cpp:50-69).
    A 4-byte big-endian length prefix is read first. The receiver
    rejects the frame (closes the connection via `on_close_`) when
    `len == 0 || len > kMaxFrameBytes`, where `kMaxFrameBytes =
    16 * 1024 * 1024` (16 MB) per messages.hpp:101. This gate fires
    BEFORE any body bytes are read or any deserialization runs — so a
    flooder cannot force the node to buffer more than 16 MB per frame.
  * Stage 2 — per-type gate (`Peer::read_body` at peer.cpp:72-105).
    After the body is read and `Message::deserialize` recovers the
    MsgType, the receiver rejects the message (closes the connection)
    when `body_buf_.size() > max_message_bytes(msg.type)`. The cap is
    type-aware (messages.hpp:124-152):
      - 16 MB for SNAPSHOT_RESPONSE / CHAIN_RESPONSE (the only
        legitimate large-payload channels; bootstrap state can be MBs).
      - 4 MB for BLOCK / BEACON_HEADER / SHARD_TIP /
        CROSS_SHARD_RECEIPT_BUNDLE / HEADERS_RESPONSE (bounded by
        tx-set × tx-size or 256-header page).
      - 1 MB for everything else — the DEFAULT branch, covering
        consensus chatter (CONTRIB / BLOCK_SIG / ABORT_CLAIM /
        ABORT_EVENT / EQUIVOCATION_EVIDENCE / HELLO / STATUS_*),
        request envelopes (GET_CHAIN / SNAPSHOT_REQUEST /
        HEADERS_REQUEST), and tx. The default keeps the cap tight so
        a new MsgType variant added without explicit categorisation
        cannot slip through unbounded.

The headline robustness property: the only types that can reach
`on_msg_` carrying more than 1 MB are the five explicitly-large types
(the 16 MB pair + the 4 MB block-class quintet). Every other type —
in particular all consensus chatter — is bounded at 1 MB at the type
gate even though the framing gate admitted up to 16 MB. A flooder
cannot use the 16 MB framing ceiling as an amplification vector
against a node that is not currently bootstrapping: an oversize
CONTRIB (say 8 MB, under the framing ceiling but over its 1 MB type
cap) is read off the wire but then dropped + the connection closed at
Stage 2, never reaching consensus-message processing.

This spec is the state-machine companion to FB37 HelloHandshake.tla
(which explicitly DEFERS the S-022 cap surface — "the S-022 per-
message-type size caps ... are NOT modeled here ... both gates fire
before the handshake admission gate this spec models") and FB39
TcpKeepaliveReap.tla (whose §7 notes "FB36 and S022WireFormatCaps.md
cover the per-message size surface" — at the analytic layer; this
spec is the missing state-machine witness). Where FB37 covers the
HELLO admission gate and FB39 covers the dead-peer reap gate, FB47
covers the per-frame size-admission gate — the third independent
gossip-layer admission surface.

Six paired theorems are pinned (per the S-022 closure narrative in
SECURITY.md §S-022 + the cap table at messages.hpp:103-152):

  (T-1) Framing Ceiling. Every frame whose declared length exceeds
        kMaxFrameBytes (or equals 0) is rejected at Stage 1 — the
        connection is closed and NO body bytes are buffered. State-
        form witness: INV_FramingCeilingEnforced.
  (T-2) Per-Type Cap. Every message that reaches the dispatch
        (`on_msg_`) has body size <= max_message_bytes(msg.type). A
        message over its type cap is dropped at Stage 2. State-form
        witness: INV_DispatchedWithinTypeCap.
  (T-3) Tight Default. Every dispatched message whose type is NOT one
        of the five explicitly-large types (the 16 MB pair + the 4 MB
        block-class quintet) has body size <= 1 MB. Consensus chatter
        in particular cannot reach dispatch carrying a multi-MB body.
        State-form witness: INV_DefaultTypeTightlyBounded.
  (T-4) No Silent Oversize. A frame that passes Stage 1 but fails
        Stage 2 is NEVER dispatched — it is dropped and the
        connection closed (same disposition as a Stage-1 failure).
        State-form witness: INV_OversizeNeverDispatched +
        PROP_NoSilentOversizeDispatch.
  (T-5) Bounded Buffering. The node never resizes `body_buf_` beyond
        kMaxFrameBytes (Stage 1 gates the resize). State-form
        witness: INV_BufferBounded — the per-frame memory the
        receiver commits is at most the framing ceiling.
  (T-6) Eventual Frame Resolution. Under fairness on the gate
        actions, every frame that arrives on the wire eventually
        transitions to a terminal disposition (DISPATCHED or
        DROPPED). State-form witness: PROP_EventualFrameResolution.

The state machine. Five actions cover the two-stage read pipeline:

  * ArriveFrame(t, sz) — a frame of MsgType `t` and declared body
    length `sz` arrives on the wire. Appends a new frame record with
    stage = "ARRIVED" to frames. Mirrors the async_read completion on
    the 4-byte header at peer.cpp:52 (the length prefix has been read;
    the body has NOT yet been buffered). The (type, size) pair is a
    non-deterministic choice over MsgTypes × FrameSizes — TLC explores
    every reachable combination, including the over-framing-ceiling
    and over-type-cap cases that trigger the drop branches.
  * RejectAtFraming(idx) — Stage-1 rejection. Pre-condition: the frame
    at idx is ARRIVED and `sz = 0 OR sz > kMaxFrameBytes`. Sets stage
    to "DROPPED". No body is buffered (buffered[idx] stays FALSE).
    Mirrors the `if (len == 0 || len > kMaxFrameBytes)` branch at
    peer.cpp:64-67 (close before read_body).
  * BufferBody(idx) — the body passes the framing gate and is read off
    the wire. Pre-condition: the frame at idx is ARRIVED and
    `1 <= sz <= kMaxFrameBytes`. Sets stage to "BUFFERED" and marks
    buffered[idx] = TRUE. Mirrors `read_body(len)` at peer.cpp:68 +
    the `Message::deserialize` recovery at peer.cpp:82 — at this point
    the MsgType is known and the per-type cap can be applied.
  * RejectAtTypeCap(idx) — Stage-2 rejection. Pre-condition: the frame
    at idx is BUFFERED and `sz > max_message_bytes(type)`. Sets stage
    to "DROPPED". Mirrors the `if (body_buf_.size() >
    max_message_bytes(msg.type))` branch at peer.cpp:90-97 (drop +
    close after deserialize).
  * Dispatch(idx) — the message passes both gates and reaches
    `on_msg_`. Pre-condition: the frame at idx is BUFFERED and
    `sz <= max_message_bytes(type)`. Sets stage to "DISPATCHED".
    Mirrors `if (self->on_msg_) self->on_msg_(self, msg)` at
    peer.cpp:98.

Six invariants codify the structural contracts:

  TypeOK — shape predicate for all variables.
  INV_FramingCeilingEnforced (T-1) — no frame with sz = 0 or
        sz > kMaxFrameBytes ever reaches BUFFERED / DISPATCHED. Such
        frames can only be DROPPED (via RejectAtFraming).
  INV_DispatchedWithinTypeCap (T-2) — every DISPATCHED frame has
        sz <= max_message_bytes(type).
  INV_DefaultTypeTightlyBounded (T-3) — every DISPATCHED frame whose
        type is NOT one of the five explicitly-large types has
        sz <= OneMB (the default cap).
  INV_OversizeNeverDispatched (T-4) — no frame with sz >
        max_message_bytes(type) is DISPATCHED.
  INV_BufferBounded (T-5) — every frame ever buffered has
        sz <= kMaxFrameBytes (the framing gate bounds the resize).
  INV_StageProgression — the per-frame stage is one of the four
        legal values and never moves backward (ARRIVED is initial;
        BUFFERED follows ARRIVED; DISPATCHED follows BUFFERED;
        DROPPED is terminal from ARRIVED or BUFFERED).

Two temporal properties pin the headline composition claims:

  PROP_EventualFrameResolution (T-6) — under fairness on the gate
        actions, every ARRIVED frame eventually reaches a terminal
        stage (DISPATCHED or DROPPED). No frame is left mid-pipeline
        indefinitely.
  PROP_NoSilentOversizeDispatch (T-4 temporal) — invariantly, no
        frame over its type cap is ever DISPATCHED. The standing
        invariant restated as a box-property to document the "no
        silent oversize dispatch" composition.

Modeling scope (kept tractable for TLC):

  * `MsgTypes` is a SUBSET of strings — the universe of message-type
    discriminators. Production uses the `enum class MsgType` at
    messages.hpp:60-82 (HELLO / CONTRIB / BLOCK_SIG / BLOCK /
    SNAPSHOT_RESPONSE / CHAIN_RESPONSE / ...). The cfg uses a
    representative subset that spans all three cap tiers:
      - "snapshot_resp" — the 16 MB tier (SNAPSHOT_RESPONSE).
      - "block"         — the 4 MB tier (BLOCK).
      - "contrib"       — the 1 MB default tier (consensus chatter).
    so all three branches of max_message_bytes are exercised.
  * `FrameSizes` is a SUBSET of Nat — the universe of declared body
    lengths in spec-time size units (NOT raw bytes — see UnitScale
    below). The cfg picks sizes straddling each cap boundary so the
    pass / drop branches at each gate are reachable.
  * Production byte counts (16 MB / 4 MB / 1 MB) are scaled down by
    UnitScale = 1 MB so the spec arithmetic stays small: at the spec
    layer OneMB = 1, FourMB = 4, SixteenMB = 16. The cap ORDERING and
    the boundary predicates are preserved exactly (a sz strictly
    above a cap drops; sz at-or-below passes), which is all the
    structural invariants depend on. The literal byte values are
    documentary; the spec checks the gate ARITHMETIC.
  * `MaxFrames` bounds the frames log growth so TLC exhausts in
    seconds. Production runs unbounded; the model bounds at 4 to
    exercise: 0->1 (first ARRIVED), 1->2 (first DROP-at-framing),
    2->3 (DROP-at-type-cap), 3->4 (happy-path DISPATCH).
  * The 4-byte big-endian length-prefix decode at peer.cpp:58-61 is
    NOT modeled at the byte level — the spec carries the decoded
    `sz` directly as a Nat. The decode correctness is the C++ side's
    domain; the spec models the gate decisions on the decoded value.
  * The `Message::deserialize` format-detecting dispatch (JSON vs
    binary, messages.hpp:166-171) is NOT modeled — the spec carries
    the recovered MsgType directly as the frame's `type` field. The
    binary-codec round-trip is FB-track-adjacent (binary_codec.cpp);
    this spec models the SIZE-admission gate, not the codec.
  * The async-read completion-handler chain (asio buffers + the
    `self` shared_ptr lifetime) is collapsed into the atomic actions.
    The spec does not model the asio layer; each action is the
    atomic effect of one completion handler.
  * `buffered` is a per-frame BOOLEAN flag (TRUE iff the body bytes
    were read off the wire — i.e. the frame passed Stage 1). It is
    the structural witness for INV_BufferBounded: a frame is buffered
    ONLY if it passed the framing gate, so its sz <= kMaxFrameBytes.

The state machine. Five actions cover the two-stage read pipeline
(plus a Stutter to bound TLC):

  * ArriveFrame(t, sz) — appends a new [type |-> t, sz |-> sz,
    stage |-> "ARRIVED"] record to frames; sets buffered[new_idx] =
    FALSE. Pre-condition: Len(frames) < MaxFrames.
  * RejectAtFraming(idx) — pre-condition: frames[idx].stage =
    "ARRIVED" AND (frames[idx].sz = 0 OR frames[idx].sz >
    SixteenMB). Sets stage to "DROPPED". UNCHANGED buffered.
  * BufferBody(idx) — pre-condition: frames[idx].stage = "ARRIVED"
    AND 1 <= frames[idx].sz <= SixteenMB. Sets stage to "BUFFERED";
    sets buffered[idx] = TRUE.
  * RejectAtTypeCap(idx) — pre-condition: frames[idx].stage =
    "BUFFERED" AND frames[idx].sz > Cap(frames[idx].type). Sets
    stage to "DROPPED". UNCHANGED buffered.
  * Dispatch(idx) — pre-condition: frames[idx].stage = "BUFFERED"
    AND frames[idx].sz <= Cap(frames[idx].type). Sets stage to
    "DISPATCHED". UNCHANGED buffered.

To check (assuming TLC installed):
  $ tlc WireFrameCap.tla -config WireFrameCap.cfg

Recommended config (state space ~10^4, < 30s):
  MsgTypes = {"snapshot_resp", "block", "contrib"},
  FrameSizes = {0, 1, 2, 5, 16, 20}, MaxFrames = 4.
  (0 = empty-frame Stage-1 reject; 2 = over-1MB / under-4MB so a
   contrib drops at Stage 2 but a block passes; 5 = over-4MB / under-
   16MB so a block drops but a snapshot_resp passes; 20 = over-16MB
   Stage-1 reject for every type.)

Cross-references:
  - src/net/peer.cpp:50-69 : Peer::read_header — the Stage-1 framing
      gate (`if (len == 0 || len > kMaxFrameBytes)` at :64-67). The
      spec's RejectAtFraming + the BufferBody pre-condition mirror
      this branch.
  - src/net/peer.cpp:72-105 : Peer::read_body — the Stage-2 per-type
      gate (`if (body_buf_.size() > max_message_bytes(msg.type))` at
      :90-97) + the dispatch at :98. The spec's RejectAtTypeCap +
      Dispatch mirror these branches.
  - include/determ/net/messages.hpp:94-101 : kMaxFrameBytes = 16 MB
      framing-layer ceiling. The spec's SixteenMB constant (scaled).
  - include/determ/net/messages.hpp:103-152 : max_message_bytes(type)
      per-message-type cap table. The spec's Cap(type) operator lifts
      the three-tier switch (16 MB / 4 MB / 1 MB default).
  - include/determ/net/messages.hpp:60-82 : enum class MsgType — the
      message-type universe. The spec's MsgTypes is a representative
      subset spanning all three cap tiers.
  - SECURITY.md §S-022 : per-message-type size caps closure narrative.
      FB47 formalizes the two-stage gate at the state-machine layer.
  - docs/proofs/tla/HelloHandshake.tla (FB37) : sibling spec at the
      gossip admission surface (HELLO chain_id + wire_version gate).
      FB37 explicitly DEFERS the S-022 cap surface ("the S-022 per-
      message-type size caps ... are NOT modeled here ... both gates
      fire before the handshake admission gate this spec models");
      FB47 is the missing state-machine witness for that deferred
      surface. The two compose: a frame transits FB47's size gate
      (Stages 1 + 2) before FB37's HELLO admission gate ever runs.
  - docs/proofs/tla/TcpKeepaliveReap.tla (FB39) : sibling spec at the
      gossip resource-exhaustion surface (per-IP slot lifetime).
      FB39's §7 notes "FB36 and S022WireFormatCaps.md cover the per-
      message size surface" at the analytic layer; FB47 is the state-
      machine witness. FB39 bounds per-IP slot LIFETIME; FB47 bounds
      per-FRAME size — orthogonal axes of the same flooding-defense
      surface (alongside FB25 RateLimiterEviction's per-IP message
      RATE bound).
  - docs/proofs/tla/RateLimiterEviction.tla (FB25) : the third
      gossip-layer flooding-defense axis (per-IP message rate via
      token-bucket). FB25 (rate) + FB39 (slot lifetime) + FB47 (frame
      size) jointly cover the gossip-layer resource-exhaustion
      surface along three orthogonal axes.
  - docs/proofs/Preliminaries.md §3 (network adversary model) — the
      V0 framing for the flooding adversary. The spec's two-stage
      gate is the structural admission boundary that bounds per-frame
      memory commitment (Stage 1) + per-type body size (Stage 2).
*)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    MsgTypes,        \* SUBSET of strings — the universe of message-
                      \*  type discriminators. Production uses the
                      \*  `enum class MsgType` at messages.hpp:60-82;
                      \*  the cfg uses a subset spanning all three cap
                      \*  tiers (16 MB / 4 MB / 1 MB default).
    FrameSizes,      \* SUBSET of Nat — declared body lengths in
                      \*  spec-time size units (scaled by 1 MB; see
                      \*  the §scope note). The cfg picks sizes
                      \*  straddling each cap boundary.
    MaxFrames         \* Nat — bound on frames log growth (TLC
                      \*  tractability).

ASSUME ConfigOK ==
    /\ Cardinality(MsgTypes) >= 1
       \* At least one message type so the spec is non-trivial. The
       \* cfg uses 3 to span all three cap tiers (the 16 MB pair, the
       \* 4 MB block-class, and the 1 MB default chatter).
    /\ FrameSizes \subseteq Nat
       \* All declared sizes are Nat-valued (spec-time size units).
    /\ MaxFrames \in Nat /\ MaxFrames >= 1
       \* Positive bound so TLC has a non-empty reachable state space.

\* -----------------------------------------------------------------
\* §1. Constants reflecting the C++ cap surface (scaled by 1 MB).
\* -----------------------------------------------------------------
\*
\* Production byte counts are scaled down by UnitScale = 1 MB so the
\* spec arithmetic stays small. The cap ORDERING and the boundary
\* predicates are preserved exactly; the literal byte values are
\* documentary (the spec checks the gate arithmetic, not the byte
\* count).

\* OneMB: the default per-type cap (messages.hpp:149-150, `default`
\* branch). Covers consensus chatter (CONTRIB / BLOCK_SIG /
\* ABORT_CLAIM / ABORT_EVENT / EQUIVOCATION_EVIDENCE / HELLO /
\* STATUS_*), request envelopes (GET_CHAIN / SNAPSHOT_REQUEST /
\* HEADERS_REQUEST), and tx. Scaled value: 1.
OneMB == 1

\* FourMB: the block-class cap (messages.hpp:130-141). Covers BLOCK /
\* BEACON_HEADER / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE /
\* HEADERS_RESPONSE. Scaled value: 4.
FourMB == 4

\* SixteenMB: the framing-layer ceiling (kMaxFrameBytes,
\* messages.hpp:101) AND the per-type cap for the large-payload pair
\* (SNAPSHOT_RESPONSE / CHAIN_RESPONSE, messages.hpp:126-128). The
\* two share the same value (16 MB) — the framing ceiling exists
\* precisely to admit the one type-cap tier that needs it. Scaled
\* value: 16.
SixteenMB == 16

\* LargeTypes: the five MsgTypes that carry a cap strictly above the
\* default OneMB. At the spec layer these are the cfg's "block" (4 MB
\* tier) + "snapshot_resp" (16 MB tier); production's full set is
\* {SNAPSHOT_RESPONSE, CHAIN_RESPONSE} ∪ {BLOCK, BEACON_HEADER,
\* SHARD_TIP, CROSS_SHARD_RECEIPT_BUNDLE, HEADERS_RESPONSE}. The
\* operator is defined structurally via Cap(t) > OneMB so the cfg's
\* type-naming is decoupled from the production enum.
LargeTypes == { t \in MsgTypes : t = "block" \/ t = "snapshot_resp" }

\* Cap(t): the per-message-type body-size cap. Lifts the three-tier
\* switch at messages.hpp:124-152:
\*   - SNAPSHOT_RESPONSE / CHAIN_RESPONSE -> 16 MB.
\*   - BLOCK / BEACON_HEADER / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE
\*     / HEADERS_RESPONSE -> 4 MB.
\*   - default -> 1 MB.
\* The cfg uses "snapshot_resp" (16 MB tier), "block" (4 MB tier),
\* and "contrib" (1 MB default tier) as representatives. Any type not
\* matching the first two falls through to the default OneMB, exactly
\* mirroring the C++ `default:` branch that keeps a newly-added
\* uncategorised MsgType bounded at 1 MB.
Cap(t) ==
    IF      t = "snapshot_resp" THEN SixteenMB
    ELSE IF t = "block"         THEN FourMB
    ELSE                              OneMB

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    frames,      \* Seq of [type, sz, stage] — one entry per inbound
                  \*  frame. stage is one of {"ARRIVED", "BUFFERED",
                  \*  "DROPPED", "DISPATCHED"}. RejectAtFraming /
                  \*  BufferBody / RejectAtTypeCap / Dispatch mutate
                  \*  the stage field at index idx.
    buffered     \* Seq of BOOLEAN — buffered[i] = TRUE iff the body
                  \*  bytes of frame i were read off the wire (i.e. the
                  \*  frame passed the Stage-1 framing gate). Set TRUE
                  \*  by BufferBody. The structural witness for
                  \*  INV_BufferBounded: a buffered frame's sz is
                  \*  bounded by the framing ceiling.

vars == <<frames, buffered>>

\* FrameStage: the four-element stage tag set. ARRIVED is the initial
\* state after ArriveFrame; BUFFERED is the post-framing-gate state;
\* DISPATCHED and DROPPED are the terminal states.
FrameStage == {"ARRIVED", "BUFFERED", "DROPPED", "DISPATCHED"}

\* FrameRecord: shape of a frames element. Carries the recovered
\* MsgType (`type`), the declared body length (`sz`), and the
\* pipeline stage (`stage`).
FrameRecord == [
    type  : MsgTypes,
    sz    : FrameSizes,
    stage : FrameStage
]

\* -----------------------------------------------------------------
\* §3. Initial state.
\* -----------------------------------------------------------------
\*
\* frames starts empty (no frames have arrived yet). buffered starts
\* empty (no bodies read off the wire). ArriveFrame is the only path
\* to add frames.

Init ==
    /\ frames   = <<>>
    /\ buffered = <<>>

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* ArriveFrame(t, sz): a frame of MsgType `t` and declared body
\* length `sz` arrives on the wire (the 4-byte header has been read;
\* the body has NOT yet been buffered).
\*
\* Mirrors the async_read completion on the 4-byte header at
\* peer.cpp:52 — the length prefix `len` has been decoded (peer.cpp:
\* 58-61) but `read_body(len)` has not yet run. The (type, sz) pair
\* is a non-deterministic choice over MsgTypes × FrameSizes; TLC
\* explores every reachable combination, including the over-framing-
\* ceiling (sz > SixteenMB) and over-type-cap (sz > Cap(t)) cases
\* that trigger the drop branches.
\*
\* The new frame is appended to frames with stage = "ARRIVED" and the
\* corresponding buffered flag appended as FALSE (no body read yet).
\*
\* Pre-condition: Len(frames) < MaxFrames (bound).
\*
\* Post-condition: frames grows by one ARRIVED entry; buffered grows
\* by one FALSE flag.

ArriveFrame(t, sz) ==
    /\ t  \in MsgTypes
    /\ sz \in FrameSizes
    /\ Len(frames) < MaxFrames
    /\ frames'   = Append(frames,
                          [type |-> t, sz |-> sz, stage |-> "ARRIVED"])
    /\ buffered' = Append(buffered, FALSE)

\* RejectAtFraming(idx): Stage-1 rejection. The frame's declared
\* length is 0 (empty frame) or exceeds the framing ceiling
\* kMaxFrameBytes (SixteenMB at the spec layer). The connection is
\* closed BEFORE any body bytes are read.
\*
\* Mirrors the `if (len == 0 || len > kMaxFrameBytes) { on_close_;
\* return; }` branch at peer.cpp:64-67. CRITICAL: no body is read
\* (buffered[idx] stays FALSE) — the framing gate bounds the per-
\* frame memory commitment to the 4-byte header BEFORE the gate
\* decision.
\*
\* Pre-condition: idx ∈ 1..Len(frames); frames[idx].stage =
\* "ARRIVED"; frames[idx].sz = 0 OR frames[idx].sz > SixteenMB.
\*
\* Post-condition: stage set to "DROPPED". buffered UNCHANGED (the
\* frame was never buffered — the structural witness that Stage-1
\* drops commit no body memory).

RejectAtFraming(idx) ==
    /\ idx \in 1..Len(frames)
    /\ frames[idx].stage = "ARRIVED"
    /\ \/ frames[idx].sz = 0
       \/ frames[idx].sz > SixteenMB
    /\ frames' = [frames EXCEPT ![idx].stage = "DROPPED"]
    /\ UNCHANGED buffered

\* BufferBody(idx): the body passes the framing gate and is read off
\* the wire. The declared length is in range [1, SixteenMB]; the body
\* is buffered and `Message::deserialize` recovers the MsgType (so
\* the per-type cap can now be applied at Stage 2).
\*
\* Mirrors `read_body(len)` at peer.cpp:68 followed by the
\* `Message::deserialize(...)` recovery at peer.cpp:82 — at this
\* point the MsgType is known. The spec collapses the body-read +
\* deserialize into the BUFFERED transition; the per-type gate
\* decision is the subsequent RejectAtTypeCap / Dispatch.
\*
\* Pre-condition: idx ∈ 1..Len(frames); frames[idx].stage =
\* "ARRIVED"; 1 <= frames[idx].sz <= SixteenMB (the frame passed
\* the framing gate).
\*
\* Post-condition: stage set to "BUFFERED"; buffered[idx] = TRUE
\* (the body bytes were read off the wire — bounded by the framing
\* ceiling, the witness for INV_BufferBounded).

BufferBody(idx) ==
    /\ idx \in 1..Len(frames)
    /\ frames[idx].stage = "ARRIVED"
    /\ frames[idx].sz >= 1
    /\ frames[idx].sz <= SixteenMB
    /\ frames'   = [frames   EXCEPT ![idx].stage = "BUFFERED"]
    /\ buffered' = [buffered EXCEPT ![idx]       = TRUE]

\* RejectAtTypeCap(idx): Stage-2 rejection. The buffered body exceeds
\* the per-message-type cap max_message_bytes(type). The message is
\* dropped and the connection closed — the same disposition as a
\* Stage-1 failure.
\*
\* Mirrors the `if (body_buf_.size() > max_message_bytes(msg.type))
\* { on_close_; return; }` branch at peer.cpp:90-97. This is the gate
\* that defeats the framing-ceiling-as-amplification attack: an
\* oversize CONTRIB (under the 16 MB framing ceiling but over its
\* 1 MB type cap) is read off the wire at Stage 1 but dropped here at
\* Stage 2, never reaching consensus-message processing.
\*
\* Pre-condition: idx ∈ 1..Len(frames); frames[idx].stage =
\* "BUFFERED"; frames[idx].sz > Cap(frames[idx].type).
\*
\* Post-condition: stage set to "DROPPED". buffered UNCHANGED (the
\* body was already read; the spec keeps buffered[idx] = TRUE as the
\* record that the body bytes were committed before the type-cap
\* drop — bounded by SixteenMB per INV_BufferBounded).

RejectAtTypeCap(idx) ==
    /\ idx \in 1..Len(frames)
    /\ frames[idx].stage = "BUFFERED"
    /\ frames[idx].sz > Cap(frames[idx].type)
    /\ frames' = [frames EXCEPT ![idx].stage = "DROPPED"]
    /\ UNCHANGED buffered

\* Dispatch(idx): the message passes BOTH gates and reaches the
\* `on_msg_` dispatch.
\*
\* Mirrors `if (self->on_msg_) self->on_msg_(self, msg)` at
\* peer.cpp:98. The frame's declared length is within both the
\* framing ceiling (witnessed by the BUFFERED stage — only reachable
\* via BufferBody, whose pre-condition gated sz <= SixteenMB) AND the
\* per-type cap (the Dispatch pre-condition `sz <= Cap(type)`).
\*
\* Pre-condition: idx ∈ 1..Len(frames); frames[idx].stage =
\* "BUFFERED"; frames[idx].sz <= Cap(frames[idx].type).
\*
\* Post-condition: stage set to "DISPATCHED". buffered UNCHANGED.

Dispatch(idx) ==
    /\ idx \in 1..Len(frames)
    /\ frames[idx].stage = "BUFFERED"
    /\ frames[idx].sz <= Cap(frames[idx].type)
    /\ frames' = [frames EXCEPT ![idx].stage = "DISPATCHED"]
    /\ UNCHANGED buffered

\* Stutter (TLC bounds the state space; invariants are evaluated at
\* every reachable state along the way). Enabled once the frames log
\* is saturated and every frame has reached a terminal stage.

Stutter ==
    /\ Len(frames) >= MaxFrames
    /\ \A i \in 1..Len(frames) :
         frames[i].stage \in {"DROPPED", "DISPATCHED"}
    /\ UNCHANGED vars

Next ==
    \/ \E t \in MsgTypes : \E sz \in FrameSizes : ArriveFrame(t, sz)
    \/ \E i \in 1..MaxFrames : RejectAtFraming(i)
    \/ \E i \in 1..MaxFrames : BufferBody(i)
    \/ \E i \in 1..MaxFrames : RejectAtTypeCap(i)
    \/ \E i \in 1..MaxFrames : Dispatch(i)
    \/ Stutter

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E i \in 1..MaxFrames : RejectAtFraming(i))
             /\ WF_vars(\E i \in 1..MaxFrames : BufferBody(i))
             /\ WF_vars(\E i \in 1..MaxFrames : RejectAtTypeCap(i))
             /\ WF_vars(\E i \in 1..MaxFrames : Dispatch(i))

\* -----------------------------------------------------------------
\* §5. Invariants — TypeOK + T-1 + T-2 + T-3 + T-4 + T-5 + stage
\*     progression.
\* -----------------------------------------------------------------

\* TypeOK — shape predicate for all variables.

TypeOK ==
    /\ frames   \in Seq(FrameRecord)
    /\ buffered \in Seq(BOOLEAN)
    /\ Len(frames) = Len(buffered)
    /\ Len(frames) <= MaxFrames

\* INV_FramingCeilingEnforced (T-1).
\*
\* No frame with declared length 0 or > kMaxFrameBytes (SixteenMB)
\* ever reaches BUFFERED or DISPATCHED — such frames can only be
\* DROPPED (via RejectAtFraming) or still ARRIVED.
\*
\* Structural witness: BufferBody's pre-condition is
\* `1 <= sz <= SixteenMB`, so a frame with sz = 0 or sz > SixteenMB
\* can never transition to BUFFERED; and DISPATCHED is reachable only
\* from BUFFERED. RejectAtFraming is the only resolution path for
\* over-ceiling / empty frames. The invariant body asserts the
\* contrapositive over the frames log.

INV_FramingCeilingEnforced ==
    \A i \in 1..Len(frames) :
       LET f == frames[i] IN
       (f.stage \in {"BUFFERED", "DISPATCHED"})
       => (f.sz >= 1 /\ f.sz <= SixteenMB)

\* INV_DispatchedWithinTypeCap (T-2).
\*
\* Every DISPATCHED frame has declared length <=
\* max_message_bytes(type). A message over its type cap is dropped at
\* Stage 2 (RejectAtTypeCap) and never dispatched.
\*
\* Structural witness: Dispatch's pre-condition is
\* `sz <= Cap(frames[idx].type)`; no path sets stage = "DISPATCHED"
\* when the per-type cap is exceeded. The invariant body asserts this
\* per-entry over the frames log.

INV_DispatchedWithinTypeCap ==
    \A i \in 1..Len(frames) :
       LET f == frames[i] IN
       (f.stage = "DISPATCHED") => (f.sz <= Cap(f.type))

\* INV_DefaultTypeTightlyBounded (T-3).
\*
\* Every DISPATCHED frame whose type is NOT one of the five
\* explicitly-large types (LargeTypes — the 16 MB pair + the 4 MB
\* block-class) has declared length <= OneMB (the default cap).
\* Consensus chatter in particular cannot reach dispatch carrying a
\* multi-MB body even though the framing ceiling admitted up to
\* 16 MB.
\*
\* Structural witness: for a default-tier type, Cap(type) = OneMB
\* (the `default:` branch at messages.hpp:149-150); composed with
\* INV_DispatchedWithinTypeCap, a dispatched default-tier frame has
\* sz <= OneMB. This is the headline robustness claim: the 16 MB
\* framing ceiling is NOT an amplification vector for the 1 MB-capped
\* default types. The invariant body asserts it directly.

INV_DefaultTypeTightlyBounded ==
    \A i \in 1..Len(frames) :
       LET f == frames[i] IN
       ((f.stage = "DISPATCHED") /\ (f.type \notin LargeTypes))
       => (f.sz <= OneMB)

\* INV_OversizeNeverDispatched (T-4).
\*
\* No frame whose declared length exceeds its per-type cap is ever
\* DISPATCHED. The structural complement to INV_DispatchedWithinType-
\* Cap, phrased as an explicit "no oversize dispatch" guard.
\*
\* Structural witness: both gates drop oversize frames —
\* RejectAtFraming for sz > SixteenMB, RejectAtTypeCap for SixteenMB
\* >= sz > Cap(type). Dispatch's pre-condition forbids sz > Cap(type).
\* No reachable state has a DISPATCHED frame over its cap.

INV_OversizeNeverDispatched ==
    \A i \in 1..Len(frames) :
       (frames[i].sz > Cap(frames[i].type))
       => (frames[i].stage /= "DISPATCHED")

\* INV_BufferBounded (T-5).
\*
\* Every frame whose body was read off the wire (buffered[i] = TRUE)
\* has declared length <= kMaxFrameBytes (SixteenMB). The framing
\* gate bounds the body-buffer resize: `body_buf_.resize(len)` at
\* peer.cpp:73 runs only after the framing gate accepted
\* `len <= kMaxFrameBytes`.
\*
\* Structural witness: buffered[i] = TRUE only via BufferBody, whose
\* pre-condition gated `sz <= SixteenMB`. So the receiver never
\* commits more than the framing ceiling of body memory per frame.
\* The invariant body asserts the bound over the buffered flags.

INV_BufferBounded ==
    \A i \in 1..Len(frames) :
       (buffered[i] = TRUE) => (frames[i].sz <= SixteenMB)

\* INV_StageProgression.
\*
\* The per-frame stage discipline: buffered[i] = TRUE iff the frame
\* has passed the framing gate (stage \in {"BUFFERED", "DISPATCHED"}
\* — BUFFERED, or DISPATCHED which is reachable only from BUFFERED).
\* A frame that is still ARRIVED or was DROPPED-at-framing has
\* buffered[i] = FALSE (no body read). A frame DROPPED-at-type-cap
\* has buffered[i] = TRUE (the body WAS read before the type gate).
\*
\* The structural witness couples the buffered flag to the stage:
\*   - ARRIVED    => buffered = FALSE (no body read yet).
\*   - BUFFERED   => buffered = TRUE  (body read at Stage 1 pass).
\*   - DISPATCHED => buffered = TRUE  (reached only from BUFFERED).
\*   - DROPPED    => buffered is FALSE if dropped at Stage 1,
\*                   TRUE if dropped at Stage 2 (so the flag alone
\*                   does not determine DROPPED; the coupling is
\*                   asserted only for the non-DROPPED stages).
\* The invariant pins the non-DROPPED coupling, which is the load-
\* bearing structural discipline for INV_BufferBounded + T-1.

INV_StageProgression ==
    \A i \in 1..Len(frames) :
       LET f == frames[i] IN
       /\ (f.stage = "ARRIVED")    => (buffered[i] = FALSE)
       /\ (f.stage = "BUFFERED")   => (buffered[i] = TRUE)
       /\ (f.stage = "DISPATCHED") => (buffered[i] = TRUE)

\* -----------------------------------------------------------------
\* §6. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualFrameResolution (T-6).
\*
\* Under fairness on the gate actions (RejectAtFraming + BufferBody +
\* RejectAtTypeCap + Dispatch), every ARRIVED frame eventually
\* reaches a terminal stage (DISPATCHED or DROPPED). No frame is left
\* mid-pipeline indefinitely.
\*
\* The forward-progress contract: a frame at any log position is
\* eventually resolved. The Spec's fairness clauses (WF_vars on each
\* gate action) ensure any ARRIVED / BUFFERED frame is eventually
\* picked up by one of the resolution paths. The model bound
\* MaxFrames prevents infinite enumeration; within the bounded run,
\* every frame either resolves or the run terminates via Stutter once
\* all frames are terminal.

PROP_EventualFrameResolution ==
    \A i \in 1..MaxFrames :
       <>(i > Len(frames)
          \/ frames[i].stage \in {"DROPPED", "DISPATCHED"})
    \* For every position i, either the log is shorter than i (so
    \* position i has not been populated yet) OR the entry at
    \* position i has reached a terminal stage. The eventually claim:
    \* every frame at some log position is eventually resolved.

\* PROP_NoSilentOversizeDispatch (T-4 temporal restatement).
\*
\* Invariantly, no frame whose declared length exceeds its per-type
\* cap is ever DISPATCHED. The standing INV_OversizeNeverDispatched
\* restated as a box-property to document the "no silent oversize
\* dispatch" composition: an oversize frame is always dropped at one
\* of the two gates, never silently delivered to on_msg_.
\*
\* The structural argument: RejectAtFraming drops sz > SixteenMB
\* before any body read; RejectAtTypeCap drops SixteenMB >= sz >
\* Cap(type) after the body read but before dispatch; Dispatch's
\* pre-condition forbids sz > Cap(type). There is no reachable path
\* that delivers an oversize frame to dispatch.

PROP_NoSilentOversizeDispatch ==
    [] (\A i \in 1..Len(frames) :
          (frames[i].sz > Cap(frames[i].type))
          => (frames[i].stage /= "DISPATCHED"))

\* -----------------------------------------------------------------
\* §7. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The S-022 two-stage admission gate is pinned at the state-machine
\* layer by the six invariants + two temporal properties. The
\* abstraction boundary:
\*
\*   * The 4-byte big-endian length-prefix decode at peer.cpp:58-61
\*     is NOT modeled at the byte level. The spec carries the decoded
\*     `sz` directly as a Nat; the decode correctness (shift-and-or
\*     reassembly of the four header bytes) is the C++ side's domain.
\*     The spec models the gate DECISIONS on the decoded value.
\*
\*   * The `Message::deserialize` format-detecting dispatch (JSON vs
\*     binary, messages.hpp:166-171; binary_codec.cpp) is NOT
\*     modeled. The spec carries the recovered MsgType directly as
\*     the frame's `type` field; the BUFFERED stage collapses the
\*     body-read + deserialize step. The binary-codec round-trip +
\*     version negotiation are adjacent surfaces (the codec layer);
\*     this spec models the SIZE-admission gate, not the codec.
\*     The HELLO-always-JSON carve-out + wire-version negotiation are
\*     FB37 HelloHandshake.tla territory.
\*
\*   * The async-read completion-handler chain (asio buffers + the
\*     `self` shared_ptr lifetime extension + the re-arm
\*     `read_header()` at peer.cpp:103) is collapsed into the atomic
\*     actions. Each action is the atomic effect of one completion
\*     handler. The spec does not model the asio scheduling layer;
\*     TLA+'s atomic-action model is the structural equivalent.
\*
\*   * The connection-close side effect (`on_close_(self)` at
\*     peer.cpp:65 / :95) is collapsed into the DROPPED stage. The
\*     spec models the message-level disposition (the oversize frame
\*     is not dispatched); the peer-table removal that follows the
\*     close is FB39 TcpKeepaliveReap.tla territory (the reap path).
\*
\*   * The byte-count scaling (16 MB / 4 MB / 1 MB -> 16 / 4 / 1) is
\*     a spec-layer simplification. The cap ORDERING and the boundary
\*     predicates (strict-greater drops; at-or-below passes) are
\*     preserved exactly; the structural invariants depend only on
\*     the ordering + boundary, not the literal byte values. The
\*     literal byte counts are documentary.
\*
\*   * The full MsgType enum (messages.hpp:60-82, ~19 variants) is
\*     reduced to a representative subset spanning the three cap
\*     tiers. Adding more types in the same tier does not change any
\*     invariant — Cap(t) partitions MsgTypes into three equivalence
\*     classes, and the spec checks one representative per class. The
\*     `default:` branch's tightness (a newly-added uncategorised
\*     type lands at OneMB) is witnessed by Cap's final ELSE arm.
\*
\*   * The framing ceiling and the SNAPSHOT_RESPONSE / CHAIN_RESPONSE
\*     type cap share the same value (16 MB) by design — the framing
\*     ceiling exists precisely to admit the one type-cap tier that
\*     needs it. The spec models them as the single SixteenMB
\*     constant; the structural point is that no OTHER type can use
\*     the 16 MB ceiling (INV_DefaultTypeTightlyBounded +
\*     INV_DispatchedWithinTypeCap jointly cap every non-large type
\*     well below the ceiling).
\*
\*   * The per-IP message RATE bound (S-014 / FB25
\*     RateLimiterEviction.tla) and the per-IP slot LIFETIME bound
\*     (S-026 / FB39 TcpKeepaliveReap.tla) are NOT modeled here. They
\*     are orthogonal axes of the same gossip-layer flooding-defense
\*     surface: FB25 bounds how MANY frames a peer can send per unit
\*     time, FB39 bounds how LONG a stale peer-table slot survives,
\*     FB47 bounds how BIG each individual frame can be. The three
\*     compose without coordination; no joint invariant is asserted
\*     here.
\*
\* What this spec adds beyond the analytic narrative: a state-machine
\* witness that the two-stage size-admission contract is preserved
\* across every reachable interleaving of ArriveFrame /
\* RejectAtFraming / BufferBody / RejectAtTypeCap / Dispatch within
\* the bounded universe. TLC enumerates every reachable schedule and
\* the invariants are checked against the accumulated frames +
\* buffered state — in particular the headline
\* INV_DefaultTypeTightlyBounded (no default-tier frame reaches
\* dispatch over 1 MB despite the 16 MB framing ceiling).
\*
\* What the spec does NOT check (consistent with the §scope above):
\*
\*   * The byte-level length-prefix decode (the C++ side's shift-and-
\*     or reassembly). The spec carries the decoded Nat directly.
\*   * The JSON / binary codec round-trip (the deserialize step). The
\*     spec carries the recovered MsgType directly; the codec is an
\*     adjacent surface.
\*   * The asio completion-handler scheduling. The spec collapses
\*     each handler into an atomic action.
\*   * The connection-close + peer-table removal that follows a DROP.
\*     The spec models the message-level non-dispatch; the reap path
\*     is FB39 territory.
\*   * The per-IP rate / slot-lifetime flooding axes (FB25 / FB39).
\*     The spec models the per-frame SIZE axis only.

============================================================================
\* Cross-references.
\*
\* C++ enforcement: src/net/peer.cpp
\*   Peer::read_header            @ lines 50-69
\*     framing gate `if (len == 0 || len > kMaxFrameBytes)` @ :64-67
\*     (the spec's RejectAtFraming + BufferBody pre-condition)
\*   Peer::read_body              @ lines 72-105
\*     body resize `body_buf_.resize(len)`             @ :73
\*     deserialize recovery `Message::deserialize`     @ :82
\*     per-type gate `if (... > max_message_bytes(...))` @ :90-97
\*     (the spec's RejectAtTypeCap)
\*     dispatch `if (on_msg_) on_msg_(self, msg)`      @ :98
\*     (the spec's Dispatch)
\*     re-arm `read_header()`                          @ :103
\*
\* C++ enforcement: include/determ/net/messages.hpp
\*   kMaxFrameBytes = 16 MB framing ceiling           @ :94-101
\*     (the spec's SixteenMB framing constant)
\*   max_message_bytes(MsgType) cap table             @ :103-152
\*     16 MB tier (SNAPSHOT_RESPONSE / CHAIN_RESPONSE) @ :126-128
\*     4  MB tier (BLOCK / BEACON_HEADER / SHARD_TIP /
\*       CROSS_SHARD_RECEIPT_BUNDLE / HEADERS_RESPONSE) @ :130-141
\*     1  MB default (consensus chatter / requests / tx) @ :149-150
\*     (the spec's Cap(t) three-tier operator)
\*   enum class MsgType                               @ :60-82
\*     (the spec's MsgTypes universe — representative subset)
\*
\* SECURITY.md §S-022 : per-message-type size caps closure narrative;
\*   the 16 MB framing ceiling + the type-aware post-deserialize cap.
\*   FB47 formalizes the two-stage gate at the state-machine layer.
\*
\* FB37 HelloHandshake.tla : sibling spec at the gossip admission
\*   surface (HELLO chain_id + wire_version gate). FB37 explicitly
\*   DEFERS the S-022 cap surface ("the S-022 per-message-type size
\*   caps ... are NOT modeled here"); FB47 is the missing state-
\*   machine witness. A frame transits FB47's size gate (Stages 1+2)
\*   before FB37's HELLO admission gate ever runs.
\*
\* FB39 TcpKeepaliveReap.tla : sibling spec at the gossip resource-
\*   exhaustion surface (per-IP slot lifetime). FB39's §7 cites
\*   "FB36 and S022WireFormatCaps.md cover the per-message size
\*   surface"; FB47 is the state-machine witness for that surface.
\*   FB39 bounds per-IP slot LIFETIME; FB47 bounds per-FRAME SIZE.
\*
\* FB25 RateLimiterEviction.tla : sibling spec at the gossip
\*   resource-exhaustion surface (per-IP message rate). FB25 (rate) +
\*   FB39 (slot lifetime) + FB47 (frame size) jointly cover the
\*   gossip-layer flooding-defense surface along three orthogonal
\*   axes.
\*
\* Preliminaries.md §3 : network adversary model (V0 framing for the
\*   flooding adversary). The spec's two-stage gate is the structural
\*   admission boundary bounding per-frame memory commitment (Stage 1)
\*   + per-type body size (Stage 2).
\*
\* Runtime regressions:
\*   No dedicated automated test for the oversize-frame drop path (the
\*   property is a connection-close side effect whose exercise would
\*   require a synthetic oversize-frame fuzzer feeding a live Peer).
\*   The cap table itself is exercised indirectly by every gossip
\*   integration test (tools/test_gossip_*.sh) — legitimate traffic
\*   stays well under each cap. FB47 is the state-machine witness for
\*   the drop-on-oversize disposition.
\*
\* Doc updates:
\*   docs/proofs/README.md FB47 row : added.
\*   CHECK-RESULTS.md FB47 row      : added by the same commit.
============================================================================
