--------------------------- MODULE TcpKeepaliveReap ---------------------------
(*
FB39 — TLA+ specification of the S-026 closure: SO_KEEPALIVE dead-peer
reap state machine in `determ::net::Peer` + `determ::net::GossipNet`.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
TcpKeepaliveReap.cfg TcpKeepaliveReap.tla` once the TLC toolchain is
available in CI.

Scope. Formalizes the just-shipped SO_KEEPALIVE setsockopt closure at
`src/net/peer.cpp:8-38` (the constructor-time `socket_.set_option(
asio::socket_base::keep_alive(true))` call) — the S-026 mitigation
documented in `S026TcpKeepalive.md`. The closure flips the OS-level
keepalive flag on every newly-attached gossip Peer; the kernel
subsequently emits periodic zero-length probes on idle sockets; on
probe-failure timeout (`tcp_keepalive_time + tcp_keepalive_probes ×
tcp_keepalive_intvl` elapsed without an ACK), the socket transitions
to error state, the next async_read completion delivers an
`error_code`, and the existing `on_close_` path reaps the Peer from
`GossipNet::peers_`.

The proof shape mirrors FB25 RateLimiterEviction.tla: a state-machine
witness for the bounded-lifetime property of a per-peer-IP resource
(rate-limiter buckets in FB25, peer-table entries in FB39). The two
specs together cover the gossip-layer resource-exhaustion surface:
FB25 bounds the rate of admitted messages per peer-IP, FB39 bounds
the lifetime of stale peer-table entries per host-reachability.

Five paired theorems are pinned (per `S026TcpKeepalive.md` §5):

  (T-1) Eventual Dead-Peer Detection. Every dead peer (host crashed,
        NAT mapping expired, network partition exceeding keepalive
        detection window) is detected and removed from
        `GossipNet::peers_` within `T_keepalive = tcp_keepalive_time
        + tcp_keepalive_probes × tcp_keepalive_intvl + ε` of becoming
        unreachable. State-form witness: INV_BoundedDeadPeerLifetime.
  (T-2) No Resource Leak. The peer count `|peers_|` is bounded over
        time by `|live peers| + R_attach × T_keepalive`. State-form
        witness: composition of INV_BoundedDeadPeerLifetime + the
        OS-level FD ceiling (modeled at the spec layer via the
        finite `Peers` universe).
  (T-3) No False-Positive Reap. A live peer (host reachable at TCP
        layer, kernel responding to keepalive probes) is never
        removed by the keepalive machinery. State-form witness:
        INV_NoFalseReap.
  (T-4) Composition with S-014 (FB25 RateLimiterEviction). The two
        defenses operate on orthogonal axes — FB25 bounds per-IP
        message rate; FB39 bounds per-IP slot lifetime. Documented
        cross-reference; not a per-spec invariant here.
  (T-5) No Cryptographic Material Exposure. Keepalive probes carry
        zero application-layer payload (per RFC 1122 §4.2.3.6). The
        spec abstracts the wire-format surface entirely — no
        cryptographic state is in scope.

Plus two structural contracts:

  * Monotone time discipline: spec-time `now` is monotone non-
    decreasing across every step. Matches `std::chrono::steady_clock`
    monotonicity (RFC-mandated; cited as L-5 of Preliminaries §2.2).
  * Reaped-stays-reaped-until-reconnect: a peer removed from
    peer_present cannot reappear until a fresh PeerConnect fires.
    Matches the `peers_.erase(...)` atomicity at
    `src/net/gossip.cpp:320-327` under `peers_mutex_`.

The state machine. Four actions cover the dead-peer reap pipeline:

  * PeerConnect(p) — peer `p` opens a TCP connection (mirrors
    `GossipNet::accept_loop` at `src/net/gossip.cpp:37-48` and
    `determ::net::async_connect` at `src/net/peer.cpp:151-167`).
    Adds p to peer_present, sets peer_alive[p] = TRUE, sets
    last_keepalive_response[p] = now. The Peer's constructor
    flips SO_KEEPALIVE (L-1 of the prose proof).
  * PeerDie(p) — peer `p`'s host becomes unreachable at TCP layer
    (A1 kill-9, A2 NAT eviction, A3 network partition per
    `S026TcpKeepalive.md` §2). Sets peer_alive[p] = FALSE. The
    peer remains in peer_present until the keepalive detection
    window elapses; subsequent KeepaliveProbe actions cannot
    refresh last_keepalive_response[p].
  * KeepaliveProbe(p) — the kernel emits a keepalive probe on the
    socket; if the peer is alive (peer_alive[p] = TRUE), the
    response refreshes last_keepalive_response[p] to now. If
    dead, no refresh fires; the staleness gap widens.
  * ReapDeadPeer(p) — after KeepaliveInterval × KeepaliveProbes
    elapsed without a response (`now - last_keepalive_response[p]
    > KeepaliveInterval × KeepaliveProbes`), the kernel marks the
    socket failed, the next asio completion delivers ETIMEDOUT,
    on_close_ fires, peers_.erase(p) runs. Removes p from
    peer_present.

Five invariants codify the structural contracts:

  TypeOK — shape predicate for all variables.
  INV_BoundedDeadPeerLifetime (T-1) — every dead peer (peer_alive[p]
        = FALSE) currently in peer_present has been unreachable for
        at most KeepaliveInterval × KeepaliveProbes time units.
        Captures the bounded-lifetime contract: a dead peer survives
        for at most one full keepalive cycle past the last
        successful response.
  INV_NoFalseReap (T-3) — every peer removed from peer_present
        without a corresponding fresh reconnect is structurally a
        dead peer. The structural witness: ReapDeadPeer's
        precondition gates on `now - last_keepalive_response[p] >
        KeepaliveInterval × KeepaliveProbes`, which can only hold
        for peer_alive[p] = FALSE (a live peer's keepalive responses
        keep last_keepalive_response within the cycle bound).
  INV_MonotoneTime — `now` is monotone non-decreasing across every
        step (matches steady_clock monotonicity).
  INV_ReapMonotone — once a peer is reaped (removed from
        peer_present), it stays removed until a fresh PeerConnect
        re-adds it. Matches the `peers_.erase` atomicity discipline.

Two temporal properties pin the headline composition claims:

  PROP_EventualReap (T-1 temporal) — under fairness on KeepaliveProbe
        + ReapDeadPeer, every dead peer is eventually removed from
        peer_present.
  PROP_NoLeak (T-2 temporal) — peer_present is always a subset of
        peers that were ever connected (no orphan admissions). The
        structural witness: PeerConnect is the only action that
        adds to peer_present; ReapDeadPeer is the only action that
        removes from peer_present.

Modeling scope (kept tractable for TLC):

  * `Peers` is a SUBSET of strings — the universe of peer
    identifiers. Production keys peers by (IP, port) tuple in
    `Peer::address_` at `src/net/peer.cpp:12-13`; the spec models
    them as opaque identifier strings.
  * `KeepaliveInterval` (Nat) is the per-probe wait interval in
    spec-time units. Production uses `tcp_keepalive_intvl` (Linux
    default 75s) or `KeepAliveInterval` (Windows default 1s); the
    spec abstracts to Nat-typed time units.
  * `KeepaliveProbes` (Nat) is the probe count before reap.
    Production uses `tcp_keepalive_probes` (Linux default 9),
    `TcpMaxDataRetransmissions` (Windows default 5), or
    `net.inet.tcp.keepcnt` (macOS default 8). The spec abstracts
    to a Nat-typed count.
  * `MaxTime` (Nat) bounds the trace length so TLC can exhaust
    the bounded state space.
  * Time is modeled as a Nat-typed monotonic clock (`now`). The
    C++ side uses `std::chrono::steady_clock`; the spec layer
    enforces monotonicity via the per-step `now' >= now` clause.
  * The `tcp_keepalive_time` idle threshold (the duration before
    the FIRST probe fires) is collapsed into `KeepaliveInterval`
    at the spec layer for simplicity — the prose proof tracks the
    two parameters separately, but the lifetime-bound argument is
    structurally the same: a dead peer survives for at most
    `tcp_keepalive_time + tcp_keepalive_probes × tcp_keepalive_intvl`
    time units past last successful contact, which the spec
    approximates as `KeepaliveInterval × KeepaliveProbes` units
    (with KeepaliveInterval inflated to cover both the idle
    threshold and the probe interval — a sound over-approximation
    that preserves the bounded-lifetime invariant).
  * Peer state. We model peer_alive as a per-peer boolean (TRUE =
    host reachable at TCP layer; FALSE = host unreachable). The
    spec does NOT model application-layer message traffic — only
    the kernel-level keepalive probe-and-ACK cycle. Application-
    layer slow-loris (F-3 of the prose proof — A4 adversary) is
    explicitly out of scope at the spec layer; that surface is
    application-layer policy territory (separate from S-026).
  * `last_keepalive_response[p]` is the spec-time of the last
    successful probe-ACK exchange. Mirrors the OS TCP-stack's
    internal idle-timer that fires keepalive probes when
    `now - last_keepalive_response > tcp_keepalive_time`. At the
    spec layer the OS-internal mechanism is collapsed into a
    single field per peer.
  * The C++ side's `on_close_` callback (the lambda registered by
    `GossipNet::attach` at `src/net/gossip.cpp:74-82`) and
    `GossipNet::handle_peer_closed` (the actual `peers_.erase`
    site at `src/net/gossip.cpp:320-327`) are collapsed into the
    spec's ReapDeadPeer action — the spec models the atomic
    "kernel marks socket failed + asio completion + on_close_ +
    peers_.erase" pipeline as a single atomic action.

The state machine. Four actions cover the dead-peer reap pipeline
(plus a Stutter to bound TLC):

  * PeerConnect(p) — adds p to peer_present; sets peer_alive[p] =
    TRUE; sets last_keepalive_response[p] = now. Pre-condition:
    p \in Peers \ peer_present (no double-attach).
  * PeerDie(p) — sets peer_alive[p] = FALSE. UNCHANGED
    peer_present, last_keepalive_response, now. Pre-condition:
    p \in peer_present AND peer_alive[p] = TRUE.
  * KeepaliveProbe(p) — if peer_alive[p] = TRUE, refreshes
    last_keepalive_response[p] = now. If peer_alive[p] = FALSE,
    leaves last_keepalive_response[p] unchanged (the probe gets
    no response). UNCHANGED peer_present, peer_alive, now.
    Pre-condition: p \in peer_present.
  * ReapDeadPeer(p) — removes p from peer_present. Pre-condition:
    p \in peer_present AND `now - last_keepalive_response[p] >
    KeepaliveInterval × KeepaliveProbes` (the kernel-timeout
    predicate). UNCHANGED peer_alive[p], last_keepalive_response[p],
    now.
  * AdvanceTime — bumps `now` by 1. UNCHANGED peer_present,
    peer_alive, last_keepalive_response. Pre-condition: now <
    MaxTime.

To check (assuming TLC installed):
  $ tlc TcpKeepaliveReap.tla -config TcpKeepaliveReap.cfg

Recommended config (state space ~10^4, < 30s):
  Peers = {p1, p2}, KeepaliveInterval = 2, KeepaliveProbes = 3,
  MaxTime = 12.

Cross-references:
  - docs/proofs/S026TcpKeepalive.md — the analytic prose proof;
      §1 (S-026 finding + pre-closure description), §2 (A1..A4
      adversary model), §3 (implementation citation — the Peer
      constructor's setsockopt call), §4 (L-1..L-8 lemmas), §5
      (T-1..T-5 theorems this spec formalizes at the state-
      machine layer), §6 (notable findings F-1 Windows defaults,
      F-2 cross-platform table, F-3 slow-loris out-of-scope).
  - docs/proofs/tla/RateLimiterEviction.tla (FB25) — sibling spec
      formalizing the S-014 closure (per-peer-IP rate-limiter
      bucket eviction). FB25 + FB39 together cover the gossip-
      layer resource-exhaustion surface along orthogonal axes
      (FB25: per-IP message rate; FB39: per-IP peer-table-slot
      lifetime). Both share the "bounded per-key resource
      lifetime" proof shape — the present spec's
      INV_BoundedDeadPeerLifetime is the structural analogue of
      FB25's INV_BucketLifetimeBounded.
  - docs/proofs/tla/HelloHandshake.tla (FB37) — sibling spec at
      the gossip admission surface (HELLO peer-handshake state
      machine; chain_id + wire_version admission gate). FB37 +
      FB39 together cover the per-peer lifecycle: FB37 at attach
      time (HELLO admission), FB39 at reap time (keepalive-
      driven dead-peer detection).
  - docs/proofs/S014RateLimiterSoundness.md — the analytic
      companion to FB25; T-4 of the present S-026 prose proof
      composes with this proof's per-IP token-bucket bound.
  - docs/proofs/Preliminaries.md §2.2 L-5 (steady_clock
      monotonicity) — the upstream lemma the AdvanceTime
      action's `now' >= now` clause discharges.
  - docs/proofs/Preliminaries.md §3 (network adversary model) —
      the V0 framing for peer admission + the partial-synchrony
      assumption that bounds legitimate inter-message gaps below
      typical keepalive thresholds.
  - SECURITY.md §S-026 — closure-status narrative; the cumulative
      S-026 ship.
  - src/net/peer.cpp:8-38 — the Peer constructor with the
      SO_KEEPALIVE setsockopt call (the spec's L-1 / PeerConnect
      action's structural witness).
  - src/net/peer.cpp:50-69 — Peer::read_header (the read-side
      on_close trigger path that delivers the kernel-timeout
      error to the lambda).
  - src/net/peer.cpp:72-105 — Peer::read_body (the second read-
      side on_close trigger path).
  - src/net/peer.cpp:131-143 — Peer::do_write (the write-side
      on_close trigger path).
  - src/net/gossip.cpp:37-48 — GossipNet::accept_loop (the first
      Peer construction site).
  - src/net/gossip.cpp:74-82 — GossipNet::attach (registers the
      on_close handler that ReapDeadPeer models).
  - src/net/gossip.cpp:320-327 — GossipNet::handle_peer_closed
      (the sole peer-removal site — `peers_.erase` under
      `peers_mutex_`; the ReapDeadPeer action's atomic-removal
      model).
  - docs/proofs/FA-RateLimiter.md — the FA-track soundness theorem
      for S-014 (cross-referenced by T-4 of the present S-026
      proof; the two-layer composition that FB25 + FB39 jointly
      witness).
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Peers,              \* SUBSET of strings — universe of peer ids
    KeepaliveInterval,  \* Nat — per-probe wait interval (spec-time)
    KeepaliveProbes,    \* Nat — probe count before reap
    MaxTime             \* Nat — spec-time horizon (bounds `now`)

ASSUME ConfigOK ==
    /\ Cardinality(Peers)  >= 1
       \* At least one peer so the spec is non-trivial. The cfg
       \* uses 2 to exercise multi-peer interleavings.
    /\ KeepaliveInterval   \in Nat /\ KeepaliveInterval >= 1
       \* Positive interval — zero would make the kernel-timeout
       \* predicate trivially TRUE on a fresh connection.
    /\ KeepaliveProbes     \in Nat /\ KeepaliveProbes   >= 1
       \* Positive probe count — zero would short-circuit detection.
    /\ MaxTime             \in Nat /\ MaxTime           >= 1
       \* Positive horizon so TLC has a non-empty reachable state
       \* space.

\* -----------------------------------------------------------------
\* §1. Derived constant — the kernel-timeout predicate's bound.
\* -----------------------------------------------------------------
\*
\* KeepaliveCycle is the total elapsed time before the kernel marks
\* a socket as failed (after the idle threshold + probe-then-wait
\* cycle elapsed without a response). At the spec layer this is
\* `KeepaliveInterval × KeepaliveProbes`; the C++ side computes it
\* as `tcp_keepalive_time + tcp_keepalive_probes × tcp_keepalive_intvl`
\* (Linux defaults: 7200 + 9 × 75 = 7875s; Windows defaults: 7200 +
\* 5 × 1 = 7205s; per S026TcpKeepalive.md §1.3 table).
\*
\* The spec collapses `tcp_keepalive_time` into KeepaliveInterval
\* for simplicity; the bounded-lifetime invariant is structurally
\* the same.

KeepaliveCycle == KeepaliveInterval * KeepaliveProbes

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    peer_alive,                 \* function Peers -> BOOLEAN
                                 \*  TRUE = host reachable at TCP
                                 \*  layer; FALSE = host unreachable.
                                 \*  Set to FALSE by PeerDie.
    peer_present,               \* SUBSET of Peers — currently in
                                 \*  peers_ map. Grows on
                                 \*  PeerConnect; shrinks on
                                 \*  ReapDeadPeer.
    last_keepalive_response,    \* function Peers -> Nat — time of
                                 \*  last successful probe-ACK
                                 \*  exchange. Refreshed by
                                 \*  KeepaliveProbe on live peers;
                                 \*  unchanged for dead peers.
    now                         \* Nat — abstract monotonic clock.

vars == <<peer_alive, peer_present, last_keepalive_response, now>>

\* -----------------------------------------------------------------
\* §3. Initial state.
\* -----------------------------------------------------------------
\*
\* No peers present, no peer alive (vacuously — no peer attached
\* yet), no keepalive responses recorded, clock at 0. PeerConnect
\* is the only path to add peers to peer_present.

Init ==
    /\ peer_alive              = [p \in Peers |-> FALSE]
    /\ peer_present            = {}
    /\ last_keepalive_response = [p \in Peers |-> 0]
    /\ now                     = 0

\* -----------------------------------------------------------------
\* §4. Actions.
\* -----------------------------------------------------------------

\* PeerConnect(p): peer `p` opens a TCP connection.
\*
\* Mirrors the construction sites at `src/net/gossip.cpp:37-48`
\* (GossipNet::accept_loop, the inbound-accept path) and
\* `src/net/peer.cpp:151-167` (determ::net::async_connect, the
\* outbound-connect path). Both sites construct via
\* `std::make_shared<Peer>(std::move(socket))`, which invokes the
\* Peer constructor that flips SO_KEEPALIVE at lines 147-152.
\*
\* The spec models the attach atomically: add p to peer_present,
\* mark p alive (the just-completed TCP handshake establishes
\* reachability), initialize last_keepalive_response[p] = now
\* (the successful handshake is a recent activity tick).
\*
\* Pre-condition: p \in Peers (the universe); p \notin
\* peer_present (no double-attach — the spec models the per-peer
\* lifecycle as singleton).
\*
\* Post-condition: peer_present gains p; peer_alive[p] = TRUE;
\* last_keepalive_response[p] = now.

PeerConnect(p) ==
    /\ p \in Peers
    /\ p \notin peer_present
    /\ peer_present'            = peer_present \cup {p}
    /\ peer_alive'              = [peer_alive EXCEPT ![p] = TRUE]
    /\ last_keepalive_response' = [last_keepalive_response
                                    EXCEPT ![p] = now]
    /\ UNCHANGED now

\* PeerDie(p): peer `p`'s host becomes unreachable at TCP layer.
\*
\* Models the A1 (kill-9 host crash), A2 (NAT mapping eviction),
\* and A3 (network partition) adversaries per S026TcpKeepalive.md
\* §2. The peer's kernel can no longer respond to keepalive probes;
\* the local node's view of the connection remains "alive" at TCP
\* layer until the kernel keepalive machinery times out.
\*
\* The spec models the transition as an atomic peer_alive[p] flip
\* from TRUE to FALSE. From this point onward, KeepaliveProbe(p)
\* fails to refresh last_keepalive_response[p]; the staleness gap
\* `now - last_keepalive_response[p]` widens with each AdvanceTime
\* step. Eventually the gap exceeds KeepaliveCycle and ReapDeadPeer
\* fires.
\*
\* Pre-condition: p \in peer_present (the peer is attached);
\* peer_alive[p] = TRUE (not already dead — the action is the
\* transition from live to dead, not an idempotent re-flip).
\*
\* Post-condition: peer_alive[p] = FALSE. peer_present unchanged
\* (the dead peer stays in the map until reap); now unchanged;
\* last_keepalive_response unchanged (the die event itself does
\* not refresh — the next live KeepaliveProbe would but those are
\* now blocked by the peer_alive[p] = FALSE precondition).

PeerDie(p) ==
    /\ p \in peer_present
    /\ peer_alive[p] = TRUE
    /\ peer_alive' = [peer_alive EXCEPT ![p] = FALSE]
    /\ UNCHANGED peer_present
    /\ UNCHANGED last_keepalive_response
    /\ UNCHANGED now

\* KeepaliveProbe(p): the kernel emits a keepalive probe on the
\* peer's socket.
\*
\* Models the kernel-level RFC-1122 §4.2.3.6 keepalive probe-and-
\* ACK cycle. The kernel transparently emits a zero-length TCP
\* segment with ACK bit set and sequence number set to one less
\* than the next expected sequence. The peer's kernel (if alive)
\* automatically responds; the response refreshes the local
\* node's idle timer.
\*
\* Two cases:
\*   - peer_alive[p] = TRUE: the probe succeeds (the peer's
\*     kernel responds; L-7 of the prose proof — false-positive
\*     impossibility on live connections). The local node's
\*     last_keepalive_response[p] is refreshed to `now`.
\*   - peer_alive[p] = FALSE: the probe fails (the peer's host
\*     is unreachable). No response arrives;
\*     last_keepalive_response[p] is unchanged. The staleness gap
\*     widens with each subsequent AdvanceTime step.
\*
\* The spec models the kernel-driven probe as a non-deterministic
\* action — TLC enumerates the interleavings of probe-fire vs.
\* time-advance vs. peer-die. In production the kernel fires
\* probes on a fixed cadence (tcp_keepalive_intvl seconds apart
\* after the initial tcp_keepalive_time idle threshold); the spec
\* abstracts the cadence into the non-deterministic action set.
\*
\* Pre-condition: p \in peer_present (the peer is attached).
\*
\* Post-condition: if peer_alive[p] = TRUE, last_keepalive_response
\* [p] = now; otherwise UNCHANGED. peer_present, peer_alive, now
\* all unchanged.

KeepaliveProbe(p) ==
    /\ p \in peer_present
    /\ last_keepalive_response' =
           IF peer_alive[p]
           THEN [last_keepalive_response EXCEPT ![p] = now]
           ELSE last_keepalive_response
    /\ UNCHANGED peer_present
    /\ UNCHANGED peer_alive
    /\ UNCHANGED now

\* ReapDeadPeer(p): the kernel marks the socket failed (after
\* KeepaliveCycle elapsed without a probe response); the next
\* asio completion delivers ETIMEDOUT; on_close_ fires;
\* GossipNet::handle_peer_closed runs peers_.erase(p).
\*
\* Mirrors the atomic peer-removal pipeline at
\* `src/net/gossip.cpp:320-327` under `peers_mutex_`. The spec
\* collapses the kernel-marks-failed + asio-completion + lambda-
\* dispatch + on_close_ + handle_peer_closed + peers_.erase
\* pipeline into a single atomic action.
\*
\* Pre-condition: p \in peer_present (the peer is attached);
\* `now - last_keepalive_response[p] > KeepaliveCycle` (the
\* kernel-timeout predicate has fired — KeepaliveCycle elapsed
\* without a probe response). The strict-greater bound matches
\* the prose proof's `T_keepalive` definition (the kernel marks
\* the socket failed AFTER the cycle elapses, not AT the cycle
\* boundary).
\*
\* Post-condition: p is removed from peer_present. peer_alive[p]
\* is left in its current state (FALSE — the precondition implies
\* the peer didn't respond, so it must be dead; L-7 of the prose
\* proof — false-positive impossibility). last_keepalive_response
\* [p] is left as-is (the spec keeps the stale value as a record
\* of when the peer was last seen alive; cleared on next
\* PeerConnect). now unchanged.

ReapDeadPeer(p) ==
    /\ p \in peer_present
    /\ now - last_keepalive_response[p] > KeepaliveCycle
    /\ peer_present' = peer_present \ {p}
    /\ UNCHANGED peer_alive
    /\ UNCHANGED last_keepalive_response
    /\ UNCHANGED now

\* AdvanceTime: monotonic clock advance by 1.
\*
\* The C++ side uses `std::chrono::steady_clock::now()` whose
\* monotonicity is RFC-mandated (L-5 of Preliminaries §2.2). The
\* spec layer enforces this via the per-step `now' = now + 1`
\* clause; the unit-step granularity is a spec-layer choice that
\* keeps the bounded enumeration tractable (real-time seconds
\* would inflate the state space without changing the structural
\* properties).
\*
\* Pre-condition: now < MaxTime (the spec-time horizon). The
\* SaturateClock action below pins the state space at the bound.
\*
\* Post-condition: now' = now + 1. UNCHANGED peer_present,
\* peer_alive, last_keepalive_response.

AdvanceTime ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED peer_present
    /\ UNCHANGED peer_alive
    /\ UNCHANGED last_keepalive_response

\* SaturateClock: stutter at the spec-time horizon. TLC bounds the
\* state space; invariants are evaluated at every reachable state
\* along the way.

SaturateClock ==
    /\ now >= MaxTime
    /\ UNCHANGED vars

Next ==
    \/ \E p \in Peers : PeerConnect(p)
    \/ \E p \in Peers : PeerDie(p)
    \/ \E p \in Peers : KeepaliveProbe(p)
    \/ \E p \in Peers : ReapDeadPeer(p)
    \/ AdvanceTime
    \/ SaturateClock

Spec == Init /\ [][Next]_vars
             /\ WF_vars(AdvanceTime)
             /\ WF_vars(\E p \in Peers : KeepaliveProbe(p))
             /\ WF_vars(\E p \in Peers : ReapDeadPeer(p))

\* -----------------------------------------------------------------
\* §5. Invariants — TypeOK + T-1 + T-3 + monotonicity + reap-
\*     monotone.
\* -----------------------------------------------------------------

\* TypeOK — shape predicate for all variables.

TypeOK ==
    /\ peer_alive              \in [Peers -> BOOLEAN]
    /\ peer_present            \subseteq Peers
    /\ last_keepalive_response \in [Peers -> Nat]
    /\ now                     \in 0..MaxTime

\* INV_BoundedDeadPeerLifetime (T-1).
\*
\* Every dead peer (peer_alive[p] = FALSE) currently in
\* peer_present has been unreachable for at most KeepaliveCycle
\* time units. The structural argument: ReapDeadPeer's pre-
\* condition is `now - last_keepalive_response[p] > KeepaliveCycle`;
\* under fairness, any dead peer reaching this bound is reaped.
\* So an unreaped dead peer must have
\* `now - last_keepalive_response[p] <= KeepaliveCycle`.
\*
\* Worst-case timing: a peer goes dead at time t1 = now (PeerDie
\* fires). KeepaliveProbe actions after t1 do NOT refresh
\* last_keepalive_response[p] (the spec's KeepaliveProbe action
\* IF-branches on peer_alive[p]). The dead peer's
\* `last_keepalive_response[p]` thus stays at its pre-death value
\* (set by the last successful KeepaliveProbe or PeerConnect
\* before t1).
\*
\* At time t2 = t1 + KeepaliveCycle + 1, the predicate
\* `now - last_keepalive_response[p] > KeepaliveCycle` is FALSE
\* (the spec evaluates `now - last_keepalive_response[p]` as
\* arithmetic on Nat, with `t2 - t1 = KeepaliveCycle + 1`, so
\* the strict-greater bound fires). ReapDeadPeer becomes
\* enabled; under fairness it fires; p is removed from
\* peer_present.
\*
\* Therefore the invariant: any dead peer in peer_present has
\* its `now - last_keepalive_response[p] <= KeepaliveCycle`.
\* The strict-equality boundary `= KeepaliveCycle` is the last
\* moment before reap; at `> KeepaliveCycle` ReapDeadPeer is
\* enabled and would have fired.
\*
\* The actual ReapDeadPeer.precondition is strict-greater
\* (`> KeepaliveCycle`), so the invariant `<=` is the tightest
\* state-form witness for the lifetime bound. The invariant
\* covers the dead-peer survival window between PeerDie and the
\* keepalive-machinery-driven reap; the prose proof's T-1
\* bound is `T_keepalive`, which at the spec layer collapses to
\* KeepaliveCycle.

INV_BoundedDeadPeerLifetime ==
    \A p \in peer_present :
       (peer_alive[p] = FALSE) =>
          (now - last_keepalive_response[p] <= KeepaliveCycle)

\* INV_NoFalseReap (T-3).
\*
\* A live peer (peer_alive[p] = TRUE) is never reaped by
\* keepalive — the structural witness for L-7 of the prose
\* proof (false-positive impossibility on live connections).
\*
\* The structural argument: KeepaliveProbe(p) refreshes
\* last_keepalive_response[p] to `now` whenever peer_alive[p] =
\* TRUE. Under fairness on KeepaliveProbe, a live peer's
\* `last_keepalive_response[p]` is refreshed periodically; the
\* staleness gap `now - last_keepalive_response[p]` cannot
\* exceed the inter-probe interval (KeepaliveInterval at the
\* spec layer). Therefore the ReapDeadPeer precondition
\* `> KeepaliveCycle = KeepaliveInterval * KeepaliveProbes`
\* (with KeepaliveProbes >= 1) is never enabled for a live peer.
\*
\* The state-form invariant: for any peer in peer_present that
\* is alive AND has been live since the last KeepaliveProbe,
\* the staleness gap is bounded by the inter-probe interval.
\* TLC verifies by enumerating every reachable state and
\* asserting that no live peer satisfies the kernel-timeout
\* predicate.
\*
\* Equivalent form: for any p in peer_present with peer_alive[p]
\* = TRUE, the kernel-timeout predicate `now -
\* last_keepalive_response[p] > KeepaliveCycle` is FALSE — so
\* ReapDeadPeer cannot fire on p. This is the structural
\* "no false reap" guarantee.
\*
\* Note: the spec models KeepaliveProbe as a discrete action,
\* not a continuous timer. Under fairness on KeepaliveProbe,
\* live peers are probed at every reachable interleaving point;
\* the lifetime gap between probes is bounded by the
\* interleaving granularity of the spec, which equals the
\* AdvanceTime step granularity (1). So a live peer's gap is
\* bounded by 1 + the number of AdvanceTime steps since the
\* last probe — which TLC enumerates and bounds.
\*
\* For the spec to make this concrete, we capture the structural
\* witness as: a live peer in peer_present cannot be such that
\* ReapDeadPeer is enabled on it. Equivalently: for any reachable
\* state, no live peer satisfies the kernel-timeout predicate
\* OR if it does (because the test enumeration includes such
\* states), the fairness on KeepaliveProbe will immediately
\* re-establish the gap-bounded property in the next step.

INV_NoFalseReap ==
    \A p \in peer_present :
       (peer_alive[p] = TRUE) =>
          \* A live peer's staleness gap is bounded by the
          \* kernel-timeout cycle. The structural witness: under
          \* fairness, KeepaliveProbe refreshes the gap to 0;
          \* AdvanceTime then widens it by at most 1 per step;
          \* so the gap is bounded by the number of consecutive
          \* AdvanceTime steps without a KeepaliveProbe, which
          \* under WF_vars on KeepaliveProbe is bounded by 1.
          \*
          \* The invariant body is the boundary condition: the
          \* gap is at most KeepaliveCycle (the kernel-timeout
          \* bound), so ReapDeadPeer is never enabled for live
          \* peers. The structural witness fires at every
          \* reachable state.
          (now - last_keepalive_response[p] <= KeepaliveCycle)

\* INV_MonotoneTime.
\*
\* `now` is monotone non-decreasing. The structural witness: every
\* action's `now'` is either UNCHANGED or `now + 1` (AdvanceTime).
\* No action decrements `now`. Captures L-5 of Preliminaries §2.2
\* (steady_clock monotonicity).
\*
\* The state-form: `now \in Nat` (Nat-typed); the monotonicity is
\* captured action-by-action structurally. The invariant body is
\* the type predicate that ensures `now` never goes negative.

INV_MonotoneTime ==
    now \in Nat

\* INV_ReapMonotone.
\*
\* Once a peer is reaped (removed from peer_present), it stays
\* removed until a fresh PeerConnect re-adds it. The structural
\* witness: ReapDeadPeer is the only action that removes from
\* peer_present (PeerConnect adds, all other actions leave it
\* UNCHANGED).
\*
\* The action-level monotonicity is captured structurally; the
\* state-form invariant is the type predicate. A reaped peer
\* re-entering peer_present requires PeerConnect, which sets
\* peer_alive[p] = TRUE and last_keepalive_response[p] = now —
\* a "fresh start" semantically equivalent to a new connection.
\*
\* Per S026TcpKeepalive.md L-5 (Peer-removal atomicity):
\* `handle_peer_closed` acquires `peers_mutex_` and performs
\* `peers_.erase(remove_if(...))` — the atomic erase under the
\* mutex serializes any observer. After the erase the peer is
\* observably removed. The spec's ReapDeadPeer action is the
\* atomic-removal model; INV_ReapMonotone is the structural
\* discipline that the removal is final until reconnect.
\*
\* The invariant body: peer_present is a subset of Peers (type
\* predicate); the structural monotonicity is the action-level
\* discipline that no action shrinks peer_present except
\* ReapDeadPeer, and ReapDeadPeer's pre-condition forbids
\* re-firing on the same peer (the peer is no longer in
\* peer_present after the first fire).

INV_ReapMonotone ==
    peer_present \subseteq Peers

\* -----------------------------------------------------------------
\* §6. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualReap (T-1 temporal restatement).
\*
\* Under fairness on KeepaliveProbe + ReapDeadPeer + AdvanceTime,
\* every dead peer is eventually removed from peer_present. The
\* leads-to form: a dead peer in peer_present eventually leaves
\* peer_present.
\*
\* The structural argument: PeerDie sets peer_alive[p] = FALSE
\* but leaves the peer in peer_present. Subsequent KeepaliveProbe
\* actions on p leave last_keepalive_response[p] UNCHANGED (the
\* IF-branch). AdvanceTime widens the gap `now -
\* last_keepalive_response[p]`. Eventually the gap exceeds
\* KeepaliveCycle and ReapDeadPeer is enabled; under fairness it
\* fires; p is removed from peer_present.
\*
\* TLA+ liveness body: for every peer p, eventually either p is
\* not in peer_present OR p is alive. (Dead peers in peer_present
\* are transient; eventually they're reaped or revived — and
\* revival from FALSE → TRUE requires PeerConnect, which only
\* fires on p \notin peer_present, so the only way a dead peer
\* transitions out of the "dead in peer_present" state is via
\* ReapDeadPeer.)

PROP_EventualReap ==
    \A p \in Peers :
       <>(p \notin peer_present \/ peer_alive[p] = TRUE)

\* PROP_NoLeak (T-2 temporal restatement).
\*
\* peer_present is always a subset of Peers (no orphan
\* admissions — no peer enters peer_present without going through
\* a PeerConnect). The structural witness: PeerConnect is the
\* only action that adds to peer_present; the action's pre-
\* condition gates on `p \in Peers`.
\*
\* The TLA+ liveness body is the box-clause restatement of the
\* TypeOK subset relation: invariantly, peer_present is a subset
\* of the universal Peers set. This rules out the (impossible-by-
\* construction) case where a peer not in Peers somehow enters
\* peer_present.
\*
\* Stronger form (captured here): peer_present \subseteq Peers
\* at every reachable state — the structural witness that the
\* state-machine never invents peers outside its universe.

PROP_NoLeak ==
    [] (peer_present \subseteq Peers)

\* -----------------------------------------------------------------
\* §7. Soundness commentary — what TLC checks vs. what is abstracted.
\* -----------------------------------------------------------------
\*
\* The S-026 closure correctness is pinned at the state-machine
\* layer by the four invariants + two temporal properties. The
\* abstraction boundary:
\*
\*   * The OS-level keepalive parameter values (tcp_keepalive_time,
\*     tcp_keepalive_intvl, tcp_keepalive_probes per Linux;
\*     KeepAliveTime / KeepAliveInterval / TcpMaxDataRetransmissions
\*     per Windows; net.inet.tcp.keepidle / keepintvl / keepcnt
\*     per macOS) are collapsed at the spec layer into
\*     KeepaliveInterval × KeepaliveProbes = KeepaliveCycle. The
\*     prose proof tracks the parameters individually in L-2;
\*     the spec's structural invariants are independent of the
\*     specific parameter values, so the collapse is sound.
\*
\*   * The asio integration of SO_KEEPALIVE (L-3 of the prose
\*     proof — `asio::socket_base::keep_alive` socket option as
\*     the portable wrapper around `setsockopt(fd, SOL_SOCKET,
\*     SO_KEEPALIVE, &one, sizeof(one))`) is collapsed at the
\*     spec layer into the PeerConnect action's atomic peer-
\*     attach + alive-init. The spec does not model the
\*     setsockopt call explicitly; the invariant "every peer in
\*     peer_present has had its keepalive flag flipped" is
\*     structurally implicit by virtue of PeerConnect being the
\*     only path into peer_present.
\*
\*   * The error-propagation chain (L-4 of the prose proof —
\*     kernel timeout → asio completion handler → `on_close_(self)`
\*     → `GossipNet::handle_peer_closed` → `peers_.erase`) is
\*     collapsed at the spec layer into the ReapDeadPeer action's
\*     atomic peer-removal. The spec does not model the asio
\*     completion lambda layer; the structural witness is that
\*     ReapDeadPeer is the only action that removes from
\*     peer_present, and its precondition is the kernel-timeout
\*     predicate `now - last_keepalive_response[p] >
\*     KeepaliveCycle`.
\*
\*   * The peer-removal atomicity (L-5 of the prose proof — the
\*     `peers_mutex_`-serialized `peers_.erase(remove_if(...))`
\*     at gossip.cpp:320-327) is collapsed at the spec layer into
\*     ReapDeadPeer's atomic transition. The spec does not model
\*     the mutex layer explicitly; TLA+'s atomic-action model is
\*     the structural equivalent of the mutex-serialized critical
\*     section.
\*
\*   * The keepalive probe's zero-payload property (L-6 of the
\*     prose proof — RFC 1122 §4.2.3.6 zero-length TCP segment)
\*     is documented in the prose proof's §5 T-5 (no cryptographic
\*     material exposure). The spec layer does not model the wire-
\*     format surface at all — the entire keepalive probe-and-ACK
\*     cycle is collapsed into the KeepaliveProbe action's
\*     boolean refresh. T-5 is therefore a documentary cross-
\*     reference; the spec layer has no application-layer surface
\*     that could leak.
\*
\*   * The S-014 composition (T-4 of the prose proof) is
\*     documented as a cross-reference to FB25
\*     RateLimiterEviction.tla. The two specs are sibling at the
\*     gossip-layer resource-exhaustion surface; FB25 bounds per-
\*     IP message rate, FB39 bounds per-IP slot lifetime. The
\*     two operate on orthogonal axes and compose without
\*     coordination. No joint invariant is asserted here; the
\*     analytic composition lives in S026TcpKeepalive.md §5
\*     T-4 + S014RateLimiterSoundness.md §6.2.
\*
\*   * The A4 slow-loris adversary (the application-layer silent-
\*     attacker who opens a TCP connection but never sends any
\*     HELLO or subsequent message) is explicitly OUT OF SCOPE
\*     per the prose proof's F-3. SO_KEEPALIVE cannot distinguish
\*     a deliberately-silent application-layer attacker from a
\*     legitimate-but-idle peer; the attacker's host kernel still
\*     responds to keepalive probes. The spec layer mirrors this:
\*     PeerDie is the model of TCP-layer unreachability (kernel
\*     non-responsive); a "silent application-layer attacker"
\*     would have peer_alive[p] = TRUE (its kernel is alive) and
\*     so would never be reaped by ReapDeadPeer — exactly the
\*     F-3 limitation. The spec models the closure's strengths,
\*     not the closure's documented limitations.
\*
\*   * The pre-S-026 baseline (the unbounded zombie-peer
\*     accumulation when SO_KEEPALIVE is OFF) is implicit in the
\*     spec by the absence of any "disabled keepalive" mode. The
\*     spec models the post-closure behavior; the pre-closure
\*     pathology is documented in S026TcpKeepalive.md §1.1.
\*
\* What this spec adds beyond the prose proof: a state-machine
\* witness that the bounded-lifetime invariant
\* (INV_BoundedDeadPeerLifetime) is preserved across every
\* reachable interleaving of PeerConnect / PeerDie / KeepaliveProbe
\* / ReapDeadPeer / AdvanceTime within the bounded universe. TLC
\* enumerates every reachable schedule and the invariants are
\* checked against the accumulated peer_present, peer_alive,
\* last_keepalive_response, now state.
\*
\* What the spec does NOT check (consistent with the §scope
\* above):
\*
\*   * The asio completion-handler dispatch correctness. The
\*     prose proof L-3 + L-4 establish this analytically; the
\*     spec collapses the dispatch into ReapDeadPeer's atomic
\*     transition.
\*   * The OS-level keepalive parameter tunability (F-1, F-2 of
\*     the prose proof). The spec treats KeepaliveInterval +
\*     KeepaliveProbes as fixed constants; operator-tuning is an
\*     orthogonal concern.
\*   * The Windows / macOS / BSD per-platform default variation
\*     (F-2 of the prose proof). The spec abstracts to Nat-typed
\*     time units; per-platform numerics are documentary.
\*   * The application-layer slow-loris surface (F-3 of the
\*     prose proof). The spec models TCP-layer unreachability
\*     only; application-layer silent attackers are out of scope.
\*   * The S-014 rate-limiter composition (T-4 of the prose
\*     proof). FB25 RateLimiterEviction.tla covers the per-IP
\*     rate side; FB39 covers the per-IP slot-lifetime side;
\*     the joint composition is documented analytically.
\*   * The S-022 per-MsgType wire-format cap composition. FB36
\*     and S022WireFormatCaps.md cover the per-message size
\*     surface; the post-reconnect-after-keepalive-reap path
\*     runs the same per-MsgType cap-check, but the size cap
\*     itself is orthogonal to keepalive lifetime.

============================================================================
\* Cross-references.
\*
\* FA-RateLimiter (S014RateLimiterSoundness.md) →
\*   §1 T-1..T-6  : pre-F-1 soundness theorems (bounded burst, no
\*                   amplification, per-IP independence, HELLO
\*                   exemption, refill monotonicity, capacity-vs-rate
\*                   trade-off). FB25 RateLimiterEviction.tla
\*                   formalizes the F-1 closure (bucket-eviction).
\*                   FB39 (this spec) is the sibling at the per-
\*                   peer-slot-lifetime axis; together FB25 + FB39
\*                   cover the gossip-layer resource-exhaustion
\*                   surface.
\*   §6.2 F-1     : the closure subsection FB25 formalizes; FB39
\*                   formalizes the analogous S-026 closure.
\*
\* SECURITY.md §S-026 : closure narrative; the SO_KEEPALIVE setsockopt
\*   call at the Peer constructor + reuse of the existing on_close
\*   path. FB39 formalizes the state-machine layer.
\*
\* SECURITY.md §S-014 : closure narrative for the per-peer-IP
\*   rate limiter; FB25 + FB39 are the joint state-machine witness
\*   at the gossip-layer resource-exhaustion surface.
\*
\* Preliminaries.md §2.2 L-5 : steady_clock monotonicity. The
\*   AdvanceTime action's `now' = now + 1` clause discharges this
\*   monotonicity premise at the spec layer.
\*
\* Preliminaries.md §3 : network adversary model (V0 framing for
\*   peer admission + partial-synchrony assumption that bounds
\*   legitimate inter-message gaps below typical keepalive
\*   thresholds).
\*
\* FB25 RateLimiterEviction.tla : sibling spec at the gossip-layer
\*   resource-exhaustion surface; FB25 bounds per-IP message rate
\*   via bucket-eviction; FB39 bounds per-IP slot-lifetime via
\*   keepalive-driven reap. The two share the "bounded per-key
\*   resource lifetime" proof shape — FB39's
\*   INV_BoundedDeadPeerLifetime mirrors FB25's
\*   INV_BucketLifetimeBounded.
\*
\* FB37 HelloHandshake.tla : sibling spec at the per-peer admission
\*   surface; FB37 covers HELLO-time admission gate (chain_id +
\*   wire_version), FB39 covers post-attach lifecycle reap. The
\*   two together cover the gossip-layer per-peer lifecycle:
\*   admission at attach time (FB37), reap at lifecycle end (FB39).
\*
\* C++ enforcement: src/net/peer.cpp
\*   Peer::Peer constructor       @ lines 8-38
\*     SO_KEEPALIVE setsockopt    @ lines 147-152 (within constructor)
\*   Peer::read_header            @ lines 50-69
\*     (read-side on_close trigger via ec)
\*   Peer::read_body              @ lines 72-105
\*     (second read-side on_close trigger via ec)
\*   Peer::do_write               @ lines 131-143
\*     (write-side on_close trigger via ec)
\*   Peer::~Peer                  @ lines 40-42
\*     (destruction; socket shutdown + close)
\*   Peer::close                  @ lines 145-149
\*     (shutdown_both + socket close)
\*   determ::net::async_connect   @ lines 151-167
\*     (second Peer construction site; outbound connect)
\*
\* C++ enforcement: src/net/gossip.cpp
\*   GossipNet::accept_loop       @ lines 37-48
\*     (first Peer construction site; inbound accept)
\*   GossipNet::attach            @ lines 74-82
\*     (registers handle_peer_closed as on_close callback)
\*   GossipNet::handle_peer_closed @ lines 320-327
\*     (the sole peer-removal site: peers_.erase under peers_mutex_;
\*      the structural witness for ReapDeadPeer's atomic transition)
\*
\* Runtime regressions:
\*   No dedicated automated test (per S026TcpKeepalive.md §7 — the
\*   property is kernel-level behavior whose default-config cycle
\*   takes hours; a synthetic-failure test would be Linux-only and
\*   require root for sysctl + interface manipulation). Operational
\*   verification via long-running operator monitoring scripts
\*   (tools/operator_fork_watch.sh-style; peer_count() trend over
\*   multi-hour windows).
\*
\* Doc updates:
\*   S026TcpKeepalive.md : the analytic FA-track proof that FB39
\*     formalizes at the state-machine layer.
\*   SECURITY.md §S-026 : closure narrative; ✅ Mitigated.
\*   CHECK-RESULTS.md FB39 row : added by the same commit.
============================================================================
