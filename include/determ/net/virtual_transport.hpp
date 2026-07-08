// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// net::Virtual* — the deterministic IN-MEMORY backend for the minix net seam
// (docs/proofs/MinixTacticalProfile.md §4.1: the same seam scoped for DSF
// §Q2 and the FA4 liveness harness). Multiple real determ::node::Node
// instances run in ONE process, connected by in-process byte pipes instead
// of sockets: VirtualNetwork is the port registry the test creates and
// shares between nodes; VirtualTransport implements listen/async_connect
// against it; a connect/accept rendezvous wires up a PAIR of
// VirtualConnections whose two directions are plain byte queues under a
// per-pair mutex + condition variable. No OS resource is touched anywhere
// in this backend — header AND implementation are pure std, no platform
// guards, compiled identically on MSVC and GCC (the .cpp is deliberately
// NOT CMake-pruned like the native backends; nothing is platform-specific).
//
// SEAM CONFORMANCE. A consumer written for IocpConnection/ReactorConnection
// works unmodified (transport.hpp is the spec):
//  - async_read is exactly-N: a parked read completes only when >= N bytes
//    are queued; partial data stays queued until then.
//  - async_write is whole-span (the unbounded in-memory queue absorbs it).
//  - Completions run on loop threads and are POSTED, never invoked inline
//    in the caller; one outstanding op per kind per connection (Peer's
//    model), serialized by the pair mutex exactly like the reactor's op_mu_.
//  - close() is idempotent, cross-thread safe, synthesizes aborted
//    completions for parked ops exactly once (posted), wakes sync waiters
//    on BOTH ends, and the remote end sees EOF once its queued bytes drain.
//  - remote_endpoint() is "ip:port"-shaped and never throws, so consumers
//    that rfind(':')-strip the port (RpcServer's rate-limit key, GossipNet's
//    per-peer-IP bucket) behave identically.
//  - The sync half (write_all / read_line / set_send_timeout) backs
//    RpcServer sessions and the dapp_subscribe writer thread.
//
// DOCUMENTED DEVIATIONS (where a socket contract cannot apply in-memory):
//  - set_send_timeout()/set_keep_alive() are no-ops: there is no OS socket,
//    and writes NEVER block (each direction is an UNBOUNDED queue —
//    acceptable for a test backend; the FB71 stuck-writer kill still works
//    because a cross-thread close() makes the next write_all return false).
//  - Write-after-peer-close fails IMMEDIATELY (error completion / false)
//    instead of TCP's buffered-grace-then-RST — stricter and deterministic.
//  - listen()'s localhost_only and async_connect()'s host are accepted and
//    ignored: everything is in-process; only the port selects the peer.
//  - remote_endpoint() is "127.0.0.1:<pseudo-port>" with a unique
//    pseudo-port per pair; BOTH ends of a pair report the same string. All
//    virtual peers therefore share the "127.0.0.1" rate-limit bucket —
//    exactly like a native localhost cluster.
//  - async_connect completes only at RENDEZVOUS with an armed async_accept
//    (until then it parks in the listener's backlog): there is no kernel
//    backlog that completes the client's handshake before the server
//    accepts. Consumers that connect and immediately WRITE still work (the
//    write lands once the pair exists); consumers that require connect
//    completion before the passive side ever calls async_accept would hang
//    here where a native backend proceeds.
//  - Close-abort/EOF error completions report n=0 and leave any undelivered
//    bytes queued in the inbox; a native reactor may report partial n>0
//    with the bytes copied out. Seam consumers ignore n on error (Peer
//    tears the session down), so the difference is unobservable through
//    the seam.
//  - read_line after LOCAL close still drains already-buffered COMPLETE
//    lines before returning false (the same drain it performs on peer-close
//    EOF); a native backend's post-close read fails without draining.
//
// DETERMINISM. With a SINGLE run() thread per loop, delivery order is
// exactly post() order (a locked FIFO) — deterministic multi-node traces
// run one thread per VirtualEventLoop. Blocking consumers change that
// calculus: an RpcServer session is a posted closure that OCCUPIES a loop
// thread for the connection's lifetime (the model all backends share), so a
// loop that must service RPC sessions AND async completions needs more than
// one run() thread.
//
// LIFETIME RULES (the same discipline the native backends impose):
//  - The VirtualNetwork outlives every VirtualTransport/VirtualAcceptor
//    created against it (declare it first in the test).
//  - Connections and the transport are destroyed BEFORE their loop (Node's
//    member order already guarantees this for real consumers).
//  - ~VirtualTransport cancels this transport's still-queued connects;
//    their callbacks are dropped, never invoked (the never-dispatched-
//    handler semantics all backends share).
#pragma once
#include <determ/net/event_loop.hpp>
#include <determ/net/timer_service.hpp>
#include <determ/net/transport.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace determ::net {

class VirtualAcceptor;
class VirtualTransport;

// A real thread-driven loop (not manually pumped): run() from N threads
// services one locked work queue; post() enqueues; stop() is permanent and
// releases every runner (the IocpEventLoop/ReactorEventLoop contract).
// Undelivered work is dropped at destruction without invoking.
class VirtualEventLoop final : public EventLoop {
public:
    // The loop's post-target state, held by shared_ptr: every internal
    // post SOURCE (a Pair side, a Listener, a queued connect) keeps a ref,
    // so a completion synthesized during PAIR teardown — e.g. a dropped
    // closure's ~Peer running close() — always posts into a live State
    // even when the VirtualEventLoop OBJECT was already destroyed (the
    // closure is then dropped when the state's last ref goes; it never
    // runs). This is what makes multi-loop teardown order-free: a review
    // round found the raw-pointer form UAFs when survivors' loops die
    // before a dead node's queued closures do. INTERNAL — consumers never
    // touch this type.
    struct State {
        std::mutex                        mu;
        std::condition_variable           cv;
        std::deque<std::function<void()>> q;
        bool                              stopped = false;   // guarded by mu
        void post(std::function<void()> fn);
        void drain();   // destroy undelivered closures OUTSIDE the lock,
                        // looping until their dtors stop re-posting
        ~State() { drain(); }
    };

    VirtualEventLoop() = default;
    ~VirtualEventLoop() override;   // stop() + timer shutdown + drain
                                    // (undelivered posts dropped, never
                                    // invoked). Callers join their own
                                    // run() threads first, as everywhere.

    VirtualEventLoop(const VirtualEventLoop&) = delete;
    VirtualEventLoop& operator=(const VirtualEventLoop&) = delete;

    void run() override;
    void stop() override;
    void post(std::function<void()> fn) override;

    // ── Timer service (the EventLoop interface's timer half) ────────────
    // REAL wall-clock deadlines via the shared net::TimerService deadline
    // thread (virtual time is a later evolution of this backend) — the
    // same shape as IocpEventLoop/ReactorEventLoop, so net::LoopTimer
    // works over a VirtualEventLoop unchanged.
    uint64_t timer_schedule(std::chrono::milliseconds delay,
                            std::function<void()> fn) override {
        return timers_.schedule(delay, std::move(fn));
    }
    void timer_cancel(uint64_t id) override { timers_.cancel(id); }

private:
    friend class VirtualNetwork;   // reads st_ to wire pair/listener posts

    std::shared_ptr<State> st_{std::make_shared<State>()};

    TimerService timers_{[st = st_](std::function<void()> fn) {
        st->post(std::move(fn));
    }};
};

// One end of an in-process pipe pair. Created only by the VirtualNetwork
// rendezvous (listen/connect) — never constructed directly by consumers.
class VirtualConnection final : public Connection {
public:
    // The two-sided shared pair state: per-direction byte queues, parked
    // read ops, the per-pair mutex + condition variable, each side's loop.
    // Defined in the .cpp; public ONLY so the implementation's file-local
    // helpers can name it — not consumer surface.
    struct Pair;

    VirtualConnection(std::shared_ptr<Pair> pair, int side);
    ~VirtualConnection() override;   // close()

    void async_read(void* buf, std::size_t n, IoCb cb) override;
    void async_write(const void* buf, std::size_t n, IoCb cb) override;
    void close() override;
    std::string remote_endpoint() const override { return endpoint_; }

    // No OS socket to probe — no-op (header preamble, deviations).
    void set_keep_alive(bool) override {}

    bool write_all(const void* buf, std::size_t n) override;
    // Writes never block against the unbounded in-memory queue, so there
    // is nothing for a send bound to interrupt — no-op (the interface
    // explicitly allows backends that cannot bound sends to no-op).
    void set_send_timeout(std::chrono::milliseconds) override {}
    bool read_line(std::string& out_line) override;

private:
    std::shared_ptr<Pair> pair_;
    int                   side_;      // 0 = accept side, 1 = connect side
    std::string           endpoint_;  // "127.0.0.1:<pseudo-port>", fixed at
                                      // pair creation; returned by copy
};

// The in-process endpoint registry — the "network" a set of virtual nodes
// share. The test creates ONE (or uses VirtualTransport::default_network())
// and passes it to every node's VirtualTransport; ports are meaningful only
// within one VirtualNetwork. Thread-safe. Must outlive every transport and
// acceptor created against it.
class VirtualNetwork {
public:
    VirtualNetwork() = default;
    ~VirtualNetwork();

    VirtualNetwork(const VirtualNetwork&) = delete;
    VirtualNetwork& operator=(const VirtualNetwork&) = delete;

    // ── Adversarial fault injection (test-facing; OFF by default) ────────
    // The virtual backend can model a lossy/partitioned network so the FA4
    // harness can stress consensus liveness under adversarial DELIVERY (the
    // S-047 territory), not just node death. On the GOSSIP path this is
    // WHOLE-FRAME granular: Peer's write pump issues exactly one complete
    // length-prefixed message per async_write call (src/net/peer.cpp
    // do_write), so dropping/gating one write drops exactly one logical
    // message and can never split a frame — the property the consensus
    // harness relies on. (The SYNC half `write_all` is a raw byte-stream op
    // with no intrinsic framing: a fault drops the whole span of a SINGLE
    // write_all call, so it never splits WITHIN a call, but a sync consumer
    // that wrote one frame across MULTIPLE write_all calls under loss could
    // have a fragment dropped. That is by-convention-safe for today's sync
    // callers, which each write one complete line/reply — see the write_all
    // note in the .cpp; the gossip/consensus path never uses write_all.) A
    // fault gates the
    // SENDER's delivery into the peer inbox; the write still "succeeds" to
    // the caller (a packet that left the host and was lost downstream), so
    // no connection tears down and no peer is reaped — a lossy link, not a
    // crash. Default (no group set, no partition, zero loss) is
    // byte-identical to a perfect network; every existing test is
    // unaffected. Thread-safe; call these from the harness thread while the
    // cluster runs.

    // Per-link message-drop probability in PER-MILLE (0..1000), applied to
    // every current AND future link, both directions. Seeded per-link
    // (xorshift advanced under the pair mutex); the drop DISTRIBUTION is
    // fixed but exact drops inherit the harness's existing wall-clock
    // nondeterminism.
    void set_loss(uint32_t permille);

    // Partition: every link whose two endpoint groups STRADDLE the boundary
    // (one in `side_a`, the other not) has delivery blocked BOTH ways;
    // non-straddling links deliver normally. Applies to current AND future
    // links; recomputable (idempotent). Endpoints are tagged via
    // VirtualTransport::set_partition_group (default group 0 → no straddle
    // possible). Gates DELIVERY only — does not sever, so on heal() gossip
    // resumes and the S-047 retry re-delivers. A minority partitioned below
    // quorum cannot finalize (safety), and absent a periodic re-sync probe
    // does NOT auto-catch-up on heal — that recovery boundary is
    // operational (SECURITY.md §S-048).
    void partition(const std::set<int>& side_a);

    // Remove any partition (loss unaffected; clear it via set_loss(0)).
    void heal();

private:
    friend class VirtualTransport;
    friend class VirtualAcceptor;
    // The connection pair holds a shared_ptr<LinkFlags> — grant it access to
    // name the (otherwise-private) nested policy type.
    friend struct VirtualConnection::Pair;

    // Per-link delivery policy: two direction gates + a drop rate + the two
    // endpoint groups + the per-link RNG. Co-owned by the Pair and the
    // network — the write path reads the atomics without touching the
    // network, and the network flips them without touching the pair.
    // Defined in the .cpp.
    struct LinkFlags;

    // Per-port listener state: the parked one-shot accept callback and the
    // queue of connects that arrived before an async_accept (both
    // connect-then-accept and accept-then-connect orders are supported).
    // Defined in the .cpp.
    struct Listener;

    // Registry ops (implemented in the .cpp; every one takes mu_).
    // register_listener assigns `port` in place when it is 0 (auto-assign
    // from a counter) and throws std::runtime_error when taken. `group` is
    // the acceptor's partition group (recorded so links it forms inherit
    // it).
    std::shared_ptr<Listener> register_listener(uint16_t& port,
                                                VirtualEventLoop& loop,
                                                int group);
    void unregister_listener(const std::shared_ptr<Listener>& l);
    void arm_accept(const std::shared_ptr<Listener>& l, Acceptor::AcceptCb cb);
    void connect(uint16_t port, VirtualEventLoop& caller_loop, int caller_group,
                 VirtualTransport* owner, Transport::ConnectCb cb);
    void cancel_connects(VirtualTransport* owner);
    // Builds a wired pair; {accept-side, connect-side}. Caller holds mu_.
    // Takes the loops' shared STATEs (see VirtualEventLoop::State) — the
    // pair keeps them alive so its teardown posts are order-free — plus the
    // two endpoint groups, so the new link inherits the current partition +
    // loss and is registered for later mutation.
    std::pair<std::shared_ptr<VirtualConnection>,
              std::shared_ptr<VirtualConnection>>
    make_pair_locked(std::shared_ptr<VirtualEventLoop::State> accept_loop,
                     int accept_group,
                     std::shared_ptr<VirtualEventLoop::State> connect_loop,
                     int connect_group);
    // Does a link between groups (ga, gb) straddle the current partition?
    // Caller holds mu_.
    bool link_blocked_locked(int ga, int gb) const;

    std::mutex mu_;
    std::map<uint16_t, std::shared_ptr<Listener>> listeners_;
    std::vector<std::shared_ptr<LinkFlags>> links_;   // fault registry (all pairs)
    std::set<int> partition_a_;                        // empty = no partition
    uint32_t      loss_permille_   = 0;                // 0 = lossless
    uint16_t next_auto_port_   = 30000;   // listen(0) auto-assignment
    uint16_t next_pseudo_port_ = 50000;   // remote_endpoint() pair ids
};

class VirtualAcceptor final : public Acceptor {
public:
    // Registers `port` in the network (port 0 = auto-assign; read the
    // result back via local_port()). Throws std::runtime_error when the
    // port is taken (bind-failure parity with the native acceptors).
    // localhost_only is accepted and ignored — in-process by construction.
    // `group` is the owning transport's partition group (default 0).
    VirtualAcceptor(VirtualNetwork& net, VirtualEventLoop& loop,
                    uint16_t port, bool localhost_only, int group);
    // Unregisters the port. A parked accept callback is DROPPED, never
    // invoked (the drained-handlers contract every backend shares);
    // still-queued connects to this port are refused (posted on each
    // connector's own loop — the closed-listen-backlog RST analogue).
    ~VirtualAcceptor() override;

    void async_accept(AcceptCb cb) override;

    // The actual bound port — lets tests bind port 0 and learn the
    // assignment. Concrete-class-only; not part of the Acceptor seam
    // (same shape as ReactorAcceptor/IocpAcceptor).
    uint16_t local_port() const { return port_; }

private:
    VirtualNetwork& net_;
    uint16_t        port_;
    std::shared_ptr<VirtualNetwork::Listener> state_;
};

class VirtualTransport final : public Transport {
public:
    // `net` is the registry shared between the nodes of one virtual
    // cluster; `loop` is where THIS endpoint's completions run. Both must
    // outlive the transport. Sharing one VirtualNetwork across multiple
    // (loop, transport) pairs is exactly how a multi-node in-process
    // cluster is assembled.
    VirtualTransport(VirtualEventLoop& loop, VirtualNetwork& net);
    ~VirtualTransport() override;   // cancels this transport's queued
                                    // connects (callbacks dropped)

    std::unique_ptr<Acceptor> listen(uint16_t port,
                                     bool localhost_only) override;
    // host is ignored (in-process; the port selects the peer). Connection
    // refused (no listener on `port`) → cb(error, nullptr), posted.
    void async_connect(const std::string& host, uint16_t port,
                       ConnectCb cb) override;

    // A process-wide shared registry for tests that don't want to plumb an
    // explicit VirtualNetwork; sharing stays explicit at every
    // construction site: VirtualTransport(loop, VirtualTransport::default_network()).
    static VirtualNetwork& default_network();

    // Partition group of THIS endpoint (= this node) for the fault model
    // (VirtualNetwork::partition). Default 0 = all endpoints in one group =
    // no partition possible. Set before the node forms connections; a link
    // records the groups of its two endpoints at creation.
    void set_partition_group(int g) { group_ = g; }

private:
    VirtualEventLoop& loop_;
    VirtualNetwork&   net_;
    int               group_ = 0;
};

} // namespace determ::net
