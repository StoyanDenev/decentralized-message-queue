// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// Virtual* implementation (minix §4.1 / DSF §Q2 — the deterministic
// in-memory backend). PURE std — zero OS includes, zero platform guards:
// this TU compiles identically on MSVC and GCC and is deliberately NOT
// CMake-pruned per platform like the native backends (there is nothing
// platform-specific to prune; the src/ glob picks it up everywhere).
//
// LOCKING MODEL. One mutex per connection pair (Pair::mu) serializes both
// directions' queues, parked ops, and closed flags — the same role the
// reactor's op_mu_ plays, extended across the pair because a write on one
// end completes a parked read on the other. Completion POSTS happen while
// holding Pair::mu; that is safe because every post target is a
// shared_ptr<VirtualEventLoop::State> the SOURCE itself keeps alive (a
// Pair side, a Listener, a queued connect), so a post can never touch a
// destroyed loop no matter what order the loop OBJECTS die in — the
// adversarial-review finding that motivated the shared-state design. This
// does not violate the reactor's completion-outside-lock discipline:
// post() only ENQUEUES (it takes the state's queue mutex briefly, a leaf
// lock); the completion is INVOKED later on a loop thread with no pair
// lock held. Lock order is strictly {network mu_ | pair mu} → loop queue
// mutex, never the reverse — which is why State::drain() destroys dropped
// closures OUTSIDE the queue mutex (their dtors run ~Peer → close(),
// which takes pair mutexes and re-posts).
#include <determ/net/virtual_transport.hpp>

#include <algorithm>
#include <atomic>
#include <stdexcept>

namespace determ::net {

// Per-link delivery policy (the fault model). Co-owned by the Pair (read on
// the write path) and the VirtualNetwork (mutated by set_loss/partition/heal
// from the harness thread). The gates + rate are atomics so the write path
// reads them lock-free; `rng` is touched ONLY under the owning Pair::mu (the
// write path holds it), so it needs no atomicity; groups are immutable after
// creation.
struct VirtualNetwork::LinkFlags {
    std::atomic<bool>     ab{true};          // deliver side0 -> side1
    std::atomic<bool>     ba{true};          // deliver side1 -> side0
    std::atomic<uint32_t> drop_permille{0};  // 0 = lossless
    int      group0 = 0;   // accept-side group  (immutable)
    int      group1 = 0;   // connect-side group (immutable)
    uint64_t rng    = 0;   // xorshift64 state; advanced under owning Pair::mu

    // Advance the per-link RNG (caller holds the owning Pair::mu) and decide
    // whether THIS frame is dropped by the loss model. Never a fixed point:
    // seeded non-zero at creation.
    bool roll_drop() {
        const uint32_t d = drop_permille.load(std::memory_order_relaxed);
        if (d == 0) return false;
        uint64_t x = rng;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;   // xorshift64
        rng = x;
        return (x % 1000u) < d;
    }
    // Is delivery in the given direction currently allowed by the partition?
    bool gate(int side) const {
        return (side == 0) ? ab.load(std::memory_order_relaxed)
                           : ba.load(std::memory_order_relaxed);
    }
};

namespace {

// std::errc gives portable, OS-header-free error codes. Consumers only
// truth-test the code (Peer, RpcServer), so the exact values are
// informational; the choices mirror the reactor's errno usage
// (ECANCELED for close-aborts, ECONNRESET for EOF-mid-read/peer-gone,
// ECONNREFUSED for no-listener).
std::error_code ec_canceled() {
    return std::make_error_code(std::errc::operation_canceled);
}
std::error_code ec_reset() {
    return std::make_error_code(std::errc::connection_reset);
}
std::error_code ec_refused() {
    return std::make_error_code(std::errc::connection_refused);
}

} // namespace

// ── VirtualEventLoop ─────────────────────────────────────────────────────────

void VirtualEventLoop::State::post(std::function<void()> fn) {
    {
        std::lock_guard<std::mutex> lk(mu);
        // Post-after-stop still enqueues; the closure is dropped at
        // drain() (the reactor's failed-wakeup drop semantics).
        q.push_back(std::move(fn));
    }
    cv.notify_one();
}

void VirtualEventLoop::State::drain() {
    // Destroy undelivered closures with NO lock held: their destructors
    // run consumer teardown (~Peer -> close()) which takes pair mutexes
    // and posts to states — including, possibly, THIS one again. The loop
    // re-swaps until those re-posts stop; holding mu across the
    // destruction would reverse the {pair mu -> loop mu} lock order
    // (review finding: ABBA deadlock under concurrent multi-loop
    // teardown).
    for (;;) {
        std::deque<std::function<void()>> drop;
        {
            std::lock_guard<std::mutex> lk(mu);
            if (q.empty()) break;
            drop.swap(q);
        }
        // `drop` destroyed here, lock-free.
    }
}

VirtualEventLoop::~VirtualEventLoop() {
    stop();
    // Stop the timer thread BEFORE dropping the queue so no timer post
    // races the teardown (the reactor-destructor ordering).
    timers_.shutdown();
    // Drop undelivered posts NOW (never invoked). Pairs/listeners still
    // holding st_ keep the STATE alive past this dtor, so their later
    // teardown posts land harmlessly in a stopped queue and are dropped
    // by ~State when the last ref goes.
    st_->drain();
}

void VirtualEventLoop::run() {
    State& s = *st_;
    std::unique_lock<std::mutex> lk(s.mu);
    for (;;) {
        s.cv.wait(lk, [&s] { return s.stopped || !s.q.empty(); });
        if (s.stopped) return;
        std::function<void()> fn = std::move(s.q.front());
        s.q.pop_front();
        lk.unlock();
        // May block for a session's lifetime (RpcServer's posted-closure
        // session model) — other run() threads keep servicing the queue.
        fn();
        lk.lock();
    }
}

void VirtualEventLoop::stop() {
    {
        std::lock_guard<std::mutex> lk(st_->mu);
        st_->stopped = true;   // permanent — run() never resumes (contract)
    }
    st_->cv.notify_all();
}

void VirtualEventLoop::post(std::function<void()> fn) {
    st_->post(std::move(fn));
}

// ── VirtualConnection::Pair ──────────────────────────────────────────────────

struct VirtualConnection::Pair {
    // A parked exactly-N async_read (the only op kind that parks in this
    // backend: writes complete inline against the unbounded queue).
    struct ParkedRead {
        uint8_t*          buf = nullptr;
        std::size_t       n   = 0;
        Connection::IoCb  cb;
        bool              active = false;
    };
    struct Side {
        // Where THIS side's completions run. A shared ref to the loop's
        // STATE (not the loop object): teardown-synthesized completions
        // (close() from a dropped closure's ~Peer) must be able to post
        // after the loop object is gone, in any loop-destruction order.
        std::shared_ptr<VirtualEventLoop::State> loop;
        std::deque<uint8_t> inbox;           // bytes awaiting this side's reads
        ParkedRead          rd;
        bool                closed = false;
    };

    std::mutex              mu;   // serializes everything below (both sides)
    std::condition_variable cv;   // wakes read_line waiters on either end
    Side                    side[2];
    std::string             endpoint;   // "127.0.0.1:<pseudo-port>", both ends
    // The fault-model policy for this link (never null once wired). Read on
    // the write path under mu (for rng); the gate/rate atomics may also be
    // flipped by the network without mu — that race is intended (a partition
    // taking effect "around" an in-flight write is exactly what a real
    // network does).
    std::shared_ptr<VirtualNetwork::LinkFlags> link;
};

namespace {

// Caller holds P.mu. Completes side s's parked read when the inbox can now
// satisfy exactly-N (partial data stays queued — the seam contract), POSTED
// on s's loop, and wakes any thread parked in the sync half (read_line).
void deliver_locked(VirtualConnection::Pair& P,
                    VirtualConnection::Pair::Side& s) {
    if (s.rd.active && s.inbox.size() >= s.rd.n) {
        std::copy_n(s.inbox.begin(), s.rd.n, s.rd.buf);
        s.inbox.erase(s.inbox.begin(),
                      s.inbox.begin() + static_cast<std::ptrdiff_t>(s.rd.n));
        const std::size_t n = s.rd.n;
        s.loop->post([cb = std::move(s.rd.cb), n] { cb({}, n); });
        s.rd = VirtualConnection::Pair::ParkedRead{};
    }
    P.cv.notify_all();
}

} // namespace

// ── VirtualConnection ────────────────────────────────────────────────────────

VirtualConnection::VirtualConnection(std::shared_ptr<Pair> pair, int side)
    : pair_(std::move(pair)), side_(side), endpoint_(pair_->endpoint) {}

VirtualConnection::~VirtualConnection() {
    close();
    // The Pair outlives both handles via shared_ptr, so the other end's
    // in-flight operations never dereference THIS object — only the
    // shared state (the analogue of the reactor's destructor-deferred
    // ::close(fd) fd-reuse discipline).
}

void VirtualConnection::async_read(void* buf, std::size_t n, IoCb cb) {
    Pair& P = *pair_;
    std::lock_guard<std::mutex> lk(P.mu);
    Pair::Side& me   = P.side[side_];
    Pair::Side& peer = P.side[1 - side_];
    if (me.closed) {   // reactor start_op parity: post the abort, never inline
        me.loop->post([cb = std::move(cb)] { cb(ec_canceled(), 0); });
        return;
    }
    if (n == 0) {
        me.loop->post([cb = std::move(cb)] { cb({}, 0); });
        return;
    }
    if (me.inbox.size() >= n) {
        std::copy_n(me.inbox.begin(), n, static_cast<uint8_t*>(buf));
        me.inbox.erase(me.inbox.begin(),
                       me.inbox.begin() + static_cast<std::ptrdiff_t>(n));
        me.loop->post([cb = std::move(cb), n] { cb({}, n); });
        return;
    }
    if (peer.closed) {
        // No more bytes can ever arrive — the reactor's r==0-mid-read
        // semantics (ECONNRESET-shaped; consumers only truth-test it).
        me.loop->post([cb = std::move(cb)] { cb(ec_reset(), 0); });
        return;
    }
    // Park. ONE outstanding read per the seam contract — issuing a second
    // while one is parked is a consumer bug on every backend.
    me.rd.buf    = static_cast<uint8_t*>(buf);
    me.rd.n      = n;
    me.rd.cb     = std::move(cb);
    me.rd.active = true;
}

void VirtualConnection::async_write(const void* buf, std::size_t n, IoCb cb) {
    Pair& P = *pair_;
    std::lock_guard<std::mutex> lk(P.mu);
    Pair::Side& me   = P.side[side_];
    Pair::Side& peer = P.side[1 - side_];
    if (me.closed) {
        me.loop->post([cb = std::move(cb)] { cb(ec_canceled(), 0); });
        return;
    }
    if (n == 0) {
        me.loop->post([cb = std::move(cb)] { cb({}, 0); });
        return;
    }
    if (peer.closed) {
        // Documented deviation: fails immediately instead of TCP's
        // buffered-grace-then-RST (EPIPE-equivalent disposition).
        me.loop->post([cb = std::move(cb)] { cb(ec_reset(), 0); });
        return;
    }
    // Fault model: a partitioned or randomly-dropped frame LEAVES the host
    // (the write completes successfully to the caller) but never reaches the
    // peer inbox — a packet lost downstream. Whole-frame granularity: one
    // async_write == one Peer message, so this drops exactly one message and
    // never splits a frame. Default policy (gate open, 0 loss) never drops.
    if (P.link && (!P.link->gate(side_) || P.link->roll_drop())) {
        me.loop->post([cb = std::move(cb), n] { cb({}, n); });
        return;
    }
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    peer.inbox.insert(peer.inbox.end(), p, p + n);
    // Whole-span completion first, then the peer's now-satisfiable parked
    // read — a fixed post order so single-threaded loops trace
    // deterministically.
    me.loop->post([cb = std::move(cb), n] { cb({}, n); });
    deliver_locked(P, peer);
}

void VirtualConnection::close() {
    Pair& P = *pair_;
    std::lock_guard<std::mutex> lk(P.mu);
    Pair::Side& me   = P.side[side_];
    Pair::Side& peer = P.side[1 - side_];
    if (me.closed) return;   // idempotent; cross-thread safe (P.mu)
    me.closed = true;
    // The §4.5 abort recipe: nothing blocks in a syscall here, so
    // synthesize the parked op's aborted completion NOW, exactly once —
    // P.mu serializes against a racing real completion, so exactly one of
    // {real completion, synthesized abort} ever fires per op.
    if (me.rd.active) {
        me.loop->post([cb = std::move(me.rd.cb)] { cb(ec_canceled(), 0); });
        me.rd = Pair::ParkedRead{};
    }
    // The peer's parked read can never be satisfied by future writes now.
    // Data already queued that satisfies it would have completed at write
    // time, so the >=N branch inside deliver_locked is defensive; the
    // normal case is the EOF error (TCP-FIN-arrives semantics).
    if (peer.rd.active) {
        if (peer.inbox.size() >= peer.rd.n) {
            deliver_locked(P, peer);
        } else {
            peer.loop->post([cb = std::move(peer.rd.cb)] { cb(ec_reset(), 0); });
            peer.rd = Pair::ParkedRead{};
        }
    }
    // Wake every sync waiter on BOTH ends: our read_line drains buffered
    // complete lines then returns false; the peer's drains then sees EOF.
    P.cv.notify_all();
}

bool VirtualConnection::write_all(const void* buf, std::size_t n) {
    if (n == 0) return true;
    Pair& P = *pair_;
    std::lock_guard<std::mutex> lk(P.mu);
    Pair::Side& me   = P.side[side_];
    Pair::Side& peer = P.side[1 - side_];
    // In-memory never blocks (unbounded queue) — the whole span either
    // lands atomically or the connection is already down. A cross-thread
    // close() therefore "breaks" a writer by failing its NEXT write, which
    // is what the FB71 kill path needs (there is no in-flight stall to
    // interrupt in this backend).
    if (me.closed || peer.closed) return false;
    // Fault model (see async_write): a partitioned/dropped frame "sends"
    // (returns true — bytes left the host) but is not delivered. The sync
    // half isn't on the gossip path, so this matters only if a future sync
    // consumer runs under fault injection; kept for parity.
    if (P.link && (!P.link->gate(side_) || P.link->roll_drop())) return true;
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    peer.inbox.insert(peer.inbox.end(), p, p + n);
    deliver_locked(P, peer);
    return true;
}

bool VirtualConnection::read_line(std::string& out_line) {
    Pair& P = *pair_;
    std::unique_lock<std::mutex> lk(P.mu);
    Pair::Side& me   = P.side[side_];
    Pair::Side& peer = P.side[1 - side_];
    for (;;) {
        // Buffered complete lines are delivered even after close(). For
        // PEER-close this is the reactor's carry_-scan-before-EOF-check
        // ordering; for LOCAL close it is a documented deviation (header
        // preamble) — deterministic drain instead of the native fail-
        // without-drain. The inbox IS the carry: bytes past '\n' stay
        // queued.
        auto nl = std::find(me.inbox.begin(), me.inbox.end(),
                            static_cast<uint8_t>('\n'));
        if (nl != me.inbox.end()) {
            out_line.assign(me.inbox.begin(), nl);
            me.inbox.erase(me.inbox.begin(), nl + 1);
            return true;
        }
        if (me.closed) return false;    // local close → session ends
        if (peer.closed) return false;  // EOF — no more bytes can arrive
        P.cv.wait(lk);   // woken by writes and by close() on either end
    }
}

// ── VirtualNetwork ───────────────────────────────────────────────────────────

struct VirtualNetwork::Listener {
    struct PendingConnect {
        // Connector's loop STATE (shared ref — outlives the loop object;
        // ~VirtualTransport additionally cancels its own entries).
        std::shared_ptr<VirtualEventLoop::State> loop;
        int                  group;   // connector's partition group
        VirtualTransport*    owner;   // cancellation key for the above
        Transport::ConnectCb cb;
    };

    std::shared_ptr<VirtualEventLoop::State> loop;   // acceptor's loop state
    int                        group = 0;   // acceptor's partition group
    uint16_t                   port = 0;
    bool                       dead = false;
    Acceptor::AcceptCb         parked;    // one-shot; the consumer re-arms
    std::deque<PendingConnect> pending;   // connects awaiting async_accept
};

VirtualNetwork::~VirtualNetwork() = default;

std::shared_ptr<VirtualNetwork::Listener>
VirtualNetwork::register_listener(uint16_t& port, VirtualEventLoop& loop,
                                  int group) {
    std::lock_guard<std::mutex> lk(mu_);
    if (port == 0) {
        // Auto-assign from the counter, skipping taken ports; wraps within
        // [30000, 65535] (test-scale registry — linear probe is fine).
        for (int i = 0; i < 65536 && port == 0; ++i) {
            const uint16_t cand = next_auto_port_;
            next_auto_port_ = next_auto_port_ == 65535
                                  ? static_cast<uint16_t>(30000)
                                  : static_cast<uint16_t>(next_auto_port_ + 1);
            if (listeners_.find(cand) == listeners_.end()) port = cand;
        }
        if (port == 0)
            throw std::runtime_error("VirtualAcceptor: port space exhausted");
    } else if (listeners_.find(port) != listeners_.end()) {
        // Bind-failure parity with the native acceptors' ctor throw.
        throw std::runtime_error("VirtualAcceptor: bind failed on port " +
                                 std::to_string(port));
    }
    auto l   = std::make_shared<Listener>();
    l->loop  = loop.st_;
    l->group = group;
    l->port  = port;
    listeners_[port] = l;
    return l;
}

void VirtualNetwork::unregister_listener(const std::shared_ptr<Listener>& l) {
    std::lock_guard<std::mutex> lk(mu_);
    l->dead   = true;
    l->parked = nullptr;   // dropped, never invoked (acceptor-dtor contract)
    // Still-queued connects lose their rendezvous — refuse each on its own
    // connector's loop (the closed-listen-backlog RST analogue).
    for (auto& pc : l->pending)
        pc.loop->post([cb = std::move(pc.cb)] { cb(ec_refused(), nullptr); });
    l->pending.clear();
    auto it = listeners_.find(l->port);
    if (it != listeners_.end() && it->second == l) listeners_.erase(it);
}

void VirtualNetwork::arm_accept(const std::shared_ptr<Listener>& l,
                                Acceptor::AcceptCb cb) {
    std::lock_guard<std::mutex> lk(mu_);
    if (l->dead) return;   // defensive: accept on a torn-down acceptor
    if (!l->pending.empty()) {
        // A connect was queued before this accept (both orders supported).
        Listener::PendingConnect pc = std::move(l->pending.front());
        l->pending.pop_front();
        auto [acc, conn] = make_pair_locked(l->loop, l->group,
                                            pc.loop, pc.group);
        std::shared_ptr<Connection> accepted  = std::move(acc);
        std::shared_ptr<Connection> connected = std::move(conn);
        // Both callbacks delivered ON A LOOP THREAD via post — never
        // inline. mu_ is held across the posts: unregister_listener /
        // cancel_connects serialize behind it, so both target loops are
        // alive (see the .cpp preamble's locking model).
        l->loop->post([acb = std::move(cb), accepted] { acb({}, accepted); });
        pc.loop->post([ccb = std::move(pc.cb), connected] {
            ccb({}, connected);
        });
    } else {
        l->parked = std::move(cb);
    }
}

void VirtualNetwork::connect(uint16_t port, VirtualEventLoop& caller_loop,
                             int caller_group, VirtualTransport* owner,
                             Transport::ConnectCb cb) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = listeners_.find(port);
    if (it == listeners_.end()) {
        // Connection refused — posted, never inline (seam discipline).
        caller_loop.post([cb = std::move(cb)] { cb(ec_refused(), nullptr); });
        return;
    }
    const std::shared_ptr<Listener>& l = it->second;
    if (l->parked) {
        Acceptor::AcceptCb acb = std::move(l->parked);
        l->parked = nullptr;
        auto [acc, conn] = make_pair_locked(l->loop, l->group,
                                            caller_loop.st_, caller_group);
        std::shared_ptr<Connection> accepted  = std::move(acc);
        std::shared_ptr<Connection> connected = std::move(conn);
        l->loop->post([acb = std::move(acb), accepted] { acb({}, accepted); });
        caller_loop.post([cb = std::move(cb), connected] {
            cb({}, connected);
        });
    } else {
        // Park the connect until async_accept is called (TCP backlog
        // analogue; refused if the acceptor is destroyed first).
        l->pending.push_back(Listener::PendingConnect{
            caller_loop.st_, caller_group, owner, std::move(cb)});
    }
}

void VirtualNetwork::cancel_connects(VirtualTransport* owner) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& entry : listeners_) {
        auto& dq = entry.second->pending;
        for (auto it = dq.begin(); it != dq.end();) {
            if (it->owner == owner)
                it = dq.erase(it);   // dropped, never invoked
            else
                ++it;
        }
    }
}

std::pair<std::shared_ptr<VirtualConnection>,
          std::shared_ptr<VirtualConnection>>
VirtualNetwork::make_pair_locked(
    std::shared_ptr<VirtualEventLoop::State> accept_loop, int accept_group,
    std::shared_ptr<VirtualEventLoop::State> connect_loop, int connect_group) {
    auto P = std::make_shared<VirtualConnection::Pair>();
    P->side[0].loop = std::move(accept_loop);
    P->side[1].loop = std::move(connect_loop);
    // Unique pseudo-port per pair so consumers that parse "ip:port"
    // (RpcServer's rfind(':') strip, gossip's per-IP bucket) behave
    // identically; wraps within [50000, 65535].
    const uint16_t pseudo = next_pseudo_port_;
    next_pseudo_port_ = next_pseudo_port_ == 65535
                            ? static_cast<uint16_t>(50000)
                            : static_cast<uint16_t>(next_pseudo_port_ + 1);
    P->endpoint = "127.0.0.1:" + std::to_string(pseudo);

    // Wire the fault-model policy: inherit the current loss + partition,
    // seed the per-link RNG non-zero (0 is an xorshift fixed point), and
    // register the link so a later set_loss/partition/heal can mutate it.
    auto lf = std::make_shared<LinkFlags>();
    lf->group0 = accept_group;
    lf->group1 = connect_group;
    lf->drop_permille.store(loss_permille_, std::memory_order_relaxed);
    lf->rng = (static_cast<uint64_t>(pseudo) << 1) | 1ull;
    if (link_blocked_locked(accept_group, connect_group)) {
        lf->ab.store(false, std::memory_order_relaxed);
        lf->ba.store(false, std::memory_order_relaxed);
    }
    P->link = lf;
    links_.push_back(std::move(lf));

    return {std::make_shared<VirtualConnection>(P, 0),
            std::make_shared<VirtualConnection>(P, 1)};
}

bool VirtualNetwork::link_blocked_locked(int ga, int gb) const {
    if (partition_a_.empty()) return false;
    const bool a_in = partition_a_.count(ga) != 0;
    const bool b_in = partition_a_.count(gb) != 0;
    return a_in != b_in;   // straddles the boundary
}

void VirtualNetwork::set_loss(uint32_t permille) {
    if (permille > 1000) permille = 1000;
    std::lock_guard<std::mutex> lk(mu_);
    loss_permille_ = permille;
    for (auto& lf : links_)
        lf->drop_permille.store(permille, std::memory_order_relaxed);
}

void VirtualNetwork::partition(const std::set<int>& side_a) {
    std::lock_guard<std::mutex> lk(mu_);
    partition_a_ = side_a;
    for (auto& lf : links_) {
        const bool blocked = link_blocked_locked(lf->group0, lf->group1);
        lf->ab.store(!blocked, std::memory_order_relaxed);
        lf->ba.store(!blocked, std::memory_order_relaxed);
    }
}

void VirtualNetwork::heal() {
    std::lock_guard<std::mutex> lk(mu_);
    partition_a_.clear();
    for (auto& lf : links_) {
        lf->ab.store(true, std::memory_order_relaxed);
        lf->ba.store(true, std::memory_order_relaxed);
    }
}

// ── VirtualAcceptor ──────────────────────────────────────────────────────────

VirtualAcceptor::VirtualAcceptor(VirtualNetwork& net, VirtualEventLoop& loop,
                                 uint16_t port, bool /*localhost_only*/,
                                 int group)
    : net_(net), port_(port) {
    state_ = net_.register_listener(port_, loop, group);   // may assign port_ (0)
}

VirtualAcceptor::~VirtualAcceptor() {
    net_.unregister_listener(state_);
}

void VirtualAcceptor::async_accept(AcceptCb cb) {
    net_.arm_accept(state_, std::move(cb));
}

// ── VirtualTransport ─────────────────────────────────────────────────────────

VirtualTransport::VirtualTransport(VirtualEventLoop& loop, VirtualNetwork& net)
    : loop_(loop), net_(net) {}

VirtualTransport::~VirtualTransport() {
    // Queued connects hold loop_ by pointer; remove them before the loop
    // can die (the tracked-connect-helper join of the native transports,
    // realized as a registry sweep — callbacks dropped, never invoked).
    net_.cancel_connects(this);
}

std::unique_ptr<Acceptor> VirtualTransport::listen(uint16_t port,
                                                   bool localhost_only) {
    return std::make_unique<VirtualAcceptor>(net_, loop_, port,
                                             localhost_only, group_);
}

void VirtualTransport::async_connect(const std::string& /*host*/,
                                     uint16_t port, ConnectCb cb) {
    net_.connect(port, loop_, group_, this, std::move(cb));
}

VirtualNetwork& VirtualTransport::default_network() {
    static VirtualNetwork net;
    return net;
}

} // namespace determ::net
