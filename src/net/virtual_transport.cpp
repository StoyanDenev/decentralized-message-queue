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
// holding Pair::mu ON PURPOSE: a post can target the PEER's loop, and the
// peer's teardown path (close() in ~VirtualConnection, which runs before
// the peer destroys its loop) serializes behind the same mutex — so the
// target loop cannot be destroyed mid-post. This does not violate the
// reactor's completion-outside-lock discipline: post() only ENQUEUES (it
// takes the loop's queue mutex briefly, a leaf lock); the completion is
// INVOKED later on a loop thread with no pair lock held. Lock order is
// strictly {network mu_ | pair mu} → loop queue mutex, never the reverse.
#include <determ/net/virtual_transport.hpp>

#include <algorithm>
#include <stdexcept>

namespace determ::net {

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

VirtualEventLoop::~VirtualEventLoop() {
    stop();
    // Stop the timer thread BEFORE dropping the queue so no timer post
    // races the teardown (the reactor-destructor ordering).
    timers_.shutdown();
    std::lock_guard<std::mutex> lk(mu_);
    q_.clear();   // undelivered posts dropped without invoking — the
                  // never-dispatched-handler semantics all backends share
}

void VirtualEventLoop::run() {
    std::unique_lock<std::mutex> lk(mu_);
    for (;;) {
        cv_.wait(lk, [this] { return stopped_ || !q_.empty(); });
        if (stopped_) return;
        std::function<void()> fn = std::move(q_.front());
        q_.pop_front();
        lk.unlock();
        // May block for a session's lifetime (RpcServer's posted-closure
        // session model) — other run() threads keep servicing the queue.
        fn();
        lk.lock();
    }
}

void VirtualEventLoop::stop() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        stopped_ = true;   // permanent — run() never resumes (contract)
    }
    cv_.notify_all();
}

void VirtualEventLoop::post(std::function<void()> fn) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        // Post-after-stop still enqueues; the closure is dropped at
        // destruction (the reactor's failed-wakeup drop semantics).
        q_.push_back(std::move(fn));
    }
    cv_.notify_one();
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
        VirtualEventLoop*   loop = nullptr;  // where THIS side's completions run
        std::deque<uint8_t> inbox;           // bytes awaiting this side's reads
        ParkedRead          rd;
        bool                closed = false;
    };

    std::mutex              mu;   // serializes everything below (both sides)
    std::condition_variable cv;   // wakes read_line waiters on either end
    Side                    side[2];
    std::string             endpoint;   // "127.0.0.1:<pseudo-port>", both ends
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
        // Buffered complete lines are delivered even after close() — the
        // reactor's carry_-scan-before-closed-check ordering. The inbox IS
        // the carry: bytes past '\n' simply stay queued.
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
        VirtualEventLoop*    loop;    // connector's loop; guaranteed alive —
                                      // ~VirtualTransport cancels its own
                                      // entries before its loop can die
        VirtualTransport*    owner;   // cancellation key for the above
        Transport::ConnectCb cb;
    };

    VirtualEventLoop*          loop = nullptr;   // acceptor's loop
    uint16_t                   port = 0;
    bool                       dead = false;
    Acceptor::AcceptCb         parked;    // one-shot; the consumer re-arms
    std::deque<PendingConnect> pending;   // connects awaiting async_accept
};

VirtualNetwork::~VirtualNetwork() = default;

std::shared_ptr<VirtualNetwork::Listener>
VirtualNetwork::register_listener(uint16_t& port, VirtualEventLoop& loop) {
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
    auto l  = std::make_shared<Listener>();
    l->loop = &loop;
    l->port = port;
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
        auto [acc, conn] = make_pair_locked(*l->loop, *pc.loop);
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
                             VirtualTransport* owner,
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
        auto [acc, conn] = make_pair_locked(*l->loop, caller_loop);
        std::shared_ptr<Connection> accepted  = std::move(acc);
        std::shared_ptr<Connection> connected = std::move(conn);
        l->loop->post([acb = std::move(acb), accepted] { acb({}, accepted); });
        caller_loop.post([cb = std::move(cb), connected] {
            cb({}, connected);
        });
    } else {
        // Park the connect until async_accept is called (TCP backlog
        // analogue; refused if the acceptor is destroyed first).
        l->pending.push_back(
            Listener::PendingConnect{&caller_loop, owner, std::move(cb)});
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
VirtualNetwork::make_pair_locked(VirtualEventLoop& accept_loop,
                                 VirtualEventLoop& connect_loop) {
    auto P = std::make_shared<VirtualConnection::Pair>();
    P->side[0].loop = &accept_loop;
    P->side[1].loop = &connect_loop;
    // Unique pseudo-port per pair so consumers that parse "ip:port"
    // (RpcServer's rfind(':') strip, gossip's per-IP bucket) behave
    // identically; wraps within [50000, 65535].
    const uint16_t pseudo = next_pseudo_port_;
    next_pseudo_port_ = next_pseudo_port_ == 65535
                            ? static_cast<uint16_t>(50000)
                            : static_cast<uint16_t>(next_pseudo_port_ + 1);
    P->endpoint = "127.0.0.1:" + std::to_string(pseudo);
    return {std::make_shared<VirtualConnection>(P, 0),
            std::make_shared<VirtualConnection>(P, 1)};
}

// ── VirtualAcceptor ──────────────────────────────────────────────────────────

VirtualAcceptor::VirtualAcceptor(VirtualNetwork& net, VirtualEventLoop& loop,
                                 uint16_t port, bool /*localhost_only*/)
    : net_(net), port_(port) {
    state_ = net_.register_listener(port_, loop);   // may assign port_ (0)
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
                                             localhost_only);
}

void VirtualTransport::async_connect(const std::string& /*host*/,
                                     uint16_t port, ConnectCb cb) {
    net_.connect(port, loop_, this, std::move(cb));
}

VirtualNetwork& VirtualTransport::default_network() {
    static VirtualNetwork net;
    return net;
}

} // namespace determ::net
