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
    std::atomic<uint32_t> dup_permille{0};   // 0 = no duplication
    // Fault-delivery WITNESS counters (inc.9): how many frames this link
    // actually dropped / partition-blocked / duplicated. Test-facing
    // observability only — never read on the delivery path, so they cannot
    // change behavior; relaxed atomics because the threaded harnesses sum
    // them from the harness thread while loop threads write. They exist so
    // a fault phase can assert its fault FIRED (delta > 0): a silently
    // no-opped fault (a zeroed roll, an always-open gate) otherwise greens
    // the phase vacuously — the clean network trivially satisfies liveness
    // and agreement. RED-on-mutant verified: zeroing the three fault
    // branches turns exactly the witness checks red.
    std::atomic<uint64_t> n_dropped{0};
    std::atomic<uint64_t> n_blocked{0};
    std::atomic<uint64_t> n_dup{0};
    std::atomic<uint64_t> n_delayed{0};
    // Per-link CONSTANT latency (inc.10). Derived from the link's IMMUTABLE
    // id via splitmix — deliberately NOT a fault-rng draw, so enabling
    // latency never perturbs the drop/dup draw streams (byte-invariance of
    // the other fault models) and assigning it to EXISTING links from the
    // harness thread races nothing (no rng touch outside Pair::mu).
    std::atomic<uint32_t> latency_ms{0};
    // Back-pointer for the delayed-delivery handoff; the network outlives
    // every transport (documented ctor contract), and pending entries pin
    // the Pair — never the reverse — so there is no cycle and no dangle.
    VirtualNetwork* net = nullptr;
    int      group0 = 0;   // accept-side group  (immutable)
    int      group1 = 0;   // connect-side group (immutable)
    uint64_t link_id = 0;  // the pseudo port; immutable latency-draw identity
    uint64_t rng    = 0;   // xorshift64 state; advanced under owning Pair::mu

    // The id-derived constant latency for a [min,max] configuration.
    static uint32_t latency_for(uint64_t id, uint32_t min_ms, uint32_t max_ms) {
        if (max_ms == 0 || max_ms < min_ms) return 0;
        uint64_t z = id + 0x9E3779B97F4A7C15ull;         // splitmix64
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z ^= z >> 31;
        const uint64_t span = static_cast<uint64_t>(max_ms - min_ms) + 1;
        return min_ms + static_cast<uint32_t>(z % span);
    }

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
    // Same draw discipline for the duplication model (caller holds the owning
    // Pair::mu; rolled only for frames that WILL be delivered). Rate 0
    // consumes no draw, so phases run before set_dup() replay byte-identically
    // whether or not a later phase enables duplication.
    bool roll_dup() {
        const uint32_t d = dup_permille.load(std::memory_order_relaxed);
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
    // inc.3: drain the VIRTUAL-time timer queue with the same move-out-under-
    // lock discipline. A self-owning timer — one whose only owner is its own
    // scheduled fn, e.g. the startup grace armed by a node driven via
    // start_external() and torn down BEFORE virtual time reaches its deadline
    // (an isolated / never-selected node in an A4 fault scenario) — runs
    // ~LoopTimer → timer_cancel(vtimers_) the instant its fn is destroyed. If
    // that destruction happened during the member-wise destruction of vtimers_,
    // the re-entrant cancel would erase() from the vector mid-destruction (UB).
    // Swapping the queue into a local under vt_mu_ and letting it destroy with
    // the lock RELEASED means any such re-entrant cancel locks vt_mu_ and scans
    // an already-empty vtimers_ (an idempotent no-op). Native-path loops keep
    // vtimers_ empty, so this is a two-empty-vector swap for them.
    std::vector<VTimer> drop_timers;
    {
        std::lock_guard<std::mutex> lk(vt_mu_);
        drop_timers.swap(vtimers_);
    }
    // `drop_timers` destroyed here, vt_mu_ released.
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

void VirtualEventLoop::run_until_idle() {
    // Deterministic single-thread drive (DeterministicSchedulerDesign.md §2).
    // run() with the cv.wait replaced by "empty => return": the CALLING thread
    // drains the ready FIFO to quiescence and returns. Re-posts a closure makes
    // while it runs land back in s.q and are picked up by the same loop (the
    // while re-tests q.empty() after each fn). No stop() needed; if the loop was
    // stopped, this returns without processing (run()'s stopped semantics).
    State& s = *st_;
    std::unique_lock<std::mutex> lk(s.mu);
    while (!s.stopped && !s.q.empty()) {
        std::function<void()> fn = std::move(s.q.front());
        s.q.pop_front();
        lk.unlock();
        fn();
        lk.lock();
    }
}

std::size_t VirtualEventLoop::run_ready(std::size_t max_closures) {
    // inc.3 bounded-step drive: like run_until_idle but caps the number of
    // ready closures processed, so a self-producing node's unbounded re-post
    // cascade can be advanced in inspectable batches instead of hanging a
    // drain-to-quiescence call. Same FIFO order; re-posts land at the back and
    // are eligible within the SAME call only if the cap has room.
    State& s = *st_;
    std::unique_lock<std::mutex> lk(s.mu);
    std::size_t ran = 0;
    while (!s.stopped && !s.q.empty() && ran < max_closures) {
        std::function<void()> fn = std::move(s.q.front());
        s.q.pop_front();
        lk.unlock();
        fn();
        lk.lock();
        ++ran;
    }
    return ran;
}

void VirtualEventLoop::stop() {
    {
        std::lock_guard<std::mutex> lk(st_->mu);
        st_->stopped = true;   // permanent — run() never resumes (contract)
    }
    st_->cv.notify_all();
}

// ── Virtual-time timer source (DeterministicSchedulerDesign.md §2b, inc.2) ────
// Additive + opt-in: the DEFAULT (virtual_time_ == false) path is byte-identical
// to the shipped inline forms — it delegates straight to TimerService, so the
// native timer behaviour (test-net-virtual) is untouched. Only enable_virtual_time()
// flips a loop onto the deterministic queue, and only a harness holding the
// concrete VirtualEventLoop can call it.

uint64_t VirtualEventLoop::timer_schedule(std::chrono::milliseconds delay,
                                          std::function<void()> fn) {
    if (virtual_time_) {
        // Deterministic path: insert into the loop-local ordered queue keyed on
        // virtual `now`; the TimerService/steady_clock/timer thread are never
        // touched. Single-threaded by contract, but guarded so a stray
        // cross-thread arm cannot corrupt the vector.
        std::lock_guard<std::mutex> lk(vt_mu_);
        uint64_t id = next_vtimer_id_++;
        uint64_t d  = delay.count() < 0 ? 0
                                        : static_cast<uint64_t>(delay.count());
        vtimers_.push_back(
            VTimer{virtual_now_ms_ + d, next_vtimer_seq_++, id, std::move(fn)});
        return id;
    }
    // Native (default) path — record that it was taken so a later
    // enable_virtual_time() can refuse the mixed state (see the guard there).
    native_timer_used_.store(true, std::memory_order_relaxed);
    return timers_.schedule(delay, std::move(fn));
}

void VirtualEventLoop::timer_cancel(uint64_t id) {
    if (virtual_time_) {
        std::lock_guard<std::mutex> lk(vt_mu_);
        for (auto it = vtimers_.begin(); it != vtimers_.end(); ++it) {
            if (it->id == id) { vtimers_.erase(it); return; }
        }
        return;   // already fired / unknown id — cancel is idempotent
    }
    timers_.cancel(id);
}

void VirtualEventLoop::enable_virtual_time() {
    // Flip the source BEFORE any timer is scheduled. timers_ (the TimerService)
    // is left dormant — it lazily starts its thread only on first schedule(),
    // which the virtual path never calls, so virtual mode spawns zero threads.
    // Guard the documented precondition instead of only asserting it in prose:
    // enabling AFTER a native timer was armed would leave that timer on the
    // wall-clock thread (nondeterministic fire) while a later cancel(id) hits
    // the wrong queue (aliased id spaces). Turn that silent determinism break
    // into a loud, immediate error.
    if (native_timer_used_.load(std::memory_order_relaxed)) {
        throw std::logic_error(
            "VirtualEventLoop::enable_virtual_time() called after a native timer "
            "was already scheduled; call it before any timer op");
    }
    virtual_time_ = true;
}

bool VirtualEventLoop::advance_to_next_timer() {
    std::function<void()> fn;
    {
        std::lock_guard<std::mutex> lk(vt_mu_);
        if (vtimers_.empty()) return false;
        // Earliest (deadline, seq): a stable total order (§3.3) — same-deadline
        // ties fire in schedule order, so a replay from the same schedule fires
        // the same sequence.
        std::size_t best = 0;
        for (std::size_t i = 1; i < vtimers_.size(); ++i) {
            const VTimer& a = vtimers_[i];
            const VTimer& b = vtimers_[best];
            if (a.deadline_ms < b.deadline_ms ||
                (a.deadline_ms == b.deadline_ms && a.seq < b.seq)) best = i;
        }
        // Virtual `now` never moves backwards: a timer armed in the past (e.g. a
        // zero-delay re-arm at the current instant) fires at the current now.
        if (vtimers_[best].deadline_ms > virtual_now_ms_)
            virtual_now_ms_ = vtimers_[best].deadline_ms;
        fn = std::move(vtimers_[best].fn);
        vtimers_.erase(vtimers_.begin() + static_cast<std::ptrdiff_t>(best));
    }
    // Outside the lock: the callback may re-arm/cancel timers or post()
    // closures (same discipline as run()'s invoke-outside-lock).
    if (fn) fn();
    return true;
}

std::size_t VirtualEventLoop::pending_timer_count() const {
    std::lock_guard<std::mutex> lk(vt_mu_);
    return vtimers_.size();
}

bool VirtualEventLoop::next_virtual_deadline_ms(uint64_t& out) const {
    std::lock_guard<std::mutex> lk(vt_mu_);
    if (vtimers_.empty()) return false;
    // The min DEADLINE — identical to the (deadline, seq) winner
    // advance_to_next_timer fires to, since seq only breaks deadline ties and
    // the global scheduler compares deadlines across loops.
    uint64_t best = vtimers_[0].deadline_ms;
    for (std::size_t i = 1; i < vtimers_.size(); ++i)
        if (vtimers_[i].deadline_ms < best) best = vtimers_[i].deadline_ms;
    out = best;
    return true;
}

void VirtualEventLoop::set_virtual_now_ms(uint64_t now_ms) {
    std::lock_guard<std::mutex> lk(vt_mu_);
    if (now_ms > virtual_now_ms_) virtual_now_ms_ = now_ms;   // forward-only
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
    // The gate-then-roll order (and roll-only-if-open) is the same
    // short-circuit the original combined condition had; the split exists
    // only to attribute the witness counters (inc.9).
    if (P.link && !P.link->gate(side_)) {
        P.link->n_blocked.fetch_add(1, std::memory_order_relaxed);
        me.loop->post([cb = std::move(cb), n] { cb({}, n); });
        return;
    }
    if (P.link && P.link->roll_drop()) {
        P.link->n_dropped.fetch_add(1, std::memory_order_relaxed);
        me.loop->post([cb = std::move(cb), n] { cb({}, n); });
        return;
    }
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    // Fault model: a duplicated frame lands in the inbox TWICE back-to-back
    // (whole-frame granularity ⇒ the receiver reads the same complete Peer
    // message a second time — the S-047 redelivery class; see set_dup).
    // Only delivered frames roll: a dropped frame was never sent twice. The
    // roll happens HERE regardless of latency so the per-link draw stream
    // is identical with and without the latency model.
    const bool dup = P.link && P.link->roll_dup();
    if (dup) P.link->n_dup.fetch_add(1, std::memory_order_relaxed);
    const uint32_t lat =
        P.link ? P.link->latency_ms.load(std::memory_order_relaxed) : 0;
    if (lat > 0 && P.link->net && P.link->net->drive_attached()) {
        // inc.10: the frame is held by the NETWORK until its arrival time;
        // the write still completes NOW (bytes left the host). A dup copy
        // shares the arrival with a consecutive seq — same-link order
        // preserved, though other deliveries/drains may run between the
        // two delivery events (unlike the immediate path's contiguity).
        // Gated on drive_attached(): with no deterministic drive, nothing
        // ever fires pending entries, so latency MUST fall through to
        // immediate delivery (review finding — the silent-blackhole trap).
        P.link->n_delayed.fetch_add(1, std::memory_order_relaxed);
        P.link->net->schedule_delivery(pair_, 1 - side_, p, n, lat);
        if (dup)
            P.link->net->schedule_delivery(pair_, 1 - side_, p, n, lat);
        me.loop->post([cb = std::move(cb), n] { cb({}, n); });
        return;
    }
    peer.inbox.insert(peer.inbox.end(), p, p + n);
    if (dup) peer.inbox.insert(peer.inbox.end(), p, p + n);
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
    // consumer runs under fault injection; kept for parity (witness
    // counters included).
    if (P.link && !P.link->gate(side_)) {
        P.link->n_blocked.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    if (P.link && P.link->roll_drop()) {
        P.link->n_dropped.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    // Duplication + latency parity with async_write (sync consumers are off
    // the gossip path; kept so a future sync consumer under fault injection
    // behaves consistently). NOTE: a latencied sync frame delivers only
    // when the deterministic drive fires it — a sync reader blocking in
    // read_line under the threaded model would wait forever, which is why
    // latency is a deterministic-drive-only knob.
    const bool dup = P.link && P.link->roll_dup();
    if (dup) P.link->n_dup.fetch_add(1, std::memory_order_relaxed);
    const uint32_t lat =
        P.link ? P.link->latency_ms.load(std::memory_order_relaxed) : 0;
    if (lat > 0 && P.link->net && P.link->net->drive_attached()) {
        P.link->n_delayed.fetch_add(1, std::memory_order_relaxed);
        P.link->net->schedule_delivery(pair_, 1 - side_, p, n, lat);
        if (dup)
            P.link->net->schedule_delivery(pair_, 1 - side_, p, n, lat);
        return true;
    }
    peer.inbox.insert(peer.inbox.end(), p, p + n);
    if (dup) peer.inbox.insert(peer.inbox.end(), p, p + n);
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
    lf->dup_permille.store(dup_permille_, std::memory_order_relaxed);
    lf->net     = this;
    lf->link_id = pseudo;
    lf->latency_ms.store(
        LinkFlags::latency_for(pseudo, latency_min_ms_, latency_max_ms_),
        std::memory_order_relaxed);
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

VirtualNetwork::FaultCounts VirtualNetwork::fault_counts() {
    FaultCounts fc;
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& lf : links_) {
        fc.dropped    += lf->n_dropped.load(std::memory_order_relaxed);
        fc.blocked    += lf->n_blocked.load(std::memory_order_relaxed);
        fc.duplicated += lf->n_dup.load(std::memory_order_relaxed);
        fc.delayed    += lf->n_delayed.load(std::memory_order_relaxed);
    }
    return fc;
}

void VirtualNetwork::set_latency(uint32_t min_ms, uint32_t max_ms) {
    std::lock_guard<std::mutex> lk(mu_);
    latency_min_ms_ = min_ms;
    latency_max_ms_ = max_ms;
    // Assign each existing link its id-derived constant. No rng touch, no
    // Pair::mu needed — the atomics are the only cross-thread surface.
    for (auto& lf : links_)
        lf->latency_ms.store(
            LinkFlags::latency_for(lf->link_id, min_ms, max_ms),
            std::memory_order_relaxed);
}

void VirtualNetwork::schedule_delivery(
    std::shared_ptr<VirtualConnection::Pair> pair, int to_side,
    const uint8_t* data, std::size_t n, uint32_t latency_ms) {
    // Caller holds the owning Pair::mu (the allowed Pair::mu -> mu_ order).
    std::lock_guard<std::mutex> lk(mu_);
    PendingDelivery d;
    d.pair    = std::move(pair);
    d.to_side = to_side;
    d.bytes.assign(data, data + n);
    pending_.emplace(std::make_pair(net_now_ms_ + latency_ms,
                                    delivery_seq_++),
                     std::move(d));
}

void VirtualNetwork::set_virtual_now_ms(uint64_t now_ms) {
    std::lock_guard<std::mutex> lk(mu_);
    if (now_ms > net_now_ms_) net_now_ms_ = now_ms;
}

bool VirtualNetwork::next_delivery_ms(uint64_t& out) {
    std::lock_guard<std::mutex> lk(mu_);
    if (pending_.empty()) return false;
    out = pending_.begin()->first.first;
    return true;
}

void VirtualNetwork::flush_pending() {
    // Repeated deliver_next drains in (arrival, seq) order; each iteration
    // re-checks emptiness under mu_, so deliveries that would schedule new
    // pending entries (none today — delivery never sends) stay safe.
    for (;;) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (pending_.empty()) return;
        }
        deliver_next();
    }
}

std::size_t VirtualNetwork::latency_diversity() {
    std::lock_guard<std::mutex> lk(mu_);
    std::set<uint32_t> vals;
    for (auto& lf : links_)
        vals.insert(lf->latency_ms.load(std::memory_order_relaxed));
    return vals.size();
}

void VirtualNetwork::deliver_next() {
    // Pop under mu_, then RELEASE it before taking Pair::mu — taking both
    // would establish mu_ -> Pair::mu against the write path's
    // Pair::mu -> mu_ (schedule_delivery) and ABBA-deadlock the threaded
    // model; the pop-then-release discipline keeps the order one-way.
    PendingDelivery d;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (pending_.empty()) return;
        auto it = pending_.begin();
        d = std::move(it->second);
        pending_.erase(it);
    }
    VirtualConnection::Pair& P = *d.pair;
    std::lock_guard<std::mutex> lk(P.mu);
    VirtualConnection::Pair::Side& s = P.side[d.to_side];
    // A frame arriving after the destination closed is a packet after FIN —
    // silently discarded, exactly like the immediate path's send-time
    // peer.closed check, just evaluated at ARRIVAL time.
    if (s.closed) return;
    s.inbox.insert(s.inbox.end(), d.bytes.begin(), d.bytes.end());
    deliver_locked(P, s);
}

void VirtualNetwork::set_dup(uint32_t permille) {
    if (permille > 1000) permille = 1000;
    std::lock_guard<std::mutex> lk(mu_);
    dup_permille_ = permille;
    for (auto& lf : links_)
        lf->dup_permille.store(permille, std::memory_order_relaxed);
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
