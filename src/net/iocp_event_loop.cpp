// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// IocpEventLoop implementation (minix §4.5 increment 1). Windows-only TU —
// pruned from SOURCES on other platforms by CMakeLists.txt.
#ifdef _WIN32

#include <determ/net/iocp_event_loop.hpp>
#include "iocp_detail.hpp"
#include <stdexcept>
#include <utility>

namespace determ::net {

using detail::OverlappedOp;
using detail::kKeyOp;
using detail::kKeyStop;

namespace detail {
void winsock_init() {
    // Function-local static: thread-safe once-init (C++11 magic statics).
    static const int rc = [] {
        WSADATA wsa;
        return ::WSAStartup(MAKEWORD(2, 2), &wsa);
    }();
    if (rc != 0) throw std::runtime_error("IocpEventLoop: WSAStartup failed");
}
} // namespace detail

namespace {

// post()'s packet: a heap closure dispatched through the same port as I/O.
struct PostOp {
    OverlappedOp          base;
    std::function<void()> fn;

    static void complete(OverlappedOp* self, DWORD, DWORD) {
        auto* op = reinterpret_cast<PostOp*>(self);
        auto  f  = std::move(op->fn);
        delete op;
        f();
    }
    static void abandon(OverlappedOp* self) {
        delete reinterpret_cast<PostOp*>(self);
    }
};

} // namespace

IocpEventLoop::IocpEventLoop() {
    detail::winsock_init();
    port_ = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0,
                                     /*NumberOfConcurrentThreads=*/0);
    if (!port_)
        throw std::runtime_error("IocpEventLoop: CreateIoCompletionPort failed");
}

IocpEventLoop::~IocpEventLoop() {
    stop();
    {
        std::lock_guard<std::mutex> lk(timer_mu_);
        timer_shutdown_ = true;
    }
    timer_cv_.notify_all();
    if (timer_thread_.joinable()) timer_thread_.join();

    // Drain: free still-queued op packets WITHOUT invoking user callbacks
    // (asio's never-dispatched-handler semantics). In-flight socket I/O must
    // have completed before destruction — ops pin their connections, and
    // consumers join their run() threads first. One 50ms grace re-poll after
    // the queue first reads empty: an ERROR_OPERATION_ABORTED packet from a
    // just-closed socket is queued ASYNCHRONOUSLY by the kernel and can
    // still be propagating when the 0-timeout poll sees empty — dropping it
    // at CloseHandle would leak its op.
    bool graced = false;
    for (;;) {
        DWORD        bytes   = 0;
        ULONG_PTR    key     = 0;
        LPOVERLAPPED pov     = nullptr;
        DWORD        timeout = 0;
        BOOL ok = ::GetQueuedCompletionStatus(port_, &bytes, &key, &pov,
                                              timeout);
        if (!pov) {
            if (!ok) {
                // Queue reads empty (WAIT_TIMEOUT) or the port is dead.
                if (graced) break;
                graced = true;
                DWORD        b2 = 0;
                ULONG_PTR    k2 = 0;
                LPOVERLAPPED p2 = nullptr;
                BOOL ok2 = ::GetQueuedCompletionStatus(port_, &b2, &k2, &p2,
                                                       50);
                if (!p2) {
                    if (!ok2) break;   // still empty after the grace window
                    continue;          // late stop packet — discard
                }
                auto* op2 = reinterpret_cast<OverlappedOp*>(p2);
                if (op2->on_abandon) op2->on_abandon(op2);
                continue;              // something arrived — keep draining
            }
            continue;   // stop packet (null ov) — discard
        }
        graced   = false;   // real packet seen — reset the grace window
        auto* op = reinterpret_cast<OverlappedOp*>(pov);
        if (op->on_abandon) op->on_abandon(op);
    }
    ::CloseHandle(port_);
}

void IocpEventLoop::run() {
    threads_in_run_.fetch_add(1);
    struct Dec {
        std::atomic<int>& c;
        ~Dec() { c.fetch_sub(1); }
    } dec{threads_in_run_};

    for (;;) {
        if (stopped_.load()) return;
        DWORD        bytes = 0;
        ULONG_PTR    key   = 0;
        LPOVERLAPPED pov   = nullptr;
        BOOL ok = ::GetQueuedCompletionStatus(port_, &bytes, &key, &pov,
                                              INFINITE);
        if (key == kKeyStop) return;
        if (!pov) {
            // GQCS itself failed with no packet (port closed under us).
            if (!ok) return;
            continue;
        }
        DWORD err = ok ? 0 : ::GetLastError();
        auto* op  = reinterpret_cast<OverlappedOp*>(pov);
        op->on_complete(op, bytes, err);
    }
}

void IocpEventLoop::stop() {
    if (stopped_.exchange(true)) return;
    // One wakeup per thread currently inside run(); each dequeued kKeyStop
    // packet releases exactly one. Late run() entrants see stopped_ before
    // blocking; leftover packets are discarded by the destructor's drain.
    int n = threads_in_run_.load();
    for (int i = 0; i < n; ++i)
        ::PostQueuedCompletionStatus(port_, 0, kKeyStop, nullptr);
}

void IocpEventLoop::post(std::function<void()> fn) {
    auto* op            = new PostOp;
    op->fn              = std::move(fn);
    op->base.on_complete = &PostOp::complete;
    op->base.on_abandon  = &PostOp::abandon;
    if (!::PostQueuedCompletionStatus(port_, 0, kKeyOp, &op->base.ov))
        delete op;   // port dead — drop, matching a stopped io_context
}

// ── Timer service ────────────────────────────────────────────────────────────

uint64_t IocpEventLoop::timer_schedule(std::chrono::milliseconds delay,
                                       std::function<void()> fn) {
    std::lock_guard<std::mutex> lk(timer_mu_);
    uint64_t id = next_timer_id_++;
    timer_entries_.push_back(
        {std::chrono::steady_clock::now() + delay, id, std::move(fn)});
    if (!timer_thread_.joinable())
        timer_thread_ = std::thread([this] { timer_thread_body(); });
    timer_cv_.notify_all();
    return id;
}

void IocpEventLoop::timer_cancel(uint64_t id) {
    if (id == 0) return;
    std::lock_guard<std::mutex> lk(timer_mu_);
    for (auto it = timer_entries_.begin(); it != timer_entries_.end(); ++it) {
        if (it->id == id) {
            timer_entries_.erase(it);
            break;
        }
    }
    // Already-fired (or never-existed) ids: nothing to remove — the
    // suppression window closed when the entry was popped for posting,
    // exactly the asio waitable-timer race documented in the header.
}

void IocpEventLoop::timer_thread_body() {
    std::unique_lock<std::mutex> lk(timer_mu_);
    while (!timer_shutdown_) {
        if (timer_entries_.empty()) {
            timer_cv_.wait(lk);
            continue;
        }
        auto next = timer_entries_.front().deadline;
        for (const auto& e : timer_entries_)
            if (e.deadline < next) next = e.deadline;

        if (std::chrono::steady_clock::now() < next) {
            timer_cv_.wait_until(lk, next);
            continue;   // re-evaluate: entries may have changed under the wait
        }

        // Pop everything due, post outside the lock (post() never blocks,
        // but holding timer_mu_ across foreign code invites lock-order knots).
        auto now = std::chrono::steady_clock::now();
        std::vector<std::function<void()>> due;
        for (auto it = timer_entries_.begin(); it != timer_entries_.end();) {
            if (it->deadline <= now) {
                due.push_back(std::move(it->fn));
                it = timer_entries_.erase(it);
            } else {
                ++it;
            }
        }
        lk.unlock();
        for (auto& f : due) post(std::move(f));
        lk.lock();
    }
}

} // namespace determ::net

#endif // _WIN32
