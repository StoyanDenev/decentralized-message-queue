// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// ReactorEventLoop — the native POSIX backend for net::EventLoop (minix
// §4.5, epoll today; the kqueue policy split happens when a BSD/macOS gate
// exists). One epoll instance services everything: socket readiness
// (ReactorTransport), posted closures (an EFD_SEMAPHORE eventfd — each
// post() wakes exactly one run() thread, which pops exactly one closure),
// and timer expiries via the shared net::TimerService deadline thread.
//
// run() keeps the interface's multi-thread contract: N worker threads all
// blocked in epoll_wait on the same instance. Socket interest is registered
// ONE-SHOT (EPOLLONESHOT) — the §4.5 requirement that makes N-thread
// dispatch safe: two threads' epoll_wait calls CAN return the same fd
// simultaneously under plain level-triggering, silently splitting one
// logical exactly-N read across threads (a byte-scrambling, error-free
// corruption — the worst failure class for consensus-carrying framing).
// One-shot disables the fd after each delivery; the handler re-arms.
//
// Handler dispatch is registry-based (fd → shared_ptr<ReactorHandler> under
// a mutex): a looked-up handler is pinned for the duration of its on_event
// call, so a concurrent close()/deregister can never free it mid-dispatch,
// and a stale event for a deregistered (or reused) fd either finds no
// registration or finds the NEW handler — which must tolerate spurious
// wakeups (both of this file's handlers check their own parked-op state
// under their own lock and ignore events they didn't ask for). This is the
// §4.5 "close() races a real completion" serialization IOCP gets from the
// kernel and POSIX builds by hand.
//
// stop() is permanent (no restart), matching the IocpEventLoop contract.
// This header is OS-include-free (§4.5 layout rule): fds are plain ints;
// all <sys/epoll.h>/<sys/eventfd.h> usage lives in src/net/*.cpp.
#pragma once
#include <determ/net/event_loop.hpp>
#include <determ/net/timer_service.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>

namespace determ::net {

// What the loop calls when a registered fd turns ready. `events` is the
// loop's OS-free readiness mask (kEventRead/kEventWrite/kEventError below),
// NOT raw epoll bits. Implementations must tolerate spurious calls.
struct ReactorHandler {
    virtual ~ReactorHandler() = default;
    virtual void on_event(uint32_t events) = 0;
};

// OS-free readiness/interest flags (translated to EPOLLIN/EPOLLOUT/… in the
// .cpp). kEventError is delivery-only (never requested): the handler's next
// syscall surfaces the actual error.
constexpr uint32_t kEventRead  = 0x1;
constexpr uint32_t kEventWrite = 0x2;
constexpr uint32_t kEventError = 0x4;

class ReactorEventLoop final : public EventLoop {
public:
    ReactorEventLoop();               // epoll + eventfd; throws on failure
    ~ReactorEventLoop() override;     // stop + timer shutdown + close fds;
                                      // undelivered posts are dropped (the
                                      // never-dispatched-handler semantics)

    ReactorEventLoop(const ReactorEventLoop&) = delete;
    ReactorEventLoop& operator=(const ReactorEventLoop&) = delete;

    void run() override;
    void stop() override;
    void post(std::function<void()> fn) override;

    // ── fd registry (backs ReactorTransport) ────────────────────────────
    // arm(): register (first call) or re-arm (subsequent) one-shot interest
    // for fd; `interest` is kEventRead|kEventWrite. The handler is pinned by
    // the registry until deregister(). deregister() is idempotent and safe
    // while another thread is mid-dispatch for the same fd (the dispatch
    // holds its own shared_ptr pin).
    void arm(int fd, uint32_t interest, std::shared_ptr<ReactorHandler> h);
    void deregister(int fd);

    // ── Timer service (EventLoop interface; backs net::LoopTimer) ───────
    uint64_t timer_schedule(std::chrono::milliseconds delay,
                            std::function<void()> fn) override {
        return timers_.schedule(delay, std::move(fn));
    }
    void timer_cancel(uint64_t id) override { timers_.cancel(id); }

private:
    int               epfd_   = -1;
    int               wake_fd_ = -1;   // EFD_SEMAPHORE eventfd
    std::atomic<bool> stopped_{false};
    std::atomic<int>  threads_in_run_{0};   // stop() writes one unit each

    std::mutex                        reg_mu_;
    std::map<int, std::shared_ptr<ReactorHandler>> registry_;

    std::mutex                        post_mu_;
    std::deque<std::function<void()>> post_q_;

    TimerService timers_{[this](std::function<void()> fn) {
        post(std::move(fn));
    }};
};

} // namespace determ::net
