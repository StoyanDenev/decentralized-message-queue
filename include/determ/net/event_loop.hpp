// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// net::EventLoop — the daemon event-loop slice of the minix net seam
// (docs/proofs/MinixTacticalProfile.md §4). The loop services async
// completions (sockets, timers) and executes posted callbacks. Backends:
// IocpEventLoop (Windows completion port) and ReactorEventLoop (POSIX
// epoll), selected by net/native.hpp; asio is DELETED (minix §7 step 4).
// UNCONDITIONAL — not gated on any build profile (minix is the long-term
// architecture, not a TACTICAL-profile switch).
#pragma once
#include <chrono>
#include <cstdint>
#include <functional>

namespace determ::net {

class EventLoop {
public:
    virtual ~EventLoop() = default;

    // Service the loop until stop() is called. MULTI-THREAD contract: run()
    // may be called concurrently from N worker threads, all servicing the same
    // loop (the io_context / IOCP-completion-port model — a native epoll
    // backend must provide the same property).
    virtual void run() = 0;

    // Release every thread blocked in run(). Idempotent.
    virtual void stop() = 0;

    // Queue fn for execution on a loop thread (never inline in the caller).
    virtual void post(std::function<void()> fn) = 0;

    // ── Timer service (backs net::LoopTimer) ────────────────────────────
    // Schedule fn to be post()ed after `delay`; returns an id that
    // timer_cancel suppresses if it fires first. Every backend delegates to
    // the shared net::TimerService (timer_service.hpp), so the suppression
    // window is uniform: a cancel racing the exact expiry moment may lose —
    // the seam contract tests use unreachable deadlines for their cancel
    // assertions. Interface-level so consumers holding an abstract
    // EventLoop& (Node's injection seam, LoopTimer) can schedule without
    // knowing the concrete backend.
    virtual uint64_t timer_schedule(std::chrono::milliseconds delay,
                                    std::function<void()> fn) = 0;
    virtual void     timer_cancel(uint64_t id) = 0;
};

} // namespace determ::net
