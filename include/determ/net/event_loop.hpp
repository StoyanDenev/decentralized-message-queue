// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// net::EventLoop — the daemon event-loop slice of the minix net seam
// (docs/proofs/MinixTacticalProfile.md §4; slice 2 after net::Timer). The loop
// services async completions (timers, and eventually sockets) and executes
// posted callbacks. AsioEventLoop (net/asio_event_loop.hpp) is today's backend;
// the future minix native backends (IOCP completion port on Windows,
// epoll/kqueue on POSIX) implement the SAME interface, at which point asio is
// dropped. UNCONDITIONAL — not gated on any build profile (minix is the
// long-term architecture, not a TACTICAL-profile switch).
#pragma once
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
};

} // namespace determ::net
