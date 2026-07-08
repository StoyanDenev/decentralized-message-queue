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
