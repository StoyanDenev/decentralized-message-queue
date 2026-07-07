// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// net::Timer — the deadline-timer slice of the minix net::Transport seam
// (docs/proofs/MinixTacticalProfile.md §4). One-shot, proactor-style: arm(delay,
// on_expire) schedules a callback that runs on the owning event loop ONLY on a
// clean expiry; a cancel() (or a re-arm) before firing suppresses it — the asio
// `if (ec) return;` idiom made the interface contract.
//
// This interface is ASIO-FREE. AsioTimer (net/asio_timer.hpp) is today's backend;
// the future minix native backends (IOCP on Windows, epoll/kqueue on POSIX)
// implement the SAME interface, at which point asio is dropped. UNCONDITIONAL —
// not gated on any build profile (minix is the long-term architecture, not a
// TACTICAL-profile switch).
#pragma once
#include <chrono>
#include <functional>

namespace determ::net {

class Timer {
public:
    virtual ~Timer() = default;

    // Arm the timer to fire once after `delay`. `on_expire` runs on the owning
    // event loop ONLY if the timer expires cleanly; if cancel() (or a re-arm)
    // fires first, `on_expire` is NOT called.
    virtual void arm(std::chrono::milliseconds delay,
                     std::function<void()> on_expire) = 0;

    // Cancel a pending arm(). Idempotent; safe if not currently armed.
    virtual void cancel() = 0;
};

} // namespace determ::net
