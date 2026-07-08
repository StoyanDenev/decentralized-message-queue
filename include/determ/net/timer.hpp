// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// net::Timer — the deadline-timer slice of the minix net::Transport seam
// (docs/proofs/MinixTacticalProfile.md §4). One-shot, proactor-style: arm(delay,
// on_expire) schedules a callback that runs on the owning event loop ONLY on a
// clean expiry; a cancel() (or a re-arm) before firing suppresses it — the asio
// `if (ec) return;` idiom made the interface contract.
//
// Backends: IocpTimer (Windows) and ReactorTimer (POSIX epoll), selected by
// net/native.hpp — both over the shared net::TimerService deadline engine.
// asio is DELETED (minix §7 step 4). UNCONDITIONAL — not gated on any build
// profile (minix is the long-term architecture, not a TACTICAL-profile
// switch).
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
