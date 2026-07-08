// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// ReactorTimer — the native POSIX backend for net::Timer (minix §4.5), the
// exact mirror of IocpTimer: a thin id-holder over the loop's shared
// TimerService. on_expire runs on a loop thread ONLY on clean expiry;
// cancel() or a re-arm before firing suppresses it. Not thread-safe
// per-object — same as AsioTimer/IocpTimer.
#pragma once
#include <determ/net/timer.hpp>
#include <determ/net/reactor_event_loop.hpp>

namespace determ::net {

class ReactorTimer final : public Timer {
public:
    explicit ReactorTimer(ReactorEventLoop& loop) : loop_(loop) {}
    ~ReactorTimer() override { cancel(); }

    void arm(std::chrono::milliseconds delay,
             std::function<void()> on_expire) override {
        loop_.timer_cancel(current_);   // re-arm supersedes
        current_ = loop_.timer_schedule(delay, std::move(on_expire));
    }

    void cancel() override {
        loop_.timer_cancel(current_);   // no-op for id 0 / already-fired ids
        current_ = 0;
    }

private:
    ReactorEventLoop& loop_;
    uint64_t          current_ = 0;
};

} // namespace determ::net
