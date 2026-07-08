// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// LoopTimer — THE net::Timer implementation, a thin id-holder over any
// EventLoop's timer service (event_loop.hpp timer_schedule/timer_cancel,
// which every backend delegates to the shared net::TimerService). This
// replaced the per-backend IocpTimer/ReactorTimer pair, which were
// byte-identical except for the concrete loop type — the timer never needed
// backend knowledge, only scheduling. Working over the ABSTRACT loop is
// also what lets Node hold timers against its injected EventLoop& (the
// transport/loop injection seam).
//
// Contract (net/timer.hpp): on_expire runs on a loop thread ONLY on clean
// expiry; cancel() or a re-arm before firing suppresses it. Not thread-safe
// per-object; the loop's timer service is internally locked.
#pragma once
#include <determ/net/timer.hpp>
#include <determ/net/event_loop.hpp>

namespace determ::net {

class LoopTimer final : public Timer {
public:
    explicit LoopTimer(EventLoop& loop) : loop_(loop) {}
    ~LoopTimer() override { cancel(); }

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
    EventLoop& loop_;
    uint64_t   current_ = 0;
};

} // namespace determ::net
