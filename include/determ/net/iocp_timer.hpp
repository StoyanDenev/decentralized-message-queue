// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// IocpTimer — the native Windows backend for net::Timer (minix §4.5,
// increment 1), a thin id-holder over IocpEventLoop's timer service. Same
// contract as AsioTimer: on_expire runs on a loop thread ONLY on clean
// expiry; cancel() or a re-arm before firing suppresses it (the service
// removes the pending entry, so the superseded callback is simply never
// posted). Not thread-safe per-object — same as AsioTimer; the service's
// internal lock protects cross-timer state.
#pragma once
#include <determ/net/timer.hpp>
#include <determ/net/iocp_event_loop.hpp>

namespace determ::net {

class IocpTimer final : public Timer {
public:
    explicit IocpTimer(IocpEventLoop& loop) : loop_(loop) {}
    ~IocpTimer() override { cancel(); }

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
    IocpEventLoop& loop_;
    uint64_t       current_ = 0;
};

} // namespace determ::net
