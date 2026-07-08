// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// AsioTimer — today's backend for net::Timer, wrapping asio::steady_timer.
// Behavior-identical to the direct asio usage it replaces: same steady_clock,
// same expires_after(delay), same "suppress the callback on cancel/re-arm"
// semantics (the `if (ec) return;` idiom). Timers are pure scheduling — NOT
// digest-bound — so this seam is byte-invariant for consensus (goldens
// unaffected); the only observable surface is liveness (phase timeouts), gated
// by the native cluster tests.
//
// The minix goal (docs/proofs/MinixTacticalProfile.md) is to add native
// IOCP/epoll/kqueue backends behind the SAME net::Timer interface and then drop
// asio; until then this is the sole backend.
#pragma once
#include <determ/net/timer.hpp>
#include <determ/net/asio_event_loop.hpp>
#include <asio.hpp>
#include <utility>

namespace determ::net {

class AsioTimer final : public Timer {
public:
    explicit AsioTimer(asio::io_context& io) : timer_(io) {}
    // Loop-taking ctor: the SAME construction shape as IocpTimer(loop), so
    // the platform-selector alias (net/native.hpp) lets Node construct its
    // timers uniformly as Timer(loop_) on both backends.
    explicit AsioTimer(AsioEventLoop& loop) : timer_(loop.raw()) {}

    void arm(std::chrono::milliseconds delay,
             std::function<void()> on_expire) override {
        timer_.expires_after(delay);
        timer_.async_wait([cb = std::move(on_expire)](std::error_code ec) {
            if (ec) return;    // operation_aborted (cancel / re-arm) -> suppress
            cb();
        });
    }

    void cancel() override { timer_.cancel(); }

private:
    asio::steady_timer timer_;
};

} // namespace determ::net
