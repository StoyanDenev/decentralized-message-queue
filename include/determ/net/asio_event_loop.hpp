// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// AsioEventLoop — today's backend for net::EventLoop, owning the
// asio::io_context. Behavior-identical to the direct io_context usage it
// replaces (same run/stop/post semantics, same multi-thread run() support).
//
// raw() is a TRANSITIONAL accessor for the consumers not yet behind the minix
// seam (GossipNet's acceptor/sockets, AsioTimer construction, RpcServer). Each
// later minix slice moves a consumer off raw(); when the native IOCP /
// epoll/kqueue backends land, raw() is deleted together with asio
// (docs/proofs/MinixTacticalProfile.md §4/§7).
#pragma once
#include <determ/net/event_loop.hpp>
#include <asio.hpp>
#include <utility>

namespace determ::net {

class AsioEventLoop final : public EventLoop {
public:
    AsioEventLoop() = default;

    void run() override { io_.run(); }
    void stop() override { io_.stop(); }
    void post(std::function<void()> fn) override {
        asio::post(io_, std::move(fn));
    }

    asio::io_context& raw() { return io_; }

private:
    asio::io_context io_;
};

} // namespace determ::net
