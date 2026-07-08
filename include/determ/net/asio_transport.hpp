// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// AsioTransport — today's backend for net::Transport, wrapping asio's
// socket/acceptor/resolver. Behavior-identical to the direct asio usage it
// replaces in Peer/GossipNet: same async_read/async_write exactly-N/whole-span
// semantics, same shutdown_both+close teardown, same SO_KEEPALIVE flip, same
// resolve->connect two-stage with shared_ptr pinning across the async gap.
// Transport is byte-stream only (framing stays in Peer) so this seam cannot
// change wire bytes; the observable surface is gossip liveness, gated by the
// native cluster tests. Replaced by the native IOCP / epoll/kqueue backends
// when they land (docs/proofs/MinixTacticalProfile.md §4), then deleted with
// asio.
#pragma once
#include <determ/net/transport.hpp>
#include <asio.hpp>
#include <utility>

namespace determ::net {

class AsioConnection final : public Connection {
public:
    explicit AsioConnection(asio::ip::tcp::socket socket)
        : socket_(std::move(socket)) {
        // Cache the endpoint once: remote_endpoint() throws on a dead socket,
        // and the interface promises a never-throwing accessor.
        try {
            endpoint_ = socket_.remote_endpoint().address().to_string() + ":" +
                        std::to_string(socket_.remote_endpoint().port());
        } catch (...) {
            endpoint_ = "unknown";
        }
    }

    void async_read(void* buf, std::size_t n, IoCb cb) override {
        asio::async_read(socket_, asio::buffer(buf, n), std::move(cb));
    }

    void async_write(const void* buf, std::size_t n, IoCb cb) override {
        asio::async_write(socket_, asio::buffer(buf, n), std::move(cb));
    }

    void close() override {
        std::error_code ec;
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }

    std::string remote_endpoint() const override { return endpoint_; }

    void set_keep_alive(bool on) override {
        try {
            socket_.set_option(asio::socket_base::keep_alive(on));
        } catch (...) {
            // Best-effort (closed socket, etc.) — matches the previous
            // in-Peer behavior; not worth failing an attach over.
        }
    }

private:
    asio::ip::tcp::socket socket_;
    std::string           endpoint_;
};

class AsioAcceptor final : public Acceptor {
public:
    AsioAcceptor(asio::io_context& io, uint16_t port)
        : acceptor_(io, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)) {}

    void async_accept(AcceptCb cb) override {
        acceptor_.async_accept(
            [cb = std::move(cb)](std::error_code ec,
                                 asio::ip::tcp::socket socket) {
                cb(ec, ec ? nullptr
                          : std::make_shared<AsioConnection>(std::move(socket)));
            });
    }

private:
    asio::ip::tcp::acceptor acceptor_;
};

class AsioTransport final : public Transport {
public:
    explicit AsioTransport(asio::io_context& io) : io_(io) {}

    std::unique_ptr<Acceptor> listen(uint16_t port) override {
        return std::make_unique<AsioAcceptor>(io_, port);
    }

    void async_connect(const std::string& host, uint16_t port,
                       ConnectCb cb) override {
        // Two-stage resolve -> connect; the resolver and socket are pinned by
        // shared_ptr captures across the async gap (as the previous free-fn
        // implementation did).
        auto resolver = std::make_shared<asio::ip::tcp::resolver>(io_);
        resolver->async_resolve(host, std::to_string(port),
            [this, resolver, cb](std::error_code ec,
                                 asio::ip::tcp::resolver::results_type results) {
                if (ec) { cb(ec, nullptr); return; }
                auto socket = std::make_shared<asio::ip::tcp::socket>(io_);
                asio::async_connect(*socket, results,
                    [socket, resolver, cb](std::error_code ec2, auto) {
                        cb(ec2, ec2 ? nullptr
                                    : std::make_shared<AsioConnection>(
                                          std::move(*socket)));
                    });
            });
    }

private:
    asio::io_context& io_;
};

} // namespace determ::net
