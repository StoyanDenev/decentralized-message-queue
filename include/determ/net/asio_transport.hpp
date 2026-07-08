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
#include <istream>
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

    bool write_all(const void* buf, std::size_t n) override {
        std::error_code ec;
        asio::write(socket_, asio::buffer(buf, n), ec);
        return !ec;
    }

    void set_send_timeout(std::chrono::milliseconds ms) override {
        // Same setsockopt(SO_SNDTIMEO) the pre-seam subscriber_session used
        // directly via native_handle() — moved here so both synchronous
        // consumers (RpcServer, the subscriber writer) share one
        // platform-split implementation instead of each carrying its own.
#ifdef _WIN32
        DWORD tv = static_cast<DWORD>(ms.count());
        setsockopt(socket_.native_handle(), SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char*>(&tv), sizeof tv);
#else
        struct timeval tv {};
        tv.tv_sec  = static_cast<long>(ms.count() / 1000);
        tv.tv_usec = static_cast<long>((ms.count() % 1000) * 1000);
        setsockopt(socket_.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv,
                   sizeof tv);
#endif
    }

    bool read_line(std::string& out_line) override {
        // read_buf_ persists across calls: read_until may buffer bytes past
        // the delimiter, and a session calls this in a loop (one RPC line
        // per call) — the excess must carry over, exactly as the previous
        // in-RpcServer asio::streambuf did.
        std::error_code ec;
        asio::read_until(socket_, read_buf_, '\n', ec);
        if (ec) return false;
        std::istream is(&read_buf_);
        std::getline(is, out_line);
        return true;
    }

private:
    asio::ip::tcp::socket socket_;
    std::string           endpoint_;
    asio::streambuf       read_buf_;
};

class AsioAcceptor final : public Acceptor {
public:
    AsioAcceptor(asio::io_context& io, uint16_t port, bool localhost_only)
        : acceptor_(io, asio::ip::tcp::endpoint(
                            localhost_only
                                ? asio::ip::address(
                                      asio::ip::address_v4::loopback())
                                : asio::ip::address(asio::ip::address_v4::any()),
                            port)) {}

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

    std::unique_ptr<Acceptor> listen(uint16_t port,
                                      bool localhost_only) override {
        return std::make_unique<AsioAcceptor>(io_, port, localhost_only);
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
