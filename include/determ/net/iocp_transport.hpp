// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// IocpTransport — the native Windows backend for net::Transport (minix §4.5,
// increment 1). Implements the full Connection contract from transport.hpp:
//
//  - async_read/async_write: overlapped WSARecv/WSASend driven by a
//    self-owning per-op state machine. WSARecv/WSASend do NOT guarantee N
//    bytes per completion even under IOCP (§4.5) — partial completions
//    advance the buffer and re-issue on the SAME op until exactly-N, then
//    invoke the callback on a loop thread. Each op pins its connection via
//    shared_ptr for the whole in-flight window.
//  - close(): CancelIoEx (ALL pending ops, cross-thread — the FB71
//    contract) + shutdown(both) + closesocket. A cancelled op still
//    completes through the port with ERROR_OPERATION_ABORTED and frees
//    itself there — never earlier (§4.5 risk 1).
//  - write_all/read_line/set_send_timeout: the synchronous half (RpcServer +
//    the dapp_subscribe writer). read_line is a plain blocking recv (sockets
//    stay in blocking mode). write_all is an overlapped send waited on a
//    port-skipping event (low-bit hEvent tag) — a cross-thread close()
//    aborts it PROMPTLY via CancelIoEx, which a raw blocking send() on
//    Windows does NOT guarantee (§4.5 §1.6: the native backend makes the
//    FB71 stuck-writer release strictly cleaner than SO_SNDTIMEO-bounded
//    blocking sends); set_send_timeout bounds the stalled-peer case.
//
// Headers here are OS-include-free (§4.5 layout rule): sockets are opaque
// std::uintptr_t (SOCKET is UINT_PTR); all Winsock usage lives in
// src/net/iocp_transport.cpp.
#pragma once
#include <determ/net/transport.hpp>
#include <determ/net/iocp_event_loop.hpp>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace determ::net {

class IocpConnection final : public Connection,
                             public std::enable_shared_from_this<IocpConnection> {
public:
    // Takes ownership of an already-connected, already-port-associated
    // socket (accept and connect paths both associate before wrapping).
    IocpConnection(IocpEventLoop& loop, std::uintptr_t sock,
                   std::string endpoint);
    ~IocpConnection() override;   // close() if still open

    void async_read(void* buf, std::size_t n, IoCb cb) override;
    void async_write(const void* buf, std::size_t n, IoCb cb) override;
    void close() override;
    std::string remote_endpoint() const override { return endpoint_; }
    void set_keep_alive(bool on) override;

    bool write_all(const void* buf, std::size_t n) override;
    void set_send_timeout(std::chrono::milliseconds ms) override;
    bool read_line(std::string& out_line) override;

private:
    void start_xfer(bool is_read, void* buf, std::size_t n, IoCb cb);

    IocpEventLoop&        loop_;
    std::uintptr_t        sock_;
    std::string           endpoint_;
    std::atomic<bool>     closed_{false};
    std::string           carry_;   // read_line: bytes past '\n' carry over
    // write_all's stalled-peer bound (ms; 0 = unbounded). Enforced by the
    // event wait — overlapped sends ignore SO_SNDTIMEO.
    std::atomic<uint32_t> send_timeout_ms_{0};
};

class IocpAcceptor final : public Acceptor {
public:
    // Binds (loopback when localhost_only, any-interface otherwise; sets
    // SO_REUSEADDR for behavior-parity with AsioAcceptor — §4.5 risk 7) and
    // listens; associates the listen socket with the loop's port (AcceptEx
    // completions are delivered against it). Throws std::runtime_error on
    // failure, as the asio acceptor construction does.
    IocpAcceptor(IocpEventLoop& loop, uint16_t port, bool localhost_only);
    ~IocpAcceptor() override;   // closes the listen socket; a pending accept
                                // completes with operation-aborted

    void async_accept(AcceptCb cb) override;

    // The actual bound port — lets tests bind port 0 (ephemeral) and learn
    // the assignment. Concrete-class-only; not part of the Acceptor seam.
    uint16_t local_port() const { return local_port_; }

private:
    IocpEventLoop& loop_;
    std::uintptr_t listen_sock_;
    uint16_t       local_port_ = 0;
};

class IocpTransport final : public Transport {
public:
    explicit IocpTransport(IocpEventLoop& loop) : loop_(loop) {}
    ~IocpTransport() override;   // joins in-flight connect helper threads

    std::unique_ptr<Acceptor> listen(uint16_t port,
                                      bool localhost_only) override;

    // getaddrinfo has no IOCP-native async form (§4.5): resolve + a
    // candidate-loop blocking connect (matching asio's try-every-resolver-
    // result behavior, and SyncClient's) run on a short-lived helper
    // thread; the callback is posted onto a loop thread. The threads are
    // TRACKED, not detached — the destructor joins them, which is what
    // enforces the loop-outlives-any-in-flight-connect requirement for
    // every consumer that (like Node) declares the transport after the
    // loop. A join can wait out one OS connect timeout on a dead peer.
    void async_connect(const std::string& host, uint16_t port,
                       ConnectCb cb) override;

private:
    struct PendingConnect {
        std::thread                        thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    void reap_finished_connects();   // joins finished helpers (caller locks)

    IocpEventLoop&              loop_;
    std::mutex                  connects_mu_;
    std::vector<PendingConnect> connects_;
};

} // namespace determ::net
