// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// ReactorTransport — the native POSIX backend for net::Transport (minix
// §4.5, epoll today). Implements the full Connection contract from
// transport.hpp with the reactor emulation the design prescribes:
//
//  - async_read/async_write: a resumable per-connection ReadOp/WriteOp
//    state machine — attempt the syscall immediately (data may already be
//    buffered), park on EAGAIN by arming one-shot readiness interest,
//    resume from the partial offset on the next wakeup, complete when
//    exactly-N bytes moved. Both ops live under ONE op mutex; completions
//    are invoked outside it. Fds are non-blocking; sockets never block a
//    loop thread.
//  - close(): the §4.5 POSIX abort recipe — there is NO blocked syscall to
//    interrupt (the fd is non-blocking), so close() synthesizes the parked
//    ops' aborted completions immediately (posted to a loop thread),
//    serialized against real readiness-driven completions by the op mutex
//    (exactly one of {real completion, synthesized abort} ever fires per
//    op). shutdown(SHUT_RDWR) then kills the TCP conversation — which also
//    wakes any thread parked in the SYNC half's poll(). The fd itself is
//    ::close()d in the DESTRUCTOR, not in close(): keeping the number
//    reserved until every owner drops its shared_ptr closes the §4.5
//    fd-reuse stale-event/stale-poll hazard for both halves.
//  - write_all/read_line/set_send_timeout: the synchronous half (RpcServer
//    sessions + the dapp_subscribe writer) — send/recv loops that park in
//    poll() on EAGAIN. MSG_NOSIGNAL on every send (SIGPIPE immunity — the
//    sync_client lesson). A cross-thread close()'s shutdown wakes the poll
//    promptly (POSIX gives the sync half the wake IOCP needed an
//    event-abort design for); set_send_timeout bounds the stalled-peer
//    case via the poll timeout.
//
// Headers are OS-include-free (§4.5 layout rule): fds are ints; all
// <sys/socket.h>/<sys/epoll.h> usage lives in src/net/reactor_transport.cpp.
#pragma once
#include <determ/net/transport.hpp>
#include <determ/net/reactor_event_loop.hpp>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace determ::net {

class ReactorConnection final
    : public Connection,
      public ReactorHandler,
      public std::enable_shared_from_this<ReactorConnection> {
public:
    // Takes ownership of a connected fd; sets it non-blocking. Registration
    // with the loop happens lazily on the first parked async op (the sync
    // half never registers).
    ReactorConnection(ReactorEventLoop& loop, int fd, std::string endpoint);
    ~ReactorConnection() override;   // close() + ::close(fd)

    void async_read(void* buf, std::size_t n, IoCb cb) override;
    void async_write(const void* buf, std::size_t n, IoCb cb) override;
    void close() override;
    std::string remote_endpoint() const override { return endpoint_; }
    void set_keep_alive(bool on) override;

    bool write_all(const void* buf, std::size_t n) override;
    void set_send_timeout(std::chrono::milliseconds ms) override;
    bool read_line(std::string& out_line) override;

    void on_event(uint32_t events) override;

private:
    struct Op {
        uint8_t*    buf  = nullptr;
        std::size_t n    = 0;
        std::size_t done = 0;
        IoCb        cb;
        bool        active = false;
    };

    void start_op(bool is_read, void* buf, std::size_t n, IoCb cb);
    // Advances `op` with non-blocking syscalls. Returns true when the op
    // left the parked state (completed or failed) — `fire` then holds the
    // completion to invoke AFTER op_mu_ is released. Caller holds op_mu_.
    bool advance_locked(Op& op, bool is_read, std::function<void()>& fire);
    void update_interest_locked();   // re-arm one-shot interest for parked ops

    ReactorEventLoop&     loop_;
    int                   fd_;
    std::string           endpoint_;
    std::atomic<bool>     closed_{false};
    std::string           carry_;   // read_line: bytes past '\n' carry over
    std::atomic<uint32_t> send_timeout_ms_{0};

    std::mutex op_mu_;
    Op         rd_, wr_;
    bool       registered_ = false;   // guarded by op_mu_
};

class ReactorAcceptor final : public Acceptor {
public:
    // Binds (loopback when localhost_only; SO_REUSEADDR for asio parity)
    // and listens, non-blocking. Throws std::runtime_error on failure.
    ReactorAcceptor(ReactorEventLoop& loop, uint16_t port,
                    bool localhost_only);
    // Deregisters + closes the listen fd. A parked accept callback is
    // DROPPED, never invoked — consumers tear the loop down first (the
    // drained-handlers-never-fire semantics every backend shares).
    ~ReactorAcceptor() override;

    void async_accept(AcceptCb cb) override;

    // The actual bound port — lets tests bind port 0 (ephemeral) and learn
    // the assignment. Concrete-class-only; not part of the Acceptor seam.
    uint16_t local_port() const { return local_port_; }

private:
    struct State;   // : ReactorHandler; owns the parked cb (defined in .cpp)

    ReactorEventLoop&      loop_;
    int                    listen_fd_ = -1;
    uint16_t               local_port_ = 0;
    std::shared_ptr<State> state_;
};

class ReactorTransport final : public Transport {
public:
    explicit ReactorTransport(ReactorEventLoop& loop) : loop_(loop) {}
    ~ReactorTransport() override;   // joins in-flight connect helper threads

    std::unique_ptr<Acceptor> listen(uint16_t port,
                                      bool localhost_only) override;

    // Resolve + candidate-loop blocking connect on a TRACKED short-lived
    // helper thread, exactly the IocpTransport design (asio's
    // try-every-resolver-result behavior; ~ReactorTransport joins the
    // helpers, which is what enforces loop-outlives-any-in-flight-connect).
    void async_connect(const std::string& host, uint16_t port,
                       ConnectCb cb) override;

private:
    struct PendingConnect {
        std::thread                        thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    void reap_finished_connects();   // caller holds connects_mu_

    ReactorEventLoop&           loop_;
    std::mutex                  connects_mu_;
    std::vector<PendingConnect> connects_;
};

} // namespace determ::net
