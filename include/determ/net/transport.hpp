// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// net::Transport — the socket/acceptor/connect slice of the minix net seam
// (docs/proofs/MinixTacticalProfile.md §4.4; slice 3 after net::Timer and
// net::EventLoop). Proactor-style completion interface: it maps 1:1 onto IOCP
// completions and is emulated over epoll/kqueue readiness (loop the syscall
// until exactly-N bytes transfer, THEN invoke the completion). AsioTransport
// (net/asio_transport.hpp) is today's backend; the native minix backends
// (IOCP on Windows, epoll/kqueue on POSIX) implement the SAME interface, at
// which point asio is dropped. UNCONDITIONAL — not gated on any build profile.
//
// Transport is BYTE-STREAM only: all framing (the 4-byte big-endian length
// prefix, S-022 caps) stays in Peer/messages — swapping the backend cannot
// change wire bytes.
#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <system_error>

namespace determ::net {

// One established TCP connection.
//
// COMPLETION CONTRACTS (every backend must uphold; Peer's single-outstanding-
// read/write safety silently depends on them, so they are explicit here):
//   - async_read fills EXACTLY n bytes before invoking cb (or fails) — the
//     asio::async_read semantic. Readiness-based backends must loop until n.
//   - async_write drains the WHOLE span before invoking cb (or fails).
//   - Completions run on event-loop threads; two completions of the SAME
//     operation kind on the SAME connection are never invoked concurrently.
//   - The caller guarantees the Connection (and the buffer) outlive the
//     in-flight operation — Peer does this by capturing shared_from_this()
//     in every completion, which pins the Connection it owns.
class Connection {
public:
    using IoCb = std::function<void(std::error_code, std::size_t)>;

    virtual ~Connection() = default;

    virtual void async_read(void* buf, std::size_t n, IoCb cb) = 0;
    virtual void async_write(const void* buf, std::size_t n, IoCb cb) = 0;

    // shutdown(both) + close. Idempotent, and callable from a DIFFERENT
    // thread than one blocked in / awaiting an operation on this connection —
    // pending operations then complete with an error (the mechanism the
    // subscriber kill-on-overflow path relies on; FB71).
    virtual void close() = 0;

    // "ip:port" of the remote end, or "unknown" — never throws.
    virtual std::string remote_endpoint() const = 0;

    // S-026: SO_KEEPALIVE (OS-default probe intervals). Best-effort.
    virtual void set_keep_alive(bool on) = 0;

    // ── Synchronous half (slice B: RpcServer + the dapp_subscribe writer) ──
    // Both consumers are thread-per-session/thread-per-subscriber blocking
    // models, not callback-driven — they call these directly on their own
    // thread instead of async_read/async_write. Readiness-based backends
    // (epoll/kqueue) implement these by looping the syscall on the calling
    // thread until done; a proactor backend (IOCP) can implement them as a
    // post-and-wait over its own completion.

    // Blocking, whole-span write. true iff all n bytes were written.
    virtual bool write_all(const void* buf, std::size_t n) = 0;

    // Best-effort bound (SO_SNDTIMEO-equivalent) on subsequent write_all()
    // calls — the mechanism that keeps a stalled subscriber's writer thread
    // from blocking forever. Not required to be exact; a backend that
    // cannot bound sends may no-op.
    virtual void set_send_timeout(std::chrono::milliseconds ms) = 0;

    // Blocking read of one line, delimited by '\n' (consumed, excluded from
    // out_line). false = error/EOF; the caller must stop reading. Backs the
    // line-oriented JSON-RPC session model (RpcServer::handle_session).
    virtual bool read_line(std::string& out_line) = 0;
};

// A listening endpoint producing Connections.
class Acceptor {
public:
    using AcceptCb =
        std::function<void(std::error_code, std::shared_ptr<Connection>)>;

    virtual ~Acceptor() = default;

    // One-shot: invoke cb for the next inbound connection; the caller re-arms
    // (the perpetual accept loop lives in the consumer, as today).
    virtual void async_accept(AcceptCb cb) = 0;
};

// The seam. Owns nothing about framing or protocol — pure byte transport.
class Transport {
public:
    using ConnectCb =
        std::function<void(std::error_code, std::shared_ptr<Connection>)>;

    virtual ~Transport() = default;

    // Bind + listen on the given port. any-interface IPv4 (the gossip model)
    // when localhost_only is false; 127.0.0.1-only when true (S-001,
    // RpcServer's default posture). Throws on bind failure (as the current
    // acceptor construction does).
    virtual std::unique_ptr<Acceptor> listen(uint16_t port,
                                              bool localhost_only) = 0;

    // Resolve + connect (the two stages folded together — both call sites do
    // both). On failure cb receives a non-zero error_code and a null
    // Connection.
    virtual void async_connect(const std::string& host, uint16_t port,
                               ConnectCb cb) = 0;
};

} // namespace determ::net
