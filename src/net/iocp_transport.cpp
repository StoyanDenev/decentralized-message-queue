// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// IocpTransport implementation (minix §4.5 increment 1). Windows-only TU —
// pruned from SOURCES on other platforms by CMakeLists.txt.
#ifdef _WIN32

#include <determ/net/iocp_transport.hpp>
#include "iocp_detail.hpp"
#include <cstring>
#include <stdexcept>
#include <thread>
#include <utility>

namespace determ::net {

using detail::OverlappedOp;
using detail::kKeyOp;

namespace {

std::error_code make_ec(DWORD err) {
    return std::error_code(static_cast<int>(err), std::system_category());
}

// AcceptEx address-buffer sizing: the +16 padding per address is an AcceptEx
// API requirement, not optional (getting it wrong silently corrupts the
// parsed addresses — §4.5). IPv4 only, matching the asio v4 usage.
constexpr DWORD kAddrLen = sizeof(sockaddr_in) + 16;

// AcceptEx / GetAcceptExSockaddrs are extension functions resolved once per
// process via WSAIoctl (§4.5). (ConnectEx is deliberately NOT used: the
// connect path resolves + candidate-loops a blocking connect on a tracked
// helper thread instead — see IocpTransport::async_connect.)
LPFN_ACCEPTEX             pAcceptEx             = nullptr;
LPFN_GETACCEPTEXSOCKADDRS pGetAcceptExSockaddrs = nullptr;

void resolve_extensions() {
    static const bool ok = [] {
        SOCKET s = ::WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                                WSA_FLAG_OVERLAPPED);
        if (s == INVALID_SOCKET) return false;
        DWORD bytes = 0;
        GUID  g1    = WSAID_ACCEPTEX;
        GUID  g3    = WSAID_GETACCEPTEXSOCKADDRS;
        bool  r =
            ::WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g1, sizeof g1,
                       &pAcceptEx, sizeof pAcceptEx, &bytes, nullptr,
                       nullptr) == 0 &&
            ::WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &g3, sizeof g3,
                       &pGetAcceptExSockaddrs, sizeof pGetAcceptExSockaddrs,
                       &bytes, nullptr, nullptr) == 0;
        ::closesocket(s);
        return r;
    }();
    if (!ok)
        throw std::runtime_error(
            "IocpTransport: WSAIoctl extension-function resolution failed");
}

std::string format_endpoint(const sockaddr_in& sa) {
    char ip[INET_ADDRSTRLEN] = {};
    if (!::inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof ip)) return "unknown";
    return std::string(ip) + ":" + std::to_string(ntohs(sa.sin_port));
}

void associate(SOCKET s, void* port) {
    if (!::CreateIoCompletionPort(reinterpret_cast<HANDLE>(s),
                                  static_cast<HANDLE>(port), kKeyOp, 0))
        throw std::runtime_error(
            "IocpTransport: completion-port association failed");
}

// ── The read/write op: loop-until-exactly-N over partial completions ────────
// One WSARecv/WSASend completion can transfer FEWER bytes than requested
// (IOCP is a proactor for the syscall, not for "exactly N" — §4.5). The op
// re-issues from the running offset on the SAME OVERLAPPED (legal: the prior
// call has fully completed) until total bytes move, then invokes cb once.
struct XferOp {
    OverlappedOp                    base;
    std::shared_ptr<IocpConnection> pin;   // connection outlives the op
    Connection::IoCb                cb;
    SOCKET                          sock = INVALID_SOCKET;
    uint8_t*                        buf  = nullptr;
    std::size_t                     total = 0;
    std::size_t                     done  = 0;
    bool                            is_read = false;

    // Issues (or re-issues) from the current offset. Returns 0 on
    // queued/pending, else the WSA error (caller invokes cb + frees).
    DWORD issue() {
        std::memset(&base.ov, 0, sizeof base.ov);
        WSABUF wb;
        wb.buf = reinterpret_cast<CHAR*>(buf + done);
        wb.len = static_cast<ULONG>(total - done);
        int rc;
        if (is_read) {
            DWORD flags = 0;
            rc = ::WSARecv(sock, &wb, 1, nullptr, &flags, &base.ov, nullptr);
        } else {
            rc = ::WSASend(sock, &wb, 1, nullptr, 0, &base.ov, nullptr);
        }
        if (rc == 0) return 0;   // completed synchronously — the completion
                                 // is STILL queued to the port (no
                                 // skip-on-success mode set); wait for it
        DWORD err = static_cast<DWORD>(::WSAGetLastError());
        return err == WSA_IO_PENDING ? 0 : err;
    }

    static void complete(OverlappedOp* self, DWORD bytes, DWORD error) {
        auto* op = reinterpret_cast<XferOp*>(self);
        op->done += bytes;
        if (error != 0) {
            finish(op, make_ec(error));
            return;
        }
        if (op->is_read && bytes == 0) {
            // Orderly remote close mid-read: asio's eof semantics — any
            // nonzero ec; Peer treats every error as disconnect.
            finish(op, make_ec(ERROR_HANDLE_EOF));
            return;
        }
        if (op->done >= op->total) {
            finish(op, {});
            return;
        }
        DWORD err = op->issue();
        if (err != 0) finish(op, make_ec(err));
    }

    static void finish(XferOp* op, std::error_code ec) {
        auto cb   = std::move(op->cb);
        auto done = op->done;
        delete op;
        cb(ec, done);
    }

    static void abandon(OverlappedOp* self) {
        delete reinterpret_cast<XferOp*>(self);
    }
};

// ── AcceptEx op ──────────────────────────────────────────────────────────────
struct AcceptOp {
    OverlappedOp       base;
    IocpEventLoop*     loop = nullptr;
    SOCKET             listen_sock = INVALID_SOCKET;
    SOCKET             accept_sock = INVALID_SOCKET;
    Acceptor::AcceptCb cb;
    char               addr_buf[2 * kAddrLen] = {};

    static void complete(OverlappedOp* self, DWORD, DWORD error) {
        auto* op = reinterpret_cast<AcceptOp*>(self);
        if (error != 0) {
            ::closesocket(op->accept_sock);
            auto cb = std::move(op->cb);
            delete op;
            cb(make_ec(error), nullptr);
            return;
        }
        // Required before shutdown/getpeername/setsockopt behave on the
        // accepted socket (the classic AcceptEx gotcha — §4.5).
        ::setsockopt(op->accept_sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                     reinterpret_cast<const char*>(&op->listen_sock),
                     sizeof op->listen_sock);
        sockaddr* local  = nullptr;
        sockaddr* remote = nullptr;
        int llen = 0, rlen = 0;
        pGetAcceptExSockaddrs(op->addr_buf, 0, kAddrLen, kAddrLen, &local,
                              &llen, &remote, &rlen);
        std::string endpoint = "unknown";
        if (remote && rlen >= static_cast<int>(sizeof(sockaddr_in)))
            endpoint = format_endpoint(
                *reinterpret_cast<const sockaddr_in*>(remote));
        auto conn = std::make_shared<IocpConnection>(
            *op->loop, static_cast<std::uintptr_t>(op->accept_sock),
            std::move(endpoint));
        auto cb = std::move(op->cb);
        delete op;
        cb({}, std::move(conn));
    }

    static void abandon(OverlappedOp* self) {
        auto* op = reinterpret_cast<AcceptOp*>(self);
        ::closesocket(op->accept_sock);
        delete op;
    }
};

} // namespace

// ── IocpConnection ───────────────────────────────────────────────────────────

IocpConnection::IocpConnection(IocpEventLoop& loop, std::uintptr_t sock,
                               std::string endpoint)
    : loop_(loop), sock_(sock), endpoint_(std::move(endpoint)) {}

IocpConnection::~IocpConnection() { close(); }

void IocpConnection::start_xfer(bool is_read, void* buf, std::size_t n,
                                IoCb cb) {
    if (n == 0) {
        // Zero-length transfer: complete immediately on a loop thread
        // (asio's async_read with an empty buffer does the same).
        loop_.post([cb = std::move(cb)] { cb({}, 0); });
        return;
    }
    auto* op            = new XferOp;
    op->base.on_complete = &XferOp::complete;
    op->base.on_abandon  = &XferOp::abandon;
    op->pin             = shared_from_this();
    op->cb              = std::move(cb);
    op->sock            = static_cast<SOCKET>(sock_);
    op->buf             = static_cast<uint8_t*>(buf);
    op->total           = n;
    op->is_read         = is_read;
    DWORD err = op->issue();
    if (err != 0) {
        // Synchronous issue failure (closed socket, etc.): the completion
        // will never arrive — fail through the loop so the callback still
        // runs on a loop thread, never inline in the caller.
        auto fail_cb = std::move(op->cb);
        delete op;
        loop_.post([fail_cb = std::move(fail_cb), err] {
            fail_cb(make_ec(err), 0);
        });
    }
}

void IocpConnection::async_read(void* buf, std::size_t n, IoCb cb) {
    start_xfer(true, buf, n, std::move(cb));
}

void IocpConnection::async_write(const void* buf, std::size_t n, IoCb cb) {
    start_xfer(false, const_cast<void*>(buf), n, std::move(cb));
}

void IocpConnection::close() {
    if (closed_.exchange(true)) return;
    SOCKET s = static_cast<SOCKET>(sock_);
    // CancelIoEx (NOT the thread-scoped CancelIo): pending overlapped ops
    // were issued by loop threads, close() may run on any thread — the FB71
    // cross-thread contract. Cancelled ops still complete through the port
    // (ERROR_OPERATION_ABORTED) and free themselves there.
    ::CancelIoEx(reinterpret_cast<HANDLE>(s), nullptr);
    ::shutdown(s, SD_BOTH);
    ::closesocket(s);
}

void IocpConnection::set_keep_alive(bool on) {
    BOOL v = on ? TRUE : FALSE;
    ::setsockopt(static_cast<SOCKET>(sock_), SOL_SOCKET, SO_KEEPALIVE,
                 reinterpret_cast<const char*>(&v), sizeof v);
}

bool IocpConnection::write_all(const void* buf, std::size_t n) {
    // NOT a plain blocking send(): on Windows a thread blocked in send() is
    // NOT reliably woken by a cross-thread closesocket — the pre-seam code
    // was silently bounded by SO_SNDTIMEO alone there. The native backend
    // does strictly better (the §4.5 §1.6 prediction): each chunk is an
    // overlapped WSASend waited on a dedicated event whose LOW BIT is set —
    // the documented tag that keeps the completion OFF the port (no run()
    // thread involvement) — so close()'s CancelIoEx aborts the in-flight
    // send PROMPTLY and deterministically (FB71), with send_timeout_ms_ as
    // the stalled-peer bound. On the timeout/cancel paths we always wait
    // for the (now-failing) completion before the stack-local OVERLAPPED/
    // buffer go out of scope — the kernel owns them until then (§4.5 risk 1).
    const char* p   = static_cast<const char*>(buf);
    std::size_t off = 0;
    HANDLE ev = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ev) return false;
    bool ok = true;
    while (off < n) {
        if (closed_.load()) { ok = false; break; }
        OVERLAPPED ov{};
        ov.hEvent = reinterpret_cast<HANDLE>(
            reinterpret_cast<ULONG_PTR>(ev) | 1);   // low bit: skip the port
        ::ResetEvent(ev);
        WSABUF wb;
        wb.buf = const_cast<CHAR*>(p + off);
        wb.len = static_cast<ULONG>(
            n - off > 0x40000000 ? 0x40000000 : n - off);
        int rc = ::WSASend(static_cast<SOCKET>(sock_), &wb, 1, nullptr, 0,
                           &ov, nullptr);
        if (rc == SOCKET_ERROR &&
            ::WSAGetLastError() != WSA_IO_PENDING) {
            ok = false;
            break;
        }
        uint32_t timeout = send_timeout_ms_.load();
        DWORD    wait    = ::WaitForSingleObject(
            ev, timeout == 0 ? INFINITE : static_cast<DWORD>(timeout));
        if (wait != WAIT_OBJECT_0) {
            // Stalled past the bound: cancel OUR op, then wait for its
            // (aborted) completion — never abandon a kernel-owned buffer.
            ::CancelIoEx(reinterpret_cast<HANDLE>(sock_), &ov);
            ::WaitForSingleObject(ev, INFINITE);
        }
        DWORD sent = 0, flags = 0;
        BOOL  done = ::WSAGetOverlappedResult(static_cast<SOCKET>(sock_),
                                              &ov, &sent, FALSE, &flags);
        off += sent;
        if (!done || sent == 0) { ok = false; break; }
    }
    ::CloseHandle(ev);
    return ok && off == n;
}

void IocpConnection::set_send_timeout(std::chrono::milliseconds ms) {
    // write_all's event wait enforces the bound (overlapped sends ignore
    // SO_SNDTIMEO); the setsockopt is kept for any plain-send path parity.
    send_timeout_ms_.store(static_cast<uint32_t>(ms.count()));
    DWORD tv = static_cast<DWORD>(ms.count());
    ::setsockopt(static_cast<SOCKET>(sock_), SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof tv);
}

bool IocpConnection::read_line(std::string& out_line) {
    for (;;) {
        auto nl = carry_.find('\n');
        if (nl != std::string::npos) {
            out_line = carry_.substr(0, nl);
            carry_.erase(0, nl + 1);
            return true;
        }
        char buf[4096];
        int  rc = ::recv(static_cast<SOCKET>(sock_), buf, sizeof buf, 0);
        if (rc <= 0) return false;   // EOF or error — session ends
        carry_.append(buf, static_cast<std::size_t>(rc));
    }
}

// ── IocpAcceptor ─────────────────────────────────────────────────────────────

IocpAcceptor::IocpAcceptor(IocpEventLoop& loop, uint16_t port,
                           bool localhost_only)
    : loop_(loop), listen_sock_(static_cast<std::uintptr_t>(INVALID_SOCKET)) {
    detail::winsock_init();
    resolve_extensions();

    SOCKET s = ::WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                            WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET)
        throw std::runtime_error("IocpAcceptor: WSASocket failed");

    // Behavior parity with AsioAcceptor, whose convenience ctor sets
    // reuse_address by default (§4.5 risk 7 — a missing SO_REUSEADDR would
    // regress restart-racing-TIME_WAIT rebinds, invisible to the golden
    // gates).
    BOOL reuse = TRUE;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&reuse), sizeof reuse);

    sockaddr_in sa{};
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = htonl(localhost_only ? INADDR_LOOPBACK : INADDR_ANY);
    if (::bind(s, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) != 0) {
        ::closesocket(s);
        throw std::runtime_error("IocpAcceptor: bind failed on port " +
                                 std::to_string(port));
    }
    sockaddr_in bound{};
    int         blen = sizeof bound;
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&bound), &blen) == 0)
        local_port_ = ntohs(bound.sin_port);
    if (::listen(s, SOMAXCONN) != 0) {
        ::closesocket(s);
        throw std::runtime_error("IocpAcceptor: listen failed");
    }
    // AcceptEx completions are delivered against the LISTEN socket's port
    // association. Close on failure like the bind/listen branches — a
    // throwing ctor never runs the destructor, so this branch must reclaim
    // the socket itself.
    try {
        associate(s, loop_.native_port());
    } catch (...) {
        ::closesocket(s);
        throw;
    }
    listen_sock_ = static_cast<std::uintptr_t>(s);
}

IocpAcceptor::~IocpAcceptor() {
    SOCKET s = static_cast<SOCKET>(listen_sock_);
    if (s != INVALID_SOCKET) ::closesocket(s);
    // A pending AcceptOp completes with ERROR_OPERATION_ABORTED through the
    // port and cleans itself (and its pre-created accept socket) up there.
}

void IocpAcceptor::async_accept(AcceptCb cb) {
    // AcceptEx needs the not-yet-connected socket supplied up front (unlike
    // POSIX accept); associate it with the port NOW so its later I/O
    // completions land without an extra step (§4.5).
    SOCKET as = ::WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                             WSA_FLAG_OVERLAPPED);
    if (as == INVALID_SOCKET) {
        loop_.post([cb = std::move(cb)] {
            cb(make_ec(WSAEMFILE), nullptr);
        });
        return;
    }
    try {
        associate(as, loop_.native_port());
    } catch (...) {
        ::closesocket(as);
        loop_.post([cb = std::move(cb)] {
            cb(make_ec(ERROR_INVALID_HANDLE), nullptr);
        });
        return;
    }

    auto* op            = new AcceptOp;
    op->base.on_complete = &AcceptOp::complete;
    op->base.on_abandon  = &AcceptOp::abandon;
    op->loop            = &loop_;
    op->listen_sock     = static_cast<SOCKET>(listen_sock_);
    op->accept_sock     = as;
    op->cb              = std::move(cb);

    DWORD bytes = 0;
    BOOL  ok = pAcceptEx(op->listen_sock, as, op->addr_buf, 0, kAddrLen,
                         kAddrLen, &bytes, &op->base.ov);
    if (!ok) {
        DWORD err = static_cast<DWORD>(::WSAGetLastError());
        if (err != ERROR_IO_PENDING) {
            ::closesocket(as);
            auto fail_cb = std::move(op->cb);
            delete op;
            loop_.post([fail_cb = std::move(fail_cb), err] {
                fail_cb(make_ec(err), nullptr);
            });
        }
    }
    // ok == TRUE: completed synchronously — the completion is still queued
    // to the port (no skip-on-success mode); the normal dispatch handles it.
}

// ── IocpTransport ────────────────────────────────────────────────────────────

std::unique_ptr<Acceptor> IocpTransport::listen(uint16_t port,
                                                bool localhost_only) {
    return std::make_unique<IocpAcceptor>(loop_, port, localhost_only);
}

IocpTransport::~IocpTransport() {
    std::lock_guard<std::mutex> lk(connects_mu_);
    for (auto& pc : connects_)
        if (pc.thread.joinable()) pc.thread.join();
    connects_.clear();
}

void IocpTransport::reap_finished_connects() {
    // Caller holds connects_mu_. Joining a finished thread is instant; only
    // an actively-connecting helper would block, and those are skipped.
    for (auto it = connects_.begin(); it != connects_.end();) {
        if (it->done->load()) {
            if (it->thread.joinable()) it->thread.join();
            it = connects_.erase(it);
        } else {
            ++it;
        }
    }
}

void IocpTransport::async_connect(const std::string& host, uint16_t port,
                                  ConnectCb cb) {
    detail::winsock_init();
    IocpEventLoop* loop = &loop_;
    // getaddrinfo is blocking with no IOCP-native async form (§4.5): resolve
    // AND a candidate-loop blocking connect run on a short-lived helper
    // thread (a blocking connect on an overlapped-capable socket is
    // mode-independent), matching asio's try-every-resolver-result behavior
    // and SyncClient's proven candidate loop; the callback is posted onto a
    // loop thread either way. The thread is TRACKED (joined by ~IocpTransport
    // or reaped on the next connect) — never detached — so the loop cannot
    // be destroyed under an in-flight connect (every consumer destroys the
    // transport before the loop; Node's member order guarantees it).
    auto done = std::make_shared<std::atomic<bool>>(false);
    std::thread helper([loop, host, port, cb = std::move(cb),
                        done]() mutable {
        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* res = nullptr;
        int rc = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(),
                               &hints, &res);
        if (rc != 0 || !res) {
            loop->post([cb = std::move(cb)] {
                cb(make_ec(WSAHOST_NOT_FOUND), nullptr);
            });
            done->store(true);
            return;
        }

        SOCKET      s        = INVALID_SOCKET;
        std::string endpoint = "unknown";
        DWORD       last_err = WSAECONNREFUSED;
        for (addrinfo* ai = res; ai; ai = ai->ai_next) {
            SOCKET c = ::WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                    nullptr, 0, WSA_FLAG_OVERLAPPED);
            if (c == INVALID_SOCKET) {
                last_err = WSAEMFILE;
                continue;
            }
            if (::connect(c, ai->ai_addr,
                          static_cast<int>(ai->ai_addrlen)) == 0) {
                s = c;
                if (ai->ai_addrlen >= sizeof(sockaddr_in))
                    endpoint = format_endpoint(
                        *reinterpret_cast<const sockaddr_in*>(ai->ai_addr));
                break;
            }
            last_err = static_cast<DWORD>(::WSAGetLastError());
            ::closesocket(c);
        }
        ::freeaddrinfo(res);
        if (s == INVALID_SOCKET) {
            loop->post([cb = std::move(cb), last_err] {
                cb(make_ec(last_err), nullptr);
            });
            done->store(true);
            return;
        }
        try {
            associate(s, loop->native_port());
        } catch (...) {
            ::closesocket(s);
            loop->post([cb = std::move(cb)] {
                cb(make_ec(ERROR_INVALID_HANDLE), nullptr);
            });
            done->store(true);
            return;
        }
        auto conn = std::make_shared<IocpConnection>(
            *loop, static_cast<std::uintptr_t>(s), std::move(endpoint));
        loop->post([cb = std::move(cb), conn]() mutable {
            cb({}, std::move(conn));
        });
        done->store(true);
    });
    std::lock_guard<std::mutex> lk(connects_mu_);
    reap_finished_connects();
    connects_.push_back({std::move(helper), std::move(done)});
}

} // namespace determ::net

#endif // _WIN32
