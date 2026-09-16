// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light RPC client — BSD-socket JSON-over-TCP wrapper.
//
// Mirrors the pattern in wallet/main.cpp::rpc_call_over_socket (around
// line 8778): a single-connection JSON-RPC client that talks to a
// local daemon on 127.0.0.1:<port>. No asio, no libsodium. Each request
// is a single line of JSON terminated by '\n'; each response is also a
// single line of JSON. Errors throw std::runtime_error with a
// diagnostic naming the failing method.
//
// Usage:
//   RpcClient rpc(7778);
//   if (!rpc.open()) throw ...;
//   auto headers = rpc.call("headers", {{"from", 0}, {"count", 10}});
//   rpc.close();
//
// The connection is re-used across multiple `call` invocations on the
// same client (the daemon's handle_session loops on line-framed reads),
// so composite commands like balance-trustless can issue several RPCs
// over one TCP connection.

#pragma once
#include <nlohmann/json.hpp>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#endif

namespace determ::light {

#ifdef _WIN32
using sock_t = SOCKET;
constexpr sock_t kInvalidSock = INVALID_SOCKET;
#else
using sock_t = int;
constexpr sock_t kInvalidSock = -1;
#endif

// Max bytes RpcClient::read_line will accumulate for a SINGLE response line
// before treating the peer as hostile. The light client talks to an untrusted
// / MITM daemon (LightVerifyGateAudit surface); without a bound, a malicious
// daemon can stream an endless newline-less body to exhaust the reader's
// memory (LRPC-1). Mirrors the node's ingress `net::kMaxRpcLineBytes`; every
// legitimate daemon response (state proof / header / committee list / paged
// history) is far under 16 MiB.
constexpr size_t kLightRpcMaxLineBytes = 16u * 1024u * 1024u;   // 16 MiB

// Testable core of RpcClient::read_line, with the byte source INJECTED so the
// cap is unit-testable with NO socket. Pulls bytes via `fill` (which appends
// >=0 bytes to `inbuf` and returns false on EOF/transport error) until a '\n'
// is seen — returns the line (newline stripped; any remainder left in `inbuf`)
// — or throws std::runtime_error once `inbuf` exceeds kLightRpcMaxLineBytes
// without a newline. Returns std::nullopt if `fill` reports EOF/error first.
// The socket read_line is a thin wrapper whose `fill` does one recv().
std::optional<std::string> read_line_capped(
    std::string& inbuf, const std::function<bool(std::string&)>& fill);

class RpcClient {
public:
    // Loopback client — connects to 127.0.0.1:port (the original behavior;
    // every existing determ-light command uses this and keeps the exact
    // INADDR_LOOPBACK fast path in open()).
    explicit RpcClient(uint16_t port);
    // Host client — connects to host:port, resolved via getaddrinfo (IPv4).
    // host "127.0.0.1" / "localhost" / "" routes through the same loopback
    // fast path; any other host takes the getaddrinfo branch. Enables
    // cross-HOST multi-peer cross-check without touching the loopback path.
    RpcClient(std::string host, uint16_t port);
    // Virtual so an in-process fixture daemon can stand in for the socket
    // (the outbox selftests drive the REAL submit/reconcile cores over a
    // committee-signed fixture chain, light/outbox_selftest.cpp).
    virtual ~RpcClient();

    RpcClient(const RpcClient&) = delete;
    RpcClient& operator=(const RpcClient&) = delete;

    // Open the TCP connection to 127.0.0.1:port. Returns true on
    // success; on failure populates `last_error()` and returns false.
    bool open();

    // Close the TCP connection (idempotent).
    void close();

    // Returns true if the socket is open.
    bool is_open() const { return sock_ != kInvalidSock; }

    // Issue one JSON-RPC call over the open socket. Throws
    // std::runtime_error on transport / parse / RPC-error. The
    // exception text names the failing method so callers can surface
    // it directly.
    virtual nlohmann::json call(const std::string& method,
                                const nlohmann::json& params);

    // Bound every send/recv on the open socket (SO_SNDTIMEO / SO_RCVTIMEO).
    // Default: none (the pre-existing behaviour). A timed-out call throws
    // "… timed out …" so the outbox records the outcome as UNKNOWN instead
    // of hanging under its directory lock. Returns false if setsockopt fails.
    bool set_timeout_ms(uint32_t ms);

    // Human-readable diagnostic for the last open() failure.
    const std::string& last_error() const { return last_error_; }

    uint16_t port() const { return port_; }
    const std::string& host() const { return host_; }

private:
    std::string    host_;      // "127.0.0.1" for the loopback ctor
    uint16_t       port_;
    sock_t         sock_;
    std::string    inbuf_;     // leftover bytes between read_line calls
    std::string    last_error_;
};

} // namespace determ::light
