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

class RpcClient {
public:
    explicit RpcClient(uint16_t port);
    ~RpcClient();

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
    nlohmann::json call(const std::string& method,
                        const nlohmann::json& params);

    // Human-readable diagnostic for the last open() failure.
    const std::string& last_error() const { return last_error_; }

    uint16_t port() const { return port_; }

private:
    uint16_t       port_;
    sock_t         sock_;
    std::string    inbuf_;     // leftover bytes between read_line calls
    std::string    last_error_;
};

} // namespace determ::light
