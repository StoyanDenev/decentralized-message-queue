// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/net/rate_limiter.hpp>
#include <determ/node/node.hpp>
#include <asio.hpp>
#include <functional>
#include <memory>
#include <string>

namespace determ::rpc {

// Minimal line-oriented JSON-RPC server.
// Client sends: {"method": "...", "params": {...}}\n
// Server replies: {"result": ..., "error": null}\n
class RpcServer {
public:
    // S-001 mitigation: when localhost_only is true (the new default),
    // the acceptor binds to 127.0.0.1 only. External clients cannot
    // reach the RPC port even if firewall rules would allow them.
    // Pre-mitigation default (tcp::v4() any-interface bind) is reached
    // only by explicitly setting rpc_localhost_only=false in config.
    //
    // v2.16 / S-001 full closure: HMAC-SHA-256 RPC authentication.
    // auth_secret_hex is a hex-encoded shared secret. Empty = auth
    // disabled (only localhost-only enforcement). Non-empty = every
    // RPC request must carry an `auth` field that's hex(HMAC-SHA-256(
    // secret, method || "|" || params_canonical_json)). Server
    // rejects requests with missing or wrong auth.
    // S-014: token-bucket rate limiter parameters. `rate_per_sec` is
    // the steady-state RPC-calls-per-second budget per peer IP;
    // `burst` is the bucket capacity (max calls in a sudden burst
    // before steady-state rate kicks in). Both 0 disables rate
    // limiting entirely (default behavior, backward compat).
    RpcServer(asio::io_context& io, node::Node& node, uint16_t port,
                bool localhost_only = true,
                const std::string& auth_secret_hex = "",
                double rate_per_sec = 0.0,
                double burst = 0.0);
    void start();

private:
    void accept_loop();
    void handle_session(std::shared_ptr<asio::ip::tcp::socket> socket);
    nlohmann::json dispatch(const nlohmann::json& req);
    // v2.16: verify HMAC if auth_secret_ is set. Returns empty string on
    // pass; error message on failure. No-op when auth is disabled.
    std::string verify_auth(const nlohmann::json& req) const;
    asio::io_context&             io_;
    node::Node&                   node_;
    asio::ip::tcp::acceptor       acceptor_;
    std::vector<uint8_t>          auth_secret_;  // empty = auth disabled

    // S-014: per-peer-IP token bucket. Shared limiter type with GossipNet.
    net::RateLimiter              rate_limiter_;
};

// Simple blocking RPC client — used by CLI to talk to a running node.
// v2.16: if auth_secret_hex is set, every request includes a
// computed HMAC-SHA-256 `auth` field.
nlohmann::json rpc_call(const std::string& host, uint16_t port,
                         const std::string& method,
                         const nlohmann::json& params = {},
                         const std::string& auth_secret_hex = "");

} // namespace determ::rpc
