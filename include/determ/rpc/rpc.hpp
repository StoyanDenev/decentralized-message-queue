// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/node/node.hpp>
#include <asio.hpp>
#include <functional>
#include <memory>

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
    RpcServer(asio::io_context& io, node::Node& node, uint16_t port,
                bool localhost_only = true);
    void start();

private:
    void accept_loop();
    void handle_session(std::shared_ptr<asio::ip::tcp::socket> socket);
    nlohmann::json dispatch(const nlohmann::json& req);

    asio::io_context&             io_;
    node::Node&                   node_;
    asio::ip::tcp::acceptor       acceptor_;
};

// Simple blocking RPC client — used by CLI to talk to a running node
nlohmann::json rpc_call(const std::string& host, uint16_t port,
                         const std::string& method,
                         const nlohmann::json& params = {});

} // namespace determ::rpc
