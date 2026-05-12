// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/rpc/rpc.hpp>
#include <iostream>

namespace determ::rpc {

using json = nlohmann::json;

// ─── Server ──────────────────────────────────────────────────────────────────

// S-001 mitigation: localhost_only binds to 127.0.0.1 only.
// asio::ip::address_v4::loopback() returns the loopback address — equivalent
// to make_address("127.0.0.1") but avoids the string-parsing path.
RpcServer::RpcServer(asio::io_context& io, node::Node& node, uint16_t port,
                       bool localhost_only)
    : io_(io)
    , node_(node)
    , acceptor_(io, asio::ip::tcp::endpoint(
                       localhost_only
                           ? asio::ip::tcp::endpoint(
                                 asio::ip::address_v4::loopback(), port).address()
                           : asio::ip::address(asio::ip::address_v4::any()),
                       port)) {
    std::cout << "[rpc] listening on "
              << (localhost_only ? "127.0.0.1" : "0.0.0.0")
              << ":" << port << "\n";
}

void RpcServer::start() { accept_loop(); }

void RpcServer::accept_loop() {
    auto socket = std::make_shared<asio::ip::tcp::socket>(io_);
    acceptor_.async_accept(*socket, [this, socket](std::error_code ec) {
        if (!ec)
            asio::post(io_, [this, socket] { handle_session(socket); });
        accept_loop();
    });
}

void RpcServer::handle_session(std::shared_ptr<asio::ip::tcp::socket> socket) {
    asio::streambuf buf;
    std::error_code ec;
    while (!ec) {
        asio::read_until(*socket, buf, '\n', ec);
        if (ec) break;
        std::istream is(&buf);
        std::string line;
        std::getline(is, line);
        if (line.empty()) continue;
        json response;
        try {
            auto req = json::parse(line);
            response["result"] = dispatch(req);
            response["error"]  = nullptr;
        } catch (std::exception& e) {
            response["result"] = nullptr;
            response["error"]  = e.what();
        }
        std::string reply = response.dump() + "\n";
        asio::write(*socket, asio::buffer(reply), ec);
    }
}

json RpcServer::dispatch(const json& req) {
    std::string method = req.value("method", "");
    auto params = req.value("params", json::object());

    if (method == "status")   return node_.rpc_status();
    if (method == "peers")    return node_.rpc_peers();
    if (method == "register") return node_.rpc_register();
    if (method == "balance")
        return node_.rpc_balance(params.value("domain", ""));
    if (method == "send") {
        std::string to  = params.value("to",     "");
        uint64_t amount = params.value("amount", uint64_t{0});
        uint64_t fee    = params.value("fee",    uint64_t{0});
        return node_.rpc_send(to, amount, fee);
    }
    if (method == "stake") {
        uint64_t amount = params.value("amount", uint64_t{0});
        uint64_t fee    = params.value("fee",    uint64_t{0});
        return node_.rpc_stake(amount, fee);
    }
    if (method == "unstake") {
        uint64_t amount = params.value("amount", uint64_t{0});
        uint64_t fee    = params.value("fee",    uint64_t{0});
        return node_.rpc_unstake(amount, fee);
    }
    if (method == "nonce")
        return node_.rpc_nonce(params.value("domain", ""));
    if (method == "stake_info")
        return node_.rpc_stake_info(params.value("domain", ""));
    if (method == "submit_tx")
        return node_.rpc_submit_tx(params.value("tx", json::object()));
    if (method == "submit_equivocation")
        return node_.rpc_submit_equivocation(
            params.value("event", json::object()));
    if (method == "snapshot")
        return node_.rpc_snapshot(params.value("headers", uint32_t{16}));
    if (method == "state_root")
        return node_.rpc_state_root();
    if (method == "state_proof")
        return node_.rpc_state_proof(
            params.value("namespace", std::string{}),
            params.value("key",       std::string{}));
    // v2.18/v2.19 Theme 7: DApp registry queries.
    if (method == "dapp_info")
        return node_.rpc_dapp_info(params.value("domain", std::string{}));
    if (method == "dapp_list")
        return node_.rpc_dapp_list(
            params.value("prefix", std::string{}),
            params.value("topic",  std::string{}));
    if (method == "block")
        return node_.rpc_block(params.value("index", uint64_t{0}));
    if (method == "chain_summary")
        return node_.rpc_chain_summary(params.value("last_n", uint32_t{10}));
    if (method == "validators")
        return node_.rpc_validators();
    if (method == "committee")
        return node_.rpc_committee();
    if (method == "account")
        return node_.rpc_account(params.value("address", std::string{}));
    if (method == "tx")
        return node_.rpc_tx(params.value("hash", std::string{}));
    throw std::runtime_error("Unknown method: " + method);
}

// ─── Client ──────────────────────────────────────────────────────────────────

json rpc_call(const std::string& host, uint16_t port,
               const std::string& method, const json& params) {
    asio::io_context io;
    asio::ip::tcp::resolver resolver(io);
    auto endpoints = resolver.resolve(host, std::to_string(port));

    asio::ip::tcp::socket socket(io);
    asio::connect(socket, endpoints);

    json req = {{"method", method}, {"params", params}};
    std::string line = req.dump() + "\n";
    asio::write(socket, asio::buffer(line));

    asio::streambuf buf;
    asio::read_until(socket, buf, '\n');
    std::istream is(&buf);
    std::string resp;
    std::getline(is, resp);

    auto j = json::parse(resp);
    if (!j["error"].is_null())
        throw std::runtime_error(j["error"].get<std::string>());
    return j["result"];
}

} // namespace determ::rpc
