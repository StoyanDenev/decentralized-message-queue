// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/rpc/rpc.hpp>
#include <determ/net/sync_client.hpp>
#include <determ/types.hpp>
#include <determ/crypto/sha2/sha2.h>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace determ::rpc {

using json = nlohmann::json;

namespace {

// v2.16: parse hex string → bytes. Returns empty on parse failure.
std::vector<uint8_t> hex_to_bytes(const std::string& s) {
    if (s.size() % 2 != 0) return {};
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned int byte;
        if (std::sscanf(s.c_str() + i, "%02x", &byte) != 1) return {};
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
}

// v2.16: hex-encode bytes.
std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        o << std::setw(2) << static_cast<int>(data[i]);
    return o.str();
}

// v2.16: canonical serialization of (method, params) for HMAC input.
// Format: "<method>|<params.dump>" where params.dump uses nlohmann's
// default key ordering (insertion-order for json::object). For
// determinism across client/server, both sides must use the same
// params object structure — the client constructs the params and
// computes the HMAC over its own dump; the server re-dumps after
// JSON parsing.
//
// Note: nlohmann::json json::object preserves insertion order, but
// json::parse normalizes to sorted order. To make client-and-server
// agree, both should use sorted keys. We achieve this by serializing
// to a string with json's default "compact" dump which uses
// alphabetical key order for objects (per nlohmann's spec).
std::string canonical_for_hmac(const std::string& method, const json& params) {
    // dump() with no indent uses sorted keys for json::object (since
    // params is parsed from JSON on the server, the parse-then-dump
    // round trip yields the same canonical form the client would
    // compute pre-send).
    return method + "|" + params.dump();
}

std::string hmac_sha256_hex(const std::vector<uint8_t>& key,
                              const std::string& message) {
    // §3.15 swap: C99 HMAC-SHA256 (validated byte-equal vs OpenSSL by
    // `determ test-sha2-c99`; the test-rpc-auth-hmac self-test keeps an
    // OpenSSL mirror as the independent oracle). On the (alloc-failure-only)
    // error path return "" — never matches any client MAC, so auth
    // fails CLOSED.
    unsigned char hmac[32];
    if (determ_hmac_sha256(key.data(), key.size(),
                           reinterpret_cast<const unsigned char*>(message.data()),
                           message.size(), hmac) != 0)
        return {};
    return bytes_to_hex(hmac, 32);
}

} // namespace

// ─── Server ──────────────────────────────────────────────────────────────────

// S-001 mitigation: localhost_only binds to 127.0.0.1 only (now the
// Transport::listen() backend's job — AsioTransport picks loopback vs
// any-interface the same way this ctor used to inline).
RpcServer::RpcServer(net::Transport& transport, net::EventLoop& loop,
                       node::Node& node, uint16_t port,
                       bool localhost_only, const std::string& auth_secret_hex,
                       double rate_per_sec, double burst)
    : transport_(transport)
    , loop_(loop)
    , node_(node)
    , acceptor_(transport_.listen(port, localhost_only))
    , auth_secret_(hex_to_bytes(auth_secret_hex)) {
    rate_limiter_.configure(rate_per_sec, burst);
    std::cout << "[rpc] listening on "
              << (localhost_only ? "127.0.0.1" : "0.0.0.0")
              << ":" << port;
    if (!auth_secret_.empty()) {
        std::cout << " (HMAC auth enabled, "
                  << auth_secret_.size() << "-byte secret)";
    } else if (!localhost_only) {
        // S-001 warning: external bind WITHOUT auth is dangerous. Operator
        // should set rpc_auth_secret OR keep localhost_only=true.
        std::cout << " [WARNING: external bind without HMAC auth — "
                  << "set rpc_auth_secret in config or enable "
                  << "rpc_localhost_only]";
    }
    if (rate_limiter_.enabled()) {
        std::cout << " (rate-limit " << rate_limiter_.rate_per_sec() << "/s, burst "
                  << rate_limiter_.burst() << ")";
    }
    std::cout << "\n";
}

std::string RpcServer::verify_auth(const json& req) const {
    if (auth_secret_.empty()) return ""; // Auth disabled, pass.
    if (!req.contains("auth") || !req["auth"].is_string()) {
        return "auth_required: missing 'auth' field";
    }
    std::string method = req.value("method", "");
    auto params = req.value("params", json::object());
    std::string expected = hmac_sha256_hex(auth_secret_,
                                              canonical_for_hmac(method, params));
    std::string got = req.value("auth", std::string{});
    // Constant-time compare to avoid timing side-channels.
    if (expected.size() != got.size()) return "auth_failed";
    int diff = 0;
    for (size_t i = 0; i < expected.size(); ++i) {
        diff |= (expected[i] ^ got[i]);
    }
    return (diff == 0) ? "" : "auth_failed";
}

void RpcServer::start() { accept_loop(); }

void RpcServer::accept_loop() {
    acceptor_->async_accept(
        [this](std::error_code ec, std::shared_ptr<net::Connection> conn) {
            if (!ec && conn)
                loop_.post([this, conn] { handle_session(conn); });
            accept_loop();
        });
}

void RpcServer::handle_session(std::shared_ptr<net::Connection> conn) {
    // S-014: cache the peer's IP once per session for rate-limit lookup.
    // remote_endpoint() is "ip:port" (never throws) — strip the port the
    // same way GossipNet does for its own per-peer-IP bucket (gossip.cpp):
    // keying by ip:port would give every new connection from the same
    // client a fresh bucket, defeating the limit.
    std::string peer_ip = conn->remote_endpoint();
    auto colon = peer_ip.rfind(':');
    if (colon != std::string::npos) peer_ip = peer_ip.substr(0, colon);

    while (true) {
        std::string line;
        if (!conn->read_line(line)) break;
        if (line.empty()) continue;
        json response;
        try {
            // S-014: rate-limit check BEFORE parse to avoid spending
            // JSON-parse cost on rate-limited callers. Auth check
            // still happens AFTER parse (need the method+params to
            // compute HMAC) — auth-rate-limit ordering: rate-limit
            // fires first because rate-limited callers shouldn't
            // even reveal whether their auth was valid.
            if (!rate_limiter_.consume(peer_ip)) {
                response["result"] = nullptr;
                response["error"]  = "rate_limited";
            } else {
                auto req = json::parse(line);
                // v2.16: HMAC auth check before dispatching. Skip if
                // auth_secret_ is empty (auth disabled).
                std::string auth_err = verify_auth(req);
                if (!auth_err.empty()) {
                    response["result"] = nullptr;
                    response["error"]  = auth_err;
                } else if (req.value("method", "") == "dapp_subscribe") {
                    // v2.20 streaming takeover. Ordering matters:
                    //   1. rate-limit (line-level consume above) — done
                    //   2. HMAC auth — done (auth_err empty here)
                    //   3. subscription weight: a long-lived connection
                    //      is priced as ~100 requests up front so one
                    //      client can't cheaply hoard subscriber slots
                    //      (S-014 extension; 99 more on top of the one
                    //      token already consumed for this line).
                    //   4. hand the connection to the node; on success the
                    //      subscriber's writer thread owns it and this
                    //      session loop must never touch it again.
                    // Validation failures reply through the normal
                    // one-line error envelope and the session survives.
                    std::string sub_err;
                    if (!rate_limiter_.consume(peer_ip, 99.0)) {
                        response["result"] = nullptr;
                        response["error"]  = "rate_limited";
                    } else if (node_.rpc_dapp_subscribe(
                                   conn, req.value("params", json::object()),
                                   sub_err)) {
                        return;  // connection taken over — streaming
                    } else {
                        response["result"] = nullptr;
                        response["error"]  = sub_err;
                    }
                } else {
                    response["result"] = dispatch(req);
                    response["error"]  = nullptr;
                }
            }
        } catch (std::exception& e) {
            response["result"] = nullptr;
            response["error"]  = e.what();
        }
        std::string reply = response.dump() + "\n";
        if (!conn->write_all(reply.data(), reply.size())) break;
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
    // D3.5e-7e / S-036: the frozen epoch-committee checkpoint content read
    // (untrusted on its own; the auditor pins it via the "cc" state_proof).
    if (method == "cc_checkpoint")
        return node_.rpc_cc_checkpoint(params.value("epoch", uint64_t{0}));
    // v2.18/v2.19 Theme 7: DApp registry queries + retrospective messages.
    if (method == "dapp_info")
        return node_.rpc_dapp_info(params.value("domain", std::string{}));
    if (method == "dapp_list")
        return node_.rpc_dapp_list(
            params.value("prefix", std::string{}),
            params.value("topic",  std::string{}));
    if (method == "dapp_messages")
        return node_.rpc_dapp_messages(
            params.value("domain",      std::string{}),
            params.value("from_height", uint64_t{0}),
            params.value("to_height",   uint64_t{0}),
            params.value("topic",       std::string{}));
    if (method == "dapp_subscribers")   // v2.20 observability (R54)
        return node_.rpc_dapp_subscribers();
    if (method == "block")
        return node_.rpc_block(params.value("index", uint64_t{0}));
    if (method == "headers")
        return node_.rpc_headers(params.value("from",  uint64_t{0}),
                                    params.value("count", uint32_t{16}));
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
    if (method == "pending_params")
        return node_.rpc_pending_params();
    if (method == "abort_records")
        return node_.rpc_abort_records();
    throw std::runtime_error("Unknown method: " + method);
}

// ─── Client ──────────────────────────────────────────────────────────────────

json rpc_call(const std::string& host, uint16_t port,
               const std::string& method, const json& params,
               const std::string& auth_secret_hex) {
    net::SyncClient client;
    client.connect(host, port);

    json req = {{"method", method}, {"params", params}};
    // v2.16: auth secret resolution. Order of precedence:
    //   1. Explicit auth_secret_hex argument (programmatic / per-call)
    //   2. DETERM_RPC_AUTH_SECRET env var (operator/CLI standard)
    //   3. None (auth disabled — server accepts only if it also has
    //      no rpc_auth_secret configured)
    std::string effective_secret = auth_secret_hex;
    if (effective_secret.empty()) {
        const char* env = std::getenv("DETERM_RPC_AUTH_SECRET");
        if (env && *env) effective_secret = env;
    }
    if (!effective_secret.empty()) {
        auto key = hex_to_bytes(effective_secret);
        if (key.empty()) {
            throw std::runtime_error(
                "rpc_call: auth secret is not valid hex "
                "(expected 2N hex chars from --auth-secret or "
                "DETERM_RPC_AUTH_SECRET env var)");
        }
        req["auth"] = hmac_sha256_hex(key,
            canonical_for_hmac(method, params));
    }
    std::string line = req.dump() + "\n";
    client.write_all(line.data(), line.size());
    std::string resp = client.read_line();

    auto j = json::parse(resp);
    if (!j["error"].is_null())
        throw std::runtime_error(j["error"].get<std::string>());
    return j["result"];
}

} // namespace determ::rpc
