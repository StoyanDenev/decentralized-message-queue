// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/rpc/rpc.hpp>
#include <determ/types.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
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
    unsigned char hmac[32];
    unsigned int  hmac_len = 0;
    HMAC(EVP_sha256(),
         key.data(),  static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(message.data()),
         message.size(),
         hmac, &hmac_len);
    return bytes_to_hex(hmac, hmac_len);
}

} // namespace

// ─── Server ──────────────────────────────────────────────────────────────────

// S-001 mitigation: localhost_only binds to 127.0.0.1 only.
// asio::ip::address_v4::loopback() returns the loopback address — equivalent
// to make_address("127.0.0.1") but avoids the string-parsing path.
RpcServer::RpcServer(asio::io_context& io, node::Node& node, uint16_t port,
                       bool localhost_only, const std::string& auth_secret_hex,
                       double rate_per_sec, double burst)
    : io_(io)
    , node_(node)
    , acceptor_(io, asio::ip::tcp::endpoint(
                       localhost_only
                           ? asio::ip::tcp::endpoint(
                                 asio::ip::address_v4::loopback(), port).address()
                           : asio::ip::address(asio::ip::address_v4::any()),
                       port))
    , auth_secret_(hex_to_bytes(auth_secret_hex))
    , rate_per_sec_(rate_per_sec)
    , burst_(burst) {
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
    if (rate_per_sec_ > 0.0 && burst_ > 0.0) {
        std::cout << " (rate-limit " << rate_per_sec_ << "/s, burst "
                  << burst_ << ")";
    }
    std::cout << "\n";
}

// S-014: token-bucket consume. Refill based on wall-clock elapsed
// since last consume (capped at `burst_` capacity); attempt to
// consume 1 token. Returns true on success, false on rate-limited.
// rate_per_sec_ == 0 disables the gate (always true).
bool RpcServer::consume_rate_token(const std::string& ip) {
    if (rate_per_sec_ <= 0.0 || burst_ <= 0.0) return true;
    std::lock_guard<std::mutex> lk(buckets_mutex_);
    auto now = std::chrono::steady_clock::now();
    auto& b = buckets_[ip];
    if (b.last.time_since_epoch().count() == 0) {
        // First request from this IP: start with full bucket.
        b.tokens = burst_;
        b.last   = now;
    } else {
        double elapsed_sec = std::chrono::duration<double>(now - b.last).count();
        b.tokens = std::min(burst_, b.tokens + elapsed_sec * rate_per_sec_);
        b.last   = now;
    }
    if (b.tokens < 1.0) return false;
    b.tokens -= 1.0;
    return true;
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
    auto socket = std::make_shared<asio::ip::tcp::socket>(io_);
    acceptor_.async_accept(*socket, [this, socket](std::error_code ec) {
        if (!ec)
            asio::post(io_, [this, socket] { handle_session(socket); });
        accept_loop();
    });
}

void RpcServer::handle_session(std::shared_ptr<asio::ip::tcp::socket> socket) {
    // S-014: cache the peer's IP once per session for rate-limit lookup.
    // remote_endpoint() can throw on disconnected sockets; catch and
    // default to "unknown" (rate-limit bucket name; unaffected
    // operationally since rate limiter is per-name).
    std::string peer_ip;
    try {
        auto ep = socket->remote_endpoint();
        peer_ip = ep.address().to_string();
    } catch (...) {
        peer_ip = "unknown";
    }

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
            // S-014: rate-limit check BEFORE parse to avoid spending
            // JSON-parse cost on rate-limited callers. Auth check
            // still happens AFTER parse (need the method+params to
            // compute HMAC) — auth-rate-limit ordering: rate-limit
            // fires first because rate-limited callers shouldn't
            // even reveal whether their auth was valid.
            if (!consume_rate_token(peer_ip)) {
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
               const std::string& method, const json& params,
               const std::string& auth_secret_hex) {
    asio::io_context io;
    asio::ip::tcp::resolver resolver(io);
    auto endpoints = resolver.resolve(host, std::to_string(port));

    asio::ip::tcp::socket socket(io);
    asio::connect(socket, endpoints);

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
