// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light RPC client implementation.
//
// Ported from wallet/main.cpp::rpc_call_over_socket pattern (line ~8778).
// The wallet binary inlines the helpers; the light-client splits them
// out into a small class so composite commands (verify-chain,
// balance-trustless, verify-and-submit) can reuse a single TCP
// connection across multiple RPCs without re-opening the socket.

#include "rpc_client.hpp"
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#ifndef _WIN32
#  include <netdb.h>   // getaddrinfo / addrinfo / freeaddrinfo (POSIX); Win32 gets them from <ws2tcpip.h>
#endif

namespace determ::light {

namespace {

#ifdef _WIN32
// One-shot Winsock init for the process. Reference-counted internally
// because multiple RpcClient instances can co-exist; only the first
// WSAStartup matters, and WSACleanup is reference-counted by the OS.
struct WinsockInit {
    WinsockInit() : ok_(false) {
        WSADATA wsa{};
        ok_ = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    }
    ~WinsockInit() { if (ok_) WSACleanup(); }
    bool ok_;
};
WinsockInit& winsock() {
    static WinsockInit w;
    return w;
}
#endif

inline void close_sock(sock_t s) {
#ifdef _WIN32
    closesocket(s);
#else
    ::close(s);
#endif
}

// Send `line + \n` over the open socket. Returns false on any short
// write or socket error.
bool send_line(sock_t s, const std::string& payload) {
    std::string buf = payload;
    if (buf.empty() || buf.back() != '\n') buf.push_back('\n');
    size_t sent = 0;
    while (sent < buf.size()) {
#ifdef _WIN32
        int n = ::send(s, buf.data() + sent,
                       static_cast<int>(buf.size() - sent), 0);
#else
        ssize_t n = ::send(s, buf.data() + sent, buf.size() - sent, 0);
#endif
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

// Read bytes until we see '\n'; return the line content (without
// the newline). Buffers any leftover bytes after the newline in
// `inbuf` for subsequent reads.
std::optional<std::string> read_line(sock_t s, std::string& inbuf) {
    while (true) {
        auto nl = inbuf.find('\n');
        if (nl != std::string::npos) {
            std::string line = inbuf.substr(0, nl);
            inbuf.erase(0, nl + 1);
            return line;
        }
        char tmp[4096];
#ifdef _WIN32
        int n = ::recv(s, tmp, sizeof(tmp), 0);
#else
        ssize_t n = ::recv(s, tmp, sizeof(tmp), 0);
#endif
        if (n <= 0) return std::nullopt;
        inbuf.append(tmp, static_cast<size_t>(n));
    }
}

} // namespace

RpcClient::RpcClient(uint16_t port)
    : host_("127.0.0.1"), port_(port), sock_(kInvalidSock) {
#ifdef _WIN32
    (void)winsock();
#endif
}

RpcClient::RpcClient(std::string host, uint16_t port)
    : host_(std::move(host)), port_(port), sock_(kInvalidSock) {
#ifdef _WIN32
    (void)winsock();
#endif
}

RpcClient::~RpcClient() {
    close();
}

bool RpcClient::open() {
    if (sock_ != kInvalidSock) return true;
#ifdef _WIN32
    if (!winsock().ok_) {
        last_error_ = "WSAStartup failed";
        return false;
    }
#endif
    // Loopback fast path — UNCHANGED from the original (every existing
    // command + the port-only ctor route here). A non-loopback host takes
    // the getaddrinfo branch below; this preserves the loopback path
    // byte-for-byte so the 18 existing determ-light commands are unaffected.
    const bool is_loopback =
        host_.empty() || host_ == "127.0.0.1" || host_ == "localhost";
    if (is_loopback) {
        sock_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ == kInvalidSock) {
            last_error_ = "socket() failed";
            return false;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port_);
#ifdef _WIN32
        addr.sin_addr.s_addr = htonl(0x7F000001UL);
#else
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#endif
        if (::connect(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            close_sock(sock_);
            sock_ = kInvalidSock;
            last_error_ = "connect() to 127.0.0.1:" + std::to_string(port_)
                        + " failed (daemon not running?)";
            return false;
        }
        last_error_.clear();
        return true;
    }

    // Host path — resolve host_:port_ via getaddrinfo (IPv4) and connect to
    // the first address that accepts. Enables cross-HOST multi-peer
    // cross-check. The socket family/proto come from the resolved addrinfo.
    struct addrinfo hints{};
    hints.ai_family   = AF_INET;       // IPv4 (matches the daemon's listen socket)
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    const std::string portstr = std::to_string(port_);
    const int gai = ::getaddrinfo(host_.c_str(), portstr.c_str(), &hints, &res);
    if (gai != 0 || res == nullptr) {
        if (res) ::freeaddrinfo(res);
        last_error_ = "getaddrinfo(" + host_ + ":" + portstr + ") failed";
        return false;
    }
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        sock_t s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == kInvalidSock) continue;
        if (::connect(s, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0) {
            sock_ = s;
            break;
        }
        close_sock(s);
    }
    ::freeaddrinfo(res);
    if (sock_ == kInvalidSock) {
        last_error_ = "connect() to " + host_ + ":" + portstr
                    + " failed (daemon not running / unreachable?)";
        return false;
    }
    last_error_.clear();
    return true;
}

void RpcClient::close() {
    if (sock_ != kInvalidSock) {
        close_sock(sock_);
        sock_ = kInvalidSock;
    }
    inbuf_.clear();
}

nlohmann::json RpcClient::call(const std::string& method,
                                const nlohmann::json& params) {
    if (sock_ == kInvalidSock) {
        throw std::runtime_error("RPC client: socket not open (call open() first)");
    }
    nlohmann::json req = {{"method", method}, {"params", params}};
    if (!send_line(sock_, req.dump())) {
        throw std::runtime_error("send failed for " + method);
    }
    auto line = read_line(sock_, inbuf_);
    if (!line) {
        throw std::runtime_error("no response for " + method
                                 + " (daemon closed connection?)");
    }
    nlohmann::json resp;
    try {
        resp = nlohmann::json::parse(*line);
    } catch (const std::exception& e) {
        throw std::runtime_error("malformed response for " + method
                                 + ": " + e.what());
    }
    // The daemon's reply shape: `{"result": ..., "error": null | "..."}`.
    // Treat null-error as success; non-null error throws.
    if (resp.contains("error") && !resp["error"].is_null()) {
        std::string err = resp["error"].dump();
        throw std::runtime_error("RPC error on " + method + ": " + err);
    }
    return resp.value("result", nlohmann::json());
}

} // namespace determ::light
