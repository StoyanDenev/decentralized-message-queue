// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// net::SyncClient implementation — socket code ported from
// light/rpc_client.cpp (WinsockInit refcounting, loopback fast path,
// getaddrinfo branch, carry-buffer line reads), reshaped from that
// class's bool/last_error() model to a throwing one and extended with
// read_exact for the binary gossip-frame clients.
//
// All OS headers live HERE; the public header stays OS-header-free
// (minix file-layout rule — see the header comment).

#include <determ/net/sync_client.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX   // keep windows.h's min/max macros away from std::min
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <netdb.h>   // getaddrinfo / addrinfo / freeaddrinfo (POSIX); Win32 gets them from <ws2tcpip.h>
#endif

namespace determ::net {

namespace {

#ifdef _WIN32
using sock_t = SOCKET;
constexpr sock_t kOsInvalid = INVALID_SOCKET;
#else
using sock_t = int;
constexpr sock_t kOsInvalid = -1;
#endif

// The header stores the handle as std::uintptr_t so it carries no OS
// types. Round-trips are exact on both platforms: SOCKET is UINT_PTR on
// Windows (INVALID_SOCKET == UINTPTR_MAX == kInvalidSock), and a POSIX
// fd is >= 0 (its -1 failure value converts modularly to UINTPTR_MAX,
// again matching kInvalidSock).
inline sock_t as_os(std::uintptr_t s) { return static_cast<sock_t>(s); }

#ifdef _WIN32
// One-shot Winsock init for the process. Reference-counted internally
// because multiple SyncClient instances can co-exist; only the first
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

} // namespace

SyncClient::SyncClient() : sock_(kInvalidSock) {
#ifdef _WIN32
    (void)winsock();
#endif
}

SyncClient::~SyncClient() {
    close();
}

void SyncClient::connect(const std::string& host, uint16_t port) {
    if (sock_ != kInvalidSock) {
        throw std::runtime_error(
            "SyncClient: already connected (close() first)");
    }
#ifdef _WIN32
    if (!winsock().ok_) {
        throw std::runtime_error("SyncClient: WSAStartup failed");
    }
#endif
    const std::string where = host + ":" + std::to_string(port);

    // Loopback fast path — mirrors light/rpc_client.cpp::open(). The
    // dominant CLI case (local daemon) never touches the resolver.
    const bool is_loopback =
        host.empty() || host == "127.0.0.1" || host == "localhost";
    if (is_loopback) {
        sock_t s = ::socket(AF_INET, SOCK_STREAM, 0);
        if (s == kOsInvalid) {
            throw std::runtime_error(
                "SyncClient: socket() failed connecting to " + where);
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
#ifdef _WIN32
        addr.sin_addr.s_addr = htonl(0x7F000001UL);
#else
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#endif
        if (::connect(s, reinterpret_cast<sockaddr*>(&addr),
                      sizeof(addr)) != 0) {
            close_sock(s);
            throw std::runtime_error(
                "SyncClient: connect() to " + where
                + " failed (daemon not running?)");
        }
        sock_ = static_cast<std::uintptr_t>(s);
        return;
    }

    // Host path — resolve host:port via getaddrinfo (IPv4, matching the
    // daemon's listen socket) and connect to the first address that
    // accepts.
    struct addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    const std::string portstr = std::to_string(port);
    const int gai = ::getaddrinfo(host.c_str(), portstr.c_str(),
                                  &hints, &res);
    if (gai != 0 || res == nullptr) {
        if (res) ::freeaddrinfo(res);
        throw std::runtime_error(
            "SyncClient: getaddrinfo(" + where + ") failed");
    }
    sock_t s = kOsInvalid;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        sock_t cand = ::socket(p->ai_family, p->ai_socktype,
                               p->ai_protocol);
        if (cand == kOsInvalid) continue;
        if (::connect(cand, p->ai_addr,
                      static_cast<int>(p->ai_addrlen)) == 0) {
            s = cand;
            break;
        }
        close_sock(cand);
    }
    ::freeaddrinfo(res);
    if (s == kOsInvalid) {
        throw std::runtime_error(
            "SyncClient: connect() to " + where
            + " failed (daemon not running / unreachable?)");
    }
    sock_ = static_cast<std::uintptr_t>(s);
}

void SyncClient::write_all(const void* buf, std::size_t n) {
    if (sock_ == kInvalidSock) {
        throw std::runtime_error("SyncClient::write_all: not connected");
    }
    const char* p = static_cast<const char*>(buf);
    std::size_t sent = 0;
    while (sent < n) {
#ifdef _WIN32
        // send() takes an int count on Winsock; chunk defensively (the
        // callers' frames are capped far below INT_MAX, but the class
        // does not rely on that).
        const int chunk = static_cast<int>(
            std::min<std::size_t>(n - sent, std::size_t{1} << 30));
        const int r = ::send(as_os(sock_), p + sent, chunk, 0);
#else
        // MSG_NOSIGNAL: a write racing a daemon-side close must surface as
        // the error/throw path below, not kill the CLI with SIGPIPE — the
        // asio clients this class replaces OR'd it into every sync send
        // (asio socket_ops), so its absence would be a POSIX regression
        // (dapp-subscribe --reconnect's redial loop depends on surviving
        // exactly this race).
#ifdef MSG_NOSIGNAL
        const int send_flags = MSG_NOSIGNAL;
#else
        const int send_flags = 0;
#endif
        const ssize_t r = ::send(as_os(sock_), p + sent, n - sent, send_flags);
#endif
        if (r <= 0) {
            throw std::runtime_error(
                "SyncClient::write_all: send failed after "
                + std::to_string(sent) + " of " + std::to_string(n)
                + " bytes");
        }
        sent += static_cast<std::size_t>(r);
    }
}

void SyncClient::read_exact(void* buf, std::size_t n) {
    if (sock_ == kInvalidSock) {
        throw std::runtime_error("SyncClient::read_exact: not connected");
    }
    char* out = static_cast<char*>(buf);
    std::size_t got = 0;
    // Drain the carry buffer FIRST: a previous read_line may already
    // have pulled the leading bytes of this frame off the socket.
    // Skipping this drain is the classic interleaving bug this class
    // exists to prevent.
    if (got < n && !inbuf_.empty()) {
        const std::size_t take = std::min(inbuf_.size(), n - got);
        std::memcpy(out + got, inbuf_.data(), take);
        inbuf_.erase(0, take);
        got += take;
    }
    while (got < n) {
#ifdef _WIN32
        const int want = static_cast<int>(
            std::min<std::size_t>(n - got, std::size_t{1} << 30));
        const int r = ::recv(as_os(sock_), out + got, want, 0);
#else
        const ssize_t r = ::recv(as_os(sock_), out + got, n - got, 0);
#endif
        if (r <= 0) {
            throw std::runtime_error(
                "SyncClient::read_exact: connection closed after "
                + std::to_string(got) + " of " + std::to_string(n)
                + " bytes");
        }
        got += static_cast<std::size_t>(r);
    }
}

std::string SyncClient::read_line() {
    if (sock_ == kInvalidSock) {
        throw std::runtime_error("SyncClient::read_line: not connected");
    }
    while (true) {
        const auto nl = inbuf_.find('\n');
        if (nl != std::string::npos) {
            std::string line = inbuf_.substr(0, nl);
            inbuf_.erase(0, nl + 1);
            return line;
        }
        char tmp[4096];
#ifdef _WIN32
        const int r = ::recv(as_os(sock_), tmp,
                             static_cast<int>(sizeof(tmp)), 0);
#else
        const ssize_t r = ::recv(as_os(sock_), tmp, sizeof(tmp), 0);
#endif
        if (r <= 0) {
            throw std::runtime_error(
                "SyncClient::read_line: connection closed before '\\n'"
                " (peer closed connection?)");
        }
        inbuf_.append(tmp, static_cast<std::size_t>(r));
    }
}

void SyncClient::close() {
    if (sock_ != kInvalidSock) {
        close_sock(as_os(sock_));
        sock_ = kInvalidSock;
    }
    inbuf_.clear();
}

} // namespace determ::net
