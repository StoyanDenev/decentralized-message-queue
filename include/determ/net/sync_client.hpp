// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// net::SyncClient — blocking TCP client for CLI tools; the asio-free
// replacement for the synchronous asio clients on the minix cut-asio
// checklist (docs/proofs/MinixTacticalProfile.md §4.4 "CLI blocking
// clients"): rpc::rpc_call's line-oriented JSON-RPC exchange (write one
// '\n'-terminated line, read one back) and the headers/snapshot
// gossip-frame fetchers in main.cpp (write a length-prefixed binary
// frame, read exactly-4-byte header then exactly-N-byte body).
//
// Socket code mirrors light/rpc_client.cpp (the repo's reviewed
// BSD-socket/Winsock client): refcounted Winsock init, loopback fast
// path + getaddrinfo(IPv4) branch, '\n'-delimited line reads with a
// carry buffer for bytes received past the delimiter.
//
// Interleaving read_line and read_exact on one connection is SAFE:
// bytes a read_line pulled off the socket past its '\n' are held in the
// carry buffer, and read_exact drains that buffer BEFORE reading from
// the socket. The carry buffer is the single source of already-received
// bytes for both read paths.
//
// Error model: every operation throws std::runtime_error with a
// diagnostic (connect names host:port); there are no error codes to
// check. Suits the CLI call sites, which wrap the exchange in one
// try/catch and print e.what().
//
// Minix file-layout rule (deliberately stricter than light/
// rpc_client.hpp): this header includes ZERO OS headers. The socket
// handle is stored as std::uintptr_t — SOCKET is UINT_PTR on Windows,
// and a POSIX int fd converts losslessly — so winsock2.h/sys/socket.h
// live in src/net/sync_client.cpp only and never leak into includers.

#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace determ::net {

class SyncClient {
public:
    SyncClient();
    ~SyncClient();                       // closes if open
    SyncClient(const SyncClient&) = delete;
    SyncClient& operator=(const SyncClient&) = delete;

    // Resolve + connect. Throws std::runtime_error with a diagnostic
    // naming host:port on failure, or if already connected (close()
    // first). "127.0.0.1" / "localhost" / "" take a loopback fast path
    // that skips the resolver (mirrors light/rpc_client.cpp); any other
    // host resolves via getaddrinfo (IPv4) and connects to the first
    // address that accepts.
    void connect(const std::string& host, uint16_t port);

    // Blocking whole-span write of n bytes. Throws std::runtime_error
    // on any short write or socket error.
    void write_all(const void* buf, std::size_t n);

    // Blocking read of exactly n bytes (the gossip-frame shape: 4-byte
    // big-endian length header, then the body). Drains the carry buffer
    // left by a previous read_line before touching the socket. Throws
    // std::runtime_error on EOF or error.
    void read_exact(void* buf, std::size_t n);

    // Blocking read of one line delimited by '\n' (consumed, excluded
    // from the result). Bytes received past the delimiter carry over to
    // the next read_line OR read_exact call. Throws std::runtime_error
    // on EOF/error.
    std::string read_line();

    // Idempotent; also discards any carried-over bytes.
    void close();

    bool is_open() const { return sock_ != kInvalidSock; }

private:
    // Closed sentinel. UINTPTR_MAX equals both Winsock's INVALID_SOCKET
    // ((SOCKET)~0) and the modular conversion of a POSIX -1, so the
    // .cpp-side handle conversions round-trip it exactly on both
    // platforms (a valid POSIX fd is >= 0 and can never collide).
    static constexpr std::uintptr_t kInvalidSock =
        ~static_cast<std::uintptr_t>(0);

    std::uintptr_t sock_;    // OS socket handle (SOCKET / int fd)
    std::string    inbuf_;   // carry buffer: leftover bytes between reads
};

} // namespace determ::net
