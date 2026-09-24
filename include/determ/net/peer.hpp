// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/net/messages.hpp>
#include <determ/net/transport.hpp>
#include <functional>
#include <memory>
#include <string>
#include <deque>
#include <mutex>

namespace determ::net {

class Peer : public std::enable_shared_from_this<Peer> {
public:
    using MessageHandler = std::function<void(std::shared_ptr<Peer>, const Message&)>;
    using CloseHandler   = std::function<void(std::shared_ptr<Peer>)>;

    // §minix net::Transport seam — Peer sits on a Connection (byte stream)
    // instead of a raw asio socket; all framing (4-byte BE length prefix,
    // S-022 caps) stays here, so the backend swap cannot change wire bytes.
    explicit Peer(std::shared_ptr<Connection> conn);
    ~Peer();

    void start(MessageHandler on_msg, CloseHandler on_close);
    void send(const Message& msg);
    void close();

    std::string address() const { return address_; }
    std::string domain()  const { return domain_;  }
    void set_domain(const std::string& d) { domain_ = d; }

    // rev.9 B2c.5: per-peer chain identity learned from HELLO. Used by
    // gossip dispatcher to filter cross-chain message pollution (a shard
    // node peering with a beacon node should not consume the beacon's
    // intra-chain BLOCK / TRANSACTION / etc as its own).
    ChainRole chain_role() const { return chain_role_; }
    ShardId          shard_id()   const { return shard_id_; }
    void set_chain_role(ChainRole r) { chain_role_ = r; }
    void set_shard_id(ShardId s)            { shard_id_ = s; }
    bool hello_received() const { return hello_received_; }
    void mark_hello_received()  { hello_received_ = true; }

    // S-082: bound egress write queue per peer to prevent unbounded memory growth
    // on slow or non-reading peers.
    static constexpr size_t MAX_PEER_WRITE_QUEUE = 256;

    size_t write_queue_size() {
        std::lock_guard<std::mutex> lock(write_mutex_);
        return write_queue_.size();
    }

private:
    void read_header();
    void read_body(uint32_t len);
    void do_write();

    std::shared_ptr<Connection>   conn_;
    std::string                   address_;
    std::string                   domain_;
    ChainRole              chain_role_{ChainRole::SINGLE};
    ShardId                       shard_id_{0};
    bool                          hello_received_{false};
    std::array<uint8_t, 4>        header_buf_{};
    std::vector<uint8_t>          body_buf_;
    std::deque<std::vector<uint8_t>> write_queue_;
    std::mutex                    write_mutex_;
    MessageHandler                on_msg_;
    CloseHandler                  on_close_;
};

// Async outbound connection helper: resolve + connect via the Transport seam,
// wrapping the resulting Connection in a Peer.
void async_connect(Transport& transport,
                   const std::string& host, uint16_t port,
                   std::function<void(std::shared_ptr<Peer>)> on_connect,
                   std::function<void(const std::string&)>    on_error);

} // namespace determ::net
