// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Unchained Contributors
#pragma once
#include <unchained/net/messages.hpp>
#include <asio.hpp>
#include <functional>
#include <memory>
#include <string>
#include <deque>
#include <mutex>

namespace unchained::net {

class Peer : public std::enable_shared_from_this<Peer> {
public:
    using MessageHandler = std::function<void(std::shared_ptr<Peer>, const Message&)>;
    using CloseHandler   = std::function<void(std::shared_ptr<Peer>)>;

    explicit Peer(asio::ip::tcp::socket socket);
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

    // A3 / S8: the per-pair wire-format version, negotiated via HELLO.
    // 0 = legacy JSON (pre-A3 default). 1 = binary envelope. Stays at 0
    // until HELLO arrives; that lets us interop seamlessly with peers
    // that never advertise a version.
    uint8_t wire_version() const            { return wire_version_; }
    void    set_wire_version(uint8_t v)     { wire_version_ = v; }

private:
    void read_header();
    void read_body(uint32_t len);
    void do_write();

    asio::ip::tcp::socket         socket_;
    std::string                   address_;
    std::string                   domain_;
    ChainRole              chain_role_{ChainRole::SINGLE};
    ShardId                       shard_id_{0};
    bool                          hello_received_{false};
    // A3 / S8: per-pair negotiated wire format. Default 0 (legacy JSON)
    // until HELLO upgrades us. Updated by GossipNet on HELLO receipt.
    uint8_t                       wire_version_{kWireVersionLegacy};
    std::array<uint8_t, 4>        header_buf_{};
    std::vector<uint8_t>          body_buf_;
    std::deque<std::vector<uint8_t>> write_queue_;
    std::mutex                    write_mutex_;
    MessageHandler                on_msg_;
    CloseHandler                  on_close_;
};

// Async outbound connection helper
void async_connect(asio::io_context& io,
                   const std::string& host, uint16_t port,
                   std::function<void(std::shared_ptr<Peer>)> on_connect,
                   std::function<void(const std::string&)>    on_error);

} // namespace unchained::net
