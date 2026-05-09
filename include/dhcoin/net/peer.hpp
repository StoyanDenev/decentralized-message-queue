#pragma once
#include <dhcoin/net/messages.hpp>
#include <asio.hpp>
#include <functional>
#include <memory>
#include <string>
#include <deque>
#include <mutex>

namespace dhcoin::net {

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

} // namespace dhcoin::net
