#pragma once
#include <dhcoin/net/peer.hpp>
#include <dhcoin/chain/block.hpp>
#include <dhcoin/node/producer.hpp>
#include <asio.hpp>
#include <functional>
#include <memory>
#include <vector>
#include <mutex>
#include <string>

namespace dhcoin::net {

class GossipNet {
public:
    explicit GossipNet(asio::io_context& io);

    void listen(uint16_t port);
    void connect(const std::string& host, uint16_t port);
    void broadcast(const Message& msg);
    void send_to_domain(const std::string& domain, const Message& msg);
    void set_hello(const std::string& domain, uint16_t listen_port);

    std::vector<std::string> peer_addresses() const;
    size_t peer_count() const;

    // Callbacks set by Node
    std::function<void(const chain::Block&)>        on_block;
    std::function<void(const chain::Transaction&)>  on_tx;
    std::function<void(const node::ContribMsg&)>    on_contrib;
    std::function<void(const node::BlockSigMsg&)>   on_block_sig;
    std::function<void(const node::AbortClaimMsg&)> on_abort_claim;
    std::function<void(uint64_t /*block_index*/, const Hash& /*prev_hash*/,
                       const chain::AbortEvent&)>   on_abort_event;
    std::function<void(const chain::EquivocationEvent&)>
                                                    on_equivocation_evidence;
    // rev.9 B2c.1: beacon-block-as-header gossip from beacon role to
    // shard nodes. Shards use these to maintain a verified light view
    // of the beacon chain.
    std::function<void(const chain::Block&)>        on_beacon_header;
    // rev.9 B2c.3: shard-tip gossip from shard role to beacon nodes.
    // Beacon validates K-of-K (or BFT) sigs against the shard committee
    // it derives from its own validator pool + shard_id salt.
    std::function<void(ShardId, const chain::Block&)> on_shard_tip;
    std::function<void(uint64_t /*from_index*/, uint16_t /*count*/,
                       std::shared_ptr<Peer>)>      on_get_chain;
    std::function<void(const std::vector<chain::Block>& /*blocks*/,
                       bool /*has_more*/,
                       std::shared_ptr<Peer>)>      on_chain_response;
    std::function<void(std::shared_ptr<Peer>)>      on_status_request;
    std::function<void(uint64_t /*height*/,
                       const std::string& /*genesis_hash*/,
                       std::shared_ptr<Peer>)>      on_status_response;

private:
    void accept_loop();
    void attach(std::shared_ptr<Peer> peer);
    void handle_message(std::shared_ptr<Peer> peer, const Message& msg);
    void handle_peer_closed(std::shared_ptr<Peer> peer);

    asio::io_context&                        io_;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
    std::vector<std::shared_ptr<Peer>>       peers_;
    mutable std::mutex                       peers_mutex_;
    std::string                              our_domain_;
    uint16_t                                 our_port_{0};
};

} // namespace dhcoin::net
