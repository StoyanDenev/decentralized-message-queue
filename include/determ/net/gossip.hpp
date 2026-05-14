// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/net/peer.hpp>
#include <determ/net/rate_limiter.hpp>
#include <determ/chain/block.hpp>
#include <determ/node/producer.hpp>
#include <asio.hpp>
#include <functional>
#include <memory>
#include <vector>
#include <mutex>
#include <string>

namespace determ::net {

class GossipNet {
public:
    explicit GossipNet(asio::io_context& io);

    void listen(uint16_t port);
    void connect(const std::string& host, uint16_t port);
    void broadcast(const Message& msg);
    void send_to_domain(const std::string& domain, const Message& msg);
    void set_hello(const std::string& domain, uint16_t listen_port);

    // S-014 (gossip side): per-peer-IP token-bucket rate limit on
    // inbound message dispatch. Same mechanism as RpcServer's. Both 0
    // disables the limiter (default). HELLO is exempt so newly-attached
    // peers can complete the handshake; everything else is metered.
    // Recommended starter settings for external-bind nodes:
    //   per_sec = 500, burst = 1000 — sufficient for healthy consensus
    //   gossip (a single node sends a few msgs/s steady-state; bursts
    //   on round transitions). Adjust upward for high-throughput shards.
    void set_rate_limit(double per_sec, double burst);

    // S-027 operator hygiene: gate the chatty per-connection
    // diagnostic lines (`[gossip] connected to ...`,
    // `[gossip] peer disconnected: ...`) behind `quiet=true`.
    // WARN/ERROR diagnostics surface regardless. Default `false`
    // preserves the current verbose-listen behavior.
    void set_log_quiet(bool quiet) { log_quiet_ = quiet; }

    // rev.9 B2c.5: this node's chain identity, included in HELLOs we
    // send so peers can tag us. Default SINGLE/0 preserves rev.7/8
    // behavior on chains where roles aren't used.
    void set_chain_identity(ChainRole role, ShardId shard_id);

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
    // rev.9 B3.3: cross-shard receipt bundle. The third Message& arg is
    // the raw inbound message — beacon-role handlers re-broadcast it
    // verbatim to other peers (the shard A → beacon → shard B relay).
    // Shard-role handlers ignore the relay arg and use src_shard +
    // src_block to filter receipts addressed to my_shard_id.
    std::function<void(ShardId, const chain::Block&, const Message&)>
                                                    on_cross_shard_receipt_bundle;
    // rev.9 B6.basic: snapshot fetch over gossip. Server-side handler
    // builds a snapshot via Chain::serialize_state and replies via the
    // peer pointer. Client-side handler ingests the response and
    // restores via Chain::restore_from_snapshot.
    std::function<void(uint32_t /*header_count*/,
                       std::shared_ptr<Peer>)>      on_snapshot_request;
    std::function<void(const nlohmann::json&)>      on_snapshot_response;
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
    ChainRole                                our_role_{ChainRole::SINGLE};
    ShardId                                  our_shard_id_{0};

    // S-014 (gossip side): per-peer-IP token bucket, keyed on bare IP
    // (port stripped). Shared limiter type with RpcServer.
    RateLimiter                              rate_limiter_;

    // S-027: operator log-volume flag for the chatty per-connection
    // diagnostic lines. Default `false` (verbose); operators set via
    // `set_log_quiet(true)` on init.
    bool                                     log_quiet_{false};
};

} // namespace determ::net
