// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/net/gossip.hpp>
#include <iostream>
#include <algorithm>

namespace determ::net {

GossipNet::GossipNet(asio::io_context& io) : io_(io) {}

void GossipNet::set_hello(const std::string& domain, uint16_t listen_port) {
    our_domain_ = domain;
    our_port_   = listen_port;
}

void GossipNet::set_chain_identity(ChainRole role, ShardId shard_id) {
    our_role_     = role;
    our_shard_id_ = shard_id;
}

void GossipNet::set_rate_limit(double per_sec, double burst) {
    rate_limiter_.configure(per_sec, burst);
    if (rate_limiter_.enabled()) {
        std::cout << "[gossip] rate-limit " << per_sec << "/s, burst " << burst
                  << " per peer-IP (HELLO exempt)\n";
    }
}

void GossipNet::listen(uint16_t port) {
    asio::ip::tcp::endpoint ep(asio::ip::tcp::v4(), port);
    acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(io_, ep);
    accept_loop();
    std::cout << "[gossip] listening on port " << port << "\n";
}

void GossipNet::accept_loop() {
    acceptor_->async_accept(
        [this](std::error_code ec, asio::ip::tcp::socket socket) {
            if (!ec) {
                auto peer = std::make_shared<Peer>(std::move(socket));
                attach(peer);
                if (!our_domain_.empty())
                    peer->send(make_hello(our_domain_, our_port_, our_role_, our_shard_id_));
            }
            accept_loop();
        });
}

void GossipNet::connect(const std::string& host, uint16_t port) {
    async_connect(io_, host, port,
        [this, host, port](std::shared_ptr<Peer> peer) {
            if (!log_quiet_) {
                std::cout << "[gossip] connected to " << host << ":" << port << "\n";
            }
            attach(peer);
            if (!our_domain_.empty())
                // rev.9 fix: outbound HELLO must carry our role + shard_id so
                // the receiver tags us correctly. Pre-fix this called the
                // 2-arg overload which defaulted role=SINGLE, shard_id=0,
                // breaking SHARD_TIP / BEACON_HEADER routing for outbound-
                // initiated cross-chain peering (the receiver's role-based
                // gossip filter dropped these messages from the mistagged
                // peer).
                peer->send(make_hello(our_domain_, our_port_,
                                       our_role_, our_shard_id_));
        },
        [host, port](const std::string& err) {
            std::cerr << "[gossip] connect to " << host << ":" << port
                      << " failed: " << err << "\n";
        });
}

void GossipNet::attach(std::shared_ptr<Peer> peer) {
    {
        std::lock_guard<std::mutex> lk(peers_mutex_);
        peers_.push_back(peer);
    }
    peer->start(
        [this](auto p, auto& m) { handle_message(p, m); },
        [this](auto p) { handle_peer_closed(p); });
}

// rev.9 B2c.5b: filter rule for cross-chain gossip pollution. Each
// message type is acceptable from a source peer iff their chain role
// (and shard_id, where applicable) matches the rules below.
//
// Rules summary:
//   HELLO: from any peer (initial handshake; pre-tag).
//   STATUS_REQUEST/RESPONSE: from any peer (peer discovery).
//   BEACON_HEADER: only from BEACON peers (received by SHARD).
//   SHARD_TIP: only from SHARD peers (received by BEACON).
//   EQUIVOCATION_EVIDENCE, ABORT_EVENT: from any peer (verifiable
//     independently; cross-chain forensics needs to flow).
//   Everything else (BLOCK, TRANSACTION, BLOCK_SIG, CONTRIB,
//     ABORT_CLAIM, GET_CHAIN, CHAIN_RESPONSE): only from peers with
//     SAME chain_role AND SAME shard_id (intra-chain consensus +
//     mempool — must not cross chain boundaries).
//
// Pre-HELLO: peer->chain_role() is SINGLE/0 by default. Single-chain
// deployments where everyone is SINGLE/0 see no filter effect (the
// "same role, same shard_id" rule trivially holds).
static bool peer_message_allowed(const Peer& peer, MsgType type,
                                  ChainRole our_role, ShardId our_shard_id) {
    switch (type) {
    case MsgType::HELLO:
    case MsgType::STATUS_REQUEST:
    case MsgType::STATUS_RESPONSE:
    case MsgType::EQUIVOCATION_EVIDENCE:
    case MsgType::ABORT_EVENT:
        return true;
    case MsgType::BEACON_HEADER:
        return peer.chain_role() == ChainRole::BEACON;
    case MsgType::SHARD_TIP:
        return peer.chain_role() == ChainRole::SHARD;
    case MsgType::CROSS_SHARD_RECEIPT_BUNDLE:
        // Bundles flow shard → beacon (entry) and beacon → shard
        // (relay). Accept from either side; reject SINGLE peers.
        return peer.chain_role() == ChainRole::BEACON
            || peer.chain_role() == ChainRole::SHARD;
    case MsgType::SNAPSHOT_REQUEST:
    case MsgType::SNAPSHOT_RESPONSE:
        // Snapshot fetch is role-agnostic: any peer with chain state
        // can serve, any peer can request. Bootstrap clients (CLI
        // fetchers) typically tag themselves as SINGLE.
        return true;
    default:
        // Intra-chain messages: source peer must be on the same chain
        // (same role, same shard_id when SHARD).
        if (peer.chain_role() != our_role) return false;
        if (our_role == ChainRole::SHARD && peer.shard_id() != our_shard_id) return false;
        return true;
    }
}

void GossipNet::handle_message(std::shared_ptr<Peer> peer, const Message& msg) {
    try {
        // S-014 (gossip side): per-peer-IP token bucket. Gate every
        // non-HELLO message. HELLO is exempt so a freshly-attached peer
        // can finish the handshake even when their IP's bucket is empty
        // (the HELLO is a single message per connection — it cannot be
        // weaponised on its own). For everything else, drop silently on
        // rate-limit; the peer's gossip path is metered without
        // closing the TCP connection.
        if (msg.type != MsgType::HELLO) {
            // Strip ":<port>" from peer address to key on bare IP.
            // Multiple connections from the same source share one bucket.
            std::string ip = peer->address();
            auto colon = ip.rfind(':');
            if (colon != std::string::npos) ip = ip.substr(0, colon);
            if (!rate_limiter_.consume(ip)) return;
        }
        // rev.9 B2c.5b: enforce role-based filter for cross-chain
        // pollution. HELLO is exempt (it's the handshake that tags the
        // peer in the first place). For all other messages, the peer
        // must have completed HELLO and the message type must be
        // allowed for the peer's role.
        if (msg.type != MsgType::HELLO && peer->hello_received()) {
            if (!peer_message_allowed(*peer, msg.type, our_role_, our_shard_id_)) {
                return;     // silent drop — wrong role for this msg type
            }
        }

        switch (msg.type) {
        case MsgType::HELLO: {
            peer->set_domain(msg.payload.value("domain", ""));
            // rev.9 B2c.5: tag the peer with its claimed chain identity.
            // Older peers without these fields default to SINGLE/0, which
            // matches the rev.7/8 single-chain behavior.
            peer->set_chain_role(static_cast<ChainRole>(
                msg.payload.value("role", uint8_t{0})));
            peer->set_shard_id(msg.payload.value("shard_id", ShardId{0}));
            // A3 / S8: negotiate wire-version down to min(ours, theirs).
            // Pre-A3 peers omit the field — `value(..., 0)` defaults them
            // to legacy JSON, matching today's behavior. Subsequent
            // outbound messages on this peer use the negotiated codec.
            uint8_t their_v = msg.payload.value("wire_version",
                                                kWireVersionLegacy);
            uint8_t negotiated = their_v < kWireVersionMax
                               ? their_v : kWireVersionMax;
            peer->set_wire_version(negotiated);
            peer->mark_hello_received();
            break;
        }
        case MsgType::BLOCK:
            if (on_block) on_block(chain::Block::from_json(msg.payload));
            break;
        case MsgType::TRANSACTION:
            if (on_tx) on_tx(chain::Transaction::from_json(msg.payload));
            break;
        case MsgType::BLOCK_SIG:
            if (on_block_sig) on_block_sig(node::BlockSigMsg::from_json(msg.payload));
            break;
        case MsgType::CONTRIB:
            if (on_contrib) on_contrib(node::ContribMsg::from_json(msg.payload));
            break;
        case MsgType::ABORT_CLAIM:
            if (on_abort_claim) on_abort_claim(node::AbortClaimMsg::from_json(msg.payload));
            break;
        case MsgType::ABORT_EVENT:
            if (on_abort_event) {
                uint64_t bi = msg.payload.value("block_index", uint64_t{0});
                Hash ph = from_hex_arr<32>(msg.payload.value("prev_hash", std::string{}));
                auto ev = chain::AbortEvent::from_json(msg.payload["event"]);
                on_abort_event(bi, ph, ev);
            }
            break;
        case MsgType::EQUIVOCATION_EVIDENCE:
            if (on_equivocation_evidence) {
                on_equivocation_evidence(chain::EquivocationEvent::from_json(msg.payload));
            }
            break;
        case MsgType::BEACON_HEADER:
            if (on_beacon_header) {
                on_beacon_header(chain::Block::from_json(msg.payload));
            }
            break;
        case MsgType::SHARD_TIP:
            if (on_shard_tip) {
                ShardId sid = msg.payload.value("shard_id", ShardId{0});
                on_shard_tip(sid, chain::Block::from_json(msg.payload["tip"]));
            }
            break;
        case MsgType::CROSS_SHARD_RECEIPT_BUNDLE:
            if (on_cross_shard_receipt_bundle) {
                ShardId sid = msg.payload.value("src_shard", ShardId{0});
                on_cross_shard_receipt_bundle(sid,
                    chain::Block::from_json(msg.payload["src_block"]),
                    msg);   // raw msg passed for relay re-broadcast
            }
            break;
        case MsgType::SNAPSHOT_REQUEST:
            if (on_snapshot_request) {
                on_snapshot_request(
                    msg.payload.value("headers", uint32_t{16}),
                    peer);
            }
            break;
        case MsgType::SNAPSHOT_RESPONSE:
            if (on_snapshot_response) {
                on_snapshot_response(msg.payload);
            }
            break;
        case MsgType::GET_CHAIN:
            if (on_get_chain)
                on_get_chain(msg.payload.value("from",  uint64_t{0}),
                             msg.payload.value("count", uint16_t{64}),
                             peer);
            break;
        case MsgType::CHAIN_RESPONSE: {
            if (!on_chain_response) break;
            std::vector<chain::Block> blocks;
            for (auto& bj : msg.payload.value("blocks", nlohmann::json::array()))
                blocks.push_back(chain::Block::from_json(bj));
            bool has_more = msg.payload.value("has_more", false);
            on_chain_response(blocks, has_more, peer);
            break;
        }
        case MsgType::STATUS_REQUEST:
            if (on_status_request) on_status_request(peer);
            break;
        case MsgType::STATUS_RESPONSE:
            if (on_status_response)
                on_status_response(msg.payload.value("height", uint64_t{0}),
                                   msg.payload.value("genesis", std::string{}),
                                   peer);
            break;
        default:
            break;
        }
    } catch (std::exception& e) {
        std::cerr << "[gossip] dispatch error from " << peer->address()
                  << ": " << e.what() << "\n";
    }
}

void GossipNet::handle_peer_closed(std::shared_ptr<Peer> peer) {
    std::lock_guard<std::mutex> lk(peers_mutex_);
    peers_.erase(std::remove_if(peers_.begin(), peers_.end(),
        [&](auto& p) { return p.get() == peer.get(); }), peers_.end());
    if (!log_quiet_) {
        std::cout << "[gossip] peer disconnected: " << peer->address() << "\n";
    }
}

void GossipNet::broadcast(const Message& msg) {
    std::lock_guard<std::mutex> lk(peers_mutex_);
    for (auto& p : peers_) {
        try { p->send(msg); } catch (...) {}
    }
}

void GossipNet::send_to_domain(const std::string& domain, const Message& msg) {
    std::lock_guard<std::mutex> lk(peers_mutex_);
    for (auto& p : peers_) {
        if (p->domain() == domain) {
            try { p->send(msg); } catch (...) {}
        }
    }
}

std::vector<std::string> GossipNet::peer_addresses() const {
    std::lock_guard<std::mutex> lk(peers_mutex_);
    std::vector<std::string> addrs;
    for (auto& p : peers_) addrs.push_back(p->address() +
        (p->domain().empty() ? "" : " (" + p->domain() + ")"));
    return addrs;
}

size_t GossipNet::peer_count() const {
    std::lock_guard<std::mutex> lk(peers_mutex_);
    return peers_.size();
}

} // namespace determ::net
