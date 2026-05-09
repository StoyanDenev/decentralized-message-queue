#include <dhcoin/net/gossip.hpp>
#include <iostream>
#include <algorithm>

namespace dhcoin::net {

GossipNet::GossipNet(asio::io_context& io) : io_(io) {}

void GossipNet::set_hello(const std::string& domain, uint16_t listen_port) {
    our_domain_ = domain;
    our_port_   = listen_port;
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
                    peer->send(make_hello(our_domain_, our_port_));
            }
            accept_loop();
        });
}

void GossipNet::connect(const std::string& host, uint16_t port) {
    async_connect(io_, host, port,
        [this, host, port](std::shared_ptr<Peer> peer) {
            std::cout << "[gossip] connected to " << host << ":" << port << "\n";
            attach(peer);
            if (!our_domain_.empty())
                peer->send(make_hello(our_domain_, our_port_));
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

void GossipNet::handle_message(std::shared_ptr<Peer> peer, const Message& msg) {
    try {
        switch (msg.type) {
        case MsgType::HELLO:
            peer->set_domain(msg.payload.value("domain", ""));
            break;
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
    std::cout << "[gossip] peer disconnected: " << peer->address() << "\n";
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

} // namespace dhcoin::net
