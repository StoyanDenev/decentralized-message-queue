#include <dhcoin/node/node.hpp>
#include <dhcoin/chain/genesis.hpp>
#include <dhcoin/chain/params.hpp>
#include <dhcoin/crypto/random.hpp>
#include <dhcoin/crypto/sha256.hpp>
#include <dhcoin/crypto/delay_hash.hpp>
#include <set>
#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>

namespace dhcoin::node {

namespace fs = std::filesystem;
using json = nlohmann::json;

// ─── Config ──────────────────────────────────────────────────────────────────

json Config::to_json() const {
    json j;
    j["domain"]          = domain;
    j["data_dir"]        = data_dir;
    j["listen_port"]     = listen_port;
    j["rpc_port"]        = rpc_port;
    j["bootstrap_peers"] = bootstrap_peers;
    j["beacon_peers"]    = beacon_peers;
    j["shard_peers"]     = shard_peers;
    j["key_path"]        = key_path;
    j["chain_path"]      = chain_path;
    j["genesis_path"]    = genesis_path;
    j["genesis_hash"]    = genesis_hash;
    j["m_creators"]              = m_creators;
    j["k_block_sigs"]            = k_block_sigs;
    j["bft_enabled"]             = bft_enabled;
    j["bft_escalation_threshold"]= bft_escalation_threshold;
    j["chain_role"]              = static_cast<uint8_t>(chain_role);
    j["shard_id"]                = shard_id;
    j["initial_shard_count"]     = initial_shard_count;
    j["epoch_blocks"]            = epoch_blocks;
    j["tx_commit_ms"]    = tx_commit_ms;
    j["delay_T"]         = delay_T;
    j["block_sig_ms"]    = block_sig_ms;
    j["abort_claim_ms"]  = abort_claim_ms;
    return j;
}

Config Config::from_json(const json& j) {
    Config c;
    c.domain          = j.value("domain",         "");
    c.data_dir        = j.value("data_dir",       "");
    c.listen_port     = j.value("listen_port",    uint16_t{7777});
    c.rpc_port        = j.value("rpc_port",       uint16_t{7778});
    c.bootstrap_peers = j.value("bootstrap_peers", std::vector<std::string>{});
    c.beacon_peers    = j.value("beacon_peers",    std::vector<std::string>{});
    c.shard_peers     = j.value("shard_peers",     std::vector<std::string>{});
    c.key_path        = j.value("key_path",       "");
    c.chain_path      = j.value("chain_path",     "");
    c.genesis_path    = j.value("genesis_path",   "");
    c.genesis_hash    = j.value("genesis_hash",   "");
    c.m_creators      = j.value("m_creators",     uint32_t{3});
    c.k_block_sigs    = j.value("k_block_sigs",   c.m_creators);   // default = strong
    c.bft_enabled              = j.value("bft_enabled",              true);
    c.bft_escalation_threshold = j.value("bft_escalation_threshold", uint32_t{5});
    c.chain_role               = static_cast<ChainRole>(j.value("chain_role", uint8_t{0}));
    c.shard_id                 = j.value("shard_id",                 ShardId{0});
    c.initial_shard_count      = j.value("initial_shard_count",      uint32_t{1});
    c.epoch_blocks             = j.value("epoch_blocks",             uint32_t{1000});
    c.tx_commit_ms    = j.value("tx_commit_ms",   uint32_t{200});
    c.delay_T         = j.value("delay_T",        uint64_t{4'000'000});
    c.block_sig_ms    = j.value("block_sig_ms",   uint32_t{200});
    c.abort_claim_ms  = j.value("abort_claim_ms", uint32_t{200});
    return c;
}

Config Config::load(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open config: " + path);
    return from_json(json::parse(f));
}

void Config::save(const std::string& path) const {
    fs::create_directories(fs::path(path).parent_path());
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write config: " + path);
    f << to_json().dump(2);
}

// ─── Node ────────────────────────────────────────────────────────────────────

Node::Node(const Config& cfg)
    : cfg_(cfg)
    , gossip_(io_)
    , contrib_timer_(io_)
    , block_sig_timer_(io_) {

    validator_.set_delay_T(cfg.delay_T);
    validator_.set_k_block_sigs(cfg.k_block_sigs);
    validator_.set_m_pool(cfg.m_creators);

    key_ = crypto::load_node_key(cfg_.key_path);

    // Rev. 4: genesis is the source of truth for chain-wide constants
    // (M, K, block_subsidy). Load it FIRST so chain replay during load uses
    // the correct subsidy when crediting creators.
    uint64_t genesis_subsidy = 0;
    uint64_t genesis_min_stake = 1000;
    chain::InclusionModel genesis_inclusion = chain::InclusionModel::STAKE_INCLUSION;
    std::optional<chain::GenesisConfig> gcfg_opt;
    if (!cfg_.genesis_path.empty()) {
        auto gcfg = chain::GenesisConfig::load(cfg_.genesis_path);
        if (gcfg.k_block_sigs == 0 || gcfg.k_block_sigs > gcfg.m_creators)
            throw std::runtime_error(
                "genesis: invalid k_block_sigs (must satisfy 1 <= K <= M)");
        cfg_.m_creators              = gcfg.m_creators;
        cfg_.k_block_sigs            = gcfg.k_block_sigs;
        cfg_.bft_enabled             = gcfg.bft_enabled;
        cfg_.bft_escalation_threshold= gcfg.bft_escalation_threshold;
        cfg_.chain_role              = gcfg.chain_role;
        cfg_.shard_id                = gcfg.shard_id;
        cfg_.initial_shard_count     = gcfg.initial_shard_count;
        cfg_.epoch_blocks            = gcfg.epoch_blocks;
        genesis_subsidy              = gcfg.block_subsidy;
        genesis_min_stake            = gcfg.min_stake;
        genesis_inclusion            = gcfg.inclusion_model;
        validator_.set_k_block_sigs(cfg_.k_block_sigs);
        validator_.set_m_pool(cfg_.m_creators);
        validator_.set_bft_enabled(cfg_.bft_enabled);
        validator_.set_bft_escalation_threshold(cfg_.bft_escalation_threshold);
        validator_.set_epoch_blocks(cfg_.epoch_blocks);
        validator_.set_shard_id(cfg_.shard_id);

        // rev.9 B2c.2-full: SHARD chains source committee rand from the
        // beacon's chain (zero-trust: both sides derive the same committee
        // from the same beacon-anchored rand). Provider returns nullopt
        // when beacon headers haven't reached the requested height yet —
        // validator falls back to local chain (early bootstrap; shard
        // registry mirrors beacon at genesis, so behavior is identical
        // until headers begin to land).
        if (cfg_.chain_role == ChainRole::SHARD) {
            validator_.set_external_epoch_rand_provider(
                [this](uint64_t epoch_start_height) -> std::optional<Hash> {
                    if (epoch_start_height == 0) return std::nullopt;
                    if (epoch_start_height > beacon_headers_.size())
                        return std::nullopt;
                    return beacon_headers_[epoch_start_height - 1].cumulative_rand;
                });
        }
        gcfg_opt = std::move(gcfg);
    }

    Hash genesis_shard_salt{};
    uint32_t genesis_shard_count = 1;
    ShardId  genesis_my_shard    = 0;
    if (gcfg_opt.has_value()) {
        genesis_shard_salt  = gcfg_opt->shard_address_salt;
        genesis_shard_count = gcfg_opt->initial_shard_count;
        genesis_my_shard    = gcfg_opt->shard_id;
    }
    chain_ = chain::Chain::load(cfg_.chain_path, genesis_subsidy,
                                  genesis_shard_count, genesis_shard_salt,
                                  genesis_my_shard);
    chain_.set_min_stake(genesis_min_stake);
    chain_.set_shard_routing(genesis_shard_count, genesis_shard_salt,
                              genesis_my_shard);

    if (chain_.empty()) {
        // No on-disk chain: bootstrap from genesis config if provided, else
        // fall back to the legacy zeros-genesis.
        if (gcfg_opt.has_value()) {
            chain::Block g = chain::make_genesis_block(*gcfg_opt);
            std::string actual_hash = to_hex(g.compute_hash());
            if (!cfg_.genesis_hash.empty() && actual_hash != cfg_.genesis_hash)
                throw std::runtime_error(
                    "genesis hash mismatch: config pinned " + cfg_.genesis_hash
                  + " but loaded genesis hashes to " + actual_hash);
            chain_ = chain::Chain(std::move(g));
            chain_.set_block_subsidy(genesis_subsidy);
            chain_.set_min_stake(genesis_min_stake);
            chain_.set_shard_routing(genesis_shard_count,
                                       genesis_shard_salt,
                                       genesis_my_shard);
            const char* mode = (cfg_.k_block_sigs == cfg_.m_creators)
                              ? "strong" : "hybrid";
            std::cout << "[node] genesis loaded from " << cfg_.genesis_path
                      << " hash=" << actual_hash
                      << " role=" << to_string(cfg_.chain_role)
                      << " shard_id=" << cfg_.shard_id
                      << " M=" << cfg_.m_creators
                      << " K=" << cfg_.k_block_sigs
                      << " subsidy=" << genesis_subsidy
                      << " mode=" << mode
                      << " inclusion=" << to_string(genesis_inclusion)
                      << " min_stake=" << genesis_min_stake << "\n";
        } else {
            chain_ = chain::Chain(chain::make_genesis());
            std::cerr << "[node] WARNING: no genesis_path configured; "
                         "using legacy zeros-genesis (chain cannot bootstrap)\n";
        }
    } else if (!cfg_.genesis_hash.empty()) {
        std::string actual_hash = to_hex(chain_.at(0).compute_hash());
        if (actual_hash != cfg_.genesis_hash)
            throw std::runtime_error(
                "stored chain genesis " + actual_hash
              + " does not match pinned " + cfg_.genesis_hash);
    }

    registry_ = NodeRegistry::build_from_chain(chain_, chain_.height());

    gossip_.set_hello(cfg_.domain, cfg_.listen_port);
    gossip_.set_chain_identity(cfg_.chain_role, cfg_.shard_id);
    gossip_.on_block         = [this](auto& b)   { on_block(b); };
    gossip_.on_tx            = [this](auto& tx)  { on_tx(tx); };
    gossip_.on_contrib       = [this](auto& c)   { on_contrib(c); };
    gossip_.on_block_sig     = [this](auto& s)   { on_block_sig(s); };
    gossip_.on_abort_claim   = [this](auto& a)   { on_abort_claim(a); };
    gossip_.on_abort_event   = [this](auto bi, auto& ph, auto& e)
                                  { on_abort_event(bi, ph, e); };
    gossip_.on_equivocation_evidence = [this](auto& ev)
                                  { on_equivocation_evidence(ev); };
    gossip_.on_beacon_header  = [this](auto& b)  { on_beacon_header(b); };
    gossip_.on_shard_tip      = [this](auto sid, auto& t) { on_shard_tip(sid, t); };
    gossip_.on_get_chain     = [this](auto idx, auto cnt, auto peer)
                                  { on_get_chain(idx, cnt, peer); };
    gossip_.on_chain_response = [this](auto& blocks, auto has_more, auto peer)
                                  { on_chain_response(blocks, has_more, peer); };
    gossip_.on_status_request  = [this](auto peer)
                                  { on_status_request(peer); };
    gossip_.on_status_response = [this](auto h, auto& gh, auto peer)
                                  { on_status_response(h, gh, peer); };
}

Node::~Node() { stop(); }

void Node::run() {
    running_ = true;
    gossip_.listen(cfg_.listen_port);

    auto connect_addrs = [this](const std::vector<std::string>& addrs) {
        for (auto& addr : addrs) {
            auto colon = addr.rfind(':');
            if (colon == std::string::npos) continue;
            std::string host = addr.substr(0, colon);
            uint16_t port = static_cast<uint16_t>(std::stoi(addr.substr(colon + 1)));
            gossip_.connect(host, port);
        }
    };
    connect_addrs(cfg_.bootstrap_peers);
    // rev.9 B2c.5c: shard-role nodes connect to beacon nodes; beacon-role
    // nodes (optionally) connect to shard nodes. The role-based gossip
    // filter (B2c.5b) ensures cross-chain peers don't pollute intra-chain
    // state. SINGLE-role chains ignore both lists.
    if (cfg_.chain_role == ChainRole::SHARD) connect_addrs(cfg_.beacon_peers);
    if (cfg_.chain_role == ChainRole::BEACON) connect_addrs(cfg_.shard_peers);

    unsigned n = std::max(1u, std::thread::hardware_concurrency());
    for (unsigned i = 0; i < n; ++i)
        threads_.emplace_back([this] { io_.run(); });

    // Initial sync probe with a startup grace period: give bootstrap peers
    // a chance to connect before we engage consensus. Without this, a fresh
    // multi-node cluster fires the first round before peers are reachable,
    // the contrib phase aborts (broadcast goes nowhere), and per-node
    // generations diverge; recovery never converges.
    auto grace = std::make_shared<asio::steady_timer>(
        io_, std::chrono::milliseconds(1500));
    grace->async_wait([this, grace](std::error_code ec) {
        if (ec) return;
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (gossip_.peer_count() == 0) {
            state_ = SyncState::IN_SYNC;
            check_if_selected();
            return;
        }
        gossip_.broadcast(net::make_status_request());
    });

    for (auto& t : threads_) t.join();
}

void Node::stop() {
    if (running_.exchange(false)) {
        delay_cancel_ = true;
        if (delay_worker_.joinable()) delay_worker_.join();
        io_.stop();
        for (auto& t : threads_) if (t.joinable()) t.join();
        chain_.save(cfg_.chain_path);
    }
}

// ─── Consensus ───────────────────────────────────────────────────────────────

bool Node::in_sync() const {
    return state_ == SyncState::IN_SYNC;
}

// Caller must hold state_mutex_. Computes the K-committee for the current
// height (rotating subset of the M-pool) and, if we are one of them, kicks
// off Round 1. Gated by in_sync().
//
// K-committee model:
//   - cfg_.m_creators = registered pool size guideline (genesis-pinned).
//   - cfg_.k_block_sigs = committee size per block (genesis-pinned, K ≤ M).
//   - K = M  → strong mode: every registered creator always on committee.
//   - K < M  → hybrid mode: rotating committee from the eligible pool.
//   tx_root is always the union of K hash lists (K-conjunction censorship
//   within the committee), independent of mode.
void Node::check_if_selected() {
    if (!in_sync())                       return;
    if (phase_ != ConsensusPhase::IDLE)   return;

    auto nodes = registry_.sorted_nodes();
    size_t k_target = cfg_.k_block_sigs;       // committee size per round (MD)

    // Build the available pool: registry minus any domains already aborted in
    // this height's current_aborts_. This is the local-aborts equivalent of
    // chain-baked suspension — needed because suspension only kicks in once a
    // block finalizes and bakes the abort_events into the chain.
    std::set<std::string> excluded;
    for (auto& ae : current_aborts_) excluded.insert(ae.aborting_node);
    std::vector<std::string> avail_domains;
    for (auto& nd : nodes) {
        if (excluded.count(nd.domain)) continue;
        avail_domains.push_back(nd.domain);
    }

    // rev.8 escalation. If the pool is too small to form a K-of-K committee
    // AND bft_enabled AND we've hit the abort threshold, fall back to a
    // smaller committee with size ceil(2K/3). The committee will run in
    // BFT mode (validator enforces). Both round-1 and round-2 aborts count
    // toward escalation (any kind of abort indicates a stuck round). Note:
    // suspension (registry.cpp) still counts only round-1 to avoid
    // Phase-2-timing-skew false-positive suspensions.
    size_t total_aborts = current_aborts_.size();
    size_t k_bft = (2 * cfg_.k_block_sigs + 2) / 3;     // ceil(2K/3)
    size_t k_use = k_target;
    chain::ConsensusMode round_mode = chain::ConsensusMode::MUTUAL_DISTRUST;
    if (avail_domains.size() < k_target
        && cfg_.bft_enabled
        && total_aborts >= cfg_.bft_escalation_threshold
        && avail_domains.size() >= k_bft) {
        k_use      = k_bft;
        round_mode = chain::ConsensusMode::BFT;
    }
    if (avail_domains.size() < k_use) return;
    current_round_mode_ = round_mode;

    // rev.9 (B1): committee derives from per-shard, per-epoch seed (stable
    // for the duration of an epoch), then mixes in any in-flight abort
    // hashes so re-selection within an epoch still depends on the abort
    // sequence. With S=1 SINGLE the salt is fixed; behavior is the same
    // as rev.8 within a single epoch.
    Hash epoch_rand = current_epoch_rand();
    Hash rand = crypto::epoch_committee_seed(epoch_rand, cfg_.shard_id);
    for (auto& ae : current_aborts_) {
        rand = crypto::SHA256Builder{}.append(rand).append(ae.event_hash).finalize();
    }

    try {
        current_creator_indices_ = crypto::select_m_creators(rand, avail_domains.size(), k_use);
    } catch (...) { return; }

    current_creator_domains_.clear();
    for (size_t idx : current_creator_indices_)
        current_creator_domains_.push_back(avail_domains[idx]);

    auto it = std::find(current_creator_domains_.begin(),
                        current_creator_domains_.end(), cfg_.domain);
    if (it == current_creator_domains_.end()) return;

    start_contrib_phase();
}

// Phase 1: snapshot mempool, generate fresh dh_input, sign & broadcast our
// ContribMsg. Other ContribMsgs may already be buffered from peers; we keep
// them (they were already gen-checked on receipt). reset_round handles
// cross-round cleanup; this function is also reachable on first-ever
// startup, where the maps are already empty.
void Node::start_contrib_phase() {
    phase_ = ConsensusPhase::CONTRIB;
    // Keep pending_contribs_ — pre-phase arrivals (received during the
    // IN_SYNC ramp-up) are valid for this gen.
    pending_block_sigs_.clear();
    buffered_block_sigs_.clear();

    uint64_t block_index = chain_.height();
    Hash     prev_hash   = chain_.empty() ? Hash{} : chain_.head_hash();

    std::vector<Hash> snap;
    snap.reserve(tx_store_.size());
    for (auto& [h, _] : tx_store_) snap.push_back(h);

    Hash dh_input{};
    if (RAND_bytes(dh_input.data(), 32) != 1)
        throw std::runtime_error("RAND_bytes failed for dh_input");

    ContribMsg my_contrib = make_contrib(key_, cfg_.domain,
                                          block_index, prev_hash,
                                          current_aborts_.size(),
                                          snap, dh_input);
    pending_contribs_[cfg_.domain] = my_contrib;
    gossip_.broadcast(net::make_contrib(my_contrib));

    contrib_timer_.expires_after(std::chrono::milliseconds(cfg_.tx_commit_ms));
    contrib_timer_.async_wait([this](std::error_code ec) {
        if (ec) return;
        std::lock_guard<std::mutex> lk(state_mutex_);
        handle_contrib_timeout();
    });

    if (pending_contribs_.size() == current_creator_domains_.size())
        start_delay_compute();
}

// Transition Phase 1 → local delay-hash compute. Derive tx_root and seed,
// kick off worker thread (O2). When the delay finishes (or a peer's R
// arrives via O1 piggyback), we transition to Phase 2.
void Node::start_delay_compute() {
    if (phase_ != ConsensusPhase::CONTRIB) return;
    phase_ = ConsensusPhase::RUNNING_DELAY;
    contrib_timer_.cancel();

    std::vector<std::vector<Hash>> ordered_lists;
    std::vector<Hash>              ordered_dh_inputs;
    for (auto& d : current_creator_domains_) {
        auto it = pending_contribs_.find(d);
        if (it == pending_contribs_.end()) return;
        ordered_lists.push_back(it->second.tx_hashes);
        ordered_dh_inputs.push_back(it->second.dh_input);
    }
    current_tx_root_    = compute_tx_root(ordered_lists);
    current_delay_seed_ = compute_delay_seed(chain_.height(),
        chain_.empty() ? Hash{} : chain_.head_hash(),
        current_tx_root_, ordered_dh_inputs);

    delay_cancel_ = false;
    delay_done_   = false;
    if (delay_worker_.joinable()) delay_worker_.join();

    Hash     seed = current_delay_seed_;
    uint64_t T    = cfg_.delay_T;
    delay_worker_ = std::thread([this, seed, T] {
        // O2: delay-hash on a worker thread, never blocks consensus.
        Hash output = crypto::delay_hash_compute(seed, T);
        if (delay_cancel_) return;
        asio::post(io_, [this, output] {
            std::lock_guard<std::mutex> lk(state_mutex_);
            on_delay_complete(output);
        });
    });

    // O3: replay any block_sigs that arrived early. Caller is on_contrib
    // which holds state_mutex_, so use the *_locked variant to avoid the
    // recursive-lock crash.
    auto buffered = std::move(buffered_block_sigs_);
    buffered_block_sigs_.clear();
    for (auto& m : buffered) on_block_sig_locked(m);
}

void Node::on_delay_complete(const Hash& output) {
    if (phase_ != ConsensusPhase::RUNNING_DELAY) return;
    if (delay_done_) return;
    delay_done_ = true;
    local_delay_output_ = output;
    start_block_sig_phase(output);
}

chain::ConsensusMode Node::current_mode() const {
    return current_round_mode_;
}

EpochIndex Node::current_epoch_index() const {
    if (cfg_.epoch_blocks == 0) return 0;
    return chain_.height() / cfg_.epoch_blocks;
}

Hash Node::current_epoch_rand() const {
    if (chain_.empty()) return Hash{};
    if (cfg_.epoch_blocks == 0) return chain_.head().cumulative_rand;
    uint64_t epoch_start = current_epoch_index() * cfg_.epoch_blocks;

    // rev.9 B2c.2-full: SHARD producers source rand from beacon headers,
    // not their own chain — both sides of the cross-chain relationship
    // (this shard producing, beacon validating tips) must derive the
    // same committee. Bootstrap fallback (no header yet) → local chain;
    // shard registry mirrors beacon at genesis so it produces a valid
    // committee until the first beacon header lands.
    if (cfg_.chain_role == ChainRole::SHARD
        && epoch_start > 0
        && epoch_start <= beacon_headers_.size()) {
        return beacon_headers_[epoch_start - 1].cumulative_rand;
    }

    if (epoch_start == 0)        return chain_.head().cumulative_rand;
    if (epoch_start > chain_.height()) return chain_.head().cumulative_rand;
    return chain_.at(epoch_start - 1).cumulative_rand;
}

std::string Node::current_proposer_domain() const {
    if (current_mode() != chain::ConsensusMode::BFT) return "";
    if (current_creator_domains_.empty()) return "";
    // Epoch-relative + shard-salted rand keeps proposer derivation
    // consistent with committee selection (Stage B1). Within an epoch the
    // proposer rotates only via abort_events.
    Hash epoch_rand = current_epoch_rand();
    Hash seed = crypto::epoch_committee_seed(epoch_rand, cfg_.shard_id);
    size_t idx = proposer_idx(seed, current_aborts_,
                                current_creator_domains_.size());
    if (idx >= current_creator_domains_.size()) return "";
    return current_creator_domains_[idx];
}

void Node::start_block_sig_phase(const Hash& delay_output) {
    if (phase_ == ConsensusPhase::BLOCK_SIG) return;
    phase_ = ConsensusPhase::BLOCK_SIG;
    current_delay_output_ = delay_output;

    // Build a candidate block to compute the digest we sign over. We need
    // to produce the same digest every node will compute, so we order
    // contribs by selection order and tag the same mode + proposer.
    std::vector<ContribMsg> ordered_contribs;
    for (auto& d : current_creator_domains_) {
        auto it = pending_contribs_.find(d);
        if (it == pending_contribs_.end()) return;
        ordered_contribs.push_back(it->second);
    }
    auto mode     = current_mode();
    auto proposer = current_proposer_domain();
    chain::Block tentative = build_body(tx_store_, chain_, current_aborts_,
                                         current_creator_domains_,
                                         ordered_contribs, delay_output,
                                         cfg_.m_creators, mode, proposer,
                                         pending_equivocation_evidence_);
    Hash digest = compute_block_digest(tentative);

    BlockSigMsg my_sig = make_block_sig(key_, cfg_.domain,
                                         tentative.index,
                                         delay_output, digest);
    pending_block_sigs_[cfg_.domain] = my_sig;
    gossip_.broadcast(net::make_block_sig(my_sig));

    block_sig_timer_.expires_after(std::chrono::milliseconds(cfg_.block_sig_ms));
    block_sig_timer_.async_wait([this](std::error_code ec) {
        if (ec) return;
        std::lock_guard<std::mutex> lk(state_mutex_);
        handle_block_sig_timeout();
    });

    if (pending_block_sigs_.size() == current_creator_domains_.size())
        try_finalize_round();
}

void Node::try_finalize_round() {
    // Phase 1 unanimity preserved in both modes: all K contribs required.
    std::vector<ContribMsg> ordered_contribs;
    for (auto& d : current_creator_domains_) {
        auto cit = pending_contribs_.find(d);
        if (cit == pending_contribs_.end()) return;
        ordered_contribs.push_back(cit->second);
    }

    auto mode     = current_mode();
    auto proposer = current_proposer_domain();

    // BFT mode: only the designated proposer finalizes (eliminates
    // silent-fork race where different peers pick different K-subsets of
    // sigs).
    if (mode == chain::ConsensusMode::BFT && cfg_.domain != proposer) return;

    // Phase 2: build a sentinel-aligned block_sigs vector. Position i is
    // creators[i]'s sig if they signed, else Signature{} (zero sentinel).
    Signature zero_sig{};
    std::vector<Signature> ordered_block_sigs(current_creator_domains_.size(), zero_sig);
    size_t signed_count = 0;
    for (size_t i = 0; i < current_creator_domains_.size(); ++i) {
        auto sit = pending_block_sigs_.find(current_creator_domains_[i]);
        if (sit != pending_block_sigs_.end()) {
            ordered_block_sigs[i] = sit->second.ed_sig;
            ++signed_count;
        }
    }

    size_t required = required_block_sigs(mode, current_creator_domains_.size());
    if (signed_count < required) return;     // not enough yet, wait
    block_sig_timer_.cancel();

    // BFT requires the proposer's own sig present (sentinel-zero at the
    // proposer's index would be illegal — validator rejects).
    if (mode == chain::ConsensusMode::BFT) {
        auto pit = std::find(current_creator_domains_.begin(),
                              current_creator_domains_.end(), proposer);
        if (pit == current_creator_domains_.end()) return;
        size_t pidx = pit - current_creator_domains_.begin();
        if (ordered_block_sigs[pidx] == zero_sig) return;
    }

    chain::Block body = build_body(tx_store_, chain_, current_aborts_,
                                    current_creator_domains_,
                                    ordered_contribs,
                                    current_delay_output_,
                                    cfg_.m_creators, mode, proposer,
                                    pending_equivocation_evidence_);
    body.creator_block_sigs = std::move(ordered_block_sigs);

    apply_block_locked(body);
    gossip_.broadcast(net::make_block(body));
}

// S7: timeout fires only emit a claim. The round advances when M-1 matching
// claims (signed by distinct claimers) arrive — see try_advance_on_claims.
namespace {
    std::string find_first_missing(
        const std::vector<std::string>& creators,
        const std::function<bool(const std::string&)>& is_present)
    {
        for (auto& d : creators) if (!is_present(d)) return d;
        return {};
    }
}

void Node::handle_contrib_timeout() {
    std::string missing = find_first_missing(current_creator_domains_,
        [&](const std::string& d) {
            return pending_contribs_.find(d) != pending_contribs_.end();
        });
    if (missing.empty()) return;
    if (std::find(current_creator_domains_.begin(),
                  current_creator_domains_.end(), cfg_.domain)
        == current_creator_domains_.end()) return;
    if (cfg_.domain == missing) return;     // we don't claim against ourselves

    Hash prev_hash = chain_.empty() ? Hash{} : chain_.head_hash();
    AbortClaimMsg my_claim = make_abort_claim(key_, cfg_.domain,
        chain_.height(), uint8_t{1}, prev_hash, missing);
    pending_claims_[{1, missing}][cfg_.domain] = my_claim;
    gossip_.broadcast(net::make_abort_claim(my_claim));

    std::cout << "[node] phase1 timeout, claim against " << missing << "\n";
}

void Node::handle_block_sig_timeout() {
    // rev.8 mode-aware: in MD mode, finalize only on full K-of-K (today's
    // behavior). In BFT mode, only the designated proposer finalizes, on
    // ≥ ceil(2K/3) sigs. Designated proposer eliminates the silent-fork
    // race (different peers picking different K-subsets).
    auto mode = current_mode();
    size_t required = required_block_sigs(mode, current_creator_domains_.size());
    if (pending_block_sigs_.size() >= required) {
        try_finalize_round();   // try_finalize_round itself enforces proposer-only in BFT
        return;
    }

    std::string missing = find_first_missing(current_creator_domains_,
        [&](const std::string& d) {
            return pending_block_sigs_.find(d) != pending_block_sigs_.end();
        });
    if (missing.empty()) return;
    if (std::find(current_creator_domains_.begin(),
                  current_creator_domains_.end(), cfg_.domain)
        == current_creator_domains_.end()) return;
    if (cfg_.domain == missing) return;

    Hash prev_hash = chain_.empty() ? Hash{} : chain_.head_hash();
    AbortClaimMsg my_claim = make_abort_claim(key_, cfg_.domain,
        chain_.height(), uint8_t{2}, prev_hash, missing);
    pending_claims_[{2, missing}][cfg_.domain] = my_claim;
    gossip_.broadcast(net::make_abort_claim(my_claim));

    std::cout << "[node] phase2 timeout, " << pending_block_sigs_.size()
              << "/" << cfg_.k_block_sigs << " sigs, claim against "
              << missing << "\n";
}

void Node::on_abort_claim(const AbortClaimMsg& msg) {
    std::lock_guard<std::mutex> lk(state_mutex_);

    if (msg.block_index != chain_.height()) return;
    Hash prev_hash = chain_.empty() ? Hash{} : chain_.head_hash();
    if (msg.prev_hash != prev_hash) return;

    // Both claimer and missing must be in the current selected creator set.
    auto in_creators = [&](const std::string& d) {
        return std::find(current_creator_domains_.begin(),
                         current_creator_domains_.end(), d)
            != current_creator_domains_.end();
    };
    if (!in_creators(msg.claimer))         return;
    if (!in_creators(msg.missing_creator)) return;
    if (msg.claimer == msg.missing_creator) return;

    auto entry = registry_.find(msg.claimer);
    if (!entry) return;

    Hash digest = make_abort_claim_message(msg.block_index, msg.round,
                                             msg.prev_hash, msg.missing_creator);
    if (!crypto::verify(entry->pubkey, digest.data(), digest.size(), msg.ed_sig)) {
        std::cerr << "[node] invalid AbortClaim sig from " << msg.claimer << "\n";
        return;
    }

    // Bucket by (round, missing_creator). Each claimer contributes at most
    // one claim per bucket; equivocation across buckets is detectable later.
    auto& bucket = pending_claims_[{msg.round, msg.missing_creator}];
    if (bucket.find(msg.claimer) != bucket.end()) return;  // dup
    bucket[msg.claimer] = msg;

    // Quorum check: M-1 distinct signers, all from current_creator_domains_,
    // none equal to missing_creator.
    size_t needed = current_creator_domains_.size() > 0
                  ? current_creator_domains_.size() - 1
                  : 0;
    if (bucket.size() < needed) return;

    // Build the AbortEvent with the claim quorum.
    int64_t ts   = now_unix();
    Hash    rand = chain_.empty() ? Hash{} : chain_.head().cumulative_rand;
    Hash    ah   = current_aborts_.empty()
                 ? crypto::compute_abort_hash(msg.round, msg.missing_creator, ts, rand)
                 : crypto::chain_abort_hash(current_aborts_.back().event_hash,
                                              msg.round, msg.missing_creator, ts);

    chain::AbortEvent ev;
    ev.round         = msg.round;
    ev.aborting_node = msg.missing_creator;
    ev.timestamp     = ts;
    ev.event_hash    = ah;
    nlohmann::json claims_arr = nlohmann::json::array();
    for (auto& [_, c] : bucket) claims_arr.push_back(c.to_json());
    ev.claims_json = claims_arr;
    current_aborts_.push_back(ev);

    std::cout << "[node] abort quorum (round " << int(msg.round)
              << ") against " << msg.missing_creator
              << " (" << bucket.size() << " claims)\n";

    // rev.8 follow-on: broadcast the assembled AbortEvent so peers that
    // missed a claim can adopt it and advance their abort generation in
    // lock-step. Without this, peers stuck with only their own claim stay
    // out-of-sync forever (the original claim isn't re-broadcast).
    Hash bcast_prev = chain_.empty() ? Hash{} : chain_.head_hash();
    gossip_.broadcast(net::make_abort_event(ev, chain_.height(), bcast_prev));

    reset_round();
    check_if_selected();
}

void Node::on_abort_event(uint64_t block_index, const Hash& prev_hash,
                            const chain::AbortEvent& ev) {
    std::lock_guard<std::mutex> lk(state_mutex_);

    if (block_index != chain_.height()) return;
    Hash my_prev = chain_.empty() ? Hash{} : chain_.head_hash();
    if (prev_hash != my_prev) return;

    // Already adopted? Idempotent: ignore duplicates.
    for (auto& existing : current_aborts_) {
        if (existing.event_hash == ev.event_hash) return;
    }

    // Validate the K-1 claim quorum carried inline. We can do this
    // independently of whether we ever heard the individual AbortClaimMsgs
    // ourselves — that's the whole point of this message.
    if (!ev.claims_json.is_array()) return;
    size_t needed = current_creator_domains_.size() > 0
                  ? current_creator_domains_.size() - 1 : 0;
    if (ev.claims_json.size() < needed) return;

    std::set<std::string> seen_claimers;
    for (auto& cj : ev.claims_json) {
        auto m_ = node::AbortClaimMsg::from_json(cj);
        if (m_.block_index     != block_index)       return;
        if (m_.round           != ev.round)          return;
        if (m_.prev_hash       != prev_hash)         return;
        if (m_.missing_creator != ev.aborting_node)  return;
        if (m_.claimer == m_.missing_creator)        return;
        // Claimer must be in current committee to be authoritative
        if (std::find(current_creator_domains_.begin(),
                       current_creator_domains_.end(),
                       m_.claimer) == current_creator_domains_.end()) return;
        if (!seen_claimers.insert(m_.claimer).second) return;

        auto e = registry_.find(m_.claimer);
        if (!e) return;
        Hash digest = make_abort_claim_message(m_.block_index, m_.round,
                                                  m_.prev_hash, m_.missing_creator);
        if (!crypto::verify(e->pubkey, digest.data(), digest.size(), m_.ed_sig))
            return;
    }
    if (seen_claimers.size() < needed) return;

    // Adopt and advance.
    current_aborts_.push_back(ev);
    std::cout << "[node] adopted gossiped abort event (round " << int(ev.round)
              << ") against " << ev.aborting_node << "\n";

    reset_round();
    check_if_selected();
}

// rev.8 follow-on: peer-gossiped equivocation evidence. Validate the
// two-signature proof against the equivocator's registered key. If valid
// and not already pooled, accept into pending_equivocation_evidence_ for
// inclusion in the next block we produce.
void Node::on_equivocation_evidence(const chain::EquivocationEvent& ev) {
    std::lock_guard<std::mutex> lk(state_mutex_);

    if (ev.digest_a == ev.digest_b) return;
    if (ev.sig_a == ev.sig_b)       return;

    auto entry = registry_.find(ev.equivocator);
    if (!entry) return;

    if (!crypto::verify(entry->pubkey, ev.digest_a.data(), ev.digest_a.size(), ev.sig_a))
        return;
    if (!crypto::verify(entry->pubkey, ev.digest_b.data(), ev.digest_b.size(), ev.sig_b))
        return;

    for (auto& e : pending_equivocation_evidence_) {
        if (e.equivocator == ev.equivocator && e.block_index == ev.block_index)
            return; // dup
    }
    pending_equivocation_evidence_.push_back(ev);
    std::cout << "[node] adopted gossiped equivocation evidence: equivocator="
              << ev.equivocator << " at h=" << ev.block_index << "\n";
}

// rev.9 B2c.2: shard receives a beacon block via gossip from a peering
// beacon node and validates it under zero-trust assumptions:
//   1. Sequential index (gap detection requires BEACON_HEADER_REQUEST;
//      out-of-order arrivals are dropped — caller will retry via gossip).
//   2. prev_hash chains to the previously-validated header (or to the
//      shard's pinned beacon-genesis-hash for the first header — the
//      beacon-genesis pinning is a B2c.5 follow-on; B2c.2 trusts the
//      first header's prev_hash if no prior context).
//   3. consensus_mode is MD (beacon doesn't escalate to BFT — beacons
//      always run K-of-K).
//   4. Each non-zero entry in creator_block_sigs verifies against the
//      corresponding creator's Ed25519 key, and signed_count == K.
//      The shard derives the validator pool from chain_.registrants()
//      since shard genesis shares initial_creators with beacon (via
//      genesis-tool build-sharded). This is correct at genesis time;
//      tracking pool deltas from beacon REGISTER/STAKE txs is B2c.2-full.
//
// SINGLE / BEACON roles ignore this message.
void Node::on_beacon_header(const chain::Block& b) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (cfg_.chain_role != ChainRole::SHARD) return;

    // 1. Sequential index check.
    uint64_t expected_index = beacon_headers_.empty()
        ? 1
        : beacon_headers_.back().index + 1;
    if (b.index != expected_index) return;     // dup or gap; sync fallback is B2c.2-full

    // 2. prev_hash chain check (skipped for first header; beacon-genesis
    //    pinning is B2c.5).
    if (!beacon_headers_.empty()) {
        if (b.prev_hash != beacon_headers_.back().compute_hash()) {
            std::cerr << "[node] beacon header prev_hash mismatch at h=" << b.index << "\n";
            return;
        }
    }

    // 3. Beacon must run MD (K-of-K, no escalation).
    if (b.consensus_mode != chain::ConsensusMode::MUTUAL_DISTRUST) {
        std::cerr << "[node] beacon header at h=" << b.index
                  << " has unexpected consensus_mode (beacons run MD only)\n";
        return;
    }

    // 4. K-of-K signature verification. The shard's registry mirrors the
    //    beacon's at genesis time (build-sharded shares initial_creators).
    //    For B2c.2-minimal we use the shard's local registry as the pool.
    auto reg = NodeRegistry::build_from_chain(chain_, chain_.height());
    if (b.creator_block_sigs.size() != b.creators.size()) {
        std::cerr << "[node] beacon header: creator_block_sigs size mismatch\n";
        return;
    }

    Hash digest = compute_block_digest(b);
    Signature zero_sig{};
    size_t signed_count = 0;
    for (size_t i = 0; i < b.creators.size(); ++i) {
        if (b.creator_block_sigs[i] == zero_sig) continue;
        auto e = reg.find(b.creators[i]);
        if (!e) {
            std::cerr << "[node] beacon header at h=" << b.index
                      << ": creator '" << b.creators[i]
                      << "' not in shard's tracked beacon pool\n";
            return;
        }
        if (!crypto::verify(e->pubkey, digest.data(), digest.size(),
                              b.creator_block_sigs[i])) {
            std::cerr << "[node] beacon header at h=" << b.index
                      << ": invalid sig from " << b.creators[i] << "\n";
            return;
        }
        ++signed_count;
    }
    // K-of-K beacon: every committee member must have signed (no zero
    // sentinels permitted in MD mode).
    if (signed_count != b.creators.size()) {
        std::cerr << "[node] beacon header at h=" << b.index
                  << ": incomplete K-of-K (signed=" << signed_count
                  << ", required=" << b.creators.size() << ")\n";
        return;
    }

    beacon_headers_.push_back(b);
    std::cout << "[node] verified beacon header #" << b.index
              << " (K-of-K=" << signed_count << ")\n";
}

// rev.9 B2c.3: beacon receives a shard's newly-applied block via gossip
// from a peering shard node. The beacon validates under zero-trust:
//   1. shard_id within configured range.
//   2. Sequential index (vs prior tip we have for this shard).
//   3. prev_hash chains to prior tip.
//   4. consensus_mode is permitted (MD always, BFT only when bft_enabled).
//   5. tip.creators matches the shard committee the BEACON derives from
//      its own validator pool + epoch_committee_seed(beacon_cum_rand,
//      shard_id), with abort_event hashes mixed in. This is the key
//      check: the beacon doesn't trust shard claims about who's on the
//      committee; it derives independently.
//   6. K-of-K (MD) or ceil(2K/3) (BFT) signatures verify against the
//      committee from step 5.
// Validated tips populate latest_shard_tips_; beacon block production
// (Stage B3+) reads from this for shard_summaries[].
//
// SINGLE / SHARD roles ignore this message.
void Node::on_shard_tip(ShardId shard_id, const chain::Block& tip) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (cfg_.chain_role != ChainRole::BEACON) return;

    // 1. Shard ID range.
    if (cfg_.initial_shard_count > 0 && shard_id >= cfg_.initial_shard_count) return;

    // 2. + 3. Sequential + prev_hash chain.
    auto it = latest_shard_tips_.find(shard_id);
    if (it != latest_shard_tips_.end()) {
        if (tip.index <= it->second.index) return;          // older or dup
        if (tip.index != it->second.index + 1) return;      // gap; sync fallback is B2c.3-full
        if (tip.prev_hash != it->second.compute_hash()) {
            std::cerr << "[node] shard tip prev_hash mismatch: shard=" << shard_id
                      << " block=" << tip.index << "\n";
            return;
        }
    }

    // 4. consensus_mode permitted.
    if (tip.consensus_mode == chain::ConsensusMode::BFT && !cfg_.bft_enabled) return;

    // 5. Derive expected committee. Epoch is determined by shard's block index.
    EpochIndex shard_epoch = (cfg_.epoch_blocks > 0)
        ? (tip.index / cfg_.epoch_blocks)
        : 0;
    uint64_t beacon_anchor_height = shard_epoch * (cfg_.epoch_blocks ? cfg_.epoch_blocks : 1);
    Hash beacon_rand;
    if (beacon_anchor_height == 0 || beacon_anchor_height > chain_.height()) {
        beacon_rand = chain_.empty() ? Hash{} : chain_.head().cumulative_rand;
    } else {
        beacon_rand = chain_.at(beacon_anchor_height - 1).cumulative_rand;
    }

    auto beacon_reg = NodeRegistry::build_from_chain(chain_, chain_.height());
    auto pool_nodes = beacon_reg.sorted_nodes();

    std::set<std::string> excluded;
    for (auto& ae : tip.abort_events) excluded.insert(ae.aborting_node);
    std::vector<std::string> avail;
    for (auto& nd : pool_nodes) {
        if (!excluded.count(nd.domain)) avail.push_back(nd.domain);
    }

    size_t k_full = cfg_.k_block_sigs;
    size_t k_bft  = (2 * k_full + 2) / 3;
    size_t expected_k = (tip.consensus_mode == chain::ConsensusMode::BFT) ? k_bft : k_full;
    if (avail.size() < expected_k) {
        std::cerr << "[node] shard tip: insufficient pool to derive committee for shard="
                  << shard_id << "\n";
        return;
    }
    if (tip.creators.size() != expected_k) {
        std::cerr << "[node] shard tip: creators size (" << tip.creators.size()
                  << ") != expected_k (" << expected_k << ")\n";
        return;
    }

    Hash rand = crypto::epoch_committee_seed(beacon_rand, shard_id);
    for (auto& ae : tip.abort_events) {
        rand = crypto::SHA256Builder{}.append(rand).append(ae.event_hash).finalize();
    }
    auto indices = crypto::select_m_creators(rand, avail.size(), expected_k);
    for (size_t i = 0; i < expected_k; ++i) {
        if (avail[indices[i]] != tip.creators[i]) {
            std::cerr << "[node] shard tip: creators[" << i << "] mismatch ('"
                      << tip.creators[i] << "' vs derived '"
                      << avail[indices[i]] << "')\n";
            return;
        }
    }

    // 6. Signature verification.
    if (tip.creator_block_sigs.size() != tip.creators.size()) return;
    Hash digest = compute_block_digest(tip);
    Signature zero_sig{};
    size_t signed_count = 0;
    for (size_t i = 0; i < tip.creators.size(); ++i) {
        if (tip.creator_block_sigs[i] == zero_sig) continue;
        auto e = beacon_reg.find(tip.creators[i]);
        if (!e) return;
        if (!crypto::verify(e->pubkey, digest.data(), digest.size(),
                              tip.creator_block_sigs[i])) {
            std::cerr << "[node] shard tip: invalid sig from " << tip.creators[i] << "\n";
            return;
        }
        ++signed_count;
    }
    size_t required = (tip.consensus_mode == chain::ConsensusMode::BFT) ? k_bft : k_full;
    if (signed_count < required) {
        std::cerr << "[node] shard tip: insufficient sigs (" << signed_count
                  << "/" << required << ")\n";
        return;
    }

    latest_shard_tips_[shard_id] = tip;
    std::cout << "[node] verified shard tip: shard=" << shard_id
              << " block=" << tip.index << " sigs=" << signed_count << "\n";
}

void Node::reset_round() {
    delay_cancel_ = true;
    pending_contribs_.clear();
    contrib_equivocations_.clear();
    pending_block_sigs_.clear();
    buffered_block_sigs_.clear();
    pending_claims_.clear();
    current_tx_root_     = Hash{};
    current_delay_seed_  = Hash{};
    current_delay_output_= Hash{};
    delay_done_ = false;
    phase_ = ConsensusPhase::IDLE;
}

// ─── Event Handlers ──────────────────────────────────────────────────────────

void Node::apply_block_locked(const chain::Block& b) {
    // Skip duplicates silently. With M creators each broadcasting the block
    // and the gossip mesh fanning it out across peer connections, every
    // node receives each block ~M times. After the first apply, b.index <
    // chain_.height() and the duplicate's prev_hash no longer matches our
    // head — used to log "invalid block: prev_hash mismatch" spam.
    if (b.index < chain_.height()) {
        // rev.8 equivocation detection + evidence assembly. If the
        // incoming block's hash differs from the block we already have at
        // b.index, AND it carries a non-empty bft_proposer (BFT-mode
        // block), that proposer signed two different digests for the
        // same height — equivocation. Extract proof: digest_a/sig_a from
        // the stored block, digest_b/sig_b from the incoming block, both
        // by the same proposer key. Push to evidence pool, gossip.
        if (!b.bft_proposer.empty()) {
            const auto& stored = chain_.at(b.index);
            Hash stored_hash   = stored.compute_hash();
            Hash incoming_hash = b.compute_hash();
            if (stored_hash != incoming_hash
                && stored.bft_proposer == b.bft_proposer
                && !stored.bft_proposer.empty()) {

                auto sit = std::find(stored.creators.begin(),
                                       stored.creators.end(),
                                       stored.bft_proposer);
                auto bit = std::find(b.creators.begin(),
                                       b.creators.end(),
                                       b.bft_proposer);
                if (sit != stored.creators.end() && bit != b.creators.end()) {
                    size_t sidx = sit - stored.creators.begin();
                    size_t bidx = bit - b.creators.begin();
                    Hash digest_a = compute_block_digest(stored);
                    Hash digest_b = compute_block_digest(b);
                    Signature sig_a = stored.creator_block_sigs[sidx];
                    Signature sig_b = b.creator_block_sigs[bidx];
                    if (digest_a != digest_b && sig_a != sig_b) {
                        chain::EquivocationEvent ev;
                        ev.equivocator = stored.bft_proposer;
                        ev.block_index = b.index;
                        ev.digest_a    = digest_a;
                        ev.sig_a       = sig_a;
                        ev.digest_b    = digest_b;
                        ev.sig_b       = sig_b;
                        // rev.9 B2c.4: cross-chain provenance. SHARD-role
                        // detections record their shard_id + the latest
                        // verified beacon header's height as the anchor.
                        // SINGLE / BEACON detections leave them at default
                        // (0, 0), distinguishing the source chain in the
                        // forensic trail.
                        if (cfg_.chain_role == ChainRole::SHARD) {
                            ev.shard_id = cfg_.shard_id;
                            ev.beacon_anchor_height = beacon_headers_.empty()
                                ? 0 : beacon_headers_.back().index;
                        }

                        // Add to pool if not already present.
                        bool dup = false;
                        for (auto& e : pending_equivocation_evidence_) {
                            if (e.equivocator == ev.equivocator
                                && e.block_index == ev.block_index) {
                                dup = true; break;
                            }
                        }
                        if (!dup) {
                            pending_equivocation_evidence_.push_back(ev);
                            gossip_.broadcast(net::make_equivocation_evidence(ev));
                            std::cerr << "[node] EQUIVOCATION evidence built at h="
                                      << b.index << " equivocator=" << ev.equivocator
                                      << " (gossiped; will be baked into next block)\n";
                        }
                    }
                }
            }
        }
        return;
    }

    auto reg = NodeRegistry::build_from_chain(chain_, b.index);
    auto res = validator_.validate(b, chain_, reg);
    if (!res.ok) {
        std::cerr << "[node] invalid block: " << res.error << "\n";
        return;
    }

    chain_.append(b);

    // Drop applied txs from the mempool, keyed by both indices.
    for (auto& tx : b.transactions) {
        tx_store_.erase(tx.hash);
        tx_by_account_nonce_.erase({tx.from, tx.nonce});
    }

    // Sweep stale-nonce txs (M11): any mempool entry whose nonce is now
    // behind the chain's next_nonce can never be included.
    for (auto it = tx_store_.begin(); it != tx_store_.end(); ) {
        if (it->second.nonce < chain_.next_nonce(it->second.from)) {
            tx_by_account_nonce_.erase({it->second.from, it->second.nonce});
            it = tx_store_.erase(it);
        } else {
            ++it;
        }
    }

    registry_ = NodeRegistry::build_from_chain(chain_, chain_.height());
    current_aborts_.clear();
    contrib_timer_.cancel();
    block_sig_timer_.cancel();
    reset_round();

    // Drop equivocation evidence that was just baked into this block
    // (slashing already applied to the equivocator's stake in
    // apply_transactions). Match by equivocator since once they're
    // slashed to 0 stake they're suspended from selection anyway.
    for (auto& ev : b.equivocation_events) {
        pending_equivocation_evidence_.erase(
            std::remove_if(pending_equivocation_evidence_.begin(),
                            pending_equivocation_evidence_.end(),
                [&](const chain::EquivocationEvent& e) {
                    return e.equivocator == ev.equivocator;
                }),
            pending_equivocation_evidence_.end());
    }
    chain_.save(cfg_.chain_path);

    std::cout << "[node] accepted block #" << b.index
              << " creators=" << b.creators.size() << "\n";

    // rev.9 B2c.1: beacon nodes broadcast each newly-applied block as a
    // BEACON_HEADER so peering shard nodes can light-validate it. SINGLE
    // / SHARD roles do nothing — this gossip is beacon-emitted only.
    if (cfg_.chain_role == ChainRole::BEACON) {
        gossip_.broadcast(net::make_beacon_header(b));
    }
    // rev.9 B2c.3: shard nodes broadcast each newly-applied block as a
    // SHARD_TIP so peering beacon nodes can validate the committee K-of-K
    // and update latest_shard_tips_. SINGLE / BEACON roles do nothing.
    if (cfg_.chain_role == ChainRole::SHARD) {
        gossip_.broadcast(net::make_shard_tip(cfg_.shard_id, b));
    }

    check_if_selected();
}

void Node::on_block(const chain::Block& b) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    apply_block_locked(b);
}

void Node::on_tx(const chain::Transaction& tx) {
    std::lock_guard<std::mutex> lk(state_mutex_);

    // Drop stale-nonce txs immediately.
    if (tx.nonce < chain_.next_nonce(tx.from)) return;

    auto key = std::make_pair(tx.from, tx.nonce);
    auto idx = tx_by_account_nonce_.find(key);
    if (idx != tx_by_account_nonce_.end()) {
        // Replace-by-fee: keep the higher-fee version.
        auto existing = tx_store_.find(idx->second);
        if (existing != tx_store_.end() && existing->second.fee >= tx.fee) {
            return; // incumbent wins (ties favor incumbent — no resource churn)
        }
        if (existing != tx_store_.end()) tx_store_.erase(existing);
    }
    tx_store_[tx.hash] = tx;
    tx_by_account_nonce_[key] = tx.hash;
}

void Node::on_contrib(const ContribMsg& msg) {
    std::lock_guard<std::mutex> lk(state_mutex_);

    uint64_t expected_index = chain_.height();
    if (msg.block_index != expected_index) return;

    Hash prev_hash = chain_.empty() ? Hash{} : chain_.head_hash();
    if (msg.prev_hash != prev_hash) return;

    // Generation gate: drop contribs from a different abort-generation. After
    // a peer aborts and restarts, their fresh contrib carries a higher gen;
    // ours catches up via gossip convergence on AbortClaim quorums.
    if (msg.aborts_gen != current_aborts_.size()) return;

    // Note: we do NOT filter by current_creator_domains_ here. A contrib may
    // arrive before this node has entered IN_SYNC and computed its creator
    // set; rejecting would lose the message permanently (no retransmit).
    // Instead, we accept any signer that's in the registry. start_delay_compute
    // looks up pending_contribs_[d] for each selected creator at use time.
    auto entry = registry_.find(msg.signer);
    if (!entry) return;

    Hash commit = make_contrib_commitment(msg.block_index, msg.prev_hash,
                                            msg.tx_hashes, msg.dh_input);
    if (!crypto::verify(entry->pubkey, commit.data(), commit.size(), msg.ed_sig)) {
        std::cerr << "[node] invalid Contrib sig from " << msg.signer << "\n";
        return;
    }

    // Duplicate handling: a same-signer ContribMsg may arrive after a round
    // restart (post-abort) with a fresh dh_input — this is NOT equivocation,
    // it's a legitimate retry within the same height under a different abort
    // generation. Real equivocation detection requires generation tracking
    // (planned for a future rev). For now, if we're still in CONTRIB phase
    // and receive a duplicate from a signer we already have, ignore the new
    // one (keep the earlier-arrived view). If we're past CONTRIB (in
    // RUNNING_DELAY/BLOCK_SIG), the round is locked-in and stale messages
    // shouldn't reach here anyway.
    auto existing = pending_contribs_.find(msg.signer);
    if (existing != pending_contribs_.end()) return;

    pending_contribs_[msg.signer] = msg;

    if (phase_ == ConsensusPhase::CONTRIB &&
        pending_contribs_.size() == current_creator_domains_.size())
        start_delay_compute();
}

void Node::on_block_sig(const BlockSigMsg& msg) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    on_block_sig_locked(msg);
}

void Node::on_block_sig_locked(const BlockSigMsg& msg) {
    // Caller must hold state_mutex_. Used both from gossip dispatch (via
    // on_block_sig wrapper) and from start_delay_compute when replaying
    // buffered O3 messages.
    uint64_t expected_index = chain_.height();
    if (msg.block_index != expected_index) return;

    if (std::find(current_creator_domains_.begin(),
                  current_creator_domains_.end(), msg.signer)
        == current_creator_domains_.end()) return;

    auto entry = registry_.find(msg.signer);
    if (!entry) return;

    // O3: if we haven't reached BLOCK_SIG yet, buffer for replay.
    if (phase_ != ConsensusPhase::BLOCK_SIG) {
        // O1 piggyback opportunity: if we're currently RUNNING_DELAY and this
        // sig carries a delay_output that verifies against our seed, adopt
        // it and short-circuit the local compute.
        if (phase_ == ConsensusPhase::RUNNING_DELAY && !delay_done_) {
            if (crypto::delay_hash_verify(current_delay_seed_, cfg_.delay_T,
                                            msg.delay_output)) {
                delay_cancel_ = true;
                delay_done_   = true;
                local_delay_output_ = msg.delay_output;
                start_block_sig_phase(msg.delay_output);
                // fall through to validate this sig under the now-active phase
            }
        }
        if (phase_ != ConsensusPhase::BLOCK_SIG) {
            buffered_block_sigs_.push_back(msg);
            return;
        }
    }

    // delay_output must match the round's canonical output.
    if (msg.delay_output != current_delay_output_) {
        std::cerr << "[node] BlockSig with mismatched delay_output from "
                  << msg.signer << "\n";
        return;
    }

    // Build the same tentative block we used for our own digest, so we can
    // verify the peer's Ed25519 sig over it.
    std::vector<ContribMsg> ordered_contribs;
    for (auto& d : current_creator_domains_) {
        auto it = pending_contribs_.find(d);
        if (it == pending_contribs_.end()) return;
        ordered_contribs.push_back(it->second);
    }
    auto mode_local     = current_mode();
    auto proposer_local = current_proposer_domain();
    chain::Block tentative = build_body(tx_store_, chain_, current_aborts_,
                                         current_creator_domains_,
                                         ordered_contribs,
                                         current_delay_output_,
                                         cfg_.m_creators, mode_local, proposer_local,
                                         pending_equivocation_evidence_);
    Hash digest = compute_block_digest(tentative);

    if (!crypto::verify(entry->pubkey, digest.data(), digest.size(), msg.ed_sig)) {
        std::cerr << "[node] invalid BlockSig from " << msg.signer << "\n";
        return;
    }

    pending_block_sigs_[msg.signer] = msg;

    // Eager-finalize ONLY when we have all M sigs (the fast happy-path shared
    // by both modes). Finalizing on just K (when K<M) would race: different
    // peers would collect different K-sized subsets, build blocks with
    // different `creator_block_sigs` content, and produce divergent block
    // hashes. The block_sig_timer falls back to ≥K on timeout once gossip
    // has settled and all peers see the same sig set.
    if (pending_block_sigs_.size() == current_creator_domains_.size())
        try_finalize_round();
}

void Node::on_get_chain(uint64_t from_index, uint16_t count,
                         std::shared_ptr<net::Peer> peer) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (count == 0)   count = 64;
    if (count > 256)  count = 256;     // anti-DoS cap

    uint64_t end = std::min(chain_.height(), from_index + count);
    json blocks = json::array();
    for (uint64_t i = from_index; i < end; ++i)
        blocks.push_back(chain_.at(i).to_json());
    bool has_more = end < chain_.height();
    peer->send({net::MsgType::CHAIN_RESPONSE,
                {{"blocks", blocks}, {"has_more", has_more}}});
}

void Node::on_chain_response(const std::vector<chain::Block>& blocks,
                              bool has_more,
                              std::shared_ptr<net::Peer> peer) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (blocks.empty()) {
        // Peer reports nothing more — try transitioning to IN_SYNC.
        start_sync_if_behind();
        return;
    }

    for (auto& b : blocks) {
        // Apply each block; if any fails validation, drop the peer for this
        // sync session and re-probe.
        if (b.index != chain_.height()) continue;        // out-of-range chunk
        apply_block_locked(b);
    }

    if (has_more) {
        sync_peer_ = peer;
        request_next_chunk();
    } else {
        start_sync_if_behind();
    }
}

void Node::on_status_request(std::shared_ptr<net::Peer> peer) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    std::string ghash = chain_.empty() ? std::string{} : to_hex(chain_.at(0).compute_hash());
    peer->send(net::make_status_response(chain_.height(), ghash));
}

void Node::on_status_response(uint64_t height, const std::string& genesis_hash,
                               std::shared_ptr<net::Peer> peer) {
    std::lock_guard<std::mutex> lk(state_mutex_);

    // Reject peers on a different genesis. Their chain is not ours; they will
    // never feed us valid blocks.
    if (!chain_.empty()) {
        std::string ours = to_hex(chain_.at(0).compute_hash());
        if (!genesis_hash.empty() && genesis_hash != ours) {
            std::cerr << "[node] peer " << peer->address()
                      << " on different genesis (" << genesis_hash
                      << ", ours " << ours << "); ignoring\n";
            return;
        }
    }

    peer_heights_[peer->address()] = height;
    start_sync_if_behind();
}

void Node::start_sync_if_behind() {
    // state_mutex_ held by caller.
    uint64_t max_h = chain_.height();
    for (auto& [_, h] : peer_heights_) max_h = std::max(max_h, h);

    constexpr uint64_t TOLERANCE = 5;
    if (chain_.height() + TOLERANCE >= max_h) {
        if (state_ != SyncState::IN_SYNC) {
            state_ = SyncState::IN_SYNC;
            std::cout << "[node] caught up to height " << chain_.height()
                      << "; entering IN_SYNC\n";
            check_if_selected();
        }
        return;
    }

    state_ = SyncState::SYNCING;

    // Pick the highest-reported peer and request the next chunk from them.
    std::string best_addr;
    uint64_t    best_h = 0;
    for (auto& [addr, h] : peer_heights_) {
        if (h > best_h) { best_h = h; best_addr = addr; }
    }
    if (best_addr.empty()) return;

    // Resolve to the actual peer pointer. (peer_addresses returns the same
    // string format used as the key; for simplicity we just broadcast and
    // rely on the chunk responder being the highest peer.)
    sync_peer_ = nullptr; // we'll just broadcast — first responder wins
    request_next_chunk();
}

void Node::request_next_chunk() {
    // state_mutex_ held by caller.
    auto msg = net::make_get_chain(chain_.height(), 64);
    if (sync_peer_) {
        try { sync_peer_->send(msg); } catch (...) { sync_peer_ = nullptr; }
    } else {
        gossip_.broadcast(msg);
    }
}

// ─── RPC Handlers ────────────────────────────────────────────────────────────

json Node::rpc_status() const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    json j;
    j["height"]      = chain_.height();
    j["head_hash"]   = chain_.empty() ? "" : to_hex(chain_.head_hash());
    j["node_count"]  = registry_.size();
    j["domain"]      = cfg_.domain;
    j["peer_count"]  = gossip_.peer_count();
    j["m_creators"]  = cfg_.m_creators;
    j["k_block_sigs"]= cfg_.k_block_sigs;
    j["sync_state"]  = (state_ == SyncState::IN_SYNC) ? "in_sync" : "syncing";
    j["genesis"]     = chain_.empty() ? "" : to_hex(chain_.at(0).compute_hash());
    j["chain_role"]  = to_string(cfg_.chain_role);
    j["shard_id"]    = cfg_.shard_id;
    j["epoch_index"] = current_epoch_index();
    j["mempool_size"] = tx_store_.size();
    j["beacon_headers"]    = beacon_headers_.size();    // shard-only; 0 elsewhere
    j["tracked_shard_tips"] = latest_shard_tips_.size(); // beacon-only; 0 elsewhere

    // Block-mode + tx counters across the full chain. Useful for ops
    // dashboards and test assertions ("did the chain actually escalate?").
    uint64_t md_blocks = 0, bft_blocks = 0, total_txs = 0;
    for (uint64_t i = 0; i < chain_.height(); ++i) {
        const auto& b = chain_.at(i);
        total_txs += b.transactions.size();
        if (b.consensus_mode == chain::ConsensusMode::BFT) ++bft_blocks;
        else ++md_blocks;
    }
    j["md_block_count"]  = md_blocks;
    j["bft_block_count"] = bft_blocks;
    j["tx_count"]        = total_txs;

    auto nodes = registry_.sorted_nodes();
    if (!chain_.empty() && nodes.size() >= cfg_.m_creators) {
        Hash rand = chain_.head().cumulative_rand;
        try {
            auto indices = crypto::select_m_creators(rand, nodes.size(), cfg_.m_creators);
            json next = json::array();
            for (auto i : indices) next.push_back(nodes[i].domain);
            j["next_creators"] = next;
        } catch (...) {}
    }
    return j;
}

json Node::rpc_peers() const {
    auto addrs = gossip_.peer_addresses();
    return json(addrs);
}

json Node::rpc_block(uint64_t index) const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (index >= chain_.height()) return nullptr;
    return chain_.at(index).to_json();
}

json Node::rpc_account(const std::string& addr) const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    json j;
    j["address"]    = addr;
    j["balance"]    = chain_.balance(addr);
    j["next_nonce"] = chain_.next_nonce(addr);

    // Bearer-wallet anonymous addresses surface as their pubkey-derived
    // address; show that fact for the explorer.
    j["is_anonymous"] = is_anon_address(addr);

    // If the address is a registered domain, attach registry + stake info.
    auto reg_entry = chain_.registrant(addr);
    if (reg_entry) {
        json r;
        r["ed_pub"]        = to_hex(reg_entry->ed_pub);
        r["registered_at"] = reg_entry->registered_at;
        r["active_from"]   = reg_entry->active_from;
        r["inactive_from"] = reg_entry->inactive_from;
        j["registry"]      = r;
        j["stake"]         = chain_.stake(addr);
    } else {
        j["registry"] = nullptr;
        j["stake"]    = chain_.stake(addr);    // 0 if not staked
    }

    // Aggregate visibility: has this address ever appeared on-chain?
    bool has_state = (chain_.balance(addr) > 0)
                  || (chain_.next_nonce(addr) > 0)
                  || reg_entry.has_value();
    if (!has_state) return nullptr;
    return j;
}

json Node::rpc_tx(const std::string& hash_hex) const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (hash_hex.size() != 64) return nullptr;
    Hash target;
    try {
        target = from_hex_arr<32>(hash_hex);
    } catch (...) { return nullptr; }

    // Scan tip → genesis (recent blocks first; explorer queries skew
    // toward fresh transactions). Linear in chain height; fine for the
    // current single-chain volume — a hash-keyed index lives in B6.
    uint64_t total = chain_.height();
    for (uint64_t i = total; i > 0; --i) {
        const auto& b = chain_.at(i - 1);
        for (const auto& tx : b.transactions) {
            if (tx.hash == target) {
                json out;
                out["tx"]          = tx.to_json();
                out["block_index"] = b.index;
                out["block_hash"]  = to_hex(b.compute_hash());
                out["timestamp"]   = b.timestamp;
                return out;
            }
        }
    }
    return nullptr;
}

json Node::rpc_validators() const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    json arr = json::array();
    auto reg = NodeRegistry::build_from_chain(chain_, chain_.height());
    for (auto& nd : reg.sorted_nodes()) {
        json e;
        e["domain"]       = nd.domain;
        e["ed_pub"]       = to_hex(nd.pubkey);
        e["active_from"]  = nd.active_from;
        e["registered_at"]= nd.registered_at;
        e["stake"]        = chain_.stake(nd.domain);
        arr.push_back(e);
    }
    return arr;
}

json Node::rpc_chain_summary(uint32_t last_n) const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    json arr = json::array();
    uint64_t total = chain_.height();
    if (total == 0) return arr;
    uint64_t start = (total > last_n) ? total - last_n : 0;
    for (uint64_t i = start; i < total; ++i) {
        const auto& b = chain_.at(i);
        json e;
        e["index"]          = b.index;
        e["hash"]           = to_hex(b.compute_hash());
        e["prev_hash"]      = to_hex(b.prev_hash);
        e["timestamp"]      = b.timestamp;
        e["consensus_mode"] = static_cast<uint8_t>(b.consensus_mode);
        e["bft_proposer"]   = b.bft_proposer;
        e["tx_count"]       = b.transactions.size();
        e["creators"]       = b.creators;
        arr.push_back(e);
    }
    return arr;
}

json Node::rpc_send(const std::string& to, uint64_t amount, uint64_t fee) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    chain::Transaction tx;
    tx.type   = chain::TxType::TRANSFER;
    tx.from   = cfg_.domain;
    tx.to     = to;
    tx.amount = amount;
    tx.fee    = fee;
    tx.nonce  = chain_.next_nonce(cfg_.domain);

    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(key_, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    tx_store_[tx.hash] = tx;
    tx_by_account_nonce_[{tx.from, tx.nonce}] = tx.hash;
    gossip_.broadcast(net::make_transaction(tx));
    return {{"status", "queued"}, {"hash", to_hex(tx.hash)}};
}

static std::vector<uint8_t> encode_amount(uint64_t a) {
    std::vector<uint8_t> v(8);
    for (int i = 0; i < 8; ++i) v[i] = (a >> (8 * i)) & 0xFF;
    return v;
}

json Node::rpc_stake(uint64_t amount, uint64_t fee) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    chain::Transaction tx;
    tx.type    = chain::TxType::STAKE;
    tx.from    = cfg_.domain;
    tx.to      = "";
    tx.amount  = 0;
    tx.fee     = fee;
    tx.nonce   = chain_.next_nonce(cfg_.domain);
    tx.payload = encode_amount(amount);

    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(key_, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    tx_store_[tx.hash] = tx;
    tx_by_account_nonce_[{tx.from, tx.nonce}] = tx.hash;
    gossip_.broadcast(net::make_transaction(tx));
    return {{"status", "queued"}, {"hash", to_hex(tx.hash)}, {"locked_increment", amount}};
}

json Node::rpc_unstake(uint64_t amount, uint64_t fee) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    chain::Transaction tx;
    tx.type    = chain::TxType::UNSTAKE;
    tx.from    = cfg_.domain;
    tx.to      = "";
    tx.amount  = 0;
    tx.fee     = fee;
    tx.nonce   = chain_.next_nonce(cfg_.domain);
    tx.payload = encode_amount(amount);

    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(key_, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    tx_store_[tx.hash] = tx;
    tx_by_account_nonce_[{tx.from, tx.nonce}] = tx.hash;
    gossip_.broadcast(net::make_transaction(tx));
    return {{"status", "queued"}, {"hash", to_hex(tx.hash)}, {"unlock_at", chain_.stake_unlock_height(cfg_.domain)}};
}

json Node::rpc_nonce(const std::string& domain) const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return {{"domain", domain}, {"next_nonce", chain_.next_nonce(domain)}};
}

json Node::rpc_stake_info(const std::string& domain) const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return {
        {"domain",        domain},
        {"locked",        chain_.stake(domain)},
        {"unlock_height", chain_.stake_unlock_height(domain)}
    };
}

json Node::rpc_submit_tx(const json& tx_json) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    chain::Transaction tx = chain::Transaction::from_json(tx_json);

    // Recompute hash to defend against client-side errors / tampering.
    Hash expected_hash = tx.compute_hash();
    if (tx.hash != expected_hash)
        throw std::runtime_error(
            "submitted tx hash mismatch: expected " + to_hex(expected_hash)
          + " got " + to_hex(tx.hash));

    // Stale-nonce drop here too (mirrors on_tx).
    if (tx.nonce < chain_.next_nonce(tx.from))
        throw std::runtime_error(
            "submitted tx has stale nonce " + std::to_string(tx.nonce)
          + " (expected >= " + std::to_string(chain_.next_nonce(tx.from)) + ")");

    auto key = std::make_pair(tx.from, tx.nonce);
    auto idx = tx_by_account_nonce_.find(key);
    if (idx != tx_by_account_nonce_.end()) {
        auto existing = tx_store_.find(idx->second);
        if (existing != tx_store_.end() && existing->second.fee >= tx.fee)
            throw std::runtime_error(
                "incumbent tx at (from, nonce) has equal-or-higher fee");
        if (existing != tx_store_.end()) tx_store_.erase(existing);
    }
    tx_store_[tx.hash] = tx;
    tx_by_account_nonce_[key] = tx.hash;
    gossip_.broadcast(net::make_transaction(tx));
    return {{"status", "queued"}, {"hash", to_hex(tx.hash)}};
}

json Node::rpc_balance(const std::string& domain) const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return {{"domain", domain}, {"balance", chain_.balance(domain)}};
}

json Node::rpc_register() {
    std::lock_guard<std::mutex> lk(state_mutex_);

    // Payload: just the Ed25519 pubkey (32 B). The tx's own Ed25519 sig
    // (verified at validator) proves possession of the key — no separate PoP.
    std::vector<uint8_t> payload(chain::REGISTER_PAYLOAD_SIZE);
    std::copy(key_.pub.begin(), key_.pub.end(), payload.begin());

    chain::Transaction tx;
    tx.type    = chain::TxType::REGISTER;
    tx.from    = cfg_.domain;
    tx.to      = "";
    tx.amount  = 0;
    tx.fee     = 0;
    tx.nonce   = chain_.next_nonce(cfg_.domain);
    tx.payload = std::move(payload);

    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(key_, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    tx_store_[tx.hash] = tx;
    tx_by_account_nonce_[{tx.from, tx.nonce}] = tx.hash;
    gossip_.broadcast(net::make_transaction(tx));
    return {{"status", "queued"}, {"hash", to_hex(tx.hash)}};
}

} // namespace dhcoin::node
