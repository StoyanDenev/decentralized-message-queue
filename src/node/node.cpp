// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/node/node.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/chain/params.hpp>
#include <determ/crypto/random.hpp>
#include <determ/crypto/sha256.hpp>
#include <set>
#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>

namespace determ::node {

namespace fs = std::filesystem;
using json = nlohmann::json;

// ─── Config ──────────────────────────────────────────────────────────────────

json Config::to_json() const {
    json j;
    j["domain"]          = domain;
    j["data_dir"]        = data_dir;
    j["listen_port"]     = listen_port;
    j["rpc_port"]        = rpc_port;
    j["rpc_localhost_only"] = rpc_localhost_only;
    j["rpc_auth_secret"] = rpc_auth_secret;
    j["rpc_rate_per_sec"] = rpc_rate_per_sec;
    j["rpc_rate_burst"]   = rpc_rate_burst;
    j["bootstrap_peers"] = bootstrap_peers;
    j["beacon_peers"]    = beacon_peers;
    j["shard_peers"]     = shard_peers;
    j["key_path"]        = key_path;
    j["chain_path"]      = chain_path;
    j["snapshot_path"]   = snapshot_path;
    j["shard_manifest_path"] = shard_manifest_path;
    j["genesis_path"]    = genesis_path;
    j["genesis_hash"]    = genesis_hash;
    j["m_creators"]              = m_creators;
    j["k_block_sigs"]            = k_block_sigs;
    j["bft_enabled"]             = bft_enabled;
    j["bft_escalation_threshold"]= bft_escalation_threshold;
    j["chain_role"]              = static_cast<uint8_t>(chain_role);
    j["sharding_mode"]           = static_cast<uint8_t>(sharding_mode);
    j["shard_id"]                = shard_id;
    j["initial_shard_count"]     = initial_shard_count;
    j["epoch_blocks"]            = epoch_blocks;
    j["tx_commit_ms"]    = tx_commit_ms;
    j["block_sig_ms"]    = block_sig_ms;
    j["abort_claim_ms"]  = abort_claim_ms;
    j["region"]          = region;
    j["committee_region"]= committee_region;
    return j;
}

Config Config::from_json(const json& j) {
    Config c;
    c.domain          = j.value("domain",         "");
    c.data_dir        = j.value("data_dir",       "");
    c.listen_port     = j.value("listen_port",    uint16_t{7777});
    c.rpc_port        = j.value("rpc_port",       uint16_t{7778});
    c.rpc_auth_secret = j.value("rpc_auth_secret", std::string{});
    c.rpc_rate_per_sec = j.value("rpc_rate_per_sec", 0.0);
    c.rpc_rate_burst   = j.value("rpc_rate_burst",   0.0);
    // S-001: default to localhost-only. Absent field in legacy configs
    // gets the secure default; operators must opt-in to all-interfaces.
    c.rpc_localhost_only = j.value("rpc_localhost_only", true);
    c.bootstrap_peers = j.value("bootstrap_peers", std::vector<std::string>{});
    c.beacon_peers    = j.value("beacon_peers",    std::vector<std::string>{});
    c.shard_peers     = j.value("shard_peers",     std::vector<std::string>{});
    c.key_path        = j.value("key_path",       "");
    c.chain_path      = j.value("chain_path",     "");
    c.snapshot_path   = j.value("snapshot_path",  "");
    c.shard_manifest_path = j.value("shard_manifest_path", "");
    c.genesis_path    = j.value("genesis_path",   "");
    c.genesis_hash    = j.value("genesis_hash",   "");
    c.m_creators      = j.value("m_creators",     uint32_t{3});
    c.k_block_sigs    = j.value("k_block_sigs",   c.m_creators);   // default = strong
    c.bft_enabled              = j.value("bft_enabled",              true);
    c.bft_escalation_threshold = j.value("bft_escalation_threshold", uint32_t{5});
    c.chain_role               = static_cast<ChainRole>(j.value("chain_role", uint8_t{0}));
    // A6: sharding_mode persisted alongside chain_role. Default
    // CURRENT preserves byte-identical behavior for pre-A6 configs that
    // lack the field — those were necessarily running CURRENT semantics
    // (rev.9 sharding) since EXTENDED requires R1+R2 plumbing that
    // didn't exist when those configs were written.
    c.sharding_mode            = static_cast<ShardingMode>(j.value("sharding_mode", uint8_t{1}));
    c.shard_id                 = j.value("shard_id",                 ShardId{0});
    c.initial_shard_count      = j.value("initial_shard_count",      uint32_t{1});
    c.epoch_blocks             = j.value("epoch_blocks",             uint32_t{1000});
    c.tx_commit_ms    = j.value("tx_commit_ms",   uint32_t{200});
    c.block_sig_ms    = j.value("block_sig_ms",   uint32_t{200});
    c.abort_claim_ms  = j.value("abort_claim_ms", uint32_t{200});
    // rev.9 R1: optional region tags. Empty defaults preserve byte-
    // identical behavior with pre-R1 configs.
    c.region          = j.value("region",          std::string{});
    c.committee_region= j.value("committee_region",std::string{});
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

    validator_.set_k_block_sigs(cfg.k_block_sigs);
    validator_.set_m_pool(cfg.m_creators);

    key_ = crypto::load_node_key(cfg_.key_path);

    // Rev. 4: genesis is the source of truth for chain-wide constants
    // (M, K, block_subsidy). Load it FIRST so chain replay during load uses
    // the correct subsidy when crediting creators.
    uint64_t genesis_subsidy = 0;
    uint64_t genesis_min_stake = 1000;
    uint64_t genesis_suspension_slash = 10;
    uint64_t genesis_unstake_delay    = 1000;
    uint32_t genesis_merge_threshold  = 100;
    uint32_t genesis_revert_threshold = 200;
    uint32_t genesis_merge_grace      = 10;
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
        // rev.9 R2: genesis is the source of truth for committee_region.
        // The cfg_ copy is what check_if_selected reads; the validator
        // mirror is set immediately below.
        cfg_.committee_region        = gcfg.committee_region;
        genesis_subsidy              = gcfg.block_subsidy;
        genesis_min_stake            = gcfg.min_stake;
        genesis_suspension_slash     = gcfg.suspension_slash;
        genesis_unstake_delay        = gcfg.unstake_delay;
        genesis_merge_threshold      = gcfg.merge_threshold_blocks;
        genesis_revert_threshold     = gcfg.revert_threshold_blocks;
        genesis_merge_grace          = gcfg.merge_grace_blocks;
        genesis_inclusion            = gcfg.inclusion_model;
        validator_.set_k_block_sigs(cfg_.k_block_sigs);
        validator_.set_m_pool(cfg_.m_creators);
        validator_.set_bft_enabled(cfg_.bft_enabled);
        validator_.set_bft_escalation_threshold(cfg_.bft_escalation_threshold);
        validator_.set_epoch_blocks(cfg_.epoch_blocks);
        validator_.set_shard_id(cfg_.shard_id);
        validator_.set_committee_region(cfg_.committee_region);
        validator_.set_sharding_mode(cfg_.sharding_mode);
        // A5: governance state mirrored from genesis. Uncontrolled
        // chains pass mode=0 + empty keyholders, which makes the
        // validator reject any PARAM_CHANGE outright (the default).
        validator_.set_governance_mode(gcfg.governance_mode);
        validator_.set_param_keyholders(gcfg.param_keyholders);
        validator_.set_param_threshold(gcfg.param_threshold);

        // A5 Phase 2: install Chain → Validator parameter-changed hook.
        // When a staged PARAM_CHANGE activates at a block boundary, the
        // chain calls back for each (name, value) pair so the validator
        // state mirrors any field that lives outside the chain's own
        // instance state. Chain-local fields (MIN_STAKE → min_stake_)
        // already updated themselves; here we only handle the validator-
        // side fields.
        chain_.set_param_changed_hook(
            [this](const std::string& name,
                     const std::vector<uint8_t>& value) {
                if (name == "bft_escalation_threshold" && value.size() == 8) {
                    uint64_t v = 0;
                    for (int i = 0; i < 8; ++i) v |= uint64_t(value[i]) << (8 * i);
                    validator_.set_bft_escalation_threshold(static_cast<uint32_t>(v));
                } else if (name == "param_threshold" && value.size() == 8) {
                    uint64_t v = 0;
                    for (int i = 0; i < 8; ++i) v |= uint64_t(value[i]) << (8 * i);
                    validator_.set_param_threshold(static_cast<uint32_t>(v));
                } else if (name == "param_keyholders") {
                    // Wire format: [count: u8] count × { ed_pub: 32B }
                    if (!value.empty()) {
                        uint8_t n = value[0];
                        if (value.size() == size_t(1) + size_t(n) * 32) {
                            std::vector<PubKey> ks;
                            ks.reserve(n);
                            for (uint8_t i = 0; i < n; ++i) {
                                PubKey pk{};
                                std::copy_n(value.begin() + 1 + i * 32, 32,
                                            pk.begin());
                                ks.push_back(pk);
                            }
                            validator_.set_param_keyholders(std::move(ks));
                        }
                    }
                }
                // A5 Phase 4: producer timing fields. Reads happen at
                // timer-scheduling time inside on_phase_1_done /
                // on_phase_2_done, so any update here is picked up on
                // the next round. These do not need to live on Chain
                // (replay doesn't depend on timing); cfg_ is the
                // canonical runtime carrier.
                else if (name == "tx_commit_ms" && value.size() == 8) {
                    uint64_t v = 0;
                    for (int i = 0; i < 8; ++i) v |= uint64_t(value[i]) << (8 * i);
                    cfg_.tx_commit_ms = static_cast<uint32_t>(v);
                }
                else if (name == "block_sig_ms" && value.size() == 8) {
                    uint64_t v = 0;
                    for (int i = 0; i < 8; ++i) v |= uint64_t(value[i]) << (8 * i);
                    cfg_.block_sig_ms = static_cast<uint32_t>(v);
                }
                else if (name == "abort_claim_ms" && value.size() == 8) {
                    uint64_t v = 0;
                    for (int i = 0; i < 8; ++i) v |= uint64_t(value[i]) << (8 * i);
                    cfg_.abort_claim_ms = static_cast<uint32_t>(v);
                }
                // MIN_STAKE / UNSTAKE_DELAY / SUSPENSION_SLASH are
                // chain-local: the chain wrote them itself before this
                // hook fired, so no mirror needed here.
            });

        // A6 startup gate: enforce that the operator-selected sharding
        // mode is consistent with the genesis being loaded. Defense in
        // depth — genesis-tool already rejects most of these at build
        // time, but a node can be pointed at any genesis file at start
        // time. Mismatch here means the operator picked the wrong
        // profile for this chain (or the genesis was tampered with);
        // refusing to start is the safe response.
        switch (cfg_.sharding_mode) {
        case ShardingMode::NONE:
            if (gcfg.chain_role != ChainRole::SINGLE) {
                throw std::runtime_error(
                    "sharding_mode=none requires chain_role=single, "
                    "but genesis declares chain_role="
                    + std::string(to_string(gcfg.chain_role)));
            }
            if (!gcfg.committee_region.empty()) {
                throw std::runtime_error(
                    "sharding_mode=none rejects non-empty "
                    "committee_region (got '" + gcfg.committee_region
                    + "') — region is meaningless in single-chain "
                      "deployments");
            }
            for (auto& gc : gcfg.initial_creators) {
                if (!gc.region.empty()) {
                    throw std::runtime_error(
                        "sharding_mode=none rejects per-creator region "
                        "tag (creator '" + gc.domain + "' has region='"
                        + gc.region + "')");
                }
            }
            break;
        case ShardingMode::CURRENT:
            // CURRENT accepts BEACON/SHARD/SINGLE chain_role. The
            // committee_region must be empty (no regional grouping in
            // CURRENT — that's exactly what EXTENDED is for). Per-
            // creator region is tolerated silently for forward compat
            // with chains that ship region tags but don't yet use them.
            if (!gcfg.committee_region.empty()) {
                throw std::runtime_error(
                    "sharding_mode=current rejects non-empty "
                    "committee_region (got '" + gcfg.committee_region
                    + "') — regional committees require "
                      "sharding_mode=extended");
            }
            break;
        case ShardingMode::EXTENDED:
            // EXTENDED requires the S-038 invariant: a regional shard
            // deployment with fewer than 3 shards is degenerate (the
            // under-quorum merge mechanism that justifies the EXTENDED
            // mode needs at least 3 shards to make a meaningful
            // modular fold). Re-checked here as defense in depth on
            // top of the genesis-tool guard.
            if (gcfg.initial_shard_count < 3) {
                throw std::runtime_error(
                    "sharding_mode=extended requires initial_shard_count "
                    ">= 3 (got " + std::to_string(gcfg.initial_shard_count)
                    + ") — S-038 mitigation");
            }
            break;
        }

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

        // R2: BEACON-role nodes optionally load a shard manifest to learn
        // per-shard committee_region. Required under EXTENDED (where region
        // enforcement matters); optional under CURRENT (where every shard
        // has committee_region == "" anyway). Manifest path defaults to
        // <data_dir>/shard_manifest.json if cfg_.shard_manifest_path is empty.
        if (cfg_.chain_role == ChainRole::BEACON) {
            std::string mpath = cfg_.shard_manifest_path;
            if (mpath.empty() && !cfg_.data_dir.empty())
                mpath = cfg_.data_dir + "/shard_manifest.json";
            bool extended =
                (cfg_.sharding_mode == ShardingMode::EXTENDED);
            std::ifstream mf(mpath);
            if (!mf) {
                if (extended) {
                    throw std::runtime_error(
                        "beacon (EXTENDED) requires shard_manifest at '"
                        + mpath + "' — file not found. Set "
                        "shard_manifest_path in config.json or pass "
                        "--shard-manifest <path>");
                }
                // CURRENT / NONE: silent skip (region filter is a no-op anyway).
            } else {
                json mj;
                try { mj = json::parse(mf); }
                catch (std::exception& e) {
                    throw std::runtime_error(
                        std::string("shard_manifest parse error: ") + e.what());
                }
                if (!mj.is_object() || !mj.contains("shards")
                    || !mj["shards"].is_array()) {
                    throw std::runtime_error(
                        "shard_manifest: expected {\"shards\": [...]}");
                }
                std::set<ShardId> seen;
                for (auto& entry : mj["shards"]) {
                    if (!entry.is_object()) {
                        throw std::runtime_error(
                            "shard_manifest: each entry must be an object");
                    }
                    ShardId sid = entry.value("shard_id", ShardId{0});
                    std::string region = entry.value("committee_region", "");
                    // Normalize + validate region (same rules as
                    // genesis-load + REGISTER apply elsewhere).
                    for (auto& c : region) {
                        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
                    }
                    if (region.size() > 32) {
                        throw std::runtime_error(
                            "shard_manifest: region too long (shard_id="
                            + std::to_string(sid) + ", "
                            + std::to_string(region.size()) + " > 32 bytes)");
                    }
                    for (char c : region) {
                        bool ok = (c >= 'a' && c <= 'z')
                               || (c >= '0' && c <= '9')
                               || c == '-' || c == '_';
                        if (!ok) {
                            throw std::runtime_error(
                                "shard_manifest: region for shard_id="
                                + std::to_string(sid)
                                + " contains forbidden character (charset is [a-z0-9-_])");
                        }
                    }
                    if (!seen.insert(sid).second) {
                        throw std::runtime_error(
                            "shard_manifest: duplicate shard_id="
                            + std::to_string(sid));
                    }
                    shard_committee_regions_[sid] = region;
                }
                std::cout << "[node] loaded shard_manifest with "
                          << shard_committee_regions_.size() << " entries from "
                          << mpath << "\n";
            }
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
    chain_.set_suspension_slash(genesis_suspension_slash);
    chain_.set_unstake_delay(genesis_unstake_delay);
    chain_.set_merge_threshold_blocks(genesis_merge_threshold);
    chain_.set_revert_threshold_blocks(genesis_revert_threshold);
    chain_.set_merge_grace_blocks(genesis_merge_grace);
    chain_.set_shard_routing(genesis_shard_count, genesis_shard_salt,
                              genesis_my_shard);

    if (chain_.empty()) {
        // rev.9 B6.basic: prefer snapshot bootstrap when configured.
        // Skips block-by-block replay; state is restored directly from
        // the snapshot's accounts/stakes/registrants/dedup maps. Tail
        // headers in the snapshot become blocks_; subsequent blocks
        // apply normally. The snapshot's claimed head_hash is verified
        // against compute_hash() on the tail head (rejects loudly on
        // mismatch). Genesis bootstrap is skipped when snapshot loads
        // successfully — no need for the original genesis to be present.
        if (!cfg_.snapshot_path.empty()
            && std::filesystem::exists(cfg_.snapshot_path)) {
            try {
                std::ifstream sf(cfg_.snapshot_path);
                nlohmann::json sj = nlohmann::json::parse(sf);
                chain_ = chain::Chain::restore_from_snapshot(sj);
                // restore_from_snapshot reads constants from the
                // snapshot itself; they should match what genesis
                // would set, but we do not require gcfg_opt here.
                std::cout << "[node] restored from snapshot "
                          << cfg_.snapshot_path
                          << " block_index=" << chain_.head().index
                          << " head=" << to_hex(chain_.head_hash())
                          << " accounts=" << chain_.accounts().size()
                          << " stakes=" << chain_.stakes().size()
                          << " registrants=" << chain_.registrants().size()
                          << "\n";
                // Persist as the working chain.json so subsequent
                // restarts see a populated chain (they'll re-apply
                // the tail headers — apply on already-applied state
                // is a no-op for genesis-skipped paths since there's
                // no prior state to overwrite). Note: the snapshot
                // file remains the canonical state seed; do not
                // delete it.
                chain_.save(cfg_.chain_path);
                goto chain_loaded;
            } catch (std::exception& e) {
                std::cerr << "[node] snapshot restore failed: " << e.what()
                          << "; falling back to genesis bootstrap\n";
            }
        }

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
            chain_.set_subsidy_pool_initial(gcfg_opt->subsidy_pool_initial);
            chain_.set_subsidy_mode(gcfg_opt->subsidy_mode);
            chain_.set_lottery_jackpot_multiplier(gcfg_opt->lottery_jackpot_multiplier);
            chain_.set_min_stake(genesis_min_stake);
            chain_.set_suspension_slash(genesis_suspension_slash);
            chain_.set_unstake_delay(genesis_unstake_delay);
            chain_.set_merge_threshold_blocks(genesis_merge_threshold);
            chain_.set_revert_threshold_blocks(genesis_revert_threshold);
            chain_.set_merge_grace_blocks(genesis_merge_grace);
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

chain_loaded:
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
    gossip_.on_cross_shard_receipt_bundle =
        [this](auto sid, auto& src_block, auto& relay) {
            on_cross_shard_receipt_bundle(sid, src_block, relay);
        };
    gossip_.on_snapshot_request = [this](auto headers, auto peer) {
        on_snapshot_request(headers, peer);
    };
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

    // A9 / S-031 follow-on: spawn the async chain.save worker.
    // Sits idle on save_cv_ until enqueue_save() flips save_pending_.
    // See save_worker_loop() below for the loop body. The thread is
    // joined in stop() after save_stop_ is set and save_cv_ is notified.
    save_thread_ = std::thread([this] { save_worker_loop(); });

    // Initial sync probe with a startup grace period: give bootstrap peers
    // a chance to connect before we engage consensus. Without this, a fresh
    // multi-node cluster fires the first round before peers are reachable,
    // the contrib phase aborts (broadcast goes nowhere), and per-node
    // generations diverge; recovery never converges.
    auto grace = std::make_shared<asio::steady_timer>(
        io_, std::chrono::milliseconds(1500));
    grace->async_wait([this, grace](std::error_code ec) {
        if (ec) return;
        std::unique_lock<std::shared_mutex> lk(state_mutex_);
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
        io_.stop();
        for (auto& t : threads_) if (t.joinable()) t.join();

        // A9 / S-031 follow-on: wind down the save worker. Signal stop,
        // notify the cv, join. After join, run one final synchronous
        // save below to guarantee the chain.json on disk reflects the
        // most-recent applied state (the worker may have been waiting
        // when stop was called, with a save_pending flag set but not
        // yet acted on, or may have completed an earlier save before
        // the last apply landed).
        save_stop_.store(true);
        save_cv_.notify_all();
        if (save_thread_.joinable()) save_thread_.join();

        // Final synchronous save covers two cases:
        //  1. save_pending_ was set when stop fired — worker exits
        //     loop before processing the flag.
        //  2. An apply landed between the worker's last save and
        //     stop() — no pending flag, but disk is stale.
        // Both are made-good by writing once more here.
        chain_.save(cfg_.chain_path);
    }
}

// A9 / S-031 follow-on: async chain.save worker loop. Waits on
// save_cv_ until either save_pending_ flips true (work to do) or
// save_stop_ flips true (shutdown). On wake-with-work: clear the
// flag, take state_mutex_'s shared_lock, call chain_.save(),
// release the lock. Multiple notify_one calls during a running
// save coalesce: the flag stays set, and one additional save fires
// after the running one completes.
//
// Lock semantics: chain_.save() under shared_lock is concurrent with
// RPC readers (which already hold shared_lock for their queries).
// It DOES serialize against the next apply's unique_lock acquisition.
// On long chains where serialize+write dominates, the next apply
// blocks until the save finishes — same as the pre-fix behavior in
// the limit, but with the difference that the save is no longer
// holding the unique_lock through the disk write. The async path
// helps most when RPCs dominate the workload (readers proceed in
// parallel with the save), and is a stepping stone to the eventual
// one-file-per-block model (Phase 2D) which makes save O(1).
void Node::save_worker_loop() {
    while (true) {
        bool do_save = false;
        {
            std::unique_lock<std::mutex> lk(save_mutex_);
            save_cv_.wait(lk, [&]() {
                return save_pending_.load() || save_stop_.load();
            });
            if (save_stop_.load()) {
                // Don't process the in-flight flag here — stop() will
                // run the final synchronous save after we exit, so any
                // pending work is covered. This avoids a race where the
                // worker reads chain_ while stop() is destroying state.
                return;
            }
            // Clear the flag while still holding save_mutex_ so an
            // enqueue_save() arriving NOW will re-set the flag and the
            // next iteration will run again. This guarantees no
            // missed save.
            save_pending_.store(false);
            do_save = true;
        }
        if (!do_save) continue;
        try {
            std::shared_lock<std::shared_mutex> slk(state_mutex_);
            chain_.save(cfg_.chain_path);
        } catch (std::exception& e) {
            std::cerr << "[save worker] save failed: " << e.what() << "\n";
            // Don't terminate the loop — transient disk failures
            // (full disk, locked file) should retry on the next
            // enqueue_save signal. The chain in memory is fine; only
            // the on-disk persistence is at risk.
        }
    }
}

void Node::enqueue_save() {
    {
        std::lock_guard<std::mutex> lk(save_mutex_);
        save_pending_.store(true);
    }
    save_cv_.notify_one();
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

    // rev.9 R2: filter the eligible pool by this chain's
    // committee_region BEFORE running select_m_creators. Empty region
    // (the default) yields the full pool — pre-R2 behavior preserved
    // exactly. Non-empty restricts the pool to validators whose
    // self-declared region matches.
    auto nodes = registry_.eligible_in_region(cfg_.committee_region);
    // R4 Phase 4: under-quorum stress branch. When this shard absorbs
    // refugees from another shard (per Chain::merge_state_), extend
    // the eligible pool with validators tagged with each refugee's
    // region. The validator (check_creator_selection) mirrors this
    // logic so what we propose here remains acceptable to others.
    for (auto& [refugee_shard, refugee_region] :
         chain_.shards_absorbed_by(cfg_.shard_id)) {
        (void)refugee_shard;
        if (refugee_region.empty() || refugee_region == cfg_.committee_region)
            continue;
        auto refugees = registry_.eligible_in_region(refugee_region);
        for (auto& r : refugees) {
            bool dup = false;
            for (auto& n : nodes) if (n.domain == r.domain) { dup = true; break; }
            if (!dup) nodes.push_back(r);
        }
    }
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

    // rev.9 S-009: generate a fresh Phase-1 secret. The contribmsg's
    // dh_input is now SHA256(secret || my_pubkey) — a commit, not the
    // raw secret. The secret is held locally until Phase 2, when it's
    // revealed in our BlockSigMsg.dh_secret. Selective-abort defense
    // shifts to SHA-256 preimage resistance: an attacker cannot
    // extract any honest member's secret from its commit during
    // Phase 1, so they cannot precompute the eventual delay_output
    // (which depends on all K secrets).
    Hash my_secret{};
    if (RAND_bytes(my_secret.data(), 32) != 1)
        throw std::runtime_error("RAND_bytes failed for dh_secret");
    current_round_secret_ = my_secret;
    Hash my_commit = crypto::SHA256Builder{}
        .append(my_secret)
        .append(key_.pub.data(), key_.pub.size())
        .finalize();

    ContribMsg my_contrib = make_contrib(key_, cfg_.domain,
                                          block_index, prev_hash,
                                          current_aborts_.size(),
                                          snap, my_commit);
    pending_contribs_[cfg_.domain] = my_contrib;
    gossip_.broadcast(net::make_contrib(my_contrib));

    contrib_timer_.expires_after(std::chrono::milliseconds(cfg_.tx_commit_ms));
    contrib_timer_.async_wait([this](std::error_code ec) {
        if (ec) return;
        std::unique_lock<std::shared_mutex> lk(state_mutex_);
        handle_contrib_timeout();
    });

    if (pending_contribs_.size() == current_creator_domains_.size())
        enter_block_sig_phase();
}

// Transition Phase 1 → Phase 2 once K Phase-1 contribs have arrived.
// Derive tx_root + delay_seed (from the K commits) and a placeholder
// delay_output = SHA256(delay_seed). The block's final delay_output is
// recomputed from the revealed Phase-2 secrets via compute_block_rand
// (rev.9 S-009 commit-reveal); this placeholder only matters as a
// per-round identifier in BlockSigMsg.
//
// The actual phase change + sig broadcast is deferred via asio::post.
// This breaks the synchronous call chain on M=K=1 chains where
// finalize_round → apply_block → check_if_selected → start_contrib
// would otherwise recurse without bound.
void Node::enter_block_sig_phase() {
    if (phase_ != ConsensusPhase::CONTRIB) return;
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

    Hash placeholder = crypto::sha256(current_delay_seed_);
    asio::post(io_, [this, placeholder] {
        std::unique_lock<std::shared_mutex> lk(state_mutex_);
        if (phase_ != ConsensusPhase::CONTRIB) return;
        start_block_sig_phase(placeholder);

        // Replay any block_sigs that arrived before this transition.
        auto buffered = std::move(buffered_block_sigs_);
        buffered_block_sigs_.clear();
        for (auto& m : buffered) on_block_sig_locked(m);
    });
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
    std::vector<chain::CrossShardReceipt> inbound_snapshot;
    inbound_snapshot.reserve(pending_inbound_receipts_.size());
    for (auto& kv : pending_inbound_receipts_) inbound_snapshot.push_back(kv.second);
    chain::Block tentative = build_body(tx_store_, chain_, current_aborts_,
                                         current_creator_domains_,
                                         ordered_contribs, delay_output,
                                         cfg_.m_creators, mode, proposer,
                                         pending_equivocation_evidence_,
                                         inbound_snapshot);

    // v2.1 / S-033 activation: populate state_root from the post-apply
    // state. Dry-run apply on a Chain copy to compute the commitment
    // without mutating the live chain. Other K committee members
    // perform the same computation and either agree (matching root)
    // or fail apply-time verification (different root → throw). The
    // root is bound into compute_hash (via signing_bytes when non-zero),
    // so the next block's prev_hash transitively authenticates this
    // state commitment.
    //
    // Cost: O(state size) — bounded by the same primitive that closes
    // S-032 (chain.compute_state_root reads cached fields where
    // available). The Chain copy is bounded by std::map heap allocation
    // for the four primary state maps. A future v2.4 overlay/delta
    // model removes the copy by computing state_root from the apply
    // overlay directly.
    {
        chain::Chain tentative_chain = chain_;
        // Chain::append() runs apply_transactions internally. It also
        // checks prev_hash consistency, which matches what the real
        // apply would check. tentative.state_root is zero at this
        // point, so the state_root verification inside apply_transactions
        // short-circuits (zero == zero is the "not set" path).
        tentative_chain.append(tentative);
        tentative.state_root = tentative_chain.compute_state_root();
    }
    Hash digest = compute_block_digest(tentative);

    BlockSigMsg my_sig = make_block_sig(key_, cfg_.domain,
                                         tentative.index,
                                         delay_output, digest,
                                         current_round_secret_);
    pending_block_sigs_[cfg_.domain] = my_sig;
    pending_secrets_[cfg_.domain]    = current_round_secret_;
    gossip_.broadcast(net::make_block_sig(my_sig));

    block_sig_timer_.expires_after(std::chrono::milliseconds(cfg_.block_sig_ms));
    block_sig_timer_.async_wait([this](std::error_code ec) {
        if (ec) return;
        std::unique_lock<std::shared_mutex> lk(state_mutex_);
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

    std::vector<chain::CrossShardReceipt> inbound_snapshot;
    inbound_snapshot.reserve(pending_inbound_receipts_.size());
    for (auto& kv : pending_inbound_receipts_) inbound_snapshot.push_back(kv.second);

    // rev.9 S-009: gather K revealed secrets in committee selection order.
    // build_body uses these to populate creator_dh_secrets and recompute
    // delay_output via compute_block_rand. We require all K secrets here
    // (in MD mode); in BFT mode missing positions are filled with zero
    // sentinels, but the proposer's secret (and all signers' secrets)
    // must be present so the delay_output binds.
    std::vector<Hash> ordered_secrets(current_creator_domains_.size(), Hash{});
    for (size_t i = 0; i < current_creator_domains_.size(); ++i) {
        auto sit = pending_secrets_.find(current_creator_domains_[i]);
        if (sit != pending_secrets_.end()) ordered_secrets[i] = sit->second;
    }

    chain::Block body = build_body(tx_store_, chain_, current_aborts_,
                                    current_creator_domains_,
                                    ordered_contribs,
                                    current_delay_output_,
                                    cfg_.m_creators, mode, proposer,
                                    pending_equivocation_evidence_,
                                    inbound_snapshot,
                                    ordered_secrets);
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
    std::unique_lock<std::shared_mutex> lk(state_mutex_);

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
    std::unique_lock<std::shared_mutex> lk(state_mutex_);

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
    std::unique_lock<std::shared_mutex> lk(state_mutex_);

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
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
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
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
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
    // R2: filter pool by this shard's committee_region (from manifest).
    // Missing entry / empty manifest yields region == "" which
    // eligible_in_region treats as "full pool" — preserves CURRENT-mode
    // backward-compat where every shard is global.
    std::string shard_region;
    {
        auto it = shard_committee_regions_.find(shard_id);
        if (it != shard_committee_regions_.end()) shard_region = it->second;
    }
    auto pool_nodes = beacon_reg.eligible_in_region(shard_region);

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

// rev.9 B3.3: cross-shard receipt bundle handler.
//   * BEACON: relay (re-broadcast to all peers); does not apply.
//   * SHARD: filter src_block.cross_shard_receipts to those addressed
//     to this shard, dedupe against pending_inbound_receipts_, store.
//   * SINGLE: ignore.
// Full K-of-K verification of the source block against the source-
// shard committee is deferred to B3.4 (where the destination producer
// bakes verified receipts into a block and apply credits `to`). For
// B3.3 the receipt is held in pending_inbound_receipts_ as untrusted
// transit data — it doesn't affect any state until B3.4 verifies +
// credits.
void Node::on_cross_shard_receipt_bundle(ShardId src_shard,
                                            const chain::Block& src_block,
                                            const net::Message& relay) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);

    if (cfg_.chain_role == ChainRole::BEACON) {
        // Relay: re-broadcast to peers other than the sender. The
        // existing GossipNet::broadcast hits all peers; loop avoidance
        // here is best-effort (peers de-dupe at apply by tx_hash key).
        gossip_.broadcast(relay);
        return;
    }
    if (cfg_.chain_role != ChainRole::SHARD) return;

    // Don't ingest our own emitted bundle.
    if (src_shard == cfg_.shard_id) return;

    size_t added = 0;
    for (auto& r : src_block.cross_shard_receipts) {
        if (r.dst_shard != cfg_.shard_id) continue;
        if (r.src_shard != src_shard)     continue;     // sanity
        auto key = std::make_pair(r.src_shard, r.tx_hash);
        if (pending_inbound_receipts_.count(key)) continue;     // already buffered
        pending_inbound_receipts_[key] = r;
        ++added;
    }
    if (added > 0) {
        std::cout << "[node] inbound receipt bundle: src_shard=" << src_shard
                  << " block=" << src_block.index
                  << " accepted=" << added
                  << " pending_total=" << pending_inbound_receipts_.size() << "\n";
    }
}

// rev.9 B6.basic: serve a snapshot to a requesting peer. Empty chains
// silently skip (nothing useful to send). Otherwise build the snapshot
// via Chain::serialize_state and reply directly to the requester.
void Node::on_snapshot_request(uint32_t header_count,
                                  std::shared_ptr<net::Peer> peer) {
    nlohmann::json snap;
    {
        std::unique_lock<std::shared_mutex> lk(state_mutex_);
        if (chain_.empty()) return;     // nothing to serve
        snap = chain_.serialize_state(header_count);
    }
    if (peer) peer->send(net::make_snapshot_response(snap));
    std::cout << "[node] served snapshot to peer "
              << (peer ? peer->address() : std::string("?"))
              << " (block_index=" << snap.value("block_index", uint64_t{0})
              << ")\n";
}

void Node::reset_round() {
    pending_contribs_.clear();
    contrib_equivocations_.clear();
    pending_block_sigs_.clear();
    buffered_block_sigs_.clear();
    pending_claims_.clear();
    pending_secrets_.clear();
    current_round_secret_ = Hash{};
    current_tx_root_     = Hash{};
    current_delay_seed_  = Hash{};
    current_delay_output_= Hash{};
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
    // rev.9 B3.4: prune inbound receipts that this block credited.
    // Apply (above) already inserted into chain.applied_inbound_receipts_;
    // here we drop the matching pending entries so the producer doesn't
    // re-propose them next round. The on-chain dedup set is canonical;
    // pending is just a fast path for inclusion.
    for (auto& r : b.inbound_receipts) {
        pending_inbound_receipts_.erase({r.src_shard, r.tx_hash});
    }
    // A9 / S-031 follow-on: async chain.save off the hot path.
    // Previously: chain_.save(cfg_.chain_path) ran synchronously under
    // state_mutex_'s unique_lock, blocking the next apply on the
    // disk-write duration (O(N) JSON serialize + fsync per block).
    // Now: enqueue_save sets save_pending_ and notifies; the worker
    // thread does the serialize+write under shared_lock (concurrent
    // with RPC readers). Apply hot path returns immediately. Crash
    // window between apply and save is recovered via peer gossip
    // on restart — same correctness as pre-fix.
    enqueue_save();

    std::cout << "[node] accepted block #" << b.index
              << " creators=" << b.creators.size() << "\n";

    // rev.9 B5: epoch boundary observability. When this block opens a
    // new epoch (height % epoch_blocks == 1, since the epoch's "rand
    // anchor" is the block at index = epoch_index * epoch_blocks - 1
    // and committee selection at the next round reads it), log the
    // transition + the freshly-derived committee. Operators can use
    // this to trace rotation.
    if (cfg_.epoch_blocks > 0
        && chain_.height() > 0
        && (chain_.height() - 1) % cfg_.epoch_blocks == 0
        && chain_.height() > 1) {
        EpochIndex new_epoch = current_epoch_index();
        size_t pool_size = NodeRegistry::build_from_chain(
                                chain_, chain_.height()).size();
        std::cout << "[node] epoch boundary: epoch_index=" << new_epoch
                  << " pool_size=" << pool_size
                  << " (next-round committee will derive from this height's rand)\n";
    }

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
        // rev.9 B3.3: emit cross-shard receipts bundle when the block
        // produced any outbound receipts. Beacon peers relay the
        // bundle to other shards; destination shards filter on
        // dst_shard == my_shard_id and queue inbound receipts for
        // B3.4 (apply-side credit).
        if (!b.cross_shard_receipts.empty()) {
            gossip_.broadcast(
                net::make_cross_shard_receipt_bundle(cfg_.shard_id, b));
        }
    }

    check_if_selected();
}

void Node::on_block(const chain::Block& b) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
    apply_block_locked(b);
}

// S-002 mitigation: cheap forgery check at mempool-admission time.
// Mirrors the validator's per-tx signature verification in
// check_transactions but does ONLY the sig check — full validation
// (charset, payload-size bounds, type-specific rules) still happens
// at block apply. The intent is to reject obvious forgeries before
// they consume mempool slots or amplify through gossip.
//
// Dependency: this only works correctly when src/net/binary_codec.cpp's
// decode_tx_frame preserves amount/fee/nonce — see the comment in
// binary_codec.cpp and docs/proofs/S002-Mempool-Sig-Verify.md.
bool Node::verify_tx_signature_locked(const chain::Transaction& tx) const {
    using namespace determ::crypto;
    using namespace determ::chain;
    PubKey pk{};
    const bool from_anon = is_anon_address(tx.from);
    if (tx.type == TxType::REGISTER) {
        if (from_anon) return false;
        if (tx.payload.size() < 32) return false;
        std::copy_n(tx.payload.begin(), 32, pk.begin());
    } else if (from_anon) {
        if (tx.type != TxType::TRANSFER) return false;
        pk = parse_anon_pubkey(tx.from);
    } else {
        auto& regs = chain_.registrants();
        auto it = regs.find(tx.from);
        if (it == regs.end()) return false;
        pk = it->second.ed_pub;
    }
    auto sb = tx.signing_bytes();
    return verify(pk, sb.data(), sb.size(), tx.sig);
}

// S-008 helpers (mempool admission policy).
//
// mempool_count_from: count tx_by_account_nonce_ entries whose key.first
// matches `sender`. std::map iterates in sorted key order; lower_bound at
// (sender, 0) gives the start of the sender's range. Stop when key.first
// changes. Linear in per-sender count (bounded by MEMPOOL_MAX_PER_SENDER).
size_t Node::mempool_count_from(const std::string& sender) const {
    size_t count = 0;
    auto it = tx_by_account_nonce_.lower_bound({sender, 0});
    while (it != tx_by_account_nonce_.end() && it->first.first == sender) {
        ++count;
        ++it;
    }
    return count;
}

// mempool_admit_check: shared S-008 admission gate. Returns "" on accept,
// non-empty error string on reject. Called by both on_tx (gossip path) and
// rpc_submit_tx (RPC path) so the policy is the same regardless of channel.
//
// Order of checks:
//   1. Per-sender quota (cheapest, bounded scan).
//   2. Global cap + eviction feasibility (most expensive; only run if
//      sender-quota passes).
std::string Node::mempool_admit_check(const chain::Transaction& tx) const {
    // Check if this tx would REPLACE an existing one at (from, nonce).
    // A replace doesn't add to the mempool count — same slot, same sender.
    auto existing_it = tx_by_account_nonce_.find({tx.from, tx.nonce});
    bool is_replace = (existing_it != tx_by_account_nonce_.end());

    if (!is_replace) {
        // Per-sender quota.
        size_t sender_count = mempool_count_from(tx.from);
        if (sender_count >= MEMPOOL_MAX_PER_SENDER) {
            return "mempool: per-sender quota exceeded ("
                 + std::to_string(MEMPOOL_MAX_PER_SENDER)
                 + " txs from " + tx.from + ")";
        }
        // Global cap. Eviction is feasible only if tx.fee > current
        // mempool minimum. Don't enforce at admission — the eviction
        // step happens INSIDE the insert path (mempool_make_room_for).
        // Here we just check that admission is even possible: if cap
        // is hit AND tx.fee <= mempool min, reject early.
        if (tx_store_.size() >= MEMPOOL_MAX_TXS) {
            // Scan for current minimum fee.
            uint64_t min_fee = UINT64_MAX;
            for (auto& [_, t] : tx_store_) {
                if (t.fee < min_fee) min_fee = t.fee;
            }
            if (tx.fee <= min_fee) {
                return "mempool: full ("
                     + std::to_string(MEMPOOL_MAX_TXS)
                     + " txs); incoming fee " + std::to_string(tx.fee)
                     + " <= mempool minimum " + std::to_string(min_fee);
            }
        }
    }
    return "";
}

// mempool_make_room_for: evict the lowest-fee tx if mempool is at cap.
// Returns true if room is available (no cap hit, or eviction happened);
// false if cap hit AND incoming tx's fee isn't high enough to displace
// anything. Caller rejects the tx if this returns false.
bool Node::mempool_make_room_for(const chain::Transaction& tx) {
    if (tx_store_.size() < MEMPOOL_MAX_TXS) return true;
    // Find lowest-fee tx. Tie-broken by hash (deterministic across nodes).
    auto min_it = tx_store_.end();
    for (auto it = tx_store_.begin(); it != tx_store_.end(); ++it) {
        if (min_it == tx_store_.end() || it->second.fee < min_it->second.fee) {
            min_it = it;
        }
    }
    if (min_it == tx_store_.end()) return true; // shouldn't reach (size>=cap)
    if (tx.fee <= min_it->second.fee) return false; // can't displace
    // Evict the minimum.
    auto evicted_key = std::make_pair(min_it->second.from, min_it->second.nonce);
    tx_store_.erase(min_it);
    tx_by_account_nonce_.erase(evicted_key);
    return true;
}

void Node::on_tx(const chain::Transaction& tx) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);

    // Drop stale-nonce txs immediately.
    if (tx.nonce < chain_.next_nonce(tx.from)) return;

    // S-002: verify signature before admitting to mempool. Silent drop
    // on the gossip path — a forged-sig flood from any peer would
    // otherwise consume mempool slots and amplify to other peers.
    if (!verify_tx_signature_locked(tx)) return;

    // S-008: enforce mempool size cap + per-sender quota. Silent drop
    // on the gossip path (a flood from N senders gets rate-limited
    // without amplifying the attacker's traffic; the rejected tx
    // doesn't propagate further).
    if (!mempool_admit_check(tx).empty()) return;

    auto key = std::make_pair(tx.from, tx.nonce);
    auto idx = tx_by_account_nonce_.find(key);
    if (idx != tx_by_account_nonce_.end()) {
        // Replace-by-fee: keep the higher-fee version.
        auto existing = tx_store_.find(idx->second);
        if (existing != tx_store_.end() && existing->second.fee >= tx.fee) {
            return; // incumbent wins (ties favor incumbent — no resource churn)
        }
        if (existing != tx_store_.end()) tx_store_.erase(existing);
    } else {
        // Fresh slot — check eviction feasibility for the global cap.
        // mempool_admit_check already verified eviction is possible
        // (tx.fee > current min), but the actual eviction happens here
        // atomically with the insert.
        if (!mempool_make_room_for(tx)) return;
    }
    tx_store_[tx.hash] = tx;
    tx_by_account_nonce_[key] = tx.hash;
}

void Node::on_contrib(const ContribMsg& msg) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);

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
    // Instead, we accept any signer that's in the registry. enter_block_sig_phase
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
    // BLOCK_SIG), the round is locked-in and stale messages shouldn't reach
    // here anyway.
    auto existing = pending_contribs_.find(msg.signer);
    if (existing != pending_contribs_.end()) return;

    pending_contribs_[msg.signer] = msg;

    if (phase_ == ConsensusPhase::CONTRIB &&
        pending_contribs_.size() == current_creator_domains_.size())
        enter_block_sig_phase();
}

void Node::on_block_sig(const BlockSigMsg& msg) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
    on_block_sig_locked(msg);
}

void Node::on_block_sig_locked(const BlockSigMsg& msg) {
    // Caller must hold state_mutex_. Used both from gossip dispatch (via
    // on_block_sig wrapper) and from enter_block_sig_phase when replaying
    // buffered messages.
    uint64_t expected_index = chain_.height();
    if (msg.block_index != expected_index) return;

    if (std::find(current_creator_domains_.begin(),
                  current_creator_domains_.end(), msg.signer)
        == current_creator_domains_.end()) return;

    auto entry = registry_.find(msg.signer);
    if (!entry) return;

    // If we haven't reached BLOCK_SIG yet, buffer for replay.
    if (phase_ != ConsensusPhase::BLOCK_SIG) {
        buffered_block_sigs_.push_back(msg);
        return;
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
    std::vector<chain::CrossShardReceipt> inbound_snapshot;
    inbound_snapshot.reserve(pending_inbound_receipts_.size());
    for (auto& kv : pending_inbound_receipts_) inbound_snapshot.push_back(kv.second);
    chain::Block tentative = build_body(tx_store_, chain_, current_aborts_,
                                         current_creator_domains_,
                                         ordered_contribs,
                                         current_delay_output_,
                                         cfg_.m_creators, mode_local, proposer_local,
                                         pending_equivocation_evidence_,
                                         inbound_snapshot);
    Hash digest = compute_block_digest(tentative);

    if (!crypto::verify(entry->pubkey, digest.data(), digest.size(), msg.ed_sig)) {
        std::cerr << "[node] invalid BlockSig from " << msg.signer << "\n";
        return;
    }

    // rev.9 S-009: verify the revealed secret against the signer's
    // Phase-1 commit (carried in pending_contribs_[signer].dh_input).
    auto cit = pending_contribs_.find(msg.signer);
    if (cit == pending_contribs_.end()) {
        // No commit yet — buffer for later (the contrib may be in flight).
        buffered_block_sigs_.push_back(msg);
        return;
    }
    Hash expected_commit = crypto::SHA256Builder{}
        .append(msg.dh_secret)
        .append(entry->pubkey.data(), entry->pubkey.size())
        .finalize();
    if (expected_commit != cit->second.dh_input) {
        std::cerr << "[node] BlockSig dh_secret/commit mismatch from "
                  << msg.signer << "\n";
        return;
    }

    pending_block_sigs_[msg.signer] = msg;
    pending_secrets_[msg.signer]    = msg.dh_secret;

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
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
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
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
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
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
    std::string ghash = chain_.empty() ? std::string{} : to_hex(chain_.at(0).compute_hash());
    peer->send(net::make_status_response(chain_.height(), ghash));
}

void Node::on_status_response(uint64_t height, const std::string& genesis_hash,
                               std::shared_ptr<net::Peer> peer) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);

    // Reject peers on a different genesis. Their chain is not ours; they will
    // never feed us valid blocks. But STILL fall through to
    // start_sync_if_behind() — without it, a node whose only peers are
    // cross-chain (BEACON ↔ SHARD via beacon_peers/shard_peers) would
    // never transition to IN_SYNC and never start producing. Different-
    // genesis peers simply don't contribute to peer_heights_ so the
    // sync-height comparison correctly ignores them.
    if (!chain_.empty()) {
        std::string ours = to_hex(chain_.at(0).compute_hash());
        if (!genesis_hash.empty() && genesis_hash != ours) {
            std::cerr << "[node] peer " << peer->address()
                      << " on different genesis (" << genesis_hash
                      << ", ours " << ours << "); ignoring for sync\n";
            start_sync_if_behind();
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
    std::shared_lock<std::shared_mutex> lk(state_mutex_);
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
    j["pending_inbound_receipts"] = pending_inbound_receipts_.size(); // shard-only

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

    // rev.9 R2: status preview of "next_creators" must mirror the same
    // region-filtered pool that check_if_selected operates on.
    auto nodes = registry_.eligible_in_region(cfg_.committee_region);
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
    std::shared_lock<std::shared_mutex> lk(state_mutex_);
    if (index >= chain_.height()) return nullptr;
    return chain_.at(index).to_json();
}

json Node::rpc_account(const std::string& addr) const {
    // A9 Phase 2C-Node bundled path. Grab the committed view ONCE
    // and read all four fields (balance, next_nonce, stake,
    // registrant) from the same bundle. All four reads are
    // guaranteed cross-container atomic — they come from the same
    // commit, no straddling. Lock-free: no state_mutex_ acquisition.
    // The shared_ptr keeps the bundle alive for the duration of
    // this function; the writer's next commit publishes a fresh
    // bundle but does not disturb our view.
    auto view = chain_.committed_state_view();

    json j;
    j["address"] = addr;

    // Bearer-wallet anonymous addresses surface as their pubkey-derived
    // address; show that fact for the explorer.
    j["is_anonymous"] = is_anon_address(addr);

    uint64_t balance    = 0;
    uint64_t next_nonce = 0;
    uint64_t stake      = 0;
    std::optional<chain::RegistryEntry> reg_entry;

    if (view) {
        auto ait = view->accounts.find(addr);
        if (ait != view->accounts.end()) {
            balance    = ait->second.balance;
            next_nonce = ait->second.next_nonce;
        }
        auto sit = view->stakes.find(addr);
        if (sit != view->stakes.end()) {
            stake = sit->second.locked;
        }
        auto rit = view->registrants.find(addr);
        if (rit != view->registrants.end()) {
            reg_entry = rit->second;
        }
    }

    j["balance"]    = balance;
    j["next_nonce"] = next_nonce;

    if (reg_entry) {
        json r;
        r["ed_pub"]        = to_hex(reg_entry->ed_pub);
        r["registered_at"] = reg_entry->registered_at;
        r["active_from"]   = reg_entry->active_from;
        r["inactive_from"] = reg_entry->inactive_from;
        j["registry"] = r;
        j["stake"]    = stake;
    } else {
        j["registry"] = nullptr;
        j["stake"]    = stake;    // 0 if not staked
    }

    // Aggregate visibility: has this address ever appeared on-chain?
    bool has_state = (balance > 0)
                  || (next_nonce > 0)
                  || reg_entry.has_value();
    if (!has_state) return nullptr;
    return j;
}

json Node::rpc_tx(const std::string& hash_hex) const {
    std::shared_lock<std::shared_mutex> lk(state_mutex_);
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

json Node::rpc_committee() const {
    std::shared_lock<std::shared_mutex> lk(state_mutex_);
    json arr = json::array();
    if (chain_.empty()) return arr;

    auto reg = NodeRegistry::build_from_chain(chain_, chain_.height());
    // rev.9 R2: rpc_committee must mirror check_if_selected's pool so
    // the displayed committee matches what producers actually run.
    auto pool = reg.eligible_in_region(cfg_.committee_region);
    if (pool.empty()) return arr;

    // Mirror check_if_selected's seed derivation so the result matches
    // what producers actually use this round (modulo abort_events which
    // only enter once a round has had aborts).
    Hash epoch_rand = current_epoch_rand();
    Hash rand = crypto::epoch_committee_seed(epoch_rand, cfg_.shard_id);

    size_t k = std::min<size_t>(cfg_.k_block_sigs, pool.size());
    if (k == 0) return arr;

    std::vector<size_t> indices;
    try {
        indices = crypto::select_m_creators(rand, pool.size(), k);
    } catch (...) { return arr; }

    for (size_t idx : indices) {
        const auto& nd = pool[idx];
        json e;
        e["domain"]      = nd.domain;
        e["ed_pub"]      = to_hex(nd.pubkey);
        e["active_from"] = nd.active_from;
        e["stake"]       = chain_.stake(nd.domain);
        arr.push_back(e);
    }
    return arr;
}

json Node::rpc_validators() const {
    std::shared_lock<std::shared_mutex> lk(state_mutex_);
    json arr = json::array();
    auto reg = NodeRegistry::build_from_chain(chain_, chain_.height());
    for (auto& nd : reg.sorted_nodes()) {
        json e;
        e["domain"]       = nd.domain;
        e["ed_pub"]       = to_hex(nd.pubkey);
        e["active_from"]  = nd.active_from;
        e["registered_at"]= nd.registered_at;
        e["stake"]        = chain_.stake(nd.domain);
        e["region"]       = nd.region; // rev.9 R1
        arr.push_back(e);
    }
    return arr;
}

json Node::rpc_chain_summary(uint32_t last_n) const {
    std::shared_lock<std::shared_mutex> lk(state_mutex_);
    json arr = json::array();
    uint64_t total = chain_.height();
    if (total > 0) {
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
    }
    // A1: surface the unitary-balance invariant. `total_supply` is the
    // live walk over accounts.balance + stakes.locked; the four delta
    // counters break down how it diverges from genesis_total. Useful as
    // a single-RPC sanity probe in regression tests: total_supply must
    // equal expected_total at the head of every applied block, and
    // total_supply == genesis_total + accumulated_subsidy + accumulated_inbound
    //   - accumulated_slashed - accumulated_outbound is the same equality.
    json out;
    out["blocks"]               = arr;
    out["height"]               = total;
    out["total_supply"]         = chain_.live_total_supply();
    out["genesis_total"]        = chain_.genesis_total();
    out["expected_total"]       = chain_.expected_total();
    out["accumulated_subsidy"]  = chain_.accumulated_subsidy();
    out["accumulated_slashed"]  = chain_.accumulated_slashed();
    out["accumulated_inbound"]  = chain_.accumulated_inbound();
    out["accumulated_outbound"] = chain_.accumulated_outbound();
    return out;
}

json Node::rpc_send(const std::string& to, uint64_t amount, uint64_t fee) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
    // S-023: balance pre-check. The chain's apply path silently drops
    // (continues the tx loop) if balance < amount + fee — the user
    // would otherwise get "queued" but their tx would never debit.
    // Surface the rejection upfront so the client knows to top up or
    // adjust the amount before submitting.
    uint64_t cost = amount + fee;
    uint64_t bal  = chain_.balance(cfg_.domain);
    if (bal < cost) {
        throw std::runtime_error(
            "insufficient balance: have " + std::to_string(bal)
          + ", need " + std::to_string(cost)
          + " (amount " + std::to_string(amount)
          + " + fee " + std::to_string(fee) + ")");
    }
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
    // v2.6 / S-031 polish: release state_mutex_ before broadcast.
    lk.unlock();
    gossip_.broadcast(net::make_transaction(tx));
    return {{"status", "queued"}, {"hash", to_hex(tx.hash)}};
}

static std::vector<uint8_t> encode_amount(uint64_t a) {
    std::vector<uint8_t> v(8);
    for (int i = 0; i < 8; ++i) v[i] = (a >> (8 * i)) & 0xFF;
    return v;
}

json Node::rpc_stake(uint64_t amount, uint64_t fee) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
    // S-023: balance pre-check. STAKE locks `amount` from balance AND
    // pays `fee` from balance; total deducted = amount + fee.
    uint64_t cost = amount + fee;
    uint64_t bal  = chain_.balance(cfg_.domain);
    if (bal < cost) {
        throw std::runtime_error(
            "insufficient balance: have " + std::to_string(bal)
          + ", need " + std::to_string(cost)
          + " (stake-amount " + std::to_string(amount)
          + " + fee " + std::to_string(fee) + ")");
    }
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
    // v2.6 / S-031 polish: release state_mutex_ before broadcast.
    lk.unlock();
    gossip_.broadcast(net::make_transaction(tx));
    return {{"status", "queued"}, {"hash", to_hex(tx.hash)}, {"locked_increment", amount}};
}

json Node::rpc_unstake(uint64_t amount, uint64_t fee) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
    // S-023: pre-check both balance (for fee) AND locked stake (for
    // the unstake amount). UNSTAKE only pays fee from balance; it
    // RETURNS `amount` from stake back to balance. So bal >= fee
    // suffices for the cost side, but stake >= amount must hold for
    // the amount side. Also check unlock_height ≤ current chain
    // height: an UNSTAKE before the unlock window is rejected by the
    // chain's apply path (fee refunded) but it's friendlier to fail
    // upfront.
    uint64_t bal = chain_.balance(cfg_.domain);
    if (bal < fee) {
        throw std::runtime_error(
            "insufficient balance for fee: have " + std::to_string(bal)
          + ", fee " + std::to_string(fee));
    }
    uint64_t locked = chain_.stake(cfg_.domain);
    if (locked < amount) {
        throw std::runtime_error(
            "insufficient stake to unlock: locked " + std::to_string(locked)
          + ", attempting to unstake " + std::to_string(amount));
    }
    uint64_t unlock_h = chain_.stake_unlock_height(cfg_.domain);
    if (chain_.height() < unlock_h) {
        throw std::runtime_error(
            "stake still locked: current height " + std::to_string(chain_.height())
          + ", unlock_height " + std::to_string(unlock_h));
    }
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
    // v2.6 / S-031 polish: release state_mutex_ before broadcast.
    lk.unlock();
    gossip_.broadcast(net::make_transaction(tx));
    return {{"status", "queued"}, {"hash", to_hex(tx.hash)}, {"unlock_at", chain_.stake_unlock_height(cfg_.domain)}};
}

json Node::rpc_nonce(const std::string& domain) const {
    // A9 Phase 2C-Node: lock-free read path. balance_lockfree /
    // next_nonce_lockfree atomic-load the committed accounts view
    // published at the last successful apply commit. No state_mutex_
    // acquisition needed — the call doesn't block on the writer's
    // unique_lock during apply. RPC clients querying nonce while a
    // block applies see the prior committed state (correct semantics:
    // the in-progress apply isn't finalized yet). Throughput on the
    // hot RPC paths is no longer gated on apply duration.
    return {{"domain", domain}, {"next_nonce", chain_.next_nonce_lockfree(domain)}};
}

json Node::rpc_stake_info(const std::string& domain) const {
    // A9 Phase 2C-Node: lock-free read path for stakes. See rpc_balance
    // / rpc_nonce above. The two atomic_loads (one per lockfree call)
    // are independent — they may return shared_ptrs from different
    // commit cycles. For rpc_stake_info this is fine: locked and
    // unlock_height come from the SAME StakeEntry inside one shared_ptr
    // load, so the per-call view is internally consistent even though
    // the two calls may straddle a commit boundary.
    return {
        {"domain",        domain},
        {"locked",        chain_.stake_lockfree(domain)},
        {"unlock_height", chain_.stake_unlock_height_lockfree(domain)}
    };
}

// v2.18/v2.19 Theme 7: DApp registry queries.
//
// v2.18 Phase 7.3: lock-free read path. dapp_lockfree atomic-loads
// the bundled CommittedStateBundle (Phase 2C extension) and reads
// dapp_registry from it. No state_mutex_ acquisition needed — these
// RPC paths don't block on apply's writer lock. dapp-discovery
// queries from wallets, light clients, and explorer tooling are now
// genuinely concurrent with consensus.
json Node::rpc_dapp_info(const std::string& domain) const {
    auto entry = chain_.dapp_lockfree(domain);
    if (!entry) {
        return {{"error", "not_found"}, {"domain", domain}};
    }

    json topics = json::array();
    for (auto& t : entry->topics) topics.push_back(t);

    return {
        {"domain",         domain},
        {"service_pubkey", to_hex(entry->service_pubkey)},
        {"endpoint_url",   entry->endpoint_url},
        {"topics",         topics},
        {"retention",      entry->retention},
        {"metadata",       to_hex(entry->metadata.data(), entry->metadata.size())},
        {"registered_at",  entry->registered_at},
        {"active_from",    entry->active_from},
        {"inactive_from",  entry->inactive_from},
        {"height",         chain_.height()},
    };
}

// v2.19 Theme 7 Phase 7.4 (polling subset): scan blocks for DAPP_CALL
// events addressed to a DApp. DApp nodes poll this every N seconds
// from their last-processed height; chain replies with all events in
// the requested window. Streaming subscription is a future follow-on.
//
// Lock semantics: holds state_mutex_'s shared_lock for the block-
// iteration (blocks_ is mutated by Chain::append; reading
// concurrently with apply is unsafe without the lock). The lock IS
// shared so other readers proceed; only the next apply's writer-lock
// acquire waits.
//
// Pagination: at most DAPP_MESSAGES_PAGE_LIMIT events per call. If
// the filter window has more, caller bumps from_height to one past
// the last returned block_height and re-queries.
namespace {
constexpr size_t DAPP_MESSAGES_PAGE_LIMIT = 256;
} // namespace

json Node::rpc_dapp_messages(const std::string& domain,
                                uint64_t           from_height,
                                uint64_t           to_height,
                                const std::string& topic) const {
    std::shared_lock<std::shared_mutex> lk(state_mutex_);
    uint64_t head = chain_.height();
    if (to_height == 0 || to_height > head) to_height = head;
    json events = json::array();
    bool truncated = false;
    uint64_t last_scanned = from_height;
    for (uint64_t h = from_height; h < to_height; ++h) {
        const auto& b = chain_.at(h);
        for (auto& tx : b.transactions) {
            if (tx.type != chain::TxType::DAPP_CALL) continue;
            if (tx.to != domain) continue;
            // Optional topic filter: decode the payload header
            // ([topic_len:u8][topic][ct_len:u32 LE][ct]).
            std::string tx_topic;
            if (!tx.payload.empty()) {
                uint8_t tl = tx.payload[0];
                if (size_t(1) + tl <= tx.payload.size()) {
                    tx_topic.assign(
                        reinterpret_cast<const char*>(tx.payload.data() + 1), tl);
                }
            }
            if (!topic.empty() && tx_topic != topic) continue;
            events.push_back({
                {"block_height", h},
                {"tx_hash",      to_hex(tx.hash)},
                {"from",         tx.from},
                {"to",           tx.to},
                {"amount",       tx.amount},
                {"fee",          tx.fee},
                {"nonce",        tx.nonce},
                {"topic",        tx_topic},
                {"payload_hex",  to_hex(tx.payload.data(), tx.payload.size())},
            });
            if (events.size() >= DAPP_MESSAGES_PAGE_LIMIT) {
                truncated = true;
                break;
            }
        }
        last_scanned = h;
        if (truncated) break;
    }
    return {
        {"domain",       domain},
        {"from_height",  from_height},
        {"to_height",    to_height},
        {"last_scanned", last_scanned},
        {"truncated",    truncated},
        {"count",        events.size()},
        {"events",       events},
    };
}

json Node::rpc_dapp_list(const std::string& prefix,
                            const std::string& topic) const {
    // Lock-free via the committed bundle. Single atomic_load yields a
    // shared_ptr that keeps the snapshot alive for the iteration —
    // even if the writer publishes new bundles during the loop, we
    // see a consistent snapshot.
    auto view = chain_.committed_state_view();
    json out = json::array();
    uint64_t h = chain_.height();
    if (!view) return {{"height", h}, {"count", 0}, {"dapps", out}};
    for (auto& [domain, entry] : view->dapp_registry) {
        // Filter: prefix match (empty prefix matches all)
        if (!prefix.empty() &&
            domain.size() < prefix.size()) continue;
        if (!prefix.empty() &&
            domain.compare(0, prefix.size(), prefix) != 0) continue;
        // Filter: topic match (empty topic matches all)
        if (!topic.empty()) {
            bool found = false;
            for (auto& t : entry.topics) {
                if (t == topic) { found = true; break; }
            }
            if (!found) continue;
        }
        // Compact summary — full entry comes from rpc_dapp_info.
        json topics_json = json::array();
        for (auto& t : entry.topics) topics_json.push_back(t);
        out.push_back({
            {"domain",       domain},
            {"endpoint_url", entry.endpoint_url},
            {"topics",       topics_json},
            {"active",       entry.inactive_from > h},
        });
    }
    return {{"height", h}, {"count", out.size()}, {"dapps", out}};
}

json Node::rpc_submit_tx(const json& tx_json) {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
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

    // S-002: verify signature before admitting to mempool. Surface as
    // a hard error to the submitting client (RPC callers get feedback;
    // unlike a faceless gossip peer, the client can correct and retry).
    if (!verify_tx_signature_locked(tx))
        throw std::runtime_error(
            "submitted tx signature verification failed (from " + tx.from + ")");

    // S-008: enforce mempool admission policy. RPC path surfaces the
    // rejection reason to the client (vs gossip's silent drop) so the
    // submitter can decide whether to retry with a higher fee or
    // back off.
    if (auto err = mempool_admit_check(tx); !err.empty()) {
        throw std::runtime_error(err);
    }

    auto key = std::make_pair(tx.from, tx.nonce);
    auto idx = tx_by_account_nonce_.find(key);
    if (idx != tx_by_account_nonce_.end()) {
        auto existing = tx_store_.find(idx->second);
        if (existing != tx_store_.end() && existing->second.fee >= tx.fee)
            throw std::runtime_error(
                "incumbent tx at (from, nonce) has equal-or-higher fee");
        if (existing != tx_store_.end()) tx_store_.erase(existing);
    } else {
        // S-008: fresh-slot insert — apply eviction if at cap.
        if (!mempool_make_room_for(tx)) {
            throw std::runtime_error(
                "mempool full; fee too low to evict any incumbent tx");
        }
    }
    tx_store_[tx.hash] = tx;
    tx_by_account_nonce_[key] = tx.hash;
    // v2.6 / S-031 polish: release state_mutex_ BEFORE the gossip
    // broadcast. The tx is already in tx_store_ + tx_by_account_nonce_
    // by this point — peers receiving the broadcast will gossip-replay
    // through on_tx, which re-validates and re-inserts (idempotent
    // under replace-by-fee). The broadcast itself is a network op that
    // doesn't touch chain state; holding state_mutex_ across it
    // serialized all other state operations against network latency.
    lk.unlock();
    gossip_.broadcast(net::make_transaction(tx));
    return {{"status", "queued"}, {"hash", to_hex(tx.hash)}};
}

json Node::rpc_submit_equivocation(const json& ev_json) {
    auto ev = chain::EquivocationEvent::from_json(ev_json);

    // Reuse the gossip handler's validation + dedup + acceptance path:
    //   - rejects digest_a == digest_b
    //   - rejects sig_a == sig_b
    //   - rejects unregistered equivocator
    //   - verifies BOTH sigs against equivocator's pubkey
    //   - dedupes against pending pool
    // The handler grabs state_mutex_ itself.
    on_equivocation_evidence(ev);

    // Re-grab to inspect post-handler state for the response.
    std::unique_lock<std::shared_mutex> lk(state_mutex_);
    bool present = false;
    for (auto& e : pending_equivocation_evidence_) {
        if (e.equivocator == ev.equivocator
            && e.block_index == ev.block_index) { present = true; break; }
    }
    if (present) {
        // Gossip so peers can also slash. The handler doesn't broadcast
        // (it processes inbound), so we do it here on the submission path.
        gossip_.broadcast(net::make_equivocation_evidence(ev));
        return {{"accepted", true}, {"equivocator", ev.equivocator},
                {"block_index", ev.block_index}};
    }
    return {{"accepted", false},
            {"reason", "evidence rejected (invalid sigs, "
                       "unregistered equivocator, or duplicate)"}};
}

json Node::rpc_snapshot(uint32_t header_count) const {
    std::shared_lock<std::shared_mutex> lk(state_mutex_);
    return chain_.serialize_state(header_count);
}

json Node::rpc_balance(const std::string& domain) const {
    // A9 Phase 2C-Node: lock-free path. See rpc_nonce above for the
    // semantics — atomic_load of the committed accounts view, no
    // state_mutex_ acquisition. balance is one of the most-hammered
    // RPC paths (wallets poll it after every send); decoupling it
    // from apply's writer lock is a meaningful operational improvement.
    return {{"domain", domain}, {"balance", chain_.balance_lockfree(domain)}};
}

// S-033 / v2.1: query the chain's current cryptographic state commitment.
// Operators can call this against multiple nodes to detect silent state
// divergence (a real S-030 D1 / S-030 D2 attack would manifest as the
// same height but different state_root across nodes). Read-only via
// shared_lock — concurrent with other readers, blocked only by active
// writers.
json Node::rpc_state_root() const {
    std::shared_lock<std::shared_mutex> lk(state_mutex_);
    return {
        {"state_root", to_hex(chain_.compute_state_root())},
        {"height",     chain_.height()},
        {"head_hash",  chain_.empty() ? "" : to_hex(chain_.head_hash())},
    };
}

// v2.2 light-client foundation: inclusion proof RPC.
//
// Wire format: {
//   "key": "<hex>",                  // domain-prefixed key bytes
//   "value_hash": "<hex-32>",        // SHA-256 of the canonical value
//   "target_index": <number>,        // sorted-leaf position
//   "leaf_count": <number>,          // total leaves at this height
//   "proof": ["<hex-32>", ...],      // sibling hashes bottom-up
//   "state_root": "<hex-32>",        // recomputed at the same instant
//   "height": <number>               // current chain height
// }
//
// state_root and height are returned together so the light client can
// verify them against the (committee-signed) Block header at that
// height — if the header's state_root matches, the proof is honest.
// Returning {"error": "not_found"} if the key is absent from the
// current state. (Non-membership proofs require an SMT migration.)
json Node::rpc_state_proof(const std::string& ns,
                              const std::string& key) const {
    std::shared_lock<std::shared_mutex> lk(state_mutex_);

    // Build domain-prefixed key bytes matching build_state_leaves'
    // encoding. Only the simple namespaces (single byte prefix +
    // ASCII key) are exposed here; composite-key namespaces
    // (i/m/p) are out of scope for this RPC.
    std::vector<uint8_t> k;
    if (ns == "a" || ns == "s" || ns == "r" || ns == "b" || ns == "k") {
        // "a:" / "s:" / "r:" / "b:" / "k:" + key string
        k.reserve(2 + key.size());
        k.push_back(ns[0]);
        k.push_back(':');
        k.insert(k.end(), key.begin(), key.end());
    } else if (ns == "c") {
        // counters: "k:c:" + name (see build_state_leaves's const_leaf
        // calls for counters using "c:" prefix as the name)
        std::string composite = "c:" + key;
        k.reserve(2 + composite.size());
        k.push_back('k'); k.push_back(':');
        k.insert(k.end(), composite.begin(), composite.end());
    } else {
        return {{"error", "unsupported namespace; use a|s|r|b|k|c"}};
    }

    auto proof_opt = chain_.state_proof(k);
    if (!proof_opt) {
        return {{"error", "not_found"}, {"namespace", ns}, {"key", key}};
    }
    auto& p = *proof_opt;

    json proof_arr = json::array();
    for (auto& h : p.proof) proof_arr.push_back(to_hex(h));

    return {
        {"namespace",    ns},
        {"key",          key},
        {"key_bytes",    to_hex(p.key.data(), p.key.size())},
        {"value_hash",   to_hex(p.value_hash)},
        {"target_index", p.target_index},
        {"leaf_count",   p.leaf_count},
        {"proof",        proof_arr},
        {"state_root",   to_hex(chain_.compute_state_root())},
        {"height",       chain_.height()},
    };
}

json Node::rpc_register() {
    std::unique_lock<std::shared_mutex> lk(state_mutex_);

    // Payload (rev.9 R1): [pubkey: 32B][region_len: u8][region: utf8].
    // When cfg_.region is empty we emit only the 32-byte pubkey
    // (legacy / wire-compat path; old REGISTER txs replay byte-identical).
    // The tx's own Ed25519 sig (verified at validator) proves possession
    // of the key — no separate PoP. signing_bytes() includes the full
    // payload, so the region binds into the tx hash automatically.
    std::vector<uint8_t> payload;
    payload.reserve(chain::REGISTER_PAYLOAD_PUBKEY_SIZE
                    + (cfg_.region.empty() ? 0 : 1 + cfg_.region.size()));
    payload.insert(payload.end(), key_.pub.begin(), key_.pub.end());
    if (!cfg_.region.empty()) {
        payload.push_back(static_cast<uint8_t>(cfg_.region.size()));
        payload.insert(payload.end(), cfg_.region.begin(), cfg_.region.end());
    }

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
    // v2.6 / S-031 polish: release state_mutex_ before broadcast.
    lk.unlock();
    gossip_.broadcast(net::make_transaction(tx));
    return {{"status", "queued"}, {"hash", to_hex(tx.hash)}};
}

} // namespace determ::node
