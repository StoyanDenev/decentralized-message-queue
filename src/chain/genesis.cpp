#include <determ/chain/genesis.hpp>
#include <determ/chain/params.hpp>
#include <determ/crypto/sha256.hpp>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <algorithm>

namespace determ::chain {

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace determ::crypto;

// rev.9 R1: region tag normalization. Used at every parse boundary
// (genesis JSON load, REGISTER tx apply / validate). ASCII tolower;
// then enforce charset [a-z0-9-_] and size <= 32 bytes. Empty string
// is always valid (= global pool). Throws on charset / size violation.
static std::string normalize_region(const std::string& in,
                                     const char* ctx) {
    if (in.size() > 32) {
        throw std::runtime_error(std::string("genesis: ") + ctx
            + " region exceeds 32 bytes");
    }
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
        bool ok = (c >= 'a' && c <= 'z')
               || (c >= '0' && c <= '9')
               || c == '-' || c == '_';
        if (!ok) {
            throw std::runtime_error(std::string("genesis: ") + ctx
                + " region has invalid char (allowed [a-z0-9-_])");
        }
        out.push_back(static_cast<char>(c));
    }
    return out;
}

// ─── GenesisConfig JSON ──────────────────────────────────────────────────────

json GenesisConfig::to_json() const {
    json creators = json::array();
    for (auto& c : initial_creators) {
        creators.push_back({
            {"domain",        c.domain},
            {"ed_pub",        to_hex(c.ed_pub)},
            {"initial_stake", c.initial_stake},
            {"region",        c.region}
        });
    }
    json balances = json::array();
    for (auto& b : initial_balances) {
        balances.push_back({
            {"domain",  b.domain},
            {"balance", b.balance}
        });
    }
    return {
        {"chain_id",                 chain_id},
        {"m_creators",               m_creators},
        {"k_block_sigs",             k_block_sigs},
        {"block_subsidy",            block_subsidy},
        {"bft_enabled",              bft_enabled},
        {"bft_escalation_threshold", bft_escalation_threshold},
        {"inclusion_model",         static_cast<uint8_t>(inclusion_model)},
        {"min_stake",                min_stake},
        {"chain_role",               static_cast<uint8_t>(chain_role)},
        {"shard_id",                 shard_id},
        {"initial_shard_count",      initial_shard_count},
        {"epoch_blocks",             epoch_blocks},
        {"shard_address_salt",       to_hex(shard_address_salt)},
        {"committee_region",         committee_region},
        {"initial_creators",         creators},
        {"initial_balances",         balances}
    };
}

GenesisConfig GenesisConfig::from_json(const json& j) {
    GenesisConfig c;
    c.chain_id      = j.value("chain_id",      "");
    c.m_creators    = j.value("m_creators",    uint32_t{3});
    c.k_block_sigs  = j.value("k_block_sigs",  c.m_creators);   // default to M (strong)
    c.block_subsidy = j.value("block_subsidy", uint64_t{0});
    c.bft_enabled              = j.value("bft_enabled",              true);
    c.bft_escalation_threshold = j.value("bft_escalation_threshold", uint32_t{5});
    c.inclusion_model         = static_cast<InclusionModel>(j.value("inclusion_model", uint8_t{0}));
    c.min_stake                = j.value("min_stake",                uint64_t{1000});
    c.chain_role               = static_cast<ChainRole>(j.value("chain_role", uint8_t{0}));
    c.shard_id                 = j.value("shard_id",                 ShardId{0});
    c.initial_shard_count      = j.value("initial_shard_count",      uint32_t{1});
    c.epoch_blocks             = j.value("epoch_blocks",             uint32_t{1000});
    if (j.contains("shard_address_salt")) {
        c.shard_address_salt = from_hex_arr<32>(j["shard_address_salt"].get<std::string>());
    }
    // rev.9 R1: committee_region is normalized at load. Empty (or absent
    // for legacy genesis files) preserves byte-identical hashing.
    c.committee_region = normalize_region(j.value("committee_region",
                                                    std::string{}),
                                            "committee_region");

    if (j.contains("initial_creators")) {
        for (auto& cj : j["initial_creators"]) {
            GenesisCreator gc;
            gc.domain        = cj["domain"].get<std::string>();
            gc.ed_pub        = from_hex_arr<32>(cj["ed_pub"].get<std::string>());
            gc.initial_stake = cj.value("initial_stake", uint64_t{0});
            gc.region        = normalize_region(cj.value("region",
                                                           std::string{}),
                                                  "initial_creator.region");
            c.initial_creators.push_back(gc);
        }
    }
    if (j.contains("initial_balances")) {
        for (auto& bj : j["initial_balances"]) {
            GenesisAllocation a;
            a.domain  = bj["domain"].get<std::string>();
            a.balance = bj.value("balance", uint64_t{0});
            c.initial_balances.push_back(a);
        }
    }
    return c;
}

GenesisConfig GenesisConfig::load(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open genesis config: " + path);
    return from_json(json::parse(f));
}

void GenesisConfig::save(const std::string& path) const {
    fs::create_directories(fs::path(path).parent_path());
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write genesis config: " + path);
    f << to_json().dump(2);
}

// ─── Genesis block construction ──────────────────────────────────────────────

Block make_genesis_block(const GenesisConfig& cfg) {
    Block g;
    g.index            = 0;
    g.prev_hash        = {};
    g.timestamp        = 0;
    g.creator_tx_lists = {};
    g.creator_ed_sigs  = {};
    g.creator_dh_inputs= {};
    g.tx_root          = {};
    g.delay_seed       = {};
    g.delay_output     = {};
    g.creator_block_sigs = {};

    // creators[] = the initial set (in domain order). Block-1's selection
    // draws from this set via cumulative_rand.
    for (auto& c : cfg.initial_creators) g.creators.push_back(c.domain);
    std::sort(g.creators.begin(), g.creators.end());

    // initial_state encodes the seeded accounts/stakes/registry. apply_transactions
    // special-cases index 0 to install these directly.
    for (auto& c : cfg.initial_creators) {
        GenesisAlloc a;
        a.domain  = c.domain;
        a.ed_pub  = c.ed_pub;
        a.stake   = c.initial_stake;
        // rev.9 R1: propagate region into the genesis-installed registry
        // entry. Empty preserves pre-R1 behavior.
        a.region  = c.region;
        // balance defaults to 0; explicit balances come from initial_balances.
        g.initial_state.push_back(a);
    }
    for (auto& alloc : cfg.initial_balances) {
        bool merged = false;
        for (auto& a : g.initial_state) {
            if (a.domain == alloc.domain) { a.balance += alloc.balance; merged = true; break; }
        }
        if (!merged) {
            GenesisAlloc a;
            a.domain  = alloc.domain;
            a.balance = alloc.balance;
            g.initial_state.push_back(a);
        }
    }

    // cumulative_rand anchored to chain_id + role + shard_id + concat(ed_pubs).
    // The role + shard_id make a beacon vs shard_i genesis distinguishable
    // even when they share the same chain_id and creator set.
    //
    // rev.9 R1: committee_region is length-prefixed (u8 length + bytes)
    // and mixed in after shard_id ONLY when non-empty. The empty-region
    // path skips the mix entirely so legacy / unsharded / global-pool
    // genesis files remain byte-identical (backward-compat invariant).
    // Two shards differing only in non-empty committee_region get
    // distinct genesis hashes via the length-prefix encoding.
    SHA256Builder rb;
    rb.append(std::string("DTM-genesis-v1"));
    rb.append(cfg.chain_id);
    rb.append(static_cast<uint8_t>(cfg.chain_role));
    rb.append(static_cast<uint64_t>(cfg.shard_id));
    if (!cfg.committee_region.empty()) {
        rb.append(static_cast<uint8_t>(cfg.committee_region.size()));
        rb.append(cfg.committee_region);
    }
    for (auto& c : cfg.initial_creators) rb.append(c.ed_pub.data(), c.ed_pub.size());
    g.cumulative_rand = rb.finalize();

    return g;
}

Hash compute_genesis_hash(const GenesisConfig& cfg) {
    Block g = make_genesis_block(cfg);
    return g.compute_hash();
}

// ─── Legacy ──────────────────────────────────────────────────────────────────

Block make_genesis(const std::string& /*seed*/) {
    Block g;
    g.index            = 0;
    g.prev_hash        = {};
    g.timestamp        = 0;
    g.creators         = {};
    g.creator_tx_lists = {};
    g.creator_ed_sigs  = {};
    g.creator_dh_inputs= {};
    g.tx_root          = {};
    g.delay_seed       = {};
    g.delay_output     = {};
    g.creator_block_sigs = {};
    g.cumulative_rand  = sha256(g.tx_root.data(), 32);
    return g;
}

} // namespace determ::chain
