// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/chain/genesis.hpp>
#include <determ/chain/params.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/util/json_validate.hpp>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <algorithm>
#include <set>
#include <cstring>   // D2 inc8 DGC1 codec: memcmp / memcpy
#include <iterator>  // D2 inc8: istreambuf_iterator whole-file reads

namespace determ::chain {

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace determ::crypto;
using determ::util::json_require;
using determ::util::json_require_hex;
using determ::util::json_require_array;

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
    json keyholders = json::array();
    for (auto& k : param_keyholders) keyholders.push_back(to_hex(k));
    json out = {
        {"chain_id",                 chain_id},
        {"genesis_message",          genesis_message},
        {"m_creators",               m_creators},
        {"k_block_sigs",             k_block_sigs},
        {"block_subsidy",            block_subsidy},
        {"subsidy_pool_initial",     subsidy_pool_initial},
        {"subsidy_mode",             subsidy_mode},
        {"lottery_jackpot_multiplier", lottery_jackpot_multiplier},
        {"zeroth_pool_initial",      zeroth_pool_initial},
        {"bft_enabled",              bft_enabled},
        {"bft_escalation_threshold", bft_escalation_threshold},
        {"inclusion_model",         static_cast<uint8_t>(inclusion_model)},
        {"min_stake",                min_stake},
        {"suspension_slash",         suspension_slash},
        {"unstake_delay",            unstake_delay},
        {"merge_threshold_blocks",   merge_threshold_blocks},
        {"revert_threshold_blocks",  revert_threshold_blocks},
        {"merge_grace_blocks",       merge_grace_blocks},
        {"chain_role",               static_cast<uint8_t>(chain_role)},
        {"shard_id",                 shard_id},
        {"initial_shard_count",      initial_shard_count},
        {"epoch_blocks",             epoch_blocks},
        {"shard_address_salt",       to_hex(shard_address_salt)},
        {"committee_region",         committee_region},
        {"governance_mode",          governance_mode},
        {"param_keyholders",         keyholders},
        {"param_threshold",          param_threshold},
        {"initial_creators",         creators},
        {"initial_balances",         balances}
    };
    // D1: emit the CT-disable flag ONLY when set (disabled), so a CT-enabled
    // (default) chain's genesis JSON stays byte-identical to pre-flag files.
    if (!confidential_tx_enabled) out["confidential_tx_enabled"] = false;
    // NC-8 profile gating: emit the crypto profile ONLY when non-default (FIPS),
    // so a MODERN (default) chain's genesis JSON stays byte-identical.
    if (crypto_profile != CryptoProfile::MODERN)
        out["crypto_profile"] = static_cast<uint64_t>(crypto_profile);
    // D3.5e-1: emit the shard→region map ONLY when non-empty, so every
    // existing genesis file stays byte-identical. Same entry shape as the
    // node-local shard_manifest.json it replaces.
    if (!shard_regions.empty()) {
        json arr = json::array();
        for (auto& [sid, region] : shard_regions) {
            arr.push_back(json{{"shard_id",         sid},
                               {"committee_region", region}});
        }
        out["beacon_shard_regions"] = arr;
    }
    return out;
}

// ─── Shared validation / normalization ───────────────────────────────────────
// D2 inc8: every semantic rule that used to live inside from_json now lives
// HERE, so the JSON view and the canonical DGC1 binary container enforce the
// IDENTICAL rule set. The check order is textually the same as the pre-split
// from_json, so existing diagnostics are unchanged. validate() also NORMALIZES
// (regions to lowercase-canonical, shard_regions to shard_id order, governed
// param_threshold defaulted to N-of-N); it is idempotent, so running it on an
// already-validated config is a no-op.
void GenesisConfig::validate() {
    GenesisConfig& c = *this;

    // QUORUM INTERSECTION — the K/M genesis band. Checked FIRST: it is the only
    // genesis rule whose violation is a consensus SAFETY hole rather than a
    // configuration mistake.
    //
    // If two K-committees at one height can be DISJOINT, each can sign a
    // DIFFERENT block, each reaches the threshold, and both finalize with NO
    // member ever signing twice — a fork that is UNATTRIBUTABLE. Two K-subsets
    // of an N-set overlap iff 2K > N. SCOPE (DECISION-LOG 2026-08-14 ddfe877;
    // SECURITY.md S-054 is PARTIAL): this check is over m_creators, which no
    // accept rule reads. At runtime the committee is drawn from the ELIGIBLE
    // POOL N(h) (validator.cpp check_creator_selection: registry minus the
    // block's own aborters), and REGISTER leaves N uncapped, so this band
    // delivers intersection only while N(h) <= M. It is a necessary genesis
    // condition; the runtime bound 2K > N(h) is OPEN (DECISION CLOCK R-4).
    //
    // Band: M/2 < K <= M. K == M is legal (unanimity / maximal mutual
    // distrust) and satisfies intersection trivially (2M > M); it has zero
    // MUTUAL-DISTRUST margin (one dead member stops MD production; with
    // bft_enabled, abort-quorum escalation to ceil(2K/3) can still tolerate a
    // crash). The upper bound 1 <= K <= M is enforced at the boot/tool sites
    // (src/node/node.cpp, src/main.cpp genesis-tool).
    //
    // 64-bit promotion is load-bearing: 2 * uint32_t wraps in uint32_t, so a
    // near-UINT32_MAX K would wrap to 2K-2^32 and be rejected as under-band.
    if (static_cast<uint64_t>(c.k_block_sigs) * 2ull
            <= static_cast<uint64_t>(c.m_creators)) {
        throw std::runtime_error(
            "genesis: k_block_sigs=" + std::to_string(c.k_block_sigs)
            + " with m_creators=" + std::to_string(c.m_creators)
            + " violates QUORUM INTERSECTION (2*K must exceed M). At 2K <= M "
              "two DISJOINT K-subsets of one committee can each reach the "
              "signature threshold and finalize CONFLICTING blocks at one "
              "height with NO member double-signing, so the fork is not "
              "merely unpunished but UNATTRIBUTABLE. Safe band: M/2 < K <= M "
              "(K == M is legal — unanimity, zero liveness margin).");
    }

    if (c.genesis_message.size() > GENESIS_MESSAGE_MAX_BYTES) {
        throw std::runtime_error(
            "genesis: genesis_message exceeds "
            + std::to_string(GENESIS_MESSAGE_MAX_BYTES)
            + " bytes (got "
            + std::to_string(c.genesis_message.size()) + ")");
    }

    // E3 validation: under LOTTERY, multiplier must be >= 2 (M=1 is just FLAT;
    // M=0 would divide-by-zero).
    if (c.subsidy_mode == 1 && c.lottery_jackpot_multiplier < 2) {
        throw std::runtime_error(
            "genesis: subsidy_mode=1 (LOTTERY) requires "
            "lottery_jackpot_multiplier >= 2 (got "
            + std::to_string(c.lottery_jackpot_multiplier) + ")");
    }
    if (c.subsidy_mode > 1) {
        throw std::runtime_error(
            "genesis: unknown subsidy_mode "
            + std::to_string(c.subsidy_mode) + " (0=FLAT, 1=LOTTERY)");
    }

    // S-007: sane-bounds check on subsidy-related fields. The apply
    // path's per-mutation overflow checks catch wrap-around but a
    // genesis with absurdly-large block_subsidy would still throw at
    // first apply rather than at genesis-load. Reject obviously-bogus
    // values up-front so operators see the problem before deploying.
    // 10^18 = 1 quintillion units; sane for any realistic denomination
    // (even 18-decimal-place currencies have <= 10^18 native units
    // per "unit" of value).
    constexpr uint64_t kSaneBoundsMax = 1000000000000000000ull; // 1e18
    if (c.block_subsidy > kSaneBoundsMax) {
        throw std::runtime_error(
            "genesis: block_subsidy " + std::to_string(c.block_subsidy)
          + " exceeds sane-bounds (1e18); refusing to load. S-007.");
    }
    if (c.subsidy_pool_initial > kSaneBoundsMax) {
        throw std::runtime_error(
            "genesis: subsidy_pool_initial "
          + std::to_string(c.subsidy_pool_initial)
          + " exceeds sane-bounds (1e18); refusing to load. S-007.");
    }
    if (c.zeroth_pool_initial > kSaneBoundsMax) {
        throw std::runtime_error(
            "genesis: zeroth_pool_initial "
          + std::to_string(c.zeroth_pool_initial)
          + " exceeds sane-bounds (1e18); refusing to load. S-007.");
    }
    if (c.lottery_jackpot_multiplier > 0
        && c.block_subsidy != 0
        && c.block_subsidy > kSaneBoundsMax / c.lottery_jackpot_multiplier) {
        throw std::runtime_error(
            "genesis: block_subsidy * lottery_jackpot_multiplier "
            "would overflow on jackpot block; reduce one or both. "
            "S-007.");
    }

    // rev.9 R1: committee_region normalized. Empty preserves byte-identical
    // hashing for legacy configs.
    c.committee_region = normalize_region(c.committee_region, "committee_region");

    // D3.5e-1 (S-036 Layer 2): the genesis-committed shard→region map.
    if (!c.shard_regions.empty()) {
        for (auto& e : c.shard_regions)
            e.second = normalize_region(e.second,
                                        "beacon_shard_regions.committee_region");
        // Canonical order: sorted by shard_id, so the hash mix is a pure
        // function of the SET regardless of source ordering.
        std::sort(c.shard_regions.begin(), c.shard_regions.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        for (size_t i = 1; i < c.shard_regions.size(); ++i) {
            if (c.shard_regions[i].first == c.shard_regions[i - 1].first) {
                throw std::runtime_error(
                    "genesis: beacon_shard_regions duplicate shard_id="
                    + std::to_string(c.shard_regions[i].first));
            }
        }
        if (c.chain_role != ChainRole::BEACON) {
            throw std::runtime_error(
                "genesis: beacon_shard_regions is valid only on a BEACON chain "
                "(chain_role=1) — it is the committed input to the "
                "beacon's shard-tip verification (S-036 Layer 2)");
        }
        if (c.epoch_blocks < 2) {
            throw std::runtime_error(
                "genesis: beacon_shard_regions requires epoch_blocks >= 2 — "
                "with epoch_blocks=1, epoch 1's rand anchor is the "
                "genesis block, which BEACON_HEADER gossip can never "
                "carry (an unfixable producer/verifier asymmetry)");
        }
        for (auto& [sid, region] : c.shard_regions) {
            (void)region;
            if (sid >= c.initial_shard_count) {
                throw std::runtime_error(
                    "genesis: beacon_shard_regions shard_id="
                    + std::to_string(sid)
                    + " >= initial_shard_count="
                    + std::to_string(c.initial_shard_count));
            }
        }
    }

    // A5 governance coupling.
    if (c.governance_mode > 1) {
        throw std::runtime_error(
            "genesis: unknown governance_mode "
            + std::to_string(c.governance_mode)
            + " (0=uncontrolled, 1=governed)");
    }
    if (c.governance_mode == 1) {
        if (c.param_keyholders.empty()) {
            throw std::runtime_error(
                "genesis: governance_mode=governed requires at least one "
                "param_keyholder");
        }
        if (c.param_keyholders.size() > 255) {
            throw std::runtime_error(
                "genesis: param_keyholders count exceeds 255 (got "
                + std::to_string(c.param_keyholders.size()) + ")");
        }
        if (c.param_threshold == 0) {
            // Default to N-of-N when threshold field is absent/zero.
            c.param_threshold =
                static_cast<uint32_t>(c.param_keyholders.size());
        }
        if (c.param_threshold > c.param_keyholders.size()) {
            throw std::runtime_error(
                "genesis: param_threshold "
                + std::to_string(c.param_threshold)
                + " exceeds keyholder count "
                + std::to_string(c.param_keyholders.size()));
        }
    } else {
        // Uncontrolled: reject stray governance fields to avoid silent
        // mis-deployment. Empty/zero is fine.
        if (!c.param_keyholders.empty() || c.param_threshold != 0) {
            throw std::runtime_error(
                "genesis: governance_mode=uncontrolled must not set "
                "param_keyholders or param_threshold");
        }
    }

    for (auto& gc : c.initial_creators)
        gc.region = normalize_region(gc.region, "initial_creator.region");
}

GenesisConfig GenesisConfig::from_json(const json& j) {
    GenesisConfig c;
    c.chain_id      = j.value("chain_id",      "");
    // Optional genesis_message. Default (key absent) is DEFAULT_GENESIS_MESSAGE
    // — the protocol-level philosophical anchor. Explicit empty string is
    // allowed for operators who want no inscription. Validated against
    // GENESIS_MESSAGE_MAX_BYTES.
    c.genesis_message = j.value("genesis_message", std::string{DEFAULT_GENESIS_MESSAGE});
    c.m_creators    = j.value("m_creators",    uint32_t{3});
    c.k_block_sigs  = j.value("k_block_sigs",  c.m_creators);   // default to M (strong)
    c.block_subsidy = j.value("block_subsidy", uint64_t{0});
    c.subsidy_pool_initial = j.value("subsidy_pool_initial", uint64_t{0});
    c.subsidy_mode  = j.value("subsidy_mode",  uint8_t{0});
    c.lottery_jackpot_multiplier = j.value("lottery_jackpot_multiplier",
                                            uint32_t{0});
    c.zeroth_pool_initial = j.value("zeroth_pool_initial", uint64_t{0});
    c.bft_enabled              = j.value("bft_enabled",              true);
    c.bft_escalation_threshold = j.value("bft_escalation_threshold", uint32_t{1});  // S-045: default 1 (was 5)
    c.inclusion_model         = static_cast<InclusionModel>(j.value("inclusion_model", uint8_t{0}));
    c.min_stake                = j.value("min_stake",                uint64_t{1000});
    // D1: CT layer enabled by default; absent key -> true (pre-flag genesis
    // files load byte-identically as CT-enabled).
    c.confidential_tx_enabled  = j.value("confidential_tx_enabled",  true);
    c.crypto_profile           = static_cast<CryptoProfile>(
                                     j.value("crypto_profile", uint64_t{0}));
    c.suspension_slash         = j.value("suspension_slash",         uint64_t{10});
    c.unstake_delay            = j.value("unstake_delay",            uint64_t{1000});
    c.merge_threshold_blocks   = j.value("merge_threshold_blocks",   uint32_t{100});
    c.revert_threshold_blocks  = j.value("revert_threshold_blocks",  uint32_t{200});
    c.merge_grace_blocks       = j.value("merge_grace_blocks",       uint32_t{10});
    c.chain_role               = static_cast<ChainRole>(j.value("chain_role", uint8_t{0}));
    c.shard_id                 = j.value("shard_id",                 ShardId{0});
    c.initial_shard_count      = j.value("initial_shard_count",      uint32_t{1});
    c.epoch_blocks             = j.value("epoch_blocks",             uint32_t{1000});
    if (j.contains("shard_address_salt")) {
        // S-018 defense-in-depth: optional field but if present
        // must be a 64-char hex string. Wrong-length or non-string
        // throws clean S-018 diagnostic naming the field.
        c.shard_address_salt = from_hex_arr<32>(json_require_hex(j, "shard_address_salt", 64));
    }
    // rev.9 R1: committee_region is normalized by validate() below. Empty
    // (or absent for legacy genesis files) preserves byte-identical hashing.
    c.committee_region = j.value("committee_region", std::string{});

    // D3.5e-1 (S-036 Layer 2): the genesis-committed shard→region map.
    // Absent (every existing genesis file) = empty = byte-identical hashing.
    // JSON key is `beacon_shard_regions` — deliberately DISTINCT from the
    // `shard_regions` STRING-array key that build-sharded consumes as
    // positional build-time INPUT (test_tactical.sh), so the two shapes can
    // never alias through GenesisConfig::load.
    if (j.contains("beacon_shard_regions")) {
        for (auto& entry : json_require_array(j, "beacon_shard_regions")) {
            if (!entry.is_object()) {
                throw std::runtime_error(
                    "genesis: beacon_shard_regions entries must be objects");
            }
            c.shard_regions.emplace_back(
                entry.value("shard_id", ShardId{0}),
                entry.value("committee_region", std::string{}));
        }
        // validate() below normalizes each region, sorts by shard_id (the
        // canonical order the hash mix depends on), and rejects duplicates
        // and the BEACON/epoch_blocks/shard_id-range constraints.
    }

    // A5: governance mode. Absent / 0 = uncontrolled (default, byte-
    // identical to pre-A5 genesis files: keyholders empty, threshold 0,
    // and the genesis-hash mix below skips these fields entirely).
    c.governance_mode = j.value("governance_mode", uint8_t{0});
    if (j.contains("param_keyholders")) {
        // S-018 defense-in-depth: param_keyholders is optional but if
        // present MUST be an array. A genesis with `"param_keyholders":
        // "scalar"` previously threw an opaque nlohmann error mid-
        // iteration; now throws a clean S-018 diagnostic naming the
        // field.
        for (auto& kj : json_require_array(j, "param_keyholders")) {
            c.param_keyholders.push_back(
                from_hex_arr<32>(kj.get<std::string>()));
        }
    }
    c.param_threshold = j.value("param_threshold", uint32_t{0});

    if (j.contains("initial_creators")) {
        // S-018: each entry has required {domain, ed_pub}. Surface the
        // field name in the diagnostic so operators editing genesis
        // JSON files don't have to dig through nlohmann internals on
        // a typo. Outer wrap with json_require_array adds wrong-type
        // diagnostic if the field is scalar/object instead of array.
        for (auto& cj : json_require_array(j, "initial_creators")) {
            GenesisCreator gc;
            gc.domain        = json_require<std::string>(cj, "domain");
            gc.ed_pub        = from_hex_arr<32>(json_require_hex(cj, "ed_pub", 64));
            gc.initial_stake = cj.value("initial_stake", uint64_t{0});
            gc.region        = cj.value("region", std::string{});
            c.initial_creators.push_back(gc);
        }
    }
    if (j.contains("initial_balances")) {
        // S-018: `domain` is required; `balance` defaults to 0.
        // Wrong-type initial_balances field throws clean diagnostic.
        for (auto& bj : json_require_array(j, "initial_balances")) {
            GenesisAllocation a;
            a.domain  = json_require<std::string>(bj, "domain");
            a.balance = bj.value("balance", uint64_t{0});
            c.initial_balances.push_back(a);
        }
    }
    c.validate();
    return c;
}

// ─── DGC1: the canonical binary GenesisConfig container ──────────────────────
// D2 inc8. The genesis config FILE is at-rest storage, so it is binary-only —
// to_json/from_json survive purely as the CLI text VIEW and as the build-time
// input shape for `genesis-tool build`. All integers little-endian; lpN = an
// N-bit LE length prefix followed by that many bytes.
//
//   magic 4 = 'D','G','C','1'
//   chain_id lp16 | genesis_message lp16
//   m_creators u32 | k_block_sigs u32
//   block_subsidy u64 | subsidy_pool_initial u64 | subsidy_mode u8
//   lottery_jackpot_multiplier u32 | zeroth_pool_initial u64
//   bft_enabled u8 | bft_escalation_threshold u32
//   inclusion_model u8 | min_stake u64
//   confidential_tx_enabled u8 | crypto_profile u8
//   suspension_slash u64 | unstake_delay u64
//   merge_threshold_blocks u32 | revert_threshold_blocks u32 | merge_grace_blocks u32
//   chain_role u8 | shard_id u32 | initial_shard_count u32 | epoch_blocks u32
//   shard_address_salt 32 raw
//   committee_region lp8
//   governance_mode u8 | param_threshold u32
//   param_keyholders: u16 count x 32 raw
//   initial_creators: u16 count x { domain lp16 | ed_pub 32 | initial_stake u64 | region lp8 }
//   initial_balances: u16 count x { domain lp16 | balance u64 }
//   beacon_shard_regions: u16 count x { shard_id u32 | region lp8 }
//
// Every field is UNCONDITIONAL (the JSON conditional-emission tricks exist only
// to keep pre-existing text files byte-identical; there is no such legacy for
// the binary form). decode() is bounds-checked, EXACT-consumption, rejects
// non-0/1 booleans and non-canonical regions, requires strictly-ascending
// beacon_shard_regions shard_ids, and finishes by running the SAME validate()
// as from_json. Hash neutrality is therefore structural: compute_genesis_hash
// reads field VALUES only, so decode(encode(c)) hashes identically to c.
namespace {
constexpr char kGenesisMagic[4] = {'D','G','C','1'};

void put_u8 (std::vector<uint8_t>& o, uint8_t v)  { o.push_back(v); }
void put_u16(std::vector<uint8_t>& o, uint16_t v) {
    o.push_back(uint8_t(v & 0xFF)); o.push_back(uint8_t((v >> 8) & 0xFF));
}
void put_u32(std::vector<uint8_t>& o, uint32_t v) {
    for (int i = 0; i < 4; ++i) o.push_back(uint8_t((v >> (8 * i)) & 0xFF));
}
void put_u64(std::vector<uint8_t>& o, uint64_t v) {
    for (int i = 0; i < 8; ++i) o.push_back(uint8_t((v >> (8 * i)) & 0xFF));
}
void put_lp16(std::vector<uint8_t>& o, const std::string& sv, const char* what) {
    if (sv.size() > 0xFFFF)
        throw std::runtime_error(std::string("genesis encode: ") + what
            + " exceeds 65535 bytes");
    put_u16(o, uint16_t(sv.size()));
    o.insert(o.end(), sv.begin(), sv.end());
}
void put_lp8(std::vector<uint8_t>& o, const std::string& sv, const char* what) {
    if (sv.size() > 0xFF)
        throw std::runtime_error(std::string("genesis encode: ") + what
            + " exceeds 255 bytes");
    put_u8(o, uint8_t(sv.size()));
    o.insert(o.end(), sv.begin(), sv.end());
}
void put_raw(std::vector<uint8_t>& o, const uint8_t* p, size_t n) {
    o.insert(o.end(), p, p + n);
}

// Bounds-checked cursor (bf_* discipline): every read validates remaining
// length BEFORE consuming, so a hostile count can never over-read or drive a
// huge reserve.
struct Rd {
    const uint8_t* p; size_t n; size_t i{0};
    void need(size_t k, const char* what) const {
        if (n - i < k) throw std::runtime_error(
            std::string("genesis decode: truncated at ") + what);
    }
    uint8_t  u8 (const char* w) { need(1, w); return p[i++]; }
    uint16_t u16(const char* w) { need(2, w); uint16_t v = uint16_t(p[i]) | uint16_t(p[i+1]) << 8; i += 2; return v; }
    uint32_t u32(const char* w) { need(4, w); uint32_t v = 0; for (int k = 0; k < 4; ++k) v |= uint32_t(p[i+k]) << (8*k); i += 4; return v; }
    uint64_t u64(const char* w) { need(8, w); uint64_t v = 0; for (int k = 0; k < 8; ++k) v |= uint64_t(p[i+k]) << (8*k); i += 8; return v; }
    std::string lp16(const char* w) { uint16_t L = u16(w); need(L, w);
        std::string s(reinterpret_cast<const char*>(p + i), L); i += L; return s; }
    std::string lp8 (const char* w) { uint8_t L = u8(w); need(L, w);
        std::string s(reinterpret_cast<const char*>(p + i), L); i += L; return s; }
    void raw(uint8_t* out, size_t k, const char* w) { need(k, w);
        std::memcpy(out, p + i, k); i += k; }
    bool boolean(const char* w) { uint8_t v = u8(w);
        if (v > 1) throw std::runtime_error(
            std::string("genesis decode: ") + w + " must be 0 or 1");
        return v != 0; }
};
} // namespace

std::vector<uint8_t> GenesisConfig::encode() const {
    std::vector<uint8_t> o;
    put_raw(o, reinterpret_cast<const uint8_t*>(kGenesisMagic), 4);
    put_lp16(o, chain_id,        "chain_id");
    put_lp16(o, genesis_message, "genesis_message");
    put_u32(o, m_creators);
    put_u32(o, k_block_sigs);
    put_u64(o, block_subsidy);
    put_u64(o, subsidy_pool_initial);
    put_u8 (o, subsidy_mode);
    put_u32(o, lottery_jackpot_multiplier);
    put_u64(o, zeroth_pool_initial);
    put_u8 (o, bft_enabled ? 1 : 0);
    put_u32(o, bft_escalation_threshold);
    put_u8 (o, static_cast<uint8_t>(inclusion_model));
    put_u64(o, min_stake);
    put_u8 (o, confidential_tx_enabled ? 1 : 0);
    put_u8 (o, static_cast<uint8_t>(crypto_profile));
    put_u64(o, suspension_slash);
    put_u64(o, unstake_delay);
    put_u32(o, merge_threshold_blocks);
    put_u32(o, revert_threshold_blocks);
    put_u32(o, merge_grace_blocks);
    put_u8 (o, static_cast<uint8_t>(chain_role));
    put_u32(o, shard_id);
    put_u32(o, initial_shard_count);
    put_u32(o, epoch_blocks);
    put_raw(o, shard_address_salt.data(), shard_address_salt.size());
    put_lp8(o, committee_region, "committee_region");
    put_u8 (o, governance_mode);
    put_u32(o, param_threshold);

    if (param_keyholders.size() > 0xFFFF)
        throw std::runtime_error("genesis encode: too many param_keyholders");
    put_u16(o, uint16_t(param_keyholders.size()));
    for (auto& k : param_keyholders) put_raw(o, k.data(), k.size());

    if (initial_creators.size() > 0xFFFF)
        throw std::runtime_error("genesis encode: too many initial_creators");
    put_u16(o, uint16_t(initial_creators.size()));
    for (auto& gc : initial_creators) {
        put_lp16(o, gc.domain, "initial_creator.domain");
        put_raw(o, gc.ed_pub.data(), gc.ed_pub.size());
        put_u64(o, gc.initial_stake);
        put_lp8(o, gc.region, "initial_creator.region");
    }

    if (initial_balances.size() > 0xFFFF)
        throw std::runtime_error("genesis encode: too many initial_balances");
    put_u16(o, uint16_t(initial_balances.size()));
    for (auto& b : initial_balances) {
        put_lp16(o, b.domain, "initial_balance.domain");
        put_u64(o, b.balance);
    }

    if (shard_regions.size() > 0xFFFF)
        throw std::runtime_error("genesis encode: too many beacon_shard_regions");
    put_u16(o, uint16_t(shard_regions.size()));
    for (auto& [sid, region] : shard_regions) {
        put_u32(o, sid);
        put_lp8(o, region, "beacon_shard_regions.committee_region");
    }
    return o;
}

GenesisConfig GenesisConfig::decode(const uint8_t* data, size_t len) {
    if (len < 4 || std::memcmp(data, kGenesisMagic, 4) != 0)
        throw std::runtime_error(
            "genesis decode: bad magic (expected DGC1)");
    Rd r{data, len, 4};
    GenesisConfig c;
    c.chain_id        = r.lp16("chain_id");
    c.genesis_message = r.lp16("genesis_message");
    c.m_creators      = r.u32("m_creators");
    c.k_block_sigs    = r.u32("k_block_sigs");
    c.block_subsidy         = r.u64("block_subsidy");
    c.subsidy_pool_initial  = r.u64("subsidy_pool_initial");
    c.subsidy_mode          = r.u8 ("subsidy_mode");
    c.lottery_jackpot_multiplier = r.u32("lottery_jackpot_multiplier");
    c.zeroth_pool_initial   = r.u64("zeroth_pool_initial");
    c.bft_enabled           = r.boolean("bft_enabled");
    c.bft_escalation_threshold = r.u32("bft_escalation_threshold");
    {
        uint8_t im = r.u8("inclusion_model");
        if (im > 1) throw std::runtime_error(
            "genesis decode: unknown inclusion_model " + std::to_string(im));
        c.inclusion_model = static_cast<InclusionModel>(im);
    }
    c.min_stake = r.u64("min_stake");
    c.confidential_tx_enabled = r.boolean("confidential_tx_enabled");
    {
        uint8_t cp = r.u8("crypto_profile");
        if (cp > 1) throw std::runtime_error(
            "genesis decode: unknown crypto_profile " + std::to_string(cp));
        c.crypto_profile = static_cast<CryptoProfile>(cp);
    }
    c.suspension_slash        = r.u64("suspension_slash");
    c.unstake_delay           = r.u64("unstake_delay");
    c.merge_threshold_blocks  = r.u32("merge_threshold_blocks");
    c.revert_threshold_blocks = r.u32("revert_threshold_blocks");
    c.merge_grace_blocks      = r.u32("merge_grace_blocks");
    {
        uint8_t cr = r.u8("chain_role");
        if (cr > 2) throw std::runtime_error(
            "genesis decode: unknown chain_role " + std::to_string(cr));
        c.chain_role = static_cast<ChainRole>(cr);
    }
    c.shard_id            = r.u32("shard_id");
    c.initial_shard_count = r.u32("initial_shard_count");
    c.epoch_blocks        = r.u32("epoch_blocks");
    r.raw(c.shard_address_salt.data(), c.shard_address_salt.size(),
          "shard_address_salt");

    // ONE canonical encoding: a region whose normalized form differs from the
    // stored bytes is REJECTED rather than silently rewritten, so two distinct
    // byte strings can never denote the same config.
    auto canonical_region = [](const std::string& in, const char* ctx) {
        if (normalize_region(in, ctx) != in)
            throw std::runtime_error(std::string("genesis decode: ") + ctx
                + " is not in canonical (normalized) form");
        return in;
    };
    c.committee_region =
        canonical_region(r.lp8("committee_region"), "committee_region");
    c.governance_mode = r.u8("governance_mode");
    c.param_threshold = r.u32("param_threshold");

    {
        uint16_t n = r.u16("param_keyholders.count");
        r.need(size_t(n) * 32, "param_keyholders");   // bound BEFORE reserve
        c.param_keyholders.resize(n);
        for (auto& k : c.param_keyholders)
            r.raw(k.data(), k.size(), "param_keyholder");
    }
    {
        uint16_t n = r.u16("initial_creators.count");
        for (uint16_t i = 0; i < n; ++i) {
            GenesisCreator gc;
            gc.domain = r.lp16("initial_creator.domain");
            r.raw(gc.ed_pub.data(), gc.ed_pub.size(), "initial_creator.ed_pub");
            gc.initial_stake = r.u64("initial_creator.initial_stake");
            gc.region = canonical_region(r.lp8("initial_creator.region"),
                                          "initial_creator.region");
            c.initial_creators.push_back(std::move(gc));
        }
    }
    {
        uint16_t n = r.u16("initial_balances.count");
        for (uint16_t i = 0; i < n; ++i) {
            GenesisAllocation a;
            a.domain  = r.lp16("initial_balance.domain");
            a.balance = r.u64("initial_balance.balance");
            c.initial_balances.push_back(std::move(a));
        }
    }
    {
        uint16_t n = r.u16("beacon_shard_regions.count");
        for (uint16_t i = 0; i < n; ++i) {
            ShardId sid = r.u32("beacon_shard_regions.shard_id");
            std::string region =
                canonical_region(r.lp8("beacon_shard_regions.committee_region"),
                                  "beacon_shard_regions.committee_region");
            // Strictly ascending: rejects both unsorted and duplicate entries,
            // so the sorted canonical order has exactly one byte encoding.
            if (i > 0 && sid <= c.shard_regions.back().first)
                throw std::runtime_error(
                    "genesis decode: beacon_shard_regions must be strictly "
                    "ascending by shard_id (got " + std::to_string(sid)
                    + " after " + std::to_string(c.shard_regions.back().first) + ")");
            c.shard_regions.emplace_back(sid, std::move(region));
        }
    }

    // EXACT consumption both directions: a trailing byte is as fatal as a
    // missing one.
    if (r.i != len)
        throw std::runtime_error(
            "genesis decode: " + std::to_string(len - r.i)
            + " trailing byte(s) after the DGC1 frame");

    c.validate();
    return c;
}

GenesisConfig GenesisConfig::load(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open genesis config: " + path);
    std::string bytes((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    return decode(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
}

void GenesisConfig::save(const std::string& path) const {
    // Atomic tmp+rename: a crash mid-write cannot leave a half-written genesis
    // file that would decode-reject on the next start.
    // A bare file name has no parent; create_directories("") throws.
    const fs::path dir = fs::path(path).parent_path();
    if (!dir.empty()) fs::create_directories(dir);
    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) throw std::runtime_error("Cannot write genesis config: " + tmp);
        const std::vector<uint8_t> bytes = encode();
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        f.flush();
        if (!f) throw std::runtime_error("Failed to flush genesis config: " + tmp);
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) throw std::runtime_error("Cannot rename genesis tmp " + tmp
        + " → " + path + ": " + ec.message());
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

    // E1: seed the Zeroth pool pseudo-account when zeroth_pool_initial > 0.
    // The pool address is the canonical all-zero anon address. The pool's
    // balance feeds NEF (Negative Entry Fee) distributions on subsequent
    // REGISTER applies. Counts toward A1's genesis_total_ via the normal
    // initial_state[] path — no separate accounting needed.
    if (cfg.zeroth_pool_initial > 0) {
        bool merged = false;
        for (auto& a : g.initial_state) {
            if (a.domain == ZEROTH_ADDRESS) {
                a.balance += cfg.zeroth_pool_initial;
                merged = true;
                break;
            }
        }
        if (!merged) {
            GenesisAlloc a;
            a.domain  = ZEROTH_ADDRESS;
            a.balance = cfg.zeroth_pool_initial;
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
    // Inscribed genesis_message: mix only when it differs from the default.
    // Pre-message genesis files (which load with the default via
    // GenesisConfig::from_json) remain byte-identical to pre-message
    // chain hashes — backward-compat invariant. Explicit empty override
    // and any custom inscription both produce distinct chain hashes.
    // Length-prefixed (u64 BE, matching Preliminaries §1.3's multi-byte
    // integer encoding convention used throughout signing_bytes /
    // compute_block_digest / compute_genesis_hash) so the encoding is
    // unambiguous: a 0-byte message hashes to a different value than
    // an absent message (the absent path skips the mix entirely).
    if (cfg.genesis_message != DEFAULT_GENESIS_MESSAGE) {
        rb.append(static_cast<uint64_t>(cfg.genesis_message.size()));
        rb.append(cfg.genesis_message);
    }
    for (auto& c : cfg.initial_creators) rb.append(c.ed_pub.data(), c.ed_pub.size());
    // A5: governance fields. governance_mode == 0 (uncontrolled) and
    // empty keyholders is the pre-A5 default; skip the mix entirely
    // so legacy / uncontrolled genesis files remain byte-identical
    // (backward-compat invariant: pre-A5 hashes are preserved).
    if (cfg.governance_mode != 0 || !cfg.param_keyholders.empty()) {
        rb.append(static_cast<uint8_t>(cfg.governance_mode));
        rb.append(static_cast<uint8_t>(cfg.param_keyholders.size()));
        for (auto& k : cfg.param_keyholders)
            rb.append(k.data(), k.size());
        rb.append(static_cast<uint64_t>(cfg.param_threshold));
    }
    // A5 Phase 3: include suspension_slash / unstake_delay in the hash
    // only when they diverge from the pre-A5 defaults. Pre-A5 genesis
    // files retain byte-identical hashes (forward-compat-safe).
    if (cfg.suspension_slash != 10 || cfg.unstake_delay != 1000) {
        rb.append(cfg.suspension_slash);
        rb.append(cfg.unstake_delay);
    }
    // R4: under-quorum merge thresholds mixed only when non-default,
    // preserving pre-R4 genesis hashes.
    if (cfg.merge_threshold_blocks  != 100
        || cfg.revert_threshold_blocks != 200
        || cfg.merge_grace_blocks   != 10) {
        rb.append(static_cast<uint64_t>(cfg.merge_threshold_blocks));
        rb.append(static_cast<uint64_t>(cfg.revert_threshold_blocks));
        rb.append(static_cast<uint64_t>(cfg.merge_grace_blocks));
    }
    // D1: the CONFIDENTIAL-TX disable flag is consensus-critical — two operators
    // who differ on it must NOT compute the same genesis_hash (one accepts a
    // SHIELD/UNSHIELD/CONFIDENTIAL_TRANSFER the other rejects → a silent fork).
    // Bind it with the same "mix only when non-default" idiom as the fields
    // above so CT-ENABLED (default) chains keep byte-identical genesis hashes,
    // while a DISABLED chain mixes a distinct domain-tagged marker → a distinct
    // hash. Presence of the tag (vs its absence) is the whole signal, so a bare
    // tag suffices; domain-separated so it can never alias an adjacent mix.
    if (!cfg.confidential_tx_enabled) {
        rb.append(std::string("DTM-genesis-ct-disabled-v1"));
    }
    // NC-8 profile gating: the crypto profile selects the encrypted-note wiring
    // (delivery placement + recipient-key derivation) + the state-root surface,
    // so two operators who differ on it must NOT share a genesis hash. Mix a
    // value-tagged marker with the same "mix only when non-default" idiom, so
    // MODERN (default) chains keep byte-identical genesis hashes.
    if (cfg.crypto_profile != CryptoProfile::MODERN) {
        rb.append(std::string("DTM-genesis-crypto-profile-v1"));
        rb.append(static_cast<uint64_t>(cfg.crypto_profile));
    }
    // D3.5e-1 (S-036 Layer 2): the shard→region map is consensus-critical on
    // a BEACON chain — it is the committed region input to shard-tip
    // verification, so two beacons that differ on it must NOT share a
    // genesis hash (one verifies a committee the other rejects). Mixed only
    // when non-empty (the "mix only when non-default" idiom above): every
    // existing genesis file keeps a byte-identical hash. Entries are in
    // canonical shard_id order (from_json sorts), each length-prefixed.
    if (!cfg.shard_regions.empty()) {
        rb.append(std::string("DTM-genesis-shard-regions-v1"));
        rb.append(static_cast<uint64_t>(cfg.shard_regions.size()));
        for (auto& [sid, region] : cfg.shard_regions) {
            rb.append(static_cast<uint64_t>(sid));
            rb.append(static_cast<uint8_t>(region.size()));
            rb.append(region);
        }
    }
    // S-039 closure: bind ALL consensus-critical operational parameters
    // into the genesis hash UNCONDITIONALLY. Pre-fix these governed
    // consensus behaviour (committee size K, Phase-2 quorum, E1/E3
    // economics, sharding, BFT escalation, epoch length, routing salt)
    // but were NOT part of the chain identity, so two operators whose
    // configs differed in any of them computed the SAME genesis_hash and
    // then silently failed to converge (different K-committees -> block
    // signatures never gather -> chain stalls with no clear cause). Now a
    // mismatch in any of these yields a DIFFERENT genesis_hash, rejected
    // at the HELLO genesis-hash handshake with a clear diagnostic. Bound
    // UNCONDITIONALLY (no "only when non-default" backward-compat guard
    // like the older optional mixes above): there is no pre-existing
    // installed base to preserve byte-compat for, and unconditional
    // binding has no default-value collision edge cases. Domain-separated
    // by its own tag so the field block can never alias the preceding
    // optional mixes.
    rb.append(std::string("DTM-genesis-ops-v1"));
    rb.append(static_cast<uint64_t>(cfg.m_creators));
    rb.append(static_cast<uint64_t>(cfg.k_block_sigs));
    rb.append(cfg.block_subsidy);
    rb.append(cfg.subsidy_pool_initial);
    rb.append(static_cast<uint8_t>(cfg.subsidy_mode));
    rb.append(static_cast<uint64_t>(cfg.lottery_jackpot_multiplier));
    rb.append(cfg.min_stake);
    rb.append(static_cast<uint64_t>(cfg.initial_shard_count));
    rb.append(static_cast<uint8_t>(cfg.bft_enabled ? 1 : 0));
    rb.append(static_cast<uint64_t>(cfg.bft_escalation_threshold));
    rb.append(static_cast<uint64_t>(cfg.epoch_blocks));
    rb.append(cfg.shard_address_salt.data(), cfg.shard_address_salt.size());
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
