// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/node/node.hpp>
#include <determ/rpc/rpc.hpp>
#include <determ/chain/block.hpp>
#include <determ/chain/params.hpp>
#include <determ/crypto/keys.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/net/messages.hpp>
#include <asio.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <cstdlib>
#include <cstring>

namespace fs = std::filesystem;
using json = nlohmann::json;
using namespace determ;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static std::string default_data_dir() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    return appdata ? std::string(appdata) + "\\determ" : ".determ";
#else
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/.determ" : ".determ";
#endif
}

static std::string config_path(const std::string& data_dir) {
    return data_dir + "/config.json";
}

static void usage() {
    std::cout << R"(Determ — fork-free DH-consensus cryptocurrency

Usage:
  determ init [--data-dir <dir>] [--profile cluster|web|regional|global|tactical|single_test|cluster_test|web_test|regional_test|global_test|tactical_test]
                                              [--genesis <config.json>]
                                              Generate node keys and config
  determ register <domain> [--rpc-port <p>]  Submit RegisterTx to running node
  determ start [--config <path>]             Start node (sync + participate in consensus)
  determ send <to_domain> <amount>           Submit TRANSFER transaction
  determ status                              Chain head, node count, next creators
  determ show-block <index>                  Print block at index (full JSON)
  determ chain-summary [--last N]            Compact summary of last N blocks
  determ validators                          List the current validator pool
  determ committee                           List the current epoch's K-of-K committee
  determ show-account <address>              Inspect any address (balance, nonce, registry, stake)
  determ show-tx <hash>                      Look up a tx by hash (block_index + payload)
  determ snapshot create [--out f]           Dump current chain state for fast bootstrap (B6.basic)
  determ snapshot inspect --in f             Validate + summarize a snapshot file (round-trip check)
  determ snapshot fetch --peer h:p --out f   Fetch a snapshot from a running node over the gossip wire
  determ peers                               List connected peers
  determ balance [<domain>]                  Show domain balance
  determ stake <amount> [--fee <n>]          Lock <amount> as registration stake
  determ unstake <amount> [--fee <n>]        Release stake (after deregister + delay)
  determ nonce [<domain>]                    Show next account nonce
  determ stake_info [<domain>]               Show locked stake and unlock height
  determ genesis-tool peer-info <domain>     Print this node's creator entry (JSON)
                                              for inclusion in a genesis config.
  determ genesis-tool build <config.json>    Build a genesis from peer-info entries
  determ genesis-tool build-sharded <cfg>    Stage B2: produce 1 beacon + S shard genesis files
                                              and print the genesis hash.
  determ account create [--out <file>]       Generate a fresh anonymous account
                                              keypair (Ed25519). Prints address + privkey.
  determ account address <privkey_hex>       Derive the account address from a hex privkey.
  determ send_anon <to> <amount> <privkey_hex>
                                              Sign a TRANSFER from the anon account
                                              corresponding to <privkey_hex> and submit
                                              via the daemon's submit_tx RPC.
)" << "\n";
}

// ─── Commands ────────────────────────────────────────────────────────────────

static int cmd_init(int argc, char** argv) {
    std::string data_dir     = default_data_dir();
    std::string profile      = "web";
    std::string genesis_path = "";
    for (int i = 0; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--data-dir") data_dir     = argv[i + 1];
        if (std::string(argv[i]) == "--profile")  profile      = argv[i + 1];
        if (std::string(argv[i]) == "--genesis")  genesis_path = argv[i + 1];
    }

    fs::create_directories(data_dir);
    std::string kpath = data_dir + "/node_key.json";
    std::string cpath = config_path(data_dir);
    std::string chain_path = data_dir + "/chain.json";

    if (fs::exists(kpath)) {
        std::cout << "Key already exists at " << kpath << " (skipping keygen)\n";
    } else {
        auto key = crypto::generate_node_key();
        crypto::save_node_key(key, kpath);
        std::cout << "Generated node key: pubkey=" << to_hex(key.pub) << "\n";
    }

    node::Config cfg;
    cfg.data_dir   = data_dir;
    cfg.key_path   = kpath;
    cfg.chain_path = chain_path;
    cfg.listen_port = 7777;
    cfg.rpc_port    = 7778;

    chain::TimingProfile tp = chain::PROFILE_WEB;
    if      (profile == "cluster")        tp = chain::PROFILE_CLUSTER;
    else if (profile == "regional")       tp = chain::PROFILE_REGIONAL;
    else if (profile == "global")         tp = chain::PROFILE_GLOBAL;
    else if (profile == "tactical")       tp = chain::PROFILE_TACTICAL;
    else if (profile == "single_test")    tp = chain::PROFILE_SINGLE_TEST;
    else if (profile == "cluster_test")   tp = chain::PROFILE_CLUSTER_TEST;
    else if (profile == "web_test")       tp = chain::PROFILE_WEB_TEST;
    else if (profile == "regional_test")  tp = chain::PROFILE_REGIONAL_TEST;
    else if (profile == "global_test")    tp = chain::PROFILE_GLOBAL_TEST;
    else if (profile == "tactical_test")  tp = chain::PROFILE_TACTICAL_TEST;
    else if (profile != "web") {
        std::cerr << "Unknown --profile " << profile
                  << " (expected: cluster|web|regional|global|tactical|"
                  << "single_test|cluster_test|web_test|regional_test|global_test|tactical_test)\n";
        return 1;
    }
    cfg.tx_commit_ms   = tp.tx_commit_ms;
    cfg.block_sig_ms   = tp.block_sig_ms;
    cfg.abort_claim_ms = tp.abort_claim_ms;
    cfg.m_creators     = tp.m_creators;
    cfg.k_block_sigs   = tp.k_block_sigs;
    // A6: pin chain_role + sharding_mode from the chosen profile so
    // cmd_start can hand them to the validator without re-resolving the
    // profile. Genesis remains the source of truth at runtime — Node's
    // ctor cross-checks gcfg.chain_role against cfg_.chain_role and
    // gates loadtime on cfg_.sharding_mode (see node.cpp).
    cfg.chain_role     = tp.chain_role;
    cfg.sharding_mode  = tp.sharding_mode;

    if (!genesis_path.empty()) {
        cfg.genesis_path = genesis_path;
        try {
            auto gcfg = chain::GenesisConfig::load(genesis_path);
            cfg.genesis_hash = to_hex(chain::compute_genesis_hash(gcfg));
            std::cout << "Pinned genesis hash: " << cfg.genesis_hash << "\n";
        } catch (std::exception& e) {
            std::cerr << "Warning: could not load genesis at " << genesis_path
                      << " (" << e.what() << "); pin left empty\n";
        }
    }

    cfg.save(cpath);

    const char* mode = (cfg.k_block_sigs == cfg.m_creators) ? "strong" : "weak";
    std::cout << "Config written to " << cpath
              << " (profile: " << profile
              << ", M=" << cfg.m_creators
              << ", K=" << cfg.k_block_sigs
              << ", mode=" << mode << ")\n";
    std::cout << "Edit the config to set your domain and bootstrap peers, then run:\n";
    std::cout << "  determ start\n";
    return 0;
}

static int cmd_start(int argc, char** argv) {
    std::string data_dir = default_data_dir();
    std::string cfg_path;
    for (int i = 0; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--config")   cfg_path = argv[i + 1];
        if (std::string(argv[i]) == "--data-dir") data_dir = argv[i + 1];
    }
    if (cfg_path.empty()) cfg_path = config_path(data_dir);

    try {
        auto cfg = node::Config::load(cfg_path);

        if (cfg.key_path.empty()) cfg.key_path = cfg.data_dir + "/node_key.json";
        if (!fs::exists(cfg.key_path)) {
            auto key = crypto::generate_node_key();
            crypto::save_node_key(key, cfg.key_path);
            std::cout << "[init] Generated node key\n" << std::flush;
        }
        if (cfg.chain_path.empty()) cfg.chain_path = cfg.data_dir + "/chain.json";

        std::cout << "[determ] Loading node domain=" << cfg.domain
                  << " genesis_path=" << cfg.genesis_path << "\n" << std::flush;

        node::Node node(cfg);

        rpc::RpcServer rpc_server(node.io_context_access(), node,
                                       cfg.rpc_port, cfg.rpc_localhost_only);
        rpc_server.start();

        std::cout << "[determ] Starting node domain=" << cfg.domain
                  << " port=" << cfg.listen_port << "\n" << std::flush;
        node.run(); // blocks
        return 0;
    } catch (std::exception& e) {
        std::cerr << "[determ] FATAL: " << e.what() << std::endl;
        std::cerr.flush();
        return 1;
    } catch (...) {
        std::cerr << "[determ] FATAL: unknown exception" << std::endl;
        std::cerr.flush();
        return 1;
    }
}

static uint16_t get_rpc_port(int argc, char** argv) {
    for (int i = 0; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--rpc-port")
            return static_cast<uint16_t>(std::stoi(argv[i + 1]));
    return 7778;
}

// Bounded auto-retry for tx submissions: re-resolves nonce on each attempt,
// returns the last response or an error after `max_retries` failures.
// "Failure" here means the RPC raised a nonce-mismatch error or returned a
// queued tx that still hadn't been included after `retry_window_blocks`
// of polling. The retry_window check is cheap (status RPC).
static int submit_tx_with_retry(uint16_t port,
                                 const std::string& method,
                                 nlohmann::json params,
                                 int max_retries = 3) {
    for (int attempt = 0; attempt < max_retries; ++attempt) {
        try {
            auto result = rpc::rpc_call("127.0.0.1", port, method, params);
            std::cout << result.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::string msg = e.what();
            // Re-attempt only on transient nonce-mismatch errors. Other errors
            // are non-retryable.
            if (msg.find("nonce") == std::string::npos || attempt + 1 == max_retries) {
                std::cerr << "Error: " << msg << "\n";
                return 1;
            }
            std::cerr << "[retry " << (attempt + 1) << "] " << msg << "\n";
        }
    }
    return 1;
}

static int cmd_register(int argc, char** argv) {
    if (argc < 1) { std::cerr << "Usage: determ register <domain>\n"; return 1; }
    std::string domain   = argv[0];
    uint16_t    rpc_port = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", rpc_port, "register",
                                    {{"domain", domain}});
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

static int cmd_send(int argc, char** argv) {
    if (argc < 2) { std::cerr << "Usage: determ send <to_domain> <amount> [--fee <n>]\n"; return 1; }
    std::string to     = argv[0];
    uint64_t    amount = std::stoull(argv[1]);
    uint64_t    fee    = 0;
    uint16_t    port   = get_rpc_port(argc, argv);
    for (int i = 2; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--fee") fee = std::stoull(argv[i + 1]);
    return submit_tx_with_retry(port, "send",
        {{"to", to}, {"amount", amount}, {"fee", fee}});
}

static int cmd_status(int argc, char** argv) {
    uint16_t port = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "status");
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error (is the node running?): " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ show-block <index> [--rpc-port N]
//   Prints the full block at the given index from a running node.
static int cmd_show_block(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ show-block <index> [--rpc-port N]\n";
        return 1;
    }
    uint64_t index = std::stoull(argv[0]);
    uint16_t port = get_rpc_port(argc, argv);
    try {
        json params = {{"index", index}};
        auto result = rpc::rpc_call("127.0.0.1", port, "block", params);
        if (result.is_null()) {
            std::cerr << "Block " << index << " out of range (chain.height too low)\n";
            return 1;
        }
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ validators [--rpc-port N]
//   Lists the current validator pool (registered + active + staked +
//   not suspended) with each entry's domain, pubkey, stake, active_from.
static int cmd_validators(int argc, char** argv) {
    uint16_t port = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "validators");
        if (!result.is_array() || result.empty()) {
            std::cout << "(no eligible validators)\n";
            return 0;
        }
        std::cout << std::left
                  << std::setw(25) << "domain"
                  << std::setw(10) << "stake"
                  << std::setw(15) << "active_from"
                  << "ed_pub\n";
        for (auto& v : result) {
            std::cout << std::setw(25) << v.value("domain", std::string{})
                      << std::setw(10) << v.value("stake", uint64_t{0})
                      << std::setw(15) << v.value("active_from", uint64_t{0})
                      << v.value("ed_pub", std::string{}).substr(0, 24) << "...\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ chain-summary [--last N] [--rpc-port N]
//   Prints a compact summary of the last N blocks (default 10).
static int cmd_chain_summary(int argc, char** argv) {
    uint32_t last_n = 10;
    for (int i = 0; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--last") {
            last_n = static_cast<uint32_t>(std::stoul(argv[i + 1]));
        }
    }
    uint16_t port = get_rpc_port(argc, argv);
    try {
        json params = {{"last_n", last_n}};
        auto result = rpc::rpc_call("127.0.0.1", port, "chain_summary", params);
        // A1: chain_summary now returns an object {blocks: [...], total_supply,
        // genesis_total, expected_total, accumulated_*}. Backward-compat note:
        // an array result (legacy server) is still accepted as the blocks list.
        json blocks = result.is_array() ? result : result.value("blocks", json::array());
        for (auto& b : blocks) {
            std::cout << "#" << std::setw(6) << std::left << b.value("index", uint64_t{0})
                      << " mode=" << b.value("consensus_mode", 0)
                      << " txs=" << std::setw(3) << std::left << b.value("tx_count", 0)
                      << " creators=" << b.value("creators", json::array()).dump()
                      << " hash=" << b.value("hash", std::string{}).substr(0, 12)
                      << "\n";
        }
        if (result.is_object()) {
            std::cout << "height=" << result.value("height", uint64_t{0})
                      << " total_supply=" << result.value("total_supply", uint64_t{0})
                      << " genesis_total=" << result.value("genesis_total", uint64_t{0})
                      << " (subsidy=+" << result.value("accumulated_subsidy", uint64_t{0})
                      << " inbound=+" << result.value("accumulated_inbound", uint64_t{0})
                      << " slashed=-" << result.value("accumulated_slashed", uint64_t{0})
                      << " outbound=-" << result.value("accumulated_outbound", uint64_t{0})
                      << ")\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ committee [--rpc-port N]
//   Print the current epoch's K-of-K committee (the creators producing
//   blocks right now). Pure function of chain state — deterministic
//   across all nodes on the same chain at the same height.
static int cmd_committee(int argc, char** argv) {
    uint16_t port = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "committee");
        if (!result.is_array() || result.empty()) {
            std::cout << "(empty committee — chain has no eligible validators yet)\n";
            return 0;
        }
        std::cout << std::left
                  << std::setw(25) << "domain"
                  << std::setw(10) << "stake"
                  << std::setw(15) << "active_from"
                  << "ed_pub\n";
        for (auto& v : result) {
            std::cout << std::setw(25) << v.value("domain", std::string{})
                      << std::setw(10) << v.value("stake", uint64_t{0})
                      << std::setw(15) << v.value("active_from", uint64_t{0})
                      << v.value("ed_pub", std::string{}).substr(0, 24) << "...\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ show-account <address> [--rpc-port N]
//   Inspect on-chain state for an arbitrary address (registered domain or
//   anonymous bearer wallet). Prints balance, next nonce, and registry
//   info + stake when the address is a registered validator.
static int cmd_show_account(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ show-account <address> [--rpc-port N]\n";
        return 1;
    }
    std::string addr = argv[0];
    uint16_t port = get_rpc_port(argc, argv);
    try {
        json params = {{"address", addr}};
        auto result = rpc::rpc_call("127.0.0.1", port, "account", params);
        if (result.is_null()) {
            std::cout << "(no on-chain state for " << addr << ")\n";
            return 0;
        }
        std::cout << "address      : " << result.value("address", std::string{}) << "\n";
        std::cout << "anonymous    : " << (result.value("is_anonymous", false) ? "yes" : "no") << "\n";
        std::cout << "balance      : " << result.value("balance", uint64_t{0}) << "\n";
        std::cout << "next_nonce   : " << result.value("next_nonce", uint64_t{0}) << "\n";
        std::cout << "stake        : " << result.value("stake", uint64_t{0}) << "\n";
        if (result.contains("registry") && !result["registry"].is_null()) {
            auto& r = result["registry"];
            std::cout << "registry     :\n";
            std::cout << "  ed_pub       : " << r.value("ed_pub", std::string{}) << "\n";
            std::cout << "  registered_at: " << r.value("registered_at", uint64_t{0}) << "\n";
            std::cout << "  active_from  : " << r.value("active_from", uint64_t{0}) << "\n";
            std::cout << "  inactive_from: " << r.value("inactive_from", uint64_t{0}) << "\n";
        } else {
            std::cout << "registry     : (not registered)\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ snapshot create [--out file.json] [--headers N] [--rpc-port N]
//   B6.basic: dump chain state (accounts, stakes, registrants, dedup,
//   tail headers) to a file. Operators host this for fast-bootstrap of
//   new nodes — restoring from a snapshot avoids replaying every block
//   from genesis. The result is JSON; a typical snapshot for a mature
//   chain is much smaller than the full chain.json. v1 verification
//   model: trust the source + post-restore consistency check (replay
//   the next handful of blocks); v2 adds state roots in the block
//   format for cryptographic verification.
static int cmd_snapshot_create(int argc, char** argv) {
    std::string out_path;
    uint32_t    header_count = 16;
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if (a == "--out")     out_path = argv[i + 1];
        if (a == "--headers") header_count = static_cast<uint32_t>(
                                    std::stoul(argv[i + 1]));
    }
    uint16_t port = get_rpc_port(argc, argv);
    try {
        json params = {{"headers", header_count}};
        auto result = rpc::rpc_call("127.0.0.1", port, "snapshot", params);
        std::string text = result.dump(2);
        if (out_path.empty()) {
            std::cout << text << "\n";
        } else {
            std::ofstream f(out_path);
            if (!f) { std::cerr << "Cannot write " << out_path << "\n"; return 1; }
            f << text << "\n";
            std::cout << "Snapshot written to " << out_path << "\n";
            std::cout << "  block_index : "
                      << result.value("block_index", uint64_t{0}) << "\n";
            std::cout << "  head_hash   : "
                      << result.value("head_hash", std::string{}) << "\n";
            std::cout << "  accounts    : "
                      << result.value("accounts", json::array()).size() << "\n";
            std::cout << "  stakes      : "
                      << result.value("stakes", json::array()).size() << "\n";
            std::cout << "  registrants : "
                      << result.value("registrants", json::array()).size() << "\n";
            std::cout << "  headers     : "
                      << result.value("headers", json::array()).size() << "\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ snapshot fetch --peer host:port --out file.json [--headers N]
//   B6.basic: connect to a running node, send a SNAPSHOT_REQUEST over
//   the gossip-wire protocol, write the response to a file. Pure
//   network client; no genesis or chain config needed locally. After
//   fetch, validates by round-tripping through restore_from_snapshot
//   (head_hash sanity check). Operator workflow:
//     determ snapshot fetch --peer 1.2.3.4:7771 --out snap.json
//     # ... edit config to set snapshot_path = snap.json ...
//     determ start
static int cmd_snapshot_fetch(int argc, char** argv) {
    std::string peer_str, out_path;
    uint32_t header_count = 16;
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if (a == "--peer")    peer_str    = argv[i + 1];
        if (a == "--out")     out_path    = argv[i + 1];
        if (a == "--headers") header_count = static_cast<uint32_t>(
                                    std::stoul(argv[i + 1]));
    }
    if (peer_str.empty() || out_path.empty()) {
        std::cerr << "Usage: determ snapshot fetch --peer host:port "
                     "--out file.json [--headers N]\n";
        return 1;
    }
    auto colon = peer_str.find(':');
    if (colon == std::string::npos) {
        std::cerr << "peer must be host:port\n";
        return 1;
    }
    std::string host = peer_str.substr(0, colon);
    uint16_t    port = static_cast<uint16_t>(std::stoi(peer_str.substr(colon + 1)));

    try {
        asio::io_context io;
        asio::ip::tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(host, std::to_string(port));
        asio::ip::tcp::socket socket(io);
        asio::connect(socket, endpoints);

        auto write_msg = [&](const net::Message& msg) {
            auto buf = msg.serialize();
            asio::write(socket, asio::buffer(buf));
        };

        // HELLO so the peer doesn't drop us. We tag ourselves as
        // SINGLE/0 — bootstrap clients don't claim a chain identity.
        write_msg(net::make_hello("snapshot-fetcher", 0,
                                    ChainRole::SINGLE, 0));
        write_msg(net::make_snapshot_request(header_count));

        // Read framed messages until SNAPSHOT_RESPONSE arrives. Skip
        // any others (peer might gossip blocks/headers in the
        // meantime).
        std::array<uint8_t, 4> hdr;
        for (int spin = 0; spin < 200; ++spin) {
            asio::read(socket, asio::buffer(hdr));
            uint32_t len = (uint32_t(hdr[0]) << 24)
                         | (uint32_t(hdr[1]) << 16)
                         | (uint32_t(hdr[2]) << 8)
                         |  uint32_t(hdr[3]);
            if (len == 0 || len > 16 * 1024 * 1024) {
                std::cerr << "fetch: bad frame length " << len << "\n";
                return 1;
            }
            std::vector<uint8_t> body(len);
            asio::read(socket, asio::buffer(body));
            net::Message m = net::Message::deserialize(body.data(), body.size());
            if (m.type != net::MsgType::SNAPSHOT_RESPONSE) continue;

            // Validate by round-trip through restore_from_snapshot.
            chain::Chain c = chain::Chain::restore_from_snapshot(m.payload);
            std::ofstream f(out_path);
            if (!f) { std::cerr << "Cannot write " << out_path << "\n"; return 1; }
            f << m.payload.dump(2) << "\n";
            std::cout << "Snapshot fetched from " << peer_str << "\n";
            std::cout << "  block_index : " << (c.empty() ? 0 : c.head().index) << "\n";
            std::cout << "  head_hash   : "
                      << (c.empty() ? std::string{} : to_hex(c.head_hash())) << "\n";
            std::cout << "  accounts    : " << c.accounts().size()    << "\n";
            std::cout << "  stakes      : " << c.stakes().size()      << "\n";
            std::cout << "  registrants : " << c.registrants().size() << "\n";
            std::cout << "  written to  : " << out_path << "\n";
            return 0;
        }
        std::cerr << "fetch: timed out waiting for SNAPSHOT_RESPONSE\n";
        return 1;
    } catch (std::exception& e) {
        std::cerr << "fetch error: " << e.what() << "\n";
        return 1;
    }
}

// determ snapshot inspect --in file.json
//   Round-trips a snapshot through Chain::restore_from_snapshot and
//   prints a human-readable summary. Validates JSON format, version,
//   and head_hash consistency (rejects loudly on mismatch). Useful
//   before staging a snapshot for fast-bootstrap of a new node.
static int cmd_snapshot_inspect(int argc, char** argv) {
    std::string in_path;
    for (int i = 0; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--in") in_path = argv[i + 1];
    if (in_path.empty()) {
        std::cerr << "Usage: determ snapshot inspect --in <file>\n";
        return 1;
    }
    try {
        std::ifstream f(in_path);
        if (!f) { std::cerr << "Cannot open " << in_path << "\n"; return 1; }
        json snap = json::parse(f);
        chain::Chain c = chain::Chain::restore_from_snapshot(snap);
        std::cout << "snapshot OK: " << in_path << "\n";
        std::cout << "  block_index : "
                  << (c.empty() ? 0 : c.head().index) << "\n";
        std::cout << "  head_hash   : "
                  << (c.empty() ? std::string{} : to_hex(c.head_hash()))
                  << "\n";
        std::cout << "  accounts    : " << c.accounts().size()    << "\n";
        std::cout << "  stakes      : " << c.stakes().size()      << "\n";
        std::cout << "  registrants : " << c.registrants().size() << "\n";
        std::cout << "  block_subsidy: " << c.block_subsidy()     << "\n";
        std::cout << "  min_stake   : " << c.min_stake()          << "\n";
        std::cout << "  shard_count : " << c.shard_count()        << "\n";
        std::cout << "  shard_id    : " << c.my_shard_id()        << "\n";
        std::cout << "  tail headers: " << c.height()             << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

static int cmd_snapshot(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ snapshot {create|inspect} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "create")  return cmd_snapshot_create (argc - 1, argv + 1);
    if (sub == "inspect") return cmd_snapshot_inspect(argc - 1, argv + 1);
    if (sub == "fetch")   return cmd_snapshot_fetch  (argc - 1, argv + 1);
    std::cerr << "Unknown snapshot subcommand: " << sub << "\n";
    return 1;
}

// determ show-tx <hash> [--rpc-port N]
//   Look up a transaction by its hex-encoded hash. Reports the tx
//   payload, the block it landed in, and the block's timestamp.
static int cmd_show_tx(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ show-tx <hash> [--rpc-port N]\n";
        return 1;
    }
    std::string hash_hex = argv[0];
    uint16_t port = get_rpc_port(argc, argv);
    try {
        json params = {{"hash", hash_hex}};
        auto result = rpc::rpc_call("127.0.0.1", port, "tx", params);
        if (result.is_null()) {
            std::cout << "(tx " << hash_hex.substr(0, 16) << "... not found in any finalized block)\n";
            return 0;
        }
        std::cout << "block_index : " << result.value("block_index", uint64_t{0}) << "\n";
        std::cout << "block_hash  : " << result.value("block_hash", std::string{}) << "\n";
        std::cout << "timestamp   : " << result.value("timestamp", int64_t{0}) << "\n";
        std::cout << "transaction :\n";
        std::cout << result["tx"].dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

static int cmd_peers(int argc, char** argv) {
    uint16_t port = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "peers");
        if (result.empty()) { std::cout << "(no peers connected)\n"; return 0; }
        for (auto& p : result) std::cout << "  " << p.get<std::string>() << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

static int cmd_balance(int argc, char** argv) {
    std::string domain = (argc >= 1) ? argv[0] : "";
    uint16_t    port   = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "balance", {{"domain", domain}});
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

static int cmd_stake(int argc, char** argv) {
    if (argc < 1) { std::cerr << "Usage: determ stake <amount> [--fee <n>]\n"; return 1; }
    uint64_t amount = std::stoull(argv[0]);
    uint64_t fee    = 0;
    uint16_t port   = get_rpc_port(argc, argv);
    for (int i = 1; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--fee") fee = std::stoull(argv[i + 1]);
    return submit_tx_with_retry(port, "stake", {{"amount", amount}, {"fee", fee}});
}

static int cmd_unstake(int argc, char** argv) {
    if (argc < 1) { std::cerr << "Usage: determ unstake <amount> [--fee <n>]\n"; return 1; }
    uint64_t amount = std::stoull(argv[0]);
    uint64_t fee    = 0;
    uint16_t port   = get_rpc_port(argc, argv);
    for (int i = 1; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--fee") fee = std::stoull(argv[i + 1]);
    return submit_tx_with_retry(port, "unstake", {{"amount", amount}, {"fee", fee}});
}

static int cmd_nonce(int argc, char** argv) {
    std::string domain = (argc >= 1) ? argv[0] : "";
    uint16_t    port   = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "nonce", {{"domain", domain}});
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// genesis-tool peer-info <domain>
//   Loads the node's local Ed25519 key and prints the JSON entry the operator
//   should send to whoever is assembling the genesis config. Possession of the
//   private key is proved later at REGISTER time (the on-chain REGISTER tx is
//   signed by the same key), so no separate proof-of-possession is emitted here.
static int cmd_genesis_tool_peer_info(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ genesis-tool peer-info <domain> [--data-dir <dir>] [--stake <n>]\n";
        return 1;
    }
    std::string domain   = argv[0];
    std::string data_dir = default_data_dir();
    uint64_t    stake    = chain::MIN_STAKE;
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--data-dir") data_dir = argv[i + 1];
        if (std::string(argv[i]) == "--stake")    stake    = std::stoull(argv[i + 1]);
    }

    std::string kpath = data_dir + "/node_key.json";
    if (!fs::exists(kpath)) {
        std::cerr << "Key not found at " << kpath
                  << " (run 'determ init --data-dir " << data_dir << "' first)\n";
        return 1;
    }
    auto key = crypto::load_node_key(kpath);

    json entry = {
        {"domain",        domain},
        {"ed_pub",        to_hex(key.pub)},
        {"initial_stake", stake}
    };
    std::cout << entry.dump(2) << "\n";
    return 0;
}

// genesis-tool build <config.json>
//   Loads a GenesisConfig (with all initial_creators + initial_balances),
//   validates K/M bounds, prints the resulting genesis hash, and writes
//   <config>.hash next to the file for convenient distribution.
static int cmd_genesis_tool_build(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ genesis-tool build <genesis_config.json>\n";
        return 1;
    }
    std::string path = argv[0];
    try {
        auto cfg  = chain::GenesisConfig::load(path);
        if (cfg.k_block_sigs == 0 || cfg.k_block_sigs > cfg.m_creators) {
            std::cerr << "Genesis invalid: k_block_sigs=" << cfg.k_block_sigs
                      << " must satisfy 1 <= K <= M=" << cfg.m_creators << "\n";
            return 1;
        }
        auto hash = chain::compute_genesis_hash(cfg);
        std::string hex = to_hex(hash);
        const char* mode = (cfg.k_block_sigs == cfg.m_creators) ? "strong" : "weak";
        std::cout << "Genesis chain_id:   " << cfg.chain_id           << "\n";
        std::cout << "Chain role:         " << to_string(cfg.chain_role)
                  << " (shard_id=" << cfg.shard_id
                  << ", S=" << cfg.initial_shard_count
                  << ", E=" << cfg.epoch_blocks << ")\n";
        std::cout << "M_creators:         " << cfg.m_creators         << "\n";
        std::cout << "K_block_sigs:       " << cfg.k_block_sigs       << "\n";
        std::cout << "Mode:               " << mode << " (default: mutual-distrust K-of-K)\n";
        std::cout << "Inclusion:          " << chain::to_string(cfg.inclusion_model)
                  << " (min_stake=" << cfg.min_stake << ")\n";
        std::cout << "BFT escalation:     "
                  << (cfg.bft_enabled
                      ? ("enabled, threshold=" + std::to_string(cfg.bft_escalation_threshold) + " round-1 aborts")
                      : "disabled (chain halts on persistent silent committee member)")
                  << "\n";
        std::cout << "Initial creators:   " << cfg.initial_creators.size() << "\n";
        std::cout << "Initial balances:   " << cfg.initial_balances.size() << "\n";
        std::cout << "Genesis hash:       " << hex << "\n";

        std::ofstream f(path + ".hash");
        f << hex << "\n";
        std::cout << "Wrote " << path << ".hash\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// genesis-tool build-sharded <config.json>
//   Stage B2a. Loads a single GenesisConfig and produces (1 + S) genesis
//   files: one beacon (chain_role=BEACON, shard_id=0) and S shard files
//   (chain_role=SHARD, shard_id=i for i in 0..S-1). All inherit the same
//   creators, balances, K, M, BFT params, and shard_address_salt.
//
//   The beacon's hash is pinned into each shard's `genesis_hash` config
//   slot at deploy time (operators copy it into shard nodes' config.json).
//   Cross-chain coordination (epoch transitions, cross-shard receipts)
//   is Stage B2b/B2c — out of scope for this minimal scaffolding step.
static int cmd_genesis_tool_build_sharded(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ genesis-tool build-sharded "
                     "<genesis_config.json> [--profile <name>]\n";
        return 1;
    }
    std::string path = argv[0];
    // A6: optional --profile pins the deployment's sharding_mode at
    // build time so we can reject mode-incompatible configs early.
    // When omitted, sharding_mode is INFERRED from the input JSON
    // (non-empty committee_region or any non-empty shard_regions[i]
    // implies EXTENDED; otherwise CURRENT). Inference keeps existing
    // build-sharded callers byte-compatible.
    std::string profile_name;
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--profile") profile_name = argv[i + 1];
    }
    try {
        auto base = chain::GenesisConfig::load(path);
        if (base.k_block_sigs == 0 || base.k_block_sigs > base.m_creators) {
            std::cerr << "Genesis invalid: k_block_sigs=" << base.k_block_sigs
                      << " must satisfy 1 <= K <= M=" << base.m_creators << "\n";
            return 1;
        }
        if (base.initial_shard_count < 1) {
            std::cerr << "build-sharded requires initial_shard_count >= 1 in input config\n";
            return 1;
        }

        // A6: reload the raw JSON so we can read shard_regions (a
        // top-level array, length S, one entry per shard). It is not
        // a field on GenesisConfig itself — per-shard regions are a
        // build-time input only; each shard genesis carries its own
        // committee_region (set below per shard once shard_regions is
        // wired by R3). For now we use shard_regions ONLY to detect
        // EXTENDED intent for the mode-consistency checks.
        std::ifstream raw_in(path);
        nlohmann::json raw;
        if (raw_in) raw = nlohmann::json::parse(raw_in, nullptr, false);
        std::vector<std::string> shard_regions;
        bool any_shard_region = false;
        if (raw.is_object() && raw.contains("shard_regions")
            && raw["shard_regions"].is_array()) {
            for (auto& sr : raw["shard_regions"]) {
                std::string s = sr.is_string() ? sr.get<std::string>()
                                                : std::string{};
                shard_regions.push_back(s);
                if (!s.empty()) any_shard_region = true;
            }
        }
        bool any_creator_region = false;
        for (auto& c : base.initial_creators) {
            if (!c.region.empty()) { any_creator_region = true; break; }
        }
        bool extended_signaled = !base.committee_region.empty()
                                || any_shard_region
                                || any_creator_region;

        // Resolve the effective sharding_mode for build-time checks.
        ShardingMode mode;
        if (!profile_name.empty()) {
            chain::TimingProfile tp = chain::PROFILE_WEB;
            bool ok = true;
            if      (profile_name == "cluster")        tp = chain::PROFILE_CLUSTER;
            else if (profile_name == "web")            tp = chain::PROFILE_WEB;
            else if (profile_name == "regional")       tp = chain::PROFILE_REGIONAL;
            else if (profile_name == "global")         tp = chain::PROFILE_GLOBAL;
            else if (profile_name == "tactical")       tp = chain::PROFILE_TACTICAL;
            else if (profile_name == "single_test")    tp = chain::PROFILE_SINGLE_TEST;
            else if (profile_name == "cluster_test")   tp = chain::PROFILE_CLUSTER_TEST;
            else if (profile_name == "web_test")       tp = chain::PROFILE_WEB_TEST;
            else if (profile_name == "regional_test")  tp = chain::PROFILE_REGIONAL_TEST;
            else if (profile_name == "global_test")    tp = chain::PROFILE_GLOBAL_TEST;
            else if (profile_name == "tactical_test")  tp = chain::PROFILE_TACTICAL_TEST;
            else ok = false;
            if (!ok) {
                std::cerr << "Unknown --profile " << profile_name << "\n";
                return 1;
            }
            mode = tp.sharding_mode;
        } else {
            mode = extended_signaled ? ShardingMode::EXTENDED
                                     : ShardingMode::CURRENT;
        }

        // A6 mismatch gate: a non-EXTENDED build refuses any region
        // input. Region tags are a no-op (CURRENT silently tolerates,
        // NONE rejects) under non-EXTENDED runtime; baking them into
        // the genesis is therefore an operator error worth catching
        // before the chain ships.
        if (mode != ShardingMode::EXTENDED) {
            if (!base.committee_region.empty()) {
                std::cerr << "build-sharded: sharding_mode="
                          << to_string(mode)
                          << " rejects non-empty committee_region "
                             "(got '" << base.committee_region
                          << "') — regional committees require "
                             "sharding_mode=extended\n";
                return 1;
            }
            if (any_shard_region) {
                std::cerr << "build-sharded: sharding_mode="
                          << to_string(mode)
                          << " rejects non-empty shard_regions[] — "
                             "per-shard regions require "
                             "sharding_mode=extended\n";
                return 1;
            }
            if (any_creator_region) {
                std::cerr << "build-sharded: sharding_mode="
                          << to_string(mode)
                          << " rejects non-empty initial_creators[].region — "
                             "creator region tags require "
                             "sharding_mode=extended\n";
                return 1;
            }
        }

        // A6 / S-038 mitigation: an EXTENDED deployment with fewer
        // than 3 shards is degenerate (the under-quorum merge mechanism
        // that justifies EXTENDED needs at least 3 shards for the
        // modular fold to be meaningful). Hard error.
        if (mode == ShardingMode::EXTENDED && base.initial_shard_count < 3) {
            std::cerr << "build-sharded: sharding_mode=extended requires "
                         "initial_shard_count >= 3 (got "
                      << base.initial_shard_count
                      << ", minimum 3) — S-038 mitigation\n";
            return 1;
        }

        // If shard_regions is present, its length must match S.
        if (!shard_regions.empty()
            && shard_regions.size() != base.initial_shard_count) {
            std::cerr << "build-sharded: shard_regions length "
                      << shard_regions.size()
                      << " != initial_shard_count "
                      << base.initial_shard_count << "\n";
            return 1;
        }

        // Generate a fresh shard_address_salt if the input didn't supply one.
        Hash zero_salt{};
        if (base.shard_address_salt == zero_salt) {
            if (RAND_bytes(base.shard_address_salt.data(), 32) != 1) {
                std::cerr << "Failed to generate shard_address_salt\n";
                return 1;
            }
        }

        // Beacon genesis (role=BEACON, shard_id=0).
        chain::GenesisConfig beacon = base;
        beacon.chain_role = ChainRole::BEACON;
        beacon.shard_id   = 0;
        std::string beacon_path = path + ".beacon.json";
        beacon.save(beacon_path);
        Hash beacon_hash = chain::compute_genesis_hash(beacon);
        std::ofstream(beacon_path + ".hash") << to_hex(beacon_hash) << "\n";

        std::cout << "Beacon genesis:     " << beacon_path << "\n";
        std::cout << "  chain_role:       beacon (shard_id=0, S=" << beacon.initial_shard_count
                  << ", E=" << beacon.epoch_blocks << ")\n";
        std::cout << "  hash:             " << to_hex(beacon_hash) << "\n";

        // Shard genesis files (role=SHARD, shard_id=0..S-1).
        for (uint32_t s = 0; s < base.initial_shard_count; ++s) {
            chain::GenesisConfig shard = base;
            shard.chain_role = ChainRole::SHARD;
            shard.shard_id   = s;
            // A6: when shard_regions is supplied (EXTENDED only — gated
            // above), the per-shard committee_region overrides the
            // base.committee_region. Empty entry leaves the base value
            // (= "" under EXTENDED defaults to global pool for that
            // shard, which is allowed). Pre-A6 callers omit
            // shard_regions and inherit base.committee_region (which
            // must be "" under non-EXTENDED).
            if (!shard_regions.empty()) {
                shard.committee_region = shard_regions[s];
            }
            std::string shard_path = path + ".shard" + std::to_string(s) + ".json";
            shard.save(shard_path);
            Hash sh = chain::compute_genesis_hash(shard);
            std::ofstream(shard_path + ".hash") << to_hex(sh) << "\n";

            std::cout << "Shard genesis:      " << shard_path << "\n";
            std::cout << "  chain_role:       shard (shard_id=" << s
                      << ", S=" << shard.initial_shard_count
                      << ", E=" << shard.epoch_blocks << ")\n";
            std::cout << "  hash:             " << to_hex(sh) << "\n";
        }

        std::cout << "\nNote: this scaffolds the genesis file structure for sharded "
                     "deployments.\n      Cross-chain coordination (validator pool at "
                     "beacon, epoch broadcast,\n      cross-shard receipts) is Stage "
                     "B2b/B2c — operators must run beacon\n      and each shard as "
                     "separate processes, with their own bootstrap_peers.\n";
        return 0;
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

// account create --out <file> [--allow-plaintext-stdout]
//
// S-004 mitigation: refuse stdout output by default. Generating a
// fresh privkey and printing it to stdout exposes it to terminal
// scrollback, shell history, accidental log capture, and any process
// reading the parent shell's tty. The default output is a file with
// restrictive permissions (owner read+write only). Operators who
// truly want stdout output (offline air-gapped key gen with a
// trusted shell history) must set --allow-plaintext-stdout
// explicitly so the choice is auditable in the invoking script.
//
// File permissions: std::filesystem::permissions narrowed to
// owner_read | owner_write on the freshly-written file. On Unix
// this is chmod 0600; on Windows the call resolves to a best-effort
// owner-only ACL via the std::filesystem implementation. Operators
// running on Windows servers with shared-volume permissions should
// additionally verify via icacls.
//
// Passphrase encryption (envelope-wrapped output) is the v1.x-prime
// next step — tracked under S-004 follow-on. The wallet binary
// (determ-wallet envelope encrypt) already provides this primitive;
// a future revision wires it into account create so the on-disk
// keyfile is encrypted at rest rather than relying on filesystem
// permissions alone.
static int cmd_account_create(int argc, char** argv) {
    std::string out_path;
    bool allow_plaintext_stdout = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--out" && i + 1 < argc) out_path = argv[i + 1];
        else if (a == "--allow-plaintext-stdout") allow_plaintext_stdout = true;
    }
    if (out_path.empty() && !allow_plaintext_stdout) {
        std::cerr <<
            "S-004: refusing to emit privkey to stdout. Either:\n"
            "  determ account create --out <file>     (recommended; "
                                                       "file gets 0600 permissions)\n"
            "  determ account create --allow-plaintext-stdout  (opt-in; "
                                                                  "be aware of\n"
            "                                                   terminal "
                                                                  "scrollback and\n"
            "                                                   shell history "
                                                                  "leakage)\n";
        return 1;
    }

    auto key = crypto::generate_node_key();
    std::string addr = make_anon_address(key.pub);
    std::string priv_hex = to_hex(key.priv_seed);

    json out = {
        {"address",   addr},
        {"privkey",   priv_hex},
        {"warning",   "store privkey securely; anyone with it controls the address"}
    };
    if (out_path.empty()) {
        // --allow-plaintext-stdout was explicitly set.
        std::cout << out.dump(2) << "\n";
    } else {
        std::ofstream f(out_path);
        if (!f) { std::cerr << "Cannot write " << out_path << "\n"; return 1; }
        f << out.dump(2) << "\n";
        f.close();
        // S-004: restrict to owner read+write only. Errors here are
        // logged but non-fatal — the file is already written; the
        // operator should investigate manually if perms don't stick.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        if (perm_ec) {
            std::cerr << "Warning: could not set 0600 permissions on "
                      << out_path << ": " << perm_ec.message() << "\n";
            std::cerr << "         Verify manually (chmod 0600 / icacls).\n";
        }
        std::cout << "Account written to " << out_path << "\n";
        std::cout << "Address: " << addr << "\n";
    }
    return 0;
}

// account address <privkey_hex>
//   Derives the account address from a privkey hex string (offline, no daemon needed).
static int cmd_account_address(int argc, char** argv) {
    if (argc < 1) { std::cerr << "Usage: determ account address <privkey_hex>\n"; return 1; }
    crypto::NodeKey key;
    key.priv_seed = from_hex_arr<32>(argv[0]);

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, key.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "invalid privkey\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, key.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    std::cout << make_anon_address(key.pub) << "\n";
    return 0;
}

static int cmd_account(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ account {create|address} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "create")  return cmd_account_create (argc - 1, argv + 1);
    if (sub == "address") return cmd_account_address(argc - 1, argv + 1);
    std::cerr << "Unknown account subcommand: " << sub << "\n";
    return 1;
}

// send_anon <to> <amount> <privkey_hex> [--fee <n>] [--rpc-port <p>]
static int cmd_send_anon(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: determ send_anon <to> <amount> <privkey_hex> "
                     "[--fee <n>] [--rpc-port <p>]\n";
        return 1;
    }
    std::string to     = argv[0];
    uint64_t    amount = std::stoull(argv[1]);
    std::string priv_hex = argv[2];
    uint64_t    fee    = 0;
    uint16_t    port   = get_rpc_port(argc, argv);
    for (int i = 3; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--fee") fee = std::stoull(argv[i + 1]);

    crypto::NodeKey key;
    try {
        key.priv_seed = from_hex_arr<32>(priv_hex);
    } catch (std::exception& e) {
        std::cerr << "Invalid privkey: " << e.what() << "\n";
        return 1;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, key.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "invalid privkey for Ed25519\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, key.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    std::string from_addr = make_anon_address(key.pub);

    uint64_t nonce = 0;
    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "nonce", {{"domain", from_addr}});
        nonce = r.value("next_nonce", uint64_t{0});
    } catch (std::exception& e) {
        std::cerr << "nonce query failed: " << e.what() << "\n";
        return 1;
    }

    chain::Transaction tx;
    tx.type    = chain::TxType::TRANSFER;
    tx.from    = from_addr;
    tx.to      = to;
    tx.amount  = amount;
    tx.fee     = fee;
    tx.nonce   = nonce;
    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(key, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "submit_tx", {{"tx", tx.to_json()}});
        std::cout << r.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "submit_tx failed: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// A5: build, sign, and submit a PARAM_CHANGE tx.
//   determ submit-param-change \
//     --priv <sender_priv_hex> \
//     --name <param_name> \
//     --value-hex <hex_le_bytes> \
//     --effective-height <N> \
//     --keyholder-sig <idx>:<priv_hex> [--keyholder-sig <idx>:<priv_hex> ...] \
//     [--fee <N>] [--rpc-port <P>]
//
// The sender pays the fee; the keyholder private keys are used purely
// for signing the (name, value, effective_height) tuple — no on-chain
// account for keyholders is required. Each --keyholder-sig produces
// one (idx, sig) entry inside the canonical payload. The canonical
// signing message format mirrors validator.cpp's check.
static int cmd_submit_param_change(int argc, char** argv) {
    std::string priv_hex;
    std::string from_domain;   // required: registered domain that pays the fee
    std::string name;
    std::string value_hex;
    uint64_t    effective_height = 0;
    uint64_t    fee  = 0;
    uint16_t    port = get_rpc_port(argc, argv);
    std::vector<std::pair<uint16_t, std::string>> keyholder_sigs;
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--priv")             priv_hex = argv[i + 1];
        else if (a == "--from")             from_domain = argv[i + 1];
        else if (a == "--name")             name = argv[i + 1];
        else if (a == "--value-hex")        value_hex = argv[i + 1];
        else if (a == "--effective-height") effective_height = std::stoull(argv[i + 1]);
        else if (a == "--fee")              fee = std::stoull(argv[i + 1]);
        else if (a == "--keyholder-sig") {
            std::string s = argv[i + 1];
            auto colon = s.find(':');
            if (colon == std::string::npos) {
                std::cerr << "--keyholder-sig requires <idx>:<priv_hex>\n";
                return 1;
            }
            uint16_t idx = static_cast<uint16_t>(std::stoul(s.substr(0, colon)));
            keyholder_sigs.emplace_back(idx, s.substr(colon + 1));
        }
    }
    if (priv_hex.empty() || from_domain.empty() || name.empty()
        || value_hex.empty() || keyholder_sigs.empty()) {
        std::cerr << "Usage: determ submit-param-change --priv <hex> "
                     "--from <domain> --name <NAME> --value-hex <hex> "
                     "--effective-height <N> "
                     "--keyholder-sig <idx>:<priv_hex> [more...] "
                     "[--fee <N>] [--rpc-port <P>]\n";
        return 1;
    }

    std::vector<uint8_t> value;
    try { value = from_hex(value_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid --value-hex: " << e.what() << "\n"; return 1;
    }
    if (name.size() > 255) {
        std::cerr << "--name too long (>255 bytes)\n"; return 1;
    }
    if (value.size() > 0xffff) {
        std::cerr << "--value-hex too long (>65535 bytes)\n"; return 1;
    }

    // Build the canonical signing message that each keyholder signs:
    //   [name_len: u8][name][value_len: u16 LE][value][effective_height: u64 LE]
    std::vector<uint8_t> sig_msg;
    sig_msg.push_back(static_cast<uint8_t>(name.size()));
    sig_msg.insert(sig_msg.end(), name.begin(), name.end());
    sig_msg.push_back(static_cast<uint8_t>(value.size() & 0xff));
    sig_msg.push_back(static_cast<uint8_t>((value.size() >> 8) & 0xff));
    sig_msg.insert(sig_msg.end(), value.begin(), value.end());
    for (int i = 0; i < 8; ++i)
        sig_msg.push_back(static_cast<uint8_t>((effective_height >> (8*i)) & 0xff));

    // Build the full tx payload: sig_msg + [sig_count: u8] + each (idx, sig).
    std::vector<uint8_t> payload = sig_msg;
    payload.push_back(static_cast<uint8_t>(keyholder_sigs.size()));
    for (auto& [idx, kh_hex] : keyholder_sigs) {
        crypto::NodeKey kh;
        try { kh.priv_seed = from_hex_arr<32>(kh_hex); }
        catch (std::exception& e) {
            std::cerr << "Invalid keyholder priv hex: " << e.what() << "\n";
            return 1;
        }
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr, kh.priv_seed.data(), 32);
        if (!pkey) { std::cerr << "keyholder priv invalid\n"; return 1; }
        size_t pub_len = 32;
        EVP_PKEY_get_raw_public_key(pkey, kh.pub.data(), &pub_len);
        EVP_PKEY_free(pkey);
        Signature sig = crypto::sign(kh, sig_msg.data(), sig_msg.size());
        payload.push_back(static_cast<uint8_t>(idx & 0xff));
        payload.push_back(static_cast<uint8_t>((idx >> 8) & 0xff));
        payload.insert(payload.end(), sig.begin(), sig.end());
    }

    // Sender side: derive anon address, query nonce, sign + submit.
    crypto::NodeKey sender;
    try { sender.priv_seed = from_hex_arr<32>(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid sender priv: " << e.what() << "\n"; return 1;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, sender.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "sender priv invalid\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, sender.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    // Sender must be a registered domain (anon accounts may only
    // TRANSFER per the validator). The provided --from is used as-is;
    // the node's registry resolves it to a pubkey, which must match
    // the --priv key.
    uint64_t nonce = 0;
    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "nonce",
                                  {{"domain", from_domain}});
        nonce = r.value("next_nonce", uint64_t{0});
    } catch (std::exception& e) {
        std::cerr << "nonce query failed: " << e.what() << "\n"; return 1;
    }

    chain::Transaction tx;
    tx.type    = chain::TxType::PARAM_CHANGE;
    tx.from    = from_domain;
    tx.to      = from_domain;   // ignored for PARAM_CHANGE
    tx.amount  = 0;
    tx.fee     = fee;
    tx.nonce   = nonce;
    tx.payload = payload;
    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(sender, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "submit_tx", {{"tx", tx.to_json()}});
        std::cout << r.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "submit_tx failed: " << e.what() << "\n"; return 1;
    }
    return 0;
}

// R4: build, sign, and submit a MERGE_EVENT tx.
//   determ submit-merge-event \
//     --priv <sender_priv_hex> --from <sender_domain> \
//     --event {begin|end} \
//     --shard-id <N> --partner-id <N> \
//     --effective-height <N> --evidence-window-start <N> \
//     [--refugee-region <region>] \
//     [--fee <N>] [--rpc-port <P>]
//
// Builds a canonical MergeEvent payload, wraps it in a Transaction
// from a registered domain, and submits via submit_tx RPC. Operator-
// driven for v1.x; auto-detection on the beacon (eligible_in_region
// < 2K observation window) is Phase 6 work.
static int cmd_submit_merge_event(int argc, char** argv) {
    std::string priv_hex, from_domain, event_str, refugee_region;
    uint32_t shard_id = 0, partner_id = 0;
    uint64_t effective_height = 0, evidence_window_start = 0;
    uint64_t fee  = 0;
    uint16_t port = get_rpc_port(argc, argv);
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--priv")              priv_hex = argv[i + 1];
        else if (a == "--from")              from_domain = argv[i + 1];
        else if (a == "--event")             event_str = argv[i + 1];
        else if (a == "--shard-id")          shard_id   = static_cast<uint32_t>(std::stoul(argv[i + 1]));
        else if (a == "--partner-id")        partner_id = static_cast<uint32_t>(std::stoul(argv[i + 1]));
        else if (a == "--effective-height")  effective_height       = std::stoull(argv[i + 1]);
        else if (a == "--evidence-window-start")
                                              evidence_window_start = std::stoull(argv[i + 1]);
        else if (a == "--refugee-region")    refugee_region = argv[i + 1];
        else if (a == "--fee")               fee  = std::stoull(argv[i + 1]);
    }
    if (priv_hex.empty() || from_domain.empty() || event_str.empty()) {
        std::cerr << "Usage: determ submit-merge-event "
                     "--priv <hex> --from <domain> --event {begin|end} "
                     "--shard-id <N> --partner-id <N> "
                     "--effective-height <N> --evidence-window-start <N> "
                     "[--refugee-region <region>] "
                     "[--fee <N>] [--rpc-port <P>]\n";
        return 1;
    }
    chain::MergeEvent ev;
    if      (event_str == "begin") ev.event_type = chain::MergeEvent::BEGIN;
    else if (event_str == "end")   ev.event_type = chain::MergeEvent::END;
    else {
        std::cerr << "--event must be 'begin' or 'end'\n"; return 1;
    }
    ev.shard_id              = shard_id;
    ev.partner_id            = partner_id;
    ev.effective_height      = effective_height;
    ev.evidence_window_start = evidence_window_start;
    ev.merging_shard_region  = refugee_region;
    std::vector<uint8_t> payload = ev.encode();

    crypto::NodeKey sender;
    try { sender.priv_seed = from_hex_arr<32>(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid sender priv: " << e.what() << "\n"; return 1;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, sender.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "sender priv invalid\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, sender.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    uint64_t nonce = 0;
    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "nonce",
                                  {{"domain", from_domain}});
        nonce = r.value("next_nonce", uint64_t{0});
    } catch (std::exception& e) {
        std::cerr << "nonce query failed: " << e.what() << "\n"; return 1;
    }

    chain::Transaction tx;
    tx.type    = chain::TxType::MERGE_EVENT;
    tx.from    = from_domain;
    tx.to      = from_domain;   // ignored for MERGE_EVENT
    tx.amount  = 0;
    tx.fee     = fee;
    tx.nonce   = nonce;
    tx.payload = payload;
    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(sender, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "submit_tx", {{"tx", tx.to_json()}});
        std::cout << r.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "submit_tx failed: " << e.what() << "\n"; return 1;
    }
    return 0;
}

static int cmd_genesis_tool(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ genesis-tool {peer-info|build|build-sharded} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "peer-info")     return cmd_genesis_tool_peer_info    (argc - 1, argv + 1);
    if (sub == "build")         return cmd_genesis_tool_build         (argc - 1, argv + 1);
    if (sub == "build-sharded") return cmd_genesis_tool_build_sharded (argc - 1, argv + 1);
    std::cerr << "Unknown genesis-tool subcommand: " << sub << "\n";
    return 1;
}

static int cmd_stake_info(int argc, char** argv) {
    std::string domain = (argc >= 1) ? argv[0] : "";
    uint16_t    port   = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "stake_info", {{"domain", domain}});
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 0; }

    std::string cmd = argv[1];
    int sub_argc = argc - 2;
    char** sub_argv = argv + 2;

    if (cmd == "init")        return cmd_init(sub_argc, sub_argv);
    if (cmd == "start")       return cmd_start(sub_argc, sub_argv);
    if (cmd == "register")    return cmd_register(sub_argc, sub_argv);
    if (cmd == "send")        return cmd_send(sub_argc, sub_argv);
    if (cmd == "status")        return cmd_status(sub_argc, sub_argv);
    if (cmd == "peers")         return cmd_peers(sub_argc, sub_argv);
    if (cmd == "show-block")    return cmd_show_block(sub_argc, sub_argv);
    if (cmd == "chain-summary") return cmd_chain_summary(sub_argc, sub_argv);
    if (cmd == "validators")    return cmd_validators(sub_argc, sub_argv);
    if (cmd == "committee")     return cmd_committee(sub_argc, sub_argv);
    if (cmd == "show-account")  return cmd_show_account(sub_argc, sub_argv);
    if (cmd == "show-tx")       return cmd_show_tx(sub_argc, sub_argv);
    if (cmd == "snapshot")      return cmd_snapshot(sub_argc, sub_argv);
    if (cmd == "balance")     return cmd_balance(sub_argc, sub_argv);
    if (cmd == "state-root") {
        uint16_t port = get_rpc_port(sub_argc, sub_argv);
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "state_root", {});
            std::cout << r.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::cerr << "state-root query failed: " << e.what() << "\n";
            return 1;
        }
    }
    if (cmd == "stake")       return cmd_stake(sub_argc, sub_argv);
    if (cmd == "unstake")     return cmd_unstake(sub_argc, sub_argv);
    if (cmd == "nonce")       return cmd_nonce(sub_argc, sub_argv);
    if (cmd == "stake_info")    return cmd_stake_info(sub_argc, sub_argv);
    if (cmd == "submit-param-change") return cmd_submit_param_change(sub_argc, sub_argv);
    if (cmd == "submit-merge-event")  return cmd_submit_merge_event(sub_argc, sub_argv);
    if (cmd == "genesis-tool")  return cmd_genesis_tool(sub_argc, sub_argv);
    if (cmd == "account")       return cmd_account(sub_argc, sub_argv);
    if (cmd == "send_anon")     return cmd_send_anon(sub_argc, sub_argv);

    std::cerr << "Unknown command: " << cmd << "\n\n";
    usage();
    return 1;
}
