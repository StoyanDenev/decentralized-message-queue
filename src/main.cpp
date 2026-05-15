// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/node/node.hpp>
#include <determ/rpc/rpc.hpp>
#include <determ/chain/chain.hpp>
#include <determ/chain/block.hpp>
#include <determ/chain/params.hpp>
#include <determ/crypto/keys.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/net/messages.hpp>
// v2.17: envelope crypto for passphrase-encrypted keyfiles.
// Lives in wallet/envelope.cpp, also linked into determ binary.
#include "envelope.hpp"
#include <asio.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <functional>
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

State commitment + light-client (v2.1 + v2.2):
  determ state-root                          Chain Merkle state root + height + head_hash
  determ state-proof --ns {a|s|r|d|b|k|c} --key <name>
                                              Merkle inclusion proof for any state entry
                                              (light-client primitive against state_root;
                                              d = v2.18 DApp registry by owning domain)

DApp substrate (v2.18 + v2.19) — the DApp's identity is its owning Determ domain:
  determ submit-dapp-register --priv <hex> --from <domain>
                              --service-pubkey <64hex> --endpoint-url <url>
                              [--topics t1,t2,...] [--retention 0|1]
                              [--metadata-hex <hex>] [--fee N]
                                              Register or update a DApp (idempotent on --from)
  determ submit-dapp-register --priv <hex> --from <domain> --deactivate
                                              Deactivate (defers via DAPP_GRACE_BLOCKS)
  determ submit-dapp-call --priv <hex> --from <sender> --to <dapp-domain>
                          [--topic T] [--payload-hex <hex>]
                          [--amount N] [--fee N]
                                              Submit a DAPP_CALL routed to --to
  determ dapp-list [--prefix P] [--topic T]   List registered DApps (optional filters)
  determ dapp-info --domain <D>               Per-DApp record
  determ dapp-messages --domain <D> [--from H] [--to H] [--topic T]
                                              Retrospective DAPP_CALL poll (256 / page)

Governance + sharded operation:
  determ submit-param-change ...              A5 PARAM_CHANGE tx (see CLI-REFERENCE.md §Governance)
  determ submit-merge-event ...               R7 MERGE_EVENT tx (EXTENDED-mode under-quorum merge)

In-process tests (deterministic, no network):
  determ test-atomic-scope                    A9 Phase 2D nested-scope rollback primitive
  determ test-composable-batch                COMPOSABLE_BATCH all-or-nothing semantics
  determ test-dapp-register                   v2.18 DAPP_REGISTER apply path
  determ test-dapp-call                       v2.19 DAPP_CALL routing + apply path
  determ test-s018-json-validation            S-018 json_require<T> field-name diagnostics

For details + flags see docs/CLI-REFERENCE.md.
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
                                       cfg.rpc_port, cfg.rpc_localhost_only,
                                       cfg.rpc_auth_secret,
                                       cfg.rpc_rate_per_sec,
                                       cfg.rpc_rate_burst);
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

        // A6 / cascading-merge invariant: an EXTENDED deployment with
        // fewer than 3 shards is degenerate (the under-quorum merge
        // mechanism that justifies EXTENDED needs at least 3 shards for
        // the modular fold to be meaningful). Hard error.
        //
        // (Originally drafted as a proposed S-038 mitigation; the S-038
        // number was later reassigned in SECURITY.md to "state_root
        // verification gate dormant". The invariant itself is closed by
        // construction here + documented inline in SECURITY.md §6.5 T-004
        // and README §16.5.)
        if (mode == ShardingMode::EXTENDED && base.initial_shard_count < 3) {
            std::cerr << "build-sharded: sharding_mode=extended requires "
                         "initial_shard_count >= 3 (got "
                      << base.initial_shard_count
                      << ", minimum 3) — cascading-merge invariant "
                         "(see SECURITY.md §6.5 + README §16.5)\n";
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

// account create --out <file> [--allow-plaintext-stdout] [--passphrase <pw>]
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
// owner-only ACL via the std::filesystem implementation.
//
// v2.17 / S-004 option 2: passphrase-encrypted keyfile at rest. If
// --passphrase is provided (or DETERM_PASSPHRASE env var is set),
// the on-disk keyfile is wrapped in an AES-256-GCM envelope keyed
// from PBKDF2-HMAC-SHA-256(passphrase, salt, 600k iters). The
// envelope is serialized in the canonical dot-separated format
// (see wallet/envelope.hpp). File permissions still get 0600 for
// belt-and-suspenders.
//
// To read back: `determ account decrypt --in <file> --passphrase ...`
// (or rely on DETERM_PASSPHRASE env var; passing on CLI is leaked
// into shell history).
static int cmd_account_create(int argc, char** argv) {
    std::string out_path;
    std::string passphrase;
    bool allow_plaintext_stdout = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--out" && i + 1 < argc) out_path = argv[i + 1];
        else if (a == "--allow-plaintext-stdout") allow_plaintext_stdout = true;
        else if (a == "--passphrase" && i + 1 < argc) passphrase = argv[i + 1];
    }
    // Env var fallback (avoids CLI leaking into shell history). The
    // CLI flag wins if both are set.
    if (passphrase.empty()) {
        const char* env = std::getenv("DETERM_PASSPHRASE");
        if (env && *env) passphrase = env;
    }
    if (out_path.empty() && !allow_plaintext_stdout) {
        std::cerr <<
            "S-004: refusing to emit privkey to stdout. Either:\n"
            "  determ account create --out <file>     (recommended; "
                                                       "file gets 0600 permissions)\n"
            "  determ account create --out <file> --passphrase <pw>\n"
            "                                         (or DETERM_PASSPHRASE env var;\n"
            "                                          encrypts at rest, S-004 option 2)\n"
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
    } else if (passphrase.empty()) {
        // Plaintext file output (S-004 option 1 — 0600 permissions only)
        std::ofstream f(out_path);
        if (!f) { std::cerr << "Cannot write " << out_path << "\n"; return 1; }
        f << out.dump(2) << "\n";
        f.close();
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
    } else {
        // v2.17 / S-004 option 2: encrypted file output. The plaintext
        // is the same JSON the plaintext path writes; the envelope
        // wraps it with AES-256-GCM keyed via PBKDF2 from the
        // passphrase. The output file is the canonical envelope
        // serialization (dot-separated hex fields, see
        // wallet/envelope.hpp). AAD binds the public address so a
        // tampered envelope cannot be substituted with another
        // address's encrypted blob.
        std::string pt = out.dump(2);
        std::vector<uint8_t> pt_bytes(pt.begin(), pt.end());
        std::vector<uint8_t> aad(addr.begin(), addr.end());
        try {
            auto env = determ::wallet::envelope::encrypt(pt_bytes, passphrase, aad);
            std::string blob = determ::wallet::envelope::serialize(env);
            std::ofstream f(out_path);
            if (!f) { std::cerr << "Cannot write " << out_path << "\n"; return 1; }
            // Header: 1-line magic + address (plaintext metadata) +
            // envelope blob. The address is in AAD so it's
            // tamper-evident, but exposing it in plaintext lets
            // operators identify which account the file belongs to
            // without decrypting.
            f << "DETERM-ACCOUNT-V1 " << addr << "\n";
            f << blob << "\n";
            f.close();
            std::error_code perm_ec;
            std::filesystem::permissions(
                out_path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace,
                perm_ec);
            if (perm_ec) {
                std::cerr << "Warning: could not set 0600 permissions on "
                          << out_path << ": " << perm_ec.message() << "\n";
            }
            std::cout << "Encrypted account written to " << out_path << "\n";
            std::cout << "Address: " << addr << "\n";
            std::cout << "  (use `determ account decrypt --in " << out_path
                      << " --passphrase ...` to recover privkey)\n";
        } catch (std::exception& e) {
            std::cerr << "Encryption failed: " << e.what() << "\n";
            return 1;
        }
    }
    return 0;
}

// v2.17 / S-004 option 2 read-back: decrypt an envelope-wrapped keyfile
// produced by `account create --passphrase`. Outputs the plaintext
// JSON to stdout (privkey + address). Requires --passphrase or
// DETERM_PASSPHRASE env var.
static int cmd_account_decrypt(int argc, char** argv) {
    std::string in_path, passphrase;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"         && i + 1 < argc) in_path    = argv[i + 1];
        else if (a == "--passphrase" && i + 1 < argc) passphrase = argv[i + 1];
    }
    if (passphrase.empty()) {
        const char* env = std::getenv("DETERM_PASSPHRASE");
        if (env && *env) passphrase = env;
    }
    if (in_path.empty()) {
        std::cerr << "Usage: determ account decrypt --in <file> "
                     "[--passphrase <pw>]\n"
                     "  (or set DETERM_PASSPHRASE env var)\n";
        return 1;
    }
    if (passphrase.empty()) {
        std::cerr << "account decrypt requires --passphrase or "
                     "DETERM_PASSPHRASE env var\n";
        return 1;
    }
    std::ifstream f(in_path);
    if (!f) { std::cerr << "Cannot read " << in_path << "\n"; return 1; }
    std::string header_line, blob_line;
    std::getline(f, header_line);
    std::getline(f, blob_line);
    // Validate header.
    if (header_line.rfind("DETERM-ACCOUNT-V1 ", 0) != 0) {
        std::cerr << "Not a DETERM-ACCOUNT-V1 file: " << in_path << "\n";
        return 1;
    }
    std::string addr = header_line.substr(std::strlen("DETERM-ACCOUNT-V1 "));
    auto env_opt = determ::wallet::envelope::deserialize(blob_line);
    if (!env_opt) {
        std::cerr << "Envelope deserialize failed\n";
        return 1;
    }
    std::vector<uint8_t> aad(addr.begin(), addr.end());
    auto pt_opt = determ::wallet::envelope::decrypt(*env_opt, passphrase, aad);
    if (!pt_opt) {
        std::cerr << "Decryption failed (wrong passphrase or "
                     "tampered file)\n";
        return 1;
    }
    std::string pt(pt_opt->begin(), pt_opt->end());
    std::cout << pt << "\n";
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
    if (sub == "decrypt") return cmd_account_decrypt(argc - 1, argv + 1);
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
    // --nonce N: override auto-fetched nonce. Useful for stress-testing
    // mempool admission (pipelined-nonce submissions) without waiting
    // for confirmations. -1 = auto-fetch via RPC (default).
    int64_t     nonce_override = -1;
    for (int i = 3; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--fee")   fee = std::stoull(argv[i + 1]);
        else if (std::string(argv[i]) == "--nonce") nonce_override = std::stoll(argv[i + 1]);
    }

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
    if (nonce_override >= 0) {
        nonce = static_cast<uint64_t>(nonce_override);
    } else {
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "nonce", {{"domain", from_addr}});
            nonce = r.value("next_nonce", uint64_t{0});
        } catch (std::exception& e) {
            std::cerr << "nonce query failed: " << e.what() << "\n";
            return 1;
        }
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
// < 2K observation window) is tracked as v2.11 in docs/V2-DESIGN.md.
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

// v2.18 Theme 7: submit a DAPP_REGISTER tx to the network.
// The signing sender (--from + --priv) must already be a REGISTER'd
// Determ identity. service_pubkey is generated separately (e.g., via
// libsodium box-keypair-gen) and provided here in hex.
static int cmd_submit_dapp_register(int argc, char** argv) {
    std::string priv_hex, from_domain, service_pubkey_hex, endpoint_url,
                topics_csv, metadata_hex;
    uint8_t retention = 0;
    bool deactivate = false;
    uint64_t fee  = 0;
    uint16_t port = get_rpc_port(argc, argv);
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--priv")            priv_hex = argv[i + 1];
        else if (a == "--from")            from_domain = argv[i + 1];
        else if (a == "--service-pubkey")  service_pubkey_hex = argv[i + 1];
        else if (a == "--endpoint-url")    endpoint_url = argv[i + 1];
        else if (a == "--topics")          topics_csv = argv[i + 1];
        else if (a == "--retention")       retention = uint8_t(std::stoi(argv[i + 1]));
        else if (a == "--metadata-hex")    metadata_hex = argv[i + 1];
        else if (a == "--fee")             fee  = std::stoull(argv[i + 1]);
    }
    // --deactivate is a flag (no value)
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--deactivate") deactivate = true;
    }
    if (priv_hex.empty() || from_domain.empty() ||
        (!deactivate && (service_pubkey_hex.empty() || endpoint_url.empty()))) {
        std::cerr << "Usage: determ submit-dapp-register --priv <hex> --from <domain>\n"
                     "  Create/update: --service-pubkey <64hex> --endpoint-url <url>\n"
                     "                 [--topics t1,t2,t3] [--retention 0|1]\n"
                     "                 [--metadata-hex <hex>]\n"
                     "  Deactivate:    --deactivate\n"
                     "  [--fee <N>] [--rpc-port <P>]\n";
        return 1;
    }

    // Build payload per the canonical encoding documented in block.hpp.
    std::vector<uint8_t> payload;
    if (deactivate) {
        payload.push_back(1);
    } else {
        payload.push_back(0);
        std::array<uint8_t, 32> svc_pk;
        try { svc_pk = from_hex_arr<32>(service_pubkey_hex); }
        catch (std::exception& e) {
            std::cerr << "Invalid --service-pubkey: " << e.what() << "\n";
            return 1;
        }
        payload.insert(payload.end(), svc_pk.begin(), svc_pk.end());
        if (endpoint_url.size() > 255) {
            std::cerr << "--endpoint-url too long (max 255)\n"; return 1;
        }
        payload.push_back(uint8_t(endpoint_url.size()));
        payload.insert(payload.end(), endpoint_url.begin(), endpoint_url.end());
        // Parse topics CSV
        std::vector<std::string> topics;
        if (!topics_csv.empty()) {
            size_t pos = 0;
            while (pos < topics_csv.size()) {
                size_t comma = topics_csv.find(',', pos);
                if (comma == std::string::npos) comma = topics_csv.size();
                topics.push_back(topics_csv.substr(pos, comma - pos));
                pos = comma + 1;
            }
        }
        if (topics.size() > 32) {
            std::cerr << "Too many topics (max 32)\n"; return 1;
        }
        payload.push_back(uint8_t(topics.size()));
        for (auto& t : topics) {
            if (t.size() > 64) {
                std::cerr << "Topic '" << t << "' too long (max 64)\n";
                return 1;
            }
            payload.push_back(uint8_t(t.size()));
            payload.insert(payload.end(), t.begin(), t.end());
        }
        payload.push_back(retention);
        std::vector<uint8_t> metadata;
        if (!metadata_hex.empty()) {
            metadata = from_hex(metadata_hex);
        }
        if (metadata.size() > 4096) {
            std::cerr << "Metadata too long (max 4096 bytes)\n"; return 1;
        }
        uint16_t mlen = uint16_t(metadata.size());
        payload.push_back(uint8_t(mlen & 0xFF));
        payload.push_back(uint8_t((mlen >> 8) & 0xFF));
        payload.insert(payload.end(), metadata.begin(), metadata.end());
    }

    // Build, sign, submit.
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
    tx.type    = chain::TxType::DAPP_REGISTER;
    tx.from    = from_domain;
    tx.to      = "";
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

// v2.19 Theme 7: submit a DAPP_CALL tx to the network.
// --to <dapp-domain> --topic <topic> --payload-hex <hex>
// Optional --amount for atomic payment.
static int cmd_submit_dapp_call(int argc, char** argv) {
    std::string priv_hex, from_domain, to_domain, topic, payload_hex;
    uint64_t amount = 0, fee = 0;
    uint16_t port = get_rpc_port(argc, argv);
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--priv")        priv_hex = argv[i + 1];
        else if (a == "--from")        from_domain = argv[i + 1];
        else if (a == "--to")          to_domain = argv[i + 1];
        else if (a == "--topic")       topic = argv[i + 1];
        else if (a == "--payload-hex") payload_hex = argv[i + 1];
        else if (a == "--amount")      amount = std::stoull(argv[i + 1]);
        else if (a == "--fee")         fee  = std::stoull(argv[i + 1]);
    }
    if (priv_hex.empty() || from_domain.empty() || to_domain.empty()) {
        std::cerr << "Usage: determ submit-dapp-call --priv <hex> --from <domain>\n"
                     "  --to <dapp-domain> [--topic <T>] [--payload-hex <hex>]\n"
                     "  [--amount <N>] [--fee <N>] [--rpc-port <P>]\n";
        return 1;
    }
    if (topic.size() > 64) {
        std::cerr << "Topic too long (max 64)\n"; return 1;
    }

    // Build DAPP_CALL payload: [topic_len:u8][topic][ct_len:u32 LE][ciphertext]
    std::vector<uint8_t> ciphertext;
    if (!payload_hex.empty()) ciphertext = from_hex(payload_hex);
    if (ciphertext.size() > 16384) {
        std::cerr << "Payload too large (max 16 KB)\n"; return 1;
    }
    std::vector<uint8_t> payload;
    payload.push_back(uint8_t(topic.size()));
    payload.insert(payload.end(), topic.begin(), topic.end());
    uint32_t cl = uint32_t(ciphertext.size());
    payload.push_back(uint8_t(cl         & 0xFF));
    payload.push_back(uint8_t((cl >>  8) & 0xFF));
    payload.push_back(uint8_t((cl >> 16) & 0xFF));
    payload.push_back(uint8_t((cl >> 24) & 0xFF));
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());

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
    tx.type    = chain::TxType::DAPP_CALL;
    tx.from    = from_domain;
    tx.to      = to_domain;
    tx.amount  = amount;
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
    // v2.18 Theme 7: DApp registry query — info for one DApp.
    // Usage: determ dapp-info --domain <D> [--rpc-port N]
    if (cmd == "dapp-info") {
        uint16_t port = get_rpc_port(sub_argc, sub_argv);
        std::string domain;
        for (int i = 0; i < sub_argc; ++i) {
            std::string a = sub_argv[i];
            if (a == "--domain" && i + 1 < sub_argc) domain = sub_argv[++i];
        }
        if (domain.empty()) {
            std::cerr << "dapp-info requires --domain\n";
            return 1;
        }
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "dapp_info",
                {{"domain", domain}});
            std::cout << r.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::cerr << "dapp-info query failed: " << e.what() << "\n";
            return 1;
        }
    }
    // v2.19 Theme 7 Phase 7.4: retrospective DAPP_CALL query.
    // Usage: determ dapp-messages --domain D [--from H] [--to H]
    //        [--topic T] [--rpc-port N]
    // DApp node poll-and-process pattern:
    //   while true: dapp-messages --from $WATERMARK; process; $WATERMARK = result.last_scanned + 1
    if (cmd == "dapp-messages") {
        uint16_t port = get_rpc_port(sub_argc, sub_argv);
        std::string domain, topic;
        uint64_t from_h = 0, to_h = 0;
        for (int i = 0; i < sub_argc; ++i) {
            std::string a = sub_argv[i];
            if      (a == "--domain" && i + 1 < sub_argc) domain = sub_argv[++i];
            else if (a == "--from"   && i + 1 < sub_argc) from_h = std::stoull(sub_argv[++i]);
            else if (a == "--to"     && i + 1 < sub_argc) to_h   = std::stoull(sub_argv[++i]);
            else if (a == "--topic"  && i + 1 < sub_argc) topic  = sub_argv[++i];
        }
        if (domain.empty()) {
            std::cerr << "dapp-messages requires --domain\n";
            return 1;
        }
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "dapp_messages",
                {{"domain", domain}, {"from_height", from_h},
                 {"to_height", to_h}, {"topic", topic}});
            std::cout << r.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::cerr << "dapp-messages query failed: " << e.what() << "\n";
            return 1;
        }
    }

    // v2.18 Theme 7: DApp registry query — list / filter.
    // Usage: determ dapp-list [--prefix P] [--topic T] [--rpc-port N]
    if (cmd == "dapp-list") {
        uint16_t port = get_rpc_port(sub_argc, sub_argv);
        std::string prefix, topic;
        for (int i = 0; i < sub_argc; ++i) {
            std::string a = sub_argv[i];
            if (a == "--prefix" && i + 1 < sub_argc) prefix = sub_argv[++i];
            else if (a == "--topic" && i + 1 < sub_argc) topic = sub_argv[++i];
        }
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "dapp_list",
                {{"prefix", prefix}, {"topic", topic}});
            std::cout << r.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::cerr << "dapp-list query failed: " << e.what() << "\n";
            return 1;
        }
    }

    // v2.2 light-client foundation: state-proof CLI.
    // Usage: determ state-proof --ns <a|s|r|d|b|k|c> --key <name> [--rpc-port N]
    // (`d` = v2.18 DApp registry; the underlying RPC was extended in this
    // session to surface the d:-namespace alongside accounts/stakes/etc.)
    if (cmd == "state-proof") {
        uint16_t port = get_rpc_port(sub_argc, sub_argv);
        std::string ns, key;
        for (int i = 0; i < sub_argc; ++i) {
            std::string a = sub_argv[i];
            if (a == "--ns" && i + 1 < sub_argc) ns = sub_argv[++i];
            else if (a == "--key" && i + 1 < sub_argc) key = sub_argv[++i];
        }
        if (ns.empty() || key.empty()) {
            std::cerr << "state-proof requires --ns and --key\n";
            return 1;
        }
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "state_proof",
                {{"namespace", ns}, {"key", key}});
            std::cout << r.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::cerr << "state-proof query failed: " << e.what() << "\n";
            return 1;
        }
    }
    // A9 Phase 2D regression: in-process exercise of Chain::atomic_scope's
    // commit / discard / nesting / exception semantics. No network, no
    // RPC — just a freshly-constructed Chain and direct method calls.
    // Exit 0 on all assertions passing, non-zero on any failure.
    if (cmd == "test-atomic-scope") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Build a minimal genesis block: alice=100, bob=0.
        Block genesis;
        genesis.index           = 0;
        genesis.prev_hash       = Hash{};
        genesis.timestamp       = 0;
        genesis.cumulative_rand = Hash{};
        genesis.creators.clear();
        GenesisAlloc a; a.domain = "alice"; a.balance = 100; a.stake = 0;
        genesis.initial_state.push_back(a);
        GenesisAlloc bb; bb.domain = "bob"; bb.balance = 0;  bb.stake = 0;
        genesis.initial_state.push_back(bb);

        Chain chain(genesis);
        uint64_t alice_initial = chain.balance("alice");
        uint64_t bob_initial   = chain.balance("bob");
        check(alice_initial == 100, "genesis: alice = 100");
        check(bob_initial   == 0,   "genesis: bob   = 0");

        // Test 1: atomic_scope returning true commits the change.
        // We invoke atomic_scope and inside fn, append a block that
        // transfers 25 from alice to bob. Return true → mutations kept.
        // Helper that builds a transfer block at the next height.
        auto build_transfer_block = [&](uint64_t amount) {
            Block tb;
            tb.index           = chain.height();
            tb.prev_hash       = chain.head_hash();
            tb.timestamp        = 1;
            tb.cumulative_rand = Hash{};
            Transaction tx;
            tx.type     = TxType::TRANSFER;
            tx.from     = "alice";
            tx.to       = "bob";
            tx.amount   = amount;
            tx.fee      = 0;
            tx.nonce    = chain.next_nonce("alice");
            tx.payload  = {};
            tx.hash     = tx.compute_hash();
            tb.transactions.push_back(tx);
            return tb;
        };

        bool committed = chain.atomic_scope([&](Chain& c) {
            c.append(build_transfer_block(25));
            return true;  // keep
        });
        check(committed == true,                "test1: scope returned true");
        check(chain.balance("alice") == 75,     "test1: alice=75 after commit");
        check(chain.balance("bob")   == 25,     "test1: bob=25 after commit");
        check(chain.height() == 2,              "test1: chain height grew");

        // Test 2: atomic_scope returning false rolls back the change.
        uint64_t alice_pre  = chain.balance("alice");
        uint64_t bob_pre    = chain.balance("bob");
        uint64_t height_pre = chain.height();
        bool kept = chain.atomic_scope([&](Chain& c) {
            c.append(build_transfer_block(10));
            return false;  // discard
        });
        check(kept == false,                          "test2: scope returned false");
        check(chain.balance("alice") == alice_pre,    "test2: alice unchanged after discard");
        check(chain.balance("bob")   == bob_pre,      "test2: bob unchanged after discard");
        check(chain.height()         == height_pre,   "test2: blocks_ rolled back");

        // Test 3: throwing in scope rolls back AND re-raises.
        bool caught = false;
        try {
            chain.atomic_scope([&](Chain& c) -> bool {
                c.append(build_transfer_block(5));
                throw std::runtime_error("synthetic");
                return true;  // unreachable
            });
        } catch (std::exception&) {
            caught = true;
        }
        check(caught,                                  "test3: exception propagates");
        check(chain.balance("alice") == alice_pre,     "test3: alice unchanged after throw");
        check(chain.balance("bob")   == bob_pre,       "test3: bob unchanged after throw");
        check(chain.height()         == height_pre,    "test3: blocks_ rolled back on throw");

        // Test 4: nested scopes — outer commits, inner discards.
        // Outer appends one transfer (5). Inner appends another (3) but
        // discards. After outer commits, only outer's 5 should land.
        uint64_t a4 = chain.balance("alice");
        uint64_t b4 = chain.balance("bob");
        uint64_t h4 = chain.height();
        chain.atomic_scope([&](Chain& outer) {
            outer.append(build_transfer_block(5));
            // After outer's append: alice -= 5, bob += 5
            outer.atomic_scope([&](Chain& inner) {
                inner.append(build_transfer_block(3));
                // After inner's append: alice -= 3 more, bob += 3 more
                return false;  // discard inner
            });
            // After inner's discard: state should reflect ONLY outer's append.
            return true;  // commit outer
        });
        check(chain.balance("alice") == a4 - 5,     "test4: alice debited only outer (5)");
        check(chain.balance("bob")   == b4 + 5,     "test4: bob credited only outer (5)");
        check(chain.height()         == h4 + 1,     "test4: only outer block landed");

        // Test 5: nested scopes — outer discards. Both inner and outer
        // mutations roll back even if inner committed.
        uint64_t a5 = chain.balance("alice");
        uint64_t b5 = chain.balance("bob");
        uint64_t h5 = chain.height();
        chain.atomic_scope([&](Chain& outer) {
            outer.append(build_transfer_block(7));
            outer.atomic_scope([&](Chain& inner) {
                inner.append(build_transfer_block(2));
                return true;  // commit inner
            });
            return false;  // discard outer — should undo BOTH appends
        });
        check(chain.balance("alice") == a5,         "test5: alice unchanged after outer discard");
        check(chain.balance("bob")   == b5,         "test5: bob unchanged after outer discard");
        check(chain.height()         == h5,         "test5: both blocks rolled back");

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": atomic_scope " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // v2.4 composable transactions: in-process apply-path test.
    // Builds a Chain with three accounts (alice, bob, carol), constructs
    // COMPOSABLE_BATCH txs with various inner-tx shapes, applies them
    // via Chain::append, and verifies the all-or-nothing semantics.
    // v2.18 Theme 7: in-process apply-path test for DAPP_REGISTER.
    // Builds a Chain with alice as a REGISTER'd domain (the DApp's
    // owner), then applies a series of DAPP_REGISTER txs exercising
    // create / update / deactivate paths. Verifies dapp_registry_
    // state + state_root changes accordingly.
    if (cmd == "test-dapp-register") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Genesis: alice is a registered Determ domain with stake.
        Block genesis;
        genesis.index           = 0;
        genesis.prev_hash       = Hash{};
        genesis.timestamp       = 0;
        genesis.cumulative_rand = Hash{};
        GenesisAlloc a;
        a.domain = "alice";
        a.balance = 1000;
        a.stake = 100;
        for (size_t i = 0; i < a.ed_pub.size(); ++i) a.ed_pub[i] = uint8_t(i + 1);
        genesis.initial_state.push_back(a);
        Chain chain(genesis);

        // Helper: build a DAPP_REGISTER payload for op=0 (create/update).
        auto pack_register_v0 = [](const PubKey& svc_pk,
                                      const std::string& url,
                                      const std::vector<std::string>& topics,
                                      uint8_t retention,
                                      const std::vector<uint8_t>& metadata) {
            std::vector<uint8_t> p;
            p.push_back(0);  // op = create/update
            p.insert(p.end(), svc_pk.begin(), svc_pk.end());
            p.push_back(uint8_t(url.size()));
            p.insert(p.end(), url.begin(), url.end());
            p.push_back(uint8_t(topics.size()));
            for (auto& t : topics) {
                p.push_back(uint8_t(t.size()));
                p.insert(p.end(), t.begin(), t.end());
            }
            p.push_back(retention);
            p.push_back(uint8_t(metadata.size() & 0xFF));
            p.push_back(uint8_t((metadata.size() >> 8) & 0xFF));
            p.insert(p.end(), metadata.begin(), metadata.end());
            return p;
        };
        auto pack_register_v1 = []() {
            return std::vector<uint8_t>{1};  // op = deactivate, no further bytes
        };

        auto build_dapp_register_block = [&](const std::string& from,
                                                const std::vector<uint8_t>& payload) {
            Block b;
            b.index           = chain.height();
            b.prev_hash       = chain.head_hash();
            b.timestamp       = 1;
            b.cumulative_rand = Hash{};
            Transaction tx;
            tx.type    = TxType::DAPP_REGISTER;
            tx.from    = from;
            tx.to      = "";
            tx.amount  = 0;
            tx.fee     = 0;
            tx.nonce   = chain.next_nonce(from);
            tx.payload = payload;
            tx.hash    = tx.compute_hash();
            b.transactions.push_back(tx);
            return b;
        };

        // Test 1: create. alice registers a DApp.
        PubKey svc_pk{};
        for (size_t i = 0; i < svc_pk.size(); ++i) svc_pk[i] = uint8_t(0xA0 + i);
        std::vector<std::string> topics = {"chat", "files"};
        std::vector<uint8_t> meta = {0xDE, 0xAD, 0xBE, 0xEF};
        auto pl1 = pack_register_v0(svc_pk, "https://dapp.example", topics, 0, meta);
        Hash root_before = chain.compute_state_root();
        chain.append(build_dapp_register_block("alice", pl1));
        Hash root_after  = chain.compute_state_root();

        auto entry_opt = chain.dapp("alice");
        check(entry_opt.has_value(),                  "test1: dapp entry exists");
        check(entry_opt && entry_opt->endpoint_url == "https://dapp.example",
              "test1: endpoint_url correct");
        check(entry_opt && entry_opt->topics.size() == 2,
              "test1: topic count = 2");
        check(entry_opt && entry_opt->topics[0] == "chat",
              "test1: topic[0] = chat");
        check(entry_opt && entry_opt->topics[1] == "files",
              "test1: topic[1] = files");
        check(entry_opt && entry_opt->service_pubkey == svc_pk,
              "test1: service_pubkey matches");
        check(entry_opt && entry_opt->retention == 0,
              "test1: retention = 0 (default)");
        check(entry_opt && entry_opt->metadata == meta,
              "test1: metadata round-trips");
        check(entry_opt && entry_opt->inactive_from == UINT64_MAX,
              "test1: entry is active");
        check(root_after != root_before,
              "test1: state_root changed after DAPP_REGISTER");

        // Test 2: update — change endpoint_url, add a topic.
        std::vector<std::string> topics2 = {"chat", "files", "notifications"};
        auto pl2 = pack_register_v0(svc_pk, "https://dapp.v2.example", topics2, 1, meta);
        uint64_t registered_at_before = entry_opt->registered_at;
        chain.append(build_dapp_register_block("alice", pl2));
        auto entry2 = chain.dapp("alice");
        check(entry2.has_value(),                      "test2: entry still exists");
        check(entry2 && entry2->endpoint_url == "https://dapp.v2.example",
              "test2: endpoint_url updated");
        check(entry2 && entry2->topics.size() == 3,
              "test2: topic count = 3");
        check(entry2 && entry2->retention == 1,
              "test2: retention updated to 1");
        check(entry2 && entry2->registered_at == registered_at_before,
              "test2: registered_at preserved across update");

        // Test 3: deactivate.
        auto pl3 = pack_register_v1();
        uint64_t height_pre_deactivate = chain.height();
        chain.append(build_dapp_register_block("alice", pl3));
        auto entry3 = chain.dapp("alice");
        check(entry3.has_value(),                      "test3: entry still in registry");
        check(entry3 && entry3->inactive_from != UINT64_MAX,
              "test3: inactive_from set");
        // height_pre_deactivate is the height BEFORE the deactivate block applies.
        // The apply-time height is height_pre_deactivate (block_index passed to apply).
        // inactive_from = height_pre_deactivate + DAPP_GRACE_BLOCKS.
        check(entry3 && entry3->inactive_from == height_pre_deactivate + DAPP_GRACE_BLOCKS,
              "test3: inactive_from = current_height + GRACE");

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": dapp_register " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // v2.19 Theme 7 Phase 7.2: in-process apply-path test for DAPP_CALL.
    // Builds a Chain with alice (user) and dapp_owner (DApp's owning
    // Determ identity), registers a DApp on dapp_owner, then exercises
    // DAPP_CALL across various scenarios (success, missing DApp,
    // deactivated DApp, unknown topic, payment + message).
    if (cmd == "test-dapp-call") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Genesis: alice (user with balance) + dappowner (DApp's owner).
        Block genesis;
        genesis.index           = 0;
        genesis.prev_hash       = Hash{};
        genesis.timestamp       = 0;
        genesis.cumulative_rand = Hash{};
        GenesisAlloc a;
        a.domain = "alice"; a.balance = 1000; a.stake = 0;
        for (size_t i = 0; i < a.ed_pub.size(); ++i) a.ed_pub[i] = uint8_t(i + 1);
        genesis.initial_state.push_back(a);
        GenesisAlloc d;
        d.domain = "dappowner"; d.balance = 0; d.stake = 100;
        for (size_t i = 0; i < d.ed_pub.size(); ++i) d.ed_pub[i] = uint8_t(i + 100);
        genesis.initial_state.push_back(d);
        Chain chain(genesis);

        // Helper: pack a DAPP_REGISTER payload (op=0).
        auto pack_register = [](const PubKey& svc_pk,
                                   const std::string& url,
                                   const std::vector<std::string>& topics) {
            std::vector<uint8_t> p;
            p.push_back(0);
            p.insert(p.end(), svc_pk.begin(), svc_pk.end());
            p.push_back(uint8_t(url.size()));
            p.insert(p.end(), url.begin(), url.end());
            p.push_back(uint8_t(topics.size()));
            for (auto& t : topics) {
                p.push_back(uint8_t(t.size()));
                p.insert(p.end(), t.begin(), t.end());
            }
            p.push_back(0);  // retention = 0
            p.push_back(0); p.push_back(0);  // metadata_len = 0
            return p;
        };
        // Helper: pack a DAPP_CALL payload (topic + ciphertext).
        auto pack_call = [](const std::string& topic,
                               const std::vector<uint8_t>& ct) {
            std::vector<uint8_t> p;
            p.push_back(uint8_t(topic.size()));
            p.insert(p.end(), topic.begin(), topic.end());
            uint32_t l = uint32_t(ct.size());
            p.push_back(uint8_t(l         & 0xFF));
            p.push_back(uint8_t((l >>  8) & 0xFF));
            p.push_back(uint8_t((l >> 16) & 0xFF));
            p.push_back(uint8_t((l >> 24) & 0xFF));
            p.insert(p.end(), ct.begin(), ct.end());
            return p;
        };
        // Helper: build a block carrying one tx.
        auto build_block = [&](TxType type,
                                  const std::string& from,
                                  const std::string& to,
                                  uint64_t amount,
                                  uint64_t fee,
                                  const std::vector<uint8_t>& payload) {
            Block b;
            b.index           = chain.height();
            b.prev_hash       = chain.head_hash();
            b.timestamp       = 1;
            b.cumulative_rand = Hash{};
            Transaction tx;
            tx.type    = type;
            tx.from    = from;
            tx.to      = to;
            tx.amount  = amount;
            tx.fee     = fee;
            tx.nonce   = chain.next_nonce(from);
            tx.payload = payload;
            tx.hash    = tx.compute_hash();
            b.transactions.push_back(tx);
            return b;
        };

        // Setup: dappowner registers a DApp with two topics.
        PubKey svc_pk{};
        for (size_t i = 0; i < svc_pk.size(); ++i) svc_pk[i] = uint8_t(0xC0 + i);
        std::vector<std::string> topics = {"chat", "rpc"};
        chain.append(build_block(TxType::DAPP_REGISTER, "dappowner", "",
                                    0, 0, pack_register(svc_pk, "https://dapp.example", topics)));
        check(chain.dapp("dappowner").has_value(),
              "setup: DApp registered");

        // Test 1: successful DAPP_CALL with payment.
        // alice sends a "chat" message to dappowner with 5 DTM payment.
        std::vector<uint8_t> ciphertext = {0xAA, 0xBB, 0xCC, 0xDD};
        uint64_t alice_pre  = chain.balance("alice");
        uint64_t dapp_pre   = chain.balance("dappowner");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "dappowner",
                                    /*amount=*/5, /*fee=*/0,
                                    pack_call("chat", ciphertext)));
        uint64_t alice_post = chain.balance("alice");
        uint64_t dapp_post  = chain.balance("dappowner");
        check(alice_post == alice_pre - 5,
              "test1: alice debited 5 (DAPP_CALL amount)");
        check(dapp_post  == dapp_pre + 5,
              "test1: dappowner credited 5");
        check(chain.next_nonce("alice") == 1,
              "test1: alice nonce +1");

        // Test 2: DAPP_CALL with amount=0 — pure message, no transfer.
        uint64_t alice_pre2 = chain.balance("alice");
        uint64_t dapp_pre2  = chain.balance("dappowner");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "dappowner",
                                    0, 0, pack_call("rpc", {0x01, 0x02})));
        check(chain.balance("alice")     == alice_pre2,
              "test2: alice unchanged (amount=0)");
        check(chain.balance("dappowner") == dapp_pre2,
              "test2: dappowner unchanged (amount=0)");
        check(chain.next_nonce("alice")  == 2,
              "test2: alice nonce +1");

        // Test 3: DAPP_CALL to nonexistent DApp — apply silently no-ops
        // (defensive; validator would have rejected at submit-time).
        uint64_t alice_pre3 = chain.balance("alice");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "ghost.dapp",
                                    100, 0, pack_call("chat", ciphertext)));
        check(chain.balance("alice")     == alice_pre3,
              "test3: alice unchanged (missing DApp)");
        check(chain.balance("ghost.dapp") == 0,
              "test3: ghost.dapp not credited");
        check(chain.next_nonce("alice")  == 3,
              "test3: alice nonce +1 (defensive consume)");

        // Test 4: DAPP_CALL with topic not in DApp's registered list.
        uint64_t alice_pre4 = chain.balance("alice");
        uint64_t dapp_pre4  = chain.balance("dappowner");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "dappowner",
                                    10, 0, pack_call("unregistered", ciphertext)));
        check(chain.balance("alice")     == alice_pre4,
              "test4: alice unchanged (unknown topic)");
        check(chain.balance("dappowner") == dapp_pre4,
              "test4: dappowner unchanged (unknown topic)");

        // Test 5: DAPP_CALL with empty topic — allowed, applies normally.
        uint64_t alice_pre5 = chain.balance("alice");
        uint64_t dapp_pre5  = chain.balance("dappowner");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "dappowner",
                                    3, 0, pack_call("", ciphertext)));
        check(chain.balance("alice")     == alice_pre5 - 3,
              "test5: alice debited 3 (empty topic allowed)");
        check(chain.balance("dappowner") == dapp_pre5 + 3,
              "test5: dappowner credited 3");

        // Test 6: deactivated DApp — DAPP_CALL no-ops after grace period.
        // Deactivate the DApp; apply at height >= deactivate_height + GRACE
        // means inactive_from <= height → rejected.
        chain.append(build_block(TxType::DAPP_REGISTER, "dappowner", "",
                                    0, 0, std::vector<uint8_t>{1}));
        // The DApp is now inactive_from = current_height + DAPP_GRACE_BLOCKS.
        // For this test, we can't easily wait 100 blocks; instead, we
        // verify the DApp ENTRY now has inactive_from set, and that a
        // DAPP_CALL one block later (inactive_from > current still) is
        // accepted (within grace period).
        auto entry = chain.dapp("dappowner");
        check(entry.has_value() && entry->inactive_from != UINT64_MAX,
              "test6: DApp inactive_from set after deactivate");
        // During grace period, calls should still apply.
        uint64_t alice_pre6 = chain.balance("alice");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "dappowner",
                                    1, 0, pack_call("chat", {0xFF})));
        check(chain.balance("alice") == alice_pre6 - 1,
              "test6: alice debited (call during grace period still applies)");

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": dapp_call " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    if (cmd == "test-composable-batch") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Genesis: alice=100, bob=50, carol=0.
        Block genesis;
        genesis.index           = 0;
        genesis.prev_hash       = Hash{};
        genesis.timestamp       = 0;
        genesis.cumulative_rand = Hash{};
        auto mk_alloc = [](const std::string& d, uint64_t bal) {
            GenesisAlloc a; a.domain = d; a.balance = bal; a.stake = 0;
            return a;
        };
        genesis.initial_state.push_back(mk_alloc("alice", 100));
        genesis.initial_state.push_back(mk_alloc("bob",   50));
        genesis.initial_state.push_back(mk_alloc("carol", 0));
        Chain chain(genesis);

        // Helper: build a TRANSFER inner tx (unsigned — apply-path doesn't
        // re-verify sigs; that's validator-side. This test exercises
        // apply semantics, not sig verification).
        auto mk_inner_transfer = [](const std::string& from,
                                       const std::string& to,
                                       uint64_t amount,
                                       uint64_t nonce) {
            Transaction t;
            t.type   = TxType::TRANSFER;
            t.from   = from;
            t.to     = to;
            t.amount = amount;
            t.fee    = 0;
            t.nonce  = nonce;
            t.payload = {};
            t.hash    = t.compute_hash();
            return t;
        };
        // Helper: package inner txs into a COMPOSABLE_BATCH JSON payload.
        auto pack_batch = [](const std::vector<Transaction>& inner) {
            nlohmann::json arr = nlohmann::json::array();
            for (auto& t : inner) arr.push_back(t.to_json());
            std::string s = arr.dump();
            return std::vector<uint8_t>(s.begin(), s.end());
        };
        // Helper: build a block carrying a single COMPOSABLE_BATCH outer tx.
        auto build_batch_block = [&](const std::string& outer_from,
                                        uint64_t outer_fee,
                                        const std::vector<Transaction>& inner) {
            Block b;
            b.index           = chain.height();
            b.prev_hash       = chain.head_hash();
            b.timestamp       = 1;
            b.cumulative_rand = Hash{};
            Transaction outer;
            outer.type    = TxType::COMPOSABLE_BATCH;
            outer.from    = outer_from;
            outer.to      = "";
            outer.amount  = 0;
            outer.fee     = outer_fee;
            outer.nonce   = chain.next_nonce(outer_from);
            outer.payload = pack_batch(inner);
            outer.hash    = outer.compute_hash();
            b.transactions.push_back(outer);
            return b;
        };

        // Test 1: successful batch — alice→bob 25, bob→carol 10.
        // Expected: alice=75, bob=65, carol=10. Nonces advance:
        // alice +2 (outer batch + inner TRANSFER), bob +1 (inner).
        uint64_t alice_n0 = chain.next_nonce("alice");
        uint64_t bob_n0   = chain.next_nonce("bob");
        std::vector<Transaction> inner1 = {
            mk_inner_transfer("alice", "bob",   25, alice_n0 + 1),
            mk_inner_transfer("bob",   "carol", 10, bob_n0),
        };
        chain.append(build_batch_block("alice", /*fee=*/0, inner1));
        check(chain.balance("alice") == 75,  "test1: alice=75 (commit)");
        check(chain.balance("bob")   == 65,  "test1: bob=65 (commit)");
        check(chain.balance("carol") == 10,  "test1: carol=10 (commit)");
        check(chain.next_nonce("alice") == alice_n0 + 2,
              "test1: alice nonce +2 (outer + inner)");
        check(chain.next_nonce("bob")   == bob_n0 + 1,
              "test1: bob nonce +1 (inner)");
        check(chain.next_nonce("carol") == 0,
              "test1: carol nonce unchanged");

        // Test 2: failing batch — alice→bob 25 (ok), then alice→bob 200
        // (alice has 50 after first inner, can't send 200). Whole batch
        // rolls back. Outer fee + outer nonce still consumed.
        uint64_t alice_pre  = chain.balance("alice");
        uint64_t bob_pre    = chain.balance("bob");
        uint64_t carol_pre  = chain.balance("carol");
        uint64_t alice_n1   = chain.next_nonce("alice");
        uint64_t bob_n1     = chain.next_nonce("bob");
        std::vector<Transaction> inner2 = {
            mk_inner_transfer("alice", "bob", 25,  alice_n1 + 1),
            mk_inner_transfer("alice", "bob", 200, alice_n1 + 2),
        };
        chain.append(build_batch_block("alice", 0, inner2));
        // Save balances/nonces to locals before checking to avoid an
        // apparent MSVC optimization issue when chain.balance() is
        // called inline in a check() argument across multiple statements
        // post-rollback (see investigation note in commit message).
        uint64_t alice_after2  = chain.balance("alice");
        uint64_t bob_after2    = chain.balance("bob");
        uint64_t carol_after2  = chain.balance("carol");
        uint64_t alice_n_after = chain.next_nonce("alice");
        uint64_t bob_n_after   = chain.next_nonce("bob");
        check(alice_after2  == alice_pre,    "test2: alice unchanged (rollback)");
        check(bob_after2    == bob_pre,      "test2: bob unchanged (rollback)");
        check(carol_after2  == carol_pre,    "test2: carol unchanged (rollback)");
        check(alice_n_after == alice_n1 + 1, "test2: alice nonce +1 (outer)");
        check(bob_n_after   == bob_n1,       "test2: bob nonce unchanged (rollback)");

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": composable_batch " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-018 regression: exercise json_require<T> and json_require_hex
    // helpers + the converted from_json paths in block.cpp /
    // producer.cpp. Verifies that malformed JSON produces a clear
    // field-name diagnostic instead of an opaque nlohmann error.
    if (cmd == "test-s018-json-validation") {
        using namespace determ;
        using namespace determ::chain;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };
        // Helper: expect that calling fn() throws and the message
        // contains every needle in `needles`. Defends against the
        // helpers regressing to opaque nlohmann errors.
        auto expect_throw_with = [&](const char* test_name,
                                       std::function<void()> fn,
                                       std::vector<std::string> needles) {
            try {
                fn();
                std::cout << "  FAIL: " << test_name
                          << " (expected exception, none thrown)\n";
                fail++;
            } catch (const std::exception& e) {
                std::string msg = e.what();
                bool all = true;
                for (auto& n : needles) {
                    if (msg.find(n) == std::string::npos) { all = false; break; }
                }
                if (all) {
                    std::cout << "  PASS: " << test_name << "\n";
                } else {
                    std::cout << "  FAIL: " << test_name
                              << " (got '" << msg << "')\n";
                    fail++;
                }
            }
        };

        // 1. Happy path: valid Transaction round-trips.
        {
            Transaction tx;
            tx.type     = TxType::TRANSFER;
            tx.from     = "alice";
            tx.to       = "bob";
            tx.amount   = 100;
            tx.fee      = 1;
            tx.nonce    = 7;
            tx.sig      = {}; tx.hash = {};
            tx.payload  = {};
            json j      = tx.to_json();
            Transaction back = Transaction::from_json(j);
            check(back.from == "alice" && back.amount == 100,
                  "happy: tx round-trips through to_json/from_json");
        }

        // 2. Missing required field — should name "amount".
        expect_throw_with("missing 'amount' names the field", [] {
            json j = {{"type", 0}, {"from", "a"}, {"to", "b"},
                      {"nonce", 0}, {"payload", ""},
                      {"sig",  std::string(128, '0')},
                      {"hash", std::string(64,  '0')}};
            Transaction::from_json(j);
        }, {"S-018", "missing", "'amount'"});

        // 3. Wrong-type field — string where uint64 expected.
        expect_throw_with("wrong-type 'amount' names the field", [] {
            json j = {{"type", 0}, {"from", "a"}, {"to", "b"},
                      {"amount", "not-a-number"}, {"nonce", 0},
                      {"payload", ""},
                      {"sig",  std::string(128, '0')},
                      {"hash", std::string(64,  '0')}};
            Transaction::from_json(j);
        }, {"S-018", "'amount'", "wrong type"});

        // 4. Wrong-length hex on a fixed-width field — should name
        //    "sig" and the expected length (128).
        expect_throw_with("wrong-hex-length 'sig' names the field", [] {
            json j = {{"type", 0}, {"from", "a"}, {"to", "b"},
                      {"amount", 1}, {"nonce", 0}, {"payload", ""},
                      {"sig",  std::string(100, '0')},   // wrong length
                      {"hash", std::string(64,  '0')}};
            Transaction::from_json(j);
        }, {"S-018", "'sig'", "hex length"});

        // 5. Missing field on AbortEvent — should name 'event_hash'.
        expect_throw_with("AbortEvent missing 'event_hash'", [] {
            json j = {{"round", 1}, {"aborting_node", "node1"},
                      {"timestamp", 0}};
            AbortEvent::from_json(j);
        }, {"S-018", "missing", "'event_hash'"});

        // 6. Missing field on EquivocationEvent — should name 'sig_b'.
        expect_throw_with("EquivocationEvent missing 'sig_b'", [] {
            json j = {{"equivocator", "node1"}, {"block_index", 5},
                      {"digest_a", std::string(64, '0')},
                      {"sig_a",    std::string(128, '0')},
                      {"digest_b", std::string(64, '1')}};
            EquivocationEvent::from_json(j);
        }, {"S-018", "missing", "'sig_b'"});

        // 7. Block missing 'transactions' array — should name the
        //    field (not produce an opaque iterator exception).
        expect_throw_with("Block missing 'transactions'", [] {
            json j = {{"index", 1},
                      {"prev_hash", std::string(64, '0')},
                      {"timestamp", 0},
                      {"creators", json::array()},
                      {"abort_events", json::array()},
                      {"cumulative_rand", std::string(64, '0')}};
            Block::from_json(j);
        }, {"S-018", "transactions"});

        // 8. GenesisAlloc missing 'domain' — protects snapshot
        //    `initial_state` + genesis-tool initial_balances paths.
        expect_throw_with("GenesisAlloc missing 'domain'", [] {
            json j = {{"balance", 100}, {"stake", 0}};
            GenesisAlloc::from_json(j);
        }, {"S-018", "missing", "'domain'"});

        // 9. Block optional 'state_root' field with wrong hex length
        //    — guards the S-033 state_root snapshot-restore path
        //    against a malformed snapshot tail-header (the field is
        //    optional, but if present must be exactly 32 bytes).
        expect_throw_with("Block 'state_root' wrong hex length", [] {
            json j = {{"index", 1},
                      {"prev_hash", std::string(64, '0')},
                      {"timestamp", 0},
                      {"transactions", json::array()},
                      {"creators", json::array()},
                      {"abort_events", json::array()},
                      {"cumulative_rand", std::string(64, '0')},
                      {"state_root", std::string(60, 'a')}};  // wrong length
            Block::from_json(j);
        }, {"S-018", "'state_root'", "hex length"});

        // 10. Block 'transactions' present but non-array (e.g., string)
        //     — exercises json_require_array's wrong-type diagnostic
        //     so a malformed BLOCK gossip message with a stringified
        //     transactions field gets a clear "expected array, got X"
        //     error.
        expect_throw_with("Block 'transactions' non-array", [] {
            json j = {{"index", 1},
                      {"prev_hash", std::string(64, '0')},
                      {"timestamp", 0},
                      {"transactions", "not-an-array"},  // string, not array
                      {"creators", json::array()},
                      {"abort_events", json::array()},
                      {"cumulative_rand", std::string(64, '0')}};
            Block::from_json(j);
        }, {"S-018", "'transactions'", "expected array"});

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": s018_json_validation "
                  << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    if (cmd == "stake")       return cmd_stake(sub_argc, sub_argv);
    if (cmd == "unstake")     return cmd_unstake(sub_argc, sub_argv);
    if (cmd == "nonce")       return cmd_nonce(sub_argc, sub_argv);
    if (cmd == "stake_info")    return cmd_stake_info(sub_argc, sub_argv);
    if (cmd == "submit-param-change") return cmd_submit_param_change(sub_argc, sub_argv);
    if (cmd == "submit-merge-event")  return cmd_submit_merge_event(sub_argc, sub_argv);
    if (cmd == "submit-dapp-register") return cmd_submit_dapp_register(sub_argc, sub_argv);
    if (cmd == "submit-dapp-call")     return cmd_submit_dapp_call(sub_argc, sub_argv);
    if (cmd == "genesis-tool")  return cmd_genesis_tool(sub_argc, sub_argv);
    if (cmd == "account")       return cmd_account(sub_argc, sub_argv);
    if (cmd == "send_anon")     return cmd_send_anon(sub_argc, sub_argv);

    std::cerr << "Unknown command: " << cmd << "\n\n";
    usage();
    return 1;
}
