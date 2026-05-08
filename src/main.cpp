#include <dhcoin/node/node.hpp>
#include <dhcoin/rpc/rpc.hpp>
#include <dhcoin/chain/block.hpp>
#include <dhcoin/chain/params.hpp>
#include <dhcoin/crypto/keys.hpp>
#include <dhcoin/chain/genesis.hpp>
#include <openssl/evp.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstring>

namespace fs = std::filesystem;
using json = nlohmann::json;
using namespace dhcoin;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static std::string default_data_dir() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    return appdata ? std::string(appdata) + "\\dhcoin" : ".dhcoin";
#else
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/.dhcoin" : ".dhcoin";
#endif
}

static std::string config_path(const std::string& data_dir) {
    return data_dir + "/config.json";
}

static void usage() {
    std::cout << R"(DHCoin — fork-free DH-consensus cryptocurrency

Usage:
  dhcoin init [--data-dir <dir>] [--profile cluster|web|regional|global]
                                              [--genesis <config.json>]
                                              Generate node keys and config
  dhcoin register <domain> [--rpc-port <p>]  Submit RegisterTx to running node
  dhcoin start [--config <path>]             Start node (sync + participate in consensus)
  dhcoin send <to_domain> <amount>           Submit TRANSFER transaction
  dhcoin status                              Chain head, node count, next creators
  dhcoin peers                               List connected peers
  dhcoin balance [<domain>]                  Show domain balance
  dhcoin stake <amount> [--fee <n>]          Lock <amount> as registration stake
  dhcoin unstake <amount> [--fee <n>]        Release stake (after deregister + delay)
  dhcoin nonce [<domain>]                    Show next account nonce
  dhcoin stake_info [<domain>]               Show locked stake and unlock height
  dhcoin genesis-tool peer-info <domain>     Print this node's creator entry (JSON)
                                              for inclusion in a genesis config.
  dhcoin genesis-tool build <config.json>    Build a genesis from peer-info entries
                                              and print the genesis hash.
  dhcoin account create [--out <file>]       Generate a fresh anonymous account
                                              keypair (Ed25519). Prints address + privkey.
  dhcoin account address <privkey_hex>       Derive the account address from a hex privkey.
  dhcoin send_anon <to> <amount> <privkey_hex>
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
    if      (profile == "cluster")  tp = chain::PROFILE_CLUSTER;
    else if (profile == "regional") tp = chain::PROFILE_REGIONAL;
    else if (profile == "global")   tp = chain::PROFILE_GLOBAL;
    else if (profile != "web") {
        std::cerr << "Unknown --profile " << profile
                  << " (expected: cluster|web|regional|global)\n";
        return 1;
    }
    cfg.tx_commit_ms   = tp.tx_commit_ms;
    cfg.delay_T        = tp.delay_T;
    cfg.block_sig_ms   = tp.block_sig_ms;
    cfg.abort_claim_ms = tp.abort_claim_ms;
    cfg.m_creators     = tp.m_creators;
    cfg.k_block_sigs   = tp.k_block_sigs;

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
    std::cout << "  dhcoin start\n";
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

        std::cout << "[dhcoin] Loading node domain=" << cfg.domain
                  << " genesis_path=" << cfg.genesis_path << "\n" << std::flush;

        node::Node node(cfg);

        rpc::RpcServer rpc_server(node.io_context_access(), node, cfg.rpc_port);
        rpc_server.start();

        std::cout << "[dhcoin] Starting node domain=" << cfg.domain
                  << " port=" << cfg.listen_port << "\n" << std::flush;
        node.run(); // blocks
        return 0;
    } catch (std::exception& e) {
        std::cerr << "[dhcoin] FATAL: " << e.what() << std::endl;
        std::cerr.flush();
        return 1;
    } catch (...) {
        std::cerr << "[dhcoin] FATAL: unknown exception" << std::endl;
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
    if (argc < 1) { std::cerr << "Usage: dhcoin register <domain>\n"; return 1; }
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
    if (argc < 2) { std::cerr << "Usage: dhcoin send <to_domain> <amount> [--fee <n>]\n"; return 1; }
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
    if (argc < 1) { std::cerr << "Usage: dhcoin stake <amount> [--fee <n>]\n"; return 1; }
    uint64_t amount = std::stoull(argv[0]);
    uint64_t fee    = 0;
    uint16_t port   = get_rpc_port(argc, argv);
    for (int i = 1; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--fee") fee = std::stoull(argv[i + 1]);
    return submit_tx_with_retry(port, "stake", {{"amount", amount}, {"fee", fee}});
}

static int cmd_unstake(int argc, char** argv) {
    if (argc < 1) { std::cerr << "Usage: dhcoin unstake <amount> [--fee <n>]\n"; return 1; }
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
//   Loads the node's local key, generates a BLS PoP, and prints the JSON entry
//   the operator should send to whoever is assembling the genesis config.
static int cmd_genesis_tool_peer_info(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: dhcoin genesis-tool peer-info <domain> [--data-dir <dir>] [--stake <n>]\n";
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
                  << " (run 'dhcoin init --data-dir " << data_dir << "' first)\n";
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
//   verifies each PoP, prints the resulting genesis hash, and writes
//   <config>.hash next to the file for convenient distribution.
static int cmd_genesis_tool_build(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: dhcoin genesis-tool build <genesis_config.json>\n";
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
        std::cout << "M_creators:         " << cfg.m_creators         << "\n";
        std::cout << "K_block_sigs:       " << cfg.k_block_sigs       << "\n";
        std::cout << "Mode:               " << mode << " BFT\n";
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

// account create [--out <file>]
//   Generates a fresh Ed25519 keypair. Prints the account address (0x + 64 hex)
//   and the secret seed. The secret is sensitive — pipe to a file or vault.
static int cmd_account_create(int argc, char** argv) {
    std::string out_path;
    for (int i = 0; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--out") out_path = argv[i + 1];

    auto key = crypto::generate_node_key();
    std::string addr = make_anon_address(key.pub);
    std::string priv_hex = to_hex(key.priv_seed);

    json out = {
        {"address",   addr},
        {"privkey",   priv_hex},
        {"warning",   "store privkey securely; anyone with it controls the address"}
    };
    if (out_path.empty()) {
        std::cout << out.dump(2) << "\n";
    } else {
        std::ofstream f(out_path);
        if (!f) { std::cerr << "Cannot write " << out_path << "\n"; return 1; }
        f << out.dump(2) << "\n";
        std::cout << "Account written to " << out_path << "\n";
        std::cout << "Address: " << addr << "\n";
    }
    return 0;
}

// account address <privkey_hex>
//   Derives the account address from a privkey hex string (offline, no daemon needed).
static int cmd_account_address(int argc, char** argv) {
    if (argc < 1) { std::cerr << "Usage: dhcoin account address <privkey_hex>\n"; return 1; }
    crypto::NodeKey key;
    key.priv_seed = from_hex_arr<32>(argv[0]);

    // Re-derive pubkey from priv_seed (Ed25519: pub = clamp(seed) over G).
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
        std::cerr << "Usage: dhcoin account {create|address} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "create")  return cmd_account_create (argc - 1, argv + 1);
    if (sub == "address") return cmd_account_address(argc - 1, argv + 1);
    std::cerr << "Unknown account subcommand: " << sub << "\n";
    return 1;
}

// send_anon <to> <amount> <privkey_hex> [--fee <n>] [--rpc-port <p>]
//   Build a TRANSFER from the anon account owning <privkey_hex>, sign it,
//   submit via daemon's submit_tx RPC.
static int cmd_send_anon(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: dhcoin send_anon <to> <amount> <privkey_hex> "
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

    // Derive pubkey.
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, key.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "invalid privkey for Ed25519\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, key.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    std::string from_addr = make_anon_address(key.pub);

    // Query nonce via RPC.
    uint64_t nonce = 0;
    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "nonce", {{"domain", from_addr}});
        nonce = r.value("next_nonce", uint64_t{0});
    } catch (std::exception& e) {
        std::cerr << "nonce query failed: " << e.what() << "\n";
        return 1;
    }

    // Build, sign, hash.
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

static int cmd_genesis_tool(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: dhcoin genesis-tool {peer-info|build} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "peer-info") return cmd_genesis_tool_peer_info(argc - 1, argv + 1);
    if (sub == "build")     return cmd_genesis_tool_build    (argc - 1, argv + 1);
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
    if (cmd == "status")      return cmd_status(sub_argc, sub_argv);
    if (cmd == "peers")       return cmd_peers(sub_argc, sub_argv);
    if (cmd == "balance")     return cmd_balance(sub_argc, sub_argv);
    if (cmd == "stake")       return cmd_stake(sub_argc, sub_argv);
    if (cmd == "unstake")     return cmd_unstake(sub_argc, sub_argv);
    if (cmd == "nonce")       return cmd_nonce(sub_argc, sub_argv);
    if (cmd == "stake_info")    return cmd_stake_info(sub_argc, sub_argv);
    if (cmd == "genesis-tool")  return cmd_genesis_tool(sub_argc, sub_argv);
    if (cmd == "account")       return cmd_account(sub_argc, sub_argv);
    if (cmd == "send_anon")     return cmd_send_anon(sub_argc, sub_argv);

    std::cerr << "Unknown command: " << cmd << "\n\n";
    usage();
    return 1;
}
