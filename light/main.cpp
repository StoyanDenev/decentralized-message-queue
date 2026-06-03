// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light — trust-minimized light-client wallet binary.
//
// A third Determ binary alongside `determ` (full daemon) and
// `determ-wallet` (account management). The light-client talks to a
// daemon's RPC but verifies every piece of data it receives. Trust
// anchor is the genesis JSON file supplied via --genesis on every
// connection — the light-client computes compute_genesis_hash locally
// and refuses to proceed if the daemon's block 0 doesn't match.
//
// Subcommands (15 total + help / version):
//   verify-headers           Verify a `headers` RPC reply's chain
//   verify-block-sigs        Verify K-of-K committee sigs on a header
//   verify-state-proof       Verify a state-proof against a root
//   fetch-headers            Fetch headers from the daemon's RPC
//   fetch-state-proof        Fetch a state-proof from the daemon's RPC
//   verify-chain             Composite: anchor + verify all to head
//   balance-trustless        Composite: verify chain + state-proof balance
//   nonce-trustless          Composite: verify chain + state-proof nonce
//   sign-tx                  Offline signed TRANSFER/STAKE/UNSTAKE
//   submit-tx                Submit a pre-signed tx to the daemon
//   verify-and-submit        Composite: trustless nonce + sign + submit
//   watch-head               Periodic trust-minimized head monitor
//   export-headers           Verifiable header archive (FETCH+VERIFY+WRITE)
//   verify-archive           OFFLINE re-verify of an export-headers archive
//   help / version
//
// Trust-model invariants:
//   * Every command that touches the daemon's RPC takes --genesis to
//     pin the chain identity on first connection.
//   * Composite read commands (balance-trustless, nonce-trustless) DO
//     NOT trust the daemon's `account` reply unless the cleartext
//     hashes to the value_hash in a verified state-proof.
//   * verify-and-submit fetches the verified nonce via nonce-trustless
//     (not the daemon's raw `account` reply) before signing.

#include "rpc_client.hpp"
#include "verify.hpp"
#include "trustless_read.hpp"
#include "keyfile.hpp"
#include "sign_tx.hpp"
#include "watch.hpp"
#include "export.hpp"
#include "verify_archive.hpp"

#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using nlohmann::json;
using namespace determ;
using namespace determ::light;

constexpr const char* DETERM_LIGHT_VERSION = "1.0.0";

void print_usage() {
    std::cout <<
        "Usage: determ-light <command> [options]\n"
        "\n"
        "A trust-minimized light-client wallet for Determ. Reads chain\n"
        "data via a daemon's RPC, verifies every piece locally against a\n"
        "pinned genesis hash, signs txs offline, and submits via RPC.\n"
        "\n"
        "Verification primitives (offline):\n"
        "  verify-headers --in <file> [--genesis-hash <hex>] [--prev-hash <hex>]\n"
        "      Verify the prev_hash chain in a `headers` RPC reply.\n"
        "  verify-block-sigs --header <file> --committee <file> [--bft]\n"
        "      Verify K-of-K committee Ed25519 sigs (or ceil(2K/3) BFT).\n"
        "  verify-state-proof --in <file> [--state-root <hex>]\n"
        "      Verify a state-proof Merkle inclusion against a root.\n"
        "\n"
        "RPC fetch primitives:\n"
        "  fetch-headers --rpc-port <N> --from <I> --count <M> [--out <file>]\n"
        "      Fetch headers [I, I+M) from 127.0.0.1:N.\n"
        "  fetch-state-proof --rpc-port <N> --ns <NS> --key <K> [--out <file>]\n"
        "      Fetch a state-proof for (NS, K) from 127.0.0.1:N.\n"
        "\n"
        "Composite trustless reads (--genesis required):\n"
        "  verify-chain --rpc-port <N> --genesis <file>\n"
        "      Anchor genesis + fetch all headers + verify every committee sig.\n"
        "  balance-trustless --rpc-port <N> --genesis <file> --domain <D> [--json]\n"
        "      Verified chain + state-proof + cross-check daemon's cleartext.\n"
        "  nonce-trustless --rpc-port <N> --genesis <file> --domain <D> [--json]\n"
        "      Same as balance-trustless but extracts next_nonce.\n"
        "\n"
        "Sign + submit:\n"
        "  sign-tx --keyfile <path> --type {TRANSFER|STAKE|UNSTAKE}\n"
        "          --to <addr> --amount <N> --fee <N> --nonce <N> [--out <file>]\n"
        "      Offline sign with operator-supplied nonce.\n"
        "  submit-tx --rpc-port <N> --tx-json <file>\n"
        "      Submit a pre-signed tx via the daemon's submit_tx RPC.\n"
        "  verify-and-submit --rpc-port <N> --genesis <file> --keyfile <path>\n"
        "                    --to <addr> --amount <N> --fee <N> [--out <file>]\n"
        "      Composite: nonce-trustless + sign-tx + submit-tx.\n"
        "\n"
        "Monitoring:\n"
        "  watch-head --rpc-port <N> --genesis <file> [--count <N>] [--interval <s>]\n"
        "      Anchor genesis once + poll the daemon's head every <s> seconds.\n"
        "      Verifies committee sigs each tick; prints a structured progress\n"
        "      line per tick. Exits on SIGINT or after --count ticks.\n"
        "\n"
        "Archive:\n"
        "  export-headers --rpc-port <N> --genesis <file> --from <H1> --count <M>\n"
        "                 --out <file> [--include-committee-sigs]\n"
        "      Fetch + verify headers [H1, H1+M) + write a self-contained\n"
        "      verifiable archive to <file>. Re-verifiable offline at any\n"
        "      later date via verify-headers --in <file>.\n"
        "  verify-archive --in <archive> --genesis <file> [--require-sigs]\n"
        "      OFFLINE re-verification of an export-headers archive (no\n"
        "      daemon, no RPC). Anchors genesis (compute_genesis_hash ==\n"
        "      archive.genesis_hash), re-checks the prev_hash chain, and\n"
        "      re-verifies committee sigs when the archive retained them\n"
        "      (--include-committee-sigs at export). --require-sigs makes a\n"
        "      sigs-stripped archive fail.\n"
        "\n"
        "Meta:\n"
        "  help, --help, -h    Show this message.\n"
        "  version, --version  Show binary version.\n"
        "\n"
        "Trust model: --genesis pins chain identity; light-client refuses to\n"
        "talk to any daemon whose block 0 doesn't hash to compute_genesis_hash\n"
        "of the supplied JSON. Verified reads cross-check the daemon's\n"
        "cleartext account RPC against state-proofs anchored to the head's\n"
        "state_root — daemon lies are detected, not propagated.\n";
}

// Read full file into a json. Throws on parse failure with a clear
// path-bearing diagnostic.
json read_json_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open: " + path);
    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        throw std::runtime_error("parse error in " + path + ": " + e.what());
    }
    return j;
}

void write_json_file(const std::string& path, const json& j) {
    std::ofstream f(path);
    if (!f) throw std::runtime_error("cannot open --out for write: " + path);
    f << j.dump() << "\n";
    if (!f) throw std::runtime_error("write failed on --out: " + path);
}

// Parse a uint64_t-like CLI argument. Throws on invalid input with a
// diagnostic naming the flag.
uint64_t parse_u64(const std::string& flag, const std::string& v) {
    try {
        size_t pos = 0;
        long long n = std::stoll(v, &pos);
        if (pos != v.size())
            throw std::invalid_argument("trailing chars");
        if (n < 0)
            throw std::invalid_argument("negative value");
        return static_cast<uint64_t>(n);
    } catch (const std::exception&) {
        throw std::runtime_error(
            flag + " must be a non-negative integer (got '" + v + "')");
    }
}

uint16_t parse_u16(const std::string& flag, const std::string& v) {
    uint64_t u = parse_u64(flag, v);
    if (u > 65535) throw std::runtime_error(flag + " out of range (>65535)");
    return static_cast<uint16_t>(u);
}

// ──────────────────────── verify-headers ──────────────────────────────

int cmd_verify_headers(int argc, char** argv) {
    std::string in_path;
    std::string genesis_hash_hex;
    std::string prev_hash_hex;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"           && i + 1 < argc) in_path          = argv[++i];
        else if (a == "--genesis-hash" && i + 1 < argc) genesis_hash_hex = argv[++i];
        else if (a == "--prev-hash"    && i + 1 < argc) prev_hash_hex    = argv[++i];
        else {
            std::cerr << "verify-headers: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    try {
        json doc = in_path.empty()
            ? json::parse(std::cin)
            : read_json_file(in_path);
        auto r = verify_headers(doc, genesis_hash_hex, prev_hash_hex);
        if (!r.ok) { std::cerr << r.detail << "\n"; return 1; }
        std::cout << "OK\n"
                  << "  verified:   " << r.count << " header(s)\n"
                  << "  head_hash:  " << r.block_hash_hex << "\n";
        if (!genesis_hash_hex.empty())
            std::cout << "  genesis pin: matches\n";
        else if (!prev_hash_hex.empty())
            std::cout << "  prev pin:    matches\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-headers: " << e.what() << "\n";
        return 1;
    }
}

// ───────────────────── verify-block-sigs ───────────────────────────────

int cmd_verify_block_sigs(int argc, char** argv) {
    std::string header_path, committee_path;
    bool bft = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--header"    && i + 1 < argc) header_path    = argv[++i];
        else if (a == "--committee" && i + 1 < argc) committee_path = argv[++i];
        else if (a == "--bft")                       bft = true;
        else {
            std::cerr << "verify-block-sigs: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (header_path.empty() || committee_path.empty()) {
        std::cerr << "verify-block-sigs: --header and --committee are required\n";
        return 1;
    }
    try {
        json header_json = read_json_file(header_path);
        json committee_json = read_json_file(committee_path);
        auto r = verify_block_sigs(header_json, committee_json, bft);
        if (!r.ok) { std::cerr << r.detail << "\n"; return 1; }
        std::cout << "OK\n"
                  << "  mode:      " << (bft ? "BFT" : "MD") << "\n"
                  << "  verified:  " << r.count << " sig(s)\n"
                  << "  digest:    " << r.digest_hex << "\n";
        if (!r.state_root_hex.empty())
            std::cout << "  state_root: " << r.state_root_hex << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-block-sigs: " << e.what() << "\n";
        return 1;
    }
}

// ───────────────────── verify-state-proof ──────────────────────────────

int cmd_verify_state_proof(int argc, char** argv) {
    std::string in_path, expected_root_hex;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"         && i + 1 < argc) in_path           = argv[++i];
        else if (a == "--state-root" && i + 1 < argc) expected_root_hex = argv[++i];
        else {
            std::cerr << "verify-state-proof: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    try {
        json doc = in_path.empty()
            ? json::parse(std::cin)
            : read_json_file(in_path);
        auto r = verify_state_proof(doc, expected_root_hex);
        if (!r.ok) { std::cerr << r.detail << "\n"; return 1; }
        std::cout << "OK\n"
                  << "  state_root:  " << r.state_root_hex << "\n"
                  << "  proof depth: " << r.count << " sibling hashes\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-state-proof: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── fetch-headers ────────────────────────────────

int cmd_fetch_headers(int argc, char** argv) {
    uint16_t port = 0;
    uint64_t from = 0;
    uint64_t count = 256;
    std::string out_path;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--from"   && i + 1 < argc) {
            from = parse_u64("--from", argv[++i]);
        } else if (a == "--count"  && i + 1 < argc) {
            count = parse_u64("--count", argv[++i]);
        } else if (a == "--out"    && i + 1 < argc) {
            out_path = argv[++i];
        } else {
            std::cerr << "fetch-headers: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port) {
        std::cerr << "fetch-headers: --rpc-port is required\n";
        return 1;
    }
    try {
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "fetch-headers: " << rpc.last_error() << "\n";
            return 1;
        }
        auto reply = rpc.call("headers", {{"from", from}, {"count", count}});
        if (out_path.empty()) {
            std::cout << reply.dump() << "\n";
        } else {
            write_json_file(out_path, reply);
            std::cout << "OK: wrote "
                      << reply.value("count", uint64_t{0})
                      << " header(s) to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fetch-headers: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────── fetch-state-proof ──────────────────────────────

int cmd_fetch_state_proof(int argc, char** argv) {
    uint16_t port = 0;
    std::string ns, key, out_path;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--ns"    && i + 1 < argc) ns       = argv[++i];
        else if   (a == "--key"   && i + 1 < argc) key      = argv[++i];
        else if   (a == "--out"   && i + 1 < argc) out_path = argv[++i];
        else {
            std::cerr << "fetch-state-proof: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || ns.empty() || key.empty()) {
        std::cerr << "fetch-state-proof: --rpc-port, --ns, --key are required\n";
        return 1;
    }
    try {
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "fetch-state-proof: " << rpc.last_error() << "\n";
            return 1;
        }
        auto reply = rpc.call("state_proof",
            {{"namespace", ns}, {"key", key}});
        if (out_path.empty()) {
            std::cout << reply.dump() << "\n";
        } else {
            write_json_file(out_path, reply);
            std::cout << "OK: wrote state-proof to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fetch-state-proof: " << e.what() << "\n";
        return 1;
    }
}

// ───────────────────────── verify-chain ────────────────────────────────

int cmd_verify_chain(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else {
            std::cerr << "verify-chain: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty()) {
        std::cerr << "verify-chain: --rpc-port and --genesis are required\n";
        return 1;
    }
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-chain: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
        std::cout << "OK\n"
                  << "  genesis pin:        matches (" << genesis_hash_hex << ")\n"
                  << "  height:             " << vc.height << "\n"
                  << "  headers verified:   " << vc.headers_verified << "\n"
                  << "  blocks (sigs):      " << vc.blocks_with_sigs_verified << "\n"
                  << "  head block_hash:    " << vc.head_block_hash << "\n";
        if (!vc.head_state_root.empty())
            std::cout << "  head state_root:    " << vc.head_state_root << "\n";
        else
            std::cout << "  head state_root:    (not populated — pre-S-033 chain)\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-chain: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────── balance-trustless / nonce-trustless ────────────

int cmd_account_trustless(int argc, char** argv,
                           bool want_balance, const std::string& cmd_name) {
    uint16_t port = 0;
    std::string genesis_path, domain;
    bool have_port = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--domain"  && i + 1 < argc) domain       = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else {
            std::cerr << cmd_name << ": unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || domain.empty()) {
        std::cerr << cmd_name
                  << ": --rpc-port, --genesis, --domain are required\n";
        return 1;
    }
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << cmd_name << ": " << rpc.last_error() << "\n";
            return 1;
        }
        std::string canon_domain = normalize_anon_address(domain);
        auto view = read_account_trustless(rpc, committee_seed, genesis,
                                            canon_domain);
        if (json_out) {
            json out = {
                {"domain",        canon_domain},
                {"balance",       view.balance},
                {"next_nonce",    view.next_nonce},
                {"height",        view.height},
                {"state_root",    view.state_root_hex},
                {"verified",      true},
            };
            std::cout << out.dump() << "\n";
        } else {
            uint64_t v = want_balance ? view.balance : view.next_nonce;
            const char* tag = want_balance ? "balance" : "next_nonce";
            std::cout << canon_domain << ": " << v << " ("
                      << tag << " verified via state-proof at height "
                      << view.height << ", state_root "
                      << view.state_root_hex.substr(0, 16) << "...)\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << cmd_name << ": " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────────── sign-tx ──────────────────────────────────

int cmd_sign_tx(int argc, char** argv) {
    std::string keyfile_path, type_str, to_str, out_path;
    bool have_amount = false, have_fee = false, have_nonce = false;
    uint64_t amount = 0, fee = 0, nonce = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--keyfile" && i + 1 < argc) keyfile_path = argv[++i];
        else if (a == "--type"    && i + 1 < argc) type_str     = argv[++i];
        else if (a == "--to"      && i + 1 < argc) to_str       = argv[++i];
        else if (a == "--amount"  && i + 1 < argc) { amount = parse_u64("--amount", argv[++i]); have_amount = true; }
        else if (a == "--fee"     && i + 1 < argc) { fee    = parse_u64("--fee",    argv[++i]); have_fee    = true; }
        else if (a == "--nonce"   && i + 1 < argc) { nonce  = parse_u64("--nonce",  argv[++i]); have_nonce  = true; }
        else if (a == "--out"     && i + 1 < argc) out_path     = argv[++i];
        else {
            std::cerr << "sign-tx: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (keyfile_path.empty() || type_str.empty()
        || !have_amount || !have_fee || !have_nonce) {
        std::cerr << "sign-tx: --keyfile, --type, --amount, --fee, --nonce "
                     "are required\n";
        return 1;
    }
    try {
        LightTxType type = parse_tx_type(type_str);
        if (type == LightTxType::TRANSFER && to_str.empty()) {
            std::cerr << "sign-tx: TRANSFER requires --to\n";
            return 1;
        }
        // Normalize anon-shape `to` to canonical lowercase (S-028).
        // Other shapes (domain names) pass through unchanged.
        if (!to_str.empty()) {
            std::string canonical = normalize_anon_address(to_str);
            if (canonical != to_str) {
                std::cerr << "sign-tx: --to is anon-shape but not canonical "
                             "lowercase (S-028); got '" << to_str << "'\n";
                return 1;
            }
        }
        auto kf = load_light_keyfile(keyfile_path);
        auto signed_tx = sign_light_tx(kf, type, to_str, amount, fee, nonce);
        if (out_path.empty()) {
            std::cout << signed_tx.dump() << "\n";
        } else {
            write_json_file(out_path, signed_tx);
            std::cout << "OK: wrote signed tx (hash="
                      << signed_tx["hash"].get<std::string>().substr(0, 16)
                      << "...) to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "sign-tx: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────────── submit-tx ────────────────────────────────

int cmd_submit_tx(int argc, char** argv) {
    uint16_t port = 0;
    std::string tx_path;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--tx-json" && i + 1 < argc) tx_path = argv[++i];
        else {
            std::cerr << "submit-tx: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || tx_path.empty()) {
        std::cerr << "submit-tx: --rpc-port and --tx-json are required\n";
        return 1;
    }
    try {
        json tx = read_json_file(tx_path);
        // The daemon's submit_tx RPC accepts {"tx": <canonical-tx-json>}
        // per rpc.cpp:226 params.value("tx", ...). Sign-tx emits the
        // canonical Transaction shape with `sig` (not `signature`); we
        // wrap it here.
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "submit-tx: " << rpc.last_error() << "\n";
            return 1;
        }
        auto reply = rpc.call("submit_tx", {{"tx", tx}});
        std::cout << reply.dump() << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "submit-tx: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────── verify-and-submit ──────────────────────────────

int cmd_verify_and_submit(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, keyfile_path, to_str, out_path;
    bool have_port = false, have_amount = false, have_fee = false;
    uint64_t amount = 0, fee = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--keyfile" && i + 1 < argc) keyfile_path = argv[++i];
        else if   (a == "--to"      && i + 1 < argc) to_str       = argv[++i];
        else if   (a == "--amount"  && i + 1 < argc) { amount = parse_u64("--amount", argv[++i]); have_amount = true; }
        else if   (a == "--fee"     && i + 1 < argc) { fee    = parse_u64("--fee",    argv[++i]); have_fee    = true; }
        else if   (a == "--out"     && i + 1 < argc) out_path     = argv[++i];
        else {
            std::cerr << "verify-and-submit: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || keyfile_path.empty()
        || to_str.empty() || !have_amount || !have_fee) {
        std::cerr << "verify-and-submit: --rpc-port, --genesis, --keyfile, "
                     "--to, --amount, --fee are required\n";
        return 1;
    }
    try {
        // 1. Load genesis + keyfile.
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        auto kf = load_light_keyfile(keyfile_path);
        // 2. Open RPC connection (shared for all three sub-calls).
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-and-submit: " << rpc.last_error() << "\n";
            return 1;
        }
        // 3. Trustless-read the sender's nonce.
        auto view = read_account_trustless(rpc, committee_seed, genesis,
                                            kf.anon_address);
        // 4. Sign locally with the verified nonce.
        std::string canonical_to = normalize_anon_address(to_str);
        if (canonical_to != to_str) {
            std::cerr << "verify-and-submit: --to is anon-shape but not "
                         "canonical lowercase (S-028); got '" << to_str << "'\n";
            return 1;
        }
        auto signed_tx = sign_light_tx(kf, LightTxType::TRANSFER,
                                         canonical_to, amount, fee,
                                         view.next_nonce);
        // 5. Submit (params shape per rpc.cpp:226 is {"tx": <tx-json>}).
        auto submit_reply = rpc.call("submit_tx", {{"tx", signed_tx}});
        json out = {
            {"verified_at_height", view.height},
            {"verified_nonce",     view.next_nonce},
            {"verified_balance",   view.balance},
            {"state_root",         view.state_root_hex},
            {"submitted_tx_hash",  signed_tx["hash"]},
            {"submit_reply",       submit_reply},
        };
        if (!out_path.empty()) {
            write_json_file(out_path, out);
            std::cout << "OK: wrote verify-and-submit log to " << out_path
                      << "\n";
        } else {
            std::cout << out.dump() << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-and-submit: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────────── watch-head ────────────────────────────────

int cmd_watch_head(int argc, char** argv) {
    WatchOptions opts;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            opts.rpc_port = parse_u16("--rpc-port", argv[++i]);
            have_port = true;
        } else if (a == "--genesis"  && i + 1 < argc) {
            opts.genesis_path = argv[++i];
        } else if (a == "--count"    && i + 1 < argc) {
            opts.count = parse_u64("--count", argv[++i]);
        } else if (a == "--interval" && i + 1 < argc) {
            opts.interval_secs = parse_u64("--interval", argv[++i]);
        } else {
            std::cerr << "watch-head: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || opts.genesis_path.empty()) {
        std::cerr << "watch-head: --rpc-port and --genesis are required\n";
        return 1;
    }
    try {
        return run_watch_head(opts);
    } catch (const std::exception& e) {
        std::cerr << "watch-head: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── export-headers ───────────────────────────────

int cmd_export_headers(int argc, char** argv) {
    ExportOptions opts;
    bool have_port = false, have_from = false, have_count = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            opts.rpc_port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) {
            opts.genesis_path = argv[++i];
        } else if (a == "--from"    && i + 1 < argc) {
            opts.from = parse_u64("--from", argv[++i]); have_from = true;
        } else if (a == "--count"   && i + 1 < argc) {
            opts.count = parse_u64("--count", argv[++i]); have_count = true;
        } else if (a == "--out"     && i + 1 < argc) {
            opts.out_path = argv[++i];
        } else if (a == "--include-committee-sigs") {
            opts.include_committee_sigs = true;
        } else {
            std::cerr << "export-headers: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || opts.genesis_path.empty() || !have_from
        || !have_count || opts.out_path.empty()) {
        std::cerr << "export-headers: --rpc-port, --genesis, --from, --count, "
                     "--out are required\n";
        return 1;
    }
    return run_export_headers(opts);
}

// ──────────────────────── verify-archive ───────────────────────────────

int cmd_verify_archive(int argc, char** argv) {
    VerifyArchiveOptions opts;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"      && i + 1 < argc) opts.in_path      = argv[++i];
        else if (a == "--genesis" && i + 1 < argc) opts.genesis_path = argv[++i];
        else if (a == "--require-sigs")            opts.require_sigs  = true;
        else {
            std::cerr << "verify-archive: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (opts.in_path.empty() || opts.genesis_path.empty()) {
        std::cerr << "verify-archive: --in and --genesis are required\n";
        return 1;
    }
    return run_verify_archive(opts);
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { print_usage(); return 1; }
    std::string cmd = argv[1];

    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_usage();
        return 0;
    }
    if (cmd == "version" || cmd == "--version") {
        std::cout << "determ-light " << DETERM_LIGHT_VERSION << "\n";
        return 0;
    }

    int sub_argc = argc - 2;
    char** sub_argv = argv + 2;

    try {
        if (cmd == "verify-headers")        return cmd_verify_headers(sub_argc, sub_argv);
        if (cmd == "verify-block-sigs")     return cmd_verify_block_sigs(sub_argc, sub_argv);
        if (cmd == "verify-state-proof")    return cmd_verify_state_proof(sub_argc, sub_argv);
        if (cmd == "fetch-headers")         return cmd_fetch_headers(sub_argc, sub_argv);
        if (cmd == "fetch-state-proof")     return cmd_fetch_state_proof(sub_argc, sub_argv);
        if (cmd == "verify-chain")          return cmd_verify_chain(sub_argc, sub_argv);
        if (cmd == "balance-trustless")     return cmd_account_trustless(sub_argc, sub_argv, true,  "balance-trustless");
        if (cmd == "nonce-trustless")       return cmd_account_trustless(sub_argc, sub_argv, false, "nonce-trustless");
        if (cmd == "sign-tx")               return cmd_sign_tx(sub_argc, sub_argv);
        if (cmd == "submit-tx")             return cmd_submit_tx(sub_argc, sub_argv);
        if (cmd == "verify-and-submit")     return cmd_verify_and_submit(sub_argc, sub_argv);
        if (cmd == "watch-head")            return cmd_watch_head(sub_argc, sub_argv);
        if (cmd == "export-headers")        return cmd_export_headers(sub_argc, sub_argv);
        if (cmd == "verify-archive")        return cmd_verify_archive(sub_argc, sub_argv);
    } catch (const std::exception& e) {
        std::cerr << "determ-light: unhandled error: " << e.what() << "\n";
        return 2;
    }

    std::cerr << "determ-light: unknown subcommand '" << cmd << "'\n"
              << "  run `determ-light help` for the list of commands\n";
    return 1;
}
