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
// Subcommands (18 total + help / version):
//   verify-headers           Verify a `headers` RPC reply's chain
//   verify-block-sigs        Verify K-of-K committee sigs on a header
//   verify-state-proof       Verify a state-proof against a root
//   verify-state-root        Report the committee-verified state_root at H
//   fetch-headers            Fetch headers from the daemon's RPC
//   fetch-state-proof        Fetch a state-proof from the daemon's RPC
//   verify-chain             Composite: anchor + verify all to head
//   balance-trustless        Composite: verify chain + state-proof balance
//   nonce-trustless          Composite: verify chain + state-proof nonce
//   stake-trustless          Composite: verify chain + state-proof stake
//   account-history          Composite: verified balance/nonce over a range
//   sign-tx                  Offline signed TRANSFER/STAKE/UNSTAKE
//   submit-tx                Submit a pre-signed tx to the daemon
//   verify-and-submit        Composite: trustless nonce + sign + submit
//   watch-head               Periodic trust-minimized head monitor
//   export-headers           Verifiable header archive (FETCH+VERIFY+WRITE)
//   verify-archive           OFFLINE re-verify of an export-headers archive
//   verify-tx-inclusion      Prove tx H is (not) in block B vs committee sigs
//   verify-receipt-inclusion Prove cross-shard receipt (src,H) is applied (i:)
//   verify-merge-state       Prove shard S is merged into partner P (m:)
//   verify-param-change      Prove gov param change (eff,idx) is staged (p:)
//   help / version
//
// Trust-model invariants:
//   * Every command that touches the daemon's RPC takes --genesis to
//     pin the chain identity on first connection.
//   * Composite read commands (balance-trustless, nonce-trustless,
//     stake-trustless) DO NOT trust the daemon's `account` / `stake_info`
//     reply unless the cleartext hashes to the value_hash in a verified
//     state-proof.
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
#include "account_history.hpp"
#include "verify_tx_inclusion.hpp"
#include "verify_state_root.hpp"

#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/crypto/sha256.hpp>
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
        "  stake-trustless --rpc-port <N> --genesis <file> --domain <D> [--json]\n"
        "      Verified chain + state-proof (s: namespace) + cross-check the\n"
        "      daemon's `stake_info` cleartext. Prints the committee-verified\n"
        "      locked stake + unlock_height (UINT64_MAX = no active unlock /\n"
        "      bonded). A domain with no stake leaf fails closed (the daemon's\n"
        "      state_proof returns not_found) — never a bare zero.\n"
        "  account-history --rpc-port <N> --genesis <file> --domain <D>\n"
        "                  --from <H1> --to <H2> [--step <S>] [--json]\n"
        "      Verified balance/nonce trajectory over a height range. For\n"
        "      each sampled height the row's state_root is read from a\n"
        "      committee-verified header chained back to the pinned genesis;\n"
        "      balance/next_nonce are Merkle-verified at the head (the\n"
        "      daemon's state_proof RPC serves the head only). --step\n"
        "      defaults to 1; --to must be <= the daemon's head index.\n"
        "  verify-state-root --rpc-port <N> --genesis <file> --height <H> [--json]\n"
        "      Report the committee-verified state_root at height H. Anchors\n"
        "      genesis, chains header[H] back to block 0, verifies header[H]'s\n"
        "      K-of-K (MD) / ceil(2K/3) (BFT) committee sigs, and prints the\n"
        "      committee-attested state_root + committee size + sig count.\n"
        "      Distinct from verify-state-proof (which checks a Merkle PROOF\n"
        "      against a GIVEN root): this verifies the ROOT ITSELF is\n"
        "      genuinely committee-signed at H. Genesis (H=0) is anchored by\n"
        "      compute_genesis_hash (no committee sigs by construction). A\n"
        "      header whose sigs don't verify fails closed (non-zero exit) —\n"
        "      never a bare daemon-reported root.\n"
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
        "Trustless inclusion proof (--genesis required):\n"
        "  verify-tx-inclusion --rpc-port <N> --genesis <file>\n"
        "                      --tx-hash <hex> --height <B> [--json]\n"
        "      Prove (or disprove) that tx <hex> is in block <B>. Anchors\n"
        "      genesis, fetches block B's full body, verifies its committee\n"
        "      sigs over the block digest (which binds tx_root +\n"
        "      creator_tx_lists), recomputes tx_root from the committed hash\n"
        "      lists, cross-checks the returned body against that set, then\n"
        "      reports INCLUDED / NOT-INCLUDED. A body that doesn't match the\n"
        "      committee-signed hash set is reported UNVERIFIABLE (never a\n"
        "      false INCLUDED). Inclusion is cryptographically anchored: any\n"
        "      historical block is verifiable (its committee sigs travel with\n"
        "      it), unlike state-proofs which the daemon serves head-only.\n"
        "  verify-receipt-inclusion --rpc-port <N> --genesis <file>\n"
        "                           --src-shard <S> --tx-hash <hex> [--json]\n"
        "      Prove (or disprove) that the cross-shard inbound receipt\n"
        "      (src_shard=<S>, tx_hash=<hex>) has been applied on this shard\n"
        "      — i.e. is a member of the committee-verified `i:`\n"
        "      (applied_inbound_receipts) namespace. Anchors genesis,\n"
        "      committee-verifies the header chain to head, computes the\n"
        "      canonical receipt key (\"i:\" + src_shard_be8 + tx_hash),\n"
        "      fetches the `i:`-namespace state-proof, and Merkle-verifies it\n"
        "      against the committee-signed state_root. The proof's key_bytes\n"
        "      must equal the locally-computed key AND its value_hash must\n"
        "      equal SHA256(0x01) (the presence marker) — binding the proof\n"
        "      to THIS receipt, not some other leaf. Receipts are\n"
        "      append-only once applied, so there is no per-block race.\n"
        "      INCLUDED / NOT-INCLUDED are sound verified verdicts. Current\n"
        "      daemons serve the composite-key `i:` namespace (hex-encoded\n"
        "      key body); against a legacy daemon that cannot, the verdict\n"
        "      is UNVERIFIABLE and the command fails closed — never a false\n"
        "      INCLUDED.\n"
        "  verify-merge-state --rpc-port <N> --genesis <file>\n"
        "                     --shard-id <S> --partner-id <P>\n"
        "                     --refugee-region <R> [--json]\n"
        "      Prove (or disprove) that shard <S> is currently merged into\n"
        "      partner <P> with refugee region <R> — i.e. that the exact\n"
        "      record (partner_id=<P>, refugee_region=<R>) is a member of the\n"
        "      committee-verified `m:` (merge_state) namespace. Anchors\n"
        "      genesis, committee-verifies the header chain to head, computes\n"
        "      the canonical merge key (\"m:\" + shard_id_be4), fetches the\n"
        "      `m:`-namespace state-proof (hex-encoded key body), and Merkle-\n"
        "      verifies it against the committee-signed state_root. The\n"
        "      proof's key_bytes must equal the locally-computed key AND its\n"
        "      value_hash must equal SHA256(u64_be(partner_id) ||\n"
        "      u64_be(region_len) || region) — binding the proof to THIS\n"
        "      merge record, so a daemon lie about the partner or region is\n"
        "      detected, not propagated. INCLUDED / NOT-INCLUDED are sound\n"
        "      verdicts anchored to the head height (merge_state is mutable:\n"
        "      a later revert flips INCLUDED back to NOT-INCLUDED). Any\n"
        "      tamper, mismatch, or daemon refusal → UNVERIFIABLE (exit 3),\n"
        "      never a false INCLUDED.\n"
        "  verify-param-change --rpc-port <N> --genesis <file>\n"
        "                     --effective-height <H> --idx <I> --name <NAME>\n"
        "                     [--value-hex <HEX>] [--json]\n"
        "      Prove (or disprove) that a staged governance parameter change\n"
        "      — the entry at index <I> within effective-height bucket <H>,\n"
        "      named <NAME> with value <HEX> — is currently a member of the\n"
        "      committee-verified `p:` (pending_param_changes) namespace, i.e.\n"
        "      that it is STILL STAGED (not yet activated). Anchors genesis,\n"
        "      committee-verifies the header chain to head, computes the\n"
        "      canonical key (\"p:\" + eff_be8 + idx_be4), fetches the\n"
        "      `p:`-namespace state-proof (hex-encoded key body), and Merkle-\n"
        "      verifies it against the committee-signed state_root. The\n"
        "      proof's key_bytes must equal the locally-computed key AND its\n"
        "      value_hash must equal SHA256(u64_be(name_len) || name ||\n"
        "      u64_be(value_len) || value) — binding the proof to THIS staged\n"
        "      change, so a daemon lie about the parameter name or value is\n"
        "      detected, not propagated. Use the daemon's `pending_params` RPC\n"
        "      to discover the (effective_height, name, value_hex) to assert;\n"
        "      --idx is the entry's 0-based position within its bucket.\n"
        "      INCLUDED / NOT-INCLUDED are sound verdicts anchored to the head\n"
        "      height (pending_param_changes is consumed at activation: once\n"
        "      the chain advances past <H> the same query flips INCLUDED back\n"
        "      to NOT-INCLUDED). Any tamper, mismatch, or daemon refusal →\n"
        "      UNVERIFIABLE (exit 3), never a false INCLUDED.\n"
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

// ─────────────────────────── stake-trustless ───────────────────────────
//
// Composite trust-minimized read of the stakes ("s:") namespace, the
// exact analogue of read_account_trustless (light/trustless_read.cpp)
// for the accounts ("a:") namespace. Because the trustless-read helper
// in trustless_read.* hard-codes the "a" namespace + `account` RPC +
// (balance, next_nonce) decode, and that lane is closed to this change,
// the stake variant is implemented here in terms of the SAME exported
// verify/anchor primitives (anchor_genesis, verify_chain_to_head,
// verify_state_proof, verify_block_sigs, verify_headers). Only three
// things differ from the account path: the namespace is "s", the
// cleartext cross-check RPC is `stake_info`, and the committed leaf
// encoding is value_hash = SHA256(u64_be(locked) || u64_be(unlock_height))
// (see chain.cpp::build_state_leaves, "stakes_" branch — it mirrors the
// accounts_ branch field-for-field with locked/unlock_height in place of
// balance/next_nonce).

struct StakeView {
    uint64_t    locked{0};
    uint64_t    unlock_height{0};
    std::string state_root_hex;  // head header's state_root the proof verified
    uint64_t    height{0};       // head block index this view is anchored at
};

StakeView read_stake_trustless(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    const std::string& domain) {

    StakeView sv;

    // 1. Anchor genesis (fail-closed if block 0 != compute_genesis_hash).
    std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

    // 2. Verify the header chain end-to-end (prev_hash continuity +
    //    per-block committee sigs), capturing the head's state_root.
    auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);

    if (vc.head_state_root.empty()) {
        throw std::runtime_error(
            "stake-trustless: chain has not activated state_root (S-033) — "
            "head header carries no state_root, so state-proofs can't be "
            "anchored. Use the daemon's `stake_info` RPC directly for "
            "chains without S-033 active.");
    }

    // 3. Fetch the state-proof for ("s:", domain). A domain with no stake
    //    leaf yields {"error":"not_found"} here — we fail closed rather
    //    than fabricate a zero.
    auto proof = rpc.call("state_proof",
        {{"namespace", "s"}, {"key", domain}});
    if (proof.contains("error") && !proof["error"].is_null()) {
        throw std::runtime_error(
            "stake-trustless: state_proof RPC error (domain has no verified "
            "stake leaf?): " + proof["error"].dump());
    }

    // 4. Verify the proof self-consistently (Merkle siblings roll up to
    //    the proof's claimed state_root).
    auto vsp = verify_state_proof(proof, {});
    if (!vsp.ok) {
        throw std::runtime_error("stake-trustless: " + vsp.detail);
    }

    // 5. Anchor the proof's claimed state_root to a committee-signed
    //    header. The chain may have advanced during the round-trip, so
    //    proof.height can be > vc.height; bind the proof root to the
    //    header at proof.height - 1 and re-verify its committee sigs.
    //    This is the identical anchoring logic read_account_trustless
    //    uses (kept in lock-step so both namespaces enjoy the same
    //    chain-advanced-during-round-trip guarantee).
    uint64_t proof_height = proof.value("height", uint64_t{0});
    std::string proof_root = proof.value("state_root", std::string{});
    if (proof_height < vc.height) {
        throw std::runtime_error(
            "stake-trustless: proof.height=" + std::to_string(proof_height)
            + " is BEFORE verified-chain head=" + std::to_string(vc.height)
            + " — daemon is serving stale state");
    }
    if (proof_height > vc.height) {
        json committee_json;
        {
            json arr = json::array();
            for (auto& [domain_, pk] : committee_seed) {
                arr.push_back({{"domain", domain_}, {"ed_pub", to_hex(pk)}});
            }
            committee_json = json{{"members", arr}};
        }
        uint64_t anchor_index = proof_height - 1;
        auto pg = rpc.call("headers",
            {{"from", anchor_index}, {"count", 1}});
        if (!pg.contains("headers") || !pg["headers"].is_array()
            || pg["headers"].empty()) {
            throw std::runtime_error(
                "stake-trustless: cannot fetch header at index="
                + std::to_string(anchor_index)
                + " (proof.height=" + std::to_string(proof_height) + ")");
        }
        auto& h = pg["headers"][0];
        std::string hdr_root = h.value("state_root", std::string{});
        if (hdr_root != proof_root) {
            throw std::runtime_error(
                "stake-trustless: proof.state_root=" + proof_root
                + " does not match header[" + std::to_string(anchor_index)
                + "].state_root=" + hdr_root);
        }
        auto vbs = verify_block_sigs(h, committee_json, /*bft=*/false);
        if (!vbs.ok) {
            vbs = verify_block_sigs(h, committee_json, /*bft=*/true);
        }
        if (!vbs.ok) {
            throw std::runtime_error(
                "stake-trustless: header[" + std::to_string(anchor_index)
                + "] committee-sig check failed: " + vbs.detail);
        }
        if (anchor_index >= vc.height) {
            auto walk = rpc.call("headers",
                {{"from", vc.height - 1}, {"count", proof_height - vc.height + 2}});
            auto vh = verify_headers(walk, "", "");
            if (!vh.ok) {
                throw std::runtime_error(
                    "stake-trustless: prev_hash walk vc.height→proof.height: "
                    + vh.detail);
            }
        }
        vc.head_state_root = proof_root;
        vc.height = proof_height;
        vc.head_block_hash = h.value("block_hash", std::string{});
    } else if (proof_root != vc.head_state_root) {
        throw std::runtime_error(
            "stake-trustless: proof.state_root=" + proof_root
            + " does not match verified head state_root="
            + vc.head_state_root);
    }

    // 6. Fetch the cleartext (locked, unlock_height) via `stake_info`,
    //    recompute the committed leaf hash, and confirm it matches the
    //    verified value_hash. This is the load-bearing cross-check: a
    //    daemon could serve an honest proof for some OTHER stake pair
    //    while lying in the cleartext; the hash recomputation forces
    //    consistency. Encoding matches build_state_leaves exactly:
    //    SHA256(u64_be(locked) || u64_be(unlock_height)).
    auto si = rpc.call("stake_info", {{"domain", domain}});
    if (si.contains("error") && !si["error"].is_null()) {
        throw std::runtime_error(
            "stake-trustless: stake_info RPC error: " + si["error"].dump());
    }
    uint64_t locked = si.value("locked",        uint64_t{0});
    uint64_t unlock = si.value("unlock_height", uint64_t{0});

    determ::crypto::SHA256Builder b;
    b.append(locked);
    b.append(unlock);
    Hash computed_value_hash = b.finalize();

    Hash proof_value_hash = from_hex_arr<32>(
        proof["value_hash"].get<std::string>());

    if (computed_value_hash != proof_value_hash) {
        throw std::runtime_error(
            "stake-trustless: TAMPERED — daemon's `stake_info` reply "
            "(locked=" + std::to_string(locked)
            + ", unlock_height=" + std::to_string(unlock)
            + ") hashes to " + to_hex(computed_value_hash)
            + " but state-proof's value_hash is "
            + to_hex(proof_value_hash)
            + " — daemon is lying about either the cleartext OR the proof");
    }

    sv.locked = locked;
    sv.unlock_height = unlock;
    sv.state_root_hex = vc.head_state_root;
    sv.height = vc.height;
    return sv;
}

int cmd_stake_trustless(int argc, char** argv) {
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
            std::cerr << "stake-trustless: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || domain.empty()) {
        std::cerr << "stake-trustless: "
                     "--rpc-port, --genesis, --domain are required\n";
        return 1;
    }
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "stake-trustless: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string canon_domain = normalize_anon_address(domain);
        auto view = read_stake_trustless(rpc, committee_seed, genesis,
                                         canon_domain);
        if (json_out) {
            json out = {
                {"domain",        canon_domain},
                {"locked",        view.locked},
                {"unlock_height", view.unlock_height},
                {"height",        view.height},
                {"state_root",    view.state_root_hex},
                {"verified",      true},
            };
            std::cout << out.dump() << "\n";
        } else {
            std::cout << canon_domain << ": locked=" << view.locked
                      << " unlock_height=" << view.unlock_height
                      << " (verified via state-proof at height "
                      << view.height << ", state_root "
                      << view.state_root_hex.substr(0, 16) << "...)\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "stake-trustless: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── account-history ──────────────────────────────

int cmd_account_history(int argc, char** argv) {
    AccountHistoryOptions opts;
    bool have_port = false, have_from = false, have_to = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            opts.rpc_port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) {
            opts.genesis_path = argv[++i];
        } else if (a == "--domain"  && i + 1 < argc) {
            opts.domain = argv[++i];
        } else if (a == "--from"    && i + 1 < argc) {
            opts.from = parse_u64("--from", argv[++i]); have_from = true;
        } else if (a == "--to"      && i + 1 < argc) {
            opts.to = parse_u64("--to", argv[++i]); have_to = true;
        } else if (a == "--step"    && i + 1 < argc) {
            opts.step = parse_u64("--step", argv[++i]);
        } else if (a == "--json") {
            opts.json_out = true;
        } else {
            std::cerr << "account-history: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || opts.genesis_path.empty() || opts.domain.empty()
        || !have_from || !have_to) {
        std::cerr << "account-history: --rpc-port, --genesis, --domain, "
                     "--from, --to are required\n";
        return 1;
    }
    try {
        return run_account_history(opts);
    } catch (const std::exception& e) {
        std::cerr << "account-history: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── verify-state-root ────────────────────────────

int cmd_verify_state_root(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path;
    uint64_t height = 0;
    bool have_port = false, have_height = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--height"  && i + 1 < argc) {
            height = parse_u64("--height", argv[++i]); have_height = true;
        } else if (a == "--json")                    json_out     = true;
        else {
            std::cerr << "verify-state-root: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_height) {
        std::cerr << "verify-state-root: --rpc-port, --genesis, --height "
                     "are required\n";
        return 1;
    }
    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-state-root: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        auto r = verify_state_root_at(rpc, committee_seed,
                                      genesis_hash_hex, height);

        if (json_out) {
            json out = {
                {"height",             r.height},
                {"state_root",         r.state_root_hex},
                {"committee_size",     r.committee_size},
                {"sigs_verified",      r.sigs_verified},
                {"committee_verified", r.committee_verified},
            };
            if (!r.detail.empty()) out["detail"] = r.detail;
            std::cout << out.dump() << "\n";
        } else if (r.ok) {
            std::cout << "OK\n"
                      << "  genesis pin:        matches (" << genesis_hash_hex << ")\n"
                      << "  height:             " << r.height << "\n";
            if (r.height == 0) {
                // Genesis is anchored by hash — it has no committee sigs.
                std::cout << "  anchor:             genesis hash "
                             "(block 0 has no committee sigs)\n";
            } else {
                std::cout << "  committee sigs:     " << r.sigs_verified
                          << " of " << r.committee_size << " verified\n";
            }
            std::cout << "  block_hash:         " << r.block_hash_hex << "\n";
            if (r.state_root_present)
                std::cout << "  state_root:         " << r.state_root_hex << "\n";
            else
                std::cout << "  state_root:         (not populated — "
                             "pre-S-033 chain)\n";
        } else {
            // Verification failed (chain break, sig failure, out-of-range,
            // malformed reply). Fail closed: print the diagnostic, exit
            // non-zero, NEVER emit a bare daemon-reported root.
            std::cerr << "verify-state-root: " << r.detail << "\n";
            return 1;
        }

        // Exit code: ok → 0; not-ok (in --json mode the diagnostic is in
        // the object, but the command still failed) → 1.
        return r.ok ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "verify-state-root: " << e.what() << "\n";
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

// ──────────────────────── verify-tx-inclusion ──────────────────────────

const char* verdict_str(InclusionVerdict v) {
    switch (v) {
        case InclusionVerdict::INCLUDED:     return "INCLUDED";
        case InclusionVerdict::NOT_INCLUDED: return "NOT-INCLUDED";
        case InclusionVerdict::UNVERIFIABLE: return "UNVERIFIABLE";
    }
    return "UNVERIFIABLE";
}

int cmd_verify_tx_inclusion(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, tx_hash;
    uint64_t height = 0;
    bool have_port = false, have_height = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--tx-hash" && i + 1 < argc) tx_hash      = argv[++i];
        else if   (a == "--height"  && i + 1 < argc) {
            height = parse_u64("--height", argv[++i]); have_height = true;
        } else if (a == "--json")                    json_out     = true;
        else {
            std::cerr << "verify-tx-inclusion: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || tx_hash.empty() || !have_height) {
        std::cerr << "verify-tx-inclusion: --rpc-port, --genesis, --tx-hash, "
                     "--height are required\n";
        return 1;
    }
    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-tx-inclusion: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        auto r = verify_tx_inclusion(rpc, committee_seed, genesis,
                                     height, tx_hash);

        bool included = (r.verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",           included},
                {"verdict",            verdict_str(r.verdict)},
                {"height",             r.height},
                {"tx_hash",            r.tx_hash_hex},
                {"tx_root",            r.tx_root_hex},
                {"block_hash",         r.block_hash_hex},
                {"committee_verified", r.committee_verified},
                {"sigs_verified",      r.sigs_verified},
                {"committee_size",     r.committee_size},
                {"tx_count",           r.tx_count},
            };
            if (!r.detail.empty()) out["detail"] = r.detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(r.verdict) << "\n"
                      << "  genesis pin:        matches (" << genesis_hash_hex << ")\n"
                      << "  tx_hash:            " << r.tx_hash_hex << "\n"
                      << "  height:             " << r.height << "\n";
            if (r.committee_verified) {
                if (r.height == 0) {
                    // Genesis is anchored by hash (it has no committee
                    // sigs — see verify_tx_inclusion); say so explicitly.
                    std::cout << "  anchor:             genesis hash "
                                 "(block 0 has no committee sigs)\n";
                } else {
                    std::cout << "  committee sigs:     " << r.sigs_verified
                              << " of " << r.committee_size << " verified\n";
                }
                std::cout << "  tx_root (signed):   " << r.tx_root_hex << "\n"
                          << "  block tx count:     " << r.tx_count << "\n";
            }
            if (!r.detail.empty())
                std::cout << "  detail:             " << r.detail << "\n";
        }

        // Exit codes: INCLUDED → 0; NOT-INCLUDED → 0 (a sound, verified
        // negative answer is success); UNVERIFIABLE → 3 (we refused to
        // answer because the committee binding broke / daemon tampered).
        if (r.verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-tx-inclusion: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────── verify-receipt-inclusion ──────────────────────
//
// Trust-minimized INCLUDED / NOT-INCLUDED / UNVERIFIABLE verdict on
// whether a cross-shard inbound receipt (src_shard, tx_hash) lives in the
// committee-verified `i:` (applied_inbound_receipts) namespace.
//
// This is the receipt-membership analogue of verify-tx-inclusion (which
// proves tx membership in a block body) and the trustless state-proof
// read of stake-trustless (which Merkle-verifies an `s:`-namespace leaf
// against a committee-signed state_root). The receipt path differs in
// three ways:
//
//   * Namespace is "i" and the leaf key is COMPOSITE — it is NOT a plain
//     ASCII domain. The canonical encoding (see chain.cpp
//     build_state_leaves, "applied_inbound_receipts_" branch) is:
//         key       = 'i' ':' || u64_be(src_shard) || tx_hash[32]
//         value_hash = SHA256(0x01)                 // presence marker
//     The verifier recomputes BOTH locally and demands the proof's
//     key_bytes == local key AND its value_hash == SHA256(0x01). Without
//     those two equalities a daemon could serve a valid Merkle proof for
//     some OTHER leaf and pass a bare verify_state_proof — so they are the
//     load-bearing binding to THIS receipt.
//
//   * A receipt is a SET membership (present/absent), not a (value)
//     decode. There is no cleartext cross-check RPC (unlike `stake_info`
//     for stakes); the presence marker IS the whole payload. Membership
//     is therefore proven entirely by the Merkle inclusion of the
//     canonical (key, SHA256(0x01)) leaf under the committee-signed root.
//
//   * Receipts are append-only / stable once applied (chain.cpp inserts
//     into applied_inbound_receipts_ and never erases — the only mutation
//     is via the atomic snapshot rollback on a FAILED apply). So unlike a
//     per-block counter there is NO per-block race: once present at any
//     height H the receipt is present at every height >= H, and the
//     head-only state_proof RPC is sufficient.
//
// Fail-closed contract: any tamper, malformed proof, key/value mismatch,
// or daemon refusal to serve the `i:` proof yields UNVERIFIABLE (exit 3),
// never a false INCLUDED. A clean Merkle-verified inclusion → INCLUDED
// (exit 0); a daemon `not_found` for the canonical key → NOT-INCLUDED
// (exit 0, a sound verified negative).

int cmd_verify_receipt_inclusion(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, tx_hash_hex;
    uint64_t src_shard = 0;
    bool have_port = false, have_shard = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port"  && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis"   && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--src-shard" && i + 1 < argc) {
            src_shard = parse_u64("--src-shard", argv[++i]); have_shard = true;
        } else if (a == "--tx-hash"   && i + 1 < argc) tx_hash_hex  = argv[++i];
        else if   (a == "--json")                      json_out     = true;
        else {
            std::cerr << "verify-receipt-inclusion: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_shard || tx_hash_hex.empty()) {
        std::cerr << "verify-receipt-inclusion: --rpc-port, --genesis, "
                     "--src-shard, --tx-hash are required\n";
        return 1;
    }

    // The verdict mirrors verify-tx-inclusion's tri-state.
    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;

    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-receipt-inclusion: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // Parse the 32-byte tx_hash now so a malformed hash fails fast.
        Hash tx_hash = from_hex_arr<32>(tx_hash_hex);

        // Compute the canonical receipt key bytes locally, byte-for-byte
        // matching chain.cpp build_state_leaves:
        //   'i' ':' || u64_be(src_shard) || tx_hash[32]
        std::vector<uint8_t> local_key;
        local_key.reserve(2 + 8 + 32);
        local_key.push_back('i'); local_key.push_back(':');
        for (int i = 7; i >= 0; --i)
            local_key.push_back(static_cast<uint8_t>((src_shard >> (8 * i)) & 0xff));
        local_key.insert(local_key.end(), tx_hash.begin(), tx_hash.end());

        // The committed value for a present receipt is SHA256(0x01).
        determ::crypto::SHA256Builder mb;
        uint8_t marker = 1; mb.append(&marker, 1);
        Hash expected_value_hash = mb.finalize();

        // Committee-verify the header chain end-to-end, capturing the
        // head's state_root (the anchor for the Merkle inclusion).
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `i:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `i:`-namespace state-proof. The daemon takes a string
        // `key`; for composite-key namespaces it builds the prefixed key
        // bytes from this string. The post-prefix body (everything after
        // "i:") is BINARY — u64_be(src) || tx_hash — which cannot ride raw
        // inside a JSON string: nlohmann::json::dump() throws on the
        // non-UTF-8 bytes a SHA-256 tx_hash almost always contains. So we
        // HEX-encode the body; the daemon hex-decodes it and prepends "i:"
        // to reconstruct the canonical key byte-for-byte.
        std::vector<uint8_t> body;
        body.reserve(8 + 32);
        for (int i = 7; i >= 0; --i)
            body.push_back(static_cast<uint8_t>((src_shard >> (8 * i)) & 0xff));
        body.insert(body.end(), tx_hash.begin(), tx_hash.end());
        std::string key_body_hex = to_hex(body.data(), body.size());

        auto proof = rpc.call("state_proof",
            {{"namespace", "i"}, {"key", key_body_hex}});

        // A daemon that cannot serve the `i:` namespace (e.g. the RPC does
        // not expose composite-key namespaces) returns an `error`. We
        // distinguish a genuine absence (`not_found` for our exact key →
        // a sound NOT-INCLUDED) from any other refusal (→ UNVERIFIABLE,
        // fail closed — we will not assert membership either way).
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = InclusionVerdict::NOT_INCLUDED;
                detail  = "daemon reports no `i:` leaf for the canonical "
                          "receipt key (state_proof not_found)";
            } else {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `i:` state-proof: " + err
                        + " (cannot prove membership trustlessly)";
            }
        } else {
            // Bind the proof to THIS receipt: (1) key_bytes must equal the
            // locally-computed canonical key, (2) value_hash must equal
            // SHA256(0x01). Either mismatch means the daemon served a proof
            // for a different leaf → UNVERIFIABLE.
            std::string proof_key_hex =
                proof.value("key_bytes", std::string{});
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical receipt key "
                        + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " is not the presence marker SHA256(0x01)="
                            + to_hex(expected_value_hash);
                } else {
                    // Anchor the proof's claimed state_root to a
                    // committee-signed header (the chain may have advanced
                    // during the round-trip), mirroring stake-trustless.
                    uint64_t proof_height =
                        proof.value("height", uint64_t{0});
                    std::string proof_root =
                        proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    if (proof_height > vc.height) {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pk] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pk)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        auto pg = rpc.call("headers",
                            {{"from", anchor_index}, {"count", 1}});
                        if (!pg.contains("headers")
                            || !pg["headers"].is_array()
                            || pg["headers"].empty()) {
                            throw std::runtime_error(
                                "cannot fetch header at index="
                                + std::to_string(anchor_index)
                                + " (proof.height="
                                + std::to_string(proof_height) + ")");
                        }
                        auto& h = pg["headers"][0];
                        std::string hdr_root =
                            h.value("state_root", std::string{});
                        if (hdr_root != proof_root) {
                            throw std::runtime_error(
                                "proof.state_root=" + proof_root
                                + " does not match header["
                                + std::to_string(anchor_index)
                                + "].state_root=" + hdr_root);
                        }
                        auto vbs = verify_block_sigs(h, committee_json,
                                                     /*bft=*/false);
                        if (!vbs.ok)
                            vbs = verify_block_sigs(h, committee_json,
                                                    /*bft=*/true);
                        if (!vbs.ok) {
                            throw std::runtime_error(
                                "header[" + std::to_string(anchor_index)
                                + "] committee-sig check failed: "
                                + vbs.detail);
                        }
                        if (anchor_index >= vc.height) {
                            auto walk = rpc.call("headers",
                                {{"from", vc.height - 1},
                                 {"count", proof_height - vc.height + 2}});
                            auto vh = verify_headers(walk, "", "");
                            if (!vh.ok) {
                                throw std::runtime_error(
                                    "prev_hash walk vc.height->proof.height: "
                                    + vh.detail);
                            }
                        }
                        anchor_root = proof_root;
                        anchor_at   = proof_height;
                    } else if (proof_root != vc.head_state_root) {
                        throw std::runtime_error(
                            "proof.state_root=" + proof_root
                            + " does not match verified head state_root="
                            + vc.head_state_root);
                    }

                    // Merkle-verify the proof against the committee-signed
                    // root. verify_state_proof re-derives key_bytes +
                    // value_hash from the proof JSON and rolls the siblings
                    // up to anchor_root; we already bound those to the
                    // canonical receipt above, so a pass here is a sound
                    // INCLUDED.
                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = InclusionVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict = InclusionVerdict::INCLUDED;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                    }
                }
            }
        }

        std::string canon_tx_hash = to_hex(tx_hash);
        bool included = (verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",    included},
                {"verdict",     verdict_str(verdict)},
                {"src_shard",   src_shard},
                {"tx_hash",     canon_tx_hash},
                {"namespace",   "i"},
            };
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(verdict) << "\n"
                      << "  genesis pin:   matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:     i (applied_inbound_receipts)\n"
                      << "  src_shard:     " << src_shard << "\n"
                      << "  tx_hash:       " << canon_tx_hash << "\n";
            if (verdict == InclusionVerdict::INCLUDED) {
                std::cout << "  state_root:    " << state_root_used << "\n"
                          << "  anchored at H: " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:        " << detail << "\n";
        }

        // Exit codes match verify-tx-inclusion: INCLUDED / NOT-INCLUDED →
        // 0 (sound verified answer); UNVERIFIABLE → 3 (refused to assert).
        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-receipt-inclusion: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────── verify-merge-state ────────────────────────────
//
// Trust-minimized INCLUDED / NOT-INCLUDED / UNVERIFIABLE verdict on
// whether a shard's under-quorum-merge record (shard_id → partner_id +
// refugee_region) lives in the committee-verified `m:` (merge_state)
// namespace, with the proof bound to the EXACT (partner_id, refugee_region)
// the caller asserts.
//
// This is the merge-state analogue of verify-receipt-inclusion (which
// proves `i:` receipt membership) and stake-trustless (which Merkle-
// verifies an `s:` leaf against a committee-signed state_root). It uses the
// SAME composite-key state-proof path the daemon now serves (the caller
// hex-encodes the binary key body; see src/node/node.cpp rpc_state_proof).
// The merge path differs from the receipt path in two ways:
//
//   * Namespace is "m" and the leaf key is COMPOSITE but SHORT. The
//     canonical encoding (see chain.cpp build_state_leaves, "merge_state_"
//     branch) is:
//         key        = 'm' ':' || u32_be(shard_id)
//         value_hash = SHA256( u64_be(partner_id)
//                            || u64_be(refugee_region.size())
//                            || refugee_region )
//     The verifier recomputes BOTH locally and demands the proof's
//     key_bytes == local key AND its value_hash == the locally-recomputed
//     hash. The value_hash binding is load-bearing: unlike `i:` (whose
//     value is the constant presence marker SHA256(0x01)), a `m:` leaf
//     carries DATA, so a daemon could serve a valid Merkle proof for shard
//     S that encodes a DIFFERENT partner/region. Recomputing the hash from
//     the caller-asserted (partner_id, refugee_region) forces the proof to
//     match exactly that record — a daemon lie about either field is
//     detected, not propagated.
//
//   * merge_state is mutable: a MERGE_END erases the leaf (chain.cpp). So
//     this is a head-anchored present/absent verdict, NOT an append-only
//     guarantee — INCLUDED means "merged INTO partner_id with that refugee
//     region AS OF the committee-verified head", and a later revert makes
//     the same query return NOT-INCLUDED. The verdict is therefore always
//     anchored to (and reported with) the head height it was proven at.
//
// Fail-closed contract: any tamper, malformed proof, key/value mismatch,
// or daemon refusal to serve the `m:` proof yields UNVERIFIABLE (exit 3),
// never a false INCLUDED. A clean Merkle-verified inclusion → INCLUDED
// (exit 0); a daemon `not_found` for the canonical key → NOT-INCLUDED
// (exit 0, a sound verified negative — shard S is not currently merged
// into THAT partner with THAT region).

int cmd_verify_merge_state(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, refugee_region;
    uint64_t shard_id = 0, partner_id = 0;
    bool have_port = false, have_shard = false, have_partner = false,
         have_region = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port"  && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis"   && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--shard-id"   && i + 1 < argc) {
            shard_id = parse_u64("--shard-id", argv[++i]); have_shard = true;
        } else if (a == "--partner-id" && i + 1 < argc) {
            partner_id = parse_u64("--partner-id", argv[++i]); have_partner = true;
        } else if (a == "--refugee-region" && i + 1 < argc) {
            refugee_region = argv[++i]; have_region = true;
        } else if (a == "--json")                      json_out     = true;
        else {
            std::cerr << "verify-merge-state: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_shard || !have_partner
        || !have_region) {
        std::cerr << "verify-merge-state: --rpc-port, --genesis, --shard-id, "
                     "--partner-id, --refugee-region are required\n";
        return 1;
    }
    // shard_id and partner_id are u32 on the wire (build_state_leaves emits
    // u32_be(shard_id) keys and stores ShardId partner_id). Reject anything
    // that cannot fit so a malformed query can't silently alias a leaf.
    if (shard_id > 0xffffffffull) {
        std::cerr << "verify-merge-state: --shard-id exceeds u32 range\n";
        return 1;
    }
    if (partner_id > 0xffffffffull) {
        std::cerr << "verify-merge-state: --partner-id exceeds u32 range\n";
        return 1;
    }
    // The region binds into the leaf hash with a u64_be length prefix; cap
    // it at the MERGE_EVENT wire ceiling (32 bytes) so a query can't assert
    // a region the protocol could never have stored.
    if (refugee_region.size() > 32) {
        std::cerr << "verify-merge-state: --refugee-region exceeds 32 bytes\n";
        return 1;
    }

    // The verdict mirrors verify-receipt-inclusion's tri-state.
    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;

    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-merge-state: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // Compute the canonical merge_state key bytes locally, byte-for-byte
        // matching chain.cpp build_state_leaves "merge_state_" branch:
        //   'm' ':' || u32_be(shard_id)
        std::vector<uint8_t> local_key;
        local_key.reserve(2 + 4);
        local_key.push_back('m'); local_key.push_back(':');
        for (int i = 3; i >= 0; --i)
            local_key.push_back(static_cast<uint8_t>(
                (static_cast<uint32_t>(shard_id) >> (8 * i)) & 0xff));

        // The committed value for THIS merge record:
        //   SHA256(u64_be(partner_id) || u64_be(region_len) || region)
        determ::crypto::SHA256Builder mb;
        mb.append(static_cast<uint64_t>(partner_id));
        mb.append(static_cast<uint64_t>(refugee_region.size()));
        mb.append(refugee_region);
        Hash expected_value_hash = mb.finalize();

        // Committee-verify the header chain end-to-end, capturing the
        // head's state_root (the anchor for the Merkle inclusion).
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `m:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `m:`-namespace state-proof. The daemon takes a string
        // `key`; for composite-key namespaces it hex-decodes the post-prefix
        // body and prepends "m:" to reconstruct the canonical key. The body
        // here is u32_be(shard_id) (4 bytes) — see rpc_state_proof's width
        // enforcement.
        std::vector<uint8_t> body;
        body.reserve(4);
        for (int i = 3; i >= 0; --i)
            body.push_back(static_cast<uint8_t>(
                (static_cast<uint32_t>(shard_id) >> (8 * i)) & 0xff));
        std::string key_body_hex = to_hex(body.data(), body.size());

        auto proof = rpc.call("state_proof",
            {{"namespace", "m"}, {"key", key_body_hex}});

        // A daemon that cannot serve the `m:` namespace returns an `error`.
        // We distinguish a genuine absence (`not_found` for our exact key →
        // a sound NOT-INCLUDED) from any other refusal (→ UNVERIFIABLE,
        // fail closed — we will not assert membership either way).
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = InclusionVerdict::NOT_INCLUDED;
                detail  = "daemon reports no `m:` leaf for shard "
                        + std::to_string(shard_id)
                        + " (state_proof not_found — shard is not currently "
                          "merged)";
            } else {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `m:` state-proof: " + err
                        + " (cannot prove membership trustlessly)";
            }
        } else {
            // Bind the proof to THIS merge record: (1) key_bytes must equal
            // the locally-computed canonical key, (2) value_hash must equal
            // the locally-recomputed SHA256 over (partner_id, region). Either
            // mismatch means the daemon served a proof for a different leaf
            // OR is lying about the merge's partner/region → UNVERIFIABLE.
            std::string proof_key_hex =
                proof.value("key_bytes", std::string{});
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical merge key "
                        + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " does not match the recomputed hash of "
                              "(partner_id=" + std::to_string(partner_id)
                            + ", refugee_region=\"" + refugee_region + "\")="
                            + to_hex(expected_value_hash)
                            + " — daemon is lying about the merge's "
                              "partner/region OR proving a different record";
                } else {
                    // Anchor the proof's claimed state_root to a
                    // committee-signed header (the chain may have advanced
                    // during the round-trip), mirroring verify-receipt-
                    // inclusion / stake-trustless.
                    uint64_t proof_height =
                        proof.value("height", uint64_t{0});
                    std::string proof_root =
                        proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    if (proof_height > vc.height) {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pk] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pk)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        auto pg = rpc.call("headers",
                            {{"from", anchor_index}, {"count", 1}});
                        if (!pg.contains("headers")
                            || !pg["headers"].is_array()
                            || pg["headers"].empty()) {
                            throw std::runtime_error(
                                "cannot fetch header at index="
                                + std::to_string(anchor_index)
                                + " (proof.height="
                                + std::to_string(proof_height) + ")");
                        }
                        auto& h = pg["headers"][0];
                        std::string hdr_root =
                            h.value("state_root", std::string{});
                        if (hdr_root != proof_root) {
                            throw std::runtime_error(
                                "proof.state_root=" + proof_root
                                + " does not match header["
                                + std::to_string(anchor_index)
                                + "].state_root=" + hdr_root);
                        }
                        auto vbs = verify_block_sigs(h, committee_json,
                                                     /*bft=*/false);
                        if (!vbs.ok)
                            vbs = verify_block_sigs(h, committee_json,
                                                    /*bft=*/true);
                        if (!vbs.ok) {
                            throw std::runtime_error(
                                "header[" + std::to_string(anchor_index)
                                + "] committee-sig check failed: "
                                + vbs.detail);
                        }
                        if (anchor_index >= vc.height) {
                            auto walk = rpc.call("headers",
                                {{"from", vc.height - 1},
                                 {"count", proof_height - vc.height + 2}});
                            auto vh = verify_headers(walk, "", "");
                            if (!vh.ok) {
                                throw std::runtime_error(
                                    "prev_hash walk vc.height->proof.height: "
                                    + vh.detail);
                            }
                        }
                        anchor_root = proof_root;
                        anchor_at   = proof_height;
                    } else if (proof_root != vc.head_state_root) {
                        throw std::runtime_error(
                            "proof.state_root=" + proof_root
                            + " does not match verified head state_root="
                            + vc.head_state_root);
                    }

                    // Merkle-verify the proof against the committee-signed
                    // root. verify_state_proof re-derives key_bytes +
                    // value_hash from the proof JSON and rolls the siblings
                    // up to anchor_root; we already bound those to the
                    // canonical merge record above, so a pass here is a
                    // sound INCLUDED.
                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = InclusionVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict = InclusionVerdict::INCLUDED;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                    }
                }
            }
        }

        bool included = (verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",       included},
                {"verdict",        verdict_str(verdict)},
                {"shard_id",       shard_id},
                {"partner_id",     partner_id},
                {"refugee_region", refugee_region},
                {"namespace",      "m"},
            };
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(verdict) << "\n"
                      << "  genesis pin:    matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:      m (merge_state)\n"
                      << "  shard_id:       " << shard_id << "\n"
                      << "  partner_id:     " << partner_id << "\n"
                      << "  refugee_region: " << refugee_region << "\n";
            if (verdict == InclusionVerdict::INCLUDED) {
                std::cout << "  state_root:     " << state_root_used << "\n"
                          << "  anchored at H:  " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:         " << detail << "\n";
        }

        // Exit codes match verify-receipt-inclusion: INCLUDED / NOT-INCLUDED
        // → 0 (sound verified answer); UNVERIFIABLE → 3 (refused to assert).
        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-merge-state: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────── verify-param-change ────────────────────────────
//
// Trust-minimized INCLUDED / NOT-INCLUDED / UNVERIFIABLE verdict on
// whether a staged governance parameter change (effective_height, idx →
// name + value) lives in the committee-verified `p:` (pending_param_changes)
// namespace, with the proof bound to the EXACT (name, value) the caller
// asserts.
//
// This is the governance analogue of verify-merge-state (which proves `m:`
// merge-record membership) and verify-receipt-inclusion (which proves `i:`
// receipt membership). It uses the SAME composite-key state-proof path the
// daemon serves (the caller hex-encodes the binary key body; see
// src/node/node.cpp rpc_state_proof). The pending-param path differs from
// the merge path in two ways:
//
//   * Namespace is "p" and the leaf key is COMPOSITE and WIDER. The
//     canonical encoding (see chain.cpp build_state_leaves,
//     "pending_param_changes_" branch) is:
//         key        = 'p' ':' || u64_be(effective_height) || u32_be(idx)
//         value_hash = SHA256( u64_be(name.size())  || name
//                            || u64_be(value.size()) || value )      // value
//                                                                    // omitted
//                                                                    // when empty
//     where idx is the entry's 0-based position within the per-height
//     bucket. The verifier recomputes BOTH locally and demands the proof's
//     key_bytes == local key AND its value_hash == the locally-recomputed
//     hash. The value_hash binding is load-bearing: like `m:` (and unlike
//     `i:` whose value is the constant presence marker SHA256(0x01)), a `p:`
//     leaf carries DATA, so a daemon could serve a valid Merkle proof for
//     slot (eff,idx) that encodes a DIFFERENT parameter name or value.
//     Recomputing the hash from the caller-asserted (name, value_hex) forces
//     the proof to match exactly that staged change — a daemon lie about
//     either field is detected, not propagated.
//
//   * pending_param_changes is consumed at activation: activate_pending_params
//     erases each per-height bucket once current_height reaches it (chain.cpp).
//     So this is a head-anchored present/absent verdict, NOT an append-only
//     guarantee — INCLUDED means "this exact change is STILL STAGED (not yet
//     activated) AS OF the committee-verified head", and once the chain
//     advances past effective_height the same query returns NOT-INCLUDED.
//     The verdict is therefore always anchored to (and reported with) the
//     head height it was proven at.
//
// Discovery: the daemon's `pending_params` RPC lists each staged entry's
// (effective_height, name, value_hex). The caller reads that to obtain the
// (height, name, value) to assert here; --idx is the 0-based position of the
// target entry within its effective_height bucket (the bucket is emitted in
// insertion order by both the RPC and build_state_leaves, so the RPC's
// per-height ordinal IS the leaf idx).
//
// Fail-closed contract: any tamper, malformed proof, key/value mismatch, or
// daemon refusal to serve the `p:` proof yields UNVERIFIABLE (exit 3), never
// a false INCLUDED. A clean Merkle-verified inclusion → INCLUDED (exit 0); a
// daemon `not_found` for the canonical key → NOT-INCLUDED (exit 0, a sound
// verified negative — no such change is staged at that slot).

int cmd_verify_param_change(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, name, value_hex;
    uint64_t eff_height = 0, idx = 0;
    bool have_port = false, have_eff = false, have_idx = false,
         have_name = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis"  && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--effective-height" && i + 1 < argc) {
            eff_height = parse_u64("--effective-height", argv[++i]); have_eff = true;
        } else if (a == "--idx"      && i + 1 < argc) {
            idx = parse_u64("--idx", argv[++i]); have_idx = true;
        } else if (a == "--name"     && i + 1 < argc) {
            name = argv[++i]; have_name = true;
        } else if (a == "--value-hex" && i + 1 < argc) value_hex = argv[++i];
        else if   (a == "--json")                      json_out  = true;
        else {
            std::cerr << "verify-param-change: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_eff || !have_idx
        || !have_name) {
        std::cerr << "verify-param-change: --rpc-port, --genesis, "
                     "--effective-height, --idx, --name are required\n";
        return 1;
    }
    // idx is u32 on the wire (build_state_leaves emits u32_be(idx)). Reject
    // anything that cannot fit so a malformed query can't silently alias a
    // different leaf.
    if (idx > 0xffffffffull) {
        std::cerr << "verify-param-change: --idx exceeds u32 range\n";
        return 1;
    }

    // The verdict mirrors verify-merge-state's tri-state.
    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;

    try {
        // The asserted value (may be empty — a zero-length param value is
        // legal, and build_state_leaves appends the value bytes only when
        // non-empty). from_hex throws on malformed hex, so a bad --value-hex
        // fails fast before any RPC.
        std::vector<uint8_t> value =
            value_hex.empty() ? std::vector<uint8_t>{} : from_hex(value_hex);

        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-param-change: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // Compute the canonical pending_param_changes key bytes locally,
        // byte-for-byte matching chain.cpp build_state_leaves
        // "pending_param_changes_" branch:
        //   'p' ':' || u64_be(effective_height) || u32_be(idx)
        std::vector<uint8_t> local_key;
        local_key.reserve(2 + 8 + 4);
        local_key.push_back('p'); local_key.push_back(':');
        for (int i = 7; i >= 0; --i)
            local_key.push_back(static_cast<uint8_t>((eff_height >> (8 * i)) & 0xff));
        for (int i = 3; i >= 0; --i)
            local_key.push_back(static_cast<uint8_t>(
                (static_cast<uint32_t>(idx) >> (8 * i)) & 0xff));

        // The committed value for THIS staged change:
        //   SHA256(u64_be(name_len) || name || u64_be(value_len) || value)
        // (value bytes appended only when non-empty — matching the
        // build_state_leaves `if (!value.empty())` guard).
        determ::crypto::SHA256Builder mb;
        mb.append(static_cast<uint64_t>(name.size()));
        mb.append(name);
        mb.append(static_cast<uint64_t>(value.size()));
        if (!value.empty()) mb.append(value.data(), value.size());
        Hash expected_value_hash = mb.finalize();

        // Committee-verify the header chain end-to-end, capturing the
        // head's state_root (the anchor for the Merkle inclusion).
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `p:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `p:`-namespace state-proof. The daemon takes a string
        // `key`; for composite-key namespaces it hex-decodes the post-prefix
        // body and prepends "p:" to reconstruct the canonical key. The body
        // here is u64_be(eff_height) || u32_be(idx) (12 bytes) — see
        // rpc_state_proof's width enforcement.
        std::vector<uint8_t> body;
        body.reserve(8 + 4);
        for (int i = 7; i >= 0; --i)
            body.push_back(static_cast<uint8_t>((eff_height >> (8 * i)) & 0xff));
        for (int i = 3; i >= 0; --i)
            body.push_back(static_cast<uint8_t>(
                (static_cast<uint32_t>(idx) >> (8 * i)) & 0xff));
        std::string key_body_hex = to_hex(body.data(), body.size());

        auto proof = rpc.call("state_proof",
            {{"namespace", "p"}, {"key", key_body_hex}});

        // A daemon that cannot serve the `p:` namespace returns an `error`.
        // We distinguish a genuine absence (`not_found` for our exact key →
        // a sound NOT-INCLUDED) from any other refusal (→ UNVERIFIABLE,
        // fail closed — we will not assert membership either way).
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = InclusionVerdict::NOT_INCLUDED;
                detail  = "daemon reports no `p:` leaf for slot (eff_height="
                        + std::to_string(eff_height) + ", idx="
                        + std::to_string(idx) + ") — no such change is staged "
                          "(state_proof not_found; may already have activated)";
            } else {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `p:` state-proof: " + err
                        + " (cannot prove membership trustlessly)";
            }
        } else {
            // Bind the proof to THIS staged change: (1) key_bytes must equal
            // the locally-computed canonical key, (2) value_hash must equal
            // the locally-recomputed SHA256 over (name, value). Either
            // mismatch means the daemon served a proof for a different leaf
            // OR is lying about the change's name/value → UNVERIFIABLE.
            std::string proof_key_hex =
                proof.value("key_bytes", std::string{});
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical param-change key "
                        + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " does not match the recomputed hash of "
                              "(name=\"" + name + "\", value_hex="
                            + (value_hex.empty() ? "<empty>" : value_hex) + ")="
                            + to_hex(expected_value_hash)
                            + " — daemon is lying about the change's "
                              "name/value OR proving a different slot";
                } else {
                    // Anchor the proof's claimed state_root to a
                    // committee-signed header (the chain may have advanced
                    // during the round-trip), mirroring verify-merge-state /
                    // verify-receipt-inclusion.
                    uint64_t proof_height =
                        proof.value("height", uint64_t{0});
                    std::string proof_root =
                        proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    if (proof_height > vc.height) {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pk] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pk)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        auto pg = rpc.call("headers",
                            {{"from", anchor_index}, {"count", 1}});
                        if (!pg.contains("headers")
                            || !pg["headers"].is_array()
                            || pg["headers"].empty()) {
                            throw std::runtime_error(
                                "cannot fetch header at index="
                                + std::to_string(anchor_index)
                                + " (proof.height="
                                + std::to_string(proof_height) + ")");
                        }
                        auto& h = pg["headers"][0];
                        std::string hdr_root =
                            h.value("state_root", std::string{});
                        if (hdr_root != proof_root) {
                            throw std::runtime_error(
                                "proof.state_root=" + proof_root
                                + " does not match header["
                                + std::to_string(anchor_index)
                                + "].state_root=" + hdr_root);
                        }
                        auto vbs = verify_block_sigs(h, committee_json,
                                                     /*bft=*/false);
                        if (!vbs.ok)
                            vbs = verify_block_sigs(h, committee_json,
                                                    /*bft=*/true);
                        if (!vbs.ok) {
                            throw std::runtime_error(
                                "header[" + std::to_string(anchor_index)
                                + "] committee-sig check failed: "
                                + vbs.detail);
                        }
                        if (anchor_index >= vc.height) {
                            auto walk = rpc.call("headers",
                                {{"from", vc.height - 1},
                                 {"count", proof_height - vc.height + 2}});
                            auto vh = verify_headers(walk, "", "");
                            if (!vh.ok) {
                                throw std::runtime_error(
                                    "prev_hash walk vc.height->proof.height: "
                                    + vh.detail);
                            }
                        }
                        anchor_root = proof_root;
                        anchor_at   = proof_height;
                    } else if (proof_root != vc.head_state_root) {
                        throw std::runtime_error(
                            "proof.state_root=" + proof_root
                            + " does not match verified head state_root="
                            + vc.head_state_root);
                    }

                    // Merkle-verify the proof against the committee-signed
                    // root. verify_state_proof re-derives key_bytes +
                    // value_hash from the proof JSON and rolls the siblings
                    // up to anchor_root; we already bound those to the
                    // canonical staged change above, so a pass here is a
                    // sound INCLUDED.
                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = InclusionVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict = InclusionVerdict::INCLUDED;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                    }
                }
            }
        }

        bool included = (verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",         included},
                {"verdict",          verdict_str(verdict)},
                {"effective_height", eff_height},
                {"idx",              idx},
                {"name",             name},
                {"value_hex",        value_hex},
                {"namespace",        "p"},
            };
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(verdict) << "\n"
                      << "  genesis pin:       matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:         p (pending_param_changes)\n"
                      << "  effective_height:  " << eff_height << "\n"
                      << "  idx:               " << idx << "\n"
                      << "  name:              " << name << "\n"
                      << "  value_hex:         "
                      << (value_hex.empty() ? "<empty>" : value_hex) << "\n";
            if (verdict == InclusionVerdict::INCLUDED) {
                std::cout << "  state_root:        " << state_root_used << "\n"
                          << "  anchored at H:     " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:            " << detail << "\n";
        }

        // Exit codes match verify-merge-state: INCLUDED / NOT-INCLUDED → 0
        // (sound verified answer); UNVERIFIABLE → 3 (refused to assert).
        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-param-change: " << e.what() << "\n";
        return 1;
    }
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
        if (cmd == "stake-trustless")       return cmd_stake_trustless(sub_argc, sub_argv);
        if (cmd == "account-history")       return cmd_account_history(sub_argc, sub_argv);
        if (cmd == "verify-state-root")     return cmd_verify_state_root(sub_argc, sub_argv);
        if (cmd == "sign-tx")               return cmd_sign_tx(sub_argc, sub_argv);
        if (cmd == "submit-tx")             return cmd_submit_tx(sub_argc, sub_argv);
        if (cmd == "verify-and-submit")     return cmd_verify_and_submit(sub_argc, sub_argv);
        if (cmd == "watch-head")            return cmd_watch_head(sub_argc, sub_argv);
        if (cmd == "export-headers")        return cmd_export_headers(sub_argc, sub_argv);
        if (cmd == "verify-archive")        return cmd_verify_archive(sub_argc, sub_argv);
        if (cmd == "verify-tx-inclusion")   return cmd_verify_tx_inclusion(sub_argc, sub_argv);
        if (cmd == "verify-receipt-inclusion") return cmd_verify_receipt_inclusion(sub_argc, sub_argv);
        if (cmd == "verify-merge-state")    return cmd_verify_merge_state(sub_argc, sub_argv);
        if (cmd == "verify-param-change")   return cmd_verify_param_change(sub_argc, sub_argv);
    } catch (const std::exception& e) {
        std::cerr << "determ-light: unhandled error: " << e.what() << "\n";
        return 2;
    }

    std::cerr << "determ-light: unknown subcommand '" << cmd << "'\n"
              << "  run `determ-light help` for the list of commands\n";
    return 1;
}
