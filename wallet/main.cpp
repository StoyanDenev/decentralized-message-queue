// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
// A2 — determ-wallet binary
//
// v1.x scope (Phase 1, this commit):
//   * shamir split <secret-hex> -t N -n M         → write N shares to stdout
//   * shamir combine <share> [<share> ...]        → recover the secret
//   * version                                     → print build banner
//
// v1.x scope (Phase 2, follow-on):
//   * envelope encrypt / decrypt (AEAD wrapping)
//   * OPAQUE registration + AKE (via libopaque)
//   * create-recovery / recover end-to-end flows
//
// Build target: determ-wallet (separate from `determ` daemon binary).
//
// Why a separate binary: the wallet handles secret material that should
// never share an address space with a networked daemon. The wallet must
// be auditable in isolation; coupling it to the chain binary's RPC and
// gossip surfaces would broaden the trusted compute base unnecessarily.

#include "shamir.hpp"
#include "envelope.hpp"
#include "recovery.hpp"
#include "opaque_primitives.hpp"
#include "opaque_adapter.hpp"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <array>
#include <set>
#include <cstring>

using namespace determ::wallet;

namespace {

std::string to_hex(const std::vector<uint8_t>& v) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (auto b : v) o << std::setw(2) << static_cast<int>(b);
    return o.str();
}

// Fixed-size overload used by the Ed25519 keygen path (pubkey and
// priv-seed are both exactly 32 bytes). Returns 64 lowercase hex chars.
template <size_t N>
std::string to_hex(const std::array<uint8_t, N>& a) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (auto b : a) o << std::setw(2) << static_cast<int>(b);
    return o.str();
}

std::vector<uint8_t> from_hex(const std::string& s) {
    if (s.size() % 2 != 0)
        throw std::invalid_argument("from_hex: odd length");
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned int byte;
        std::istringstream ss(s.substr(i, 2));
        ss >> std::hex >> byte;
        if (ss.fail())
            throw std::invalid_argument("from_hex: non-hex char");
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
}

// Share wire format: "<x_hex>:<y_hex>", e.g. "01:abcdef" for x=1.
// Compact and easy to copy/paste between guardians.
std::string serialize_share(const shamir::Share& s) {
    std::ostringstream o;
    o << std::hex << std::setfill('0') << std::setw(2)
      << static_cast<int>(s.x) << ":" << to_hex(s.y);
    return o.str();
}

shamir::Share parse_share(const std::string& blob) {
    auto colon = blob.find(':');
    if (colon == std::string::npos)
        throw std::invalid_argument("share missing ':' separator");
    shamir::Share s;
    auto x_bytes = from_hex(blob.substr(0, colon));
    if (x_bytes.size() != 1)
        throw std::invalid_argument("share x-coordinate must be 1 byte");
    s.x = x_bytes[0];
    s.y = from_hex(blob.substr(colon + 1));
    return s;
}

int cmd_shamir_split(int argc, char** argv) {
    std::string secret_hex;
    int threshold = 0, share_count = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "-t" && i + 1 < argc) threshold   = std::stoi(argv[++i]);
        else if (a == "-n" && i + 1 < argc) share_count = std::stoi(argv[++i]);
        else if (a.size() && a[0] != '-')   secret_hex  = a;
    }
    if (secret_hex.empty() || threshold <= 0 || share_count <= 0) {
        std::cerr << "Usage: determ-wallet shamir split <secret_hex> "
                     "-t <threshold> -n <share_count>\n";
        return 1;
    }
    if (threshold > 255 || share_count > 255) {
        std::cerr << "shamir split: t and n must each be <= 255\n";
        return 1;
    }
    std::vector<uint8_t> secret;
    try { secret = from_hex(secret_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid secret hex: " << e.what() << "\n"; return 1;
    }
    if (secret.empty()) {
        std::cerr << "Secret must be non-empty\n"; return 1;
    }
    std::vector<shamir::Share> shares;
    try {
        shares = shamir::split(secret,
                                  static_cast<uint8_t>(threshold),
                                  static_cast<uint8_t>(share_count));
    } catch (std::exception& e) {
        std::cerr << "shamir split error: " << e.what() << "\n"; return 1;
    }
    for (auto& s : shares) std::cout << serialize_share(s) << "\n";
    return 0;
}

int cmd_shamir_combine(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ-wallet shamir combine <share> "
                     "[<share> ...]\n";
        return 1;
    }
    std::vector<shamir::Share> shares;
    for (int i = 0; i < argc; ++i) {
        try { shares.push_back(parse_share(argv[i])); }
        catch (std::exception& e) {
            std::cerr << "Invalid share '" << argv[i] << "': "
                      << e.what() << "\n";
            return 1;
        }
    }
    auto secret = shamir::combine(shares);
    if (!secret) {
        std::cerr << "shamir combine: shares inconsistent "
                     "(duplicate x, mismatched lengths, or empty)\n";
        return 1;
    }
    std::cout << to_hex(*secret) << "\n";
    return 0;
}

int cmd_shamir(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ-wallet shamir {split|combine} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "split")   return cmd_shamir_split  (argc - 1, argv + 1);
    if (sub == "combine") return cmd_shamir_combine(argc - 1, argv + 1);
    std::cerr << "Unknown shamir subcommand: " << sub << "\n";
    return 1;
}

// Raw-primitive CLIs: expose shamir::split / ::combine directly with
// JSON-first output, independent of the recovery envelope flow. Useful
// for operator workflows that need to print physical shares, split a
// non-wallet secret, or feed shares into a different transport. The
// legacy `shamir {split|combine}` subcommand group above stays for
// backward compatibility with existing test fixtures + the
// colon-separated wire format.
int cmd_shamir_split_raw(int argc, char** argv) {
    std::string secret_hex;
    int threshold = -1, shares = -1;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--secret"    && i + 1 < argc) secret_hex = argv[++i];
        else if (a == "--threshold" && i + 1 < argc) threshold  = std::stoi(argv[++i]);
        else if (a == "--shares"    && i + 1 < argc) shares     = std::stoi(argv[++i]);
        else if (a == "--json")                      json_out   = true;
    }
    if (secret_hex.empty() || threshold < 0 || shares < 0) {
        std::cerr << "Usage: determ-wallet shamir-split --secret <hex> "
                     "--threshold T --shares N [--json]\n";
        return 1;
    }
    if (threshold < 1) {
        std::cerr << "shamir-split: --threshold must be >= 1\n"; return 1;
    }
    if (shares < threshold) {
        std::cerr << "shamir-split: --shares (" << shares
                  << ") must be >= --threshold (" << threshold << ")\n";
        return 1;
    }
    if (shares > 255) {
        std::cerr << "shamir-split: --shares must be <= 255\n"; return 1;
    }
    if (secret_hex.size() % 2 != 0) {
        std::cerr << "shamir-split: --secret hex must have even length\n";
        return 1;
    }
    std::vector<uint8_t> secret;
    try { secret = from_hex(secret_hex); }
    catch (std::exception& e) {
        std::cerr << "shamir-split: invalid --secret hex: " << e.what() << "\n";
        return 1;
    }
    if (secret.empty()) {
        std::cerr << "shamir-split: --secret must be non-empty\n"; return 1;
    }
    std::vector<shamir::Share> out;
    try {
        out = shamir::split(secret,
                              static_cast<uint8_t>(threshold),
                              static_cast<uint8_t>(shares));
    } catch (std::exception& e) {
        std::cerr << "shamir-split: " << e.what() << "\n"; return 1;
    }
    if (json_out) {
        nlohmann::json j;
        j["shares"] = nlohmann::json::array();
        for (auto& s : out) {
            j["shares"].push_back({
                {"x",      static_cast<int>(s.x)},
                {"y_hex",  to_hex(s.y)},
            });
        }
        std::cout << j.dump() << "\n";
    } else {
        for (size_t i = 0; i < out.size(); ++i) {
            std::cout << "Share " << (i + 1) << ": x="
                      << static_cast<int>(out[i].x) << " y="
                      << to_hex(out[i].y) << "\n";
        }
    }
    return 0;
}

int cmd_shamir_combine_raw(int argc, char** argv) {
    std::string shares_path;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--shares" && i + 1 < argc) shares_path = argv[++i];
        else if (a == "--json")                   json_out    = true;
    }
    if (shares_path.empty()) {
        std::cerr << "Usage: determ-wallet shamir-combine --shares <file> "
                     "[--json]\n";
        return 1;
    }
    std::ifstream f(shares_path);
    if (!f) {
        std::cerr << "shamir-combine: cannot open --shares file: "
                  << shares_path << "\n";
        return 1;
    }
    std::string blob((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    nlohmann::json j;
    try { j = nlohmann::json::parse(blob); }
    catch (std::exception& e) {
        std::cerr << "shamir-combine: JSON parse failed: " << e.what() << "\n";
        return 1;
    }
    if (!j.contains("shares") || !j["shares"].is_array()) {
        std::cerr << "shamir-combine: JSON missing 'shares' array\n";
        return 1;
    }
    std::vector<shamir::Share> in;
    std::set<int> seen_x;
    size_t y_len = 0;
    for (auto& el : j["shares"]) {
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            std::cerr << "shamir-combine: each share must have integer 'x' "
                         "and string 'y_hex'\n";
            return 1;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            std::cerr << "shamir-combine: x must be in [1,255], got "
                      << x << "\n";
            return 1;
        }
        if (!seen_x.insert(x).second) {
            std::cerr << "shamir-combine: duplicate x = " << x << "\n";
            return 1;
        }
        std::string y_hex = el["y_hex"].get<std::string>();
        if (y_hex.size() % 2 != 0) {
            std::cerr << "shamir-combine: y_hex must have even length "
                         "(x=" << x << ")\n";
            return 1;
        }
        shamir::Share s;
        s.x = static_cast<uint8_t>(x);
        try { s.y = from_hex(y_hex); }
        catch (std::exception& e) {
            std::cerr << "shamir-combine: y_hex parse failed (x=" << x
                      << "): " << e.what() << "\n";
            return 1;
        }
        if (s.y.empty()) {
            std::cerr << "shamir-combine: y_hex empty (x=" << x << ")\n";
            return 1;
        }
        if (y_len == 0) y_len = s.y.size();
        else if (s.y.size() != y_len) {
            std::cerr << "shamir-combine: share y lengths mismatch "
                         "(x=" << x << ": " << s.y.size()
                      << " vs first: " << y_len << ")\n";
            return 1;
        }
        in.push_back(std::move(s));
    }
    if (in.empty()) {
        std::cerr << "shamir-combine: 'shares' array is empty\n"; return 1;
    }
    auto out = shamir::combine(in);
    if (!out) {
        std::cerr << "shamir-combine: reconstruction failed (shares "
                     "inconsistent at the shamir layer)\n";
        return 1;
    }
    if (json_out) {
        nlohmann::json r;
        r["secret_hex"] = to_hex(*out);
        std::cout << r.dump() << "\n";
    } else {
        std::cout << to_hex(*out) << "\n";
    }
    return 0;
}

// Diagnostic CLI: structural verification of a Shamir share-set file
// WITHOUT reconstructing the secret.
//
// Use cases:
//   * Operators distributing physical shares — verify a share envelope
//     is well-formed before mailing it.
//   * Pre-reconstruction sanity check — before attempting a costly
//     T-of-N combine (which may need T-1 other shares hand-delivered),
//     verify that the shares already on hand are structurally consistent.
//   * Tooling (operator scripts, monitoring) that wants share-set
//     metadata in structured form (--json) without leaking the secret.
//
// Verification checks (all structural; no GF(2^8) reconstruction):
//   1. JSON parseable.
//   2. Top-level is object with "shares" array.
//   3. shares array non-empty.
//   4. Each share has integer x in [1, 255] and string y_hex with even length.
//   5. All x values DISTINCT (Shamir invariant — same x = same point on the
//      polynomial; reconstruction would fail at the Lagrange step).
//   6. All y_hex values share the SAME byte length (Shamir invariant —
//      every share is derived from a polynomial over the same secret-size
//      domain).
//   7. y_hex contains only hex characters [0-9a-fA-F].
//   8. If --threshold T is supplied, also report whether share count >= T
//      (informational; insufficient share count is NOT a structural error).
//
// Exit codes:
//   0  structurally valid (and threshold met if --threshold supplied)
//   1  bad args / missing file / JSON parse error
//   2  structurally invalid (operator alert gate — one of checks 2-7 failed)
//
// Insufficient-share-count when --threshold is supplied returns 0 with an
// [INFO] line (it's diagnostic, not a structural defect).
int cmd_shamir_verify(int argc, char** argv) {
    std::string shares_path;
    int threshold = -1;       // -1 sentinel = not supplied
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--shares"    && i + 1 < argc) shares_path = argv[++i];
        else if (a == "--threshold" && i + 1 < argc) threshold   = std::stoi(argv[++i]);
        else if (a == "--json")                       json_out    = true;
    }
    if (shares_path.empty()) {
        std::cerr << "Usage: determ-wallet shamir-verify --shares <file> "
                     "[--threshold T] [--json]\n";
        return 1;
    }
    std::ifstream f(shares_path);
    if (!f) {
        if (json_out) {
            std::cout << "{\"valid\":false,\"errors\":[\"cannot open file\"]}\n";
        } else {
            std::cerr << "shamir-verify: cannot open --shares file: "
                      << shares_path << "\n";
        }
        return 1;
    }
    std::string blob((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    nlohmann::json j;
    try { j = nlohmann::json::parse(blob); }
    catch (std::exception& e) {
        if (json_out) {
            nlohmann::json r;
            r["valid"] = false;
            r["errors"] = nlohmann::json::array({std::string("JSON parse error: ") + e.what()});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "shamir-verify: JSON parse failed: " << e.what() << "\n";
        }
        return 1;
    }

    auto report_fail = [&](const std::string& reason) {
        if (json_out) {
            nlohmann::json r;
            r["valid"] = false;
            r["errors"] = nlohmann::json::array({reason});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "[FAIL] " << reason << "\n";
        }
    };

    if (!j.is_object() || !j.contains("shares") || !j["shares"].is_array()) {
        report_fail("top-level must be object with 'shares' array");
        return 2;
    }
    const auto& arr = j["shares"];
    if (arr.empty()) {
        report_fail("shares array is empty");
        return 2;
    }

    // Cheap hex-validity check (independent of from_hex which throws on
    // odd length; we want to distinguish bad-char from odd-length so the
    // operator gets a precise diagnostic).
    auto is_hex_char = [](char c) {
        return (c >= '0' && c <= '9')
            || (c >= 'a' && c <= 'f')
            || (c >= 'A' && c <= 'F');
    };

    std::set<int> seen_x;
    int x_min = 256, x_max = -1;
    size_t y_byte_len = 0;
    bool y_len_consistent = true;

    for (size_t i = 0; i < arr.size(); ++i) {
        const auto& el = arr[i];
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            report_fail("share #" + std::to_string(i)
                        + ": must have integer 'x' and string 'y_hex'");
            return 2;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            report_fail("share #" + std::to_string(i) + ": x = "
                        + std::to_string(x) + " out of range [1, 255]");
            return 2;
        }
        if (!seen_x.insert(x).second) {
            report_fail("duplicate x = " + std::to_string(x)
                        + " (Shamir invariant: all x must be distinct)");
            return 2;
        }
        if (x < x_min) x_min = x;
        if (x > x_max) x_max = x;

        std::string y_hex = el["y_hex"].get<std::string>();
        if (y_hex.size() % 2 != 0) {
            report_fail("share x=" + std::to_string(x)
                        + ": y_hex has odd length (" + std::to_string(y_hex.size()) + ")");
            return 2;
        }
        for (char c : y_hex) {
            if (!is_hex_char(c)) {
                report_fail("share x=" + std::to_string(x)
                            + ": y_hex contains non-hex character");
                return 2;
            }
        }
        size_t this_y_len = y_hex.size() / 2;
        if (this_y_len == 0) {
            report_fail("share x=" + std::to_string(x) + ": y_hex is empty");
            return 2;
        }
        if (y_byte_len == 0) {
            y_byte_len = this_y_len;
        } else if (this_y_len != y_byte_len) {
            // Flag the inconsistency precisely; reject (operator alert).
            report_fail("share x=" + std::to_string(x) + ": y_hex length "
                        + std::to_string(this_y_len)
                        + " bytes differs from first share's "
                        + std::to_string(y_byte_len)
                        + " bytes (Shamir invariant: all shares must share "
                        + "the same secret-size domain)");
            y_len_consistent = false;
            return 2;
        }
    }

    const int share_count    = static_cast<int>(arr.size());
    const int distinct_x_cnt = static_cast<int>(seen_x.size());
    // threshold_satisfied tri-state: nullopt = not supplied, true = met,
    // false = supplied but insufficient. The supplied-but-insufficient
    // case is INFORMATIONAL (exit 0) — see header doc for rationale.
    std::optional<bool> threshold_satisfied;
    if (threshold >= 0) threshold_satisfied = (share_count >= threshold);

    if (json_out) {
        nlohmann::json r;
        r["valid"]              = true;
        r["share_count"]        = share_count;
        r["distinct_x"]         = distinct_x_cnt;
        r["x_range"]            = nlohmann::json::array({x_min, x_max});
        r["y_byte_length"]      = y_byte_len;
        r["consistent_lengths"] = y_len_consistent;  // always true at this point
        if (threshold_satisfied.has_value()) {
            r["threshold_satisfied"] = *threshold_satisfied;
        } else {
            r["threshold_satisfied"] = nullptr;
        }
        r["errors"] = nlohmann::json::array();
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "=== shamir share-set verification ===\n";
        std::cout << "Shares present: "      << share_count << "\n";
        std::cout << "Distinct x values: "   << distinct_x_cnt
                  << " (range: " << x_min << ".." << x_max << ")\n";
        std::cout << "y_hex byte-length: "   << y_byte_len
                  << " bytes (consistent across all shares)\n";
        std::cout << "[OK] Structural verification passed\n";
        if (threshold_satisfied.has_value()) {
            if (*threshold_satisfied) {
                std::cout << "[OK] Share count (" << share_count
                          << ") >= threshold (" << threshold
                          << ") -- sufficient for reconstruction\n";
            } else {
                std::cout << "[INFO] Share count (" << share_count
                          << ") < threshold (" << threshold
                          << ") -- insufficient for reconstruction\n";
            }
        }
    }
    return 0;
}

int cmd_envelope_encrypt(int argc, char** argv) {
    std::string plaintext_hex, password, aad_hex;
    uint32_t iters = envelope::DEFAULT_PBKDF2_ITERS;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--plaintext" && i + 1 < argc) plaintext_hex = argv[++i];
        else if (a == "--password"  && i + 1 < argc) password      = argv[++i];
        else if (a == "--aad"       && i + 1 < argc) aad_hex       = argv[++i];
        else if (a == "--iters"     && i + 1 < argc) iters         = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    if (plaintext_hex.empty() || password.empty()) {
        std::cerr << "Usage: determ-wallet envelope encrypt "
                     "--plaintext <hex> --password <str> "
                     "[--aad <hex>] [--iters <N>]\n";
        return 1;
    }
    std::vector<uint8_t> pt, aad;
    try {
        pt = from_hex(plaintext_hex);
        if (!aad_hex.empty()) aad = from_hex(aad_hex);
    } catch (std::exception& e) {
        std::cerr << "hex parse: " << e.what() << "\n"; return 1;
    }
    try {
        auto env = envelope::encrypt(pt, password, aad, iters);
        std::cout << envelope::serialize(env) << "\n";
    } catch (std::exception& e) {
        std::cerr << "encrypt: " << e.what() << "\n"; return 1;
    }
    return 0;
}

int cmd_envelope_decrypt(int argc, char** argv) {
    std::string blob, password, aad_hex;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--envelope" && i + 1 < argc) blob     = argv[++i];
        else if (a == "--password" && i + 1 < argc) password = argv[++i];
        else if (a == "--aad"      && i + 1 < argc) aad_hex  = argv[++i];
    }
    if (blob.empty() || password.empty()) {
        std::cerr << "Usage: determ-wallet envelope decrypt "
                     "--envelope <blob> --password <str> [--aad <hex>]\n";
        return 1;
    }
    auto env_opt = envelope::deserialize(blob);
    if (!env_opt) {
        std::cerr << "decrypt: envelope deserialize failed (malformed blob)\n";
        return 1;
    }
    std::vector<uint8_t> aad;
    if (!aad_hex.empty()) {
        try { aad = from_hex(aad_hex); }
        catch (std::exception& e) {
            std::cerr << "aad hex: " << e.what() << "\n"; return 1;
        }
    }
    auto pt_opt = envelope::decrypt(*env_opt, password, aad);
    if (!pt_opt) {
        std::cerr << "decrypt: AEAD tag failure "
                     "(wrong password, tampered ciphertext, or mismatched AAD)\n";
        return 2;
    }
    std::cout << to_hex(*pt_opt) << "\n";
    return 0;
}

int cmd_envelope(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ-wallet envelope {encrypt|decrypt} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "encrypt") return cmd_envelope_encrypt(argc - 1, argv + 1);
    if (sub == "decrypt") return cmd_envelope_decrypt(argc - 1, argv + 1);
    std::cerr << "Unknown envelope subcommand: " << sub << "\n";
    return 1;
}

// Diagnostic CLI: inspect an envelope file without decrypting.
//
// Use cases:
//   * Forensic inspection of stale recovery artifacts on disk.
//   * Operators verifying a candidate file is actually an envelope
//     (right magic + sane salt/nonce sizes) before paying the PBKDF2
//     cost of a decrypt attempt.
//   * Tooling (monitoring scripts, log aggregators) that wants the
//     KDF parameters in structured form (--json).
//
// Parses the canonical serialized blob via envelope::deserialize and
// reports the header fields. NEVER calls AES-GCM — no key derivation,
// no tag verification, no plaintext recovery. A password is therefore
// not required and not accepted.
//
// Wire format (recap from envelope.hpp):
//   "DWE1" magic (4B) | salt_len/salt | pbkdf2_iters (u32 LE)
//   | nonce (12B) | aad_len/aad | ct_len/(ciphertext || 16B tag)
// The serialized form is dot-separated lowercase hex of those fields.
int cmd_inspect_envelope(int argc, char** argv) {
    std::string in_path;
    bool json_output = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"   && i + 1 < argc) in_path = argv[++i];
        else if (a == "--json")                 json_output = true;
    }
    if (in_path.empty()) {
        std::cerr << "Usage: determ-wallet inspect-envelope --in <file> [--json]\n";
        return 1;
    }
    std::ifstream f(in_path);
    if (!f) {
        std::cerr << "inspect-envelope: cannot open --in: " << in_path << "\n";
        return 1;
    }
    std::string blob((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    // Strip surrounding whitespace and any trailing CR/LF — the file may
    // have been written via shell redirection which appends a newline.
    auto is_ws = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };
    while (!blob.empty() && is_ws(blob.front())) blob.erase(blob.begin());
    while (!blob.empty() && is_ws(blob.back()))  blob.pop_back();
    if (blob.empty()) {
        std::cerr << "inspect-envelope: file is empty: " << in_path << "\n";
        return 1;
    }

    auto env_opt = envelope::deserialize(blob);
    if (!env_opt) {
        std::cerr << "inspect-envelope: malformed envelope "
                     "(bad magic, truncated, or non-hex content)\n";
        return 2;
    }
    const auto& env = *env_opt;

    // ciphertext stored as (body || 16B tag). Report them separately so
    // operators can sanity-check both the body length and the tag.
    constexpr size_t TAG_LEN = 16;
    const size_t ct_total = env.ciphertext.size();
    const size_t ct_body  = ct_total - TAG_LEN;
    const bool   aad_present = !env.aad.empty();

    if (json_output) {
        // Hand-built JSON: deliberately minimal — no nested objects, no
        // arrays of bytes. Keep the schema flat so monitoring scripts can
        // parse with jq/Python json with zero ambiguity. Hex strings are
        // lowercase to match envelope::serialize convention.
        std::cout << "{"
                  << "\"format\":\"DWE1\","
                  << "\"version\":1,"
                  << "\"pbkdf2_iters\":" << env.pbkdf2_iters << ","
                  << "\"salt_len\":"     << env.salt.size()  << ","
                  << "\"salt_hex\":\""   << to_hex(env.salt) << "\","
                  << "\"nonce_len\":"    << env.nonce.size() << ","
                  << "\"nonce_hex\":\""  << to_hex(env.nonce)<< "\","
                  << "\"aad_present\":"  << (aad_present ? "true" : "false") << ","
                  << "\"aad_len\":"      << env.aad.size()   << ","
                  << "\"aad_hex\":\""    << to_hex(env.aad)  << "\","
                  << "\"ciphertext_len\":" << ct_total       << ","
                  << "\"ciphertext_body_len\":" << ct_body   << ","
                  << "\"tag_len\":"      << TAG_LEN
                  << "}\n";
    } else {
        std::cout << "envelope file:   " << in_path           << "\n";
        std::cout << "format:          DWE1 (version 1)\n";
        std::cout << "pbkdf2_iters:    " << env.pbkdf2_iters  << "\n";
        std::cout << "salt_len:        " << env.salt.size()   << " bytes\n";
        std::cout << "salt_hex:        " << to_hex(env.salt)  << "\n";
        std::cout << "nonce_len:       " << env.nonce.size()  << " bytes\n";
        std::cout << "nonce_hex:       " << to_hex(env.nonce) << "\n";
        std::cout << "aad_present:     " << (aad_present ? "true" : "false") << "\n";
        std::cout << "aad_len:         " << env.aad.size()    << " bytes\n";
        if (aad_present)
            std::cout << "aad_hex:         " << to_hex(env.aad) << "\n";
        std::cout << "ciphertext_len:  " << ct_total          << " bytes\n";
        std::cout << "  body:          " << ct_body           << " bytes\n";
        std::cout << "  tag:           " << TAG_LEN           << " bytes (GCM)\n";
    }
    return 0;
}

// Operator-workflow CLI: batch-generate N fresh anonymous account keypairs
// in one invocation. Useful for:
//   * Cold-storage provisioning (mint a batch of receive addresses to
//     distribute to clients, with privkeys kept offline).
//   * Faucet bootstrapping (pre-mint addresses to fund + hand out).
//   * Test-fixture generation (deterministic build of test corpora —
//     each call still produces fresh randomness; the "deterministic"
//     part is the on-disk JSON shape, not the values).
//
// Each entry: Ed25519 keypair (OpenSSL EVP) → anon-address derivation
// ("0x" + lowercase hex(pubkey)). Mirrors the shape produced by the
// `determ account create` command but batched, so an operator doesn't
// pay process-startup cost per account.
//
// Output modes (mutually-exclusive precedence):
//   default (no flags) — human format to stdout, one block per account:
//       Account 1:
//         address:     0x...
//         privkey_hex: ...
//   --out <file>        — write a JSON file {accounts: [{address, privkey_hex}, ...]}
//                         and print only a one-line confirmation to stdout.
//                         The privkey material lives in the file, not the terminal.
//   --json (no --out)   — write the same JSON shape to stdout.
//   --out + --json      — --out wins (explicit operator choice; no
//                         JSON to stdout even though --json was set).
//
// Safety guards:
//   * 1 <= N <= 10000. Operator-side cap; generating > 10k keypairs in
//     one call is almost certainly an automation bug (a power-of-ten
//     fat-finger), not a real workflow. Belt-and-suspenders against
//     accidentally writing a 5-MB privkey blob.
//   * --out file overwrite refused unless --force. Privkey loss via
//     accidental overwrite is unrecoverable; force a deliberate ack.
//   * --out parent directory must exist (no mkdirp). Surfacing the
//     missing-directory error early is friendlier than silently
//     creating an unintended directory tree.
//
// Privkey emission:
//   Unlike `determ account create` (which gates plaintext stdout
//   behind --allow-plaintext-stdout due to S-004), this command's
//   default human mode emits plaintext privkeys because the typical
//   workflow REDIRECTS to a file (`> accounts.txt`) or pipes to a
//   processing tool. For terminal-leakage-sensitive use, operators
//   should pass --out <file> (which gets owner-only permissions on
//   POSIX via std::filesystem::permissions; on Windows we rely on
//   the default ACL of the parent directory). This deviation is
//   intentional: batch generation has no sensible "encrypt at rest"
//   default because the operator's intent is downstream automation.
int cmd_account_create_batch(int argc, char** argv) {
    int count = 0;
    std::string out_path;
    bool json_out = false;
    bool force = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--count" && i + 1 < argc) {
            try { count = std::stoi(argv[++i]); }
            catch (std::exception&) {
                std::cerr << "account-create-batch: --count must be an integer\n";
                return 1;
            }
        }
        else if (a == "--out"   && i + 1 < argc) out_path = argv[++i];
        else if (a == "--json")                  json_out = true;
        else if (a == "--force")                 force    = true;
        else {
            std::cerr << "account-create-batch: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-create-batch --count N "
                         "[--out <file>] [--json] [--force]\n";
            return 1;
        }
    }
    if (count <= 0) {
        std::cerr << "account-create-batch: --count must be >= 1 (got "
                  << count << ")\n";
        return 1;
    }
    constexpr int MAX_COUNT = 10000;
    if (count > MAX_COUNT) {
        std::cerr << "account-create-batch: --count must be <= " << MAX_COUNT
                  << " (got " << count << "). If you genuinely need more, "
                     "invoke the command multiple times and concatenate; "
                     "the cap is an operator safety net against fat-finger "
                     "automation errors.\n";
        return 1;
    }
    // --out preconditions: parent dir must exist; destination file
    // must not exist (unless --force). Surfacing these before keygen
    // means we don't generate N keypairs and then discard them.
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "account-create-batch: --out parent directory does "
                         "not exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "account-create-batch: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // Build the accounts array via OpenSSL Ed25519 keygen. EVP_PKEY_keygen
    // ultimately pulls from OpenSSL's CSPRNG (seeded from the OS RNG at
    // library init), so each iteration gets fresh material.
    nlohmann::json arr = nlohmann::json::array();
    for (int i = 0; i < count; ++i) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!ctx) {
            std::cerr << "account-create-batch: EVP_PKEY_CTX_new_id failed\n";
            return 1;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            std::cerr << "account-create-batch: EVP_PKEY_keygen_init failed\n";
            return 1;
        }
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            std::cerr << "account-create-batch: EVP_PKEY_keygen failed\n";
            return 1;
        }
        EVP_PKEY_CTX_free(ctx);
        std::array<uint8_t, 32> pub{};
        std::array<uint8_t, 32> priv_seed{};
        size_t len = pub.size();
        if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) <= 0
            || len != 32) {
            EVP_PKEY_free(pkey);
            std::cerr << "account-create-batch: get_raw_public_key failed\n";
            return 1;
        }
        len = priv_seed.size();
        if (EVP_PKEY_get_raw_private_key(pkey, priv_seed.data(), &len) <= 0
            || len != 32) {
            EVP_PKEY_free(pkey);
            std::cerr << "account-create-batch: get_raw_private_key failed\n";
            return 1;
        }
        EVP_PKEY_free(pkey);

        std::string address = "0x" + to_hex(pub);           // matches make_anon_address
        std::string privkey_hex = to_hex(priv_seed);        // 64 lowercase hex
        arr.push_back({
            {"address",     address},
            {"privkey_hex", privkey_hex},
        });
    }

    // Dispatch on output mode.
    if (!out_path.empty()) {
        nlohmann::json doc;
        doc["accounts"] = std::move(arr);
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "account-create-batch: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << doc.dump(2) << "\n";
        f.close();
        // POSIX permissions tightening — owner-only read/write. On
        // Windows the call is a no-op for the read/write bits (NTFS
        // ACL inherits from parent); we ignore the error code there.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        // Intentionally non-fatal on perm-set failure: file is written;
        // operator may need to chmod manually on exotic filesystems.
        std::cout << "wrote " << count << " accounts to " << out_path << "\n";
        return 0;
    }
    if (json_out) {
        nlohmann::json doc;
        doc["accounts"] = std::move(arr);
        std::cout << doc.dump(2) << "\n";
        return 0;
    }
    // Default human format.
    for (size_t i = 0; i < arr.size(); ++i) {
        std::cout << "Account " << (i + 1) << ":\n"
                  << "  address:     " << arr[i]["address"].get<std::string>()     << "\n"
                  << "  privkey_hex: " << arr[i]["privkey_hex"].get<std::string>() << "\n";
    }
    return 0;
}

// Diagnostic CLI: structural verification of a complete wallet backup
// (Shamir share-set + per-share AEAD envelopes) WITHOUT decrypting.
//
// A "backup" in the Determ wallet model is the combination of:
//   1. A Shamir share-set file (output of `shamir-split --json`):
//        {"shares": [{"x": int, "y_hex": "..."}, ...]}
//   2. A per-share AEAD envelopes file (one envelope per share, each
//      wrapped with a per-keyholder passphrase). No prior CLI emits this
//      composite, so this command defines the canonical shape:
//        {"envelopes": [{"share_index": int,
//                        "envelope_blob": "<canonical envelope blob>"},
//                       ...]}
//      `share_index` corresponds 1:1 to the Shamir share's `x` field;
//      `envelope_blob` is the dot-separated canonical form emitted by
//      `envelope encrypt` / serialize().
//
// Together the two files let any T-of-N keyholders decrypt their share
// (each with their own passphrase) and feed the resulting plaintext
// shares to `shamir-combine` for secret reconstruction. This CLI
// verifies the two files are STRUCTURALLY consistent (every share has
// a matching envelope, no duplicates, no gaps, every envelope blob
// deserializes and has sane metadata) — WITHOUT requiring any
// passphrase and WITHOUT performing AES-GCM.
//
// Use cases:
//   * Pre-distribution sanity check by the secret owner — confirm the
//     pair was written correctly before mailing physical copies.
//   * Pre-recovery validation by the coordinator — confirm the
//     recovered files are well-formed before convening T keyholders.
//   * Operator tooling — monitoring scripts that want backup health
//     in structured form (--json) without secret material.
//
// Verification checks (all structural; no AEAD, no Shamir recovery):
//   1. Both files parse as JSON.
//   2. Shares file has expected shape (mirrors shamir-verify checks:
//      object with non-empty "shares" array; each entry has int x in
//      [1, 255] and hex y_hex with consistent even length).
//   3. Envelopes file has expected shape (object with "envelopes" array;
//      each entry has int share_index in [1, 255] and string envelope_blob).
//   4. share_count == envelope_count.
//   5. Share x-values match envelope share_index values 1:1 (no
//      duplicates, no gaps, full bijection).
//   6. Each envelope_blob deserializes via envelope::deserialize.
//   7. Each envelope's metadata is structurally valid:
//      PBKDF2 iters > 0, salt non-empty, nonce exactly 12B,
//      ciphertext >= 16B (so the GCM tag fits).
//   8. If --threshold T is supplied: also report whether share count
//      >= T (informational; insufficient share count is NOT a
//      structural error — same convention as shamir-verify).
//
// Exit codes:
//   0  structurally valid (and threshold met if --threshold supplied)
//   1  bad args / missing file / JSON parse error
//   2  structurally invalid (operator alert gate — any of checks 2-7 failed)
//
// Insufficient-share-count when --threshold is supplied returns 0
// (informational), matching shamir-verify's convention.
int cmd_backup_verify(int argc, char** argv) {
    std::string shares_path, envelopes_path;
    int threshold = -1;       // -1 sentinel = not supplied
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--shares"    && i + 1 < argc) shares_path    = argv[++i];
        else if (a == "--envelopes" && i + 1 < argc) envelopes_path = argv[++i];
        else if (a == "--threshold" && i + 1 < argc) threshold      = std::stoi(argv[++i]);
        else if (a == "--json")                       json_out       = true;
    }
    if (shares_path.empty() || envelopes_path.empty()) {
        std::cerr << "Usage: determ-wallet backup-verify "
                     "--shares <file> --envelopes <file> "
                     "[--threshold T] [--json]\n"
                     "\n"
                     "  Verifies structural integrity of a complete wallet backup\n"
                     "  (Shamir shares + per-share AEAD envelopes) without decrypting.\n"
                     "\n"
                     "  Shares file shape:    {\"shares\":    [{\"x\": int, \"y_hex\": \"...\"}, ...]}\n"
                     "  Envelopes file shape: {\"envelopes\": [{\"share_index\": int, "
                     "\"envelope_blob\": \"...\"}, ...]}\n";
        return 1;
    }

    // Helper: structured error reporter. In --json mode emits the JSON
    // doc to stdout (so monitoring scripts see a complete result on
    // every invocation, success or fail); in human mode emits the
    // [FAIL] line to stderr.
    auto report_fail = [&](const std::string& reason,
                           const std::string& share_count_hint = "") {
        if (json_out) {
            nlohmann::json r;
            r["valid"]               = false;
            r["shares_file"]         = shares_path;
            r["envelopes_file"]      = envelopes_path;
            r["share_count"]         = 0;
            r["envelope_count"]      = 0;
            r["mapping_consistent"]  = false;
            r["envelope_details"]    = nlohmann::json::array();
            r["threshold_satisfied"] = nullptr;
            r["errors"]              = nlohmann::json::array({reason});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "[FAIL] " << reason << "\n";
        }
        (void)share_count_hint;
    };

    // ── Load + parse the shares file ────────────────────────────────────
    std::ifstream sf(shares_path);
    if (!sf) {
        if (json_out) {
            nlohmann::json r;
            r["valid"]  = false;
            r["errors"] = nlohmann::json::array(
                {std::string("cannot open --shares file: ") + shares_path});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "backup-verify: cannot open --shares file: "
                      << shares_path << "\n";
        }
        return 1;
    }
    std::string shares_blob((std::istreambuf_iterator<char>(sf)),
                              std::istreambuf_iterator<char>());
    nlohmann::json sj;
    try { sj = nlohmann::json::parse(shares_blob); }
    catch (std::exception& e) {
        if (json_out) {
            nlohmann::json r;
            r["valid"]  = false;
            r["errors"] = nlohmann::json::array(
                {std::string("shares JSON parse error: ") + e.what()});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "backup-verify: shares JSON parse failed: "
                      << e.what() << "\n";
        }
        return 1;
    }

    // ── Load + parse the envelopes file ─────────────────────────────────
    std::ifstream ef(envelopes_path);
    if (!ef) {
        if (json_out) {
            nlohmann::json r;
            r["valid"]  = false;
            r["errors"] = nlohmann::json::array(
                {std::string("cannot open --envelopes file: ") + envelopes_path});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "backup-verify: cannot open --envelopes file: "
                      << envelopes_path << "\n";
        }
        return 1;
    }
    std::string envs_blob((std::istreambuf_iterator<char>(ef)),
                            std::istreambuf_iterator<char>());
    nlohmann::json ej;
    try { ej = nlohmann::json::parse(envs_blob); }
    catch (std::exception& e) {
        if (json_out) {
            nlohmann::json r;
            r["valid"]  = false;
            r["errors"] = nlohmann::json::array(
                {std::string("envelopes JSON parse error: ") + e.what()});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "backup-verify: envelopes JSON parse failed: "
                      << e.what() << "\n";
        }
        return 1;
    }

    // ── Validate shares file shape ──────────────────────────────────────
    if (!sj.is_object() || !sj.contains("shares") || !sj["shares"].is_array()) {
        report_fail("shares file: top-level must be object with 'shares' array");
        return 2;
    }
    const auto& shares_arr = sj["shares"];
    if (shares_arr.empty()) {
        report_fail("shares file: 'shares' array is empty");
        return 2;
    }

    auto is_hex_char = [](char c) {
        return (c >= '0' && c <= '9')
            || (c >= 'a' && c <= 'f')
            || (c >= 'A' && c <= 'F');
    };

    std::set<int> share_x;
    int x_min = 256, x_max = -1;
    size_t y_byte_len = 0;
    for (size_t i = 0; i < shares_arr.size(); ++i) {
        const auto& el = shares_arr[i];
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            report_fail("shares file: share #" + std::to_string(i)
                        + " must have integer 'x' and string 'y_hex'");
            return 2;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            report_fail("shares file: share #" + std::to_string(i)
                        + ": x = " + std::to_string(x)
                        + " out of range [1, 255]");
            return 2;
        }
        if (!share_x.insert(x).second) {
            report_fail("shares file: duplicate x = " + std::to_string(x));
            return 2;
        }
        if (x < x_min) x_min = x;
        if (x > x_max) x_max = x;

        std::string y_hex = el["y_hex"].get<std::string>();
        if (y_hex.size() % 2 != 0) {
            report_fail("shares file: share x=" + std::to_string(x)
                        + ": y_hex has odd length");
            return 2;
        }
        for (char c : y_hex) {
            if (!is_hex_char(c)) {
                report_fail("shares file: share x=" + std::to_string(x)
                            + ": y_hex contains non-hex character");
                return 2;
            }
        }
        size_t this_y_len = y_hex.size() / 2;
        if (this_y_len == 0) {
            report_fail("shares file: share x=" + std::to_string(x)
                        + ": y_hex is empty");
            return 2;
        }
        if (y_byte_len == 0) y_byte_len = this_y_len;
        else if (this_y_len != y_byte_len) {
            report_fail("shares file: share x=" + std::to_string(x)
                        + ": y_hex length differs from first share");
            return 2;
        }
    }

    // ── Validate envelopes file shape ───────────────────────────────────
    if (!ej.is_object() || !ej.contains("envelopes") || !ej["envelopes"].is_array()) {
        report_fail("envelopes file: top-level must be object with 'envelopes' array");
        return 2;
    }
    const auto& env_arr = ej["envelopes"];
    if (env_arr.empty()) {
        report_fail("envelopes file: 'envelopes' array is empty");
        return 2;
    }

    // Parse each envelope entry; collect per-entry diagnostics for the
    // envelope_details JSON output.
    struct EnvDetail {
        int      share_index{0};
        uint32_t pbkdf2_iters{0};
        size_t   salt_len{0};
        size_t   nonce_len{0};
        size_t   aad_len{0};
        size_t   ct_len{0};
        bool     ok{false};
    };
    std::vector<EnvDetail> details;
    std::set<int> env_idx;
    for (size_t i = 0; i < env_arr.size(); ++i) {
        const auto& el = env_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("envelope_blob")
            || !el["envelope_blob"].is_string()) {
            report_fail("envelopes file: entry #" + std::to_string(i)
                        + " must have integer 'share_index' and string 'envelope_blob'");
            return 2;
        }
        int idx = el["share_index"].get<int>();
        if (idx < 1 || idx > 255) {
            report_fail("envelopes file: entry #" + std::to_string(i)
                        + ": share_index = " + std::to_string(idx)
                        + " out of range [1, 255]");
            return 2;
        }
        if (!env_idx.insert(idx).second) {
            report_fail("envelopes file: duplicate share_index = "
                        + std::to_string(idx));
            return 2;
        }
        std::string blob = el["envelope_blob"].get<std::string>();
        auto env_opt = envelope::deserialize(blob);
        if (!env_opt) {
            report_fail("envelopes file: entry share_index="
                        + std::to_string(idx)
                        + ": envelope_blob deserialize failed "
                        + "(bad magic, truncated, or non-hex content)");
            return 2;
        }
        const auto& env = *env_opt;
        // Per-envelope structural sanity checks. envelope::deserialize
        // already enforces salt >= 8B, nonce == 12B, ciphertext >= 16B,
        // but recheck here so the JSON output reports the actual values
        // and a future deserialize-relaxation doesn't silently bypass.
        if (env.pbkdf2_iters == 0) {
            report_fail("envelopes file: entry share_index="
                        + std::to_string(idx) + ": pbkdf2_iters is zero");
            return 2;
        }
        if (env.salt.empty()) {
            report_fail("envelopes file: entry share_index="
                        + std::to_string(idx) + ": salt is empty");
            return 2;
        }
        if (env.nonce.size() != 12) {
            report_fail("envelopes file: entry share_index="
                        + std::to_string(idx) + ": nonce is not 12 bytes");
            return 2;
        }
        if (env.ciphertext.size() < 16) {
            report_fail("envelopes file: entry share_index="
                        + std::to_string(idx)
                        + ": ciphertext too short to contain GCM tag");
            return 2;
        }
        details.push_back({idx, env.pbkdf2_iters,
                            env.salt.size(), env.nonce.size(),
                            env.aad.size(),  env.ciphertext.size(),
                            true});
    }

    // ── Cross-file consistency: counts + 1:1 index mapping ──────────────
    const int share_count    = static_cast<int>(shares_arr.size());
    const int envelope_count = static_cast<int>(env_arr.size());
    bool mapping_consistent = true;
    if (share_count != envelope_count) {
        report_fail("share count (" + std::to_string(share_count)
                    + ") != envelope count (" + std::to_string(envelope_count) + ")");
        return 2;
    }
    if (share_x != env_idx) {
        mapping_consistent = false;
        report_fail("share x-values do not match envelope share_index values 1:1 "
                    "(some shares lack an envelope, or vice versa)");
        return 2;
    }

    // Threshold tri-state: nullopt = not supplied, true = met,
    // false = supplied but insufficient. Insufficient is INFORMATIONAL
    // (exit 0), matching shamir-verify convention.
    std::optional<bool> threshold_satisfied;
    if (threshold >= 0) threshold_satisfied = (share_count >= threshold);

    // ── Emit result ─────────────────────────────────────────────────────
    if (json_out) {
        nlohmann::json r;
        r["valid"]              = true;
        r["shares_file"]        = shares_path;
        r["envelopes_file"]     = envelopes_path;
        r["share_count"]        = share_count;
        r["envelope_count"]     = envelope_count;
        r["mapping_consistent"] = mapping_consistent;
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& d : details) {
            arr.push_back({
                {"share_index",  d.share_index},
                {"pbkdf2_iters", d.pbkdf2_iters},
                {"salt_len",     d.salt_len},
                {"nonce_len",    d.nonce_len},
                {"aad_len",      d.aad_len},
                {"ciphertext_len", d.ct_len},
            });
        }
        r["envelope_details"] = std::move(arr);
        if (threshold_satisfied.has_value()) {
            r["threshold_satisfied"] = *threshold_satisfied;
        } else {
            r["threshold_satisfied"] = nullptr;
        }
        r["errors"] = nlohmann::json::array();
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "=== Wallet backup verification ===\n";
        std::cout << "Shares file:    " << shares_path
                  << " (" << share_count << " shares, x range "
                  << x_min << ".." << x_max << ")\n";
        std::cout << "Envelopes file: " << envelopes_path
                  << " (" << envelope_count << " envelopes)\n";
        std::cout << "Share-to-envelope mapping: [OK] 1:1 by share_index\n";
        std::cout << "Envelope structural integrity:\n";
        for (const auto& d : details) {
            std::cout << "  Envelope " << d.share_index
                      << ": PBKDF2=" << d.pbkdf2_iters
                      << ", salt="   << d.salt_len  << "B"
                      << ", nonce="  << d.nonce_len << "B"
                      << ", ct="     << d.ct_len    << "B [OK]\n";
        }
        std::cout << "[OK] Backup structurally valid ("
                  << envelope_count << " envelopes, threshold-ready)\n";
        if (threshold_satisfied.has_value()) {
            if (*threshold_satisfied) {
                std::cout << "[OK] Share count (" << share_count
                          << ") >= threshold (" << threshold
                          << ") -- sufficient for recovery\n";
            } else {
                std::cout << "[INFO] Share count (" << share_count
                          << ") < threshold (" << threshold
                          << ") -- insufficient for recovery\n";
            }
        }
    }
    return 0;
}

int cmd_create_recovery(int argc, char** argv) {
    std::string seed_hex, password, out_path, scheme = "passphrase";
    int threshold = 0, share_count = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--seed"     && i + 1 < argc) seed_hex    = argv[++i];
        else if (a == "--password" && i + 1 < argc) password    = argv[++i];
        else if (a == "--out"      && i + 1 < argc) out_path    = argv[++i];
        else if (a == "--scheme"   && i + 1 < argc) scheme      = argv[++i];
        else if (a == "-t"         && i + 1 < argc) threshold   = std::stoi(argv[++i]);
        else if (a == "-n"         && i + 1 < argc) share_count = std::stoi(argv[++i]);
    }
    if (seed_hex.empty() || password.empty() || out_path.empty()
        || threshold <= 0 || share_count <= 0) {
        std::cerr << "Usage: determ-wallet create-recovery "
                     "--seed <hex> --password <str> -t T -n N --out <file> "
                     "[--scheme {passphrase|opaque}]\n";
        return 1;
    }
    if (scheme != "passphrase" && scheme != "opaque") {
        std::cerr << "--scheme must be 'passphrase' or 'opaque'\n"; return 1;
    }
    std::vector<uint8_t> seed;
    try { seed = from_hex(seed_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid --seed hex: " << e.what() << "\n"; return 1;
    }
    if (seed.empty()) {
        std::cerr << "--seed must be non-empty\n"; return 1;
    }
    auto checksum = recovery::seed_pubkey_checksum(seed);   // empty if seed != 32B
    try {
        auto setup = (scheme == "opaque")
            ? recovery::create_opaque(seed, password,
                                        static_cast<uint8_t>(threshold),
                                        static_cast<uint8_t>(share_count),
                                        checksum)
            : recovery::create       (seed, password,
                                        static_cast<uint8_t>(threshold),
                                        static_cast<uint8_t>(share_count),
                                        checksum);
        std::ofstream f(out_path);
        if (!f) { std::cerr << "Cannot open --out for write: " << out_path << "\n"; return 1; }
        f << recovery::to_json(setup);
        std::cout << "wrote " << out_path << "\n";
        std::cout << "  scheme:        " << setup.scheme       << "\n";
        std::cout << "  threshold:     " << int(setup.threshold)   << " of "
                  << int(setup.share_count) << "\n";
        std::cout << "  secret bytes:  " << setup.secret_len   << "\n";
        std::cout << "  checksum:      " << to_hex(checksum)   << "\n";
    } catch (std::exception& e) {
        std::cerr << "create-recovery error: " << e.what() << "\n"; return 1;
    }
    return 0;
}

int cmd_recover(int argc, char** argv) {
    std::string in_path, password, guardians_csv;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"        && i + 1 < argc) in_path        = argv[++i];
        else if (a == "--password"  && i + 1 < argc) password       = argv[++i];
        else if (a == "--guardians" && i + 1 < argc) guardians_csv  = argv[++i];
    }
    if (in_path.empty() || password.empty()) {
        std::cerr << "Usage: determ-wallet recover --in <file> --password <str> "
                     "[--guardians <csv of 0..N-1 indices>]\n";
        return 1;
    }
    std::ifstream f(in_path);
    if (!f) { std::cerr << "Cannot open --in: " << in_path << "\n"; return 1; }
    std::string blob((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    auto setup_opt = recovery::from_json(blob);
    if (!setup_opt) {
        std::cerr << "recover: failed to parse recovery setup\n"; return 1;
    }
    std::vector<uint8_t> guardian_indices;
    if (guardians_csv.empty()) {
        for (uint8_t i = 0; i < setup_opt->share_count; ++i)
            guardian_indices.push_back(i);
    } else {
        std::stringstream ss(guardians_csv);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (item.empty()) continue;
            guardian_indices.push_back(static_cast<uint8_t>(std::stoul(item)));
        }
    }
    auto secret = recovery::recover(*setup_opt, password, guardian_indices);
    if (!secret) {
        std::cerr << "recover: reconstruction failed "
                     "(wrong password, insufficient envelopes decrypted, "
                     "or pubkey checksum mismatch)\n";
        return 2;
    }
    std::cout << to_hex(*secret) << "\n";
    return 0;
}

// A2 Phase 4: smoke test for the libsodium primitives that libopaque
// (Phase 5) will compose. Verifies the FetchContent integration is
// wired correctly + the OPRF math works deterministically.
int cmd_oprf_smoke(int argc, char** argv) {
    (void)argc; (void)argv;
    if (!primitives::init_libsodium()) {
        std::cerr << "init_libsodium failed\n"; return 1;
    }
    // 1. Generate two random ristretto255 scalars (the user's blind r
    //    and the simulated server's key k).
    auto r = primitives::ristretto255_scalar_random();
    auto k = primitives::ristretto255_scalar_random();
    if (r.size() != 32 || k.size() != 32) {
        std::cerr << "scalar_random returned wrong size\n"; return 1;
    }
    // 2. Blind a password into a point (mock client-side OPRF step).
    std::vector<uint8_t> password = {'h','u','n','t','e','r','2'};
    auto blinded = primitives::ristretto255_point_blind(password, r);
    if (blinded.size() != 32) {
        std::cerr << "point_blind failed\n"; return 1;
    }
    // 3. Argon2id stretch (mock OPAQUE password stretching). Uses
    //    libsodium-required 16-byte salt and minimum opslimit for
    //    quick smoke testing.
    auto salt = primitives::random_bytes(16);
    auto stretched = primitives::argon2id(password, salt, 32, 1, 8 * 1024 * 1024);
    if (stretched.size() != 32) {
        std::cerr << "argon2id failed\n"; return 1;
    }
    std::cout << "scalar_r  (32B):  " << to_hex(r) << "\n";
    std::cout << "scalar_k  (32B):  " << to_hex(k) << "\n";
    std::cout << "blinded   (32B):  " << to_hex(blinded) << "\n";
    std::cout << "argon2id  (32B):  " << to_hex(stretched) << "\n";
    std::cout << "libsodium primitives OK\n";
    return 0;
}

// A2 Phase 5: exercise the OPAQUE adapter directly. Used by the
// regression test to confirm the adapter's register/authenticate
// round-trip works and that wrong passwords are rejected.
int cmd_opaque_handshake(int argc, char** argv) {
    std::string mode, password, record_hex;
    int guardian_id = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--mode"        && i + 1 < argc) mode        = argv[++i];
        else if (a == "--password"    && i + 1 < argc) password    = argv[++i];
        else if (a == "--guardian-id" && i + 1 < argc) guardian_id = std::stoi(argv[++i]);
        else if (a == "--record"      && i + 1 < argc) record_hex  = argv[++i];
    }
    if (mode.empty() || password.empty() || guardian_id < 0 || guardian_id > 255) {
        std::cerr << "Usage: determ-wallet opaque-handshake "
                     "--mode {register|authenticate} --password <str> "
                     "--guardian-id <0..255> [--record <hex>]\n";
        return 1;
    }
    if (mode == "register") {
        auto r = opaque_adapter::register_password(password,
                       static_cast<uint8_t>(guardian_id));
        if (!r) { std::cerr << "register failed\n"; return 1; }
        std::cout << "suite:      " << opaque_adapter::suite_name() << "\n";
        std::cout << "is_stub:    " << (opaque_adapter::is_stub() ? "true" : "false") << "\n";
        std::cout << "record:     " << to_hex(r->record)     << "\n";
        std::cout << "export_key: " << to_hex(r->export_key) << "\n";
        return 0;
    }
    if (mode == "authenticate") {
        if (record_hex.empty()) {
            std::cerr << "authenticate requires --record\n"; return 1;
        }
        std::vector<uint8_t> record;
        try { record = from_hex(record_hex); }
        catch (std::exception& e) {
            std::cerr << "record hex: " << e.what() << "\n"; return 1;
        }
        auto k = opaque_adapter::authenticate_password(password, record,
                       static_cast<uint8_t>(guardian_id));
        if (!k) { std::cerr << "authenticate failed\n"; return 2; }
        std::cout << "export_key: " << to_hex(*k) << "\n";
        return 0;
    }
    std::cerr << "Unknown --mode: " << mode << "\n";
    return 1;
}

void print_usage() {
    std::cerr <<
        "Usage: determ-wallet <command> ...\n"
        "\n"
        "Commands:\n"
        "  shamir split <hex> -t <T> -n <N>           Split secret into N shares\n"
        "  shamir combine <share> ...                 Reconstruct secret from >=T shares\n"
        "  shamir-split --secret <hex> --threshold T --shares N [--json]\n"
        "                                             Raw-primitive split (JSON-first output)\n"
        "  shamir-combine --shares <file> [--json]    Raw-primitive combine from JSON share file\n"
        "  shamir-verify --shares <file> [--threshold T] [--json]\n"
        "                                             Structural verification of a share-set\n"
        "                                             (no reconstruction; no secret material)\n"
        "  envelope encrypt --plaintext <hex>         AEAD-wrap a share or seed\n"
        "                    --password <str> [--aad <hex>] [--iters <N>]\n"
        "  envelope decrypt --envelope <blob>         Unwrap an envelope\n"
        "                    --password <str> [--aad <hex>]\n"
        "  inspect-envelope --in <file> [--json]      Dump envelope header metadata\n"
        "                                             (no decryption, no password)\n"
        "  account-create-batch --count N             Batch-generate N anonymous account\n"
        "                       [--out <file>] [--json] [--force]\n"
        "                                             keypairs (Ed25519 -> anon-address).\n"
        "                                             Default human output; --out writes a\n"
        "                                             JSON file (refuses overwrite without\n"
        "                                             --force); --json prints JSON to stdout\n"
        "                                             (ignored if --out is set). 1<=N<=10000.\n"
        "  backup-verify --shares <file> --envelopes <file> [--threshold T] [--json]\n"
        "                                             Composite structural verification of a\n"
        "                                             wallet backup (Shamir shares + per-share\n"
        "                                             AEAD envelopes). No decryption, no\n"
        "                                             password required. Shares file shape:\n"
        "                                             {\"shares\": [{\"x\": int, \"y_hex\": \"...\"}, ...]}.\n"
        "                                             Envelopes file shape:\n"
        "                                             {\"envelopes\": [{\"share_index\": int,\n"
        "                                             \"envelope_blob\": \"...\"}, ...]}.\n"
        "  create-recovery --seed <hex> --password <str>  Persist a T-of-N recovery setup\n"
        "                  -t T -n N --out <file>\n"
        "                  [--scheme {passphrase|opaque}]\n"
        "  recover --in <file> --password <str>       Reconstruct the secret\n"
        "          [--guardians <i,j,k,...>]\n"
        "  oprf-smoke                                 Verify libsodium primitives wired\n"
        "  opaque-handshake --mode {register|authenticate}\n"
        "                   --password <str> --guardian-id <0..255> [--record <hex>]\n"
        "                                             Exercise the OPAQUE adapter (stub in Phase 5)\n"
        "  version                                    Print version banner\n"
        "\n"
        "Pending (Phase 4):\n"
        "  OPAQUE per-guardian AKE replaces passphrase-only authentication\n"
        "  for create-recovery / recover (libopaque + libsodium integration).\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { print_usage(); return 1; }
    std::string cmd = argv[1];
    if (cmd == "shamir")          return cmd_shamir         (argc - 2, argv + 2);
    if (cmd == "shamir-split")    return cmd_shamir_split_raw  (argc - 2, argv + 2);
    if (cmd == "shamir-combine")  return cmd_shamir_combine_raw(argc - 2, argv + 2);
    if (cmd == "shamir-verify")   return cmd_shamir_verify   (argc - 2, argv + 2);
    if (cmd == "envelope")        return cmd_envelope       (argc - 2, argv + 2);
    if (cmd == "inspect-envelope") return cmd_inspect_envelope(argc - 2, argv + 2);
    if (cmd == "account-create-batch") return cmd_account_create_batch(argc - 2, argv + 2);
    if (cmd == "backup-verify")   return cmd_backup_verify  (argc - 2, argv + 2);
    if (cmd == "create-recovery") return cmd_create_recovery(argc - 2, argv + 2);
    if (cmd == "recover")         return cmd_recover        (argc - 2, argv + 2);
    if (cmd == "oprf-smoke")      return cmd_oprf_smoke     (argc - 2, argv + 2);
    if (cmd == "opaque-handshake") return cmd_opaque_handshake(argc - 2, argv + 2);
    if (cmd == "version") {
        std::cout << "determ-wallet v1.x Phase 5 (Shamir + AEAD envelope + "
                     "passphrase recovery + libsodium primitives + "
                     "OPAQUE adapter interface [stub]; libopaque vendoring "
                     "pending Phase 6)\n";
        return 0;
    }
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_usage(); return 0;
    }
    std::cerr << "Unknown command: " << cmd << "\n";
    print_usage();
    return 1;
}
