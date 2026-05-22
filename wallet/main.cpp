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
#include <openssl/sha.h>
#include <sodium.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <ctime>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#  include <termios.h>
#endif

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

// ── shamir-rotate — Proactive Secret Sharing (PSS) polynomial refresh ─────
//
// Refresh the Shamir polynomial WITHOUT changing the underlying secret.
// Defense against share leakage over time: a keyholder periodically
// rotates their physical share so accumulated compromise of any prior
// snapshot of < T shares conveys nothing about the current share set.
//
// Mechanism (Herzberg-style "share refresh"):
//   1. Read --shares file (same `{"shares":[{x, y_hex}, ...]}` shape as
//      shamir-split / backup-create output).
//   2. Structurally validate (distinct x in [1,255], consistent y-byte
//      lengths, even-length lowercase hex, non-empty).
//   3. Require length(shares) >= T (insufficient = exit 2 with diagnostic
//      mirroring the shamir-verify convention for under-threshold gates
//      that are NOT structural defects — but for ROTATE the threshold IS
//      a precondition: we must reconstruct to refresh, so insufficient
//      input is a hard failure, not informational).
//   4. Reconstruct the secret via shamir::combine (Lagrange at x=0).
//   5. Run a FRESH shamir::split of the SAME secret with N = max(input.x)
//      and threshold T. shamir::split always emits x = 1..N consecutively;
//      because operators expect "Share-K's holder remains Share-K", we
//      preserve x-coordinates by filtering the freshly-split shares down
//      to the input's x-set. (The discarded shares for x not in the input
//      set are never written anywhere.)
//   6. Verify (belt-and-suspenders): the new shares' combine() recovers
//      the SAME secret as the input. Mismatch is an internal-error exit 1
//      (would indicate a shamir-layer regression — not expected to fire).
//   7. Write the new share-set to --shares-out using the same JSON shape
//      as the input. Refuses overwrite without --force.
//
// Security property: the new shares lie on a DIFFERENT polynomial than
// the input (T-1 fresh random coefficients drawn from OpenSSL RAND_bytes
// inside shamir::split). Combining T old shares yields S; combining T
// new shares yields S; combining a mix of old + new (any T-1 from one,
// 1 from the other) yields garbage indistinguishable from a wrong secret
// (information-theoretic property of SSS over GF(2^8)). That mix-failure
// is what makes "rotate" meaningful: an attacker who held a stale subset
// of < T shares cannot combine them with one new share to recover S.
//
// Exit codes:
//   0  rotated successfully; --shares-out written.
//   1  bad args, file I/O error, JSON parse error, structural malformedness,
//      output already exists without --force.
//   2  insufficient input shares (< T supplied). Diagnostic gate: rotate
//      cannot proceed without crossing the threshold.
//
// What this CLI does NOT do:
//   * Change N or T. The output set has the SAME size and threshold as
//     the input.
//   * Touch envelopes. Only the bare share file is rotated. Operators
//     re-wrap each new share via `backup-create` (or equivalent) under
//     the same per-keyholder passphrases as the prior backup if they
//     want a refreshed envelope artifact.
//   * Change the secret. Rotating a share-set never alters the secret
//     it reconstructs.
int cmd_shamir_rotate(int argc, char** argv) {
    std::string shares_path, shares_out;
    int threshold = -1;
    bool force = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--shares"     && i + 1 < argc) shares_path = argv[++i];
        else if (a == "--threshold"  && i + 1 < argc) {
            try { threshold = std::stoi(argv[++i]); }
            catch (...) {
                std::cerr << "shamir-rotate: --threshold must be an integer\n";
                return 1;
            }
        }
        else if (a == "--shares-out" && i + 1 < argc) shares_out = argv[++i];
        else if (a == "--force")                      force      = true;
        else if (a == "--json")                       json_out   = true;
        else {
            std::cerr << "shamir-rotate: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet shamir-rotate --shares <file> "
                         "--threshold T --shares-out <file> [--force] [--json]\n";
            return 1;
        }
    }
    if (shares_path.empty() || threshold < 0 || shares_out.empty()) {
        std::cerr << "Usage: determ-wallet shamir-rotate --shares <file> "
                     "--threshold T --shares-out <file> [--force] [--json]\n";
        return 1;
    }
    if (threshold < 1) {
        std::cerr << "shamir-rotate: --threshold must be >= 1 (got "
                  << threshold << ")\n";
        return 1;
    }
    if (threshold > 255) {
        std::cerr << "shamir-rotate: --threshold must be <= 255 (got "
                  << threshold << ")\n";
        return 1;
    }
    if (shares_path == shares_out) {
        std::cerr << "shamir-rotate: --shares and --shares-out must not "
                     "point at the same file (cannot rotate in place; "
                     "the read pass and write pass would collide)\n";
        return 1;
    }

    // ── Read + parse input shares file ───────────────────────────────────
    std::ifstream f(shares_path);
    if (!f) {
        std::cerr << "shamir-rotate: cannot open --shares file: "
                  << shares_path << "\n";
        return 1;
    }
    std::string blob((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    nlohmann::json j;
    try { j = nlohmann::json::parse(blob); }
    catch (std::exception& e) {
        std::cerr << "shamir-rotate: JSON parse failed: " << e.what() << "\n";
        return 1;
    }
    if (!j.is_object() || !j.contains("shares") || !j["shares"].is_array()) {
        std::cerr << "shamir-rotate: --shares JSON must be object with "
                     "'shares' array\n";
        return 1;
    }
    const auto& arr = j["shares"];
    if (arr.empty()) {
        std::cerr << "shamir-rotate: --shares array is empty\n"; return 1;
    }

    // Structural validation mirrors shamir-combine + shamir-verify so the
    // rotate CLI never reaches the cryptographic layer with malformed
    // input. Diagnostics are precise so operators can fix shares files
    // before a costly distribution event.
    std::vector<shamir::Share> in_shares;
    std::set<int> seen_x;
    int x_max_in = 0;
    size_t y_len = 0;
    for (size_t i = 0; i < arr.size(); ++i) {
        const auto& el = arr[i];
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            std::cerr << "shamir-rotate: share #" << i
                      << " must have integer 'x' and string 'y_hex'\n";
            return 1;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            std::cerr << "shamir-rotate: x = " << x << " out of range "
                         "[1, 255]\n";
            return 1;
        }
        if (!seen_x.insert(x).second) {
            std::cerr << "shamir-rotate: duplicate x = " << x
                      << " (Shamir invariant: all x must be distinct)\n";
            return 1;
        }
        if (x > x_max_in) x_max_in = x;
        std::string y_hex = el["y_hex"].get<std::string>();
        if (y_hex.size() % 2 != 0) {
            std::cerr << "shamir-rotate: y_hex for x=" << x
                      << " has odd length\n";
            return 1;
        }
        shamir::Share s;
        s.x = static_cast<uint8_t>(x);
        try { s.y = from_hex(y_hex); }
        catch (std::exception& e) {
            std::cerr << "shamir-rotate: y_hex parse failed for x=" << x
                      << ": " << e.what() << "\n";
            return 1;
        }
        if (s.y.empty()) {
            std::cerr << "shamir-rotate: y_hex empty for x=" << x << "\n";
            return 1;
        }
        if (y_len == 0) y_len = s.y.size();
        else if (s.y.size() != y_len) {
            std::cerr << "shamir-rotate: share x=" << x
                      << " y-length " << s.y.size()
                      << " differs from first share's " << y_len << "\n";
            return 1;
        }
        in_shares.push_back(std::move(s));
    }

    const int n_in = static_cast<int>(in_shares.size());

    // ── Threshold precondition: rotation requires reconstruction ─────────
    // Unlike shamir-verify (where under-threshold is informational), here
    // we MUST cross the threshold to recover the secret. Exit 2 is the
    // operator-alert gate documented in the header.
    if (n_in < threshold) {
        std::cerr << "shamir-rotate: insufficient input shares ("
                  << n_in << " supplied, --threshold " << threshold
                  << " required for reconstruction); rotation cannot "
                     "proceed\n";
        return 2;
    }

    // ── Reconstruct the secret via existing combine ──────────────────────
    auto secret_opt = shamir::combine(in_shares);
    if (!secret_opt) {
        // shamir::combine rejects on (duplicate x | mismatched y sizes |
        // empty) — all of which the structural pass above already filters.
        // Reaching here implies a deeper inconsistency; surface verbatim.
        std::cerr << "shamir-rotate: secret reconstruction failed at the "
                     "shamir layer (shares structurally valid but mutually "
                     "inconsistent — corrupt y values?)\n";
        return 1;
    }
    const std::vector<uint8_t>& secret = *secret_opt;

    // ── Fresh split preserving input x-coordinates ───────────────────────
    // shamir::split assigns x = 1..N consecutively. To preserve arbitrary
    // input x-coordinates (operators expect "Share-K's holder stays
    // Share-K"), split with N = max(input.x) and then filter down to the
    // input x-set. The freshly-drawn polynomial is the same for all x
    // (shamir::split builds ONE polynomial per secret byte using fresh
    // T-1 random coefficients), so the kept shares are mathematically
    // equivalent to those that would have been emitted by a hypothetical
    // split-at-arbitrary-x routine.
    std::vector<shamir::Share> all_new;
    try {
        all_new = shamir::split(secret,
                                  static_cast<uint8_t>(threshold),
                                  static_cast<uint8_t>(x_max_in));
    } catch (std::exception& e) {
        std::cerr << "shamir-rotate: shamir::split failed: " << e.what() << "\n";
        return 1;
    }

    // Filter all_new down to input x-set, preserving the input order so
    // the output JSON layout matches the input layout 1:1.
    std::vector<shamir::Share> new_shares;
    new_shares.reserve(n_in);
    for (const auto& src : in_shares) {
        bool found = false;
        for (const auto& cand : all_new) {
            if (cand.x == src.x) {
                new_shares.push_back(cand);
                found = true;
                break;
            }
        }
        if (!found) {
            // shamir::split always emits x = 1..x_max_in, and every input
            // x is in [1, x_max_in] by construction, so this branch is
            // unreachable. Guard anyway — internal-error gate.
            std::cerr << "shamir-rotate: internal: x=" << static_cast<int>(src.x)
                      << " not present in fresh split output\n";
            return 1;
        }
    }

    // ── Verification round-trip ──────────────────────────────────────────
    // Belt-and-suspenders check: the new share-set must reconstruct the
    // SAME secret as the input. A mismatch would indicate a shamir-layer
    // regression (shouldn't fire); treat as internal-error exit 1.
    auto verify_opt = shamir::combine(new_shares);
    if (!verify_opt) {
        std::cerr << "shamir-rotate: internal: fresh share-set failed to "
                     "combine (shamir layer rejected its own output)\n";
        return 1;
    }
    if (*verify_opt != secret) {
        std::cerr << "shamir-rotate: internal: fresh share-set combines to "
                     "a different secret (shamir layer regression)\n";
        return 1;
    }

    // ── Output overwrite gate ────────────────────────────────────────────
    if (std::filesystem::exists(shares_out) && !force) {
        std::cerr << "shamir-rotate: --shares-out file already exists: "
                  << shares_out
                  << " (use --force to overwrite; refusing by default to "
                     "avoid destroying a prior rotated share-set)\n";
        return 1;
    }

    // ── Write the new share-set ──────────────────────────────────────────
    nlohmann::json out_doc;
    out_doc["shares"] = nlohmann::json::array();
    for (const auto& s : new_shares) {
        out_doc["shares"].push_back({
            {"x",     static_cast<int>(s.x)},
            {"y_hex", to_hex(s.y)},
        });
    }
    {
        std::ofstream of(shares_out);
        if (!of) {
            std::cerr << "shamir-rotate: cannot open --shares-out for write: "
                      << shares_out << "\n";
            return 1;
        }
        of << out_doc.dump() << "\n";
        if (!of) {
            std::cerr << "shamir-rotate: write failed on --shares-out: "
                      << shares_out << "\n";
            return 1;
        }
    }
    // Owner-only perms (POSIX); no-op on Windows.
    {
        std::error_code perm_ec;
        std::filesystem::permissions(
            shares_out,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
    }

    // ── Summary ──────────────────────────────────────────────────────────
    if (json_out) {
        nlohmann::json r;
        r["share_count"]   = n_in;
        r["threshold"]     = threshold;
        r["secret_bytes"]  = secret.size();
        r["shares_file"]   = shares_out;
        r["rotated"]       = true;
        // NEVER emit secret material in the summary. The whole point of
        // rotation is to refresh the polynomial without exposing the
        // secret; leaking it here would defeat the purpose.
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "=== shamir-rotate (PSS polynomial refresh) ===\n";
        std::cout << "Input shares:    " << n_in << " (>= threshold "
                  << threshold << ")\n";
        std::cout << "Secret bytes:    " << secret.size()
                  << " (reconstructed and verified)\n";
        std::cout << "Output shares:   " << n_in
                  << " (same N, same x-coordinates, fresh polynomial)\n";
        std::cout << "Written to:      " << shares_out << "\n";
        std::cout << "[OK] Polynomial refreshed; secret invariant.\n";
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

// ── account-derive-batch — deterministic batch derivation from a master seed ─
//
// Sibling of `account-create-batch`. Where account-create-batch generates N
// keypairs from fresh CSPRNG draws (so back-to-back invocations produce
// disjoint sets), account-derive-batch derives N keypairs from a single
// 32-byte master seed using SHA-256 domain separation. The same master
// seed ALWAYS produces the same N accounts; different seeds always produce
// disjoint sets (with cryptographic probability).
//
// Algorithm (SLIP-0010-style hardened-only derivation, flat array — no
// hierarchical paths):
//
//     for i in 0..N-1:
//         seed_i      = SHA-256(master_seed || u32_le(i))
//         keypair_i   = crypto_sign_ed25519_seed_keypair(seed_i)
//         address_i   = "0x" + lowercase hex(pubkey_i)
//
// The little-endian u32 width (NOT a variable-length encoding) keeps the
// pre-image deterministic across platforms. Caller's master seed enters
// the SHA-256 as a domain separator: an adversary who learns seed_i for
// some i still cannot derive seed_j for j != i (SHA-256 one-wayness),
// and cannot derive the master seed itself.
//
// Operator use cases:
//   1. Cold-wallet provisioning from a single backed-up seed. The operator
//      stores ONE 32-byte secret offline; on-demand they derive N receive
//      addresses, fund them, and never need to back up the per-account
//      private keys. Recovery only requires the master seed.
//   2. Test-fixture generation. CI pipelines pin a fixed master seed and
//      get reproducible account sets across machines and runs.
//   3. Recovery scenarios. If individual per-account privkeys are lost,
//      the entire set is recoverable from the master seed alone.
//
// CLI:
//   --seed <hex>:  REQUIRED. Exactly 64 hex chars (32 bytes).
//   --count N:     REQUIRED. 1 <= N <= 10000 (same cap as
//                  account-create-batch — operator safety net).
//   --out <file>:  optional. Writes JSON to file with 0600 perms (refuses
//                  overwrite without --force).
//   --json:        prints the same JSON to stdout (ignored if --out is set).
//   --force:       overwrite an existing --out.
//
// Output JSON shape (--out / --json):
//   {
//     "master_seed_hash_hex": "<64-hex SHA-256 of the master seed>",
//     "count":                N,
//     "accounts": [
//       {"index": 0, "address": "0x...", "privkey_hex": "..."},
//       ...
//     ]
//   }
//
// The `master_seed_hash_hex` field lets the operator verify (out-of-band)
// that a derivation run matches an expected master seed WITHOUT exposing
// the seed itself in the output file. This is the SHA-256 of the raw seed
// bytes (NOT a derived sub-seed). Knowledge of this hash alone reveals no
// information about the master seed beyond what a brute-force preimage
// search would require.
//
// Default human format (no --out, no --json) mirrors account-create-batch:
//     account[i]: address=0x... privkey_hex=...
// One line per account, deterministic order (i = 0..N-1).
//
// Exit codes:
//   0 = success
//   1 = argument / validation / I/O error
int cmd_account_derive_batch(int argc, char** argv) {
    std::string seed_hex;
    int count = 0;
    std::string out_path;
    bool json_out = false;
    bool force    = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--seed"  && i + 1 < argc) seed_hex = argv[++i];
        else if (a == "--count" && i + 1 < argc) {
            try { count = std::stoi(argv[++i]); }
            catch (std::exception&) {
                std::cerr << "account-derive-batch: --count must be an integer\n";
                return 1;
            }
        }
        else if (a == "--out"   && i + 1 < argc) out_path = argv[++i];
        else if (a == "--json")                  json_out = true;
        else if (a == "--force")                 force    = true;
        else {
            std::cerr << "account-derive-batch: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-derive-batch --seed <hex> "
                         "--count N [--out <file>] [--json] [--force]\n";
            return 1;
        }
    }

    // ── Validate --seed (exactly 64 hex chars = 32 bytes) ───────────────────
    if (seed_hex.empty()) {
        std::cerr << "account-derive-batch: --seed is required (32-byte master "
                     "seed = exactly 64 hex chars)\n";
        std::cerr << "Usage: determ-wallet account-derive-batch --seed <hex> "
                     "--count N [--out <file>] [--json] [--force]\n";
        return 1;
    }
    if (seed_hex.size() != 64) {
        std::cerr << "account-derive-batch: --seed must be exactly 64 hex chars "
                     "(32-byte master seed); got " << seed_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> seed_bytes;
    try { seed_bytes = from_hex(seed_hex); }
    catch (std::exception& e) {
        std::cerr << "account-derive-batch: invalid --seed hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (seed_bytes.size() != 32) {
        // Belt-and-suspenders; the 64-char check above already covered it.
        std::cerr << "account-derive-batch: --seed decoded length must be 32; "
                     "got " << seed_bytes.size() << "\n";
        return 1;
    }

    // ── Validate --count ────────────────────────────────────────────────────
    if (count <= 0) {
        std::cerr << "account-derive-batch: --count must be >= 1 (got "
                  << count << ")\n";
        return 1;
    }
    constexpr int MAX_COUNT = 10000;
    if (count > MAX_COUNT) {
        std::cerr << "account-derive-batch: --count must be <= " << MAX_COUNT
                  << " (got " << count << "). If you genuinely need more, "
                     "invoke the command multiple times and concatenate; "
                     "the cap is an operator safety net against fat-finger "
                     "automation errors.\n";
        return 1;
    }

    // ── --out preconditions checked BEFORE derivation ───────────────────────
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "account-derive-batch: --out parent directory does "
                         "not exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "account-derive-batch: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Init libsodium for the Ed25519 seed-keypair primitive ───────────────
    if (!primitives::init_libsodium()) {
        std::cerr << "account-derive-batch: libsodium init failed\n";
        return 1;
    }
    static_assert(crypto_sign_PUBLICKEYBYTES == 32, "Ed25519 pk size mismatch");
    static_assert(crypto_sign_SECRETKEYBYTES == 64, "Ed25519 sk size mismatch");
    static_assert(crypto_sign_SEEDBYTES      == 32, "Ed25519 seed size mismatch");

    // ── Compute master_seed_hash for output (does NOT leak the seed) ────────
    std::array<uint8_t, 32> master_hash{};
    SHA256(seed_bytes.data(), seed_bytes.size(), master_hash.data());

    // ── Derive accounts deterministically ───────────────────────────────────
    // seed_i = SHA-256(master_seed || u32_le(i))
    //
    // The u32_le encoding is fixed-width (4 bytes) and platform-independent
    // — this is what makes the derivation reproducible across machines.
    // A variable-width encoding (e.g. varint) could shift collision domains
    // between caller environments.
    nlohmann::json arr = nlohmann::json::array();
    for (int i = 0; i < count; ++i) {
        // Build preimage: master_seed (32 B) || u32_le(i) (4 B) = 36 B.
        std::array<uint8_t, 36> preimage{};
        std::memcpy(preimage.data(), seed_bytes.data(), 32);
        uint32_t idx = static_cast<uint32_t>(i);
        preimage[32] = static_cast<uint8_t>((idx >>  0) & 0xff);
        preimage[33] = static_cast<uint8_t>((idx >>  8) & 0xff);
        preimage[34] = static_cast<uint8_t>((idx >> 16) & 0xff);
        preimage[35] = static_cast<uint8_t>((idx >> 24) & 0xff);

        std::array<uint8_t, 32> sub_seed{};
        SHA256(preimage.data(), preimage.size(), sub_seed.data());

        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pub{};
        std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
        if (crypto_sign_ed25519_seed_keypair(pub.data(), sk.data(),
                                             sub_seed.data()) != 0) {
            // SHA-256 outputs are uniformly distributed over a 256-bit
            // range; the probability that a single output happens to be
            // rejected by ed25519 keygen is effectively zero. If we ever
            // hit this, the OS RNG / SHA-256 / libsodium are mis-wired.
            sodium_memzero(sub_seed.data(), sub_seed.size());
            sodium_memzero(sk.data(),       sk.size());
            std::cerr << "account-derive-batch: crypto_sign_ed25519_seed_"
                         "keypair failed at index " << i
                      << " (this is essentially impossible for SHA-256-"
                         "uniform input — investigate the build)\n";
            return 1;
        }
        // Per-account secret material lives in two places now: sub_seed
        // and the leading 32 B of sk. Zero the libsodium sk; serialize
        // the sub_seed as the privkey_hex (the canonical wallet-format
        // 32-byte seed, matching account-create-batch).
        sodium_memzero(sk.data(), sk.size());

        std::string address = "0x" + to_hex(pub);
        std::string privkey_hex = to_hex(sub_seed);
        arr.push_back({
            {"index",       i},
            {"address",     address},
            {"privkey_hex", privkey_hex},
        });
        sodium_memzero(sub_seed.data(), sub_seed.size());
    }

    // ── Build the output JSON document ──────────────────────────────────────
    nlohmann::json doc;
    doc["master_seed_hash_hex"] = to_hex(master_hash);
    doc["count"]                = count;
    doc["accounts"]             = std::move(arr);

    // ── Zero the master seed bytes now that derivation is done ─────────────
    // doc still holds the per-account privkey_hex strings (which is the
    // intended output); only the original master seed is wiped here.
    sodium_memzero(seed_bytes.data(), seed_bytes.size());

    // ── Dispatch on output mode ─────────────────────────────────────────────
    if (!out_path.empty()) {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "account-derive-batch: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << doc.dump(2) << "\n";
        f.close();
        // 0600 owner-only perms. On Windows the call is a no-op for the
        // read/write bits (NTFS ACL inherits from parent); non-fatal.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        std::cout << "derived " << count << " accounts to " << out_path << "\n";
        return 0;
    }
    if (json_out) {
        std::cout << doc.dump(2) << "\n";
        return 0;
    }
    // Default human format — one line per account.
    // Matches the task spec verbatim: "account[i]: address=0x... privkey_hex=..."
    for (int i = 0; i < count; ++i) {
        std::cout << "account[" << i << "]: address="
                  << doc["accounts"][i]["address"].get<std::string>()
                  << " privkey_hex="
                  << doc["accounts"][i]["privkey_hex"].get<std::string>()
                  << "\n";
    }
    return 0;
}

// ── account-import — import an existing Ed25519 privkey as a wallet account ─
//
// Companion to `account-create-batch`. Where account-create-batch generates
// fresh CSPRNG-drawn material, account-import accepts a pre-existing private
// key supplied by the operator and converts it to the wallet's anon-account
// JSON shape. Typical use cases:
//
//   1. Shamir recovery — operator runs `shamir-combine` to reconstruct a
//      32-byte seed, then pipes the hex into account-import to materialize
//      the wallet-format JSON file the daemon and tooling consume.
//   2. Cross-wallet migration — any external Ed25519-compatible wallet that
//      can export a 32-byte seed (or 64-byte seed||pubkey concatenation) can
//      be transplanted into Determ's anon-account format with a single call.
//   3. Test-fixture creation — supplying a deterministic seed lets test
//      suites pin reproducible addresses without bringing the CSPRNG into
//      the test's trusted boundary.
//
// CLI:
//   --priv <hex>: 64 hex chars (32-byte seed) OR 128 hex chars (seed || pub).
//                 The 64-byte form is supported for symmetry with external
//                 wallets that export the libsodium-shaped secret key
//                 (seed concatenated with the derived pubkey). When 64 bytes
//                 are supplied, we verify that the seed-derived pubkey
//                 matches the supplied tail-32 bytes; mismatch is rejected
//                 because it almost always means the operator concatenated
//                 the wrong pubkey or hit a transcription error.
//   --out <file>: optional. If set, writes a single-account JSON file with
//                 0600 permissions (best-effort on Windows; NTFS ACL).
//                 Refuses overwrite without --force. Parent dir must exist.
//   --force:      required to overwrite an existing --out.
//   --json:       prints {"address":..., "privkey_hex":...} to stdout
//                 instead of the human-readable two-line format. Ignored
//                 if --out is also set.
//
// Output JSON shape (matches a single element of account-create-batch's array):
//   { "address": "0x<64-hex-of-pubkey>", "privkey_hex": "<64-hex-of-seed>" }
//
// Exit codes:
//   0 = success
//   1 = argument / validation / I/O error (including mismatched 64-byte form)
int cmd_account_import(int argc, char** argv) {
    std::string priv_hex, out_path;
    bool force    = false;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv"  && i + 1 < argc) priv_hex = argv[++i];
        else if (a == "--out"   && i + 1 < argc) out_path = argv[++i];
        else if (a == "--force")                 force    = true;
        else if (a == "--json")                  json_out = true;
        else {
            std::cerr << "account-import: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-import --priv <hex> "
                         "[--out <file>] [--force] [--json]\n";
            return 1;
        }
    }
    if (priv_hex.empty()) {
        std::cerr << "account-import: --priv is required (32-byte seed = 64 "
                     "hex chars, or 64-byte keypair = 128 hex chars)\n";
        std::cerr << "Usage: determ-wallet account-import --priv <hex> "
                     "[--out <file>] [--force] [--json]\n";
        return 1;
    }

    // ── Validate --priv length (must be 32 B seed or 64 B keypair) ──────────
    // Same convention as keyfile-create. Surfacing this before from_hex
    // gives a more actionable error message than "odd length" on, say,
    // a 65-char paste.
    if (priv_hex.size() != 64 && priv_hex.size() != 128) {
        std::cerr << "account-import: --priv must be 64 hex chars (32-byte "
                     "seed) or 128 hex chars (32-byte seed || 32-byte pubkey); "
                     "got " << priv_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> priv_bytes;
    try { priv_bytes = from_hex(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "account-import: invalid --priv hex: " << e.what() << "\n";
        return 1;
    }
    if (priv_bytes.size() != 32 && priv_bytes.size() != 64) {
        // Belt-and-suspenders; the size check above already covered this.
        std::cerr << "account-import: --priv decoded length must be 32 or 64; "
                     "got " << priv_bytes.size() << "\n";
        return 1;
    }

    // ── --out preconditions checked BEFORE keygen ───────────────────────────
    // Surfacing parent-dir-missing / file-exists errors before the
    // libsodium call means we don't burn cycles on derivation only to
    // discard the result. (For account-import this is cheap, but it
    // matches the account-create-batch ergonomics — fail fast on the
    // operator's I/O misconfig.)
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "account-import: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "account-import: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Init libsodium + derive keypair from seed ───────────────────────────
    // Task spec: use crypto_sign_ed25519_seed_keypair. This is functionally
    // equivalent to crypto_sign_seed_keypair (both produce the same Ed25519
    // pub/sk from a 32-byte seed) but the _ed25519_ form is the explicit
    // alias for cases where the caller wants to be unambiguous about the
    // curve. Using the same primitive that message-sign uses keeps the
    // wallet's secret-handling surface uniform on libsodium.
    if (!primitives::init_libsodium()) {
        std::cerr << "account-import: libsodium init failed\n";
        return 1;
    }
    std::array<uint8_t, 32> seed{};
    std::memcpy(seed.data(), priv_bytes.data(), 32);
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> derived_pub{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    static_assert(crypto_sign_PUBLICKEYBYTES == 32, "Ed25519 pk size mismatch");
    static_assert(crypto_sign_SECRETKEYBYTES == 64, "Ed25519 sk size mismatch");
    static_assert(crypto_sign_SEEDBYTES      == 32, "Ed25519 seed size mismatch");
    if (crypto_sign_ed25519_seed_keypair(derived_pub.data(), sk.data(),
                                         seed.data()) != 0) {
        std::cerr << "account-import: crypto_sign_ed25519_seed_keypair failed "
                     "(seed not a valid Ed25519 private key)\n";
        return 1;
    }
    // Zero the libsodium-derived 64-byte sk — it contains seed||pubkey, both
    // of which already live in `seed` / `derived_pub`, so the duplicate is
    // unnecessary post-derivation. seed itself stays live for the JSON emit.
    sodium_memzero(sk.data(), sk.size());

    // ── 64-byte-form pubkey mismatch check (defense-in-depth) ───────────────
    // Same logic as keyfile-create: if the operator pasted a 64-byte form,
    // the trailing 32 bytes MUST match the seed-derived pubkey. A mismatch
    // is almost always a transcription error or a mixed-up keypair.
    if (priv_bytes.size() == 64) {
        std::array<uint8_t, 32> supplied_pub{};
        std::memcpy(supplied_pub.data(), priv_bytes.data() + 32, 32);
        if (supplied_pub != derived_pub) {
            std::cerr << "account-import: --priv mismatch: 64-byte form's "
                         "tail 32 bytes don't match the pubkey derived from "
                         "the seed (operator likely concatenated the wrong "
                         "pubkey, or copy-paste hit a transcription error)\n";
            return 1;
        }
    }

    // ── Build the anon-account record ───────────────────────────────────────
    // Matches account-create-batch byte-for-byte: address is "0x" + lowercase
    // hex of the 32-byte pubkey (the canonical anon-address derivation in
    // src/wallet/account.cpp::make_anon_address); privkey_hex is the 32-byte
    // seed (NOT the 64-byte libsodium sk).
    std::string address     = "0x" + to_hex(derived_pub);
    std::string privkey_hex = to_hex(seed);
    nlohmann::json record = {
        {"address",     address},
        {"privkey_hex", privkey_hex},
    };

    // ── Dispatch on output mode ─────────────────────────────────────────────
    if (!out_path.empty()) {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "account-import: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << record.dump(2) << "\n";
        f.close();
        if (!f) {
            std::cerr << "account-import: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
        // 0600 permissions — owner-only read/write. On Windows the
        // read/write bits are a no-op (NTFS ACL inherits from parent);
        // we ignore the error code as non-fatal there.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
        std::cout << "imported account: " << address << "\n";
        return 0;
    }
    if (json_out) {
        std::cout << record.dump() << "\n";
        return 0;
    }
    // Default human format — same two-field layout as account-create-batch's
    // per-account block, sans the "Account N:" header (since import always
    // produces exactly one account).
    std::cout << "address:     " << address     << "\n";
    std::cout << "privkey_hex: " << privkey_hex << "\n";
    return 0;
}

// ── account-export — re-emit a wallet account file in various formats ──────
//
// Inverse of `account-create-batch` / `account-import` / `account-recover`:
// reads an existing single-account JSON file (the canonical wallet shape
//   { "address": "0x...", "privkey_hex": "..." })
// and re-emits it in one of three external formats. Useful when an operator
// needs to feed the secret material into a downstream tool with a different
// expected shape (e.g., piping into `backup-create --secret`, or printing the
// raw hex to a shell variable, or copy-pasting the full JSON into a hex
// inspector).
//
// CLI:
//   --in <file>: required. The single-account JSON file. Must contain at
//                least `address` (string, "0x" + 64 lowercase hex) and
//                `privkey_hex` (64-char lowercase hex). Extra fields are
//                tolerated (they are ignored on `raw-hex` output, preserved
//                on `json` passthrough, and dropped on `backup-bundle`).
//   --format <name>: optional, default `raw-hex`. One of:
//                * raw-hex       — print the 64-char privkey hex on stdout,
//                                  followed by a single newline. Useful for
//                                  shell substitution: `KEY=$(determ-wallet
//                                  account-export --in acc.json)`.
//                * json          — print the input account JSON verbatim
//                                  (re-serialized with consistent shape).
//                                  Useful for inspection / re-parsing in a
//                                  different toolchain.
//                * backup-bundle — print a JSON envelope of the shape
//                                  { "seed_hex":      "<64 hex>",
//                                    "pubkey_hex":    "<64 hex>",
//                                    "anon_address":  "0x...",
//                                    "derived_at_utc":"YYYY-MM-DDTHH:MM:SSZ" }
//                                  ready to feed into `backup-create --secret
//                                  <seed_hex>` (the seed_hex field is the
//                                  required parameter for that CLI). The
//                                  envelope is plaintext — actual AEAD
//                                  wrapping requires a passphrase and lives
//                                  in backup-create.
//   --out <file>: optional. If set, writes the chosen format to file with
//                 0600 permissions (best-effort on Windows; NTFS ACL).
//                 Refuses overwrite without --force. Parent dir must exist.
//   --force:      required to overwrite an existing --out.
//   --json:       when set together with --format raw-hex, additionally
//                 wraps the hex in a {"privkey_hex": "..."} JSON object
//                 for parsing convenience. Ignored if --format is json or
//                 backup-bundle (those formats are already JSON). Ignored
//                 if --out is set without --format raw-hex.
//
// Output emission (stdout vs --out, mirrors account-create-batch / -import):
//   default (no --out)  — emits format to stdout
//   --out <file>        — writes format to file (0600); stdout shows a
//                         one-line confirmation "exported <format>: <path>"
//   The privkey_hex (or the bundle containing it) lives in the file rather
//   than the terminal when --out is used, matching the wallet's existing
//   "secret material to file by default, terminal only when explicit"
//   convention.
//
// Exit codes:
//   0 = success
//   1 = argument / validation / I/O error (missing --in, bad format,
//       malformed account JSON, missing parent dir, file-exists no --force,
//       etc.)
int cmd_account_export(int argc, char** argv) {
    std::string in_path, format = "raw-hex", out_path;
    bool force    = false;
    bool json_out = false;
    bool format_set_explicitly = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"     && i + 1 < argc) in_path  = argv[++i];
        else if (a == "--format" && i + 1 < argc) {
            format = argv[++i];
            format_set_explicitly = true;
        }
        else if (a == "--out"    && i + 1 < argc) out_path = argv[++i];
        else if (a == "--force")                  force    = true;
        else if (a == "--json")                   json_out = true;
        else {
            std::cerr << "account-export: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-export --in <file> "
                         "[--format raw-hex|json|backup-bundle] "
                         "[--out <file>] [--force] [--json]\n";
            return 1;
        }
    }
    if (in_path.empty()) {
        std::cerr << "account-export: --in is required (path to a "
                     "single-account JSON file)\n";
        std::cerr << "Usage: determ-wallet account-export --in <file> "
                     "[--format raw-hex|json|backup-bundle] "
                     "[--out <file>] [--force] [--json]\n";
        return 1;
    }
    // Validate --format up front so we don't read the input file just to
    // reject a typo'd format. Suppress this check for the silent default
    // so the diagnostic actually fires when format_set_explicitly is true.
    if (format != "raw-hex" && format != "json" && format != "backup-bundle") {
        std::cerr << "account-export: --format must be one of "
                     "{raw-hex, json, backup-bundle}; got '"
                  << format << "'\n";
        (void)format_set_explicitly;
        return 1;
    }

    // ── Read + parse the input account file ─────────────────────────────────
    // File-level failures (missing, unreadable) and structural failures
    // (bad JSON, missing required keys) both exit 1. We don't split into
    // 1/2 here because account-export is a passive transform — operators
    // pointing it at the wrong file get the same "fix your input" feedback
    // either way.
    std::ifstream in_f(in_path);
    if (!in_f) {
        std::cerr << "account-export: cannot open --in: " << in_path << "\n";
        return 1;
    }
    nlohmann::json acc_doc;
    try {
        in_f >> acc_doc;
    } catch (std::exception& e) {
        std::cerr << "account-export: --in is not valid JSON: "
                  << e.what() << "\n";
        return 1;
    }
    if (!acc_doc.is_object()) {
        std::cerr << "account-export: --in must be a JSON object "
                     "{\"address\":..., \"privkey_hex\":...}; got non-object\n";
        return 1;
    }
    if (!acc_doc.contains("address") || !acc_doc["address"].is_string()) {
        std::cerr << "account-export: --in missing required string field "
                     "'address'\n";
        return 1;
    }
    if (!acc_doc.contains("privkey_hex")
        || !acc_doc["privkey_hex"].is_string()) {
        std::cerr << "account-export: --in missing required string field "
                     "'privkey_hex'\n";
        return 1;
    }
    std::string address     = acc_doc["address"].get<std::string>();
    std::string privkey_hex = acc_doc["privkey_hex"].get<std::string>();

    // ── Validate shape: address is 0x + 64 lowercase hex; privkey is 64 hex ─
    // We deliberately accept exactly the canonical wallet shape here. If a
    // future format adds longer or shorter forms, those callers should round-
    // trip through account-import (which already supports the 128-hex form)
    // before export.
    if (address.size() != 66 || address.substr(0, 2) != "0x") {
        std::cerr << "account-export: 'address' must be \"0x\" + 64 hex "
                     "chars; got length " << address.size() << "\n";
        return 1;
    }
    try { (void)from_hex(address.substr(2)); }
    catch (std::exception& e) {
        std::cerr << "account-export: 'address' hex body is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (privkey_hex.size() != 64) {
        std::cerr << "account-export: 'privkey_hex' must be 64 hex chars "
                     "(32-byte seed); got length " << privkey_hex.size()
                  << "\n";
        return 1;
    }
    std::vector<uint8_t> priv_bytes;
    try { priv_bytes = from_hex(privkey_hex); }
    catch (std::exception& e) {
        std::cerr << "account-export: 'privkey_hex' is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (priv_bytes.size() != 32) {
        std::cerr << "account-export: 'privkey_hex' decoded length must be "
                     "32; got " << priv_bytes.size() << "\n";
        return 1;
    }

    // ── --out preconditions ─────────────────────────────────────────────────
    // Mirrors account-create-batch / account-import: parent dir must exist;
    // destination must not exist unless --force. Surfaced before any output
    // serialization so a misconfigured operator gets feedback fast.
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "account-export: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "account-export: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Build the output payload per --format ───────────────────────────────
    // raw-hex:        plain 64-char hex (optionally JSON-wrapped if --json)
    // json:           passthrough — re-serialize the input account JSON
    // backup-bundle:  {seed_hex, pubkey_hex, anon_address, derived_at_utc}
    //                 ready for `backup-create --secret <seed_hex>`
    std::string payload;
    if (format == "raw-hex") {
        if (json_out) {
            nlohmann::json doc = { {"privkey_hex", privkey_hex} };
            payload = doc.dump();
        } else {
            payload = privkey_hex;
        }
    } else if (format == "json") {
        // Passthrough — but emit with a deterministic key order so
        // downstream diffs and round-trip tests are stable. nlohmann/json's
        // default ordering is lexicographic for std::map-backed objects.
        payload = acc_doc.dump(2);
    } else {
        // backup-bundle: derive an ISO-8601 UTC timestamp + emit the
        // envelope-ready JSON. The seed_hex field is named to match
        // backup-create's --secret <hex> input (which accepts the privkey
        // seed verbatim).
        // pubkey_hex is the address minus the "0x" prefix; we already
        // validated it as 64 lowercase hex above.
        std::string pubkey_hex = address.substr(2);

        // ISO 8601 UTC. Use gmtime_r/gmtime_s for thread-safety where
        // available; on MSVC the _s suffix is the canonical form, on
        // POSIX it's the _r suffix.
        auto now = std::time(nullptr);
        std::tm tm_buf{};
#ifdef _WIN32
        gmtime_s(&tm_buf, &now);
#else
        gmtime_r(&now, &tm_buf);
#endif
        char ts[32] = {};
        std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

        nlohmann::json bundle = {
            {"seed_hex",       privkey_hex},
            {"pubkey_hex",     pubkey_hex},
            {"anon_address",   address},
            {"derived_at_utc", std::string(ts)},
        };
        payload = bundle.dump(2);
    }

    // ── Dispatch on output destination ─────────────────────────────────────
    if (!out_path.empty()) {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "account-export: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << payload;
        // raw-hex is single-line; the JSON formats already include their
        // own internal newlines from dump(2). Either way, always finish
        // the file with a trailing newline so POSIX tools don't complain.
        if (payload.empty() || payload.back() != '\n') f << "\n";
        f.close();
        if (!f) {
            std::cerr << "account-export: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
        // 0600 permissions — owner-only read/write. On Windows the
        // read/write bits are a no-op (NTFS ACL inherits from parent);
        // we ignore the error code as non-fatal there.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
        std::cout << "exported " << format << ": " << out_path << "\n";
        return 0;
    }
    // stdout — payload + single trailing newline (raw-hex needs the LF for
    // shell-script ergonomics; the JSON formats look more natural with one
    // too).
    std::cout << payload;
    if (payload.empty() || payload.back() != '\n') std::cout << "\n";
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

// Composite-backup CONSTRUCTOR (inverse of backup-verify).
//
// `backup-create` produces the two canonical backup artifacts in one call:
//   1. A Shamir share-set file (shape: {"shares": [{"x": int, "y_hex": "..."}, ...]},
//      identical to `shamir-split --json` output).
//   2. A per-share AEAD envelopes file (shape: {"envelopes": [{"share_index": int,
//      "envelope_blob": "<canonical dot-separated hex>"}, ...]}, identical to
//      the shape consumed by `backup-verify`).
//
// Inputs:
//   --secret <hex>:        hex-encoded secret (wallet seed, key, etc.)
//   --threshold <T>:       Shamir threshold (any T-of-N reconstructs)
//   --keyholders <file>:   JSON file
//                          {"keyholders": [{"share_index": int, "passphrase": "..."}, ...]}
//                          where N = length(keyholders).
//   --shares-out <file>:   destination for the shares file
//   --envelopes-out <file>:destination for the envelopes file
//   --force:               overwrite existing output files
//   --json:                emit a JSON summary instead of the human one-liner
//
// Validation:
//   * --secret hex valid + non-empty
//   * 1 <= T <= N <= 255
//   * keyholders.share_index values are distinct, all in [1, N], no gaps
//     (must be a permutation of {1..N})
//   * each keyholder.passphrase is non-empty
//   * output paths' parent directories must exist (no mkdirp); refusing to
//     overwrite without --force matches account-create-batch convention
//
// Process:
//   1. from_hex(--secret) → raw bytes
//   2. shamir::split(secret, T, N) → N shares with x = 1..N
//   3. For each share i: passphrase = keyholders[share_index == share.x].passphrase;
//      env = envelope::encrypt(plaintext = share.y, passphrase),
//      blob = envelope::serialize(env)
//   4. Write the shares file (atomic semantics — write then close before
//      writing the envelopes file, so a half-baked first file doesn't
//      mislead an observer about backup completeness)
//   5. Write the envelopes file
//   6. Emit summary
//
// Notes on share→keyholder pairing:
//   Each Shamir share's x-coordinate (1..N from shamir::split) is the
//   `share_index` used to look up the keyholder's passphrase. The
//   keyholders array doesn't need to be sorted in the input file — we
//   index by share_index, not by position. This matches the way
//   backup-verify treats envelope share_index as the bijection key.
//
// AAD note:
//   This CLI does NOT bind any AAD into the envelope (consistent with
//   `envelope encrypt --plaintext --password` invocations elsewhere in
//   the test fixtures). The OPAQUE-guarded recovery flow uses AAD
//   (recovery::create with version+index), but the operator-workflow
//   composite-backup case stays AAD-free so plain `envelope decrypt`
//   on the resulting blob round-trips without an --aad arg.
int cmd_backup_create(int argc, char** argv) {
    std::string secret_hex, keyholders_path, shares_out, envs_out;
    int threshold = -1;
    bool force = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--secret"        && i + 1 < argc) secret_hex      = argv[++i];
        else if (a == "--threshold"     && i + 1 < argc) {
            try { threshold = std::stoi(argv[++i]); }
            catch (std::exception&) {
                std::cerr << "backup-create: --threshold must be an integer\n";
                return 1;
            }
        }
        else if (a == "--keyholders"    && i + 1 < argc) keyholders_path = argv[++i];
        else if (a == "--shares-out"    && i + 1 < argc) shares_out      = argv[++i];
        else if (a == "--envelopes-out" && i + 1 < argc) envs_out        = argv[++i];
        else if (a == "--force")                         force           = true;
        else if (a == "--json")                          json_out        = true;
        else {
            std::cerr << "backup-create: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet backup-create --secret <hex> "
                         "--threshold T --keyholders <file> "
                         "--shares-out <file> --envelopes-out <file> "
                         "[--force] [--json]\n";
            return 1;
        }
    }
    if (secret_hex.empty() || threshold < 0 || keyholders_path.empty()
        || shares_out.empty() || envs_out.empty()) {
        std::cerr << "Usage: determ-wallet backup-create --secret <hex> "
                     "--threshold T --keyholders <file> "
                     "--shares-out <file> --envelopes-out <file> "
                     "[--force] [--json]\n"
                     "\n"
                     "  Produces a complete wallet backup (Shamir shares + per-share\n"
                     "  AEAD envelopes) from a secret + per-keyholder passphrases.\n"
                     "\n"
                     "  Keyholders file shape:\n"
                     "    {\"keyholders\": [{\"share_index\": int, \"passphrase\": \"...\"}, ...]}\n"
                     "  N (share count) is length(keyholders). 1 <= T <= N <= 255.\n";
        return 1;
    }

    // ── Decode --secret ─────────────────────────────────────────────────
    if (secret_hex.size() % 2 != 0) {
        std::cerr << "backup-create: --secret hex must have even length\n";
        return 1;
    }
    std::vector<uint8_t> secret;
    try { secret = from_hex(secret_hex); }
    catch (std::exception& e) {
        std::cerr << "backup-create: invalid --secret hex: " << e.what() << "\n";
        return 1;
    }
    if (secret.empty()) {
        std::cerr << "backup-create: --secret must be non-empty\n";
        return 1;
    }

    // ── Threshold sanity ─────────────────────────────────────────────────
    if (threshold < 1) {
        std::cerr << "backup-create: --threshold must be >= 1 (got "
                  << threshold << ")\n";
        return 1;
    }
    if (threshold > 255) {
        std::cerr << "backup-create: --threshold must be <= 255 (got "
                  << threshold << ")\n";
        return 1;
    }

    // ── Load + parse keyholders file ─────────────────────────────────────
    std::ifstream kf(keyholders_path);
    if (!kf) {
        std::cerr << "backup-create: cannot open --keyholders file: "
                  << keyholders_path << "\n";
        return 1;
    }
    std::string kh_blob((std::istreambuf_iterator<char>(kf)),
                          std::istreambuf_iterator<char>());
    nlohmann::json kj;
    try { kj = nlohmann::json::parse(kh_blob); }
    catch (std::exception& e) {
        std::cerr << "backup-create: keyholders JSON parse failed: "
                  << e.what() << "\n";
        return 1;
    }
    if (!kj.is_object() || !kj.contains("keyholders") || !kj["keyholders"].is_array()) {
        std::cerr << "backup-create: keyholders file must be an object with "
                     "'keyholders' array\n";
        return 1;
    }
    const auto& kh_arr = kj["keyholders"];
    if (kh_arr.empty()) {
        std::cerr << "backup-create: 'keyholders' array is empty\n";
        return 1;
    }
    if (kh_arr.size() > 255) {
        std::cerr << "backup-create: 'keyholders' array has "
                  << kh_arr.size() << " entries (max 255)\n";
        return 1;
    }
    const int share_count = static_cast<int>(kh_arr.size());
    if (threshold > share_count) {
        std::cerr << "backup-create: --threshold (" << threshold
                  << ") > keyholder count (" << share_count << ")\n";
        return 1;
    }

    // Build index → passphrase map. share_index must be a permutation of
    // {1..N} (no gaps, no duplicates, in [1,N]). This matches the
    // bijection that `shamir::split` produces (shares get x = 1..N) and
    // that `backup-verify` enforces post-hoc.
    std::vector<std::string> pw_by_index(share_count + 1);   // 1-indexed
    std::set<int> seen_idx;
    for (size_t i = 0; i < kh_arr.size(); ++i) {
        const auto& el = kh_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("passphrase")
            || !el["passphrase"].is_string()) {
            std::cerr << "backup-create: keyholders entry #" << i
                      << " must have integer 'share_index' and string "
                         "'passphrase'\n";
            return 1;
        }
        int idx = el["share_index"].get<int>();
        if (idx < 1 || idx > share_count) {
            std::cerr << "backup-create: keyholders entry #" << i
                      << ": share_index = " << idx
                      << " out of range [1, " << share_count << "]\n";
            return 1;
        }
        if (!seen_idx.insert(idx).second) {
            std::cerr << "backup-create: duplicate share_index = " << idx
                      << " in keyholders file\n";
            return 1;
        }
        std::string pw = el["passphrase"].get<std::string>();
        if (pw.empty()) {
            std::cerr << "backup-create: keyholders entry share_index="
                      << idx << ": passphrase is empty\n";
            return 1;
        }
        pw_by_index[idx] = std::move(pw);
    }
    // Bijection assertion: seen_idx == {1..N}. The duplicate check above
    // plus the [1,N] range bound + size N guarantees this; double-check
    // defensively to surface any future regression precisely.
    if (static_cast<int>(seen_idx.size()) != share_count) {
        std::cerr << "backup-create: share_index set is not "
                     "{1.." << share_count << "} "
                     "(missing or extra indices)\n";
        return 1;
    }

    // ── Output path preconditions ────────────────────────────────────────
    auto check_out_path = [&](const std::string& p,
                              const char* label) -> int {
        std::filesystem::path fp(p);
        auto parent = fp.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "backup-create: " << label
                      << " parent directory does not exist: "
                      << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(fp) && !force) {
            std::cerr << "backup-create: " << label << " file already exists: "
                      << p
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
        return 0;
    };
    if (int rc = check_out_path(shares_out, "--shares-out");      rc != 0) return rc;
    if (int rc = check_out_path(envs_out,   "--envelopes-out");   rc != 0) return rc;

    // Also reject pointing both outputs at the same file — silent
    // overwrite of the first by the second would be data loss with
    // zero diagnostic.
    if (std::filesystem::weakly_canonical(std::filesystem::path(shares_out))
        == std::filesystem::weakly_canonical(std::filesystem::path(envs_out))) {
        std::cerr << "backup-create: --shares-out and --envelopes-out "
                     "point at the same file\n";
        return 1;
    }

    // ── Shamir split ─────────────────────────────────────────────────────
    std::vector<shamir::Share> shares;
    try {
        shares = shamir::split(secret,
                                  static_cast<uint8_t>(threshold),
                                  static_cast<uint8_t>(share_count));
    } catch (std::exception& e) {
        std::cerr << "backup-create: shamir::split failed: "
                  << e.what() << "\n";
        return 1;
    }
    // shamir::split guarantees shares[i].x = i+1 (1..N), but rely only on
    // the documented invariant that x is in [1,N] and distinct; look up
    // the passphrase by share.x.

    // ── Per-share AEAD wrap ──────────────────────────────────────────────
    nlohmann::json envs_arr = nlohmann::json::array();
    nlohmann::json shares_arr = nlohmann::json::array();
    for (const auto& s : shares) {
        int idx = static_cast<int>(s.x);
        if (idx < 1 || idx > share_count || pw_by_index[idx].empty()) {
            std::cerr << "backup-create: internal: share x=" << idx
                      << " has no passphrase in keyholders map\n";
            return 1;
        }
        envelope::Envelope env;
        try {
            env = envelope::encrypt(s.y, pw_by_index[idx]);
        } catch (std::exception& e) {
            std::cerr << "backup-create: envelope::encrypt failed (x="
                      << idx << "): " << e.what() << "\n";
            return 1;
        }
        std::string blob = envelope::serialize(env);
        envs_arr.push_back({
            {"share_index",   idx},
            {"envelope_blob", blob},
        });
        shares_arr.push_back({
            {"x",     idx},
            {"y_hex", to_hex(s.y)},
        });
    }

    // ── Write shares file ────────────────────────────────────────────────
    {
        std::ofstream f(shares_out);
        if (!f) {
            std::cerr << "backup-create: cannot open --shares-out for write: "
                      << shares_out << "\n";
            return 1;
        }
        nlohmann::json doc;
        doc["shares"] = std::move(shares_arr);
        f << doc.dump() << "\n";
        if (!f) {
            std::cerr << "backup-create: write failed on --shares-out: "
                      << shares_out << "\n";
            return 1;
        }
    }
    // Owner-only perms on POSIX; no-op on Windows (NTFS ACL inherits).
    {
        std::error_code perm_ec;
        std::filesystem::permissions(
            shares_out,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
    }

    // ── Write envelopes file ─────────────────────────────────────────────
    {
        std::ofstream f(envs_out);
        if (!f) {
            std::cerr << "backup-create: cannot open --envelopes-out for write: "
                      << envs_out << "\n";
            return 1;
        }
        nlohmann::json doc;
        doc["envelopes"] = std::move(envs_arr);
        f << doc.dump() << "\n";
        if (!f) {
            std::cerr << "backup-create: write failed on --envelopes-out: "
                      << envs_out << "\n";
            return 1;
        }
    }
    {
        std::error_code perm_ec;
        std::filesystem::permissions(
            envs_out,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
    }

    // ── Summary ──────────────────────────────────────────────────────────
    if (json_out) {
        nlohmann::json r;
        r["share_count"]    = share_count;
        r["threshold"]      = threshold;
        r["shares_file"]    = shares_out;
        r["envelopes_file"] = envs_out;
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "wrote " << share_count << " shares + "
                  << share_count << " envelopes (threshold "
                  << threshold << ")\n";
    }
    return 0;
}

// ── keyfile-create — S-004 encrypted node_key.json producer ────────────────
//
// `determ` daemon supports loading both plaintext and passphrase-encrypted
// node_key.json files (the latter closes S-004: validator private key
// exposed at rest). This CLI is the operator-side workflow for producing
// the encrypted form OFFLINE on a wallet host that doesn't share an
// address space with the networked daemon.
//
// Inputs:
//   --priv <hex>          : Ed25519 seed (32 B = 64 hex) OR full keypair
//                            (64 B = 128 hex: 32 seed || 32 pub). Both
//                            accepted; the pubkey is derived/verified.
//   --passphrase-from src : `file:<path>` — first line of file
//                           `env:<VARNAME>` — environment variable
//                           `prompt` — interactive stdin no-echo prompt
//   --out <file>          : output path (refuses overwrite without --force)
//   [--force]             : permit overwriting an existing --out file
//   [--json]              : emit a structured summary on stdout
//
// Canonical encrypted-keyfile shape (mirrors `determ account create
// --passphrase` from src/main.cpp::cmd_account_create — established
// precedent for envelope-wrapped key files):
//
//   line 1: "DETERM-NODE-V1 <pubkey_hex>\n"
//   line 2: "<envelope_blob>\n"
//
//   <pubkey_hex>   = 64-char lowercase hex of the Ed25519 public key.
//                    Stored in plaintext so operators can identify which
//                    validator the file belongs to without decrypting.
//                    Also bound into the envelope AAD as a tamper-evident
//                    anchor — substituting another validator's encrypted
//                    blob under the same passphrase will fail GCM tag
//                    verification.
//   <envelope_blob> = canonical DWE1 envelope serialization (dot-separated
//                     lowercase hex; see wallet/envelope.hpp). The
//                     plaintext inside the envelope is the same JSON the
//                     daemon's plaintext load path consumes:
//                       {"pubkey": "<hex>", "priv_seed": "<hex>"}
//                     which matches src/crypto/keys.cpp::load_node_key
//                     byte-for-byte (S-018 field validation applies).
//   AAD            = pubkey_hex bytes (ASCII, lowercase, 64 bytes).
//
// File permissions: best-effort 0600 (owner read+write only). On Unix
// this is a real chmod via std::filesystem::permissions; on Windows the
// call resolves to a best-effort owner-only ACL.
//
// Round-trip note: the test wrapper exercises decrypt via the wallet's
// own `envelope decrypt` CLI (the same envelope library the daemon's
// encrypted-keyfile load path uses), so the entire produce→consume loop
// is verified without touching `src/`.

// passphrase_from_source — read the operator passphrase per --passphrase-from.
//
// Supported source specifiers:
//   "file:<path>"  — first line of the file (newline-stripped). Empty
//                    file or empty first line is rejected. Convenient
//                    for ops scripts: the passphrase lives in a
//                    permission-restricted file, not on the CLI.
//   "env:<NAME>"   — value of environment variable <NAME>. Empty value
//                    is rejected. Variable must be exported in the
//                    shell environment.
//   "prompt"       — interactive read from stdin with terminal echo
//                    disabled (best-effort: Windows + POSIX termios).
//                    Falls back to plain getline if no tty / no termios
//                    available.
//
// Returns the passphrase on success; sets `err` and returns empty on
// failure. Caller surfaces `err` on stderr.
std::string passphrase_from_source(const std::string& spec, std::string& err) {
    err.clear();
    if (spec.empty()) {
        err = "passphrase source is empty";
        return "";
    }
    if (spec.rfind("file:", 0) == 0) {
        std::string path = spec.substr(5);
        if (path.empty()) { err = "file: source has empty path"; return ""; }
        std::ifstream f(path);
        if (!f) {
            err = "cannot open passphrase file: " + path;
            return "";
        }
        std::string line;
        if (!std::getline(f, line)) {
            err = "passphrase file is empty: " + path;
            return "";
        }
        // Strip trailing CR (Windows-style line endings) but preserve
        // intentional internal whitespace — the operator may have
        // chosen a passphrase containing spaces.
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty()) {
            err = "passphrase file first line is empty: " + path;
            return "";
        }
        return line;
    }
    if (spec.rfind("env:", 0) == 0) {
        std::string name = spec.substr(4);
        if (name.empty()) { err = "env: source has empty variable name"; return ""; }
        const char* v = std::getenv(name.c_str());
        if (!v || !*v) {
            err = "environment variable not set or empty: " + name;
            return "";
        }
        return std::string(v);
    }
    if (spec == "prompt") {
        // Interactive no-echo read. Best-effort across platforms; if
        // disabling echo fails we still read the line (operator may be
        // running in a non-tty context — they're warned via stderr).
        std::cerr << "Passphrase: " << std::flush;
#ifdef _WIN32
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD orig = 0;
        bool echo_off = (hStdin != INVALID_HANDLE_VALUE
                         && GetConsoleMode(hStdin, &orig)
                         && SetConsoleMode(hStdin, orig & ~ENABLE_ECHO_INPUT));
        std::string pw;
        std::getline(std::cin, pw);
        if (echo_off) SetConsoleMode(hStdin, orig);
        std::cerr << "\n";
        if (pw.empty()) { err = "empty passphrase from prompt"; return ""; }
        return pw;
#else
        termios old_t{}, new_t{};
        bool echo_off = (tcgetattr(STDIN_FILENO, &old_t) == 0);
        if (echo_off) {
            new_t = old_t;
            new_t.c_lflag &= ~ECHO;
            if (tcsetattr(STDIN_FILENO, TCSANOW, &new_t) != 0) echo_off = false;
        }
        std::string pw;
        std::getline(std::cin, pw);
        if (echo_off) tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
        std::cerr << "\n";
        if (pw.empty()) { err = "empty passphrase from prompt"; return ""; }
        return pw;
#endif
    }
    err = "unknown passphrase source '" + spec
        + "'; expected file:<path>, env:<NAME>, or prompt";
    return "";
}

int cmd_keyfile_create(int argc, char** argv) {
    std::string priv_hex, pass_src, out_path;
    bool force = false;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv"            && i + 1 < argc) priv_hex = argv[++i];
        else if (a == "--passphrase-from" && i + 1 < argc) pass_src = argv[++i];
        else if (a == "--out"             && i + 1 < argc) out_path = argv[++i];
        else if (a == "--force")                           force    = true;
        else if (a == "--json")                            json_out = true;
        else {
            std::cerr << "keyfile-create: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet keyfile-create --priv <hex> "
                         "--passphrase-from <file:path|env:NAME|prompt> "
                         "--out <file> [--force] [--json]\n";
            return 1;
        }
    }
    if (priv_hex.empty() || pass_src.empty() || out_path.empty()) {
        std::cerr << "Usage: determ-wallet keyfile-create --priv <hex> "
                     "--passphrase-from <file:path|env:NAME|prompt> "
                     "--out <file> [--force] [--json]\n";
        return 1;
    }

    // ── Validate --priv length (must be 32 B seed or 64 B keypair) ──────────
    if (priv_hex.size() != 64 && priv_hex.size() != 128) {
        std::cerr << "keyfile-create: --priv must be 64 hex chars (32-byte seed) "
                     "or 128 hex chars (32-byte seed || 32-byte pubkey); got "
                  << priv_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> priv_bytes;
    try { priv_bytes = from_hex(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "keyfile-create: invalid --priv hex: " << e.what() << "\n";
        return 1;
    }
    if (priv_bytes.size() != 32 && priv_bytes.size() != 64) {
        // Belt-and-suspenders; the size check above already covered this.
        std::cerr << "keyfile-create: --priv decoded length must be 32 or 64; "
                     "got " << priv_bytes.size() << "\n";
        return 1;
    }

    // ── Derive / verify pubkey from seed ────────────────────────────────────
    // Ed25519 layout: the 32-byte seed deterministically derives the
    // 32-byte public key. If the operator passed a 64-byte form, we
    // still derive from the seed and verify the supplied pubkey
    // matches — a mismatch is almost always operator error (mixed up
    // two key pairs).
    std::array<uint8_t, 32> seed{};
    std::memcpy(seed.data(), priv_bytes.data(), 32);
    std::array<uint8_t, 32> derived_pub{};
    {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr, seed.data(), 32);
        if (!pkey) {
            std::cerr << "keyfile-create: EVP_PKEY_new_raw_private_key failed "
                         "(seed not a valid Ed25519 private key)\n";
            return 1;
        }
        size_t pub_len = derived_pub.size();
        if (EVP_PKEY_get_raw_public_key(pkey, derived_pub.data(), &pub_len) <= 0
            || pub_len != 32) {
            EVP_PKEY_free(pkey);
            std::cerr << "keyfile-create: EVP_PKEY_get_raw_public_key failed\n";
            return 1;
        }
        EVP_PKEY_free(pkey);
    }
    if (priv_bytes.size() == 64) {
        std::array<uint8_t, 32> supplied_pub{};
        std::memcpy(supplied_pub.data(), priv_bytes.data() + 32, 32);
        if (supplied_pub != derived_pub) {
            std::cerr << "keyfile-create: --priv mismatch: 64-byte form's tail "
                         "32 bytes don't match the pubkey derived from the "
                         "seed (operator likely concatenated the wrong "
                         "pubkey)\n";
            return 1;
        }
    }
    std::string pubkey_hex   = to_hex(derived_pub);
    std::string priv_seed_hex = to_hex(seed);

    // ── Read passphrase from configured source ──────────────────────────────
    std::string err;
    std::string passphrase = passphrase_from_source(pass_src, err);
    if (passphrase.empty()) {
        std::cerr << "keyfile-create: " << err << "\n";
        return 1;
    }

    // ── --out preconditions: parent dir exists; file absent (or --force) ────
    {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "keyfile-create: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "keyfile-create: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Build the canonical keyfile JSON (plaintext-inside-envelope) ────────
    // Matches src/crypto/keys.cpp::load_node_key exactly: top-level
    // object with `pubkey` (64-hex) and `priv_seed` (64-hex) string
    // fields. Both are required + S-018 length-validated by the daemon.
    nlohmann::json keyfile_json = {
        {"pubkey",    pubkey_hex},
        {"priv_seed", priv_seed_hex}
    };
    std::string pt_str = keyfile_json.dump(2);
    std::vector<uint8_t> pt_bytes(pt_str.begin(), pt_str.end());

    // AAD = ASCII bytes of pubkey hex. Binds the envelope to this
    // validator's public key — a tampered envelope substituted from
    // another validator (same passphrase) will fail GCM tag verification.
    std::vector<uint8_t> aad(pubkey_hex.begin(), pubkey_hex.end());

    // ── Encrypt + write the canonical 2-line file ───────────────────────────
    std::string blob;
    try {
        auto env  = envelope::encrypt(pt_bytes, passphrase, aad);
        blob      = envelope::serialize(env);
    } catch (std::exception& e) {
        std::cerr << "keyfile-create: envelope encrypt failed: "
                  << e.what() << "\n";
        return 1;
    }

    // ── Self-test round-trip: decrypt the freshly-written envelope ──────────
    // Catches any drift between encrypt + decrypt paths before the
    // operator ships the file. Cheap belt-and-suspenders: a wrong
    // passphrase / corrupted blob fails here BEFORE we touch --out.
    {
        auto roundtrip_env = envelope::deserialize(blob);
        if (!roundtrip_env) {
            std::cerr << "keyfile-create: internal: just-emitted envelope "
                         "blob fails deserialize\n";
            return 1;
        }
        auto rt_pt = envelope::decrypt(*roundtrip_env, passphrase, aad);
        if (!rt_pt) {
            std::cerr << "keyfile-create: internal: just-emitted envelope "
                         "fails decrypt round-trip\n";
            return 1;
        }
        if (*rt_pt != pt_bytes) {
            std::cerr << "keyfile-create: internal: round-trip plaintext "
                         "mismatch\n";
            return 1;
        }
    }

    {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "keyfile-create: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << "DETERM-NODE-V1 " << pubkey_hex << "\n";
        f << blob << "\n";
        f.close();
        if (!f) {
            std::cerr << "keyfile-create: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
    }

    // 0600 permissions tightening — best-effort on Windows.
    {
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
    }

    if (json_out) {
        nlohmann::json r;
        r["pubkey"]      = pubkey_hex;
        r["out"]         = out_path;
        r["format"]      = "DETERM-NODE-V1";
        r["envelope"]    = "DWE1";
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "wrote encrypted node keyfile to " << out_path << "\n";
        std::cout << "  pubkey: " << pubkey_hex << "\n";
        std::cout << "  format: DETERM-NODE-V1 (header) + DWE1 envelope\n";
    }
    return 0;
}

// ── keyfile-decrypt — S-004 encrypted node_key.json reverse path ───────────
//
// Inverse of `cmd_keyfile_create`. Operator workflow for one-shot offline
// operations: migrate an encrypted validator key to a different node,
// recover from a passphrase-protected backup, or debug a key that the
// daemon refuses to load. The daemon itself supports loading the
// encrypted form directly at runtime — this CLI exists for the cases
// where the plaintext form is required (e.g., reviewing the key
// material, exporting to a different runtime, key-archive workflow).
//
// Inputs:
//   --in <file>           : encrypted keyfile produced by keyfile-create.
//                           Canonical 2-line format:
//                              line 1: "DETERM-NODE-V1 <pubkey_hex>\n"
//                              line 2: "<DWE1 envelope blob>\n"
//   --passphrase-from src : same as keyfile-create — `file:<path>`,
//                           `env:<NAME>`, or `prompt` (no-echo interactive)
//   --out <file>          : output path for the plaintext node_key.json.
//                           Daemon loader: src/crypto/keys.cpp::load_node_key
//   [--force]             : permit overwriting an existing --out file
//   [--json]              : emit a structured summary on stdout
//
// Process:
//   1. Read --in; parse the 2-line canonical format (header + blob).
//   2. Resolve --passphrase-from to passphrase bytes.
//   3. envelope::decrypt(blob, passphrase, aad=pubkey_hex_bytes).
//      AAD binding from keyfile-create ensures the envelope is bound to
//      the validator pubkey — tampering with the header line (e.g.,
//      substituting another validator's pubkey) breaks AEAD verification.
//   4. Parse decrypted plaintext as {"pubkey": "<hex>", "priv_seed": "<hex>"}.
//   5. Verify inner pubkey matches header pubkey (defense-in-depth — they
//      must match by construction; mismatch indicates a corrupted file
//      or a deliberately-malformed keyfile produced outside the canonical
//      keyfile-create path).
//   6. Write a canonical plaintext node_key.json matching
//      src/crypto/keys.cpp::save_node_key byte-for-byte (j.dump(2)).
//   7. Apply 0600 owner-only permissions (best-effort).
//
// Diagnostic policy:
//   * Wrong passphrase OR tampered envelope OR mismatched AAD →
//     **exit 2** with a single "wrong passphrase or corrupted keyfile"
//     diagnostic. We deliberately do NOT distinguish these cases on
//     stderr — an attacker probing with various passphrases must not
//     be able to distinguish "your passphrase is wrong" from "the file
//     I gave you is malformed". They are indistinguishable to a
//     plaintext-recovering oracle.
//   * Structural problems with the --in file (wrong header magic,
//     malformed blob, unparseable plaintext JSON, mismatched pubkey
//     after decrypt) → **exit 1** with a specific diagnostic.
//     Distinguishing these is fine because they don't depend on
//     passphrase knowledge: an attacker who already has the file
//     can see them locally.
int cmd_keyfile_decrypt(int argc, char** argv) {
    std::string in_path, pass_src, out_path;
    bool force = false;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"              && i + 1 < argc) in_path  = argv[++i];
        else if (a == "--passphrase-from" && i + 1 < argc) pass_src = argv[++i];
        else if (a == "--out"             && i + 1 < argc) out_path = argv[++i];
        else if (a == "--force")                           force    = true;
        else if (a == "--json")                            json_out = true;
        else {
            std::cerr << "keyfile-decrypt: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet keyfile-decrypt --in <file> "
                         "--passphrase-from <file:path|env:NAME|prompt> "
                         "--out <file> [--force] [--json]\n";
            return 1;
        }
    }
    if (in_path.empty() || pass_src.empty() || out_path.empty()) {
        std::cerr << "Usage: determ-wallet keyfile-decrypt --in <file> "
                     "--passphrase-from <file:path|env:NAME|prompt> "
                     "--out <file> [--force] [--json]\n";
        return 1;
    }

    // ── Read --in and parse the canonical 2-line format ────────────────────
    std::string header_line, blob_line;
    {
        std::ifstream f(in_path);
        if (!f) {
            std::cerr << "keyfile-decrypt: cannot open --in: " << in_path << "\n";
            return 1;
        }
        if (!std::getline(f, header_line)) {
            std::cerr << "keyfile-decrypt: --in is empty: " << in_path << "\n";
            return 1;
        }
        if (!std::getline(f, blob_line)) {
            std::cerr << "keyfile-decrypt: --in is missing the envelope-blob "
                         "line (expected 2-line format: header + blob): "
                      << in_path << "\n";
            return 1;
        }
        // Strip trailing CR (Windows-style line endings) for portability.
        while (!header_line.empty()
               && (header_line.back() == '\r' || header_line.back() == '\n'))
            header_line.pop_back();
        while (!blob_line.empty()
               && (blob_line.back() == '\r' || blob_line.back() == '\n'))
            blob_line.pop_back();
    }

    // Header shape: "DETERM-NODE-V1 <pubkey_hex>"
    const std::string header_magic = "DETERM-NODE-V1 ";
    if (header_line.rfind(header_magic, 0) != 0) {
        std::cerr << "keyfile-decrypt: --in header does not start with "
                     "'DETERM-NODE-V1 ' (not a canonical encrypted node "
                     "keyfile)\n";
        return 1;
    }
    std::string header_pubkey_hex = header_line.substr(header_magic.size());
    if (header_pubkey_hex.size() != 64) {
        std::cerr << "keyfile-decrypt: --in header pubkey must be 64 hex "
                     "chars (32-byte Ed25519 pubkey); got "
                  << header_pubkey_hex.size() << "\n";
        return 1;
    }
    // Validate the header pubkey is well-formed hex. Done before passphrase
    // read so a structurally-broken file fails fast without prompting.
    try { (void)from_hex(header_pubkey_hex); }
    catch (std::exception& e) {
        std::cerr << "keyfile-decrypt: --in header pubkey is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (blob_line.empty()) {
        std::cerr << "keyfile-decrypt: --in envelope blob line is empty\n";
        return 1;
    }

    // ── Read passphrase ────────────────────────────────────────────────────
    std::string err;
    std::string passphrase = passphrase_from_source(pass_src, err);
    if (passphrase.empty()) {
        std::cerr << "keyfile-decrypt: " << err << "\n";
        return 1;
    }

    // ── --out preconditions ────────────────────────────────────────────────
    {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "keyfile-decrypt: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "keyfile-decrypt: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Deserialize envelope blob ──────────────────────────────────────────
    // A blob that fails to deserialize is a structural problem with the
    // --in file — exit 1 with a specific diagnostic. Distinguishing from
    // wrong-passphrase here is fine because it doesn't depend on
    // passphrase knowledge.
    auto env_opt = envelope::deserialize(blob_line);
    if (!env_opt) {
        std::cerr << "keyfile-decrypt: --in envelope blob is malformed "
                     "(not a valid DWE1 serialization)\n";
        return 1;
    }

    // ── Decrypt with pubkey_hex as AAD ─────────────────────────────────────
    // AAD binding: keyfile-create binds the header pubkey into the GCM
    // AAD. Any tampering with the header pubkey (or substitution of an
    // envelope from a different validator) breaks AEAD verification
    // here — same exit code / diagnostic as wrong passphrase, so an
    // attacker cannot distinguish.
    std::vector<uint8_t> aad(header_pubkey_hex.begin(), header_pubkey_hex.end());
    auto pt_opt = envelope::decrypt(*env_opt, passphrase, aad);
    if (!pt_opt) {
        std::cerr << "keyfile-decrypt: wrong passphrase or corrupted "
                     "keyfile\n";
        return 2;
    }
    std::string pt_str(pt_opt->begin(), pt_opt->end());

    // ── Parse decrypted plaintext as canonical node_key JSON ───────────────
    // The decrypted plaintext is the same {"pubkey","priv_seed"} JSON the
    // daemon's load_node_key path consumes. Bad JSON here is a structural
    // problem (caller used keyfile-decrypt on a non-keyfile-create envelope)
    // — exit 1 with a specific diagnostic.
    nlohmann::json keyfile_json;
    try {
        keyfile_json = nlohmann::json::parse(pt_str);
    } catch (std::exception& e) {
        std::cerr << "keyfile-decrypt: decrypted plaintext is not valid JSON "
                     "(this is not a canonical encrypted node keyfile): "
                  << e.what() << "\n";
        return 1;
    }
    if (!keyfile_json.is_object()
        || !keyfile_json.contains("pubkey")
        || !keyfile_json.contains("priv_seed")
        || !keyfile_json["pubkey"].is_string()
        || !keyfile_json["priv_seed"].is_string()) {
        std::cerr << "keyfile-decrypt: decrypted plaintext is missing the "
                     "required 'pubkey' / 'priv_seed' string fields\n";
        return 1;
    }
    std::string inner_pubkey_hex = keyfile_json["pubkey"].get<std::string>();
    std::string priv_seed_hex    = keyfile_json["priv_seed"].get<std::string>();
    if (inner_pubkey_hex.size() != 64) {
        std::cerr << "keyfile-decrypt: inner 'pubkey' must be 64 hex chars; "
                     "got " << inner_pubkey_hex.size() << "\n";
        return 1;
    }
    if (priv_seed_hex.size() != 64) {
        std::cerr << "keyfile-decrypt: inner 'priv_seed' must be 64 hex "
                     "chars; got " << priv_seed_hex.size() << "\n";
        return 1;
    }
    // Hex validation (defense-in-depth — the daemon's S-018 path enforces
    // this, but the operator probably wants the wallet to catch it first).
    try { (void)from_hex(inner_pubkey_hex); (void)from_hex(priv_seed_hex); }
    catch (std::exception& e) {
        std::cerr << "keyfile-decrypt: inner JSON contains invalid hex: "
                  << e.what() << "\n";
        return 1;
    }

    // ── Header-vs-inner pubkey defense-in-depth check ──────────────────────
    // The AAD already ties the header pubkey to the ciphertext, so a
    // mismatch here can only happen if a keyfile was hand-crafted outside
    // the canonical keyfile-create path. We surface it as a structural
    // problem with a clear diagnostic rather than silently using one or
    // the other — the operator should investigate provenance.
    if (inner_pubkey_hex != header_pubkey_hex) {
        std::cerr << "keyfile-decrypt: inner 'pubkey' (" << inner_pubkey_hex
                  << ") does not match header pubkey (" << header_pubkey_hex
                  << "); the encrypted blob was not produced by the "
                     "canonical keyfile-create path\n";
        return 1;
    }

    // ── Format canonical plaintext node_key.json ───────────────────────────
    // Matches src/crypto/keys.cpp::save_node_key byte-for-byte: nlohmann
    // dump with indent=2, fields {"pubkey","priv_seed"} as 64-hex strings.
    // The daemon's load_node_key only requires the two named fields to be
    // present, but we preserve the indented canonical shape so an operator
    // diffing wallet-decrypted vs. daemon-saved outputs sees equality.
    nlohmann::json out_json = {
        {"pubkey",    inner_pubkey_hex},
        {"priv_seed", priv_seed_hex}
    };
    std::string out_str = out_json.dump(2);

    {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "keyfile-decrypt: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << out_str;
        f.close();
        if (!f) {
            std::cerr << "keyfile-decrypt: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
    }

    // 0600 permissions tightening — best-effort on Windows.
    {
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
    }

    if (json_out) {
        nlohmann::json r;
        r["pubkey"]   = inner_pubkey_hex;
        r["out"]      = out_path;
        r["format"]   = "node_key.json";
        r["from"]     = "DETERM-NODE-V1";
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "wrote plaintext node keyfile to " << out_path << "\n";
        std::cout << "  pubkey: " << inner_pubkey_hex << "\n";
        std::cout << "  format: node_key.json (daemon plaintext load path)\n";
    }
    return 0;
}

// ── keyfile-recover — high-level T-of-N backup recovery CLI ────────────────
//
// `keyfile-recover` is the operator inverse of `backup-create`. It composes
// `envelope::decrypt` + `shamir::combine` into a single call: given the
// canonical pair of backup artifacts (shares + envelopes file produced
// by `backup-create`) and a JSON file listing a T-of-N subset of
// keyholder passphrases, recover the original secret and print it as hex.
//
// Inputs:
//   --backup-shares    <file>: shares file emitted by backup-create's
//                              --shares-out (shape: {"shares":[{"x":int,
//                              "y_hex":"..."}, ...]}). Read for cross-
//                              verification — we confirm each decrypted
//                              y-bytes matches the shares-file entry.
//   --backup-envelopes <file>: envelopes file emitted by backup-create's
//                              --envelopes-out (shape: {"envelopes":
//                              [{"share_index":int,"envelope_blob":"..."},
//                              ...]}).
//   --keyholders       <file>: SAME shape as backup-create's --keyholders
//                              input but with ONLY a T-of-N subset of
//                              passphrases supplied:
//                              {"keyholders":[{"share_index":int,
//                              "passphrase":"..."}, ...]}
//   [--out  <file>]          : if supplied, write {"secret_hex":"..."} JSON
//                              to <file> instead of emitting the hex to
//                              stdout
//   [--force]                : permit overwriting an existing --out file
//   [--json]                 : print the JSON {"secret_hex":"..."} doc to
//                              stdout (ignored if --out is supplied; --out
//                              always writes JSON)
//
// Process:
//   1. Parse the three input files.
//   2. For each keyholder entry: look up the corresponding envelope by
//      share_index, deserialize the envelope blob, decrypt with the
//      keyholder's passphrase (NO AAD — backup-create produces AAD-free
//      envelopes; the recovery composition mirrors that).
//   3. Cross-verify the recovered y-bytes against the shares-file
//      entry for the same share_index (defense-in-depth — catches a
//      shares/envelopes file mismatch before Shamir reconstruction
//      silently emits a garbage secret).
//   4. Feed the T recovered shamir::Share values into shamir::combine.
//   5. Output the recovered secret as hex (or JSON with --out / --json).
//
// Composition design:
//   This CLI is intentionally THIN — it composes existing primitives
//   (envelope::decrypt, shamir::combine) and existing file-shape
//   conventions (matched against backup-create + shamir-combine). No
//   crypto logic is duplicated; if envelope::decrypt or shamir::combine
//   change, this CLI follows transparently.
//
// Failure modes (all exit 2 with a diagnostic):
//   * Wrong passphrase: envelope::decrypt returns nullopt for an AEAD
//     tag mismatch. Same exit code as `keyfile-decrypt` for consistency.
//   * Insufficient shares (< T): shamir::combine returns nullopt or the
//     reconstruction yields a different secret. We can't tell T from the
//     inputs (the shares file doesn't carry threshold; the operator must
//     supply >= T keyholders), so we treat "shamir::combine returned
//     nullopt" as "insufficient or inconsistent shares". A reconstruction
//     run with fewer than T shares may also return a syntactically-valid
//     but wrong secret (Shamir's information-theoretic security property)
//     — the shares-file cross-verification in step 3 catches that case.
//   * Malformed inputs (missing files, bad JSON, share_index gap):
//     exit 2 with a specific diagnostic.
//
// Structural errors (missing required flags, can't open files for read,
// --out exists without --force) exit 1 — same convention as the other
// wallet CLIs.
int cmd_keyfile_recover(int argc, char** argv) {
    std::string shares_path, envelopes_path, keyholders_path, out_path;
    int threshold = -1;             // -1 sentinel = not supplied
    bool force = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--backup-shares"    && i + 1 < argc) shares_path     = argv[++i];
        else if (a == "--backup-envelopes" && i + 1 < argc) envelopes_path  = argv[++i];
        else if (a == "--keyholders"       && i + 1 < argc) keyholders_path = argv[++i];
        else if (a == "--out"              && i + 1 < argc) out_path        = argv[++i];
        else if (a == "--threshold"        && i + 1 < argc) {
            try { threshold = std::stoi(argv[++i]); }
            catch (std::exception&) {
                std::cerr << "keyfile-recover: --threshold must be an integer\n";
                return 1;
            }
        }
        else if (a == "--force")                            force           = true;
        else if (a == "--json")                             json_out        = true;
        else {
            std::cerr << "keyfile-recover: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet keyfile-recover "
                         "--backup-shares <file> --backup-envelopes <file> "
                         "--keyholders <file> [--threshold T] "
                         "[--out <file>] [--force] [--json]\n";
            return 1;
        }
    }
    if (shares_path.empty() || envelopes_path.empty()
        || keyholders_path.empty()) {
        std::cerr << "Usage: determ-wallet keyfile-recover "
                     "--backup-shares <file> --backup-envelopes <file> "
                     "--keyholders <file> [--threshold T] "
                     "[--out <file>] [--force] [--json]\n"
                     "\n"
                     "  High-level T-of-N recovery: composes envelope::decrypt\n"
                     "  + shamir::combine. Reads the (shares, envelopes) pair\n"
                     "  produced by `backup-create` and a T-of-N subset of\n"
                     "  keyholder passphrases; reconstructs the original secret.\n"
                     "\n"
                     "  Keyholders file shape (SAME as backup-create input but\n"
                     "  with only T of N entries supplied):\n"
                     "    {\"keyholders\": [{\"share_index\": int, "
                     "\"passphrase\": \"...\"}, ...]}\n"
                     "\n"
                     "  --threshold T (optional): explicitly check that the\n"
                     "    keyholders subset has at least T entries before the\n"
                     "    decrypt loop. The shares file does NOT carry T, so\n"
                     "    without --threshold the CLI cannot detect an under-\n"
                     "    threshold subset (Shamir's information-theoretic\n"
                     "    security property means combining < T shares yields\n"
                     "    a syntactically-valid but wrong secret, with no\n"
                     "    failure signal at the shamir layer).\n";
        return 1;
    }
    if (threshold == 0) {
        std::cerr << "keyfile-recover: --threshold must be >= 1 (got 0)\n";
        return 1;
    }
    if (threshold > 255) {
        std::cerr << "keyfile-recover: --threshold must be <= 255 (got "
                  << threshold << ")\n";
        return 1;
    }

    // ── Load + parse shares file ────────────────────────────────────────
    std::ifstream sf(shares_path);
    if (!sf) {
        std::cerr << "keyfile-recover: cannot open --backup-shares file: "
                  << shares_path << "\n";
        return 1;
    }
    std::string shares_blob((std::istreambuf_iterator<char>(sf)),
                              std::istreambuf_iterator<char>());
    nlohmann::json sj;
    try { sj = nlohmann::json::parse(shares_blob); }
    catch (std::exception& e) {
        std::cerr << "keyfile-recover: shares JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!sj.is_object() || !sj.contains("shares") || !sj["shares"].is_array()) {
        std::cerr << "keyfile-recover: shares file must be an object with "
                     "'shares' array\n";
        return 2;
    }
    const auto& shares_arr = sj["shares"];
    if (shares_arr.empty()) {
        std::cerr << "keyfile-recover: 'shares' array is empty\n";
        return 2;
    }
    // Build x → y_hex map for the cross-verification check in step 3.
    std::map<int, std::string> shares_y_by_x;
    for (size_t i = 0; i < shares_arr.size(); ++i) {
        const auto& el = shares_arr[i];
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            std::cerr << "keyfile-recover: shares entry #" << i
                      << " must have integer 'x' and string 'y_hex'\n";
            return 2;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            std::cerr << "keyfile-recover: shares entry #" << i
                      << ": x = " << x << " out of range [1, 255]\n";
            return 2;
        }
        if (shares_y_by_x.count(x)) {
            std::cerr << "keyfile-recover: duplicate x = " << x
                      << " in shares file\n";
            return 2;
        }
        shares_y_by_x[x] = el["y_hex"].get<std::string>();
    }

    // ── Load + parse envelopes file ─────────────────────────────────────
    std::ifstream ef(envelopes_path);
    if (!ef) {
        std::cerr << "keyfile-recover: cannot open --backup-envelopes file: "
                  << envelopes_path << "\n";
        return 1;
    }
    std::string env_blob((std::istreambuf_iterator<char>(ef)),
                           std::istreambuf_iterator<char>());
    nlohmann::json ej;
    try { ej = nlohmann::json::parse(env_blob); }
    catch (std::exception& e) {
        std::cerr << "keyfile-recover: envelopes JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!ej.is_object() || !ej.contains("envelopes") || !ej["envelopes"].is_array()) {
        std::cerr << "keyfile-recover: envelopes file must be an object with "
                     "'envelopes' array\n";
        return 2;
    }
    const auto& env_arr = ej["envelopes"];
    if (env_arr.empty()) {
        std::cerr << "keyfile-recover: 'envelopes' array is empty\n";
        return 2;
    }
    // Build share_index → envelope_blob map.
    std::map<int, std::string> env_blob_by_idx;
    for (size_t i = 0; i < env_arr.size(); ++i) {
        const auto& el = env_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("envelope_blob")
            || !el["envelope_blob"].is_string()) {
            std::cerr << "keyfile-recover: envelopes entry #" << i
                      << " must have integer 'share_index' and string "
                         "'envelope_blob'\n";
            return 2;
        }
        int idx = el["share_index"].get<int>();
        if (idx < 1 || idx > 255) {
            std::cerr << "keyfile-recover: envelopes entry #" << i
                      << ": share_index = " << idx
                      << " out of range [1, 255]\n";
            return 2;
        }
        if (env_blob_by_idx.count(idx)) {
            std::cerr << "keyfile-recover: duplicate share_index = " << idx
                      << " in envelopes file\n";
            return 2;
        }
        env_blob_by_idx[idx] = el["envelope_blob"].get<std::string>();
    }

    // ── Load + parse keyholders file (T-of-N subset) ────────────────────
    std::ifstream kf(keyholders_path);
    if (!kf) {
        std::cerr << "keyfile-recover: cannot open --keyholders file: "
                  << keyholders_path << "\n";
        return 1;
    }
    std::string kh_blob((std::istreambuf_iterator<char>(kf)),
                          std::istreambuf_iterator<char>());
    nlohmann::json kj;
    try { kj = nlohmann::json::parse(kh_blob); }
    catch (std::exception& e) {
        std::cerr << "keyfile-recover: keyholders JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!kj.is_object() || !kj.contains("keyholders") || !kj["keyholders"].is_array()) {
        std::cerr << "keyfile-recover: keyholders file must be an object with "
                     "'keyholders' array\n";
        return 2;
    }
    const auto& kh_arr = kj["keyholders"];
    if (kh_arr.empty()) {
        std::cerr << "keyfile-recover: 'keyholders' array is empty (need at "
                     "least 1 entry to attempt recovery)\n";
        return 2;
    }

    // Parse each keyholder entry. Tracks share_index → passphrase mapping
    // for the decrypt loop, and validates each share_index actually exists
    // in BOTH the shares and envelopes files before any crypto work.
    std::vector<std::pair<int, std::string>> kh_entries;
    std::set<int> seen_kh_idx;
    for (size_t i = 0; i < kh_arr.size(); ++i) {
        const auto& el = kh_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("passphrase")
            || !el["passphrase"].is_string()) {
            std::cerr << "keyfile-recover: keyholders entry #" << i
                      << " must have integer 'share_index' and string "
                         "'passphrase'\n";
            return 2;
        }
        int idx = el["share_index"].get<int>();
        std::string pw = el["passphrase"].get<std::string>();
        if (pw.empty()) {
            std::cerr << "keyfile-recover: keyholders entry share_index="
                      << idx << ": passphrase is empty\n";
            return 2;
        }
        if (!seen_kh_idx.insert(idx).second) {
            std::cerr << "keyfile-recover: duplicate share_index = " << idx
                      << " in keyholders file\n";
            return 2;
        }
        if (!env_blob_by_idx.count(idx)) {
            std::cerr << "keyfile-recover: keyholders share_index=" << idx
                      << " has no matching envelope in --backup-envelopes\n";
            return 2;
        }
        if (!shares_y_by_x.count(idx)) {
            std::cerr << "keyfile-recover: keyholders share_index=" << idx
                      << " has no matching share in --backup-shares\n";
            return 2;
        }
        kh_entries.emplace_back(idx, std::move(pw));
    }

    // ── Threshold check (if --threshold supplied) ────────────────────────
    // Without --threshold the shares file carries no T, so Shamir's
    // information-theoretic security property means combining < T shares
    // yields a syntactically-valid but wrong secret. When the operator
    // supplies T explicitly we can detect insufficient-share subsets
    // BEFORE any crypto work — fail fast and clear rather than emit
    // garbage. Same exit-2 convention as "wrong passphrase" / other
    // recovery failures.
    if (threshold > 0
        && static_cast<int>(kh_entries.size()) < threshold) {
        std::cerr << "keyfile-recover: insufficient shares for threshold "
                     "reconstruction: " << kh_entries.size()
                  << " keyholders supplied, --threshold = " << threshold
                  << "\n";
        return 2;
    }

    // ── --out preconditions (if supplied) ────────────────────────────────
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "keyfile-recover: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "keyfile-recover: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Decrypt each envelope; collect shamir::Share entries ─────────────
    std::vector<shamir::Share> recovered_shares;
    recovered_shares.reserve(kh_entries.size());
    for (const auto& [idx, pw] : kh_entries) {
        const std::string& blob = env_blob_by_idx[idx];
        auto env_opt = envelope::deserialize(blob);
        if (!env_opt) {
            std::cerr << "keyfile-recover: envelope share_index=" << idx
                      << ": envelope_blob deserialize failed "
                         "(malformed envelope in --backup-envelopes)\n";
            return 2;
        }
        // backup-create produces AAD-free envelopes — same here (empty aad).
        auto pt_opt = envelope::decrypt(*env_opt, pw, {});
        if (!pt_opt) {
            std::cerr << "keyfile-recover: envelope share_index=" << idx
                      << ": decrypt failed (wrong passphrase or corrupted "
                         "envelope)\n";
            return 2;
        }
        const auto& y_bytes = *pt_opt;
        if (y_bytes.empty()) {
            std::cerr << "keyfile-recover: envelope share_index=" << idx
                      << ": decrypted plaintext is empty\n";
            return 2;
        }
        // Cross-verify decrypted y against the shares-file y_hex. Catches
        // a shares/envelopes file mismatch before Shamir reconstruction
        // silently emits a garbage secret.
        std::string y_hex_decrypted = to_hex(y_bytes);
        const std::string& y_hex_expected = shares_y_by_x[idx];
        if (y_hex_decrypted != y_hex_expected) {
            std::cerr << "keyfile-recover: envelope share_index=" << idx
                      << ": decrypted y-bytes do NOT match the y_hex in "
                         "--backup-shares (envelope/shares file mismatch — "
                         "the two files were likely produced by different "
                         "backup-create runs)\n";
            return 2;
        }
        shamir::Share s;
        if (idx < 1 || idx > 255) {
            std::cerr << "keyfile-recover: internal: share_index=" << idx
                      << " out of byte range\n";
            return 2;
        }
        s.x = static_cast<uint8_t>(idx);
        s.y = y_bytes;
        recovered_shares.push_back(std::move(s));
    }

    if (recovered_shares.empty()) {
        std::cerr << "keyfile-recover: no shares recovered (internal — "
                     "keyholders array was already validated as non-empty)\n";
        return 2;
    }

    // ── Shamir reconstruction ───────────────────────────────────────────
    auto secret_opt = shamir::combine(recovered_shares);
    if (!secret_opt) {
        std::cerr << "keyfile-recover: shamir::combine returned nullopt "
                     "(insufficient shares for threshold reconstruction, or "
                     "shares were structurally inconsistent at the shamir "
                     "layer)\n";
        return 2;
    }
    std::string secret_hex = to_hex(*secret_opt);

    // ── Emit result ─────────────────────────────────────────────────────
    if (!out_path.empty()) {
        nlohmann::json doc;
        doc["secret_hex"] = secret_hex;
        std::ofstream of(out_path);
        if (!of) {
            std::cerr << "keyfile-recover: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        of << doc.dump() << "\n";
        if (!of) {
            std::cerr << "keyfile-recover: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
        of.close();
        // 0600 permissions tightening — best-effort on Windows.
        {
            std::error_code perm_ec;
            std::filesystem::permissions(
                out_path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace,
                perm_ec);
            (void)perm_ec;
        }
        if (json_out) {
            // --json + --out: also echo the JSON doc to stdout so the
            // operator's pipe-driven workflow sees the result.
            std::cout << doc.dump() << "\n";
        } else {
            std::cout << "recovered secret written to " << out_path
                      << " (" << recovered_shares.size()
                      << " shares combined)\n";
        }
    } else if (json_out) {
        nlohmann::json doc;
        doc["secret_hex"] = secret_hex;
        std::cout << doc.dump() << "\n";
    } else {
        std::cout << secret_hex << "\n";
    }
    return 0;
}

// ── account-recover — composite T-of-N wallet recovery CLI ─────────────────
//
// `account-recover` is the operator-facing "give me back my wallet account"
// CLI: it composes `keyfile-recover` (Shamir + envelope) with `account-import`
// (Ed25519 seed → anon-account JSON) into a SINGLE call, so the operator
// runs ONE command instead of two.
//
// Pipeline:
//   1. Run the keyfile-recover steps verbatim: decrypt T envelopes via
//      passphrases, cross-verify against shares, run shamir::combine →
//      recover a 32-byte secret (Ed25519 seed).
//   2. Treat the recovered secret as a 32-byte Ed25519 seed.
//   3. Derive the public key via libsodium crypto_sign_ed25519_seed_keypair
//      (same primitive used by account-import — keeps the wallet's
//      secret-handling surface uniform on libsodium).
//   4. Emit the anon-account JSON {"address":"0x..","privkey_hex":".."}
//      (same shape as account-import / account-create-batch single record).
//
// CLI:
//   --shares      <file>: shares file emitted by backup-create's
//                         --shares-out (shape: {"shares":[{"x":int,
//                         "y_hex":"..."}, ...]}).
//   --envelopes   <file>: envelopes file emitted by backup-create's
//                         --envelopes-out (shape: {"envelopes":
//                         [{"share_index":int,"envelope_blob":"..."}, ...]}).
//   --keyholders  <file>: T-of-N subset of keyholder passphrases (shape:
//                         {"keyholders":[{"share_index":int,
//                         "passphrase":"..."}, ...]}). MUST have >= T entries.
//   --threshold  T      : required (unlike keyfile-recover where it's
//                         optional). The seed-derivation step requires the
//                         RIGHT seed — Shamir's information-theoretic
//                         security means combining < T shares yields a
//                         syntactically-valid but wrong 32-byte secret, and
//                         account-recover MUST NOT silently emit a wrong
//                         wallet account. T is required so we can hard-fail
//                         under-threshold subsets before any keygen.
//   [--out  <file>]     : if supplied, write the anon-account JSON
//                         {"address":"0x..","privkey_hex":".."} to <file>
//                         with 0600 perms instead of stdout.
//   [--force]           : permit overwriting an existing --out file.
//   [--json]            : print the JSON doc to stdout (ignored if --out
//                         is supplied; --out always writes JSON).
//
// Output (default human): "recovered account: address=0x... privkey_hex=..."
// Output (--out):         {"address":"0x..","privkey_hex":".."} to file, 0600
// Output (--json):        same JSON to stdout
//
// Exit codes:
//   0 — success.
//   1 — args / file I/O / --out preconditions (matches keyfile-recover +
//       account-import structural-error convention).
//   2 — recovery failure (wrong passphrase, insufficient shares, share/
//       envelope mismatch, malformed inputs). SAME exit-2 convention as
//       keyfile-recover so monitoring scripts that already alert on the
//       inner CLI's exit 2 will continue to fire correctly when wrapped.
//
// Composition design:
//   This CLI is intentionally THIN — it composes the SAME primitives
//   (envelope::decrypt, shamir::combine, crypto_sign_ed25519_seed_keypair)
//   that the constituent CLIs use. No crypto logic is duplicated. If
//   keyfile-recover or account-import change, this CLI follows transparently.
//
// Seed-length contract:
//   The recovered Shamir secret MUST be exactly 32 bytes (= Ed25519 seed
//   size). If a 16-byte / 64-byte / other-length secret is recovered, we
//   reject with exit 2 — that's not an Ed25519 seed, so this is the wrong
//   recovery flow for that backup. Operators with non-32-byte backups
//   should use `keyfile-recover` directly + `account-import` separately.
int cmd_account_recover(int argc, char** argv) {
    std::string shares_path, envelopes_path, keyholders_path, out_path;
    int threshold = -1;             // -1 sentinel = not supplied
    bool force = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--shares"     && i + 1 < argc) shares_path     = argv[++i];
        else if (a == "--envelopes"  && i + 1 < argc) envelopes_path  = argv[++i];
        else if (a == "--keyholders" && i + 1 < argc) keyholders_path = argv[++i];
        else if (a == "--out"        && i + 1 < argc) out_path        = argv[++i];
        else if (a == "--threshold"  && i + 1 < argc) {
            try { threshold = std::stoi(argv[++i]); }
            catch (std::exception&) {
                std::cerr << "account-recover: --threshold must be an integer\n";
                return 1;
            }
        }
        else if (a == "--force")                      force           = true;
        else if (a == "--json")                       json_out        = true;
        else {
            std::cerr << "account-recover: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-recover "
                         "--shares <file> --envelopes <file> "
                         "--keyholders <file> --threshold T "
                         "[--out <file>] [--force] [--json]\n";
            return 1;
        }
    }
    if (shares_path.empty() || envelopes_path.empty()
        || keyholders_path.empty() || threshold < 0) {
        std::cerr << "Usage: determ-wallet account-recover "
                     "--shares <file> --envelopes <file> "
                     "--keyholders <file> --threshold T "
                     "[--out <file>] [--force] [--json]\n"
                     "\n"
                     "  Composite wallet recovery: composes keyfile-recover\n"
                     "  (Shamir + envelope) with account-import (Ed25519 seed\n"
                     "  -> anon-account JSON). Reads the (shares, envelopes)\n"
                     "  pair produced by `backup-create` and a T-of-N subset\n"
                     "  of keyholder passphrases; emits the recovered wallet\n"
                     "  account as JSON {\"address\":\"0x..\",\"privkey_hex\":\"..\"}.\n"
                     "\n"
                     "  --threshold T is REQUIRED (unlike keyfile-recover where\n"
                     "  it is optional): account-recover MUST NOT silently emit\n"
                     "  a wrong wallet account, and Shamir's info-theoretic\n"
                     "  security means combining < T shares yields a wrong but\n"
                     "  syntactically-valid 32-byte secret. T lets us hard-fail\n"
                     "  under-threshold subsets before any keygen.\n";
        return 1;
    }
    if (threshold == 0) {
        std::cerr << "account-recover: --threshold must be >= 1 (got 0)\n";
        return 1;
    }
    if (threshold > 255) {
        std::cerr << "account-recover: --threshold must be <= 255 (got "
                  << threshold << ")\n";
        return 1;
    }

    // ── Load + parse shares file ────────────────────────────────────────
    std::ifstream sf(shares_path);
    if (!sf) {
        std::cerr << "account-recover: cannot open --shares file: "
                  << shares_path << "\n";
        return 1;
    }
    std::string shares_blob((std::istreambuf_iterator<char>(sf)),
                              std::istreambuf_iterator<char>());
    nlohmann::json sj;
    try { sj = nlohmann::json::parse(shares_blob); }
    catch (std::exception& e) {
        std::cerr << "account-recover: shares JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!sj.is_object() || !sj.contains("shares") || !sj["shares"].is_array()) {
        std::cerr << "account-recover: shares file must be an object with "
                     "'shares' array\n";
        return 2;
    }
    const auto& shares_arr = sj["shares"];
    if (shares_arr.empty()) {
        std::cerr << "account-recover: 'shares' array is empty\n";
        return 2;
    }
    // Build x → y_hex map for the cross-verification step.
    std::map<int, std::string> shares_y_by_x;
    for (size_t i = 0; i < shares_arr.size(); ++i) {
        const auto& el = shares_arr[i];
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            std::cerr << "account-recover: shares entry #" << i
                      << " must have integer 'x' and string 'y_hex'\n";
            return 2;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            std::cerr << "account-recover: shares entry #" << i
                      << ": x = " << x << " out of range [1, 255]\n";
            return 2;
        }
        if (shares_y_by_x.count(x)) {
            std::cerr << "account-recover: duplicate x = " << x
                      << " in shares file\n";
            return 2;
        }
        shares_y_by_x[x] = el["y_hex"].get<std::string>();
    }

    // ── Load + parse envelopes file ─────────────────────────────────────
    std::ifstream ef(envelopes_path);
    if (!ef) {
        std::cerr << "account-recover: cannot open --envelopes file: "
                  << envelopes_path << "\n";
        return 1;
    }
    std::string env_blob((std::istreambuf_iterator<char>(ef)),
                           std::istreambuf_iterator<char>());
    nlohmann::json ej;
    try { ej = nlohmann::json::parse(env_blob); }
    catch (std::exception& e) {
        std::cerr << "account-recover: envelopes JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!ej.is_object() || !ej.contains("envelopes") || !ej["envelopes"].is_array()) {
        std::cerr << "account-recover: envelopes file must be an object with "
                     "'envelopes' array\n";
        return 2;
    }
    const auto& env_arr = ej["envelopes"];
    if (env_arr.empty()) {
        std::cerr << "account-recover: 'envelopes' array is empty\n";
        return 2;
    }
    std::map<int, std::string> env_blob_by_idx;
    for (size_t i = 0; i < env_arr.size(); ++i) {
        const auto& el = env_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("envelope_blob")
            || !el["envelope_blob"].is_string()) {
            std::cerr << "account-recover: envelopes entry #" << i
                      << " must have integer 'share_index' and string "
                         "'envelope_blob'\n";
            return 2;
        }
        int idx = el["share_index"].get<int>();
        if (idx < 1 || idx > 255) {
            std::cerr << "account-recover: envelopes entry #" << i
                      << ": share_index = " << idx
                      << " out of range [1, 255]\n";
            return 2;
        }
        if (env_blob_by_idx.count(idx)) {
            std::cerr << "account-recover: duplicate share_index = " << idx
                      << " in envelopes file\n";
            return 2;
        }
        env_blob_by_idx[idx] = el["envelope_blob"].get<std::string>();
    }

    // ── Load + parse keyholders file (T-of-N subset) ────────────────────
    std::ifstream kf(keyholders_path);
    if (!kf) {
        std::cerr << "account-recover: cannot open --keyholders file: "
                  << keyholders_path << "\n";
        return 1;
    }
    std::string kh_blob((std::istreambuf_iterator<char>(kf)),
                          std::istreambuf_iterator<char>());
    nlohmann::json kj;
    try { kj = nlohmann::json::parse(kh_blob); }
    catch (std::exception& e) {
        std::cerr << "account-recover: keyholders JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!kj.is_object() || !kj.contains("keyholders") || !kj["keyholders"].is_array()) {
        std::cerr << "account-recover: keyholders file must be an object with "
                     "'keyholders' array\n";
        return 2;
    }
    const auto& kh_arr = kj["keyholders"];
    if (kh_arr.empty()) {
        std::cerr << "account-recover: 'keyholders' array is empty (need at "
                     "least 1 entry to attempt recovery)\n";
        return 2;
    }

    std::vector<std::pair<int, std::string>> kh_entries;
    std::set<int> seen_kh_idx;
    for (size_t i = 0; i < kh_arr.size(); ++i) {
        const auto& el = kh_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("passphrase")
            || !el["passphrase"].is_string()) {
            std::cerr << "account-recover: keyholders entry #" << i
                      << " must have integer 'share_index' and string "
                         "'passphrase'\n";
            return 2;
        }
        int idx = el["share_index"].get<int>();
        std::string pw = el["passphrase"].get<std::string>();
        if (pw.empty()) {
            std::cerr << "account-recover: keyholders entry share_index="
                      << idx << ": passphrase is empty\n";
            return 2;
        }
        if (!seen_kh_idx.insert(idx).second) {
            std::cerr << "account-recover: duplicate share_index = " << idx
                      << " in keyholders file\n";
            return 2;
        }
        if (!env_blob_by_idx.count(idx)) {
            std::cerr << "account-recover: keyholders share_index=" << idx
                      << " has no matching envelope in --envelopes\n";
            return 2;
        }
        if (!shares_y_by_x.count(idx)) {
            std::cerr << "account-recover: keyholders share_index=" << idx
                      << " has no matching share in --shares\n";
            return 2;
        }
        kh_entries.emplace_back(idx, std::move(pw));
    }

    // ── Threshold check (REQUIRED here, unlike keyfile-recover) ─────────
    // Under-threshold subsets MUST hard-fail before keygen. Shamir's
    // information-theoretic security means combining < T shares yields a
    // syntactically-valid 32-byte but WRONG secret — and account-recover
    // would happily derive a wallet account from that wrong secret. The
    // operator would then have a working-looking account file for an
    // address that owns no funds. Exit 2 here matches the wrong-passphrase
    // exit code (both mean "recovery failed").
    if (static_cast<int>(kh_entries.size()) < threshold) {
        std::cerr << "account-recover: insufficient shares for threshold "
                     "reconstruction: " << kh_entries.size()
                  << " keyholders supplied, --threshold = " << threshold
                  << "\n";
        return 2;
    }

    // ── --out preconditions (if supplied) ────────────────────────────────
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "account-recover: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "account-recover: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Decrypt each envelope; collect shamir::Share entries ─────────────
    std::vector<shamir::Share> recovered_shares;
    recovered_shares.reserve(kh_entries.size());
    for (const auto& [idx, pw] : kh_entries) {
        const std::string& blob = env_blob_by_idx[idx];
        auto env_opt = envelope::deserialize(blob);
        if (!env_opt) {
            std::cerr << "account-recover: envelope share_index=" << idx
                      << ": envelope_blob deserialize failed "
                         "(malformed envelope in --envelopes)\n";
            return 2;
        }
        // backup-create produces AAD-free envelopes — same here (empty aad).
        auto pt_opt = envelope::decrypt(*env_opt, pw, {});
        if (!pt_opt) {
            std::cerr << "account-recover: envelope share_index=" << idx
                      << ": decrypt failed (wrong passphrase or corrupted "
                         "envelope)\n";
            return 2;
        }
        const auto& y_bytes = *pt_opt;
        if (y_bytes.empty()) {
            std::cerr << "account-recover: envelope share_index=" << idx
                      << ": decrypted plaintext is empty\n";
            return 2;
        }
        // Cross-verify decrypted y against the shares-file y_hex. Catches
        // a shares/envelopes file mismatch before Shamir reconstruction
        // silently emits a garbage secret.
        std::string y_hex_decrypted = to_hex(y_bytes);
        const std::string& y_hex_expected = shares_y_by_x[idx];
        if (y_hex_decrypted != y_hex_expected) {
            std::cerr << "account-recover: envelope share_index=" << idx
                      << ": decrypted y-bytes do NOT match the y_hex in "
                         "--shares (envelope/shares file mismatch — the "
                         "two files were likely produced by different "
                         "backup-create runs)\n";
            return 2;
        }
        shamir::Share s;
        if (idx < 1 || idx > 255) {
            std::cerr << "account-recover: internal: share_index=" << idx
                      << " out of byte range\n";
            return 2;
        }
        s.x = static_cast<uint8_t>(idx);
        s.y = y_bytes;
        recovered_shares.push_back(std::move(s));
    }

    if (recovered_shares.empty()) {
        std::cerr << "account-recover: no shares recovered (internal — "
                     "keyholders array was already validated as non-empty)\n";
        return 2;
    }

    // ── Shamir reconstruction ───────────────────────────────────────────
    auto secret_opt = shamir::combine(recovered_shares);
    if (!secret_opt) {
        std::cerr << "account-recover: shamir::combine returned nullopt "
                     "(insufficient shares for threshold reconstruction, or "
                     "shares were structurally inconsistent at the shamir "
                     "layer)\n";
        return 2;
    }
    const std::vector<uint8_t>& secret = *secret_opt;

    // ── Seed-length contract: Ed25519 requires exactly 32 bytes ─────────
    // A non-32-byte recovered secret means this backup wasn't created
    // from a wallet-account Ed25519 seed — operator should use
    // keyfile-recover directly. We refuse to feed a wrong-sized secret
    // into crypto_sign_ed25519_seed_keypair (which expects exactly 32).
    static_assert(crypto_sign_SEEDBYTES == 32, "Ed25519 seed size mismatch");
    if (secret.size() != crypto_sign_SEEDBYTES) {
        std::cerr << "account-recover: recovered secret is " << secret.size()
                  << " bytes, but Ed25519 seed requires exactly 32 bytes. "
                     "This backup was likely created from a non-wallet "
                     "secret (use `keyfile-recover` directly instead).\n";
        return 2;
    }

    // ── Init libsodium + derive Ed25519 keypair from the recovered seed ─
    // Same primitive as account-import (crypto_sign_ed25519_seed_keypair).
    // The 64-byte sk it produces is seed||pubkey; we hold both halves
    // separately so we zero sk immediately after the call.
    if (!primitives::init_libsodium()) {
        std::cerr << "account-recover: libsodium init failed\n";
        return 1;
    }
    std::array<uint8_t, 32> seed{};
    std::memcpy(seed.data(), secret.data(), 32);
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> derived_pub{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    static_assert(crypto_sign_PUBLICKEYBYTES == 32, "Ed25519 pk size mismatch");
    static_assert(crypto_sign_SECRETKEYBYTES == 64, "Ed25519 sk size mismatch");
    if (crypto_sign_ed25519_seed_keypair(derived_pub.data(), sk.data(),
                                         seed.data()) != 0) {
        std::cerr << "account-recover: crypto_sign_ed25519_seed_keypair failed "
                     "(recovered seed not a valid Ed25519 private key — "
                     "almost certainly a corrupted Shamir reconstruction)\n";
        sodium_memzero(seed.data(), seed.size());
        return 2;
    }
    // Zero the libsodium 64-byte sk — its content (seed||pubkey) is already
    // held in `seed` / `derived_pub`, so the duplicate is unnecessary.
    sodium_memzero(sk.data(), sk.size());

    // ── Build the anon-account record ──────────────────────────────────
    // Matches account-import / account-create-batch byte-for-byte:
    // address is "0x" + lowercase hex of the 32-byte pubkey; privkey_hex
    // is the 32-byte seed (NOT the 64-byte libsodium sk).
    std::string address     = "0x" + to_hex(derived_pub);
    std::string privkey_hex = to_hex(seed);
    nlohmann::json record = {
        {"address",     address},
        {"privkey_hex", privkey_hex},
    };

    // Zero the local seed copy now that we've serialized it to hex.
    sodium_memzero(seed.data(), seed.size());

    // ── Emit result ────────────────────────────────────────────────────
    if (!out_path.empty()) {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "account-recover: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << record.dump(2) << "\n";
        f.close();
        if (!f) {
            std::cerr << "account-recover: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
        // 0600 permissions — owner-only read/write. Best-effort on Windows
        // (NTFS ACL inherits from parent); non-fatal on perm-set failure.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
        if (json_out) {
            // --json + --out: also echo to stdout for pipe-driven workflows.
            std::cout << record.dump() << "\n";
        } else {
            std::cout << "recovered account written to " << out_path
                      << " (" << recovered_shares.size()
                      << " shares combined): address=" << address << "\n";
        }
        return 0;
    }
    if (json_out) {
        std::cout << record.dump() << "\n";
        return 0;
    }
    // Default human format — single line, both fields, no header (since
    // recovery always yields exactly one account).
    std::cout << "recovered account: address=" << address
              << " privkey_hex=" << privkey_hex << "\n";
    return 0;
}

// ── keyfile-info — passive diagnostic for an encrypted node keyfile ─────────
//
// S-004 keyfile-shape complement to `inspect-envelope`. Reads a 2-line
// encrypted node keyfile (DETERM-NODE-V1 header + DWE1 envelope blob),
// parses both, and emits the combined metadata WITHOUT decrypting (no
// passphrase, no AEAD, no plaintext recovery).
//
// Use cases:
//   * Operator sanity check before attempting decrypt (correct file? right
//     validator pubkey? PBKDF2 iters consistent with the deployment policy?).
//   * Fleet inventory: enumerate all encrypted keyfiles, dump (pubkey,
//     anon-address) without ever needing the passphrase.
//   * Forensic triage: a tampered file is rejected with a distinguishing
//     exit code (2) so monitoring can route alerts.
//
// Exit codes:
//   0 — valid keyfile shape, metadata emitted.
//   1 — file-system error (missing file, parent dir issue, argparse).
//   2 — structural malformation (wrong header magic, bad pubkey hex, bad
//        envelope serialization). Distinguishes "operator pointed at a
//        non-keyfile" or "tampering" from "file not found".
//
// Output (default human form):
//   keyfile:           <path>
//   header_version:    DETERM-NODE-V1
//   pubkey_hex:        <64-hex>
//   anon_address:      0x<64-hex>
//   envelope:
//     format:          DWE1 (version 1)
//     pbkdf2_iters:    <N>
//     salt_len:        <n> bytes
//     nonce_len:       12 bytes
//     ciphertext_len:  <n> bytes
//     aad_present:     true|false
//
// JSON shape (--json):
//   {"valid":true,
//    "header_version":"DETERM-NODE-V1",
//    "pubkey_hex":"...",
//    "anon_address":"0x...",
//    "envelope":{
//      "pbkdf2_iters":<N>,
//      "salt_len":<n>,
//      "nonce_len":12,
//      "ct_len":<n>,
//      "aad_present":false}}
//
// Anon-address derivation: matches `make_anon_address` (and the
// `account-create-batch` precedent in this same binary): the address is
// simply "0x" followed by the lowercase hex of the 32-byte pubkey. The
// hex is already present in the header byte-for-byte; the "0x" prefix is
// the only addition. This is a sanity-check column for operators eyeballing
// fleet inventories: header pubkey + derived address always line up unless
// the header was hand-tampered (in which case the hex-validation step
// above rejects with exit 2).
int cmd_keyfile_info(int argc, char** argv) {
    std::string in_path;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in" && i + 1 < argc) in_path = argv[++i];
        else if (a == "--json")                json_out = true;
        else {
            std::cerr << "keyfile-info: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet keyfile-info --in <file> [--json]\n";
            return 1;
        }
    }
    if (in_path.empty()) {
        std::cerr << "Usage: determ-wallet keyfile-info --in <file> [--json]\n";
        return 1;
    }

    // ── Read --in and parse the canonical 2-line format ────────────────────
    // File-level failures (missing, unreadable) exit 1. Structural failures
    // (wrong header magic, truncated, bad hex, bad envelope) exit 2. The
    // split lets monitoring scripts distinguish "pointed at the wrong
    // path" from "file is corrupted / not a keyfile".
    std::string header_line, blob_line;
    {
        std::ifstream f(in_path);
        if (!f) {
            std::cerr << "keyfile-info: cannot open --in: " << in_path << "\n";
            return 1;
        }
        if (!std::getline(f, header_line)) {
            // Empty file is structurally malformed — there's no header line
            // at all. Use exit 2 (malformed) rather than 1, since the file
            // is reachable but its shape is wrong.
            std::cerr << "keyfile-info: --in is empty (no header line): "
                      << in_path << "\n";
            return 2;
        }
        if (!std::getline(f, blob_line)) {
            std::cerr << "keyfile-info: --in is missing the envelope-blob "
                         "line (expected 2-line format: header + blob): "
                      << in_path << "\n";
            return 2;
        }
        // Strip trailing CR (Windows-style line endings) for portability.
        while (!header_line.empty()
               && (header_line.back() == '\r' || header_line.back() == '\n'))
            header_line.pop_back();
        while (!blob_line.empty()
               && (blob_line.back() == '\r' || blob_line.back() == '\n'))
            blob_line.pop_back();
    }

    // ── Header shape: "DETERM-NODE-V1 <pubkey_hex>" ─────────────────────────
    const std::string header_magic = "DETERM-NODE-V1 ";
    if (header_line.rfind(header_magic, 0) != 0) {
        std::cerr << "keyfile-info: --in header does not start with "
                     "'DETERM-NODE-V1 ' (not a canonical encrypted node "
                     "keyfile)\n";
        return 2;
    }
    std::string pubkey_hex = header_line.substr(header_magic.size());
    if (pubkey_hex.size() != 64) {
        std::cerr << "keyfile-info: --in header pubkey must be 64 hex "
                     "chars (32-byte Ed25519 pubkey); got "
                  << pubkey_hex.size() << "\n";
        return 2;
    }
    try { (void)from_hex(pubkey_hex); }
    catch (std::exception& e) {
        std::cerr << "keyfile-info: --in header pubkey is not valid hex: "
                  << e.what() << "\n";
        return 2;
    }
    if (blob_line.empty()) {
        std::cerr << "keyfile-info: --in envelope blob line is empty\n";
        return 2;
    }

    // ── Deserialize envelope blob (no AEAD, no key derivation) ─────────────
    auto env_opt = envelope::deserialize(blob_line);
    if (!env_opt) {
        std::cerr << "keyfile-info: --in envelope blob is malformed "
                     "(not a valid DWE1 serialization)\n";
        return 2;
    }
    const auto& env = *env_opt;

    // Anon-address: matches src/main.cpp::make_anon_address and the
    // account-create-batch precedent above — "0x" + lowercase hex(pub).
    std::string anon_address = "0x" + pubkey_hex;

    const bool aad_present = !env.aad.empty();

    if (json_out) {
        // Flat schema for monitoring scripts. The nested "envelope"
        // sub-object mirrors the spec in the command's doc-block above.
        std::cout << "{"
                  << "\"valid\":true,"
                  << "\"header_version\":\"DETERM-NODE-V1\","
                  << "\"pubkey_hex\":\""   << pubkey_hex   << "\","
                  << "\"anon_address\":\"" << anon_address << "\","
                  << "\"envelope\":{"
                  << "\"pbkdf2_iters\":"   << env.pbkdf2_iters << ","
                  << "\"salt_len\":"       << env.salt.size()  << ","
                  << "\"nonce_len\":"      << env.nonce.size() << ","
                  << "\"ct_len\":"         << env.ciphertext.size() << ","
                  << "\"aad_present\":"    << (aad_present ? "true" : "false")
                  << "}"
                  << "}\n";
    } else {
        std::cout << "keyfile:           " << in_path           << "\n";
        std::cout << "header_version:    DETERM-NODE-V1\n";
        std::cout << "pubkey_hex:        " << pubkey_hex        << "\n";
        std::cout << "anon_address:      " << anon_address      << "\n";
        std::cout << "envelope:\n";
        std::cout << "  format:          DWE1 (version 1)\n";
        std::cout << "  pbkdf2_iters:    " << env.pbkdf2_iters  << "\n";
        std::cout << "  salt_len:        " << env.salt.size()   << " bytes\n";
        std::cout << "  nonce_len:       " << env.nonce.size()  << " bytes\n";
        std::cout << "  ciphertext_len:  " << env.ciphertext.size() << " bytes\n";
        std::cout << "  aad_present:     " << (aad_present ? "true" : "false")
                  << "\n";
    }
    return 0;
}

// ── account-list — enumerate keyfiles in a directory with metadata ──────────
//
// Pure local computation: walks --keyfiles-dir, classifies each regular file
// as one of {plaintext-single, plaintext-batch, encrypted-DETERM-NODE-V1,
// unknown}, and emits a per-file metadata record. No daemon RPC, no
// decryption, no passphrase required.
//
// Detection rules (each file is read until a definitive classification or
// the rules give up):
//   * Read the first line as text. If it starts with "DETERM-NODE-V1 " AND
//     the second line is a parseable DWE1 envelope blob, it's encrypted.
//   * Otherwise try JSON parse on the full content:
//       - JSON object with string `address` (66 char "0x"+64hex) AND string
//         `privkey_hex` (64 hex chars): plaintext-single
//       - JSON object with array `accounts` whose entries match the
//         single-account shape (or contain {address, privkey_hex}):
//         plaintext-batch
//   * Anything else: "unknown" — recorded but skipped from the address
//     extraction. By default unknown rows are still listed (so the operator
//     can see what's in the dir); the `--include-encrypted` and
//     `--include-plaintext` flags only gate the keyfile-typed rows.
//
// Encrypted keyfile metadata mirrors `keyfile-info`: header_tag (the
// "DETERM-NODE-V1" magic), pbkdf2_iters, salt_hex, nonce_hex. No decrypt is
// performed, so this is safe to run on a directory of production keyfiles
// without passphrases on hand.
//
// File mode reporting:
//   * On POSIX: rwx triplet rendered as a 4-digit octal ("0600", "0644",
//     etc.). The "0600" string is the security-critical value for plaintext
//     keyfiles — anything else triggers a `mode_not_0600` warning.
//   * On Windows: NTFS doesn't have a Unix-style mode bit; we report "n/a"
//     and skip the mode_not_0600 warning entirely (operator hygiene there
//     is enforced via NTFS ACL inheritance, not visible here).
//
// Summary warnings:
//   * mode_not_0600 — any plaintext keyfile on POSIX with mode != 0600.
//   * mixed_encrypted_and_plaintext_in_same_dir — operator hygiene; a single
//     directory containing both encrypted node keyfiles and plaintext
//     account JSON probably represents an accidental cross-contamination.
//
// CLI:
//   --keyfiles-dir <path>     REQUIRED. Directory to enumerate.
//   --recursive               Walk subdirectories (default off).
//   --include-encrypted       Include encrypted keyfiles (default on).
//   --include-plaintext       Include plaintext single + batch (default on).
//   --json                    JSON output (default on — only the default
//                             output shape is documented; non-JSON form is
//                             not provided).
//   --help                    Print usage and exit 0.
//
// Negation forms `--include-encrypted=off` and `--include-plaintext=off`
// (and equivalently `--no-include-encrypted` / `--no-include-plaintext`)
// disable the respective inclusion. The flags are independent: turning
// both off yields a summary-only output with an empty keyfiles array.
//
// Exit codes:
//   0  success
//   1  bad args, missing directory, unreadable directory
int cmd_account_list(int argc, char** argv) {
    std::string keyfiles_dir;
    bool recursive          = false;
    bool include_encrypted  = true;
    bool include_plaintext  = true;
    bool json_out           = true;  // default on per spec

    auto parse_onoff = [](const std::string& v, bool& out) -> bool {
        if (v == "on" || v == "1" || v == "true" || v == "yes")  { out = true;  return true; }
        if (v == "off"|| v == "0" || v == "false"|| v == "no")   { out = false; return true; }
        return false;
    };

    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--keyfiles-dir" && i + 1 < argc) keyfiles_dir = argv[++i];
        else if (a == "--recursive")                    recursive = true;
        else if (a == "--include-encrypted")            include_encrypted = true;
        else if (a == "--no-include-encrypted")         include_encrypted = false;
        else if (a.rfind("--include-encrypted=", 0) == 0) {
            if (!parse_onoff(a.substr(20), include_encrypted)) {
                std::cerr << "account-list: --include-encrypted= must be on|off (got '"
                          << a.substr(20) << "')\n";
                return 1;
            }
        }
        else if (a == "--include-plaintext")            include_plaintext = true;
        else if (a == "--no-include-plaintext")         include_plaintext = false;
        else if (a.rfind("--include-plaintext=", 0) == 0) {
            if (!parse_onoff(a.substr(20), include_plaintext)) {
                std::cerr << "account-list: --include-plaintext= must be on|off (got '"
                          << a.substr(20) << "')\n";
                return 1;
            }
        }
        else if (a == "--json")                         json_out = true;
        else if (a == "--no-json")                      json_out = false;
        else if (a == "--help" || a == "-h") {
            std::cout <<
                "Usage: determ-wallet account-list --keyfiles-dir <path> "
                "[--recursive] [--include-encrypted[=on|off]] "
                "[--include-plaintext[=on|off]] [--json] [--help]\n"
                "\n"
                "Enumerate keyfiles in a directory and emit per-file\n"
                "metadata (type, address(es), file size, mode). Pure local\n"
                "computation; no daemon RPC; no decryption.\n"
                "\n"
                "Detected types:\n"
                "  plaintext-single             {\"address\":..., \"privkey_hex\":...}\n"
                "  plaintext-batch              {\"accounts\":[{\"address\":..., ...}, ...]}\n"
                "  encrypted-DETERM-NODE-V1     2-line: header + DWE1 envelope\n"
                "  unknown                      neither JSON nor canonical keyfile\n"
                "\n"
                "Summary warnings:\n"
                "  mode_not_0600                       plaintext keyfile with mode != 0600 (POSIX)\n"
                "  mixed_encrypted_and_plaintext_in_same_dir  hygiene flag\n";
            return 0;
        }
        else {
            std::cerr << "account-list: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-list --keyfiles-dir <path> "
                         "[--recursive] [--include-encrypted[=on|off]] "
                         "[--include-plaintext[=on|off]] [--json] [--help]\n";
            return 1;
        }
    }

    if (keyfiles_dir.empty()) {
        std::cerr << "account-list: --keyfiles-dir is required\n";
        std::cerr << "Usage: determ-wallet account-list --keyfiles-dir <path> "
                     "[--recursive] [--include-encrypted[=on|off]] "
                     "[--include-plaintext[=on|off]] [--json] [--help]\n";
        return 1;
    }

    std::error_code ec;
    if (!std::filesystem::exists(keyfiles_dir, ec) || ec) {
        std::cerr << "account-list: --keyfiles-dir does not exist: "
                  << keyfiles_dir << "\n";
        return 1;
    }
    if (!std::filesystem::is_directory(keyfiles_dir, ec) || ec) {
        std::cerr << "account-list: --keyfiles-dir is not a directory: "
                  << keyfiles_dir << "\n";
        return 1;
    }

    // ── Helper: render file mode as a 4-digit octal string ─────────────────
    // On POSIX we read st_mode permission bits and emit "0600" et al.
    // On Windows std::filesystem::permissions returns the read/write/execute
    // synthesized triplet which does not reflect NTFS ACL; rather than
    // emitting a misleading "0666", we report "n/a" so the warning logic
    // skips the mode_not_0600 check there.
    auto file_mode_str = [](const std::filesystem::path& p) -> std::string {
#ifdef _WIN32
        (void)p;
        return "n/a";
#else
        std::error_code mec;
        auto perms = std::filesystem::status(p, mec).permissions();
        if (mec) return "n/a";
        unsigned v = 0;
        using std::filesystem::perms;
        if ((perms & perms::owner_read)   != perms::none) v |= 0400;
        if ((perms & perms::owner_write)  != perms::none) v |= 0200;
        if ((perms & perms::owner_exec)   != perms::none) v |= 0100;
        if ((perms & perms::group_read)   != perms::none) v |= 0040;
        if ((perms & perms::group_write)  != perms::none) v |= 0020;
        if ((perms & perms::group_exec)   != perms::none) v |= 0010;
        if ((perms & perms::others_read)  != perms::none) v |= 0004;
        if ((perms & perms::others_write) != perms::none) v |= 0002;
        if ((perms & perms::others_exec)  != perms::none) v |= 0001;
        char buf[8]{};
        std::snprintf(buf, sizeof(buf), "%04o", v);
        return std::string(buf);
#endif
    };

    // ── Helper: validate "0x" + 64 lowercase hex (anon-address shape) ──────
    auto is_anon_address = [](const std::string& s) -> bool {
        if (s.size() != 66) return false;
        if (s[0] != '0' || s[1] != 'x') return false;
        for (size_t i = 2; i < s.size(); ++i) {
            char c = s[i];
            bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex) return false;
        }
        return true;
    };

    // ── Helper: classify a single file ─────────────────────────────────────
    // Returns a JSON record per the output schema. The "type" field is
    // always present; type-specific fields follow. Errors during read are
    // recorded as type="unknown" with a "skip_reason" field; the caller
    // decides whether to include them in the output array.
    auto classify = [&](const std::filesystem::path& path) -> nlohmann::json {
        nlohmann::json rec;
        // Canonicalize the path for the output. lexically_normal keeps it
        // readable across platforms; the generic_string() form uses forward
        // slashes uniformly (matters on Windows for test grep-ability).
        rec["path"] = path.lexically_normal().generic_string();
        std::error_code sec;
        auto sz = std::filesystem::file_size(path, sec);
        rec["size_bytes"] = sec ? 0 : static_cast<uint64_t>(sz);
        rec["mode"] = file_mode_str(path);

        // Read up to 16 MB. Anything larger isn't plausibly a wallet
        // keyfile (largest plaintext-batch caps at 10_000 accounts ~ 1.5 MB;
        // encrypted envelope is two lines under 2 KB).
        constexpr std::uintmax_t MAX_READ = 16 * 1024 * 1024;
        if (rec["size_bytes"].get<uint64_t>() > MAX_READ) {
            rec["type"] = "unknown";
            rec["skip_reason"] = "file_too_large";
            return rec;
        }
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            rec["type"] = "unknown";
            rec["skip_reason"] = "open_failed";
            return rec;
        }
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());

        // ── Detection #1: encrypted DETERM-NODE-V1 (2-line text format) ────
        // The header magic is a tight prefix match; we only treat the file
        // as encrypted if the header is well-formed AND the second line
        // deserializes as a DWE1 envelope. Anything else falls through to
        // the JSON detector.
        const std::string header_magic = "DETERM-NODE-V1 ";
        if (content.size() > header_magic.size()
            && content.compare(0, header_magic.size(), header_magic) == 0) {
            // Split on first newline.
            auto nl = content.find('\n');
            if (nl != std::string::npos) {
                std::string header_line = content.substr(0, nl);
                while (!header_line.empty()
                       && (header_line.back() == '\r' || header_line.back() == '\n'))
                    header_line.pop_back();
                // Find the blob line (skip the LF + take until next LF or EOF).
                std::string blob_line;
                auto rest_start = nl + 1;
                auto nl2 = content.find('\n', rest_start);
                if (nl2 == std::string::npos) blob_line = content.substr(rest_start);
                else                          blob_line = content.substr(rest_start,
                                                                          nl2 - rest_start);
                while (!blob_line.empty()
                       && (blob_line.back() == '\r' || blob_line.back() == '\n'))
                    blob_line.pop_back();

                std::string pubkey_hex = header_line.substr(header_magic.size());
                bool hdr_pub_ok = (pubkey_hex.size() == 64);
                if (hdr_pub_ok) {
                    try { (void)from_hex(pubkey_hex); }
                    catch (...) { hdr_pub_ok = false; }
                }
                auto env_opt = envelope::deserialize(blob_line);
                if (hdr_pub_ok && env_opt) {
                    rec["type"]         = "encrypted-DETERM-NODE-V1";
                    rec["header_tag"]   = "DETERM-NODE-V1";
                    rec["pubkey_hex"]   = pubkey_hex;
                    rec["address"]      = "0x" + pubkey_hex;
                    rec["pbkdf2_iters"] = env_opt->pbkdf2_iters;
                    rec["salt_hex"]     = to_hex(env_opt->salt);
                    rec["nonce_hex"]    = to_hex(env_opt->nonce);
                    return rec;
                }
                // Header looked like ours but the envelope failed — fall
                // through to "unknown". An operator-friendly skip_reason
                // helps debug accidentally-corrupted keyfiles.
                rec["type"]        = "unknown";
                rec["skip_reason"] = "encrypted_keyfile_malformed";
                return rec;
            }
        }

        // ── Detection #2: plaintext JSON shapes (single + batch) ───────────
        nlohmann::json doc;
        try {
            doc = nlohmann::json::parse(content);
        } catch (...) {
            rec["type"]        = "unknown";
            rec["skip_reason"] = "not_json";
            return rec;
        }

        // Single-account shape: top-level {address, privkey_hex} strings.
        if (doc.is_object()
            && doc.contains("address") && doc["address"].is_string()
            && doc.contains("privkey_hex") && doc["privkey_hex"].is_string()
            && is_anon_address(doc["address"].get<std::string>())) {
            rec["type"]    = "plaintext-single";
            rec["address"] = doc["address"].get<std::string>();
            return rec;
        }

        // Batch shape: top-level {accounts: [{address, privkey_hex}, ...]}.
        // Matches account-create-batch / account-derive-batch output. We
        // accept either pure single-account entries or the derive-batch
        // shape that adds an "index" field (so account-derive-batch output
        // is recognized too).
        if (doc.is_object() && doc.contains("accounts")
            && doc["accounts"].is_array()) {
            nlohmann::json addrs = nlohmann::json::array();
            bool all_ok = true;
            for (const auto& a : doc["accounts"]) {
                if (!a.is_object()
                    || !a.contains("address") || !a["address"].is_string()) {
                    all_ok = false; break;
                }
                std::string addr = a["address"].get<std::string>();
                if (!is_anon_address(addr)) { all_ok = false; break; }
                addrs.push_back(addr);
            }
            if (all_ok && !addrs.empty()) {
                rec["type"]      = "plaintext-batch";
                rec["addresses"] = std::move(addrs);
                return rec;
            }
        }

        // ── Detection #3: pubkey/priv_seed shape (decrypted node keyfile) ──
        // This is the plaintext form keyfile-decrypt emits — it matches
        // src/crypto/keys.cpp::save_node_key. Treat it as plaintext-single
        // with the derived anon-address ("0x" + pubkey_hex). We DON'T require
        // priv_seed to validate; the type is determined by the pubkey field.
        if (doc.is_object()
            && doc.contains("pubkey") && doc["pubkey"].is_string()
            && doc.contains("priv_seed") && doc["priv_seed"].is_string()
            && doc["pubkey"].get<std::string>().size() == 64) {
            std::string pub = doc["pubkey"].get<std::string>();
            bool pub_hex_ok = true;
            try { (void)from_hex(pub); } catch (...) { pub_hex_ok = false; }
            if (pub_hex_ok) {
                rec["type"]    = "plaintext-single";
                rec["address"] = "0x" + pub;
                return rec;
            }
        }

        rec["type"]        = "unknown";
        rec["skip_reason"] = "json_shape_not_recognized";
        return rec;
    };

    // ── Walk the directory ─────────────────────────────────────────────────
    std::vector<nlohmann::json> entries;
    entries.reserve(64);

    auto walk = [&](auto&& self, const std::filesystem::path& root, bool rec) -> void {
        std::error_code wec;
        std::filesystem::directory_iterator it(root, wec);
        if (wec) return;
        for (auto end = std::filesystem::directory_iterator{}; it != end;
             it.increment(wec)) {
            if (wec) break;
            const auto& entry = *it;
            std::error_code tec;
            if (entry.is_regular_file(tec) && !tec) {
                entries.push_back(classify(entry.path()));
            } else if (rec && entry.is_directory(tec) && !tec) {
                self(self, entry.path(), rec);
            }
        }
    };
    walk(walk, std::filesystem::path(keyfiles_dir), recursive);

    // Deterministic order — sort by path so the output is stable across
    // platforms regardless of the directory iterator's order. Operator
    // diffs and regression tests depend on this.
    std::sort(entries.begin(), entries.end(),
              [](const nlohmann::json& a, const nlohmann::json& b) {
                  return a.value("path", "") < b.value("path", "");
              });

    // ── Filter per --include-* flags and tally ─────────────────────────────
    std::map<std::string, int> by_type;
    int n_addresses                 = 0;
    int n_encrypted_kept            = 0;
    int n_plaintext_kept            = 0;
    int n_plaintext_mode_violations = 0;
    bool encrypted_seen_anywhere    = false;
    bool plaintext_seen_anywhere    = false;

    nlohmann::json kept = nlohmann::json::array();
    for (const auto& e : entries) {
        std::string t = e.value("type", "unknown");
        if (t == "encrypted-DETERM-NODE-V1") {
            encrypted_seen_anywhere = true;
            if (!include_encrypted) continue;
            ++n_encrypted_kept;
            by_type[t] += 1;
            ++n_addresses;
        } else if (t == "plaintext-single") {
            plaintext_seen_anywhere = true;
            if (!include_plaintext) continue;
            ++n_plaintext_kept;
            by_type[t] += 1;
            ++n_addresses;
            // Mode warning: only meaningful on POSIX. "n/a" mode means
            // Windows; skip the check there (NTFS ACL is the real gate).
            std::string m = e.value("mode", "n/a");
            if (m != "n/a" && m != "0600") ++n_plaintext_mode_violations;
        } else if (t == "plaintext-batch") {
            plaintext_seen_anywhere = true;
            if (!include_plaintext) continue;
            ++n_plaintext_kept;
            by_type[t] += 1;
            if (e.contains("addresses") && e["addresses"].is_array())
                n_addresses += static_cast<int>(e["addresses"].size());
            std::string m = e.value("mode", "n/a");
            if (m != "n/a" && m != "0600") ++n_plaintext_mode_violations;
        } else {
            // "unknown" — always include (operator wants to see what's there)
            by_type[t] += 1;
        }
        kept.push_back(e);
    }

    nlohmann::json by_type_obj = nlohmann::json::object();
    for (const auto& kv : by_type) by_type_obj[kv.first] = kv.second;

    nlohmann::json warnings = nlohmann::json::array();
    if (n_plaintext_mode_violations > 0) warnings.push_back("mode_not_0600");
    if (encrypted_seen_anywhere && plaintext_seen_anywhere)
        warnings.push_back("mixed_encrypted_and_plaintext_in_same_dir");

    nlohmann::json out;
    out["keyfiles_dir"] = std::filesystem::path(keyfiles_dir)
                              .lexically_normal().generic_string();
    out["recursive"]    = recursive;
    out["keyfiles"]     = std::move(kept);
    nlohmann::json summary;
    summary["total_files"]  = static_cast<int>(out["keyfiles"].size());
    summary["by_type"]      = std::move(by_type_obj);
    summary["n_addresses"]  = n_addresses;
    summary["warnings"]     = std::move(warnings);
    out["summary"]          = std::move(summary);

    if (json_out) {
        std::cout << out.dump(2) << "\n";
    } else {
        // Compact non-JSON fallback for ad-hoc terminal use. The default is
        // JSON per spec; this branch only fires when --no-json is passed.
        std::cout << "keyfiles_dir: " << out["keyfiles_dir"].get<std::string>()
                  << "  (recursive=" << (recursive ? "true" : "false") << ")\n";
        for (const auto& e : out["keyfiles"]) {
            std::cout << "  " << e.value("path", "") << "  type="
                      << e.value("type", "?");
            if (e.contains("address"))
                std::cout << "  address=" << e["address"].get<std::string>();
            if (e.contains("addresses"))
                std::cout << "  n_addresses="
                          << e["addresses"].size();
            std::cout << "  mode=" << e.value("mode", "n/a")
                      << "  size=" << e.value("size_bytes", uint64_t(0));
            std::cout << "\n";
        }
        std::cout << "summary: total_files="
                  << out["summary"]["total_files"].get<int>()
                  << "  n_addresses="
                  << out["summary"]["n_addresses"].get<int>();
        if (!out["summary"]["warnings"].empty()) {
            std::cout << "  warnings=";
            bool first = true;
            for (const auto& w : out["summary"]["warnings"]) {
                if (!first) std::cout << ",";
                std::cout << w.get<std::string>();
                first = false;
            }
        }
        std::cout << "\n";
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

// Read a `--message <spec>` arg. The spec is either an inline string or
// "file:<path>" to slurp the file's bytes verbatim (binary-safe — no UTF-8
// validation, no newline stripping). Returns false on file-open failure.
//
// Why support file input: message-signing workflows often deal with
// content too large for a command-line arg (full attestation JSON, signed
// release manifest, large SIWE challenge bodies) or that contains shell-
// hostile bytes (NUL, embedded quotes). The `file:` prefix lets operators
// keep the message verbatim in a file and pass the path; the file's
// content is hashed byte-for-byte exactly as it sits on disk.
//
// Newline handling: NO trimming. If an operator wrote the message with
// `echo "foo" > msg.txt`, the trailing '\n' is part of the signed
// content. This is by design — domain-separation only guarantees no
// cross-domain replay; within a domain, callers control the canonical
// byte form.
bool read_message_spec(const std::string& spec,
                       std::vector<uint8_t>& out_bytes,
                       std::string& err) {
    constexpr const char* kFilePrefix = "file:";
    if (spec.size() >= 5 && spec.compare(0, 5, kFilePrefix) == 0) {
        std::string path = spec.substr(5);
        if (path.empty()) {
            err = "--message file: prefix supplied without a path";
            return false;
        }
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            err = std::string("cannot open --message file: ") + path;
            return false;
        }
        std::vector<uint8_t> buf(
            (std::istreambuf_iterator<char>(f)),
             std::istreambuf_iterator<char>());
        out_bytes = std::move(buf);
        return true;
    }
    // Inline string. Bytes are exactly the literal arg passed by the shell.
    out_bytes.assign(spec.begin(), spec.end());
    return true;
}

// Compute the 32-byte SHA-256 commitment that gets signed.
//
// Domain-separation: the hashed pre-image is `domain_tag_bytes || message_bytes`.
// The domain_tag is UTF-8 bytes of the arg as-is (the operator picks the
// canonical form; we don't normalize). Concatenation, not HMAC, because:
//   * the goal is replay-prevention across domains, not authentication of
//     the tag itself (we already authenticate via the Ed25519 signature
//     over the entire pre-image);
//   * SHA-256(tag || msg) is collision-equivalent to (tag, msg) at the
//     security level of SHA-256 — second-preimage resistance dominates;
//   * the protocol-wide convention is SHA-256 + concatenation (matches
//     the `signing_bytes` pattern in PROTOCOL.md).
//
// Length-extension is not a concern here: we never expose the SHA-256
// state, only its final 32-byte digest fed into Ed25519, which is
// itself a hash-and-sign scheme — no raw SHA-256 output is ever
// returned to a third party who could then forge a longer pre-image.
std::array<uint8_t, 32> domain_commit(const std::string& domain_tag,
                                      const std::vector<uint8_t>& msg) {
    std::vector<uint8_t> buf;
    buf.reserve(domain_tag.size() + msg.size());
    buf.insert(buf.end(), domain_tag.begin(), domain_tag.end());
    buf.insert(buf.end(), msg.begin(),        msg.end());
    std::array<uint8_t, 32> out{};
    SHA256(buf.data(), buf.size(), out.data());
    return out;
}

// determ-wallet message-sign — Sign an arbitrary message with an Ed25519
// private key, using a domain-separated SHA-256 commitment as the
// signed pre-image.
//
// Use cases (all OFF-CHAIN — this CLI does NOT produce a transaction):
//   * SIWE-style ("Sign-In With Ethereum") auth challenges, where a
//     web/dapp service issues a nonce and the wallet signs it to prove
//     control of an account address.
//   * Off-chain attestations (operator-signed announcements, version
//     manifests, release artifacts) where a verifier wants to confirm
//     a specific party endorsed a specific message.
//   * Pre-image binding for ZK proofs or commit-reveal protocols where
//     the signed value is later revealed in another protocol step.
//
// Domain separation rationale:
//   A raw Ed25519 signature over `H(message)` would be replay-vulnerable
//   across context: a signature collected for "I authorize transfer X"
//   would validate as "I attest to chain state Y" if both contexts share
//   the same hash. Prepending an unambiguous domain tag before hashing
//   ensures the same message bytes in different domains produce different
//   commitments. Operators pick the tag (e.g. "siwe", "attestation",
//   "op-announcement"); verifiers MUST agree on the tag a priori.
//
// Signed pre-image: SHA-256(domain_tag_utf8_bytes || message_bytes)
// Output: 64-byte Ed25519 signature, hex-encoded (128 chars).
//
// CLI:
//   --priv <hex>:       32-byte Ed25519 seed (64 hex chars). Matches the
//                       `privkey_hex` field emitted by `account create`
//                       or `account-create-batch`.
//   --message <spec>:   inline string OR "file:<path>" to read bytes from
//                       a file. File mode is binary-safe (no newline strip).
//   --domain-tag <tag>: arbitrary domain-separation tag (typically a short
//                       ASCII slug). Required — there's no sensible default.
//   --json:             emit a JSON document instead of human lines.
//
// Output:
//   Human mode (default):
//     signature_hex:    <128 hex chars>
//     pubkey_hex:       <64 hex chars derived from the priv seed>
//     message_hash_hex: <64 hex chars = SHA-256 commitment>
//     domain_tag:       <tag verbatim>
//   --json mode:
//     {"signature_hex": "...", "pubkey_hex": "...",
//      "message_hash_hex": "...", "domain_tag": "..."}
//
// Exit codes:
//   0  signature emitted
//   1  args / parse / libsodium-init error
int cmd_message_sign(int argc, char** argv) {
    std::string priv_hex, message_spec, domain_tag;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv"       && i + 1 < argc) priv_hex     = argv[++i];
        else if (a == "--message"    && i + 1 < argc) message_spec = argv[++i];
        else if (a == "--domain-tag" && i + 1 < argc) domain_tag   = argv[++i];
        else if (a == "--json")                       json_out     = true;
        else {
            std::cerr << "message-sign: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet message-sign --priv <hex> "
                         "--message <string|file:path> --domain-tag <tag> [--json]\n";
            return 1;
        }
    }
    if (priv_hex.empty() || message_spec.empty() || domain_tag.empty()) {
        std::cerr << "Usage: determ-wallet message-sign --priv <hex> "
                     "--message <string|file:path> --domain-tag <tag> [--json]\n"
                     "\n"
                     "  Signs message with an Ed25519 private key using a\n"
                     "  domain-separated SHA-256 commitment as the signed\n"
                     "  pre-image: H = SHA-256(domain_tag || message_bytes).\n"
                     "  This is OFF-CHAIN signing — does not produce a tx.\n";
        return 1;
    }

    // Decode the priv seed (must be exactly 32 bytes = 64 hex chars).
    if (priv_hex.size() != 64) {
        std::cerr << "message-sign: --priv must be exactly 64 hex chars "
                     "(32-byte Ed25519 seed); got " << priv_hex.size() << " chars\n";
        return 1;
    }
    std::vector<uint8_t> priv_seed;
    try { priv_seed = from_hex(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "message-sign: invalid --priv hex: " << e.what() << "\n";
        return 1;
    }
    if (priv_seed.size() != 32) {
        std::cerr << "message-sign: --priv decoded to " << priv_seed.size()
                  << " bytes (expected 32)\n";
        return 1;
    }

    // Load the message bytes (inline or file).
    std::vector<uint8_t> msg;
    {
        std::string err;
        if (!read_message_spec(message_spec, msg, err)) {
            std::cerr << "message-sign: " << err << "\n";
            return 1;
        }
    }
    // Empty message is permitted (an attestation might sign just the
    // domain tag itself — a "I am present in domain X" beacon).

    // Init libsodium (idempotent; safe to call repeatedly).
    if (!primitives::init_libsodium()) {
        std::cerr << "message-sign: libsodium init failed\n";
        return 1;
    }

    // Derive the Ed25519 keypair from the 32-byte seed. libsodium's
    // crypto_sign_detached needs the 64-byte secret key (seed || pubkey);
    // crypto_sign_seed_keypair fills both pubkey and sk from the seed.
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pub{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    static_assert(crypto_sign_PUBLICKEYBYTES == 32, "Ed25519 pk size mismatch");
    static_assert(crypto_sign_SECRETKEYBYTES == 64, "Ed25519 sk size mismatch");
    static_assert(crypto_sign_SEEDBYTES      == 32, "Ed25519 seed size mismatch");
    if (crypto_sign_seed_keypair(pub.data(), sk.data(), priv_seed.data()) != 0) {
        std::cerr << "message-sign: crypto_sign_seed_keypair failed\n";
        return 1;
    }

    // Compute the domain-separated commitment.
    auto hash = domain_commit(domain_tag, msg);

    // Sign the commitment with crypto_sign_detached (deterministic per
    // RFC 8032 — no nonce input, same priv+msg always yields same sig).
    std::array<uint8_t, crypto_sign_BYTES> sig{};
    static_assert(crypto_sign_BYTES == 64, "Ed25519 sig size mismatch");
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(sig.data(), &sig_len,
                              hash.data(), hash.size(),
                              sk.data()) != 0) {
        std::cerr << "message-sign: crypto_sign_detached failed\n";
        return 1;
    }
    if (sig_len != crypto_sign_BYTES) {
        std::cerr << "message-sign: unexpected sig length " << sig_len << "\n";
        return 1;
    }

    // Zero the secret-key buffer before returning. The seed remains in
    // priv_seed (operator-supplied), but the libsodium-derived sk
    // contains the seed concatenated with the pubkey; sodium_memzero
    // is the libsodium-blessed scrub.
    sodium_memzero(sk.data(), sk.size());

    if (json_out) {
        nlohmann::json r;
        r["signature_hex"]    = to_hex(sig);
        r["pubkey_hex"]       = to_hex(pub);
        r["message_hash_hex"] = to_hex(hash);
        r["domain_tag"]       = domain_tag;
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "signature_hex:    " << to_hex(sig)  << "\n";
        std::cout << "pubkey_hex:       " << to_hex(pub)  << "\n";
        std::cout << "message_hash_hex: " << to_hex(hash) << "\n";
        std::cout << "domain_tag:       " << domain_tag   << "\n";
    }
    return 0;
}

// determ-wallet message-verify — Verify an Ed25519 signature over a
// domain-separated SHA-256 commitment of a message.
//
// Inverse of message-sign. Verifier reconstructs the same commitment
// (SHA-256(domain_tag || message_bytes)) and checks crypto_sign_verify_detached
// against the supplied pubkey.
//
// CLI:
//   --pubkey <hex>:     32-byte Ed25519 public key (64 hex chars).
//   --message <spec>:   inline string OR "file:<path>" — same convention as
//                       message-sign. Must be byte-identical to what was signed.
//   --domain-tag <tag>: MUST exactly match the tag used at sign time.
//                       Any deviation produces a different commitment and
//                       the signature fails to verify (the protective property).
//   --signature <hex>:  128 hex chars (64-byte Ed25519 sig).
//   --json:             emit a JSON document instead of human "valid: ..." text.
//
// Exit codes:
//   0  signature valid (PASS)
//   1  args / parse error (operator error, not auth failure)
//   2  signature invalid — auth-style alert gate (distinct from arg errors
//      so monitoring scripts can branch on auth-fail vs. tooling-fail)
//
// Why exit 2 for invalid: matches the convention used by envelope decrypt
// and inspect-envelope when the artifact is structurally fine but
// authentication fails. Exit-1-for-everything would force every consumer
// to grep stderr to distinguish "bad args" from "signature rejected."
int cmd_message_verify(int argc, char** argv) {
    std::string pubkey_hex, message_spec, domain_tag, signature_hex;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--pubkey"     && i + 1 < argc) pubkey_hex     = argv[++i];
        else if (a == "--message"    && i + 1 < argc) message_spec   = argv[++i];
        else if (a == "--domain-tag" && i + 1 < argc) domain_tag     = argv[++i];
        else if (a == "--signature"  && i + 1 < argc) signature_hex  = argv[++i];
        else if (a == "--json")                       json_out       = true;
        else {
            std::cerr << "message-verify: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet message-verify --pubkey <hex> "
                         "--message <string|file:path> --domain-tag <tag> "
                         "--signature <hex> [--json]\n";
            return 1;
        }
    }
    if (pubkey_hex.empty() || message_spec.empty()
        || domain_tag.empty() || signature_hex.empty()) {
        std::cerr << "Usage: determ-wallet message-verify --pubkey <hex> "
                     "--message <string|file:path> --domain-tag <tag> "
                     "--signature <hex> [--json]\n"
                     "\n"
                     "  Verifies an Ed25519 signature was produced over\n"
                     "  H = SHA-256(domain_tag || message_bytes). Inverse of\n"
                     "  message-sign. Exit 0 = valid, 2 = invalid (auth-style\n"
                     "  alert), 1 = args/parse error.\n";
        return 1;
    }

    if (pubkey_hex.size() != 64) {
        std::cerr << "message-verify: --pubkey must be exactly 64 hex chars "
                     "(32-byte Ed25519 pubkey); got " << pubkey_hex.size() << "\n";
        return 1;
    }
    if (signature_hex.size() != 128) {
        std::cerr << "message-verify: --signature must be exactly 128 hex chars "
                     "(64-byte Ed25519 signature); got "
                  << signature_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> pub_bytes, sig_bytes;
    try { pub_bytes = from_hex(pubkey_hex);    }
    catch (std::exception& e) {
        std::cerr << "message-verify: invalid --pubkey hex: " << e.what() << "\n";
        return 1;
    }
    try { sig_bytes = from_hex(signature_hex); }
    catch (std::exception& e) {
        std::cerr << "message-verify: invalid --signature hex: " << e.what() << "\n";
        return 1;
    }
    if (pub_bytes.size() != 32) {
        std::cerr << "message-verify: pubkey decoded to " << pub_bytes.size()
                  << " bytes (expected 32)\n";
        return 1;
    }
    if (sig_bytes.size() != 64) {
        std::cerr << "message-verify: signature decoded to " << sig_bytes.size()
                  << " bytes (expected 64)\n";
        return 1;
    }

    std::vector<uint8_t> msg;
    {
        std::string err;
        if (!read_message_spec(message_spec, msg, err)) {
            std::cerr << "message-verify: " << err << "\n";
            return 1;
        }
    }

    if (!primitives::init_libsodium()) {
        std::cerr << "message-verify: libsodium init failed\n";
        return 1;
    }

    auto hash = domain_commit(domain_tag, msg);

    // crypto_sign_verify_detached returns 0 on valid, -1 on invalid.
    // It is the constant-time verifier that should be used here.
    int rc = crypto_sign_verify_detached(sig_bytes.data(),
                                          hash.data(), hash.size(),
                                          pub_bytes.data());
    const bool valid = (rc == 0);

    if (json_out) {
        nlohmann::json r;
        r["valid"]            = valid;
        r["message_hash_hex"] = to_hex(hash);
        r["domain_tag"]       = domain_tag;
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "valid:            " << (valid ? "true" : "false") << "\n";
        std::cout << "message_hash_hex: " << to_hex(hash) << "\n";
        std::cout << "domain_tag:       " << domain_tag   << "\n";
    }
    return valid ? 0 : 2;
}

// determ-wallet tx-sign-verify — Verify the Ed25519 signature on a
// Transaction JSON file using the chain's CANONICAL signing_bytes scheme
// (NOT the off-chain domain-separated SHA-256 commitment used by
// message-sign / message-verify).
//
// Use cases:
//   * Operator receives a signed Transaction off the wire (RPC submit
//     queue, manual relay, off-chain batch packaging) and wants to
//     confirm the sig is valid before broadcasting / submitting.
//   * Inspect-before-submit: a signing-tier wallet hands a fully signed
//     tx to an operator who wants to verify byte-for-byte that the sig
//     binds the body fields they're about to broadcast.
//   * Forensic post-mortem: a tx was rejected at the validator; reproduce
//     the validator's verify call locally to confirm whether the sig was
//     malformed vs. some other validation gate failed.
//
// Distinction from message-sign / message-verify:
//   - message-sign signs SHA-256(domain_tag || message_bytes) for off-chain
//     uses (SIWE auth, attestations); the on-chain Transaction sig scheme
//     is a different, protocol-pinned canonical form. The two are NOT
//     interchangeable: a message-sign sig is NOT a valid tx sig and vice
//     versa, by design (cross-context replay prevention).
//
// Canonical signing_bytes layout (matches src/chain/block.cpp Transaction::signing_bytes):
//   [type:                u8 — TxType enum value]
//   [from:                utf8 bytes verbatim, NO len prefix]
//   [0x00:                NUL terminator separating from from to]
//   [to:                  utf8 bytes verbatim, NO len prefix]
//   [0x00:                NUL terminator after to]
//   [amount:              u64 BIG-ENDIAN (8 bytes, MSB first)]
//   [fee:                 u64 BIG-ENDIAN]
//   [nonce:               u64 BIG-ENDIAN]
//   [payload:             raw bytes (already-decoded hex from JSON)]
//
// Sender pubkey resolution:
//   The Transaction JSON does NOT carry the sender's pubkey explicitly
//   (the chain looks it up via the registry for domain senders, or
//   parses it out of the anon-address for anon senders). For this CLI,
//   we deliberately REQUIRE --pubkey to be supplied explicitly, because:
//     * The wallet binary has no chain registry to consult.
//     * Anon-address senders carry the pubkey IN their address (the
//       `0x` + 64 hex chars = the Ed25519 pubkey), but rather than
//       silently auto-derive we make the operator pass it explicitly —
//       this prevents an off-by-one-style mistake where the verifier
//       trusts the address-derived pubkey when the operator actually
//       meant to verify against a registry-bound key.
//     * Cross-binary surface invariant: --pubkey ALWAYS comes from
//       outside the JSON, so the verifier can't be fooled by a forged
//       JSON that names a different signer.
//
// CLI:
//   --tx <file>:     path to a JSON file containing a Transaction
//                    (fields: type, from, to, amount, fee, nonce,
//                    payload, sig, hash). The same shape `account-
//                    create-batch` test wrappers produce + the same
//                    shape `Transaction::to_json` emits.
//   --pubkey <hex>:  64 hex chars (32-byte Ed25519 pubkey) of the
//                    presumed signer. REQUIRED.
//   --json:          emit a JSON document; otherwise human lines.
//
// Output:
//   Human mode:
//     valid:                             true | false
//     tx_hash_hex:                       <64 hex chars>
//     computed_signing_bytes_sha256:     <64 hex chars>
//   --json mode:
//     {"valid": bool,
//      "tx_hash_hex": "<64 hex>",
//      "computed_signing_bytes_sha256": "<64 hex>"}
//
// Exit codes:
//   0  signature valid
//   1  args / parse / IO / JSON-shape / hex-decode error
//   2  signature invalid — auth-style alert (distinct from arg errors
//      so monitoring scripts can differentiate "bad input" from
//      "input shape is fine but the sig doesn't validate")
//
// Why exit 2 for invalid: matches the convention used by message-verify,
// keyfile-decrypt, envelope decrypt — all use 2 for "structurally fine,
// authentication failed."
//
// Output field rationale:
//   - `tx_hash_hex` is the SHA-256(signing_bytes) value the chain
//     computes as Transaction::compute_hash. This is the value that
//     appears as `hash` on the JSON and as the leaf in tx_root. We
//     compute + report it independently to let operators cross-check
//     the JSON-supplied `hash` field is consistent with the body.
//   - `computed_signing_bytes_sha256` is the same value (SHA-256 of
//     signing_bytes); it's exposed under a distinct field name so a
//     consumer that just wants "the hash of what was signed" can grab
//     it without conflating it with the tx's identity hash (they happen
//     to coincide for tx sigs, but that's a property of the scheme, not
//     a definition — message-verify's analogous field is named
//     message_hash_hex; keeping a parallel name keeps the JSON-shape
//     convention consistent).
int cmd_tx_sign_verify(int argc, char** argv) {
    std::string tx_path, pubkey_hex;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--tx"     && i + 1 < argc) tx_path    = argv[++i];
        else if (a == "--pubkey" && i + 1 < argc) pubkey_hex = argv[++i];
        else if (a == "--json")                   json_out   = true;
        else {
            std::cerr << "tx-sign-verify: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet tx-sign-verify --tx <file> "
                         "--pubkey <hex> [--json]\n";
            return 1;
        }
    }
    if (tx_path.empty() || pubkey_hex.empty()) {
        std::cerr << "Usage: determ-wallet tx-sign-verify --tx <file> "
                     "--pubkey <hex> [--json]\n"
                     "\n"
                     "  Verifies the Ed25519 sig on a Transaction JSON file\n"
                     "  using the chain's canonical signing_bytes scheme\n"
                     "  (matches src/chain/block.cpp Transaction::signing_bytes).\n"
                     "  Distinct from message-sign (off-chain domain-separated\n"
                     "  scheme). Exit 0 valid, 2 invalid (auth-style alert),\n"
                     "  1 args/parse/IO error.\n";
        return 1;
    }

    if (pubkey_hex.size() != 64) {
        std::cerr << "tx-sign-verify: --pubkey must be exactly 64 hex chars "
                     "(32-byte Ed25519 pubkey); got " << pubkey_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> pub_bytes;
    try { pub_bytes = from_hex(pubkey_hex); }
    catch (std::exception& e) {
        std::cerr << "tx-sign-verify: invalid --pubkey hex: " << e.what() << "\n";
        return 1;
    }
    if (pub_bytes.size() != 32) {
        std::cerr << "tx-sign-verify: --pubkey decoded to " << pub_bytes.size()
                  << " bytes (expected 32)\n";
        return 1;
    }

    // Read and parse the Transaction JSON. We do the parse here rather than
    // delegating to determ::chain::Transaction::from_json because we want
    // the wallet binary to stay decoupled from the chain library (the
    // wallet target deliberately doesn't link against the chain lib in
    // CMakeLists.txt — separation-of-concerns; wallet handles secrets,
    // chain handles consensus). Re-encoding signing_bytes in ~20 lines
    // here is the cheaper trade-off vs. dragging the chain lib into the
    // wallet's TCB.
    std::ifstream tx_f(tx_path);
    if (!tx_f) {
        std::cerr << "tx-sign-verify: cannot open --tx file: " << tx_path << "\n";
        return 1;
    }
    nlohmann::json j;
    try { tx_f >> j; }
    catch (std::exception& e) {
        std::cerr << "tx-sign-verify: --tx file is not valid JSON: " << e.what() << "\n";
        return 1;
    }

    // Required fields. Treat missing or wrong-typed as a parse error
    // (rc=1), not an auth failure (rc=2): the JSON shape is broken,
    // not the sig.
    int      tx_type;
    std::string from_str, to_str, payload_hex, sig_hex;
    uint64_t amount, fee, nonce;
    try {
        if (!j.contains("type")    || !j["type"].is_number())     throw std::runtime_error("missing/wrong-typed 'type' (expected integer)");
        if (!j.contains("from")    || !j["from"].is_string())     throw std::runtime_error("missing/wrong-typed 'from' (expected string)");
        if (!j.contains("to")      || !j["to"].is_string())       throw std::runtime_error("missing/wrong-typed 'to' (expected string)");
        if (!j.contains("amount")  || !j["amount"].is_number())   throw std::runtime_error("missing/wrong-typed 'amount' (expected integer)");
        if (!j.contains("nonce")   || !j["nonce"].is_number())    throw std::runtime_error("missing/wrong-typed 'nonce' (expected integer)");
        if (!j.contains("payload") || !j["payload"].is_string())  throw std::runtime_error("missing/wrong-typed 'payload' (expected hex string)");
        if (!j.contains("sig")     || !j["sig"].is_string())      throw std::runtime_error("missing/wrong-typed 'sig' (expected hex string)");

        tx_type     = j["type"].get<int>();
        from_str    = j["from"].get<std::string>();
        to_str      = j["to"].get<std::string>();
        amount      = j["amount"].get<uint64_t>();
        // `fee` is optional (matches chain's Transaction::from_json which
        // defaults to 0); the chain's signing_bytes always includes the
        // 8-byte fee field, so a missing JSON field == fee=0.
        fee         = j.value("fee", uint64_t{0});
        nonce       = j["nonce"].get<uint64_t>();
        payload_hex = j["payload"].get<std::string>();
        sig_hex     = j["sig"].get<std::string>();
    } catch (std::exception& e) {
        std::cerr << "tx-sign-verify: --tx JSON shape error: " << e.what() << "\n";
        return 1;
    }

    // Range-check the type byte. TxType is a u8 in the wire encoding;
    // values outside [0, 255] would corrupt the first byte of
    // signing_bytes silently. Reject them up front with a clean diagnostic.
    if (tx_type < 0 || tx_type > 255) {
        std::cerr << "tx-sign-verify: 'type' value " << tx_type
                  << " out of range (expected 0..255 for u8 wire encoding)\n";
        return 1;
    }

    // Decode the hex-encoded fields.
    std::vector<uint8_t> payload_bytes, sig_bytes;
    try { payload_bytes = from_hex(payload_hex); }
    catch (std::exception& e) {
        std::cerr << "tx-sign-verify: invalid 'payload' hex: " << e.what() << "\n";
        return 1;
    }
    if (sig_hex.size() != 128) {
        std::cerr << "tx-sign-verify: 'sig' must be exactly 128 hex chars "
                     "(64-byte Ed25519 signature); got " << sig_hex.size() << "\n";
        return 1;
    }
    try { sig_bytes = from_hex(sig_hex); }
    catch (std::exception& e) {
        std::cerr << "tx-sign-verify: invalid 'sig' hex: " << e.what() << "\n";
        return 1;
    }
    if (sig_bytes.size() != 64) {
        std::cerr << "tx-sign-verify: sig decoded to " << sig_bytes.size()
                  << " bytes (expected 64)\n";
        return 1;
    }

    // Reconstruct signing_bytes — byte-for-byte identical to what
    // src/chain/block.cpp Transaction::signing_bytes produces. Any drift
    // here would make every wallet-verified tx fail the chain's verify,
    // so the layout below is intentionally simple + reviewable.
    std::vector<uint8_t> sb;
    sb.reserve(1 + from_str.size() + 1 + to_str.size() + 1 + 24 + payload_bytes.size());
    sb.push_back(static_cast<uint8_t>(tx_type));
    sb.insert(sb.end(), from_str.begin(), from_str.end());
    sb.push_back(0);
    sb.insert(sb.end(), to_str.begin(), to_str.end());
    sb.push_back(0);
    // u64 BIG-ENDIAN encodings of amount / fee / nonce, in that order.
    // Chain code does the same shift-pattern (`(x >> (i*8)) & 0xFF` for
    // i = 7 down to 0). Keep the loops explicit rather than using a
    // helper — copy-paste hazard vs. one canonical reference.
    for (int i = 7; i >= 0; --i) sb.push_back((amount >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) sb.push_back((fee    >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) sb.push_back((nonce  >> (i * 8)) & 0xFF);
    sb.insert(sb.end(), payload_bytes.begin(), payload_bytes.end());

    // Compute SHA-256(signing_bytes) — this is BOTH the chain's
    // Transaction::compute_hash result (the value that appears as `hash`
    // in the JSON + as the tx_root leaf) AND the value we expose as
    // computed_signing_bytes_sha256 for the operator to cross-check.
    std::array<uint8_t, 32> sb_sha{};
    SHA256(sb.data(), sb.size(), sb_sha.data());

    // Init libsodium (idempotent) and verify the sig.
    if (!primitives::init_libsodium()) {
        std::cerr << "tx-sign-verify: libsodium init failed\n";
        return 1;
    }
    // crypto_sign_verify_detached signs/verifies the message bytes
    // directly (Ed25519 is hash-and-sign internally — it hashes with
    // SHA-512 as part of the algorithm). The chain's verify path
    // (src/crypto/keys.cpp::verify via EVP_DigestVerify on EVP_PKEY_ED25519)
    // does the same thing: both operate on the raw signing_bytes message,
    // NOT on a pre-hashed digest. A sig produced by either path is
    // verifiable by the other.
    int rc = crypto_sign_verify_detached(sig_bytes.data(),
                                          sb.data(), sb.size(),
                                          pub_bytes.data());
    const bool valid = (rc == 0);

    if (json_out) {
        nlohmann::json r;
        r["valid"]                          = valid;
        r["tx_hash_hex"]                    = to_hex(sb_sha);
        r["computed_signing_bytes_sha256"]  = to_hex(sb_sha);
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "valid:                          " << (valid ? "true" : "false") << "\n";
        std::cout << "tx_hash_hex:                    " << to_hex(sb_sha) << "\n";
        std::cout << "computed_signing_bytes_sha256:  " << to_hex(sb_sha) << "\n";
    }
    return valid ? 0 : 2;
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
        "  shamir-rotate --shares <file> --threshold T --shares-out <file>\n"
        "                [--force] [--json]\n"
        "                                             Proactive Secret Sharing (PSS) polynomial\n"
        "                                             refresh. Reconstructs the secret from >= T\n"
        "                                             input shares, then draws a FRESH polynomial\n"
        "                                             and emits a new share-set with the SAME N\n"
        "                                             and SAME x-coordinates. Old shares become\n"
        "                                             useless (different polynomial); new shares\n"
        "                                             reconstruct the SAME secret. Defense against\n"
        "                                             share leakage over time. Insufficient input\n"
        "                                             (< T) exits 2.\n"
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
        "  account-derive-batch --seed <hex>          DETERMINISTIC sibling of account-create-\n"
        "                       --count N            batch: derive N accounts from a single\n"
        "                       [--out <file>] [--json] [--force]\n"
        "                                             32-byte master seed (64 hex). Algorithm:\n"
        "                                             seed_i = SHA-256(master_seed || u32_le(i));\n"
        "                                             keypair_i = ed25519_seed_keypair(seed_i).\n"
        "                                             Same master seed always produces the same\n"
        "                                             accounts; different seeds produce disjoint\n"
        "                                             sets. Use for cold-wallet provisioning\n"
        "                                             from a single backed-up seed, reproducible\n"
        "                                             test fixtures, or recovery from a master\n"
        "                                             seed. Default human prints one line per\n"
        "                                             account; --out writes JSON file (0600)\n"
        "                                             with {master_seed_hash_hex, count,\n"
        "                                             accounts:[{index,address,privkey_hex}]}\n"
        "                                             (the master seed itself is NEVER emitted).\n"
        "                                             --json same JSON to stdout. 1<=N<=10000.\n"
        "  account-import --priv <hex>                Import an existing Ed25519 private key\n"
        "                 [--out <file>] [--force] [--json]\n"
        "                                             into the wallet's anon-account JSON\n"
        "                                             format (companion to account-create-\n"
        "                                             batch, which generates fresh keys).\n"
        "                                             --priv accepts 64 hex chars (32-byte\n"
        "                                             seed) or 128 hex chars (32-byte seed ||\n"
        "                                             32-byte pubkey); 64-byte form is\n"
        "                                             validated against the seed-derived\n"
        "                                             pubkey. --out writes the JSON to file\n"
        "                                             with 0600 perms (refuses overwrite\n"
        "                                             without --force); --json prints JSON to\n"
        "                                             stdout. Output shape (single account):\n"
        "                                             {\"address\":\"0x..\",\"privkey_hex\":\"..\"}.\n"
        "  account-export --in <file>                 Re-emit a single-account JSON file in\n"
        "                 [--format raw-hex|json|backup-bundle]\n"
        "                 [--out <file>] [--force] [--json]\n"
        "                                             one of three external formats:\n"
        "                                              * raw-hex (default) prints the 64-char\n"
        "                                                privkey hex on stdout (one line);\n"
        "                                              * json passes the input account JSON\n"
        "                                                through verbatim;\n"
        "                                              * backup-bundle emits a JSON envelope\n"
        "                                                {seed_hex, pubkey_hex, anon_address,\n"
        "                                                derived_at_utc} ready for\n"
        "                                                backup-create --secret <seed_hex>.\n"
        "                                             --out writes to file (0600; refuses\n"
        "                                             overwrite without --force). --json with\n"
        "                                             --format raw-hex wraps the hex in a\n"
        "                                             {\"privkey_hex\":\"...\"} JSON object.\n"
        "  backup-verify --shares <file> --envelopes <file> [--threshold T] [--json]\n"
        "                                             Composite structural verification of a\n"
        "                                             wallet backup (Shamir shares + per-share\n"
        "                                             AEAD envelopes). No decryption, no\n"
        "                                             password required. Shares file shape:\n"
        "                                             {\"shares\": [{\"x\": int, \"y_hex\": \"...\"}, ...]}.\n"
        "                                             Envelopes file shape:\n"
        "                                             {\"envelopes\": [{\"share_index\": int,\n"
        "                                             \"envelope_blob\": \"...\"}, ...]}.\n"
        "  backup-create --secret <hex> --threshold T --keyholders <file>\n"
        "                --shares-out <file> --envelopes-out <file> [--force] [--json]\n"
        "                                             Produce a complete wallet backup\n"
        "                                             (Shamir shares + per-share AEAD envelopes)\n"
        "                                             from a secret + per-keyholder passphrases.\n"
        "                                             Inverse of backup-verify (writes the two\n"
        "                                             files backup-verify reads). Keyholders\n"
        "                                             file shape: {\"keyholders\": [{\"share_index\":\n"
        "                                             int, \"passphrase\": \"...\"}, ...]}; N is\n"
        "                                             length(keyholders); 1<=T<=N<=255.\n"
        "                                             Refuses to overwrite existing output files\n"
        "                                             without --force.\n"
        "  keyfile-create --priv <hex>                Produce a passphrase-encrypted\n"
        "                 --passphrase-from <src>     node_key.json for the determ daemon\n"
        "                 --out <file> [--force] [--json]\n"
        "                                             (S-004: validator key at rest). --priv\n"
        "                                             is a 32-byte seed (64 hex) or 64-byte\n"
        "                                             keypair (128 hex). --passphrase-from is\n"
        "                                             file:<path>, env:<NAME>, or prompt.\n"
        "                                             Output shape: header line\n"
        "                                             'DETERM-NODE-V1 <pubkey_hex>' followed\n"
        "                                             by a DWE1 envelope blob (plaintext =\n"
        "                                             {\"pubkey\": \"...\", \"priv_seed\": \"...\"}).\n"
        "  keyfile-decrypt --in <file>                Inverse of keyfile-create. Decrypts a\n"
        "                  --passphrase-from <src>    passphrase-encrypted node_key.json back to\n"
        "                  --out <file> [--force] [--json]\n"
        "                                             plaintext for offline operator workflows\n"
        "                                             (migration, recovery, debugging). --in is\n"
        "                                             the 2-line canonical format produced by\n"
        "                                             keyfile-create. --out is written matching\n"
        "                                             src/crypto/keys.cpp::save_node_key byte-\n"
        "                                             for-byte. Wrong passphrase or tampered\n"
        "                                             envelope exits 2 (indistinguishable on\n"
        "                                             stderr); malformed --in exits 1.\n"
        "  keyfile-recover --backup-shares <file>     High-level T-of-N recovery CLI: composes\n"
        "                  --backup-envelopes <file>  envelope::decrypt + shamir::combine into a\n"
        "                  --keyholders <file>        single call. Reads the (shares, envelopes)\n"
        "                  [--threshold T]            pair produced by backup-create and a T-of-N\n"
        "                  [--out <file>] [--force]   subset of keyholder passphrases; recovers\n"
        "                  [--json]                   the original secret. Keyholders file shape\n"
        "                                             is SAME as backup-create input but with\n"
        "                                             only T of N entries supplied:\n"
        "                                             {\"keyholders\": [{\"share_index\": int,\n"
        "                                             \"passphrase\": \"...\"}, ...]}. --threshold\n"
        "                                             is optional; when supplied, enforces that\n"
        "                                             the keyholders subset has at least T entries\n"
        "                                             (Shamir's info-theoretic security means an\n"
        "                                             under-threshold subset would otherwise emit\n"
        "                                             a syntactically-valid but wrong secret). By\n"
        "                                             default prints the recovered secret hex to\n"
        "                                             stdout; --out writes {\"secret_hex\": \"...\"}\n"
        "                                             JSON; --json emits the same JSON to stdout.\n"
        "                                             All failure modes (wrong passphrase,\n"
        "                                             insufficient shares, share/envelope mismatch,\n"
        "                                             malformed files) exit 2 with a diagnostic.\n"
        "  account-recover --shares <file>            Composite wallet recovery: composes\n"
        "                  --envelopes <file>         keyfile-recover (Shamir + envelope) with\n"
        "                  --keyholders <file>        account-import (Ed25519 seed -> anon-account\n"
        "                  --threshold T              JSON) in a single call. Reads the (shares,\n"
        "                  [--out <file>] [--force]   envelopes) pair produced by backup-create\n"
        "                  [--json]                   and a T-of-N subset of keyholder passphrases;\n"
        "                                             recovers the original 32-byte Ed25519 seed\n"
        "                                             and emits the wallet anon-account JSON\n"
        "                                             {\"address\":\"0x..\",\"privkey_hex\":\"..\"}.\n"
        "                                             --threshold T is REQUIRED (Shamir's info-\n"
        "                                             theoretic security means combining < T shares\n"
        "                                             would silently emit a wrong-but-syntactically-\n"
        "                                             valid wallet account). Default human prints\n"
        "                                             one line; --out writes the JSON to file with\n"
        "                                             0600 perms; --json prints JSON to stdout. All\n"
        "                                             failure modes (wrong passphrase, insufficient\n"
        "                                             shares, mismatch, non-32-byte recovered\n"
        "                                             secret) exit 2 with a diagnostic.\n"
        "  keyfile-info --in <file> [--json]          Passive diagnostic for an encrypted node\n"
        "                                             keyfile (S-004). Parses the 2-line\n"
        "                                             DETERM-NODE-V1 + DWE1 envelope shape and\n"
        "                                             dumps header pubkey, derived anon-address,\n"
        "                                             and envelope metadata (pbkdf2_iters,\n"
        "                                             salt/nonce/ct lengths, AAD presence)\n"
        "                                             WITHOUT decrypting (no passphrase, no\n"
        "                                             plaintext recovery). Exit 0 valid, 1 file\n"
        "                                             error, 2 malformed.\n"
        "  account-list --keyfiles-dir <path>         Enumerate keyfiles in a directory with\n"
        "               [--recursive]                 per-file metadata. Pure local computation\n"
        "               [--include-encrypted[=on|off]] (no daemon RPC, no decryption). Each\n"
        "               [--include-plaintext[=on|off]] regular file is classified as one of:\n"
        "               [--json]                       plaintext-single ({\"address\":..,\n"
        "                                             \"privkey_hex\":..}),\n"
        "                                             plaintext-batch ({\"accounts\":[...]}),\n"
        "                                             encrypted-DETERM-NODE-V1 (2-line header +\n"
        "                                             DWE1 envelope), or unknown (skipped from\n"
        "                                             address extraction but still listed). For\n"
        "                                             encrypted keyfiles the metadata mirrors\n"
        "                                             keyfile-info (header_tag, pbkdf2_iters,\n"
        "                                             salt_hex, nonce_hex). File mode is\n"
        "                                             reported as a 4-digit octal on POSIX,\n"
        "                                             'n/a' on Windows (no Unix-style mode bit).\n"
        "                                             Summary warnings: mode_not_0600 (plaintext\n"
        "                                             keyfile not at 0600 on POSIX) and\n"
        "                                             mixed_encrypted_and_plaintext_in_same_dir\n"
        "                                             (operator hygiene). Exit 0 success, 1\n"
        "                                             args / missing or non-directory path.\n"
        "  message-sign --priv <hex> --message <string|file:path>\n"
        "               --domain-tag <tag> [--json]\n"
        "                                             Sign a message with an Ed25519 priv key.\n"
        "                                             OFF-CHAIN (not a transaction). Uses a\n"
        "                                             domain-separated SHA-256 commitment:\n"
        "                                             H = SHA-256(domain_tag || message_bytes).\n"
        "                                             Useful for SIWE-style auth challenges,\n"
        "                                             off-chain attestations, operator-signed\n"
        "                                             announcements. --message file:<path> reads\n"
        "                                             bytes verbatim from a file (binary-safe).\n"
        "  message-verify --pubkey <hex> --message <string|file:path>\n"
        "                 --domain-tag <tag> --signature <hex> [--json]\n"
        "                                             Verify an Ed25519 signature produced by\n"
        "                                             message-sign. Exit 0 valid, 2 invalid\n"
        "                                             (auth-style alert), 1 args/parse error.\n"
        "                                             --domain-tag MUST match the sign-time tag.\n"
        "  tx-sign-verify --tx <file> --pubkey <hex> [--json]\n"
        "                                             Verify the Ed25519 signature on a Transaction\n"
        "                                             JSON file using the chain's canonical\n"
        "                                             signing_bytes scheme (matches src/chain/\n"
        "                                             block.cpp Transaction::signing_bytes). Reads\n"
        "                                             a JSON {type,from,to,amount,fee,nonce,\n"
        "                                             payload,sig,hash} record, reconstructs\n"
        "                                             signing_bytes byte-for-byte, and checks the\n"
        "                                             sig against --pubkey. --pubkey is REQUIRED:\n"
        "                                             the wallet has no chain registry to look up\n"
        "                                             the sender's key; anon-addr senders' pubkey\n"
        "                                             IS their address (drop 0x prefix) but must\n"
        "                                             be passed explicitly to prevent off-by-one\n"
        "                                             trust mistakes. Distinct from message-sign\n"
        "                                             (off-chain domain-separated scheme); sigs\n"
        "                                             are NOT interchangeable. Exit 0 valid, 2\n"
        "                                             invalid (auth-style alert), 1 args/parse/\n"
        "                                             IO error. Output: {valid, tx_hash_hex,\n"
        "                                             computed_signing_bytes_sha256}.\n"
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
    if (cmd == "shamir-rotate")   return cmd_shamir_rotate   (argc - 2, argv + 2);
    if (cmd == "envelope")        return cmd_envelope       (argc - 2, argv + 2);
    if (cmd == "inspect-envelope") return cmd_inspect_envelope(argc - 2, argv + 2);
    if (cmd == "account-create-batch") return cmd_account_create_batch(argc - 2, argv + 2);
    if (cmd == "account-derive-batch") return cmd_account_derive_batch(argc - 2, argv + 2);
    if (cmd == "account-import")  return cmd_account_import (argc - 2, argv + 2);
    if (cmd == "account-export")  return cmd_account_export (argc - 2, argv + 2);
    if (cmd == "backup-verify")   return cmd_backup_verify  (argc - 2, argv + 2);
    if (cmd == "backup-create")   return cmd_backup_create  (argc - 2, argv + 2);
    if (cmd == "keyfile-create")  return cmd_keyfile_create (argc - 2, argv + 2);
    if (cmd == "keyfile-decrypt") return cmd_keyfile_decrypt(argc - 2, argv + 2);
    if (cmd == "keyfile-recover") return cmd_keyfile_recover(argc - 2, argv + 2);
    if (cmd == "account-recover") return cmd_account_recover(argc - 2, argv + 2);
    if (cmd == "keyfile-info")    return cmd_keyfile_info   (argc - 2, argv + 2);
    if (cmd == "account-list")    return cmd_account_list   (argc - 2, argv + 2);
    if (cmd == "message-sign")    return cmd_message_sign   (argc - 2, argv + 2);
    if (cmd == "message-verify")  return cmd_message_verify (argc - 2, argv + 2);
    if (cmd == "tx-sign-verify")  return cmd_tx_sign_verify (argc - 2, argv + 2);
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
