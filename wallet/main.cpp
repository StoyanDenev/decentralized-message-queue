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
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>

using namespace determ::wallet;

namespace {

std::string to_hex(const std::vector<uint8_t>& v) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (auto b : v) o << std::setw(2) << static_cast<int>(b);
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
        "  envelope encrypt --plaintext <hex>         AEAD-wrap a share or seed\n"
        "                    --password <str> [--aad <hex>] [--iters <N>]\n"
        "  envelope decrypt --envelope <blob>         Unwrap an envelope\n"
        "                    --password <str> [--aad <hex>]\n"
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
    if (cmd == "envelope")        return cmd_envelope       (argc - 2, argv + 2);
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
