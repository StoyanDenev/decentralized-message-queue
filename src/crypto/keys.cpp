// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// §3.15 backend swap (2026-07-03): Ed25519 keygen/sign/verify runs on the
// in-tree C99 RFC 8032 implementation (src/crypto/ed25519/ed25519.c) instead
// of OpenSSL EVP_PKEY_ED25519. Key format is unchanged (the raw private key
// IS the 32-byte RFC 8032 seed under both backends — existing node_key.json
// files load identically) and signing is deterministic RFC 8032, proven
// byte-equal to OpenSSL over a fuzzed (seed,msg) grid + the RFC 8032 KATs
// (`determ test-ed25519-c99` / `test-ed25519-vectors`). VERIFY is the
// consensus-visible edge: the C99 verifier enforces the RFC canonicality
// gates (S < L, canonical pubkey y < q) and is deliberately STRICTER than
// OpenSSL's lenient decoder on adversarial encodings. Locked in pre-genesis
// as THE consensus signature-validity rule (DECISION-LOG.md 2026-07-03):
// honestly-generated signatures are always canonical and behave identically;
// forged non-canonical encodings that OpenSSL would tolerate are rejected.
#include <determ/crypto/keys.hpp>
#include <determ/util/json_validate.hpp>
// The ONE restricted-write primitive (S-109 follow-up, 2026-09-18): the
// create-0600 + fchmod-before-the-first-byte + EINTR/short-write/no-spin +
// checked-close + leave-nothing-behind mechanism that save_node_key below,
// wallet/main.cpp::write_bytes_file_0600 and
// src/main.cpp::write_account_file_0600 each used to hand-roll.
#include <determ/util/restricted_write.hpp>
#include <determ/crypto/ed25519/ed25519.h>
#include <determ/crypto/secure_zero.h>
#include "envelope.hpp"
#include "keyfmt.hpp" 
#include <determ/crypto/rng/rng.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <cstdlib>
#include <cstring>
#ifndef _WIN32
#  include <fcntl.h>     // S-091: ::open(O_DIRECTORY|O_NOFOLLOW) — the key DIR
#  include <sys/stat.h>  // S-091: ::fchmod — 0700 on a directory this call made
#  include <unistd.h>    // S-091: ::close on that directory descriptor
#  include <cerrno>      // S-091: errno / EPERM on the directory narrowing
#endif

namespace determ::crypto {

using json = nlohmann::json;
using determ::util::json_require_hex;
namespace fs = std::filesystem;

NodeKey generate_node_key() {
    NodeKey key;
    // Fresh 32-byte RFC 8032 seed from the OS CSPRNG. Entropy failure is
    // fatal — an all-zero/partial seed must never become a node identity.
    if (determ_rng_bytes(key.priv_seed.data(), 32) != 0)
        throw std::runtime_error("OS entropy source failed (determ_rng_bytes)");
    determ_ed25519_pubkey_from_seed(key.priv_seed.data(), key.pub.data());
    return key;
}

#ifndef _WIN32
namespace {
// Test-only fault injection, in the shape light/outbox.cpp already uses
// (DETERM_LIGHT_OUTBOX_INJECT). A failed narrowing cannot be produced from
// outside the process on the platforms this is gated on — CI runs as the file's
// owner, and an owner's fchmod on a local filesystem does not fail — so without
// this hook the "report the failure, do not swallow it" rule below would have no
// gate that can go RED, i.e. no gate at all (wave doctrine rule 5). Unset (the
// production case) this is one getenv and nothing else; it can only ever turn a
// success into a reported failure, never the reverse.
bool inject_fault(const char* which) {
    const char* v = std::getenv("DETERM_NODE_KEY_INJECT");
    return v != nullptr && std::strcmp(v, which) == 0;
}
} // namespace
#endif

void save_node_key(const NodeKey& key, const std::string& path, const std::string& passphrase) {
    // S-091, PARTIAL (2026-09-17). This writes the node identity's 32-byte
    // RFC 8032 SEED. Until today it went out through a bare std::ofstream, which
    // creates at 0666 & ~umask — measured 0644 under the default umask 022, and
    // 0666 under umask 000 — and then narrowed nothing, so the seed was
    // world-readable for the life of the deployment (reproduced 2026-09-17: user
    // `nobody` read priv_seed out of a `determ init` data dir). The containing
    // directory was created by fs::create_directories at 0777 & ~umask (0755).
    //
    // CLOSED HERE, on POSIX only: the file is created 0600 and narrowed on its
    // descriptor before the first byte of the seed is written, a symlink at the
    // path is refused rather than followed, a directory THIS function creates is
    // 0700 before the file exists inside it, and a narrowing that fails is
    // reported by throwing instead of being swallowed.
    //
    // NOT CLOSED, and deliberately not papered over: the seed is still PLAINTEXT
    // hex inside JSON, where the wallet ships the DWE2 Argon2id + AES-256-GCM
    // envelope and the light client its binary DAK1/DNK1 containers. Encryption
    // is the D2 src-side keyfile increment (owner-gated), so S-091 stays OPEN.
    // Nothing is closed on Windows either — see the #else arm.
    const fs::path parent = fs::path(path).parent_path();
    bool created_parent = false;
    if (!parent.empty()) {
        std::error_code ec;
        // The 2-arg form reports whether a directory was actually CREATED; the
        // throwing 1-arg form the old code used discarded that, and it is the
        // whole basis of the narrowing decision below.
        created_parent = fs::create_directories(parent, ec);
        if (ec)
            throw std::runtime_error("Cannot create key directory " + parent.string()
                                     + ": " + ec.message());
    }

    std::vector<uint8_t> payload_bytes;
    bool is_binary = false;
    if (passphrase.empty()) {
        json j;
        j["pubkey"]    = to_hex(key.pub);
        j["priv_seed"] = to_hex(key.priv_seed);
        const std::string blob = j.dump(2);   // byte-identical to the old writer
        payload_bytes.assign(blob.begin(), blob.end());
        is_binary = false;
    } else {
        // Canonical DNK1 container wrapping DWE2 (Argon2id + AES-256-GCM) envelope.
        // Plaintext is the raw 32-byte seed; AAD is the raw 32-byte pubkey.
        std::vector<uint8_t> pt_bytes(key.priv_seed.begin(), key.priv_seed.end());
        std::vector<uint8_t> aad(key.pub.begin(), key.pub.end());
        determ::wallet::envelope::Envelope env;
        try {
            env = determ::wallet::envelope::encrypt(pt_bytes, passphrase, aad);
        } catch (...) {
            determ_secure_zero(pt_bytes.data(), pt_bytes.size());
            throw;
        }
        determ_secure_zero(pt_bytes.data(), pt_bytes.size());
        const std::vector<uint8_t> env_bytes = determ::wallet::envelope::serialize_bytes(env);
        payload_bytes = determ::wallet::keyfmt::encode_dnk1(key.pub, env_bytes);
        is_binary = true;
    }

#ifndef _WIN32
    // Narrow ONLY a directory this call created, and only that one — never a
    // pre-existing directory, and never the ancestors create_directories made on
    // the way to it. A pre-existing directory belongs to the operator: the same
    // data dir holds config.json, chain.json and exports, an operator may have
    // deliberately made it group-readable for a monitoring account, and silently
    // clamping it to 0700 from inside a keyfile writer is a surprising, invisible
    // side effect on state this function does not own. A directory that did not
    // exist one syscall ago has no such claims on it and its entire purpose at
    // that moment is to hold a node identity, so 0700 is both safe and correct
    // there. Consequence, stated rather than hidden: `determ init` creates the
    // data dir ITSELF (src/main.cpp cmd_init) before calling here, so that
    // directory stays at 0755 — the key file inside it is 0600, so the seed is
    // not exposed, but the directory listing is. Narrowing it belongs to cmd_init,
    // not here, and is not this increment.
    //
    // Narrowed on a DESCRIPTOR, not by path, for the same reason the file below
    // is: ::chmod(parent, 0700) re-resolves the name, so between the mkdir and
    // the chmod an attacker with write access to the ancestor can swap the new
    // directory for a symlink and have the mode land somewhere else. Opening it
    // O_DIRECTORY|O_NOFOLLOW and fchmod-ing that descriptor has nothing to race:
    // we just created this directory, so O_NOFOLLOW can only fail if it has
    // already been replaced, and failing is the right answer then.
    if (created_parent) {
        int rc = 0;
        int dfd = -1;
        if (inject_fault("dirchmod")) { rc = -1; errno = EPERM; }
        else {
            dfd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            rc  = (dfd < 0) ? -1 : ::fchmod(dfd, 0700);
        }
        if (rc != 0) {
            const int e = errno;
            if (dfd >= 0) ::close(dfd);
            throw std::runtime_error("Cannot restrict key directory " + parent.string()
                                     + " to 0700: " + std::strerror(e)
                                     + " — refusing to create a node identity in a"
                                       " directory whose permissions cannot be set");
        }
        ::close(dfd);
    }

#else
    (void)created_parent;   // the directory narrowing above is POSIX-only
#endif

    // The file itself goes out through the ONE shared restricted-write
    // primitive (include/determ/util/restricted_write.hpp), extracted
    // 2026-09-18 from this function, wallet/main.cpp::write_bytes_file_0600 and
    // src/main.cpp::write_account_file_0600 — three hand-rolled copies that had
    // already drifted twice within two days (on `write() == 0`, and on whether
    // a failed write leaves a truncated key container behind). The primitive
    // owns the mechanism this function used to spell out here:
    //
    //   Both the create mode and the fchmod are load-bearing and neither
    //   implies the other. Measured 2026-09-17: O_CREAT|O_TRUNC with mode 0600
    //   does NOT narrow a file that already exists — a rewrite over a 0644
    //   node_key.json leaves it 0644 — so the create mode alone leaves the
    //   window open on every rewrite; and a ::chmod by PATH after the write is
    //   a TOCTOU window plus a period in which the seed is on disk
    //   world-readable. ::fchmod on the descriptor, before the first write,
    //   closes both paths with no window and nothing to race. O_NOFOLLOW:
    //   without it a symlink planted at `path` is followed, which both
    //   redirects the seed into a file of the attacker's choosing and points
    //   the narrowing at the wrong inode. O_CLOEXEC keeps the descriptor out of
    //   any child. A write that fails, or a close that fails, removes the file:
    //   never leave a partial identity behind, and the contents of a file whose
    //   close failed are not trustworthy.
    //
    // What stays THIS site's policy, and is passed in rather than assumed:
    determ::util::RestrictedWriteOptions kopts;
    // Refuse, do not warn. save_node_key already throws on a write failure, so
    // this is the established shape here; and the choice is not close. A node
    // identity is written ONCE — both shipped callers skip keygen when the file
    // exists — and then read on every start for the life of the deployment, so
    // a stderr warning is seen at most once, in a provisioning shell that is
    // usually non-interactive, and never again, while the exposure is
    // permanent. Unlike a wallet recovery transcript, this file can be
    // REGENERATED at no cost: refusing costs the operator one re-run after
    // fixing the filesystem, where continuing costs a world-readable identity
    // that stakes and signs blocks. The repo already fails closed on the
    // sibling case — generate_node_key throws when the CSPRNG fails rather than
    // writing a weak seed. Reachable only at CREATION time, so no provisioned
    // node can be bricked by it on restart. The primitive removes the (empty,
    // O_TRUNC'd) file before returning, which is what stops a zero-byte
    // leftover from being counted as a provisioned identity by the callers'
    // fs::exists() guards.
    kopts.on_narrow_failure = determ::util::OnNarrowFailure::Refuse;
    // No trailing std::filesystem::permissions call, exactly as before. On
    // POSIX the create + fchmod above already did it and a by-path chmod after
    // close is the TOCTOU shape this function exists not to have; on Windows it
    // would look like a fix and change nothing measurable (see below).
    kopts.final_narrow = false;
    // Windows: TEXT-mode ofstream, whose \n -> \r\n translation is part of the
    // existing on-disk bytes. NOTHING about the permission window is closed
    // there and it is not papered over. _S_IREAD | _S_IWRITE on _open drives
    // only FILE_ATTRIBUTE_READONLY — it is not a mode and grants nobody
    // anything; the file's ACL arrives by inheritance from the parent
    // directory, and std::filesystem::permissions does not rewrite it either
    // (docs/proofs/S005PassphraseKeyfile.md F-4 records exactly this for the
    // wallet's keyfiles: "the actual NTFS ACL after the call is
    // operator-environment-dependent"). The exposure stands: a Windows operator
    // must set the containing directory's ACL. The gate SKIPs by name there
    // rather than reporting a pass it did not earn.
    kopts.windows_binary = is_binary;
#ifndef _WIN32
    // Test-only, unchanged in intent and in reachability: see inject_fault
    // above for why a failed narrowing cannot be produced from outside this
    // process on the platforms this is gated on. The getenv and the decision to
    // honour it stay here, where they were justified; the primitive only
    // carries the errno in.
    if (inject_fault("fchmod")) kopts.simulate_narrow_failure_errno = EPERM;
#endif

    const auto res = determ::util::write_restricted_0600(
        path, payload_bytes.data(), payload_bytes.size(), kopts);
    if (!payload_bytes.empty()) {
        determ_secure_zero(payload_bytes.data(), payload_bytes.size());
    }
    if (res.status == determ::util::RestrictedWriteStatus::NarrowRefused) {
        throw std::runtime_error("Cannot restrict key file " + path + " to 0600: "
                                 + std::strerror(res.err)
                                 + " — refusing to write a node identity seed that"
                                   " cannot be protected (remove the empty " + path
                                 + " and retry on a filesystem with POSIX permissions)");
    }
    if (!res.ok()) {
        // Every other failure — the open, a short/failed write, a failed close
        // — kept the wording this function has always used. `res.err` is 0 on
        // the Windows arm, which had no errno to print there either.
        throw std::runtime_error("Cannot write key file: " + path
                                 + (res.err ? ": " + std::string(std::strerror(res.err))
                                            : std::string()));
    }
}

NodeKey load_node_key(const std::string& path, const std::string& passphrase) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open key file: " + path);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    // S-091 D2 src-side keyfile increment:
    // Auto-detect format: if first 4 bytes are 'DNK1', decode canonical binary
    // container and decrypt DWE envelope. Otherwise, parse as legacy JSON.
    if (bytes.size() >= 4 && std::memcmp(bytes.data(), "DNK1", 4) == 0) {
        std::string pass = passphrase;
        if (pass.empty()) {
            const char* env = std::getenv("DETERM_PASSPHRASE");
            if (env && *env) pass = env;
        }
        if (pass.empty()) {
            throw std::runtime_error("Key file " + path + " is encrypted (DNK1); supply passphrase or set DETERM_PASSPHRASE");
        }
        auto nk_opt = determ::wallet::keyfmt::decode_dnk1(bytes);
        if (!nk_opt) {
            throw std::runtime_error("Corrupted DNK1 key file: " + path);
        }
        auto env_opt = determ::wallet::envelope::deserialize_bytes(nk_opt->env_bytes);
        if (!env_opt) {
            throw std::runtime_error("Corrupted DWE envelope in key file: " + path);
        }
        std::vector<uint8_t> aad(nk_opt->pubkey.begin(), nk_opt->pubkey.end());
        auto pt_opt = determ::wallet::envelope::decrypt(*env_opt, pass, aad);
        if (!pass.empty()) {
            determ_secure_zero(&pass[0], pass.size());
        }
        if (!pt_opt) {
            throw std::runtime_error("Failed to decrypt key file " + path + ": incorrect passphrase or corrupted envelope");
        }
        if (pt_opt->size() != 32) {
            determ_secure_zero(pt_opt->data(), pt_opt->size());
            throw std::runtime_error("Decrypted seed in " + path + " has invalid size (expected 32 bytes)");
        }
        NodeKey key;
        std::memcpy(key.priv_seed.data(), pt_opt->data(), 32);
        determ_secure_zero(pt_opt->data(), pt_opt->size());
        determ_ed25519_pubkey_from_seed(key.priv_seed.data(), key.pub.data());
        if (key.pub != nk_opt->pubkey) {
            determ_secure_zero(key.priv_seed.data(), key.priv_seed.size());
            throw std::runtime_error("Keyfile pubkey mismatch: header pubkey does not match decrypted seed pubkey");
        }
        return key;
    }

    std::string text(bytes.begin(), bytes.end());
    json j;
    try {
        j = json::parse(text);
    } catch (const std::exception& e) {
        throw std::runtime_error("Cannot parse key file " + path + ": " + e.what());
    }
    // S-018: name the failing field if `pubkey` or `priv_seed` is
    // missing / wrong-typed / wrong-length. Operators occasionally
    // hand-edit node_key.json (e.g., to swap keys between deployments)
    // and the prior nlohmann-internal "type must be string, but is
    // null" error didn't tell them which field they botched.
    NodeKey key;
    key.pub       = from_hex_arr<32>(json_require_hex(j, "pubkey",    64));
    key.priv_seed = from_hex_arr<32>(json_require_hex(j, "priv_seed", 64));
    return key;
}

Signature sign(const NodeKey& key, const uint8_t* data, size_t len) {
    // Re-derive the public key from the seed (matching OpenSSL EVP semantics,
    // which ignored NodeKey.pub): a hand-edited keyfile with a mismatched
    // stored pub still produces a signature valid under the SEED's pubkey.
    uint8_t pk[32];
    determ_ed25519_pubkey_from_seed(key.priv_seed.data(), pk);
    Signature sig{};
    if (determ_ed25519_sign(key.priv_seed.data(), pk, data, len, sig.data()) != 0)
        throw std::runtime_error("Ed25519 sign failed");
    return sig;
}

bool verify(const PubKey& pub, const uint8_t* data, size_t len, const Signature& sig) {
    // Strict RFC 8032 verify (S < L, canonical pubkey) — see the header
    // comment: the consensus signature-validity rule as of the §3.15 swap.
    return determ_ed25519_verify(pub.data(), data, len, sig.data()) == 0;
}

} // namespace determ::crypto
