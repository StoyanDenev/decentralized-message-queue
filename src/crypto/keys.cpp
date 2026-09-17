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
#include <determ/crypto/ed25519/ed25519.h>
#include <determ/crypto/rng/rng.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <cstdlib>
#include <cstring>
#ifndef _WIN32
#  include <fcntl.h>     // S-091: ::open + O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW
#  include <sys/stat.h>  // S-091: ::fchmod — 0600 on the file, 0700 on the dir
#  include <unistd.h>    // S-091: ::write, ::close
#  include <cerrno>
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

void save_node_key(const NodeKey& key, const std::string& path) {
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

    json j;
    j["pubkey"]    = to_hex(key.pub);
    j["priv_seed"] = to_hex(key.priv_seed);
    const std::string blob = j.dump(2);   // byte-identical to the old writer

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

    // Both the create mode and the fchmod are load-bearing and neither implies
    // the other. Measured 2026-09-17: O_CREAT|O_TRUNC with mode 0600 does NOT
    // narrow a file that already exists — a rewrite over a 0644 node_key.json
    // leaves it 0644 — so the create mode alone leaves the window open on every
    // rewrite; and a ::chmod by PATH after the write is a TOCTOU window plus a
    // period in which the seed is on disk world-readable. ::fchmod on the
    // descriptor, before the first write, closes both paths with no window and
    // nothing to race. O_NOFOLLOW: without it a symlink planted at `path` is
    // followed, which both redirects the seed into a file of the attacker's
    // choosing and points the narrowing at the wrong inode. O_CLOEXEC keeps the
    // descriptor out of any child.
    const int fd = ::open(path.c_str(),
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        throw std::runtime_error("Cannot write key file: " + path + ": "
                                 + std::strerror(errno));
    {
        int rc;
        if (inject_fault("fchmod")) { rc = -1; errno = EPERM; }
        else                        { rc = ::fchmod(fd, 0600); }
        if (rc != 0) {
            const int e = errno;
            ::close(fd);
            // O_TRUNC has already run, so `path` exists and is EMPTY. Remove it
            // before throwing: both shipped callers guard keygen with
            // fs::exists(), so a zero-byte leftover is counted as a provisioned
            // identity — the next `determ init` reports "Key already exists
            // (skipping keygen)" and exits 0, and the failure resurfaces at
            // `determ start` as a JSON parse error naming neither this file nor
            // the permission problem. Measured 2026-09-17 before this line.
            ::unlink(path.c_str());
            // Throw, do not warn. save_node_key already throws on a write
            // failure, so this is the established shape here; and the choice is
            // not close. A node identity is written ONCE — both shipped callers
            // skip keygen when the file exists — and then read on every start for
            // the life of the deployment, so a stderr warning is seen at most
            // once, in a provisioning shell that is usually non-interactive, and
            // never again, while the exposure is permanent. Unlike a wallet
            // recovery transcript, this file can be REGENERATED at no cost:
            // refusing costs the operator one re-run after fixing the filesystem,
            // where continuing costs a world-readable identity that stakes and
            // signs blocks. The repo already fails closed on the sibling case —
            // generate_node_key throws when the CSPRNG fails rather than writing
            // a weak seed. Reachable only at CREATION time, so no provisioned
            // node can be bricked by it on restart.
            throw std::runtime_error("Cannot restrict key file " + path + " to 0600: "
                                     + std::strerror(e)
                                     + " — refusing to write a node identity seed that"
                                       " cannot be protected (remove the empty " + path
                                     + " and retry on a filesystem with POSIX permissions)");
        }
    }
    const char* p = blob.data();
    size_t left  = blob.size();
    while (left > 0) {
        const ssize_t n = ::write(fd, p, left);
        // n == 0 for a positive count cannot happen on a regular file, but it
        // must not become a spin: fail the write instead of looping forever.
        // wallet/main.cpp's sibling writer guards this; this one did not.
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            if (n == 0) errno = EIO;
            const int e = errno;
            ::close(fd);
            ::unlink(path.c_str());      // never leave a partial identity behind
            throw std::runtime_error("Cannot write key file: " + path + ": "
                                     + std::strerror(e));
        }
        p    += n;
        left -= static_cast<size_t>(n);
    }
    if (::close(fd) != 0) {
        const int e = errno;
        ::unlink(path.c_str());          // the contents are not trustworthy
        throw std::runtime_error("Cannot write key file: " + path + ": "
                                 + std::strerror(e));
    }
#else
    // Windows: NOTHING here is closed, and it is not papered over. _S_IREAD |
    // _S_IWRITE on _open drives only FILE_ATTRIBUTE_READONLY — it is not a mode
    // and grants nobody anything; the file's ACL arrives by inheritance from the
    // parent directory, and std::filesystem::permissions does not rewrite it
    // either (docs/proofs/S005PassphraseKeyfile.md F-4 records exactly this for
    // the wallet's keyfiles: "the actual NTFS ACL after the call is
    // operator-environment-dependent"). Calling either would look like a fix and
    // change nothing measurable, so the Windows writer is left byte-for-byte as
    // it was — including the TEXT-mode ofstream, whose \n -> \r\n translation is
    // part of the existing on-disk bytes — and the exposure stands: a Windows
    // operator must set the containing directory's ACL. The gate SKIPs by name
    // there rather than reporting a pass it did not earn.
    (void)created_parent;   // the narrowing above is POSIX-only; nothing to do here
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write key file: " + path);
    f << blob;
#endif
}

NodeKey load_node_key(const std::string& path) {
    // Unchanged by the S-091 permission increment, deliberately: the on-disk
    // container is the same JSON it always was, so an existing 0644
    // node_key.json written by any earlier build still loads byte-identically
    // and there is no migration. It also does NOT warn about a wide mode, and
    // that is a decision, not an oversight: (a) the advice a warning could give
    // is wrong — once a 0644 seed has existed on a shared host the remedy is
    // ROTATION, not chmod, and a line telling the operator to chmod invites
    // exactly the false comfort of tightening a leaked file; (b) this is a
    // library entry point on Node's constructor path (src/node/node.cpp), so it
    // runs on every node start and inside every in-process cluster fixture that
    // builds Nodes, and the line would become FAST-suite noise; (c) it is a
    // behavior change on the happy path of every already-provisioned node,
    // which is a rider on a permissions increment.
    // The honest place for it is the D2 src-side keyfile increment, which
    // rewrites this container anyway and can offer a real migration.
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open key file: " + path);
    json j = json::parse(f);
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
