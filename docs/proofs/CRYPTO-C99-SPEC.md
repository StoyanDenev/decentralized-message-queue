> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# Determ cryptographic stack — C99-native, libsodium-free, modular

> **NOTICE 2026-06-07 — FROST removed from v1.1 chain consensus path.** Per `FROST_DEVIATION_NOTICE.md`, FROST was identified as a Claude-introduced design deviation, not part of Stoyan Denev's original Determ design. The §3.8 FROST-Ed25519 implementation under `src/crypto/frost/` is retained as a library (DApp-layer use post-launch is allowed) but is NOT part of the v1.1 consensus path, NOT part of the v1.1-locked formal-verification surface, and any re-introduction into chain consensus requires Stoyan's explicit sign-off per `FROST_DEVIATION_NOTICE.md §3`. All §3.1–§3.7 primitives (SHA-2, HMAC, HKDF, PBKDF2, ChaCha20-Poly1305, AES-256-GCM, Ed25519, X25519, BLAKE2b) remain in v1.1 scope; only §3.8 FROST is excluded from the consensus-path commitment.

**Status:** architecture spec + Phase-0 implementation underway. Resolves the cryptographic-stack architecture for Phase 0 / Phase A: vendor every primitive Determ uses as independent C99 source organized into modular sub-libraries; eliminate libsodium dependency entirely; deliver a clean C API consumable from C++20 (current Determ) and from C99 (future NH1 Stage 2 rewrite). **Landed (validated byte-equal vs OpenSSL + published KATs, additive — not yet wired into call sites):** §3.10 constant-time primitives (`determ_ct_memcmp` + `determ_secure_zero` — the one §3.10 piece every other module consumes), §3.1 SHA-256/512 + HMAC + HKDF, §3.8b PBKDF2-HMAC-SHA-256, §3.4 ChaCha20-Poly1305 AEAD, §3.5 AES-256-GCM (complete — constant-time end to end: branchless GHASH + arithmetic, no-table S-box), §3.2 Ed25519 (RFC 8032 sign/verify + scalar/point arithmetic — the FROST EC prerequisite), **§3.8 FROST-Ed25519** (trusted-dealer + **trustless DKG** keygen — Pedersen DKG with Feldman VSS + proof-of-possession, RFC 9591 §6.6, so no single party learns the group secret — plus two-round threshold signing whose t-of-n aggregate verifies as a plain Ed25519 signature under the group key — all validated under OpenSSL; binding-factor RFC-9591-byte-exact interop vectors are a documented follow-up). **Note on §3.2:** the shipped implementation is a constant-time, table-free `gf[16]` (radix-2^16) field + cswap-ladder, derived from the public-domain TweetNaCl construction, rather than the originally-planned `ref10` radix-2^51 + precomputed-base-table form. The choice is correctness-first: TweetNaCl is small, auditable, and constant-time, and avoids the ~30 KB precomputed base table that is infeasible to vendor by hand; it is validated byte-equal vs OpenSSL `EVP_PKEY_ED25519` + RFC 8032 §7.1. A `ref10`/radix-2^51 variant remains a future throughput optimization (same posture as the AES S-box). Remaining Phase-0: the FROST primitives (keygen/sign/aggregate) now become implementable on this layer. Implementation tracking lives in [V210ImplementationRoadmap.md](V210ImplementationRoadmap.md).

**Companion documents:**
- `v2.10-DKG-SPEC.md` — FROST-Ed25519 threshold-randomness spec (consumer of this stack)
- `v2.22-PRIVACY-SPEC.md` — confidential transactions spec (consumer; Bulletproofs primitive switches to secp256k1 per this spec)
- `Beaconless-v2-SPEC.md` — Phase D architecture (consumer; cross-shard threshold accumulator uses FROST-Ed25519)
- `DSF-SPEC.md` — Phase 0 deterministic-simulation framework (parallel work track)

---

## 1. Scope

This spec covers ONLY the cryptographic primitive layer — what Determ uses for hashing, signing, key exchange, AEAD encryption, KDFs, range proofs, threshold signatures, and OPRF.

In scope:
- Per-primitive vendoring source + version pinning
- Module organization (`src/crypto/<primitive>/`)
- Unified C API (`include/determ/crypto.h`)
- C++ ergonomic wrapper (`include/determ/crypto.hpp`)
- Constant-time verification approach
- Test-vector validation against canonical specifications
- Build system integration
- libsodium removal plan

Out of scope:
- Higher-level protocol design (handled by F2-SPEC, v2.10-DKG-SPEC, v2.22-PRIVACY-SPEC, etc.)
- DSF testing scenarios (handled by DSF-SPEC)
- NH4 FIPS certification process (downstream calendar work)

---

## 2. Design decisions

### Q1: Two curve families, deliberately

**Decision: curve25519 family + secp256k1 family. Three curves total (Ed25519, X25519, secp256k1). Three primitive sources but two underlying mathematical families.**

| Curve | Use case | Reason |
|---|---|---|
| Ed25519 (curve25519 family, twisted Edwards) | Wallet + committee signatures, FROST-Ed25519 threshold | Existing protocol commitment; mature C99 ref impl (Bernstein's ref10); RFC 9591 canonical for FROST |
| X25519 (curve25519 family, Montgomery) | Key exchange (gossip handshake, v2.22 amount DH handshake) | Standard DH primitive; mature C99 (curve25519-donna); cofactor handled by definition |
| **secp256k1** | **Bulletproofs (v2.22), OPRF (v2.25), prime-order needs** | **Bitcoin's curve; libsecp256k1 + libsecp256k1-zkp deliver production-tested C99 Bulletproofs (Liquid, Grin since 2019); prime-order natively** |

**Why not single-family.** Bulletproofs structurally need a prime-order group with discrete-log hardness + efficient scalar arithmetic. ristretto255 (curve25519 family quotient) is the canonical choice but has only one mature C99 implementation (libsodium). libsecp256k1-zkp is the most-production-tested C99 Bulletproof library and uses secp256k1. Accepting a second curve family for the prime-order needs is the trade-off that delivers (a) no libsodium dependency, (b) battle-tested Bulletproofs from Bitcoin's ecosystem.

**Why NIST P-256 is also in the stack (for FIPS profile).** NIST P-256 IS a third curve — added because both the `tactical` and `cluster` profiles bundle FIPS-compliant cryptography (per §2.Q10), and secp256k1 is not in NIST's FIPS-validated curve list. P-256 is FIPS 186-5 validated. P-256 supplants secp256k1 only in FIPS-profile deployments (`tactical` + `cluster`); MODERN-profile deployments (`web` / `regional` / `global`) use secp256k1.

**BLS12-381 remains rejected** for "two primitives" reasons; that decision stands.

**Three primitive families, FOUR curves total when both profiles are considered:**

| Curve | Use case | Profile(s) |
|---|---|---|
| Ed25519 | Wallet + committee signatures, FROST-Ed25519 base | MODERN + FIPS (Ed25519 is FIPS 186-5 validated since 2023) |
| X25519 | Gossip handshake KX, v2.22 amount DH | MODERN + FIPS (X25519 is NIST SP 800-186 validated) |
| **secp256k1** | Bulletproofs, OPRF, prime-order operations | **MODERN only** |
| **NIST P-256** | OPRF on P-256, prime-order operations | **FIPS only** (substitute for secp256k1; FIPS 186-5 validated) |

**"Two primitives" design value status.** Originally: SHA-256 + curve25519 family. Now: SHA-256 + curve25519 family + secp256k1 family (MODERN) OR + NIST P-256 family (FIPS) — **three primitive families per active profile**. This is a deliberate expansion to eliminate libsodium dependence + enable FIPS-compliant deployments; documented as such.

### Q2: ristretto255 elimination

**Decision: eliminate ristretto255 entirely from Determ's cryptographic stack.**

Achieved via three substitutions:
- v2.10 FROST → Ed25519 directly per RFC 9591 (Ed25519, not ristretto255)
- v2.22 amount DH handshake → X25519 (not ristretto255)
- v2.22 Bulletproofs → secp256k1 via libsecp256k1-zkp (not ristretto255)
- v2.25 T-OPAQUE OPRF → secp256k1 via voprf cipher suite for secp256k1 + Schnorr-DLEQ proofs (not ristretto255)

**Net effect:** zero ristretto255 callers. No need to vendor libsodium's ristretto255 source, no need to implement ristretto255 from the IETF draft. ristretto255 simply not in the stack.

**Trade-off:** v2.25 OPRF deviates from voprf canonical (ristretto255 is the most-deployed voprf cipher suite). secp256k1 is supported by voprf draft but less canonical. Acceptable for Determ specifically because libsecp256k1-zkp is the most-production-tested secp256k1 OPRF infrastructure (used by Grin's stealth-address-style features).

### Q3: Per-primitive vendoring source

**Decision: each primitive vendored from a canonical reference implementation, pinned to a specific version, public-domain or compatible license.**

| Primitive | Module path | Source | License | LOC |
|---|---|---|---|---|
| SHA-256 / SHA-512 | `src/crypto/sha2/` | NIST FIPS 180-4 reference | Public domain | ~1K |
| HMAC-SHA-256 | `src/crypto/sha2/hmac.c` | RFC 2104 (trivial) | Public domain | ~100 |
| HKDF-SHA-256 | `src/crypto/sha2/hkdf.c` | RFC 5869 (trivial) | Public domain | ~200 |
| Ed25519 sign/verify | `src/crypto/ed25519/` | **SHIPPED** — constant-time `gf[16]` cswap-ladder (TweetNaCl-derived); `ref10` radix-2^51 is a future perf variant | Public domain | ~330 |
| X25519 | `src/crypto/x25519/` | **SHIPPED** — constant-time Montgomery cswap-ladder (TweetNaCl-derived), shares the Ed25519 `gf[16]` field lineage; validated vs OpenSSL `EVP_PKEY_X25519` + RFC 7748 §6.1 KAT | Public domain | ~140 |
| ChaCha20 | `src/crypto/chacha20/` | RFC 8439 reference | Public domain | ~500 |
| Poly1305 | `src/crypto/chacha20/poly1305.c` | RFC 8439 reference | Public domain | ~500 |
| XChaCha20-Poly1305 | `src/crypto/chacha20/xchacha20_poly1305.c` | **SHIPPED** — HChaCha20 + the C99 ChaCha20-Poly1305 (draft-irtf-cfrg-xchacha); validated vs OpenSSL inner AEAD + HChaCha20 §2.2.1 KAT | Public domain | ~90 |
| AES-256-GCM | `src/crypto/aes/` | NIST FIPS 197 + SP 800-38D | Public domain | ~3K |
| BLAKE2b | `src/crypto/blake2/` | **SHIPPED** — canonical RFC 7693 (keyed + variable-length); the hash Argon2id is built on; validated vs OpenSSL `EVP_blake2b512` + `hashlib.blake2b` KATs | Public domain | ~140 |
| Argon2id | `src/crypto/argon2/` | **SHIPPED** — RFC 9106 / P-H-C reference on the shipped BLAKE2b; byte-equal vs libsodium `crypto_pwhash_argon2id` (12/12 over a t×m grid) | Public domain | ~180 |
| secp256k1 (ECDH + signing) | `src/crypto/secp256k1/` | libsecp256k1 (Bitcoin Core) | MIT | ~6K |
| secp256k1 Bulletproofs | `src/crypto/secp256k1_zkp/` | libsecp256k1-zkp (Blockstream/Grin) | MIT | ~3K |
| FROST-Ed25519 | `src/crypto/frost/` | **SHIPPED** — trusted-dealer + trustless DKG (Feldman VSS + PoP) keygen + threshold sign whose aggregate is a plain Ed25519 sig | Determ-original | ~330 |
| OPRF on secp256k1 | `src/crypto/oprf/` | Implemented from voprf IRTF draft + RFC 9380 hash-to-curve | Determ-original | ~1K |
| Constant-time primitives | `src/crypto/ct/` | Trivial | Public domain | ~50 |

**Total vendored C99 cryptographic code: ~22-24K LOC.**

For comparison: libsodium ~70K LOC (most unused by Determ).

### Q4: Modular sub-library structure

**Decision: each primitive family in its own `src/crypto/<family>/` subdirectory with a clean local API, exposed through a unified `include/determ/crypto.h` C99 header and an ergonomic `include/determ/crypto.hpp` C++ wrapper.**

Directory layout:

```
src/crypto/
├── sha2/                       # SHA-256, SHA-512, HMAC, HKDF
│   ├── sha256.c
│   ├── sha512.c
│   ├── hmac.c
│   ├── hkdf.c
│   └── sha2.h
├── ed25519/                    # SHIPPED: constant-time gf[16] (TweetNaCl-derived)
│   ├── ed25519.c               #   field + scalar + group + RFC 8032 sign/verify
│   └── ed25519.h               #   (one self-contained file; ref10 split is future)
├── x25519/                     # SHIPPED: constant-time Montgomery ladder (TweetNaCl-derived)
│   └── x25519.c                #   X25519 DH (RFC 7748); header at include/determ/crypto/x25519/x25519.h
├── chacha20/                   # ChaCha20-Poly1305 + XChaCha20
│   ├── chacha20.c
│   ├── poly1305.c
│   ├── chacha20_poly1305.c
│   ├── xchacha20_poly1305.c
│   └── chacha20.h
├── aes/                        # AES-256-GCM
│   ├── aes_core.c
│   ├── aes_gcm.c
│   └── aes.h
├── blake2/                     # SHIPPED: BLAKE2b (RFC 7693), keyed + variable-length
│   └── blake2b.c               #   the hash Argon2id builds on; header at include/determ/crypto/blake2/
├── argon2/                     # SHIPPED: Argon2id (RFC 9106) on ../blake2/blake2b
│   └── argon2id.c              #   one self-contained file; header at include/determ/crypto/argon2/
├── secp256k1/                  # libsecp256k1 vendored
│   ├── (libsecp256k1 source tree, pinned version)
│   └── secp256k1.h
├── secp256k1_zkp/              # libsecp256k1-zkp vendored
│   ├── bulletproofs.c
│   ├── (libsecp256k1-zkp source tree, pinned version)
│   └── secp256k1_zkp.h
├── frost/                      # FROST-Ed25519 from RFC 9591
│   ├── frost_keygen.c
│   ├── frost_sign.c
│   ├── frost_aggregate.c
│   ├── frost_pss_refresh.c
│   └── frost.h
├── oprf/                       # OPRF on secp256k1 + hash-to-curve
│   ├── oprf.c
│   ├── hash_to_curve.c         # RFC 9380 for secp256k1
│   └── oprf.h
├── ct/                         # Constant-time primitives
│   ├── ct_compare.c
│   ├── ct_select.c
│   └── ct.h
└── crypto.h                    # Unified Determ-facing C99 API
```

Each module:
- Compiles as a standalone static library OR as part of Determ's main build
- Has its own local API in `<module>.h`
- Tested independently via `tools/test_crypto_<module>.sh`
- Audited as a unit with documented provenance + constant-time discipline

Modular benefits:
- Per-primitive replacement straightforward (e.g., swap Ed25519 ref10 for a FIPS-validated impl during NH4 path)
- Independent maintenance of each sub-library against upstream advisories
- Per-module test isolation
- Build system handles each as a separate compilation unit

### Q5: Unified C API + C++ ergonomic wrapper

**Decision: single `include/determ/crypto.h` exposes the C99 API; `include/determ/crypto.hpp` wraps for C++ ergonomics.**

```c
// crypto.h — C99 API (consumable from C and C++)

#ifndef DETERM_CRYPTO_H
#define DETERM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ─── Hashing ────────────────────────────────────────────────────────
typedef struct { uint8_t bytes[32]; } determ_hash256_t;
typedef struct { uint8_t bytes[64]; } determ_hash512_t;

void determ_sha256(const uint8_t* msg, size_t msg_len, determ_hash256_t* out);
void determ_sha512(const uint8_t* msg, size_t msg_len, determ_hash512_t* out);

// ─── HMAC + HKDF ────────────────────────────────────────────────────
void determ_hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* msg, size_t msg_len,
                        determ_hash256_t* out);
void determ_hkdf_sha256(const uint8_t* salt, size_t salt_len,
                        const uint8_t* ikm, size_t ikm_len,
                        const uint8_t* info, size_t info_len,
                        uint8_t* okm, size_t okm_len);

// ─── Ed25519 ────────────────────────────────────────────────────────
typedef struct { uint8_t bytes[32]; } determ_ed25519_sk_t;
typedef struct { uint8_t bytes[32]; } determ_ed25519_pk_t;
typedef struct { uint8_t bytes[64]; } determ_ed25519_sig_t;

int  determ_ed25519_keypair(const uint8_t seed[32],
                             determ_ed25519_sk_t* sk,
                             determ_ed25519_pk_t* pk);
int  determ_ed25519_sign(const determ_ed25519_sk_t* sk,
                          const determ_ed25519_pk_t* pk,
                          const uint8_t* msg, size_t msg_len,
                          determ_ed25519_sig_t* sig);
int  determ_ed25519_verify(const determ_ed25519_pk_t* pk,
                            const uint8_t* msg, size_t msg_len,
                            const determ_ed25519_sig_t* sig);

// ─── X25519 ── SHIPPED (src/crypto/x25519/x25519.h) — the sketch below predated
// the implementation; the shipped API is two raw-buffer calls (no struct wrappers,
// the scalar is clamped internally per RFC 7748 §5):
int determ_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]); // X25519(scalar, u); -1 on low-order
int determ_x25519_base(uint8_t out[32], const uint8_t scalar[32]);                     // public key = X25519(scalar, 9)

// ─── ChaCha20-Poly1305 / XChaCha20-Poly1305 ─────────────────────────
int determ_xchacha20_poly1305_encrypt(const uint8_t key[32],
                                       const uint8_t nonce[24],
                                       const uint8_t* aad, size_t aad_len,
                                       const uint8_t* plaintext, size_t pt_len,
                                       uint8_t* ciphertext,
                                       uint8_t tag[16]);
int determ_xchacha20_poly1305_decrypt(const uint8_t key[32],
                                       const uint8_t nonce[24],
                                       const uint8_t* aad, size_t aad_len,
                                       const uint8_t* ciphertext, size_t ct_len,
                                       const uint8_t tag[16],
                                       uint8_t* plaintext);

// ─── AES-256-GCM ────────────────────────────────────────────────────
int determ_aes256_gcm_encrypt(/* ... */);
int determ_aes256_gcm_decrypt(/* ... */);

// ─── Argon2id ───────────────────────────────────────────────────────
int determ_argon2id(const uint8_t* password, size_t password_len,
                     const uint8_t* salt, size_t salt_len,
                     uint32_t time_cost,
                     uint32_t memory_cost_kib,
                     uint32_t parallelism,
                     uint8_t* out_hash, size_t out_len);

// ─── secp256k1 (Bulletproofs + OPRF + signing) ──────────────────────
typedef struct { uint8_t bytes[32]; } determ_secp256k1_scalar_t;
typedef struct { uint8_t bytes[33]; } determ_secp256k1_point_t;  // compressed

int determ_secp256k1_bulletproof_prove(/* ... */);
int determ_secp256k1_bulletproof_verify(/* ... */);

int determ_secp256k1_oprf_blind(/* ... */);
int determ_secp256k1_oprf_evaluate(/* ... */);
int determ_secp256k1_oprf_unblind(/* ... */);

// ─── FROST-Ed25519 threshold signatures ─────────────────────────────
typedef struct { /* per-member secret share */ } determ_frost_share_t;
typedef struct { /* group public key */ } determ_frost_pubkey_t;
typedef struct { /* partial signature */ } determ_frost_partial_t;

// Shipped names (src/crypto/frost/frost.h) — the sketch below predated the
// implementation; the DKG ceremony shipped as a commit / verify-PoP / share /
// verify-share decomposition rather than the round1/round2/finalize sketch:
int determ_frost_dkg_commit(/* poly,t,idx -> commitments,pop */);       // round-1 Feldman commitments + PoP
int determ_frost_dkg_verify_pop(/* commitment0,idx,pop */);             // rogue-key defence
void determ_frost_dkg_share(/* poly,t,j -> share */);                   // round-2 dealt share f_i(j)
int determ_frost_dkg_verify_share(/* share,j,commitments,t */);         // Feldman VSS check
// PSS refresh — SHIPPED as two primitives (no monolithic _refresh call): the
// caller deals zero-hole δ_i via determ_frost_pss_commit, peers check the hole
// with determ_frost_pss_verify_commit, shares reuse the dkg_share/_verify_share
// path, and s'_j = s_j + Σ_i δ_i(j) is a caller-side scalar sum:
int determ_frost_pss_commit(/* zeropoly,t -> commitments (C_0 = identity) */);   // SHIPPED
int determ_frost_pss_verify_commit(/* commitment0 -> 0 iff C_0 == [0]B */);      // SHIPPED
int determ_frost_sign_partial(/* one signer's round-2 share z_i */);    // SHIPPED (distributed signing)
int determ_frost_aggregate(/* sum z_i + recompute R -> Ed25519 sig */); // SHIPPED

// ─── Constant-time primitives ───────────────────────────────────────
int  determ_ct_memcmp(const uint8_t* a, const uint8_t* b, size_t n);
void determ_ct_zero(uint8_t* buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif // DETERM_CRYPTO_H
```

```cpp
// crypto.hpp — C++ ergonomic wrapper

namespace determ::crypto {

class Sha256 {
public:
    static Hash256 hash(std::span<const uint8_t> msg);
    static Hash256 hash(const std::string& msg);
    // RAII-managed incremental state
    void update(std::span<const uint8_t> chunk);
    Hash256 finalize();
};

class Ed25519 {
public:
    static Keypair from_seed(std::span<const uint8_t, 32> seed);
    static Signature sign(const PrivateKey& sk, const PublicKey& pk,
                          std::span<const uint8_t> msg);
    static bool verify(const PublicKey& pk,
                       std::span<const uint8_t> msg,
                       const Signature& sig);
};

// ... similar for X25519, ChaCha20-Poly1305, AES-GCM, Argon2id, secp256k1, FROST, OPRF
}
```

The C++ wrapper provides:
- RAII for incremental state (Sha256, etc.)
- `std::span` for buffer parameters (safer than raw pointers)
- Exception-throwing variants alongside error-code variants
- Type-safe wrappers (`PublicKey`, `Signature`, etc. are distinct types)

### Q6: Constant-time discipline

**Decision: every primitive verified constant-time against side-channel attacks via dudect (statistical) + manual review.**

Per-primitive validation:
- **Static**: review each primitive against constant-time anti-patterns (branching on secrets, data-dependent memory access, variable-time arithmetic)
- **Dynamic**: dudect or ctgrind run on each primitive; report timing-leak score (must be statistically zero per dudect's test)
- **Documented**: each primitive's `<module>.h` notes which operations are constant-time and which are not (e.g., key generation may be variable-time; sign/verify must be constant-time)

Build configuration:
- Compile with `-O2 -fno-strict-aliasing` (disable optimizations that risk constant-time violations)
- `-DDETERM_CT_VERIFIED=1` build flag enables runtime constant-time assertions in debug builds

### Q7: Test-vector validation

**Decision: every primitive validated against canonical test vectors before merge.**

Per-primitive test vectors:
- SHA-256/SHA-512: NIST CAVP vectors
- HMAC/HKDF: RFC 4231 / RFC 5869 vectors
- Ed25519: RFC 8032 + Bernstein's reference vectors
- X25519: RFC 7748 vectors
- ChaCha20-Poly1305: RFC 8439 vectors
- XChaCha20-Poly1305: draft-irtf-cfrg-xchacha vectors
- AES-256-GCM: NIST CAVP vectors
- Argon2id: P-H-C reference vectors
- secp256k1: libsecp256k1 test suite (vendored alongside the library)
- secp256k1-zkp Bulletproofs: libsecp256k1-zkp test vectors
- FROST-Ed25519: RFC 9591 Appendix C vectors
- OPRF: voprf draft Appendix B vectors

Validation methodology:
- Each test vector encoded as JSON in `tools/vectors/<primitive>.json`
- Test runner verifies inputs → outputs match expected byte-for-byte
- CI runs full test-vector suite on every commit
- Regression test: cross-check against libsodium outputs for primitives we previously used (validates migration correctness)

### Q8: Cross-platform considerations

**Decision: all primitives compile cleanly on x86-64, ARM64, and 32-bit ARM. No SIMD assumptions in the canonical code path.**

Build approach:
- Pure C99 code path always available (no SIMD)
- SIMD-optimized variants (AVX2 for x86-64, NEON for ARM) gated by `-DDETERM_SIMD=1` build flag
- libsecp256k1 + libsecp256k1-zkp ship with their own asm optimizations; gated by their build flags
- Cross-compilation tested for: Linux x86-64, Linux ARM64, Windows x86-64, MINIX (NH1 secondary target)

### Q9: libsodium removal

**Decision: complete removal of libsodium from Determ's dependency list once vendored C99 primitives pass test-vector + constant-time validation.**

Migration steps:
1. Phase 0 Track 2 ships all vendored C99 primitives (~6-7 weeks per §3 below) —
   **DONE for the wallet/keyfile/identity set**: SHA-2/HMAC/HKDF/PBKDF2, ChaCha20-Poly1305
   + XChaCha20-Poly1305, AES-256-GCM, Ed25519, X25519, BLAKE2b, Argon2id, and the
   full FROST suite are all shipped + adversarially audited (C99CryptoStackAudit
   §6–§8f). Remaining: §3.7 secp256k1 + §3.9 OPRF (the MODERN/FIPS-profile OPRF path).
2. Refactor every libsodium call site to use the C99 API (~1 week) — **NOT yet done**;
   needs care + versioning where it changes on-disk format (the keyfile envelope's
   `crypto_pwhash`/AEAD), so it is gated on an explicit go-ahead.
3. Cross-validate: run libsodium-output and C99-output side-by-side; verify byte-equal —
   **DONE as a standing harness**: `tools/test_c99_libsodium_xval.sh` (commit `23930b1`)
   compiles `tools/c99_libsodium_xval.c` against the build tree's `libsodium.a` and
   asserts BLAKE2b / X25519 / XChaCha20-Poly1305 / Argon2id are byte-equal to
   `crypto_generichash` / `crypto_scalarmult{,_base}` / `crypto_aead_xchacha20poly1305_ietf`
   / `crypto_pwhash_argon2id` over wide grids (5/5 families matched). This is the
   behaviour-preserving evidence for step 2.
4. Drop libsodium from CMakeLists / build system
5. Remove libsodium submodule
6. Update documentation: SECURITY.md crypto-dependency list, WHITEPAPER §7 cryptographic primitives, V2-DESIGN.md cross-references

**Validation:** the in-process `determ test-*` subcommands continue passing after
migration; per-primitive `determ test-*-c99` subcommands (sha2/aes/chacha20/ed25519/
frost/x25519/blake2b/xchacha/argon2id) + the full-stack libsodium-equivalence harness
above are the regression gate.

### Q10: Profile bundling — crypto choice tied to TimingProfile

**Decision: cryptographic profile (MODERN vs FIPS) is bundled into `TimingProfile` and selected by profile name at genesis. No separate `crypto_profile` genesis field.**

Per `include/determ/chain/params.hpp`, `TimingProfile` carries a `CryptoProfile crypto_profile` field. Choosing a profile (`tactical`, `web`, `regional`, `global`, `cluster`) automatically selects the bundled cryptographic stack.

**Profile-to-crypto mapping:**

| Timing profile | Crypto profile | Use case |
|---|---|---|
| **`cluster`** | **FIPS** | **In-house enterprise / financial services / regulated single-cluster deployments. Bank settlement, single-organization permissioned chain, regulated consortium, in-house CBDC component, healthcare-HIPAA deployments. FIPS 140-2/3 compliance mandatory for these verticals.** |
| `web` | MODERN | Standard web-scale chain; commercial non-FIPS single-cluster deployments also use this |
| `regional` | MODERN | Regional sharded deployments |
| `global` | MODERN | Global-scale chains |
| **`tactical`** | **FIPS** | **Military / defense / embedded swarm coordination. FIPS 140-2/3 compliance mandatory for these verticals.** |
| All `*_test` profiles | Match their production counterpart (cluster_test = FIPS, tactical_test = FIPS, others = MODERN) | CI validates the production posture |

**Two FIPS-bundled profiles:** `cluster` (in-house enterprise / financial services / regulated; 50ms blocks) and `tactical` (military / defense / embedded; 20ms blocks). Both bundle FIPS-compliant cryptography because both serve deployment contexts where FIPS 140-2/3 compliance is non-negotiable.

**Non-FIPS commercial use cases.** Operators wanting single-cluster (BEACON + CURRENT) deployment without FIPS regulatory requirement should use the `web` profile — sharding is acceptable for single-region commercial deployments, and `web` provides confidential transactions which are unavailable in FIPS profiles.

**Why bundled rather than orthogonal.** Real-world deployment scenarios that demand FIPS-compliant cryptography are the same scenarios that demand tactical-grade timing — military embedded systems, defense communications, regulated industries with strict cryptographic compliance. Decoupling crypto from timing would create combinatorial profile space (5 timings × 2 cryptos = 10 effective profiles) with most combinations unused in practice. Bundling reflects the real-world alignment: tactical IS the FIPS use case.

**Feature availability matrix per profile:**

| Feature | MODERN | FIPS (tactical) |
|---|---|---|
| Ed25519 signatures (committee + wallet) | ✅ | ✅ (FIPS 186-5) |
| X25519 KX | ✅ | ✅ (SP 800-186) |
| SHA-256 / SHA-512 / HMAC / HKDF | ✅ | ✅ (FIPS 180-4 / FIPS 198 / SP 800-56C) |
| FROST-Ed25519 threshold randomness (v2.10) | ✅ | ✅ (Ed25519 FIPS-validated; FROST construction is IETF-track) |
| Passphrase KDF (v2.17 keyfiles) | Argon2id (RFC 9106) | **PBKDF2-HMAC-SHA-256 (SP 800-132)** — substantially weaker; FIPS-validated |
| AEAD (v2.17 keyfiles, v2.22 amount encryption, direct-to-DApp) | XChaCha20-Poly1305 | **AES-256-GCM (FIPS 197 + SP 800-38D)** |
| Prime-order group | secp256k1 | **NIST P-256 (FIPS 186-5)** |
| ECDH (v2.22 amount handshake; v2.24 audit-key exchange) | secp256k1 ECDH (libsecp256k1) | **NIST P-256 ECDH (SP 800-56A)** |
| **Confidential transactions (v2.22 Bulletproofs)** | ✅ Available | ❌ **UNAVAILABLE — no FIPS-validated range proofs exist** |
| Theme 9 DSSO OPRF (v2.25) | secp256k1 voprf | **NIST P-256 voprf** |

**Critical caveat: confidential transactions unavailable in FIPS profiles.** Both `tactical` (military / defense) and `cluster` (in-house enterprise / financial services / regulated) deployments cannot use v2.22 confidential transactions. This is structurally required — NIST has not standardized zero-knowledge range proofs (Bulletproofs included), so no FIPS-validated implementation exists. FIPS-profile deployments must use clear-amount TRANSFER tx exclusively + v2.24 audit hooks for regulator access. Documented as accepted trade-off for FIPS compliance.

**Non-FIPS sub-50ms deployments.** Operators wanting sub-50ms blocks for non-regulated scenarios (commercial delivery drones, industrial robotics without FIPS requirement, high-frequency commercial settlement without compliance constraint) cannot use the `tactical` or `cluster` profile names directly because both bundle FIPS. The closest MODERN profile is `regional` (~150ms). Options:

1. Use `regional` (~150ms, MODERN crypto) — accept the latency cost in exchange for stronger primitives + confidential transactions
2. Custom genesis with tactical/cluster timing parameters + manual crypto-profile override (genesis advanced-config path; not recommended for new deployments — bypasses the bundling invariant)
3. Wait for v2.x to add a `tactical_civilian` or `cluster_civilian` profile if commercial demand surfaces (currently not planned)

**Adoption rationale.** Bundling crypto with timing in the profile selection delivers:
- **One operator decision instead of two** (just pick the profile)
- **Reflects real-world alignment** (low-latency regulated deployments — military `tactical` + financial `cluster` — ARE the FIPS use cases)
- **Prevents misconfiguration** (can't accidentally deploy regulated hardware with non-FIPS crypto)
- **Simplifies the genesis schema** (no separate `crypto_profile` field needed)
- **Test profiles match production posture** (tactical_test = FIPS, cluster_test = FIPS; ensures CI catches FIPS-specific issues)

---

## 3. Implementation work units

### 3.1 SHA-256 / SHA-512 / HMAC / HKDF (~2 days)

- Vendor NIST FIPS 180-4 reference for SHA-256 + SHA-512
- HMAC-SHA-256 wrapper per RFC 2104 (trivial)
- HKDF-SHA-256 wrapper per RFC 5869 (trivial)
- Test vectors from NIST CAVP + RFC 4231 + RFC 5869
- Constant-time verification (trivial — hashing is inherently CT)

### 3.2 Ed25519 — **SHIPPED** (as TweetNaCl-derived `gf[16]`, NOT the ref10 plan below)

Shipped: `src/crypto/ed25519/ed25519.c` — constant-time table-free `gf[16]`
(radix-2^16) field + cswap ladder, RFC 8032 sign/verify with the §5.1.3/§5.1.7
canonicality gates, plus the exposed scalar/group primitives in
`ed25519_group.h` that FROST builds on. Validated by `determ test-ed25519-c99`
(byte-equal vs OpenSSL `EVP_PKEY_ED25519` + RFC 8032 §7.1) and
`determ test-ed25519-vectors`. See the status-header note for why the original
plan below was deviated from (the ~30 KB ref10 base table is infeasible to
vendor by hand; ref10/radix-2^51 remains a future throughput variant).
Original plan (retained for the deviation record):

- Vendor Bernstein's `ref10` from supercop, pinned version
- Adapter layer to Determ's API
- Test vectors from RFC 8032 + Bernstein's reference
- Constant-time review (ref10 is well-understood CT)

### 3.3 X25519 — **SHIPPED** (commit `bc87704`)

- `src/crypto/x25519/x25519.c` — a from-scratch, constant-time Montgomery cswap-ladder
  (TweetNaCl-derived, the same Curve25519 `gf[16]` field lineage as the §3.2 Ed25519,
  NOT curve25519-donna — chosen for one auditable field implementation across the
  curve25519 family). `determ_x25519` (clamped scalar mult, RFC 7748 §5) +
  `determ_x25519_base` (public key); all-zero low-order result returns -1 (RFC 7748
  contributory check).
- Validated by `determ test-x25519-c99` (8 assertions): byte-equal vs OpenSSL
  `EVP_PKEY_X25519` over a fuzzed scalar grid (pubkey + ECDH `EVP_PKEY_derive` + DH
  symmetry — the §Q9 gate) and the canonical RFC 7748 §6.1 KAT.
- Constant-time: no key-dependent branch/index; clamped scalar + field intermediates
  zeroized via `determ_secure_zero`.
- Additive — no daemon call site yet (completes the curve25519 family for a future
  libsodium-free DH/handshake consumer).

### 3.4 ChaCha20-Poly1305 + XChaCha20-Poly1305 — **SHIPPED**

- ChaCha20 + Poly1305 + ChaCha20-Poly1305 IETF AEAD: `src/crypto/chacha20/`,
  validated vs OpenSSL `EVP_chacha20` / `EVP_chacha20_poly1305` + RFC 8439 Poly1305
  KAT by `determ test-chacha20-c99`.
- **XChaCha20-Poly1305 + HChaCha20 (commit `09849f6`)**: `xchacha20_poly1305.c` —
  the 192-bit-nonce AEAD = HChaCha20 subkey + the ChaCha20-Poly1305 above, per
  draft-irtf-cfrg-xchacha. Validated by `determ test-xchacha-c99`: HChaCha20 vs the
  draft §2.2.1 KAT, and the full AEAD byte-equal vs OpenSSL's inner ChaCha20-Poly1305
  on the derived (subkey, nonce) — since XChaCha20-Poly1305 IS that composition.
- Constant-time: ChaCha is ARX (no table/branch); Poly1305 + both AEAD tag compares
  are branchless aggregate-difference (audit §4).

### 3.5 AES-256-GCM (~6 days)

- Implement from NIST FIPS 197 + SP 800-38D references
- Constant-time GHASH implementation (critical for GCM)
- Test vectors from NIST CAVP
- Optional: vendor BearSSL's AES-GCM if its license permits (cleaner CT discipline)

> **COMPLETE — constant-time end to end** (`src/crypto/aes/{aes_core.c,aes_gcm.c}`,
> commits `facf915` + `a053964` + the S-box CT-hardening). The GHASH is BRANCHLESS
> / constant-time (bit-serial GF(2^128) with a mask-based reduction — no
> secret-dependent branch), and the S-box is computed arithmetically — the GF(2^8)
> inverse via a fixed x^254 addition chain over a branchless field multiply, then
> the FIPS-197 affine map — so there is no key-dependent table lookup and hence no
> cache-timing channel. `determ test-aes-c99` validates nine assertions: an
> exhaustive proof that the constant-time S-box equals the canonical FIPS-197 table
> over all 256 inputs; the AES-256 block vs the FIPS-197 C.3 KAT and byte-equal vs
> OpenSSL `EVP_aes_256_ecb`; the full AES-256-GCM (ciphertext AND tag) byte-equal
> vs OpenSSL `EVP_aes_256_gcm` over a (plaintext,aad)-length grid; and a GCM
> decrypt round-trip + tamper rejection of the tag, the ciphertext, and the AAD
> (value-flip + length-mismatch — the AAD-binding negative paths). The module
> is CT-clean for the keyfile-envelope (S-004) call site; a bitsliced / Boyar-
> Peralta / AES-NI S-box would be faster but is an optional throughput
> optimization, not a security gate (the S-004 use is one-shot).

### 3.6 Argon2id — **SHIPPED** (BLAKE2b `695d4f4` + Argon2id `00e3efb`)

- **BLAKE2b (Argon2's underlying hash):** `src/crypto/blake2/blake2b.c`, canonical
  RFC 7693, validated by `determ test-blake2b-c99`.
- **Argon2id core:** `src/crypto/argon2/argon2id.c` — the complete RFC 9106 / P-H-C
  reference on that BLAKE2b: H0 init hash, the H' variable-length hash, the
  fBlaMka + P + G 1024-byte compression, the Argon2id hybrid addressing (pass-0
  first-half data-independent / rest data-dependent), `index_alpha` reference
  selection, cross-lane XOR → H'-tag. Explicit-parameter raw API
  `determ_argon2id(out, outlen, pwd, salt, t_cost, m_cost, parallelism)`.
- **Validation:** byte-exact vs libsodium `crypto_pwhash_argon2id` (which calls
  `argon2id_hash_raw(opslimit, memlimit/1024, lanes=1, v0x13)` internally) — a
  standalone harness linking the build tree's `libsodium.a` matched 12/12 over a
  t×m grid; `determ test-argon2id-c99` pins 4 of those libsodium-generated vectors
  (the determ daemon is libsodium-free, so they are captured not computed live).
- **Memory-hard, NOT constant-time in the data-dependent passes** by design (Argon2d
  GPU-resistance); the Argon2id hybrid keeps the secret-derived addressing of pass-0
  first-half data-independent (RFC 9106 §3.4). The intended consumer is the
  passphrase keyfile KDF. (Call-site reality: the v2.17/S-004 envelope today
  derives via OpenSSL `PKCS5_PBKDF2_HMAC` (`wallet/envelope.cpp::derive_key`);
  the tree's only libsodium `crypto_pwhash` caller is the wallet OPAQUE stub
  (`wallet/opaque_primitives.cpp::argon2id`) — `determ_argon2id` is the
  byte-equal drop-in THERE, while an envelope PBKDF2→Argon2id switch is an
  on-disk format change. See `src/crypto/argon2/README.md` §5.)

### 3.7 secp256k1 + libsecp256k1-zkp (~10 days)

- Vendor libsecp256k1 from Bitcoin Core, pinned version
- Vendor libsecp256k1-zkp from Blockstream / Grin
- Integrate into Determ's build (CMake target per sub-lib)
- Test vectors from libsecp256k1's test suite
- Documented config: enable Bulletproofs module, ECDH, Schnorr signing, hash-to-curve

### 3.8 FROST-Ed25519 from RFC 9591 (~7-10 days)

- Implement DKG protocol per RFC 9591 §3
- Polynomial-commitment generation, share distribution, complaint phase, finalize
- Proactive Secret Sharing (PSS) refresh extension — **SHIPPED**: `determ_frost_pss_commit`
  (zero-hole Feldman commitments) + `determ_frost_pss_verify_commit` (the `C_0 == [0]B`
  zero-hole proof); refreshed share `s'_j = s_j + Σ_i δ_i(j)` rotates every share
  under the unchanged group key (Herzberg et al. 1995), validated by `determ test-frost-c99`
  §6 (proof: `FrostThresholdSoundness.md` T-6)
- Partial signing + aggregation — **SHIPPED**: centralized `determ_frost_sign` plus
  the distributed two-round split `determ_frost_sign_partial` (per-signer round-2
  share) + `determ_frost_aggregate` (sum + shared-R recompute); the distributed
  path is byte-identical to the centralized one (asserted by `determ test-frost-c99`)
- Test vectors from RFC 9591 Appendix C
- Reference cross-check: zcash/frost-ed25519 (Rust) output comparison

### 3.8b PBKDF2-HMAC-SHA-256 for FIPS profile (~1 day)

- Implement RFC 8018 PBKDF2 (FIPS-validated SP 800-132)
- Used by `cluster` + `tactical` profile keyfile encryption (instead of Argon2id)
- Trivial wrapper over HMAC-SHA-256
- Test vectors from NIST CAVP

### 3.8c NIST P-256 for FIPS profile (~5 days)

- Vendor P-256 from a mature C99 source (BearSSL or NIST reference)
- ECDH + scalar multiplication
- Field arithmetic (mod p256 prime)
- Constant-time discipline
- Test vectors from NIST CAVP
- Used by FIPS-profile (cluster + tactical) prime-order operations

### 3.9a OPRF on secp256k1 from voprf draft + RFC 9380 (~7 days)

- Implement OPRF-secp256k1 cipher suite from voprf draft (used by MODERN profile)
- Hash-to-curve for secp256k1 per RFC 9380 (SSWU map)
- DLEQ proof generation + verification (for verifiable OPRF)
- Test vectors from voprf draft + RFC 9380

### 3.9b OPRF on NIST P-256 from voprf draft + RFC 9380 (~4 days)

- Implement OPRF-P256 cipher suite from voprf draft (used by FIPS profile / cluster + tactical)
- Hash-to-curve for P-256 per RFC 9380 (SSWU map for P-256)
- DLEQ proof generation + verification on P-256 group
- Test vectors from voprf draft + RFC 9380 P-256 mode
- Smaller than 3.9a because P-256 primitives already in `src/crypto/p256/` from §3.8c

### 3.10 Constant-time primitives — **SHIPPED**

- `determ_ct_memcmp` (`include/determ/crypto/ct.h` + `src/crypto/ct.c`) —
  equality-only compare, no short-circuit, OR-accumulated XOR over the full
  length, 0/-1 collapse via the unsigned-borrow idiom (libsodium
  `crypto_verify` shape). Consolidates the per-module local helpers the stack
  had accumulated: `ct_eq16` (aes_gcm.c, chacha20_poly1305.c), `ct_verify_32`
  (ed25519.c), and frost.c's two PoP/VSS point-compare `memcmp`s (public
  operands — uniform discipline there, not a leak fix).
- The "ct_zero" half shipped earlier as `determ_secure_zero`
  (`include/determ/crypto/secure_zero.h`, volatile-indirection memset).
- Documented usage notes live in `ct.h` (equality-only — no lexicographic
  order; use on every secret-adjacent compare; `len` is public).
- Validated by `determ test-ct-c99` (6 assertions: boundary lengths,
  first/middle/last mismatch positions, 500-case verdict-equality fuzz vs
  memcmp, strict 0/-1 contract, wipe + no-op pins). The TIMING property
  itself is §3.12's dudect/ctgrind follow-up.

### 3.11 Unified API + C++ wrapper — **SEEDED** (two Q5 deviations recorded)

- `include/determ/crypto.h` — SHIPPED as an UMBRELLA over the per-module
  headers (one include for the whole shipped C99 layer) rather than the Q5
  struct-typedef signature set — that sketch predates the shipped raw-buffer
  APIs, and a second C-level signature set over the same primitives is churn
  without safety gain (type safety lives in the C++ wrapper). FROST + the
  ed25519 group primitives deliberately excluded (library-only per
  FROST_DEVIATION_NOTICE.md; explicit include opt-in).
- `include/determ/crypto.hpp` — SHIPPED header-only in namespace
  **`determ::c99`**, NOT Q5's `determ::crypto`: that namespace is the
  production OpenSSL-backed layer (sha256.hpp / merkle.hpp / keys.hpp) with an
  overlapping `sha256` name and different return types. The wrapper folds into
  `determ::crypto` at the §3.15 migration when the OpenSSL layer retires.
  Conventions: `std::span` in, `std::array`/`std::vector` out; parameter
  errors throw `std::runtime_error`; AEAD auth failure + X25519 low-order
  return `std::nullopt` (normal adversarial outcomes, not exceptions).
- Validated by `determ test-c99-api` (wrapper output == raw C API output per
  primitive, with KAT anchors; the full AEAD tamper -> nullopt contract).
- Remaining for full §3.11: RAII incremental/streaming state (BLAKE2b first —
  the only shipped streaming C API), the caller-refactor mechanical-edit test
  (lands with §3.15), and umbrella rows for §3.7/§3.8c/§3.9 as they ship.

### 3.12 Constant-time verification framework (~3-5 days)

- Vendor dudect or ctgrind
- Integrate into CI
- Per-primitive constant-time test
- Reports + documentation

### 3.13 Test-vector validation — **SEEDED** (both halves live for the shipped primitives)

- `tools/vectors/<primitive>.json` — 10 files / 52 vectors for the shipped
  families (SHA-256/512 incl. the million-'a' `repeat` form, HMAC RFC 4231
  TC1-7, HKDF A.1-A.3 + TC2-long + L∈{0,32,8160} edges, PBKDF2, BLAKE2b incl.
  two-block keyed + 64-byte-key edges, ChaCha20-Poly1305 + AES-256-GCM incl.
  generated block-boundary cases, Ed25519 incl. §7.1 TEST SHA(abc), X25519
  incl. the full §6.1 DH exchange + the §5.2 iterated vector at 1 and 1,000
  iterations). Mixed provenance is declared per-file in each `source` field
  (published RFC/NIST KATs + cryptography.hazmat-generated boundary cases).
  No-fabrication rule: every vector was mechanically recomputed before
  inclusion; argon2id omitted (no local oracle) — its KATs stay pinned in
  `test-argon2id-c99`. The trust analysis of the two-half gate is proof FB68
  (`VectorGateComposition.md`); the corpus count is deliberately NOT pinned
  in the proof (it pins the file set + mechanics, so the corpus can grow
  without re-staling it).
- File half: `tools/test_c99_vector_files.sh` validates every JSON against
  INDEPENDENT python implementations (hashlib / cryptography.hazmat) — a bad
  vector file goes RED without the determ binary.
- Binary half: `determ test-c99-vectors` (+ `tools/test_c99_vectors.sh`, in
  FAST=1) runs the same vetted vectors through the shipped C99
  implementations — a divergence with the file half green means OUR code is
  wrong. AEAD entries also assert the decrypt round-trip; Ed25519 asserts
  pubkey + sign + verify; missing file / unknown discriminator is a hard FAIL.
- Remaining for full §3.13: vectors for future primitives as they ship
  (secp256k1, P-256, OPRF), libsodium cross-validation during §3.15 migration,
  CI wiring.

### 3.14 Build system + module structure (~3 days)

- CMake targets per `src/crypto/<module>/`
- Each module compiles as static lib
- Top-level `libdeterm-crypto` aggregates all modules
- Cross-compilation verified (x86-64, ARM64, Linux/Windows/MINIX)
- libsodium dropped from CMakeLists

### 3.15 Migration of existing callers (~5 days)

- Refactor every libsodium call site to `determ::crypto::` API
- Existing 152 in-process test subcommands continue passing
- New `determ test-crypto-*` subcommands added per primitive
- libsodium removed from build

### 3.16 Documentation (~3 days)

- Update SECURITY.md crypto-dependency list (libsodium removed)
- Update WHITEPAPER cryptographic primitives section
- Update V2-DESIGN.md crypto cascades (v2.10/v2.22/v2.25 reflect new substrate)
- Per-module README documenting provenance + version pin + audit notes
- This spec doc as the central reference

---

## 4. Total estimated cost

| Sub-component | Effort | Profile |
|---|---|---|
| SHA-256/SHA-512 + HMAC + HKDF | 2 days | Both |
| Ed25519 (ref10) | 6 days | Both |
| X25519 (curve25519-donna) | 4 days | Both |
| ChaCha20-Poly1305 + XChaCha20 | 4 days | MODERN |
| AES-256-GCM | 6 days | FIPS |
| Argon2id (P-H-C) | 6 days | MODERN |
| PBKDF2-HMAC-SHA-256 | 1 day | FIPS |
| secp256k1 + libsecp256k1-zkp | 10 days | MODERN |
| NIST P-256 | 5 days | FIPS |
| FROST-Ed25519 from RFC 9591 | 7-10 days | Both |
| OPRF on secp256k1 | 7 days | MODERN |
| OPRF on NIST P-256 | 4 days | FIPS |
| Constant-time primitives | 1 day | Both |
| Unified API + C++ wrapper (incl. profile-aware AEAD/KDF/curve selection) | 4 days | Both |
| Constant-time verification framework | 3-5 days | Both |
| Test-vector validation | 4-6 days | Both |
| Build system + module structure | 3 days | Both |
| Migration of existing callers | 5 days | Both |
| Documentation | 3 days | Both |
| **Total** | **~85-95 working days = ~17-19 weeks (~4-4.5 months) of senior crypto engineering** |

Larger than the prior ~6-8 week estimate because the user's full vision includes:
- secp256k1 + libsecp256k1-zkp integration (not just libsodium vendor)
- FROST-Ed25519 implemented from RFC 9591 (not via libsodium)
- OPRF on secp256k1 from scratch (not via libsodium)
- ristretto255 fully eliminated (no vendoring needed but no use either)
- Modular structure with proper build system + constant-time verification framework

This is a comprehensive cryptographic-stack overhaul.

**Scheduling:** runs as Phase 0 Track 2, parallel with DSF construction (Track 1, ~3-4 weeks). If two cryptographic engineers + one DS engineer are available, all three tracks complete in ~17-19 weeks before Phase A starts. Outer envelope grows from ~9-12 months to ~12-15 months (adds ~3-4 months for the dual-profile C99 crypto overhaul covering both MODERN and FIPS cryptographic stacks).

If only one engineer is available, total adds ~3.5-4 months to the schedule — pushing outer envelope to ~13-16 months. Trade-off against permanent NH1/NH2/NH4 readiness + zero libsodium dependence.

---

## 5. Risks and rollback plan

**Risk: Audit risk during transition.** Replacing battle-tested libsodium with vendored reference implementations introduces opportunities for integration-level bugs (memory management, ABI boundaries, build-flag interactions). Even reference impls have failure modes when integrated freshly.

*Mitigation.* Cross-validation against libsodium outputs throughout migration (every test vector run on both side-by-side; verify byte-equal). Bug-bounty period before declaring migration complete. Defer-libsodium-removal until cross-validation has been clean for ~4 weeks of production exposure.

**Risk: FROST-Ed25519 implementation bug.** Implementing a threshold-signature scheme from RFC 9591 is non-trivial. DKG complaint phase, PSS refresh edge cases, threshold-aggregation correctness are subtle.

*Mitigation.* Cross-check every test vector against zcash/frost-ed25519 (Rust reference). DSF scenarios specifically targeting FROST edge cases (per DSF-SPEC). Pre-implementation review of the FROST module per a focused checklist (analogous to F2-SPEC §6).

**Risk: OPRF on secp256k1 implementation bug.** Less canonical than ristretto255 OPRF. Hash-to-curve for secp256k1 (RFC 9380 SSWU map) has specific constant-time + correctness requirements.

*Mitigation.* Implement per voprf draft + RFC 9380; validate test vectors from both. Independent review of hash-to-curve before integration.

**Risk: secp256k1 + libsecp256k1-zkp build complexity.** libsecp256k1 has complex build configuration (which modules to enable, which optimizations). libsecp256k1-zkp adds another layer.

*Mitigation.* Pinned upstream commit + documented build config. Vendor the build configuration alongside the source. Reproducible build via deterministic compilation flags.

**Risk: AES-GCM constant-time GHASH.** GHASH (Galois field multiplication) has known constant-time pitfalls. Reference implementations vary in CT quality.

*Mitigation.* Use BearSSL's AES-GCM implementation if license permits (BearSSL has carefully-engineered CT GHASH). Otherwise, implement GHASH with Karatsuba multiplication and CT-friendly reduction. Independent CT verification via dudect. **Resolved for the shipped GHASH (`src/crypto/aes/aes_gcm.c`):** implemented as a branchless bit-serial GF(2^128) multiply — the per-bit select uses a full-width mask `(uint8_t)(0u - xbit)` and the reduction is `V[0] ^= 0xe1 & (uint8_t)(0u - lsb)`, so there is no secret-dependent branch or memory-access pattern in the multiply/reduce path. (The residual CT exposure is the table-based AES S-box, tracked under §3.5, not GHASH.)

**Risk: Build system + cross-compilation breakage.** Modular sub-library structure adds CMake complexity.

*Mitigation.* Each module compiles standalone first; then integrated; then CI runs cross-compile for all targets. Documented build recipes per platform.

**Rollback plan.** If the C99 crypto vendoring introduces unfixable issues:
1. Re-enable libsodium dependency in CMakeLists (back-out)
2. Refactor `determ::crypto::` calls back to libsodium (mechanical)
3. Existing libsodium test suite verifies behavior
4. Cost: ~1 week to roll back; loses C99 crypto investment but preserves Determ's safety

Rollback is feasible at any point because libsodium remains a viable alternative until the migration is complete + validated.

---

## 6. What this enables downstream

C99 cryptographic stack delivers:

- **NH1 alignment from today.** When NH1 Stage 2 (C99 rewrite) ships, the cryptographic layer is inherited unchanged. Zero re-vendoring at NH1 trigger.
- **NH2 binary attestation.** Every cryptographic byte in the attested binary is from Determ's source tree with documented provenance + version pin. Attestation perimeter cleanly bounded.
- **NH4 FIPS path enabled.** Per-primitive replacement to FIPS-validated reference modules straightforward at NH4 trigger (per-module structure makes this surgical).
- **Embedded target portability.** All primitives compile cleanly on MINIX, RTOS, embedded ARM. NH1 secondary OS targets unblocked.
- **Audit transparency.** Auditors review actual Determ source + per-primitive provenance vs. "trust libsodium." Audit perimeter precise.
- **Cryptographic-stack control.** Determ team owns release cadence + security advisory tracking. Supply-chain isolation from libsodium upstream.
- **Smaller binary.** No libsodium link (~500KB saved). libsecp256k1 + libsecp256k1-zkp add ~300KB. Net: ~200KB binary reduction.

---

## 7. Decision review

This spec is recommended to be reviewed before implementation. Reviewers should confirm:

1. **Q1 two curve families (curve25519 + secp256k1).** Acceptable trade-off vs. "single curve family" preference? Alternative: keep ristretto255 (vendor libsodium); preserves single family but retains libsodium-derived code.
2. **Q2 ristretto255 elimination.** Acceptable that v2.25 OPRF uses secp256k1 (non-canonical) instead of ristretto255 (canonical voprf cipher suite)?
3. **Q3 per-primitive vendoring sources.** Each source acceptable for in-tree vendoring? License + provenance + version pinning approach acceptable?
4. **Q4 modular sub-library structure.** Build complexity acceptable for the cleanness gain?
5. **Q5 unified C99 API.** API shape acceptable? Migration burden from libsodium API tolerable?
6. **Q6 constant-time discipline.** dudect + manual review sufficient? Or should ctgrind be added?
7. **Q7 test-vector sources.** Canonical sources per primitive identified and acceptable?
8. **Q8 cross-platform targets.** Required targets list (x86-64, ARM64, Linux, Windows, MINIX) acceptable?
9. **Q9 libsodium removal trigger.** Acceptable to keep libsodium until cross-validation clean for ~4 weeks?
10. **Total cost.** ~17-19 weeks senior cryptographic engineering acceptable for dual-profile (MODERN + FIPS) coverage vs. ~6-8 weeks libsodium-derived alternative?
11. **Profile bundling (Q10).** Cryptographic profile (MODERN vs FIPS) bundled into `TimingProfile` rather than orthogonal genesis field. `cluster` + `tactical` bundle FIPS; `web` + `regional` + `global` bundle MODERN. Acceptable that confidential transactions (v2.22) are unavailable in FIPS profiles?

Once these are confirmed, implementation can proceed against §3 work units.

---

## 8. What this enables: long-term protocol position

Post-Phase 0 with this crypto stack:

**Determ becomes a "from-scratch-auditable" payment + identity + DSSO chain.** Every cryptographic byte traceable to a public-domain reference + version pin. No external cryptographic library dependency. Compiles on any C99-capable target. Modular structure permits per-primitive replacement for FIPS / military / embedded deployments without touching the broader codebase.

**Compared to peer chains:** unique combination of cryptographic-stack independence + production-tested primitives (Bitcoin's libsecp256k1 + Bernstein's ref10 + libsecp256k1-zkp + P-H-C Argon2id + NIST AES-GCM + RFC reference ChaCha20-Poly1305). No chain currently delivers this combination.

**The audit story:** "Here are 22-24K lines of cryptographic code, every line traceable to a canonical reference, every byte verified against published test vectors, every primitive verified constant-time." This is substantially stronger than "we use libsodium."

---

*End of specification.*
