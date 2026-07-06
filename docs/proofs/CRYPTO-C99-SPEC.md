> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# Determ cryptographic stack — C99-native, libsodium-free, modular

> **NOTICE 2026-06-07 — FROST removed from v1.1 chain consensus path.** Per `FROST_DEVIATION_NOTICE.md`, FROST was identified as a Claude-introduced design deviation, not part of Stoyan Denev's original Determ design. The §3.8 FROST-Ed25519 implementation under `src/crypto/frost/` is retained as a library (DApp-layer use post-launch is allowed) but is NOT part of the v1.1 consensus path, NOT part of the v1.1-locked formal-verification surface, and any re-introduction into chain consensus requires Stoyan's explicit sign-off per `FROST_DEVIATION_NOTICE.md §3`. All §3.1–§3.7 primitives (SHA-2, HMAC, HKDF, PBKDF2, ChaCha20-Poly1305, AES-256-GCM, Ed25519, X25519, BLAKE2b) remain in v1.1 scope; only §3.8 FROST is excluded from the consensus-path commitment.

**Status:** architecture spec + Phase-0 implementation underway. Resolves the cryptographic-stack architecture for Phase 0 / Phase A: vendor every primitive Determ uses as independent C99 source organized into modular sub-libraries; eliminate libsodium dependency entirely; deliver a clean C API consumable from C++20 (current Determ) and from C99 (future NH1 Stage 2 rewrite). **Landed (validated byte-equal vs OpenSSL + published KATs, additive — not yet wired into call sites):** §3.10 constant-time primitives (`determ_ct_memcmp` + `determ_secure_zero` — the one §3.10 piece every other module consumes), §3.1 SHA-256/512 + HMAC + HKDF, §3.8b PBKDF2-HMAC-SHA-256, §3.4 ChaCha20-Poly1305 AEAD, §3.5 AES-256-GCM (complete — constant-time end to end: branchless GHASH + arithmetic, no-table S-box), §3.2 Ed25519 (RFC 8032 sign/verify + scalar/point arithmetic — the FROST EC prerequisite), §3.8c NIST P-256 (from-scratch Montgomery field + RCB complete addition + CT ladder — the FIPS-profile curve; constants gated vs OpenSSL EC_GROUP), **§3.8 FROST-Ed25519** (trusted-dealer + **trustless DKG** keygen — Pedersen DKG with Feldman VSS + proof-of-possession, RFC 9591 §6.6, so no single party learns the group secret — plus two-round threshold signing whose t-of-n aggregate verifies as a plain Ed25519 signature under the group key — all validated under OpenSSL; RFC 9591 E.1 interop now gated via `tools/vectors/frost_ed25519_rfc9591.json` through both §3.13 halves — keygen shares + group pk byte-exact, reconstruct recovers the vector sk, the RFC aggregate verifies under the C99 Ed25519, and determ_frost_sign with the RFC's own nonces yields a valid group-key signature; the binding-factor transcript itself stays deliberately domain-separated (DETERM-FROST-RHO, src/crypto/frost/README.md §5); the module is FROZEN per the NOTICE §6 amendment 2026-07-03 — the RFC-mode transcript is closed-by-freeze, not pending). **Note on §3.2:** the shipped implementation is a constant-time, table-free `gf[16]` (radix-2^16) field + cswap-ladder, derived from the public-domain TweetNaCl construction, rather than the originally-planned `ref10` radix-2^51 + precomputed-base-table form. The choice is correctness-first: TweetNaCl is small, auditable, and constant-time, and avoids the ~30 KB precomputed base table that is infeasible to vendor by hand; it is validated byte-equal vs OpenSSL `EVP_PKEY_ED25519` + RFC 8032 §7.1. A `ref10`/radix-2^51 variant remains a future throughput optimization (same posture as the AES S-box). Remaining Phase-0: the FROST primitives (keygen/sign/aggregate) now become implementable on this layer. Implementation tracking lives in [V210ImplementationRoadmap.md](V210ImplementationRoadmap.md).

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
| SHA-3 / SHAKE | `src/crypto/sha3/` | **SHIPPED** — canonical FIPS 202 Keccak-f[1600] (SHA3-256/512 + SHAKE128/256 XOF, incremental sponge); byte-equal vs OpenSSL `EVP_sha3/shake` + `hashlib`; the PQ-track XOF (ML-DSA §3.17) | Public domain | ~150 |
| ML-DSA / Dilithium | `src/crypto/mldsa/` | **SHIPPED (inc.1-8 — COMPLETE)** — FIPS 204 the whole scheme: Z_q reduction + negacyclic NTT (+direct-DFT oracle) + rounding/hint + SHAKE samplers + bit-packing + per-poly ring ops + matrix/vector layer + **KeyGen + Sign + Verify**, all **ACVP-pinned (3 param sets)**; §3.18. Additive; chain integration is the next (owner-gated) step. | Public domain | ~740 |
| Pedersen commitment + Bulletproofs IPA + range proof (single + aggregated) + balance proof + composition | `src/crypto/pedersen/` | **SHIPPED (confidential-tx track inc.1-8)** — inc.1 `C = v*G + r*H` over P-256 (H a nothing-up-my-sleeve RFC 9380 hash-to-curve gen); inc.2 the vector commit `C = r*H + Σ(a_i*G_i + b_i*H_i)` over two nothing-up-my-sleeve generator families (the Bulletproofs A/S shape); inc.3 the general MSM `Σ s_i*P_i` (identity-aware); inc.4 the **Bulletproofs inner-product argument** `P = <a,g> + <b,h> + <a,b>*u` in `2*log2(n)` points + 2 scalars (`ipa.c`); inc.5 the **single-value range proof** — a committed `v ∈ [0, 2^n)` in `2*log2(n)+O(1)` elements, wrapping the IPA (`rangeproof.c`); inc.6 the **aggregated range proof** — `m` values in one `2*log2(m*n)+O(1)`-element proof (value `j`'s slot scaled by `z^(2+j)`, IPA over `m*n`); all non-interactive via deterministic Fiat-Shamir; pure composition over §3.8c P-256; binding + hiding + homomorphism gated by `test-pedersen-c99`, the IPA by `test-bp-ipa-c99`, the range proofs by `test-bp-rangeproof-c99` + `test-bp-agg-rangeproof-c99`, each with a dual-oracle corpus (`pedersen.json` + `bp_ipa.json` + `bp_rangeproof.json` + `bp_agg_rangeproof.json`); inc.7 the **confidential-tx balance proof** — a Schnorr PoK that the excess `E = Σ C_in − Σ C_out − fee*G` opens to zero (`E = x*H`, amount conservation), `balance.c` (zero sealed-code change), gated by `test-p256-balance-c99` + `p256_balance.json`; inc.8 the **end-to-end confidential-tx composition** (per-output range proof + balance proof, pinning `V_j == C_out[j]` + the balance-catches-inflation / range-catches-out-of-range division of labour, `test-p256-confidential-tx-c99`); §3.19. The confidential-tx LIBRARY is complete — the FIPS-profile P-256 stack now offers the same primitive set as the MODERN-profile §3.20 `Z_p*` stack; a confidential-tx chain integration is the next (owner-gated) step. | Public domain | ~900 |
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
├── sha3/                       # SHIPPED: SHA-3/SHAKE (FIPS 202) Keccak-f[1600]
│   └── sha3.c                  #   PQ-track XOF (§3.17); header at include/determ/crypto/sha3/
├── mldsa/                      # SHIPPED (inc.1-8): ML-DSA (Dilithium, FIPS 204) — COMPLETE scheme
│   ├── reduce.c                #   Z_q modular reduction (§3.18)
│   ├── ntt.c                   #   negacyclic NTT of Z_q[X]/(X^256+1) + zetas.inc
│   ├── zetas.inc               #   machine-generated twiddle factors (verify_mldsa_vectors.py)
│   ├── rounding.c              #   power2round / decompose / make+use hint (inc.2)
│   ├── sample.c                #   SHAKE samplers: uniform/eta/in-ball (inc.3) + gamma1 mask (inc.5)
│   ├── pack.c                  #   coefficient bit-packing: t1/t0/eta/w1/z (inc.4)
│   ├── poly.c                  #   per-poly ring ops: add/sub/reduce/caddq/pointwise-Montgomery (inc.5)
│   ├── polyvec.c               #   matrix/vector layer: ExpandA/S/Mask + polyvec + matrix·vector (inc.6)
│   ├── keygen.c                #   ML-DSA.KeyGen_internal + pk/sk encode (inc.7, ACVP-pinned)
│   └── sign.c                  #   ML-DSA.Sign_internal + Verify_internal + sigEncode/hint (inc.8, ACVP-pinned)
├── pedersen/                   # SHIPPED: Pedersen commitment + Bulletproofs IPA + range proof over P-256 (§3.19)
│   ├── pedersen.c              #   inc.1 C=v*G+r*H; inc.2 vector commit r*H+Σ(a_i*G_i+b_i*H_i); inc.3 MSM Σ s_i*P_i (test-pedersen-c99)
│   ├── ipa.c                   #   inc.4 Bulletproofs inner-product argument P=<a,g>+<b,h>+<a,b>*u, 2*log2(n) pts (test-bp-ipa-c99)
│   └── rangeproof.c            #   inc.5 single-value + inc.6 AGGREGATED range proof (m values), wraps the IPA (test-bp-rangeproof-c99 / test-bp-agg-rangeproof-c99)
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
frost/x25519/blake2b/sha3/mldsa/xchacha/argon2id/p256) + the full-stack libsodium-equivalence
harness above are the regression gate.

### Q10: Profile bundling — crypto choice tied to TimingProfile

> **AMENDED 2026-07-03 (authority: Stoyan Denev — `DECISION-LOG.md 2026-07-03`).**
> The build-time half of this decision is SUPERSEDED: the
> `-DDETERM_CRYPTO={modern|fips|universal}` tri-state and its
> `profile_build.hpp` genesis-compat gate are REMOVED. They linked
> identical code in every variant (all modules ship in the one
> `determ-crypto-c99` library), so the "FIPS module boundary" they
> claimed did not exist — and CMVP validation, not algorithm selection,
> is what confers FIPS 140 compliance, which a from-scratch stack cannot
> deliver. What SURVIVES: the profile presets' `crypto_profile` column as
> the documented ALGORITHM POSTURE per deployment archetype. What
> REPLACES the build split for the FIPS market: **FIPS deployments pair
> the FIPS posture with a pluggable CMVP-validated crypto module** (a
> provider interface delegating the FIPS-relevant primitives to a
> certified module, e.g. a validated OpenSSL 3.x FIPS provider). The
> provider interface is FUTURE work, gated on a concrete FIPS customer;
> this amendment records the strategy so the market position is retained
> honestly.

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
`ed25519_group.h` that FROST builds on. Also shipped:
`determ_ed25519_seed_to_x25519_sk` + `determ_ed25519_pk_to_x25519_pk` — the
RFC 7748 birational Ed25519→X25519 key conversions, byte-equal to libsodium's
`crypto_sign_ed25519_{sk,pk}_to_curve25519` (`tools/c99_libsodium_xval.c`), so
a wallet can reuse one Ed25519 identity for X25519 ECDH. Validated by
`determ test-ed25519-c99` (byte-equal vs OpenSSL `EVP_PKEY_ED25519` +
RFC 8032 §7.1) and `determ test-ed25519-vectors`. See the status-header note for why the original
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
  first-half data-independent (RFC 9106 §3.4). **WIRED as the passphrase keyfile
  KDF (R58, 2026-07-04):** the wallet envelope now derives fresh keys via
  `determ_argon2id` (`wallet/envelope.cpp::derive_key_argon2`) by default — the
  `DWE2` layout — instead of PBKDF2 (`derive_key_pbkdf2`, the retained `DWE1`
  interop path). The switch is a versioned, back-compatible on-disk format
  migration (4-byte magic selects the KDF; every `DWE1` envelope still decrypts;
  unknown magic fails closed). Proven in `KeyfileArgon2Migration.md`. This is
  Argon2id's first live caller (the tree's former only libsodium `crypto_pwhash`
  caller was the deleted wallet OPAQUE stub). See `src/crypto/argon2/README.md`
  §5.)

### 3.7 secp256k1 + libsecp256k1-zkp — **DE-SCOPED** (2026-07-03)

> **DE-SCOPED (2026-07-03, authority: Stoyan Denev — `DECISION-LOG.md 2026-07-03`).**
> No consumer exists: v2.22 confidential transactions is FUTURE-tier design-only
> (zero code) and DSSO was re-based to X25519 DLT-A (2026-06-07). Vendoring
> ~9K LOC of third-party curve code would add a lifetime audit obligation for
> nothing shipped. The section below is retained as the design record; reviving
> it requires a new decision with a real consumer.

- Vendor libsecp256k1 from Bitcoin Core, pinned version
- Vendor libsecp256k1-zkp from Blockstream / Grin
- Integrate into Determ's build (CMake target per sub-lib)
- Test vectors from libsecp256k1's test suite
- Documented config: enable Bulletproofs module, ECDH, Schnorr signing, hash-to-curve

### 3.8 FROST-Ed25519 from RFC 9591 — **FROZEN** (2026-07-03; shipped scope retained, no further investment)

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
- Test vectors from RFC 9591 Appendix C — the E.1 signing vector shipped
  (§3.13); further expansion CLOSED BY FREEZE
- **FROZEN (2026-07-03, FROST_DEVIATION_NOTICE.md §6 amendment, authority:
  Stoyan Denev):** the module is retained for audit history + test coverage
  only; existing tests/gates/probes stay green; no further feature, vector,
  probe, or doc investment. The prospective DApp-layer-usefulness rationale
  is withdrawn.
- Reference cross-check: zcash/frost-ed25519 (Rust) output comparison

### 3.8b PBKDF2-HMAC-SHA-256 for FIPS profile (~1 day)

- Implement RFC 8018 PBKDF2 (FIPS-validated SP 800-132)
- Used by `cluster` + `tactical` profile keyfile encryption (instead of Argon2id)
- Trivial wrapper over HMAC-SHA-256
- Test vectors from NIST CAVP

### 3.8c NIST P-256 for FIPS profile — **SHIPPED** (from-scratch, NOT vendored)

- SHIPPED: `src/crypto/p256/p256.c` — implemented FROM SCRATCH per published
  method rather than the originally-planned BearSSL/NIST-reference vendoring
  (third-party code entering the tree is gated on authorization per the house
  external-dependency discipline; from-scratch is the same posture as the
  §3.2 gf[16] Ed25519 deviation). Montgomery field (8×32-bit CIOS; p ≡ −1
  mod 2³² ⇒ n0' = 1), Renes–Costello–Batina complete addition (a = −3,
  exception-free), double-and-add-always cswap ladder, SEC1 uncompressed
  big-endian I/O. R²/b/G Montgomery forms derived at runtime — the only
  transcribed constants (p/n/b/Gx/Gy) are asserted byte-equal against
  OpenSSL's EC_GROUP by the test before any arithmetic is trusted.
- ECDH + scalar multiplication: `determ_p256_base_mul` / `_point_mul`
  (shared secret = the X coordinate), `_point_check`, scalar 0 / ≥ n and
  off-curve / malformed-encoding inputs all rejected.
- Constant-time discipline: no secret-dependent branch or index (uniform
  ladder + mask-select field ops; inversion iterates the public p−2).
- Validated by `determ test-p256-c99` (constants gate + the §Q9 byte-equal
  grid vs OpenSSL + ECDH parity/symmetry + reject paths) and by BOTH §3.13
  vector-gate halves via `tools/vectors/p256.json` (11 hazmat-verified
  vectors generated with library-recovered curve parameters — no memory
  constants on either side). Provenance: `src/crypto/p256/README.md`.
- SHIPPED with §3.9b: hash-to-curve, mod-n arithmetic, SEC1 compressed
  point encode/decode, and the full RFC 9497 OPRF-P256 consumer. Still
  remaining: ECDSA-P256 (only if a FIPS-profile signing consumer appears)
  and P-256-specific NIST CAVP imports (SHA-2/GCM CAVP landed via §3.13;
  the hazmat-verified + RFC-appendix P-256 coverage stands in meanwhile).
  The ConstantTimeInventory §2.9 rows + P256CryptoStackAudit shipped with
  the R47 audit round (P256-CT-1 + 3 zeroization findings, all remediated
  in-session); the tranche-3 probe generators now use full-range [1, n)
  secret scalars.

### 3.9a OPRF on secp256k1 from voprf draft + RFC 9380 — **DE-SCOPED** (2026-07-03)

> **DE-SCOPED with §3.7** (same decision + rationale; the shipped §3.9b
> OPRF-P256 covers the OPRF need for the profiles that ship).

- Implement OPRF-secp256k1 cipher suite from voprf draft (used by MODERN profile)
- Hash-to-curve for secp256k1 per RFC 9380 (SSWU map)
- DLEQ proof generation + verification (for verifiable OPRF)
- Test vectors from voprf draft + RFC 9380

### 3.9b OPRF on NIST P-256 — **SHIPPED** (RFC 9497 P256-SHA256, OPRF + VOPRF, single-element)

SHIPPED (src/crypto/p256/p256.c): the two cryptographic prerequisites —
RFC 9380 hash-to-curve suite P256_XMD:SHA-256_SSWU_RO_ (expand_message_xmd,
hash_to_field m=1/L=48/count=2, simplified SSWU Z=−10 direct/no-isogeny with
branchless mask-selects, RO composition over the RCB complete addition) and
mod-n scalar arithmetic (Montgomery with runtime-derived n0'/R²;
determ_p256_scalar_mul_mod_n / _inv_mod_n — the blind/unblind core).
Validated three ways: `determ test-p256-h2c-c99` (mod-n vs the OpenSSL BIGNUM
oracle + structural h2c gates) and BOTH §3.13 gate halves over
tools/vectors/p256_h2c.json — 15 GENUINE RFC 9380 appendix vectors (K.1 ×10 +
J.1.1 ×5), fetched from rfc-editor.org and re-verified by two independent
pure-python implementations (297/297 checks) before import; the C99 output is
byte-exact against all 15.

The voprf PROTOCOL layer is now SHIPPED too (RFC 9497 P256-SHA256,
single-element): `determ_p256_oprf_derive_key` / `_blind` / `_evaluate` /
`_finalize` (modes OPRF 0x00 + VOPRF 0x01) and the VOPRF DLEQ
`determ_p256_voprf_prove` / `_verify` (ComputeComposites + GenerateProof/
VerifyProof), plus SEC1 `_point_compress` / `_decompress` (the wire format is
compressed, Ne=33) and the two enablers `_point_add` / `_hash_to_scalar`. The
protocol layer is written entirely against the module's PUBLIC API (proving
API sufficiency for downstream consumers). Validated: `determ
test-p256-oprf-c99` (protocol self-consistency — the §3.3.1 blind/evaluate/
finalize == direct-Evaluate identity — plus the DLEQ reject paths: tampered
c / s / eval element / wrong-mode / wrong-key all rejected) AND BOTH §3.13
gate halves over `tools/vectors/p256_oprf.json` — 4 GENUINE RFC 9497
A.3.1/A.3.2 appendix vectors (OPRF + VOPRF), fetched from rfc-editor.org and
re-verified by two independent pure-python RFC 9497 implementations
(72/72 + 297/297 h2c-anchored) before import; the C99 output including the
64-byte proof is byte-exact against all 4, and the protocol pseudocode was
implemented from the FETCHED RFC text, not memory. Remaining for the wider
§3.9 (out of the §3.9b single-element scope): batch (m>1) proofs, the POPRF
mode (0x02), and — if a distinct consumer appears — the §3.9a secp256k1 OPRF.

Original plan (retained):

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
- The `determ::c99::p256` + `determ::c99::oprf_p256` namespaces cover the
  §3.8c/§3.9b surfaces (base_mul/point_mul/point_check/add/compress/
  decompress/mod-n ops/hash_to_curve/hash_to_scalar; derive_key/blind/
  evaluate/finalize/prove/verify) under the same error model — an invalid
  OWN scalar throws (separated from the C layer's conflated -1 by a cheap
  public validity check), adversarial peer inputs return nullopt/false.
- The `determ::c99::mldsa` namespace covers the §3.18 ML-DSA (Dilithium, FIPS
  204) surface (`ParamSet` {44,65,87}; `keygen(ps, seed32)`; `format_message`
  building M' = 0x00‖len(ctx)‖ctx‖M; deterministic `sign(ps, sk, mprime)` with
  an optional 32-byte `rnd` for the hedged variant; `verify(ps, pk, mprime,
  sig)`). Error model: `keygen`/`format_message`/`sign` throw `std::runtime_error`
  on a parameter/context/precondition failure; `verify` returns `bool` (any
  malformed or wrong-length signature -> `false`, never throws). A LIBRARY
  PRIMITIVE — chain integration is separately gated.
- Validated by `determ test-c99-api` (wrapper output == raw C API output per
  primitive, with KAT anchors; the full AEAD tamper -> nullopt contract;
  P-256 DH commutativity + compress round-trip + OPRF protocol identity +
  VOPRF tamper/wrong-mode rejects; ML-DSA keygen→sign→verify round-trip == raw
  C for all three sets, with tamper + short-signature rejection).
- Remaining for full §3.11: RAII incremental/streaming state (BLAKE2b first —
  the only shipped streaming C API), the caller-refactor mechanical-edit test
  (lands with §3.15), and umbrella rows for §3.7/§3.9a as they ship.

### 3.12 Constant-time verification framework — **SEEDED** (in-house probe shipped; vendoring still gated)

- `determ ct-timing-probe` — IN-HOUSE fix-vs-random Welch-t leakage probe
  implemented from the published dudect method (design + statistical
  soundness analysis: `TimingProbeDesign.md`; targets: ConstantTimeInventory
  §5). 23 registered targets across four tranches: the tranche-1 core
  (ct-memcmp with 4 mismatch-position classes, chacha/gcm-tag-verify,
  ed25519-sign, x25519, sha256-content negative control), tranche 2
  (aes-core, chacha20-core, poly1305-key, ed25519-pubkey, sc-canonical
  boundary scalars, hmac-key), tranche 3 (p256-base-mul / p256-h2c /
  p256-sc-mul — full-range [1, n) secret classes incl. an n-prefix FIX
  class, the P256-CT-1 lesson), tranche 4 (x25519-base, sc-muladd,
  hmac-sha512, blake2b-keyed, pbkdf2, frost-reconstruct, frost-dkg,
  frost-sign-partial — closing the design-§4 id list except the dedicated
  `ghash` id, which is a static internal exercised via
  gcm-tag-verify/aes-core). REPORTING tool by design — measurement mode stays out of
  run_all.sh/FAST (environmentally flaky); only the deterministic `--selftest`
  statistics fixture is suite-eligible (`tools/test_ct_timing_selftest.sh`).
- Vendoring dudect or ctgrind (third-party code into the tree) remains
  FLAGGED awaiting authorization per TimingProbeDesign.md §1; the ctgrind
  taint-analysis leg needs the Linux/WSL2 valgrind environment either way.
- Remaining: per-build report archiving
  (CSV + build recipe per TimingProbeDesign.md §6); CI wiring decision.

### 3.13 Test-vector validation — **SEEDED** (both halves live for the shipped primitives)

- `tools/vectors/<primitive>.json` — 17 files / 129 vectors for the shipped
  families (SHA-256/512 incl. the million-'a' `repeat` form, HMAC RFC 4231
  TC1-7, HKDF A.1-A.3 + TC2-long + L∈{0,32,8160} edges, PBKDF2, BLAKE2b incl.
  two-block keyed + 64-byte-key edges, ChaCha20-Poly1305 + AES-256-GCM incl.
  generated block-boundary cases, Ed25519 incl. §7.1 TEST SHA(abc), X25519
  incl. the full §6.1 DH exchange + the §5.2 iterated vector at 1 and 1,000
  iterations; the P-256 family per §3.8c/§3.9b — p256.json hazmat-verified
  grid, p256_h2c.json RFC 9380 appendix, p256_oprf.json RFC 9497 A.3.1/A.3.2;
  NIST CAVP imports — sha2_cavp_sha256/sha512.json, 30 entries verbatim from
  shabytetestvectors.zip, + aes_gcm_cavp.json, 16 entries from
  gcmEncryptExtIV256.rsp, both fetched from csrc.nist.gov with the zip/rsp
  SHA-256 pinned in each `source` field; and frost_ed25519_rfc9591.json —
  the RFC 9591 E.1 FROST(Ed25519, SHA-512) 2-of-3 signing vector, §3.8
  note). Mixed provenance is declared per-file in each `source` field
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
  (secp256k1 §3.7/§3.9a, gated), libsodium cross-validation during the §3.15
  migration, CI wiring.

### 3.14 Build system + module structure — **SEEDED** (aggregate static lib)

- SHIPPED: `determ-crypto-c99` STATIC library target (CMakeLists.txt) — all 18
  C99 sources moved out of the `determ` SOURCES list; PUBLIC include dir, so
  any consumer gets the umbrella `determ/crypto.h` + header-only
  `determ/crypto.hpp` by linking. `determ` links it; the full c99 battery is
  validated against the lib-linked binary.
- **libsodium drop — DONE (2026-07-03):** no Determ binary links libsodium.
  The daemon (`determ`) and `determ-light` never did; the last consumer,
  `determ-wallet`, migrated its ~200 call sites across `wallet/main.cpp`
  (Ed25519 sign/verify/derive, X25519, `sodium_memzero`) to `determ::c99`
  via an API-compatible shim (§3.15), and the OPAQUE stub — the tree's only
  `crypto_pwhash` caller — was DELETED with the liboprf track (DECISION-LOG.md
  2026-07-03). libsodium is no longer in any link line; `libsodium.a` is
  retained only as the byte-equal cross-validation oracle
  (`tools/c99_libsodium_xval.c`, §Q9 step 3).
- Remaining: the per-module sub-library split (one aggregate target today —
  splitting buys nothing until a second consumer with a partial-module need
  exists); the cross-compilation matrix (x86-64 / ARM64, Linux/Windows/MINIX
  — only MSVC x64 exercised so far).

### 3.15 Migration of existing callers — **DAEMON + LIGHT SHIPPED; wallet SUBSTANTIALLY DONE** (2026-07-03)

- **DAEMON/CONSENSUS PATH MIGRATED (2026-07-03, authorized by Stoyan — the 1b
  decision).** The daemon's consensus crypto now runs entirely on
  `determ::c99`: `SHA256Builder` (`src/crypto/sha256.cpp`) on the exported
  streaming `determ_sha256_init/update/final` (new in `sha2.h` — the one-shot
  is reimplemented on the same engine, so CAVP + §Q9 keep validating both);
  Ed25519 keygen/sign/verify (`src/crypto/keys.cpp`) on
  `determ_ed25519_pubkey_from_seed`/`_sign`/`_verify`; entropy on the new
  §3.15 OS shim `determ_rng_bytes` (`src/crypto/rng/` — BCryptGenRandom /
  getrandom+urandom; the stack's one non-synthesizable primitive); RPC-auth
  HMAC on `determ_hmac_sha256` (fail-closed); `light/keyfile.cpp` derivation
  on the same c99 calls. **`determ-light` links ZERO OpenSSL**; `determ`
  keeps libcrypto ONLY as the independent §Q9 test-oracle backend inside the
  `test-*-c99` subcommands (by design a non-determ implementation) — libssl
  (never used; no TLS anywhere) is dropped from all targets. Byte-invariance
  proven: `test-consensus-vectors` goldens held byte-for-byte on both MSVC
  and GCC post-swap, and `test-ed25519-vectors` (the designed backend-swap
  detector) passes with `crypto::sign/verify` on the C99 backend. The strict
  RFC 8032 verifier (S < L, canonical pubkey — stricter than OpenSSL's
  lenient decoder on adversarial encodings) is locked in PRE-GENESIS as the
  consensus signature-validity rule (DECISION-LOG.md 2026-07-03): no live
  fleet existed to fork, so the safer rule ships without any rolling-upgrade
  machinery. The EOL OpenSSL 1.1.1w liability is out of the consensus path.
- **`determ-wallet` migrated off libsodium.** The daemon (`determ`) and
  `determ-light` never linked sodium; the wallet was the last consumer, and
  its libsodium call sites now run entirely on `determ::c99` via an
  API-compatible shim in `wallet/main.cpp` (the shim re-exposes the libsodium
  names the wallet used, 1:1, over the C99 primitives): Ed25519
  sign/verify/pubkey (`determ_ed25519_sign` / `_verify` /
  `_pubkey_from_seed`), X25519 (`determ_x25519`), the two new
  Ed25519→X25519 conversions (`determ_ed25519_seed_to_x25519_sk` /
  `_pk_to_x25519_pk`, §3.2), the Argon2id path, and `secure_zero`
  (`determ_secure_zero`). Base64 moved to OpenSSL `EVP_Encode`/`EVP_Decode`.
  `libsodium` is removed from the `determ-wallet` link line (`CMakeLists.txt`).
- **OPAQUE / liboprf track DE-SCOPED (DECISION-LOG.md 2026-07-03).** The wallet
  OPAQUE recovery stub + liboprf scaffolding were DELETED rather than migrated
  (they were the tree's only `crypto_pwhash` caller); `create-recovery` /
  `recover` now support only `--scheme passphrase` (Shamir + OpenSSL PBKDF2 +
  AES-256-GCM envelope). This removes the last migration obligation that would
  otherwise have needed the §3.9 OPRF path.
- Every shim path is byte-equal to the libsodium behaviour it replaced
  (`tools/c99_libsodium_xval.c` + the per-primitive `determ test-*-c99` gates);
  existing in-process `determ test-*` subcommands and the wallet test suite
  continue passing.
- **1c EXECUTED (2026-07-03, same day):** the WALLET is now ZERO-OpenSSL too.
  Every class migrated to `determ::c99`, format-compatible byte-for-byte:
  envelopes (PBKDF2 → `determ_pbkdf2_hmac_sha256`, AES-256-GCM →
  `determ_aes256_gcm_*` — the "decrypt direction gap" turned out to be a
  stale claim (decrypt existed); the REAL §3.5 gap was arbitrary-length IVs,
  closed the same day via the SP 800-38D `gcm_j0` derivation +
  `_encrypt_iv`/`_decrypt_iv`), entropy (`determ_rng_bytes`), HKDF/HMAC
  (`determ_hmac_sha256`), Ed25519 keygen/derive, one-shot SHA-256, and
  base64 (new strict RFC 4648 module `src/crypto/base64/` — the wallet's
  last OpenSSL class). `determ-wallet` links only `determ-crypto-c99`.
  **The vendored OpenSSL (1.1.1w) is now §Q9-test-oracle-only** (inside
  `determ`'s `test-*-c99` subcommands — by design an independent non-determ
  implementation); it is in NO production code path in any binary.
  Remaining residual: opportunistic — the v2.17/S-004 keyfile envelope could
  derive via the shipped `determ_argon2id` instead of PBKDF2 (an on-disk
  format change, §3.6).

### 3.16 Documentation (~3 days)

- Update SECURITY.md crypto-dependency list (libsodium removed)
- Update WHITEPAPER cryptographic primitives section
- Update V2-DESIGN.md crypto cascades (v2.10/v2.22/v2.25 reflect new substrate)
- Per-module README documenting provenance + version pin + audit notes
- This spec doc as the central reference

### 3.17 SHA-3 / SHAKE (FIPS 202) — **SHIPPED** (post-quantum XOF prerequisite)

The libsodium-free, OpenSSL-free Keccak sponge, shipped as **increment 1 of the
owner-authorized on-chain post-quantum signature track**. It exists ahead of a
signature consumer because **ML-DSA / Dilithium (FIPS 204)** is built on SHAKE:
**SHAKE128** expands the public matrix **Â** from the seed ρ, **SHAKE256** drives
coefficient/nonce sampling and the rejection loop, and the same primitive
underlies **SLH-DSA (FIPS 205)**. Shipping the XOF first, KAT-gated, means those
schemes build on a validated sponge.

- **Implementation:** `src/crypto/sha3/sha3.c` + `include/determ/crypto/sha3/sha3.h`
  — Keccak-f[1600] (24 rounds θ ρ π χ ι, canonical RC/ρ-offset/π-permutation
  tables) plus the four FIPS 202 functions (SHA3-256, SHA3-512, SHAKE128,
  SHAKE256) and the incremental sponge context (`determ_keccak_init/absorb/
  finalize/squeeze`) the rejection-sampling loop squeezes in blocks. pad10\*1
  with the `0x06` (SHA-3) / `0x1F` (SHAKE) domain byte. State is little-endian
  lane-packed via explicit shifts (no `uint64`↔`uint8` aliasing) → byte-identical
  across toolchains/endianness.
- **Constant-time:** naturally CT by construction — no secret-dependent branch,
  rotation, or memory index (no S-box table); every branch is on public lengths.
  This is why FIPS 202 is the standard XOF for constant-time lattice signatures.
- **Validation:** `determ test-sha3-c99` (wrapper `tools/test_sha3_c99.sh`,
  FAST-eligible) — byte-equal vs the OpenSSL §Q9 oracle (`EVP_sha3_256/512`,
  `EVP_shake128/256` via `DigestFinalXOF`) over a fuzzed length grid crossing the
  sponge rate boundaries and XOF outputs exceeding the rate, plus the FIPS 202
  KATs, incremental==one-shot, and a rate-boundary byte-by-byte check. The
  `tools/vectors/sha3_shake.json` corpus (`hashlib` oracle, 32 vectors) is wired
  into **both** §3.13 halves (`determ test-c99-vectors` recomputes through
  `sha3.c`; `tools/test_c99_vector_files.sh` recomputes through `hashlib`).
  Module provenance + audit notes: `src/crypto/sha3/README.md`.
- **Scope:** the four named FIPS 202 functions only. No SHA-3-224/384, no
  cSHAKE/KMAC/TupleHash/ParallelHash (SP 800-185), no bit-interleaved/SIMD path
  (throughput tuning is a later optimization, not a security gate). ML-DSA itself
  is a later increment; today the module is additive with no in-tree signature
  consumer.

### 3.18 ML-DSA / Dilithium (FIPS 204) — **SHIPPED (increments 1-8: the COMPLETE scheme — KeyGen + Sign + Verify, all ACVP-pinned)**

The on-chain post-quantum SIGNATURE track (owner-authorized 2026-07-04 — see the
governance reversal in `DECISION-LOG.md` and the reopened
`AnonAddressDerivationMigration.md`). ML-DSA is executed **incrementally,
library-primitive-first, KAT-gated with zero consensus touch** (the Ed25519 /
P-256 / Argon2id pattern); chain integration + the anon-address-format reopening
are later, separately-reviewed steps. Increment 1 is the ring **arithmetic core**
that every parameter set (ML-DSA-44/65/87) shares.

- **Implementation:** `src/crypto/mldsa/` — `params.h` (n = 256, q = 2²³−2¹³+1 =
  8380417, `QINV`, `MONT`, `D`), `reduce.c` (Montgomery / Barrett reduction +
  conditional-add-q, branchless), `ntt.c` (canonical Dilithium Cooley-Tukey
  forward + Gentleman-Sande inverse negacyclic NTT of Z_q[X]/(X²⁵⁶+1)) over the
  256 twiddle factors in the **machine-generated** `zetas.inc` (derived from the
  primitive 512-th root ζ = 1753 by `tools/verify_mldsa_vectors.py`, never
  hand-transcribed). The NTT turns the O(n²) ring multiply ML-DSA leans on into
  O(n log n). **Built on the §3.17 SHAKE XOF** — ML-DSA expands its public matrix
  Â with SHAKE128 and samples secrets/masks + hashes the message with SHAKE256
  (this increment lays the arithmetic the sampler will feed; it does not yet call
  SHAKE). **Increment 2** adds `rounding.c` — the FIPS 204 coefficient rounding
  the higher layers sit on: `power2round` (t = t1·2^D + t0, the public-key split
  of KEYGEN), `decompose` (HighBits/LowBits around the GAMMA2 grid of SIGNING),
  and `make_hint`/`use_hint` (the signature's per-coefficient carry hint). gamma2
  is a runtime argument (GAMMA2_88 for ML-DSA-44, GAMMA2_32 for ML-DSA-65/87), so
  one core serves all three sets. **Increment 3** adds `sample.c` — the FIRST
  consumers of the §3.17 SHAKE XOF: `sample_uniform` (RejNTTPoly, SHAKE128 →
  coefficients uniform in [0,q), the public matrix Â), `sample_eta` (RejBoundedPoly,
  SHAKE256 → coefficients in [-η,η], the secret vectors; η∈{2,4} runtime), and
  `sample_in_ball` (SHAKE256 → the challenge with exactly τ coefficients in
  {-1,+1}; τ runtime). These couple the SHA-3 module into ML-DSA. Rejection
  sampling has a data-dependent LOOP COUNT (as in the canonical reference — NOT
  constant-time in the number of SHAKE bytes consumed); the coefficient values
  are branchless. `sample_in_ball` fail-safes on an out-of-contract τ (and
  `sample_eta` on an unsupported η) rather than hang/mis-fill — an R65-audit fix,
  since the untrusted vector-file path passes those through. **Increment 4** adds
  `pack.c` — the polynomial ↔ byte codec keygen/sign/verify serialize with:
  `pack_bits`/`unpack_bits` (generic LSB-first) plus the FIPS 204 field encoders
  t1 (10-bit), t0 (13-bit), s1/s2 (η-dependent), w1 (γ2-dependent), z
  (γ1-dependent). Byte-identical to the canonical Dilithium per-field packers
  (verified vs the reference `pack_t1`). **Increment 5** adds `poly.c` — the
  per-polynomial ring operations keygen/sign/verify compose over the NTT +
  samplers: `poly_add`/`poly_sub` (e.g. A·s1 + s2, A·z − c·t1·2^d),
  `poly_reduce`/`poly_caddq` (bring coefficients back into range / to the
  non-negative representative), and `poly_pointwise_montgomery` (the per-poly step
  of a matrix·vector product once both operands are in the NTT domain) — plus
  `sample_gamma1` (ExpandMask / SampleUniformGamma1): SHAKE256 → a FIXED
  256·bits/8-byte squeeze, unpacked into γ1-bit fields mapped f ↦ γ1 − f giving
  coefficients in (−γ1, γ1]. Unlike the other samplers this one does **no
  rejection**, so it IS constant-time in the SHAKE bytes consumed; an unsupported
  γ1 fail-safes to all-zero. **Increment 6** adds `polyvec.c` — the matrix/vector
  layer keygen/sign/verify are written in: the domain-separated seed expansion
  `expand_a` (ExpandA: Â[i][j] = sample_uniform(ρ ‖ col=j ‖ row=i), the k×l public
  matrix, SHAKE128), `expand_s` (ExpandS: s1[i] = sample_eta(ρ' ‖ le16(i)),
  s2[i] = sample_eta(ρ' ‖ le16(l+i)), the secret vectors, SHAKE256), and
  `expand_mask` (ExpandMask: y[i] = sample_gamma1(ρ' ‖ le16(l·κ+i)), the per-round
  mask, SHAKE256); plus the vector arithmetic (polyvec add/sub/reduce/caddq/ntt/
  invntt) and the NTT-domain **matrix·vector product** t = Â·v̂ (pointwise-
  Montgomery accumulate). The dimensions (k, l), η, and γ1 are runtime arguments,
  so this one layer serves ML-DSA-44/65/87 (out-of-range dims are a no-op).
  **Increment 7** adds `keygen.c` — **ML-DSA.KeyGen_internal(ξ)** (FIPS 204
  Algorithm 6), the first TOP-LEVEL operation: (ρ, ρ', K) ← H(ξ ‖ k ‖ l, 128);
  Â ← ExpandA(ρ); (s1, s2) ← ExpandS(ρ'); t ← invNTT(Â ∘ NTT(s1)) + s2;
  (t1, t0) ← Power2Round(t); pk ← pkEncode(ρ, t1); tr ← H(pk, 64);
  sk ← skEncode(ρ, K, tr, s1, s2, t0). Deterministic in the 32-byte seed ξ (no
  internal RNG — the caller supplies ξ, exactly as the ACVP KATs do); the three
  parameter sets are a `determ_mldsa_params{k,l,η,…}` (DETERM_MLDSA_44/65/87). The
  encoded key sizes are 1312/1952/2592 (pk) and 2560/4032/4896 (sk). **Increment 8**
  adds `sign.c` — **ML-DSA.Sign_internal (Alg 7)** and **Verify_internal (Alg 8)**,
  the Fiat-Shamir-with-aborts top level that completes the scheme. Sign runs the
  rejection loop: ExpandMask → w = A·y → the commitment hash c̃ = H(μ‖w1Encode(w1))
  → challenge c = SampleInBall(c̃) → z = y + c·s1, rejecting on the ‖z‖∞ ≥ γ1−β,
  ‖r0‖∞ ≥ γ2−β, ‖c·t0‖∞ ≥ γ2, and #hints > ω bounds, then emits sigEncode(c̃, z, h)
  with the ω+k-byte HintBitPack. Verify recomputes w'Approx = A·ẑ − ĉ·(t1·2^d)^,
  runs UseHint, and checks c̃ = H(μ‖w1Encode(w1')) with the three malformed-hint
  rejections in HintBitUnpack. Sign is **deterministic** in (sk, M', rnd): a 32-byte
  all-zero rnd gives the FIPS 204 deterministic variant (byte-reproducible, as the
  ACVP sigGen KATs use); a random rnd gives the hedged variant. The message M' is
  pre-formatted — for the pure external interface, `determ_mldsa_format_message`
  builds M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M. Signature sizes: 2420/3309/4627.
- **Constant-time:** data-independent by construction — no secret-dependent
  branch, loop bound, or memory index in the butterflies or the reductions. The
  low-word multiply in `montgomery_reduce` is unsigned (no signed-overflow UB);
  the arithmetic right shifts of possibly-negative operands are
  implementation-defined-but-not-UB (the repo's UBSan-clean discipline), and the
  forward-NTT coefficient growth is bounded (< 9q ≈ 2²⁶ < 2³¹) so the un-reduced
  additive butterflies never overflow `int32`.
- **Validation:** `determ test-mldsa-c99` (wrapper `tools/test_mldsa_c99.sh`,
  FAST-eligible) pins correctness WITHOUT an external oracle — the reduction
  contract over a swept grid, the NTT round-trip `invntt_tomont(ntt(a)) ≡ a·2³²
  (mod q)`, the NTT-domain product == from-scratch **O(n²) schoolbook negacyclic
  convolution** (the decisive twiddle-exact gate), an **independent direct-DFT
  oracle** (ntt(X)[j] == root^(2·brv8(j)+1) — a closed-form evaluation reusing
  neither the zetas table nor the butterfly, so a symmetric zeta-ordering bug the
  round-trip + convolution are blind to cannot survive), and the rounding-layer
  contracts (power2round/decompose reconstruction + bounds, the `use_hint`
  semantic round-trip `use_hint(r,[HB(r)≠HB(r+z)])==HB(r+z)`, make_hint's
  definitional formula, and boundary KATs at the decomposition seams — both
  gamma2). `tools/vectors/mldsa_ntt.json` (from-scratch reference in
  `verify_mldsa_vectors.py`, schoolbook + direct-DFT cross-checked) is wired into
  **both** §3.13 halves — `determ test-c99-vectors` matches the exact int32
  forward-NTT output through `ntt.c`; `test_c99_vector_files.sh` recomputes
  through the independent Python reference. The **samplers** are structurally
  gated + KAT'd against an independent SHAKE (python `hashlib`), and — an R65-audit
  hardening — their value MAPPING is cross-checked by an independent representation
  (spec lookup TABLE for eta / in-ball-sign, stdlib `int.from_bytes` for the
  uniform read), since a rule shared by C and python would otherwise hide a
  sign/mask bug. The **bit-packing** is validated by pack↔unpack round-trip AND an
  **independent bit-slice oracle** (each field re-read by absolute bit offset,
  distinct from the unpacker), with t1 byte-checked vs the reference `pack_t1`;
  `mldsa_sample.json` + `mldsa_pack.json` are wired into both §3.13 halves. The
  **gamma1 mask sampler** extends `mldsa_sample.json` (both γ1 = 2¹⁷/2¹⁹) — the C
  squeeze/unpack/subtract is matched byte-for-byte vs the independent hashlib-SHAKE
  reference AND an independent bit-slice field read (distinct from the word-at-a-time
  unpacker), plus a fail-safe-zero check in `test-mldsa-c99`. The **per-poly ring
  ops** are checked in `test-mldsa-c99`: add/sub exact element-wise, reduce/caddq
  residue-preserving within bounds, and `poly_pointwise_montgomery` driven through
  the SAME independent O(n²) schoolbook-negacyclic oracle as the arithmetic core
  (`invntt(pw(ntt a, ntt b)) == schoolbook a·b` — a wrong wrapper cannot pass). The
  R66-audit also closed an out-of-bounds read in the `mldsa_pack` vector-file
  handler (it now derives the compare length from `kind`, never the untrusted JSON
  `bits`). The **matrix/vector layer** is gated in `test-mldsa-c99`: ExpandA/S/Mask
  each re-derive their per-entry seed a SECOND way in the test (independent of the
  loop that produced it) and match the already-gated sampler — pinning the byte
  layout (col-then-row for Â, the s1/s2/y nonce sequence) against a transpose or a
  swapped nonce byte order; and the **matrix·vector product** is driven through the
  SAME independent O(n²) schoolbook-negacyclic oracle as the arithmetic core
  (`invntt(Â·ŝ) == schoolbook A·s`, run on a non-square k≠l set), so a wrong
  pointwise-accumulate, a transposed matrix, or a bad invntt cannot pass. There is
  no external ACVP oracle pre-signer, so those re-derivations + the schoolbook
  oracle are the pin. **Keygen (increment 7) IS the AUTHORITATIVE external pin:**
  `tools/vectors/mldsa_keygen.json` holds the **NIST ACVP** KeyGen KATs (seed →
  pk/sk, from `usnistgov/ACVP-Server` `ML-DSA-keyGen-FIPS204/internalProjection.json`,
  one per parameter set) and is wired into BOTH §3.13 halves — `determ
  test-c99-vectors` runs the shipped C keygen on the ACVP seed and matches pk + sk
  byte-for-byte; `test_c99_vector_files.sh` recomputes through an **independent
  python keygen** (hashlib SHAKE + a from-scratch python NTT, distinct from the C)
  and matches the same frozen NIST bytes, so a bug shared by C and python is still
  caught by the external reference. `test-mldsa-c99` adds the fast structural check
  (pk/sk sizes for all three sets, keygen determinism, the shared-ρ prefix) plus a
  compact SHA-256-pinned ML-DSA-44 KAT. This retroactively pins the whole increment
  1-6 stack: reproducing the ACVP pk/sk exercises the NTT, samplers, packing, ring
  ops, and the ExpandA/S seed layout end-to-end against NIST. **Sign + verify
  (increment 8) are likewise ACVP-pinned:** `tools/vectors/mldsa_sign.json` holds
  the NIST **ACVP sigGen (deterministic)** vectors and `mldsa_verify.json` the
  **sigVer** vectors (both external + internal interface, from `ML-DSA-sigGen/
  sigVer-FIPS204`), wired into BOTH §3.13 halves — `determ test-c99-vectors` runs
  the shipped C Sign_internal and matches the NIST signature **byte-for-byte**
  (deterministic) and runs Verify_internal against the sigVer accept/reject flags
  (including the failure cases that exercise the norm bounds + the three
  HintBitUnpack rejections); `test_c99_vector_files.sh` recomputes through an
  **independent python signer/verifier** (from-scratch NTT, distinct from the C).
  `test-mldsa-c99` adds a self-contained keygen→sign→verify round-trip with
  tamper-detection (flipped sig / flipped message both reject), the sign-determinism
  check, and the external `format_message` layout. Module provenance + audit:
  `src/crypto/mldsa/README.md`.
- **Scope:** the **COMPLETE FIPS 204 signature scheme** — increments 1-6 (ring
  reduction + NTT, rounding/hint, the SHAKE samplers, bit-packing, the per-poly ring
  ops, the matrix/vector layer) + **KeyGen** (inc. 7) + **Sign + Verify** (inc. 8),
  ACVP-pinned for all three parameter sets (ML-DSA-44/65/87). The pure external
  interface is covered (`format_message`); NOT implemented: the prehash HashML-DSA
  variant and the externalMu interface (out of scope for the chain path — the pure
  external + internal interfaces are the ACVP groups that gate this module). **Still
  additive — no in-tree consumer yet.** Next: chain integration (a PQ signature
  option alongside Ed25519) + the anon-address-format reopening, each a
  consensus-critical, separately-reviewed step; and the constant-time hardening
  review of the secret-dependent paths before any production signing use.

### 3.19 Pedersen commitment over P-256 — **SHIPPED (range-proof / confidential-tx track, increments 1-8: range-proof stack + balance proof + end-to-end composition)**

The owner-authorized (2026-07-04) confidential-transaction / range-proof track,
executed **library-primitive-first, KAT-gated, zero consensus touch** (the same
pattern as ML-DSA / P-256 / Argon2id) — chain integration is a later,
separately-reviewed step. Increment 1 is the **Pedersen commitment** itself;
increment 2 adds the **vector-commitment generators + vector commit** (the
Bulletproofs A/S-commitment shape); increment 3 adds the **general
multi-scalar multiplication**; increment 4 adds the **Bulletproofs inner-product
argument** (the log-size core); increment 5 adds the **Bulletproofs single-value
range proof** — the whole point of the track: proving a committed `v` lies in
`[0, 2^n)` without revealing it.

- **Implementation:** `src/crypto/pedersen/` — `C = v*G + r*H` over NIST P-256
  (group order n), where G is the base point and **H is a nothing-up-my-sleeve
  second generator** with unknown log_G(H): `H = hash_to_curve("Determ Pedersen
  generator H over NIST P-256 v1", "DETERM-PEDERSEN-P256_XMD:SHA-256_SSWU_RO_")`
  via the RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` map. **Binding** reduces to the
  unknown discrete log (finding a second opening recovers log_G(H)); **hiding** is
  information-theoretic for a uniform r (the impl rejects r==0). Pure composition
  over the §3.8c P-256 API (`base_mul`/`point_mul`/`point_add`/`hash_to_curve`/
  `compress`) — no new field/group arithmetic; correctness inherited from those
  already-OpenSSL/RFC-gated primitives. API: `determ_pedersen_generator_h` /
  `_commit` / `_verify` / `_add` (32-byte big-endian scalars < n, 33-byte SEC1
  compressed commitments; v==0 allowed, r==0 rejected).
- **Increment 2 — vector commitment (`caf6e50`):** `determ_pedersen_gen(index,
  which)` derives two independent nothing-up-my-sleeve generator FAMILIES
  `G_i`/`H_i` = `hash_to_curve(4-byte BE index, "DETERM-PEDERSEN-VEC-{G,H}-P256_
  XMD:SHA-256_SSWU_RO_")` — no known dlog to `G`, to the scalar `H`, or to each
  other. `determ_pedersen_vector_commit(a, b, n, r)` computes the Bulletproofs
  A/S-commitment shape **`C = r*H + Σ_{i<n}(a_i*G_i + b_i*H_i)`** (r = blinding,
  a = a_L, b = a_R). A zero-scalar term is skipped — a documented data-dependent
  branch; a range prover over SECRET bit-vectors needs a constant-time multi-exp
  (owner-gated CT hardening). Still pure composition over the P-256 API.
- **Increment 3 — general multi-scalar multiplication (`32ded5e`):**
  `determ_pedersen_msm(scalars, points, n)` = **`Σ_{i<n} s_i*P_i`** over ARBITRARY
  points — the operation the Bulletproofs inner-product argument (increment 4)
  reduces its L/R commitments and generator-folding to (`vector_commit`
  is its special case over the `[H, G_i, H_i]` list). 3-way return (the sum MAY be
  the group identity, which has no 33-byte SEC1 encoding): 0 = the sum; 1 = the
  identity (n==0 / canceling terms); -1 = a scalar ≥ n_order or a point fails to
  decode. Identity-aware accumulator; zero-scalar skip (same CT caveat).
- **Increment 4 — Bulletproofs inner-product argument (`732727f`):**
  `src/crypto/pedersen/ipa.c` — the log-size proof of knowledge of vectors `a`,`b`
  behind **`P = <a,g> + <b,h> + <a,b>*u`** in **`2*log2(n)` points + 2 scalars**
  (`determ_ipa_proof_len(n) = 66*log2(n) + 64`). `determ_ipa_commit(a,b,n)` forms
  `P`; `determ_ipa_prove` emits the proof; `determ_ipa_verify` checks it. Each
  recursion round folds `(a,g)`/`(b,h)` under a Fiat-Shamir challenge `x`: it
  commits the cross-terms `L = <a_lo,g_hi>+<b_hi,h_lo>+<a_lo,b_hi>*u` and `R`
  (symmetric), derives `x` by hashing the running transcript, and folds
  `a' = x*a_lo + x⁻¹*a_hi`, `b' = x⁻¹*b_lo + x*b_hi`, `g' = x⁻¹*g_lo + x*g_hi`,
  `h' = x*h_lo + x⁻¹*h_hi`, maintaining the invariant
  `P' = <a',g'> + <b',h'> + <a',b'>*u = x²*L + P + x⁻²*R`. **Non-interactive** via a
  deterministic transcript (label `DETERM-BP-IPA-v1`, seeded with `compress(P)`,
  `compress(u)`, and `n` big-endian; challenges via `hash_to_scalar` with a fixed
  challenge-DST, zero rejected + re-absorbed). Everything reduces to
  `determ_pedersen_msm` over flat scalar/point lists — no new group arithmetic.
  `DETERM_IPA_MAX_N 256`; rejects non-power-of-2 / n>MAX / n<1. The decisive
  correctness oracle is the per-round algebraic invariant above. The IPA was also
  refactored to expose **generator-supplied** `determ_ipa_prove_gens` /
  `_verify_gens` (the fixed-generator forms are now thin wrappers); the range proof
  drives them with a `y`-rescaled `h` family.
- **Increment 5 — Bulletproofs single-value range proof (`src/crypto/pedersen/
  rangeproof.c`):** the whole point of the track — proves a Pedersen-committed
  value `v` lies in **`[0, 2^n)`** WITHOUT revealing `v`, in `2*log2(n) + O(1)`
  group elements. The value commitment is the inc.1 shape `V = v*g + gamma*h` (`g`
  = base point, `h` = the nothing-up-my-sleeve scalar generator). The prover
  bit-decomposes `v` into `a_L`/`a_R = a_L - 1^n`, commits them as `A` (inc.2
  vector-commit shape over `g_i`/`h_i`) and a blinding-vector commit `S`, forms the
  polynomial-coefficient commitments `T_1`/`T_2` (inc.1 Pedersen commits over
  `g`/`h`), and reduces the final `<l, r> = t̂` check to the **inc.4 IPA** over
  `(g_i, h'_i = y^-i·h_i, u)`. Non-interactive via a deterministic Fiat-Shamir
  transcript (label `DETERM-BP-RANGE-v1`, distinct from the IPA's). API:
  `determ_rangeproof_commit`-free `_prove(V_out, proof, v, gamma, alpha, rho, tau1,
  tau2, sL, sR, n)` (randomness caller-supplied for reproducibility) / `_verify(V,
  proof, n)` / `_proof_len(n) = 228 + determ_ipa_proof_len(n)`. `n` a power of two
  ≤ `DETERM_RANGEPROOF_MAX_BITS` (64). The verifier is two checks: the `t̂`
  polynomial identity `t̂·g + τ_x·h == z²·V + δ(y,z)·g + x·T_1 + x²·T_2`, and the
  IPA over the reconstructed `P`. Fail-**closed** on any identity intermediate or
  decode failure. The only new arithmetic beyond the inc.1-4 primitives is the
  modular add/sub (`sc_add`/`sc_sub`); everything else composes over
  `determ_pedersen_msm` + the P-256 point/scalar ops.
- **Increment 6 — the AGGREGATED range proof (`rangeproof.c`, same module):**
  proves that `m` committed values `v_0..v_{m-1}` EACH lie in `[0, 2^n)` in ONE
  proof of size `2*log2(m*n) + O(1)` group elements (vs. `m` separate proofs). The
  `m` bit-vectors are concatenated into a length-`m*n` `a_L`; value `j`'s `2^n` slot
  is scaled by `z^(2+j)` (0-indexed, so `m=1` recovers inc.5); the final `<l,r>=t̂`
  check is compressed by the same inc.4 IPA over the `m*n`-wide generators. API:
  `determ_agg_rangeproof_prove(V_out, proof, v[], gamma[], alpha, rho, tau1, tau2,
  sL, sR, m, n)` (writes `m` value commitments to `V_out` + the proof) / `_verify(V,
  proof, m, n)` / `_proof_len(m, n) = 228 + determ_ipa_proof_len(m*n)`. Constraints:
  `n ≤ 64`, `m ≥ 1`, `m*n` a power of two `≤ DETERM_IPA_MAX_N` (256). The verifier's
  `t̂` identity gains the `Σ_j z^(2+j)·V_j` term and `delta` the `Σ_j z^(3+j)` sum;
  the `z^(2+j)`-slot vector places each value's `2^n` weighting. Reuses every
  single-value static (`sc_add`/`sc_sub`/`rp_inner`/`msm`/the IPA `_gens`); a single
  out-of-range value anywhere in the batch rejects. Deterministic Fiat-Shamir
  transcript with its own label `DETERM-BP-AGGRANGE-v1` (seeds `m`, `n`, all `V_j`).
- **Increment 7 — confidential-tx balance proof (`src/crypto/pedersen/balance.c`):**
  the FIPS-profile sibling of the §3.20 inc.7 finite-field balance proof — the
  *amount-conservation* half of a confidential transaction (the inc.5/6 range proofs are
  the *no-inflation* half; together they are the complete amount guarantee). Proves
  `Σ v_in = Σ v_out + fee` WITHOUT revealing any amount: a transaction balances iff the
  excess `E = Σ C_in − Σ C_out − fee*G` has no G-component, i.e. `E = x*H` for the
  blinding excess `x = (Σ r_in − Σ r_out) mod n`; the prover proves knowledge of `x` with
  a Schnorr PoK of discrete log base `H` (`E = x*H`). Since `log_G(H)` is unknown,
  `E = x*H` forces the G-coefficient `Σv_in − Σv_out − fee` to zero. The point
  subtractions are **scalar negations in the exponent** (`−C = (n−1)*C`, `−fee*G =
  (n−fee)*G`) so the excess is one `determ_pedersen_msm` — **no point-negation primitive
  and NO change to the sealed P-256 core**; built on the PUBLIC §3.19 pedersen +
  §3.8c/§3.9b P-256 API, the only local arithmetic a 256-bit add-mod-n / negate-mod-n
  over the exported curve order. API `determ_p256_balance_excess`/`_prove`/`_verify`
  (33-byte SEC1 commitments, 65-byte proof = `compress(T)‖s`); transcript DST
  `DETERM-P256-BALANCE-v1-challenge`. `determ test-p256-balance-c99` (balanced accepts;
  an unbalanced tx and a tampered proof both reject) + corpus `p256_balance.json`,
  independent Python `tools/verify_p256_balance.py`. An adversarial audit confirmed the
  local add/negate-mod-n edge cases (the `t==n` reduction; `carry ⟹ t<n` for `n>2^255`),
  the SEC1 compression, and fail-closed-on-identity.
- **Increment 8 — end-to-end confidential-tx composition (`test-p256-confidential-tx-c99`,
  a structural test — NOT a new primitive):** the FIPS-profile sibling of the §3.20 inc.8
  finite-field composition. Composes the two shipped halves into one confidential
  transaction over the **public §3.19 APIs only**: a per-output inc.5 range proof + the
  inc.7 balance proof. It pins the composition fact that an output's range-proof value
  commitment `V_j` is **byte-identical** to its tx commitment `C_out[j]` — because both
  use the base point `G` and the §3.19 generator `H` — so a cross-primitive generator
  mismatch turns the test RED. It also demonstrates the **division of labour**: an
  *inflation* attempt (`Σv_out + fee ≠ Σv_in`, honest blindings) is caught by the
  **balance** proof (each output is still an in-range commitment, so the range proofs
  pass); an *out-of-range* output (`= 2^n`) is caught by that output's **range** proof.
  Mirror: `tools/verify_p256_confidential_tx.py`; no new corpus — the composed bytes are
  pinned by `bp_rangeproof.json` / `bp_agg_rangeproof.json` / `p256_balance.json`.
- **Validation:** `determ test-pedersen-c99` (14 assertions — inc.1: H KAT +
  on-curve + H≠G; `commit == compress(v*G+r*H)` via the raw P-256 API; the v==0
  path; the **additive homomorphism**; open/verify accept + reject; binding
  sanity; input rejection r==0 / v≥n / non-decodable add. inc.2: the vector
  generators on-curve/deterministic/distinct/≠G,H + which>1 reject;
  `vector_commit == r*H+Σ(a_i*G_i+b_i*H_i)` via the raw API; the **vector
  homomorphism** `vc(a1,b1,r1)+vc(a2,b2,r2)==vc(a1+a2,b1+b2,r1+r2)`; n==0 => r*H +
  zero-entry skip + r==0 reject. inc.3: `msm == Σ s_i*P_i` recomputed AND
  `vector_commit == msm over [H,G_i,H_i]`; canceling terms → identity (rc 1) +
  zero-scalar skip + n==0; scalar≥n / non-decodable point reject) + the §3.13
  dual-oracle byte-frozen corpus `tools/vectors/pedersen.json` (14 vectors: H KAT,
  4 commits, a mod-n WRAPAROUND homomorphism, 5 generator KATs, a vector_commit,
  an msm + an msm→identity) recomputed by BOTH the C impl (`test-c99-vectors`) and
  the independent from-scratch Python EC (`tools/verify_pedersen.py`). inc.4:
  `determ test-bp-ipa-c99` (4 assertions — the `proof_len` contract
  [64/130/196/262 for n=1/2/4/8, 0 for non-power-of-2 / n>MAX]; round-trip
  commit→prove→verify accepts for n∈{1,2,4,8}; determinism [prove twice → identical
  bytes]; soundness [a byte-flipped proof AND a wrong commitment both reject]) + the
  §3.13 dual-oracle byte-frozen corpus `tools/vectors/bp_ipa.json` (2 vectors: ipa
  n=4 → 2 L/R rounds, ipa n=8 → 3) recomputed by BOTH the C impl and the
  independent from-scratch Python reference (`tools/verify_bp_ipa.py`, whose
  per-round-invariant + round-trip + wrong-P-reject + tamper self-tests pass over
  n∈{1,2,4,8,16}). inc.5: `determ test-bp-rangeproof-c99` (4 assertions — the
  `proof_len` contract [228 + `ipa_proof_len(n)`; non-power-of-2 / n>64 → 0];
  round-trip prove→verify accepts for n∈{4,8,16}; determinism [prove twice →
  identical V + proof bytes]; soundness [a byte-flipped proof, a wrong commitment,
  AND an out-of-range `v = 2^n` all reject]) + the §3.13 dual-oracle byte-frozen
  corpus `tools/vectors/bp_rangeproof.json` (3 vectors, n∈{4,8,16}) recomputed by
  BOTH the C impl and the independent from-scratch Python
  (`tools/verify_bp_rangeproof.py`, whose t0-oracle + round-trip + tamper +
  out-of-range self-tests pass over n∈{1,2,4,8,16}). inc.6: `determ
  test-bp-agg-rangeproof-c99` (4 assertions — the `proof_len` contract [228 +
  `ipa_proof_len(m*n)`; non-power-of-2 `m*n` / `m*n>256` → 0]; round-trip for
  (m,n)∈{(1,4),(2,4),(4,4),(2,8)}; determinism; soundness [a byte-flipped proof, a
  wrong batch of commitments, AND an out-of-range value anywhere in the batch all
  reject]) + the §3.13 dual-oracle corpus `tools/vectors/bp_agg_rangeproof.json` (3
  vectors, (m,n)∈{(2,4),(4,4),(2,8)}) recomputed BYTE-FOR-BYTE by BOTH the C and the
  independent from-scratch Python (`tools/verify_bp_agg_rangeproof.py`, whose
  t0-oracle + round-trip + tamper + out-of-range-in-batch self-tests pass over
  (m,n)∈{(1,4),(2,2),(2,4),(4,2),(2,8),(4,4)}); an off-corpus cross-check further
  confirms byte-exact agreement at the m*n=256 max-buffer boundary. Soundness
  accounting: `PedersenCommitmentSoundness.md` + `BulletproofsIPASoundness.md` +
  `BulletproofsRangeProofSoundness.md` (extended in-doc for the inc.6 aggregation);
  per-module provenance: `src/crypto/pedersen/README.md`. **Additive — no in-tree
  consumer yet.** The library side of the confidential-tx track is now COMPLETE
  (commit + vector commit + MSM + IPA + single-value range proof + aggregated range
  proof + **balance proof**) — the FIPS-profile P-256 stack now offers the same
  confidential-tx primitive set as the MODERN-profile §3.20 `Z_p*` stack (range proofs
  for no-inflation + a balance proof for amount conservation). Next: chain integration
  (a confidential-transaction protocol wiring these
  proofs into the ledger — see `ConfidentialTxIntegrationDesign.md`), a
  separately-reviewed, owner-gated, consensus-critical step; also
  candidate: proof aggregation (multiple values in one argument) and the
  single-multi-exp verify optimization.
  CT posture: data-independent except the documented `scalar_is_zero` branches (a
  v==0 value commitment; a zero vector entry); full timing review is the
  owner-gated step.

### 3.20 Finite-field Bulletproofs stack over Z_p* — **SHIPPED (confidential-tx MODERN backend, increments 1-8: range-proof stack + balance proof + end-to-end composition)**

The **owner-decided curve/group split** for the v2.22 confidential-transaction
integration (2026-07-05, amending the v2.22 §2.Q1/Q2 secp256k1 plan of record):
**FIPS profiles use the §3.19 P-256 Bulletproofs stack** (FIPS-validated curve,
auditability); **MODERN profiles use finite-field "large primes, not curves"**.
The philosophy is NIST-curve-for-the-NIST-trusting-audience, non-NIST-big-prime-
math-for-the-privacy-audience — and it makes confidential amounts available in
**every** profile (the v2.22 spec had marked them FIPS-unavailable under the
secp256k1 assumption). The chosen amount primitive is a **Pedersen commitment**
(not ElGamal encryption); amount delivery is the existing Q3 DH+AEAD, and the God-
Stack (zk-VM L2) carries computation privacy separately. See
`ConfidentialTxIntegrationDesign.md`.

Increment 1 is the finite-field analog of §3.19 inc.1 — library-primitive-first,
**KAT-gated, zero consensus touch**.

- **Implementation:** `src/crypto/ff/ffgroup.c` — the commitment `C = g^v * h^r mod
  p` in the prime-order subgroup `G_q ⊂ Z_p*`, where **p is the RFC 3526 MODP-3072
  safe prime** (group 15; reproduced from its published formula and machine-verified
  prime, with `q = (p-1)/2` also prime), `q` is the subgroup order, `g = 4` (a
  quadratic residue, hence an order-`q` generator), and `h` is a **nothing-up-my-
  sleeve second generator** with unknown `log_g(h)` (hash-to-group: SHA-256 over a
  fixed DST → mod p → square into the QR subgroup; pinned KAT). **Binding** reduces
  to the finite-field discrete log; **hiding** is information-theoretic for uniform
  r. The group constants (`p`, `q`, `n' = -p⁻¹ mod 2³²`, `R² mod p`, `h`) are
  machine-generated into `src/crypto/ff/ff_params.h` by
  `tools/verify_ff_pedersen.py`. API: `determ_ff_pedersen_generator_h` / `_commit` /
  `_verify` / `_add` — all elements and scalars 384-byte (3072-bit) big-endian;
  scalars `v ∈ [0,q)`, `r ∈ (0,q)`.
- **Arithmetic:** a **portable C99 bignum — 32-bit-limb CIOS Montgomery
  multiplication** (Koç–Acar–Kaliski), NO `__int128` / compiler intrinsics, so it
  builds identically on MSVC and GCC. `commit = modmul(g^v mod p, h^r mod p)` via
  modexp. The `modexp` is **constant-time in the exponent** (2026-07-06): a fixed
  4-bit-window square-and-multiply with a branchless table select (no branch on secret
  exponent bits, no secret-indexed memory; the Montgomery conditional subtract is a
  masked blend) — byte-output-invariant (the ff_* corpora are the guard), audited, and
  modestly faster than the old bit-serial square-and-multiply. The `determ_ff_msm`/
  `_vector_commit` **zero-scalar skip is also removed** (always exponentiate; `base^0 = 1`)
  — so the **Z_p\* prover is now constant-time for its own honest inputs** (no
  secret-value-dependent branch/memory). The §3.19 P-256 pedersen commit/vector_commit/msm
  zero-skips are **also removed** (via the pt-domain `determ_p256_msm_ct` + branchless
  point-selects), so **both** the FIPS and MODERN confidential-tx provers are now
  constant-time for their own honest inputs — no CT residual remains.
- **Validation:** `determ test-ff-pedersen-c99` (4 assertions — the H generator
  [deterministic, non-trivial]; `commit → verify` accept + wrong-v / wrong-r reject;
  the additive homomorphism `c1*c2 == commit(v1+v2, r1+r2)`; input validation [r==0,
  v≥q, r≥q reject]) + the §3.13 dual-oracle byte-frozen corpus
  `tools/vectors/ff_pedersen.json` (6 vectors: H KAT, 4 commits, a **mod-q
  wraparound** homomorphism) recomputed by BOTH the C impl (`test-c99-vectors`) and
  the independent from-scratch Python (`tools/verify_ff_pedersen.py`, whose
  safe-prime + subgroup-membership + binding + homomorphism self-tests pass, using
  Python's native bignums as the reference arithmetic). Soundness/provenance:
  `src/crypto/ff/README.md`.

**Increment 2 — vector-commitment generators + vector commit + MSM** (`ffgroup.c`,
mirrors §3.19 inc.2/3). Two nothing-up-my-sleeve order-`q` generator FAMILIES
`G_i = determ_ff_gen(i,0)`, `H_i = determ_ff_gen(i,1)` (hash-to-group: 13 SHA-256
counter blocks of `family-DST ‖ big-endian index` → reduce mod p → square into `G_q`);
the vector Pedersen commit `C = h^r · Π G_i^{a_i} · Π H_i^{b_i} mod p`
(`determ_ff_vector_commit`); and the general multi-exponentiation `Π P_i^{s_i} mod p`
(`determ_ff_msm`) — the `Z_p*` identity is the element `1` (representable), so the MSM
is 2-way, unlike the P-256 3-way. `test-ff-pedersen-c99` 4→7 assertions; corpus
`ff_pedersen.json` 6→14 vectors (gen KATs, vector_commit, MSM incl. the all-zero
identity).

**Increment 3 — scalar field mod `q`** (`ffgroup.c`, the exponent/challenge field the
IPA/range proof operate in). The CIOS Montgomery core is parameterized by a
`(modulus, R², n')` context — `CTX_P` for group elements, `CTX_Q` for scalars — so the
mod-`p` routines are byte-identical wrappers (the `ff_pedersen`/`bp` corpora guard the
byte-identity). API: `determ_ff_scalar_reduce` / `_add` / `_mul` / `_inv` (Fermat
`a^{q-2}`) and `determ_ff_hash_to_scalar` (13 SHA-256 counter blocks → mod q — the
deterministic Fiat-Shamir challenge map). `q`-Montgomery constants
(`DETERM_FF_QNPRIME`, `DETERM_FF_QR2`) machine-generated into `ff_params.h`.
`determ test-ff-scalar-c99` (5 assertions) + corpus `ff_scalar.json` (11 vectors),
independent Python `tools/verify_ff_scalar.py`.

**Increment 4 — Bulletproofs inner-product argument (IPA)** (`src/crypto/ff/ffipa.c`,
mirrors §3.19 inc.4). A proof of knowledge of vectors `a, b` with
`P = Π g_i^{a_i} · Π h_i^{b_i} · u^{<a,b>} mod p` in `2·log2(n)` group elements + 2
scalars, non-interactive via a deterministic Fiat-Shamir transcript (label
`DETERM-FF-BP-IPA-v1`). API `determ_ff_ipa_commit` / `_prove` / `_verify` (+ the
`_gens` generator-supplied variants the range proof will use with a `y`-rescaled `h`
family). Pure composition over inc.2/inc.3 — no new arithmetic; malformed `L/R/af/bf`
reject via the MSM/scalar bound checks. `determ test-ff-ipa-c99` (n=1,2,4 round-trip +
proof-length + wrong-`P`/tampered-proof reject) + corpus `ff_ipa.json` (commit/prove
KAT for n=2,4, the file-half also re-verifying each proof), independent Python
`tools/verify_ff_ipa.py` whose selftest also checks soundness (n up to 8) — **the C
IPA proof bytes match this Python byte-for-byte**. `n` kept small in the corpus: the
3072-bit modexp is ~1700× slower than the P-256 IPA (`n` up to 256 supported).

**Increment 5 — single-value range proof** (`src/crypto/ff/ffrangeproof.c`, mirrors
§3.19 inc.5). Proves a Pedersen-committed value `v ∈ [0, 2^n)` WITHOUT revealing `v`, in
`2·log2(n)+O(1)` group elements — the MODERN-profile confidential-tx amount range. Value
commitment `V = g^v · h^gamma mod p` (`g = 4` the inc.1 value generator; `h` the inc.1
blinding generator); `A`/`S` bit-vector commits over the inc.2 families; t-poly `T1`/`T2`;
the `⟨l,r⟩ = t̂` check compressed by the inc.4 IPA over `(G_i, h'_i = y^-i·H_i, u)`.
Transcript `DETERM-FF-BP-RANGE-v1`. API `determ_ff_rangeproof_prove`/`_verify`. Pure
composition over inc.1-4 plus a scalar subtraction (`determ_ff_scalar_sub`, `a-b mod q`).
`determ test-ff-rangeproof-c99` (n=2,4 round-trip + out-of-range `v=2^n` + tampered-proof
+ wrong-`V` reject) + corpus `ff_rangeproof.json`, independent Python
`tools/verify_ff_rangeproof.py` — the C `V`+proof bytes match it byte-for-byte, and an
independent soundness audit (re-derived from Bünz et al. 2018 §4.2) confirmed the
construction is a faithful, sound Bulletproofs range proof (δ/l/r/t-poly/Check-1/Check-2
all match the paper; the range-binding identity `t0 = δ(y,z) + z²·v` holds numerically).

**Increment 6 — aggregated range proof** (`ffrangeproof.c`, mirrors §3.19 inc.6). Proves
that m committed values `v_0..v_{m-1}` EACH lie in `[0, 2^n)` in ONE proof of size
`2·log2(m·n)+O(1)` group elements (the confidential-tx batch range). The m bit-vectors
are concatenated (m·n ≤ 256); value j's `2^n` slot is scaled by `z^(2+j)`; `taux` gains
`Σ_j z^(2+j)·gamma_j`; `delta` gains `Σ_j z^(3+j)`; Check 1's V-side is
`Π_j V_j^{z^(2+j)}`; `m=1` recovers the single-value proof. Transcript
`DETERM-FF-BP-AGGRANGE-v1`. API `determ_ff_agg_rangeproof_prove`/`_verify`.
`determ test-ff-agg-rangeproof-c99` (m·n=4,8 round-trip + one-value-out-of-range +
tamper + wrong-`V` reject) + corpus `ff_aggrangeproof.json`. An independent aggregation
audit (re-derived from Bünz et al. 2018 §4.3) confirmed all six aggregation formulas and
that an out-of-range value is rejected in **every** batch position (the z-power binding).

**Increment 7 — confidential-tx balance proof** (`src/crypto/ff/ffbalance.c`). The
*amount-conservation* half of a confidential transaction (the inc.5/6 range proofs are
the *no-inflation* half; together they are the complete amount guarantee). Proves
`Σ v_in = Σ v_out + fee` WITHOUT revealing any amount: a transaction balances iff the
excess `E = Π C_in · Π C_out^{-1} · g^{-fee}` (in `G_q`) has no g-component, i.e.
`E = h^{r_excess}`; the prover proves knowledge of that blinding excess with a Schnorr
PoK of discrete log base `h` (`E = h^x`). Since `log_g(h)` is unknown, `E = h^x` forces
the g-exponent `Σv_in − Σv_out − fee` to zero. The group-element inverses are scalar
negations in the exponent (`C^{-1} = C^{q-1}`, `g^{-fee} = g^{q-fee}`), so the excess is
one `determ_ff_msm` — **no group-inverse primitive and no change to any sealed code**;
built entirely on the public inc.1-3 API. API `determ_ff_balance_excess`/`_prove`/
`_verify`; transcript DST `DETERM-FF-BALANCE-v1-challenge`. `determ test-ff-balance-c99`
(balanced accepts; an unbalanced tx and a tampered proof both reject) + corpus
`ff_balance.json`, independent Python `tools/verify_ff_balance.py`.

**Increment 8 — end-to-end confidential-tx composition** (`test-ff-confidential-tx-c99`,
a structural test — NOT a new primitive). Composes the two shipped halves into one
confidential transaction over the **public §3.20 APIs only**: a per-output inc.5 range
proof + the inc.7 balance proof. It pins the load-bearing composition fact that an
output's range-proof value commitment `V_j` is **byte-identical** to its tx commitment
`C_out[j]` — because both use the same `g = 4` and `h` — so a cross-primitive generator
mismatch would break the composition and turn the test RED. It also demonstrates the
**division of labour**: an *inflation* attempt (`Σv_out + fee ≠ Σv_in`, honest blindings)
is caught by the **balance** proof (each output is still an in-range commitment, so the
range proofs pass); an *out-of-range* output (`= 2^n`) is caught by that output's
**range** proof (a wrapped value can still balance). Mirror: `tools/verify_ff_confidential_tx.py`
(composes the already-byte-exact inc.5/6/7 references); no new corpus — the composed
bytes are pinned by `ff_rangeproof.json` / `ff_aggrangeproof.json` / `ff_balance.json`.

All eight increments are **NOT constant-time** (the owner-gated CT-hardening step) and
**additive — no chain call site**. The confidential-tx primitive set is complete and
demonstrated end-to-end (commit → vector-commit/MSM → scalar field → IPA → single-value
range proof → aggregated range proof → balance proof → confidential-tx composition). The
full soundness accounting is `docs/proofs/FiniteFieldBulletproofsSoundness.md`. Next on
this backend: a
group-abstraction layer so P-256 and `Z_p*` share one Bulletproofs prover; then chain
integration (owner-gated, per the design doc). The `Z_p*` modexp is ~1700× slower than
the P-256 stack, so the range-proof corpora/tests keep m·n small (m·n ≤ 8). **CT status:
the modexp is constant-time + windowed AND the `determ_ff_msm`/`_vector_commit` zero-scalar
skip is removed (2026-07-06, owner-authorized) — the Z_p\* prover is now constant-time for
its own honest inputs (byte-invariant, audited). The §3.19 P-256 pedersen zero-skips are
also removed (via the pt-domain `determ_p256_msm_ct` + branchless point-selects), so BOTH
confidential-tx provers are now constant-time — no CT residual remains before the
owner-gated chain integration.**

### 3.21 DPQ1 post-quantum transaction authentication (`determ::pqauth`) + on-chain `PQ_TRANSFER` — **SHIPPED (increments 1-4)**

The owner-authorized on-chain post-quantum **signature** track (distinct from the §3.19/§3.20 confidential-tx track). Reopens the 2026-07-04 anon-address freeze (`AnonAddressDerivationMigration`) by owner authority; ships as an **additive, state-root-invariant** extension. Full accounting: [`PQSignatureEnvelopeSoundness.md`](PQSignatureEnvelopeSoundness.md) (PQE-1..5, non-claims, the §Trust-Root binding).

- **inc.1 — ML-DSA `Sign_internal` CT hardening** (`src/crypto/mldsa/sign.c`). The norm check `chknorm` (ran on the secret `z`/`r0`/`ct0`, early-returning at the first out-of-bound coefficient of a rejected candidate) and `center` are rewritten branchless / full-scan-accumulate. **Byte-invariant** — the accept/reject decision is identical, so every ACVP sigGen/sigVer KAT still matches byte-for-byte (`test-mldsa-c99` + the mldsa corpora green).
- **inc.2 — the DPQ1 envelope** (`include/determ/crypto/pqauth.hpp` + `src/crypto/pqauth.cpp`). Binds a transaction's canonical `signing_bytes` to an ML-DSA (FIPS 204) signature, optionally **HYBRID** with Ed25519 (break-BOTH). Wire: `MAGIC("DPQ1") | scheme(1) | pq_pk_len(2 BE) | pq_pk | pq_sig_len(2 BE) | pq_sig | [ed_pk(32)|ed_sig(64)]`. The **scheme byte is bound into both signatures** (ML-DSA `ctx = "determ-pqtx-v1"‖scheme`; Ed25519 signs `scheme‖message`) — the downgrade/hybrid-strip defence from a fixed MEDIUM adversarial-audit finding. Dual-oracle: `test-pqauth` (C `determ::pqauth::sign`) + `tools/verify_pqauth.py` (independent python ed25519 + from-scratch ML-DSA) over `tools/vectors/pqauth.json` (4 vectors). Verify is `noexcept` + fail-closed on any malformed envelope.
- **inc.3 — client tooling** (`light/pq_sign_tx.cpp`). `determ-light pq-sign-tx` / `pq-verify-tx` produce + offline-verify a DPQ1-authenticated tx over the real `signing_bytes` (`tools/test_light_pq_sign.sh`).
- **inc.4 — the on-chain `PQ_TRANSFER` accept-rule.** Owner chose **Option B (PQ-native bearer address)**: `address = "0x"‖hex(form)‖hex(ML-DSA pubkey)`, form 0x01/02/03 = ML-DSA-44/65/87 (`determ::pq_address`; length 2628/3908/5188 — disjoint from the 66-char Ed25519 anon address, so `is_anon_address` is untouched). New `TxType::PQ_TRANSFER` + a `Transaction.pq_auth` field **excluded from `signing_bytes` and serialized only when non-empty**, so every existing tx type is byte-identical → a PQ-free chain's state root is unchanged (FAST golden vectors green). The shared accept-rule `determ::chain::verify_pq_transaction` (S-043 one-helper; called by BOTH the block validator and mempool admission) recovers the ML-DSA key from `from`, verifies the PQ-ONLY DPQ1 envelope over `signing_bytes`, and **requires `envelope.pq_pk == address key`** — the quantum-resistance binding (a quantum adversary cannot substitute its own key). Apply/build-body treat `PQ_TRANSFER` as `TRANSFER`. Gated by `test-pq-transaction` (address round-trip + accept + 7 fail-closed rejections incl. non-canonical `from` + serialization byte-identity).
- **inc.6 — the client→consensus loop closer.** `determ-light pq-address` (derive the PQ-native bearer address from a seed) + `pq-transfer` (build a canonical, SUBMITTABLE `PQ_TRANSFER`: derives `from`, signs the PQ-only DPQ1 envelope over `signing_bytes`, emits a `from_json`-compatible tx with a 64-zero-byte `sig` placeholder). `determ verify-pq-tx --file <tx.json>` applies the SHARED consensus accept-rule to a tx file (exit 0 verified / 3 invalid) — a validator would accept exactly what this accepts. Cross-binary gate `tools/test_pq_transfer_e2e.sh` (light produces → full binary's consensus rule verifies; tamper → INVALID; hybrid refused).
- **inc.7 — S-028 canonicalization for PQ addresses.** The mempool-policy audit found NO tx-type allowlist (a valid `PQ_TRANSFER` flows through `mempool_admit_check`), but the account map keys on `tx.from` while the accept-rule parsed either hex case — a non-canonical `from` would fragment balances. Fixed CONSENSUS-side: `verify_pq_transaction` now REQUIRES `normalize_pq_anon_address(from) == from` (stronger than anon, which relies on RPC ingress — a non-canonical PQ `from` is simply an invalid tx). Mirrored at RPC ingress (`rpc_submit_tx` rejects non-canonical PQ `from`/`to`, as it already did for anon).

### 3.22 DCT1 confidential-transfer proof bundle (`determ::ctxbundle`) — **SHIPPED (CTX-1: library primitive)**

The owner-gated confidential-transaction chain-integration track (distinct from the §3.21 PQ signature track). A serialized, fail-closed-verifiable composition of the shipped §3.19 P-256 primitives — it adds NO new hardness assumption above §3.19. Full accounting: [`ConfidentialTxBundleSoundness.md`](ConfidentialTxBundleSoundness.md) (CTBN-1..5, non-claims, limits).

- **The DCT1 bundle** (`src/crypto/pedersen/ctxbundle.{c,h}`): `MAGIC("DCT1") | n_in | m | n | fee(8 BE) | C_in[n_in*33] | C_out[m*33] | agg_rangeproof | balance_proof(65)`. `determ_ctx_bundle_verify` accepts iff the ONE aggregated Bulletproofs range proof verifies against `C_out` (each output in [0,2^n)) AND the balance proof verifies against the RECOMPUTED excess `E = ΣC_in − ΣC_out − fee·G` (Σv_in = Σv_out + fee). `C_out` is passed DIRECTLY as the range proof's value commitments V, so the composition identity V_j==C_out[j] is structural (no splice possible); E is recomputed by the verifier (never carried → unspoofable). Fail-closed on bad magic / params / length / identity excess.
- **Dual-oracle**: `test-p256-ctx-bundle` (C — build + accept + per-region tamper + malformed + a SHA-256 KAT) + `tools/verify_ctx_bundle.py` (independent python composing verify_pedersen + verify_bp_agg_rangeproof + verify_p256_balance) over `tools/vectors/p256_ctx_bundle.json`; `tools/test_p256_ctx_bundle.sh` runs both.
- **The BUNDLE is a LIBRARY primitive; the SHIELD deposit op (below) is the first CONSENSUS integration.** A full confidential-tx feature needs a shielded-pool STATE MODEL (a commitment set + a nullifier set for double-spend prevention + deposit/withdraw between the transparent and confidential value pools) and the owner-gated PROFILE choice (P-256 FIPS vs Z_p* MODERN). The bundle itself proves a transfer is well-formed; it does NOT prevent replay/double-spend (the nullifier set's job) nor hide sender/receiver/graph/fee (only amounts).

#### 3.22a SHIELD — transparent → confidential on-ramp (consensus) — **SHIPPED**

The **first shielded-pool consensus operation** and the first chain integration of the §3.19/§3.22 primitives — the **deposit half** of a confidential pool. It closes the *commitment-set + deposit-bridge* part of the state model above (not the nullifier/spend/withdraw part, which is the next increment). Full accounting: [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) (SP-1..5, non-claims, limits).

- **Transaction.** `TxType::SHIELD = 12` (additive, after `PQ_TRANSFER = 11`). `tx.amount = A` is the **PUBLIC** deposit amount (must be public to debit the transparent balance); `tx.payload = C(33 SEC1) || balance_proof(65)` (exactly 98 bytes), with `C = A·G + r·H` the Pedersen commitment and the balance proof a Schnorr PoK that the excess `E = C − A·G` opens to zero on `H`.
- **Accept-rule** (`determ_shield_verify`, `ctxbundle.{c,h}`): the §3.19 balance/excess primitive specialized to *one input, zero outputs, fee = A* — `E = C − A·G`; a verifying proof forces `E = r·H`, i.e. `C` commits to **exactly** `A` (a depositor cannot mint value by committing to more than they debit). Enforced at the **validator** (authoritative, submit-time) AND re-verified at **apply** (belt-and-suspenders) via the SAME shared helper (S-043 rule); the producer debits provisionally.
- **State + supply.** Apply debits `A + fee` from the transparent sender and adds `C` to the confidential set (the `cn:` namespace) with the shielded-supply counter `accumulated_shielded_ += A`. `expected_total()` gains a `− accumulated_shielded_` term, so the always-on A1 unitary-supply invariant holds exactly (value is **relocated, not created**); total real supply `= live_total_supply() + accumulated_shielded_`. Re-SHIELDing the same commitment is a no-op (the commitment is its own identifier — no double-**mint**).
- **Additive + state-root-invariant.** The `cn:` leaves + the `c:accumulated_shielded` counter leaf are emitted ONLY when non-empty/non-zero, and the snapshot serialize/restore is likewise conditional — so a chain that never SHIELDs has a **byte-identical** state root and snapshot to a pre-§3.22 chain. The FAST golden state-root corpus (green with §3.22 compiled in) IS the invariance proof.
- **Gate**: `test-shield` (accept-rule valid/wrong-amount/tampered; apply debit + A1 conservation + `cn:`/`c:` leaves + state-root observability; bad-proof + duplicate-note no-op) via `tools/test_shield.sh`.
- **Non-claims.** SHIELD is the DEPOSIT half — the WITHDRAW half is §3.22b UNSHIELD (below); the confidential→confidential CONFIDENTIAL_TRANSFER is not yet shipped. The SHIELD **amount is PUBLIC** (SHIELD hides nothing by itself — amount privacy begins only on the not-yet-shipped confidential→confidential transfer); no sender/receiver/graph privacy; not post-quantum; single-shard / P-256 profile.

#### 3.22b UNSHIELD — confidential → transparent withdraw (consensus) — **SHIPPED**

The **withdraw** off-ramp: **spends** an unspent note `C` from the confidential set and returns its PUBLIC amount `A` to a transparent recipient (minus fee). The **commitment IS its own nullifier** — apply removes `C` from the set, so a note is spendable at most once (the *named-input* CT model; no separate nullifier set). Full accounting: [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) (SP-6..9).

- **Transaction.** `TxType::UNSHIELD = 13` (additive). Same 98-byte payload shape as SHIELD (`C(33) || balance_proof(65)`), but the balance proof is **CONTEXT-BOUND**.
- **The front-running problem + fix.** A confidential withdraw proves knowledge of the note blinding `r` (which authorizes the spend), but a *bare* PoK is **replayable**: the proof is decoupled from the tx signer, so a mempool observer could copy the public `C||proof` into their own tx and **redirect the credit** (theft). The fix binds the proof's Fiat-Shamir challenge to the withdrawing tx: `determ_p256_balance_prove_bound`/`_verify_bound` (`balance.c`) hash `E || T || ctx32` where `ctx32 = SHA-256(from || to || nonce || amount)` (the shared `unshield_spend_ctx_hash`, `shielded.hpp`, used by the client prover + validator + apply — S-043). A captured proof carries the original `ctx`; any change to from/to/nonce/amount changes the challenge and the proof fails. A bound proof and an unbound (SHIELD) proof over the same `(E,T)` get different challenges → neither verifies under the other (domain separation).
- **Accept-rule** (`determ_unshield_verify`): note must be an unspent commitment; `A ≥ fee`; the bound proof must verify against the derived `ctx32`. Enforced at the validator (submit-time) + re-verified + note-removed at apply (authoritative). Anon/bearer senders may UNSHIELD.
- **State + supply.** Apply removes `C` (`accumulated_shielded_ -= A`) and credits `A − fee` to `tx.to` (fee to creators). Pedersen **binding** guarantees `A` equals the amount `C` was SHIELDed with, so the counter cannot underflow; the A1 invariant holds (value relocated back to the transparent ledger). Additive + state-root-invariant, same as SHIELD.
- **Gate**: `test-unshield` (bound accept; front-run/redirect REJECTS; wrong-amount + unbound-proof reject; apply removes note + credits `A−fee` + A1; front-run + double-spend no-op) via `tools/test_unshield.sh`.
- **Non-claims.** UNSHIELD is amount-PUBLIC on exit and **NOT graph-private** — it links the spent note to the recipient (the tx-bound proof stops **theft**, not **linkability**); unlinkable exit needs the §3.22c confidential→confidential transfer (which itself hides amounts but still names inputs). The tx-bound proof is a NEW AI-designed, owner-authorized (2026-07-06), session-audited construction — not externally reviewed. **Single-shard: a cross-shard UNSHIELD (`tx.to` off-shard) is REJECTED in code** at validator + producer + apply (a no-op; matching DAPP_CALL v2.19) — without it a cross-shard credit would silently break the K-shard aggregate supply identity (a HIGH adversarial-audit finding, remediated). Not post-quantum; P-256 profile.

#### 3.22c CONFIDENTIAL_TRANSFER — confidential → confidential (consensus) — **SHIPPED**

The **first consensus consumer of the CTX-1 DCT1 bundle**: a confidential→confidential move that consumes `n_in` unspent **named** input notes and produces `m` output notes with **HIDDEN amounts**. `TxType::CONFIDENTIAL_TRANSFER = 14`; payload = the DCT1 bundle. Amount-**private in motion** (the transferred values are hidden) — the first op on this track to hide anything. Full accounting: [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) (SP-10..13).

- **Accept-rule.** `determ_ctx_bundle_verify` proves range (each hidden output `∈ [0, 2^n)`) ∧ balance (`Σv_in = Σv_out + fee`, fee PUBLIC). `determ_ctx_bundle_header` (new accessor) pulls `n_in/m/n/fee` + validates the exact length so the input/output commitment slices are in-bounds. Enforced at the validator (submit) + apply (authoritative).
- **State + supply.** Apply consumes the `n_in` inputs (removed — commitment is its own nullifier) and adds the `m` outputs; the public fee leaves the confidential pool to creators (`accumulated_shielded_ -= fee`, `tx.fee` bound to equal the bundle fee). Pedersen binding ⟹ no underflow. **Pool→pool**: no transparent `tx.to` credit, so **no cross-shard vector** (unlike UNSHIELD). Additive + state-root-invariant.
- **THE INFLATION GUARD (load-bearing).** The crypto can't tell two *listed* inputs are the *same* pool note — listing one note worth `V` twice would prove `Σv_in = 2V` and mint `2V − fee`. Apply defeats this with an **all-or-nothing dedup** (`std::set` across all input+output commitment keys, gather-before-mutate) — a repeated key skips the whole tx. `test-confidential-transfer` pins that a *cryptographically valid* double-listing bundle is REJECTED.
- **Gate**: `test-confidential-transfer` (valid 2-in/2-out applies + supply conserved + A1; tamper/double-spend no-op; the duplicate-input inflation guard) via `tools/test_confidential_transfer.sh`. Clean refute-by-default adversarial audit.
- **Non-claims.** Amount-private but **NOT input-unlinkable** (inputs are named → the note graph is visible; hidden inputs need a nullifier-from-secret + set-membership argument — a larger owner-gated increment); **no on-chain output-secret delivery** (recipient channel is off-chain); adds NO new crypto primitive (reuses the CTX-1 DCT1 bundle). Not post-quantum; single-shard / P-256.

### 3.23 LSAG linkable ring signature over P-256 (`determ::ringsig`) — **SHIPPED (input-unlinkability inc.1: library primitive)**

The **input-unlinkability** track — the primitive that will let a confidential spend prove it consumes *one of N* pool notes **without revealing which** (closing [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) NC-7, the visible note graph). The **Liu-Wei-Wong 2004** Linkable Spontaneous Anonymous Group signature (the CryptoNote / early-Monero RingCT membership primitive). Full accounting: [`LsagRingSignatureSoundness.md`](LsagRingSignatureSoundness.md) (LSAG-1..6).

- **Construction** (`src/crypto/ringsig/lsag.c`): a signer who knows the private key `x` of ONE of `n` ring pubkeys `{P_i = x_i·G}` proves membership without revealing which, and publishes a **key image** `I = x·H_p(P_signer)` (`H_p` = RFC 9380 SSWU RO map) that is DETERMINISTIC in the signing key — the **double-spend nullifier**. Wire: ring = `n` compressed pubkeys; sig = `c0(32) ‖ s_0..s_{n-1}` = `32·(n+1)` B. Verify walks the challenge ring `c := hash_to_scalar(prefix ‖ compress(s_i·G + c·P_i) ‖ compress(s_i·H_p_i + c·I))` and accepts iff it closes (`c == c0`); `prefix = SHA-256(DOM ‖ n ‖ ring ‖ I ‖ msg)` binds ring+image+message. Built ENTIRELY on the shipped §3.8c/§3.9b P-256 API — adds NO new hardness assumption (soundness = P-256 ECDLP + ROM).
- **Dual-oracle**: `test-lsag-c99` (C — sign/verify + linkability + tamper/wrong-msg/wrong-image/malformed reject + a key-image + signature byte KAT) + `tools/verify_lsag.py` (INDEPENDENT python: own P-256 ladder + RFC 9380 hash-to-curve) reproducing the same image + signature byte-for-byte into `tools/vectors/lsag.json`. Deterministic signing (RFC-6979-style nonces).
- **NOT a consensus feature.** This is a LIBRARY primitive. An unlinkable confidential SPEND needs a shielded-pool integration — per-note spend keys + ring selection + an on-chain **key-image (nullifier) set** for double-spend rejection, composed with the §3.22c amount-hiding proofs — a separate, owner-gated step. O(N) size (the log-size Groth-Kohlweiss / Lelantus one-of-many is a later optimization); NOT constant-time; NOT post-quantum.

### 3.23b CLSAG concise linkable ring signature over P-256 (`determ::ringsig`) — **SHIPPED (input-unlinkability inc.2: library primitive)**

The **input-unlinkability inc.2**, generalising §3.23 LSAG to the **two-layer RingCT** statement in ONE concise ring. The **Goodell-Noether-RandomRun 2019** "Concise Linkable Spontaneous Anonymous Group" signature — Monero's current RingCT membership + balance primitive (deployed since 2020, replacing MLSAG). Full accounting: [`ClsagRingSignatureSoundness.md`](ClsagRingSignatureSoundness.md) (CLSAG-1..7).

- **Construction** (`src/crypto/ringsig/clsag.c`): TWO key layers — spend key `P_i` (signer secret `p`, `P_ℓ = p·G`, image `I = p·H_p(P_ℓ)` = the nullifier) and amount commitment `C_i` (signer secret `z`, `C_ℓ − Coffset = z·G`, aux image `D = z·H_p(P_ℓ)`) — folded by hash-derived aggregation coefficients `μ_P = hash_to_scalar(agg, AGG0)`, `μ_C = hash_to_scalar(agg, AGG1)` (`agg = ringP ‖ ringC ‖ I ‖ D ‖ Coffset`) into a single ring over `W_i = μ_P·P_i + μ_C·(C_i − Coffset)` with image `Wimg = μ_P·I + μ_C·D`. Wire: `ringP`, `ringC` = `n` compressed pubkeys each; `I`, `D`, `Coffset` = 33 B; sig = `c0(32) ‖ s_0..s_{n-1}` = `32·(n+1)` B — the SAME length as LSAG despite the second layer (**concise**, vs MLSAG's `~2n`). Verify recomputes `μ_P, μ_C, W_i, Wimg`, walks `c := hash_to_scalar(prefix ‖ compress(s_i·G + c·W_i) ‖ compress(s_i·H_p_i + c·Wimg))`, accepts iff `c == c0`; point negation `−Coffset` = `(n−1)·Coffset`. Proving `C_ℓ − Coffset` is a pure-`G` multiple (no `H`) is exactly the RingCT **balance** statement; forgery against adversarial commitment keys is prevented by the unpredictable `μ` (GNR 2019). Built ENTIRELY on the shipped §3.8c/§3.9b P-256 API — adds NO new hardness assumption (soundness = P-256 ECDLP + ROM).
- **Dual-oracle**: `test-clsag-c99` (C — sign/verify + linkability + tamper/wrong-msg/wrong-aux-image/wrong-key-image/wrong-pseudo-out/malformed reject + an `I` + `D` + signature byte KAT) + `tools/verify_clsag.py` (INDEPENDENT python: own P-256 ladder + RFC 9380 hash-to-curve) reproducing the same `I`, `D`, and signature byte-for-byte into `tools/vectors/clsag.json` (`n = 2, 4, 8`). Deterministic signing (RFC-6979-style nonces bound to BOTH secrets `p`, `z`).
- **NOT a consensus feature.** LIBRARY primitive. The unlinkable RingCT SPEND wiring (per-note spend keys + commitments + ring/pseudo-out selection + an on-chain key-image nullifier set, composed with the §3.22c amount **range** proofs) is a separate, owner-gated step that supersedes the [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) NC-7 named-input model. Balance ≠ range (CLSAG binds the offset amount, not non-negativity); O(N) size; NOT constant-time; NOT post-quantum.

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
