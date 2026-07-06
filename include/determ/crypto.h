/* Determ unified C99 crypto API — CRYPTO-C99-SPEC.md §3.11 / §2 Q5.
 *
 * One include for the SHIPPED libsodium-free C99 primitive layer. This is an
 * UMBRELLA: it aggregates the per-module headers verbatim rather than
 * introducing the struct-typedef wrapper signatures sketched in §2 Q5 — the
 * sketch predates the shipped raw-buffer APIs, and a second C-level signature
 * set over the same primitives would be churn without safety gain (the
 * type-safety layer lives in the C++ wrapper, crypto.hpp). Recorded as a Q5
 * deviation in the spec's §3.11 status, same convention as the X25519 / FROST
 * shipped-name annotations inside Q5 itself.
 *
 * What you get (all C99, all validated byte-equal vs OpenSSL / libsodium /
 * published KATs — see src/crypto/<module>/README.md per module):
 *   - SHA-256/512, HMAC, HKDF, PBKDF2            (sha2/sha2.h,     §3.1+§3.8b)
 *   - BLAKE2b                                    (blake2/blake2b.h, §3.6 dep)
 *   - Argon2id                                   (argon2/argon2id.h, §3.6)
 *   - ChaCha20, Poly1305, ChaCha20-Poly1305,
 *     HChaCha20 + XChaCha20-Poly1305             (chacha20/*,       §3.4)
 *   - AES-256 block + AES-256-GCM                (aes/aes.h,        §3.5)
 *   - Ed25519 sign/verify                        (ed25519/ed25519.h, §3.2)
 *   - X25519                                     (x25519/x25519.h,  §3.3)
 *   - NIST P-256 (FIPS-profile curve)            (p256/p256.h,      §3.8c)
 *   - determ_ct_memcmp + determ_secure_zero      (ct.h, secure_zero.h, §3.10)
 *
 * Deliberately NOT included:
 *   - FROST-Ed25519 (crypto/frost/frost.h) — retained as a LIBRARY but not a
 *     Determ chain primitive (docs/proofs/FROST_DEVIATION_NOTICE.md); callers
 *     opt in with an explicit include so library presence is never mistaken
 *     for protocol adoption.
 *   - The Ed25519 scalar/group primitives (ed25519/ed25519_group.h) — the
 *     FROST building blocks; explicit include for the same reason.
 *   - §3.8c/§3.9 primitives (P-256, RFC 9497 OPRF) are shipped and included here.
 *     secp256k1 (former §3.7) was never implemented — P-256 supplants it.
 */
#ifndef DETERM_CRYPTO_H
#define DETERM_CRYPTO_H

#include "determ/crypto/secure_zero.h"
#include "determ/crypto/ct.h"
#include "determ/crypto/sha2/sha2.h"
#include "determ/crypto/blake2/blake2b.h"
#include "determ/crypto/argon2/argon2id.h"
#include "determ/crypto/chacha20/chacha20.h"
#include "determ/crypto/chacha20/xchacha20_poly1305.h"
#include "determ/crypto/aes/aes.h"
#include "determ/crypto/ed25519/ed25519.h"
#include "determ/crypto/x25519/x25519.h"
#include "determ/crypto/p256/p256.h"
/* §3.19 Pedersen commitment over P-256 (C = v*G + r*H) — the range-proof /
 * confidential-tx track's first building block; a LIBRARY PRIMITIVE, no chain
 * call site. Pure composition over the P-256 primitives above. */
#include "determ/crypto/pedersen/pedersen.h"
/* §3.18 ML-DSA (Dilithium, FIPS 204) — the complete PQ signature scheme (KeyGen +
 * Sign + Verify), owner-authorized + ACVP-pinned. Shipped as a LIBRARY PRIMITIVE;
 * chain integration (a PQ signature option) is a later, separately-reviewed step. */
#include "determ/crypto/mldsa/keygen.h"
#include "determ/crypto/mldsa/sign.h"

#endif /* DETERM_CRYPTO_H */
