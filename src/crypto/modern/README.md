# `src/crypto/modern/` — MODERN cryptographic primitives

Linked when CMake is invoked with `-DDETERM_CRYPTO=modern` (default) or
`-DDETERM_CRYPTO=universal`.

Planned contents (per `docs/proofs/CRYPTO-C99-SPEC.md` §2 + §3):

| Primitive            | Source                                  | Work unit |
|----------------------|-----------------------------------------|-----------|
| Ed25519              | Bernstein ref10                         | §3.1      |
| X25519               | curve25519-donna                        | §3.2      |
| SHA-256 / SHA-512    | NIST FIPS 180-4 reference               | §3.3      |
| ChaCha20-Poly1305    | RFC 8439                                | §3.4      |
| XChaCha20-Poly1305   | RFC 8439 + XChaCha extension            | §3.4      |
| Argon2id             | Password-Hashing Competition reference  | §3.5      |
| secp256k1            | libsecp256k1                            | §3.6      |
| Bulletproofs         | libsecp256k1-zkp                        | §3.7      |
| FROST-Ed25519        | RFC 9591 reference impl                 | §3.8      |
| OPRF on secp256k1    | voprf draft + RFC 9380                  | §3.9a     |

Placeholder — primitives land in Phase 0 Track 2.
