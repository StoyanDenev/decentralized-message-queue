# `src/crypto/fips/` — FIPS cryptographic primitives

Linked when CMake is invoked with `-DDETERM_CRYPTO=fips` or
`-DDETERM_CRYPTO=universal`. This subtree is the FIPS 140-2/3 module
boundary; for production FIPS deployments (`tactical`, `cluster`)
nothing outside this subtree may carry cryptographic primitives into
the binary.

Planned contents (per `docs/proofs/CRYPTO-C99-SPEC.md` §2 + §3):

| Primitive             | Source                                | Work unit |
|-----------------------|---------------------------------------|-----------|
| Ed25519 (FIPS 186-5)  | Bernstein ref10                       | §3.1      |
| X25519 (SP 800-186)   | curve25519-donna                      | §3.2      |
| SHA-256 / SHA-512     | NIST FIPS 180-4 reference             | §3.3      |
| AES-256-GCM           | NIST FIPS 197 + SP 800-38D reference  | §3.4 FIPS |
| PBKDF2-HMAC-SHA-256   | NIST SP 800-132                       | §3.8b     |
| NIST P-256            | NIST FIPS 186-5 reference             | §3.8c     |
| OPRF on P-256         | voprf draft + RFC 9380 (P-256 profile)| §3.9b     |

No Bulletproofs — no FIPS-validated zero-knowledge range proof exists.
v2.22 confidential transactions are structurally unavailable here.

Placeholder — primitives land in Phase 0 Track 2.
