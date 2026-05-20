# `src/crypto/` — vendored cryptographic primitives

Scaffold for the Phase 0 Track 2 C99-vendored crypto stack
(`docs/proofs/CRYPTO-C99-SPEC.md`). Three sibling subtrees mirror the
three values of the root CMake option `-DDETERM_CRYPTO`:

| Subtree       | Build value        | Contents                                                                                                   |
|---------------|--------------------|------------------------------------------------------------------------------------------------------------|
| `modern/`     | `DETERM_CRYPTO=modern`    | XChaCha20-Poly1305, Argon2id, secp256k1 + Bulletproofs, Ed25519 (ref10), X25519, FROST-Ed25519, OPRF-secp256k1 |
| `fips/`      | `DETERM_CRYPTO=fips`     | AES-256-GCM, PBKDF2-HMAC-SHA-256, NIST P-256, Ed25519 (FIPS 186-5), X25519, OPRF-P-256                       |
| `universal/` | `DETERM_CRYPTO=universal`| Both, namespaced. CI / DSF / cross-validation only — breaks the FIPS module boundary. Not for production FIPS. |

Each subtree compiles as a standalone static library and exposes the
same C99 surface declared in `include/determ/crypto.h` (added during
Phase 0 Track 2 — not present in-tree yet). The C++ wrapper in
`include/determ/crypto.hpp` provides RAII + span + type-safety on top.

`include/determ/crypto/profile_build.hpp` carries the link-time
`ProfileBuild` constant and enforces the genesis-vs-build compatibility
check at node startup.

Status: directories are placeholders; primitive vendoring lands as part
of Phase 0 Track 2 (~17-19 weeks senior cryptographic engineering).
