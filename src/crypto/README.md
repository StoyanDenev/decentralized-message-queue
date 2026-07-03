# `src/crypto/` — vendored cryptographic primitives

The Phase 0 Track 2 C99 crypto stack (`docs/proofs/CRYPTO-C99-SPEC.md`):
one per-module layout, one build. Every module below compiles into the
single `determ-crypto-c99` static library linked by all three binaries —
there is no per-posture build variant (DECISION-LOG.md 2026-07-03: the
former `-DDETERM_CRYPTO={modern|fips|universal}` tri-state linked
identical code and was removed; the MODERN/FIPS distinction is a
deployment ALGORITHM POSTURE documented in the profile presets, and
actual FIPS 140 compliance is served by pairing a FIPS deployment with a
pluggable CMVP-validated crypto module — future provider interface, not
a from-scratch-stack property).

Modules: `sha2/ blake2/ argon2/ chacha20/ aes/ ed25519/ x25519/ frost/
p256/` plus the shared `secure_zero.c` + `ct.c` (§3.10). Per-module
provenance + validation evidence: `<module>/README.md`. The umbrella C
header is `include/determ/crypto.h`;
`include/determ/crypto.hpp` provides RAII + span + type-safety on top.

`include/determ/crypto/profile_build.hpp` carries the link-time
`ProfileBuild` constant and enforces the genesis-vs-build compatibility
check at node startup.

Status: directories are placeholders; primitive vendoring lands as part
of Phase 0 Track 2 (~17-19 weeks senior cryptographic engineering).
