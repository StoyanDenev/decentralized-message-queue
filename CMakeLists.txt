cmake_minimum_required(VERSION 3.20)
project(determ CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# ── DETERM_UBSAN: instrument ONLY Determ's own targets (determ +
# determ-crypto-c99) with -fsanitize=undefined, NOT the vendored FetchContent
# deps (OpenSSL/asio/json build + cache normally). Target-scoped rather than
# global CMAKE_CXX_FLAGS so the heavy OpenSSL tree is not rebuilt under the
# sanitizer. Enables the tools/ci_local.sh --sanitize consensus-UB gate
# (the state_root-fork class, DECISION-LOG 2026-07-03). GCC/Clang only.
option(DETERM_UBSAN "Instrument Determ's own targets with UBSan (GCC/Clang)" OFF)

include(FetchContent)

# The vendored OpenSSL fork (janbar/openssl-cmake) declares a pre-3.5
# cmake_minimum_required; CMake 4.0 removed compatibility with < 3.5 and refuses
# to configure it (surfaced on the windows-latest CI runner, which upgraded to
# CMake 4.x). Allow the old minimum for the FetchContent subprojects — set BEFORE
# the FetchContent_MakeAvailable calls so it is in scope for their add_subdirectory.
# Harmless on the dev box's CMake 3.x (an unused cache/normal variable there).
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# ── OpenSSL (no Perl required) ──────────────────────────────────────────────
set(BUILD_SHARED_LIBS     OFF CACHE BOOL "" FORCE)
set(WITH_APPS             OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  openssl
  GIT_REPOSITORY https://github.com/janbar/openssl-cmake.git
  GIT_TAG        1.1.1w-20231130
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(openssl)

# ── Asio (standalone, header-only) ─────────────────────────────────────────
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG        asio-1-30-2
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(asio)

# ── nlohmann/json ───────────────────────────────────────────────────────────
FetchContent_Declare(
  json
  URL      https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
)
FetchContent_MakeAvailable(json)

# ── determ executable ───────────────────────────────────────────────────────
add_definitions(-DASIO_STANDALONE -DASIO_NO_DEPRECATED)

if(WIN32)
  add_definitions(-D_WIN32_WINNT=0x0601)
endif()

file(GLOB_RECURSE SOURCES "src/*.cpp")

# v2.17 / S-004 option 2: passphrase-encrypted keyfiles. The
# envelope crypto (AES-256-GCM + PBKDF2-HMAC-SHA-256) lives in
# wallet/envelope.cpp; main `determ` binary needs it for
# `account create --passphrase` to encrypt the generated keyfile
# at rest. No wallet-state is shared between binaries — only the
# crypto primitive code.
list(APPEND SOURCES "${CMAKE_SOURCE_DIR}/wallet/envelope.cpp")
# S-035 Option 1 seed: the `determ test-shamir` subcommand
# exercises wallet/shamir.cpp directly (in-process unit test of
# the A2 Phase 1 secret-sharing primitive). Link it into the main
# binary so the test command can call shamir::split / ::combine.
list(APPEND SOURCES "${CMAKE_SOURCE_DIR}/wallet/shamir.cpp")
# ── determ-crypto-c99: the libsodium-free C99 primitive layer as a STATIC
# library (CRYPTO-C99-SPEC §3.14 seed — "each module compiles as a static
# lib; top-level libdeterm-crypto aggregates"). One aggregate target today
# (per-module split is the §3.14 follow-up once a second consumer exists);
# consumed by `determ` and linkable by any future target without re-listing
# sources. Umbrella header: include/determ/crypto.h; C++ wrapper:
# include/determ/crypto.hpp (header-only, rides the PUBLIC include dir).
# Per-module provenance + validation evidence: src/crypto/<module>/README.md.
# The src/*.cpp glob above does not pick up .c files; list them explicitly.
# libsodium drop: DONE (2026-07-03) — no Determ binary links libsodium.
# The daemon and determ-light never did; determ-wallet, the last consumer,
# migrated its ~200 call sites (Ed25519 sign/verify/derive, X25519,
# sodium_memzero) in wallet/main.cpp to determ::c99 via an API-compatible
# shim (§3.15), and the OPAQUE stub was DELETED with the liboprf track
# (DECISION-LOG.md 2026-07-03). libsodium.a survives only as the byte-equal
# cross-validation oracle (tools/c99_libsodium_xval.c). §3.14 remaining:
# the per-module sub-library split + the cross-compilation matrix.
add_library(determ-crypto-c99 STATIC
  # §3.10 shared primitives — secure_zero (hygiene) + ct_memcmp (CT compare),
  # consumed by every module below.
  "${CMAKE_SOURCE_DIR}/src/crypto/secure_zero.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/ct.c"
  # §3.1 SHA-2 family + §3.8b PBKDF2 — `determ test-sha2-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/sha2/sha256.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/sha2/sha512.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/sha2/hmac.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/sha2/hkdf.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/sha2/pbkdf2.c"
  # §3.4 ChaCha20 / Poly1305 / ChaCha20-Poly1305 + XChaCha20-Poly1305 —
  # `determ test-chacha20-c99` + `determ test-xchacha-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/chacha20/chacha20.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/chacha20/poly1305.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/chacha20/chacha20_poly1305.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/chacha20/xchacha20_poly1305.c"
  # §3.5 AES-256 + GCM (arithmetic S-box + branchless GHASH) — `determ test-aes-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/aes/aes_core.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/aes/aes_gcm.c"
  # §3.2 Ed25519 (gf[16] cswap-ladder, RFC 8032; includes the exposed
  # scalar/group ops FROST builds on) — `determ test-ed25519-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/ed25519/ed25519.c"
  # §3.8 FROST-Ed25519 — LIBRARY-ONLY, not a chain primitive
  # (docs/proofs/FROST_DEVIATION_NOTICE.md) — `determ test-frost-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/frost/frost.c"
  # §3.3 X25519 (Montgomery cswap-ladder, RFC 7748) — `determ test-x25519-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/x25519/x25519.c"
  # §3.6 BLAKE2b (RFC 7693) + Argon2id (RFC 9106) — `determ test-blake2b-c99`
  # + `determ test-argon2id-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/blake2/blake2b.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/argon2/argon2id.c"
  # §3.8c NIST P-256 (FIPS-profile curve; Montgomery field + RCB complete
  # addition + CT ladder) — `determ test-p256-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/p256/p256.c"
  # §3.19 Pedersen commitment over P-256 (range-proof / confidential-tx track,
  # increments 1-3: commit + vector commit + MSM) — pure composition over the
  # P-256 primitives above; `determ test-pedersen-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/pedersen/pedersen.c"
  # §3.19 inc.4: the Bulletproofs inner-product argument (the range-proof track's
  # log-size core) — `determ test-bp-ipa-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/pedersen/ipa.c"
  # §3.19 inc.5: the Bulletproofs single-value range proof (v in [0,2^n)) wrapping
  # the inc.4 IPA — `determ test-bp-rangeproof-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/pedersen/rangeproof.c"
  # §3.19 inc.7: confidential-tx balance proof over P-256 (the FIPS-profile amount-
  # conservation half) — pure composition over the pedersen/P-256 public API,
  # `determ test-p256-balance-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/pedersen/balance.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/pedersen/ctxbundle.c"  # §3.22 DCT1 confidential-transfer bundle
  # §3.20 inc.1: finite-field Pedersen commitment over the RFC 3526 MODP-3072
  # prime-order subgroup (the MODERN-profile large-prime backend) — CIOS Montgomery
  # bignum, no __int128 — `determ test-ff-pedersen-c99`. ffipa.c adds the §3.20 inc.4
  # Bulletproofs inner-product argument over Z_p* — `determ test-ff-ipa-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/ff/ffgroup.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/ff/ffipa.c"
  # §3.20 inc.5 single-value Bulletproofs range proof over Z_p* — `determ test-ff-rangeproof-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/ff/ffrangeproof.c"
  # §3.20 inc.7 confidential-tx balance proof over Z_p* — `determ test-ff-balance-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/ff/ffbalance.c"
  # FIPS 202 SHA-3 / SHAKE (Keccak-f[1600]) — the XOF prerequisite for the
  # ML-DSA/Dilithium PQ signature track — `determ test-sha3-c99`.
  "${CMAKE_SOURCE_DIR}/src/crypto/sha3/sha3.c"
  # §3.18 ML-DSA (Dilithium, FIPS 204) PQ signature track, increment 1: the
  # Z_q arithmetic core (modular reduction + negacyclic NTT) — `determ
  # test-mldsa-c99`. Built on the SHAKE XOF above; additive (no signer yet).
  "${CMAKE_SOURCE_DIR}/src/crypto/mldsa/reduce.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/mldsa/ntt.c"
  "${CMAKE_SOURCE_DIR}/src/crypto/mldsa/rounding.c"
  # §3.18 increment 3: the rejection samplers — the first SHAKE consumers.
  "${CMAKE_SOURCE_DIR}/src/crypto/mldsa/sample.c"
  # §3.18 increment 4: coefficient bit-packing (the poly <-> byte codec).
  "${CMAKE_SOURCE_DIR}/src/crypto/mldsa/pack.c"
  # §3.18 increment 5: per-poly ring arithmetic (add/sub/reduce/caddq/pointwise).
  "${CMAKE_SOURCE_DIR}/src/crypto/mldsa/poly.c"
  # §3.18 increment 6: matrix/vector layer (ExpandA/ExpandS/ExpandMask + polyvec ops).
  "${CMAKE_SOURCE_DIR}/src/crypto/mldsa/polyvec.c"
  # §3.18 increment 7: ML-DSA.KeyGen_internal (ACVP-pinned; pk/sk encode).
  "${CMAKE_SOURCE_DIR}/src/crypto/mldsa/keygen.c"
  # §3.18 increment 8: ML-DSA Sign_internal + Verify_internal (ACVP-pinned).
  "${CMAKE_SOURCE_DIR}/src/crypto/mldsa/sign.c"
  # §3.15 OS-entropy shim (BCryptGenRandom / getrandom) — replaces OpenSSL
  # RAND_bytes at the daemon's entropy sites (dh_secret commit, node keygen).
  "${CMAKE_SOURCE_DIR}/src/crypto/rng/rng.c"
  # RFC 4648 Base64 (strict decode) — the 1c wallet-envelope codec, replacing
  # OpenSSL EVP_EncodeBlock/EVP_DecodeBlock (the wallet's last OpenSSL class).
  "${CMAKE_SOURCE_DIR}/src/crypto/base64/base64.c"
)
target_include_directories(determ-crypto-c99 PUBLIC include)
if(WIN32)
  # rng.c uses BCryptGenRandom; PUBLIC so every consumer links bcrypt.
  target_link_libraries(determ-crypto-c99 PUBLIC bcrypt)
endif()

add_executable(determ ${SOURCES})

target_include_directories(determ PRIVATE
  include
  ${CMAKE_SOURCE_DIR}/wallet
  ${asio_SOURCE_DIR}/asio/include
  ${openssl_SOURCE_DIR}/include
)

# §3.15 (2026-07-03): the daemon's CONSENSUS crypto (SHA-256 builder, Ed25519
# sign/verify, entropy) now runs on determ-crypto-c99. libcrypto remains
# linked ONLY for the §Q9 test-oracle subcommands in src/main.cpp
# (test-*-c99 cross-validate the C99 stack against an independent
# implementation — by design a non-determ backend). After 1c (same day)
# this is the LAST OpenSSL consumer in the tree: determ-light and
# determ-wallet link zero OpenSSL. libssl (TLS) was never used by any
# target — no TLS anywhere in src/net — and is dropped.
target_link_libraries(determ PRIVATE
  determ-crypto-c99
  crypto
  nlohmann_json::nlohmann_json
)

if(WIN32)
  target_link_libraries(determ PRIVATE ws2_32 wsock32 crypt32)
  # MSVC defaults to a 1 MB stack; the in-process test handlers
  # (test-atomic-scope, test-overflow-paths, test-time-monotonicity,
  # test-chain-prev-hash-link, test-state-root-determinism, etc.)
  # accumulate stack frames across many mutually-exclusive
  # `if (cmd == ...)` branches inside main() and can hit
  # STATUS_STACK_OVERFLOW (0xC00000FD) at startup. Bump the reserve
  # to 16 MB to eliminate the failure mode without restructuring the
  # dispatcher into a separate compilation unit.
  target_link_options(determ PRIVATE /STACK:16777216)
endif()

if(UNIX)
  target_link_libraries(determ PRIVATE pthread)
endif()

# UBSan on Determ's own code only (see the DETERM_UBSAN option above). The
# vendored deps stay uninstrumented, so the OpenSSL tree is reused from cache
# and the sanitized build is just the ~18 Determ TUs.
if(DETERM_UBSAN)
  # -O1 (overriding RelWithDebInfo's -O2) on the instrumented targets: the
  # ~14k-line main.cpp under -O2 -g + UBSan peaks several GB per TU and OOM-killed
  # the GitHub runner (SIGTERM/143 at ~5.5 min, right as the build started) when
  # compiled in parallel. -O1 slashes per-TU compiler memory while UBSan still
  # catches the C-standard UB this gate targets (the state_root determinism-fork
  # and signed-shift classes are optimization-level-independent). Paired with the
  # -j cap in tools/ci_local.sh --sanitize.
  target_compile_options(determ-crypto-c99 PRIVATE -fsanitize=undefined -O1)
  target_compile_options(determ            PRIVATE -fsanitize=undefined -O1)
  target_link_options(determ               PRIVATE -fsanitize=undefined)
  message(STATUS "DETERM_UBSAN: determ + determ-crypto-c99 instrumented with UBSan (-O1)")
endif()

# ── determ-wallet executable (A2 Phases 1-5 + 7) ────────────────────────────
# Separate binary so wallet secret material never shares address space with
# the networked `determ` daemon. 1c (2026-07-03): the wallet links ZERO
# OpenSSL — every crypto class migrated to determ-crypto-c99 (PBKDF2 +
# AES-256-GCM envelopes, HKDF/HMAC, Ed25519 keygen/derive, OS entropy,
# base64), format-compatible byte-for-byte with the OpenSSL-era output.
# Recovery uses Shamir + c99 AEAD envelopes (passphrase scheme); the
# OPAQUE/liboprf track was DE-SCOPED 2026-07-03 (DECISION-LOG).
file(GLOB_RECURSE WALLET_SOURCES "wallet/*.cpp")
add_executable(determ-wallet ${WALLET_SOURCES})
target_include_directories(determ-wallet PRIVATE
  wallet
)
target_link_libraries(determ-wallet PRIVATE
  determ-crypto-c99
  nlohmann_json::nlohmann_json
)
if(WIN32)
  target_link_libraries(determ-wallet PRIVATE ws2_32 crypt32)
endif()
if(UNIX)
  target_link_libraries(determ-wallet PRIVATE pthread)
endif()

# ── determ-light executable (R39 / robust-gathering-oasis plan) ─────────────
# Trust-minimized light-client wallet. Talks to a daemon's RPC and verifies
# every piece of data received (headers, committee sigs, state-proofs) so an
# honest light-client cannot be tricked even by a malicious daemon. Genesis
# JSON pins the chain identity on every connection.
#
# Dependency footprint: OpenSSL (Ed25519 + SHA-256) + nlohmann/json + BSD
# sockets (Winsock on Windows). Explicitly NO libsodium, NO asio, NO
# node/* / producer.cpp / validator.cpp / chain/chain.cpp linkage —
# reuses the standalone crypto + chain primitives from src/ via an
# EXPLICIT file list (not glob) so the binary stays small (~3-5 MB
# stripped) and the linker can't accidentally pull in daemon code.
add_executable(determ-light
  light/main.cpp
  light/rpc_client.cpp
  light/verify.cpp
  light/trustless_read.cpp
  light/keyfile.cpp
  light/sign_tx.cpp
  light/pq_sign_tx.cpp
  light/watch.cpp
  light/export.cpp
  light/verify_archive.cpp
  light/verify_state_bundle.cpp
  light/account_history.cpp
  light/verify_tx_inclusion.cpp
  light/verify_state_root.cpp
  light/persist.cpp
  # Reused from src/ (explicit list — no glob):
  src/crypto/merkle.cpp
  src/crypto/keys.cpp
  src/crypto/sha256.cpp
  src/crypto/pqauth.cpp          # §3.21 DPQ1 PQ tx-auth envelope (determ::pqauth)
  src/crypto/pq_address.cpp      # §3.21 PQ-native bearer address (pq-address / pq-transfer)
  src/chain/block.cpp
  src/chain/genesis.cpp
)
# §3.15 (2026-07-03): determ-light links ZERO OpenSSL. Its whole crypto
# surface (SHA-256 via src/crypto/sha256.cpp, Ed25519 via src/crypto/keys.cpp
# + light/keyfile.cpp) now runs on determ-crypto-c99; HMAC in light/main.cpp
# was already from-scratch. The EOL-OpenSSL liability is out of the
# light-client verification path entirely.
target_include_directories(determ-light PRIVATE
  include
  light
)
target_link_libraries(determ-light PRIVATE
  determ-crypto-c99
  nlohmann_json::nlohmann_json
)
if(WIN32)
  target_link_libraries(determ-light PRIVATE ws2_32 crypt32)
endif()
if(UNIX)
  target_link_libraries(determ-light PRIVATE pthread)
endif()

# ── determ-dsf: Deterministic Simulation Framework (S-035 Opt 2, DSF-SPEC) ───
# TEST-ONLY binary. Increment 1 = the deterministic core (virtual clock +
# discrete-event scheduler + scenario DSL + trace/replay + property checker +
# framework-demonstration scenarios). Fully self-contained: header-only core
# under sim/, a single .cpp TU, NO link deps (no OpenSSL, no determ core, no
# asio) — the same cross-toolchain determinism discipline as the consensus
# surface (a fixed --seed yields a byte-identical trace across -O0/-O2). The
# full virtual-network + consensus-engine coupling + 30-scenario set land in
# later increments. Excluded from install/production targets.
add_executable(determ-dsf sim/dsf_main.cpp)
target_compile_features(determ-dsf PRIVATE cxx_std_20)
target_include_directories(determ-dsf PRIVATE ${CMAKE_SOURCE_DIR}/sim)
