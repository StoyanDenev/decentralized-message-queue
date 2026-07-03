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
)
target_include_directories(determ-crypto-c99 PUBLIC include)

add_executable(determ ${SOURCES})

target_include_directories(determ PRIVATE
  include
  ${CMAKE_SOURCE_DIR}/wallet
  ${asio_SOURCE_DIR}/asio/include
  ${openssl_SOURCE_DIR}/include
)

target_link_libraries(determ PRIVATE
  determ-crypto-c99
  ssl
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
  target_compile_options(determ-crypto-c99 PRIVATE -fsanitize=undefined)
  target_compile_options(determ            PRIVATE -fsanitize=undefined)
  target_link_options(determ               PRIVATE -fsanitize=undefined)
  message(STATUS "DETERM_UBSAN: determ + determ-crypto-c99 instrumented with UBSan")
endif()

# ── determ-wallet executable (A2 Phases 1-5 + 7) ────────────────────────────
# Separate binary so wallet secret material never shares address space with
# the networked `determ` daemon. Recovery uses Shamir + OpenSSL AEAD envelopes
# (passphrase scheme). The OPAQUE/liboprf track was DE-SCOPED 2026-07-03
# (DECISION-LOG) — it was consumer-less AI-era scaffolding pointing at a
# ristretto255/libopaque road the project already rejected for OPRF-P256.
file(GLOB_RECURSE WALLET_SOURCES "wallet/*.cpp")
add_executable(determ-wallet ${WALLET_SOURCES})
target_include_directories(determ-wallet PRIVATE
  wallet
  ${openssl_SOURCE_DIR}/include
)
target_link_libraries(determ-wallet PRIVATE
  crypto
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
  src/chain/block.cpp
  src/chain/genesis.cpp
)
target_include_directories(determ-light PRIVATE
  include
  light
  ${openssl_SOURCE_DIR}/include
)
target_link_libraries(determ-light PRIVATE
  ssl
  crypto
  nlohmann_json::nlohmann_json
)
if(WIN32)
  target_link_libraries(determ-light PRIVATE ws2_32 crypt32)
endif()
if(UNIX)
  target_link_libraries(determ-light PRIVATE pthread)
endif()
