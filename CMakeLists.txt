cmake_minimum_required(VERSION 3.20)
project(determ CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

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

add_executable(determ ${SOURCES})

target_include_directories(determ PRIVATE
  include
  ${asio_SOURCE_DIR}/asio/include
  ${openssl_SOURCE_DIR}/include
)

target_link_libraries(determ PRIVATE
  ssl
  crypto
  nlohmann_json::nlohmann_json
)

if(WIN32)
  target_link_libraries(determ PRIVATE ws2_32 wsock32 crypt32)
endif()

if(UNIX)
  target_link_libraries(determ PRIVATE pthread)
endif()

# ── libsodium (A2 Phase 4: provides ristretto255 + Argon2id for libopaque) ──
# Vendored via the CMake-friendly jedisct1/libsodium-cmake fork. Builds
# cleanly on Windows MSVC + Unix without autotools.
set(SODIUM_DISABLE_TESTS         ON CACHE BOOL "" FORCE)
set(SODIUM_MINIMAL                OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  sodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG        master
)
FetchContent_MakeAvailable(sodium)

# ── liboprf (A2 Phase 6: OPRF + threshold OPRF — libopaque dependency) ──────
# Off by default. Set -DDETERM_VENDOR_OPRF=ON to enable.
#
# Status: integration scaffolding shipped (FetchContent + arpa/inet.h
# portability shim under wallet/oprf_shim/), but the actual upstream
# C source uses C99 VLAs pervasively which MSVC does not support.
# Phase 6 completion requires patching ~15-20 VLA sites in oprf.c +
# toprf.c (oprf.h + toprf.h headers also contain VLA function prototypes
# that cascade into every consumer's compile errors). On Unix this
# vendor would build cleanly; on Windows MSVC it's multi-day porting
# work. Keeping the integration declaration in-tree so a future cycle
# can pick up where this commit left off.
option(DETERM_VENDOR_OPRF "Vendor liboprf for the wallet's OPAQUE adapter" OFF)
if(DETERM_VENDOR_OPRF)
  FetchContent_Declare(
    oprf
    GIT_REPOSITORY https://github.com/stef/liboprf.git
    GIT_TAG        master
  )
  FetchContent_GetProperties(oprf)
  if(NOT oprf_POPULATED)
    FetchContent_Populate(oprf)
  endif()
  add_library(oprf STATIC
    ${oprf_SOURCE_DIR}/src/oprf.c
    ${oprf_SOURCE_DIR}/src/utils.c
    # toprf.c omitted: pervasive VLAs unsupported by MSVC.
  )
  target_include_directories(oprf PUBLIC
    ${oprf_SOURCE_DIR}/src
  )
  if(WIN32)
    target_include_directories(oprf BEFORE PUBLIC
      ${CMAKE_SOURCE_DIR}/wallet/oprf_shim
    )
    target_link_libraries(oprf PUBLIC ws2_32)
    target_compile_definitions(oprf PRIVATE
      _CRT_SECURE_NO_WARNINGS
      _CRT_NONSTDC_NO_DEPRECATE
    )
  endif()
  target_link_libraries(oprf PUBLIC sodium)
endif()

# ── determ-wallet executable (A2 Phases 1-4) ────────────────────────────────
# Separate binary so wallet secret material never shares address space with
# the networked `determ` daemon. Phase 5 will add libopaque on top of
# libsodium with an in-tree CMake shim (libopaque upstream is autotools).
file(GLOB_RECURSE WALLET_SOURCES "wallet/*.cpp")
add_executable(determ-wallet ${WALLET_SOURCES})
target_include_directories(determ-wallet PRIVATE
  wallet
  ${openssl_SOURCE_DIR}/include
)
target_link_libraries(determ-wallet PRIVATE
  crypto
  sodium
  nlohmann_json::nlohmann_json
)
if(WIN32)
  target_link_libraries(determ-wallet PRIVATE ws2_32 crypt32)
endif()
if(UNIX)
  target_link_libraries(determ-wallet PRIVATE pthread)
endif()
