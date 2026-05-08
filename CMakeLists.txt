cmake_minimum_required(VERSION 3.20)
project(dhcoin CXX C)

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

# ── dhcoin executable ───────────────────────────────────────────────────────
# BLS dropped in v1 rev. 2 — protocol uses Ed25519 + class-group VDF.
# chiavdf integration is pending (placeholder VDF implementation in src/crypto/vdf.cpp).
add_definitions(-DASIO_STANDALONE -DASIO_NO_DEPRECATED)

if(WIN32)
  add_definitions(-D_WIN32_WINNT=0x0601)
endif()

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(dhcoin ${SOURCES})

target_include_directories(dhcoin PRIVATE
  include
  ${asio_SOURCE_DIR}/asio/include
  ${openssl_SOURCE_DIR}/include
)

target_link_libraries(dhcoin PRIVATE
  ssl
  crypto
  nlohmann_json::nlohmann_json
)

if(WIN32)
  target_link_libraries(dhcoin PRIVATE ws2_32 wsock32 crypt32)
endif()

if(UNIX)
  target_link_libraries(dhcoin PRIVATE pthread)
endif()
