cmake_minimum_required(VERSION 3.20)
project(determ C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Werror -pedantic)

if(WIN32)
  link_libraries(ws2_32)
elseif(UNIX AND NOT APPLE)
  link_libraries(rt pthread)
endif()

include_directories(include src tests)

# Core C99 Cryptography Sources
set(CRYPTO_SRCS
    src/crypto/secure_zero.c
    src/crypto/ct.c
    src/crypto/aes/aes_core.c
    src/crypto/sha2/sha256.c
    src/crypto/sha2/sha512.c
    src/crypto/sha2/hmac.c
    src/crypto/sha2/hkdf.c
    src/crypto/sha2/pbkdf2.c
    src/crypto/chacha20/chacha20.c
    src/crypto/chacha20/poly1305.c
    src/crypto/chacha20/chacha20_poly1305.c
    src/crypto/chacha20/xchacha20_poly1305.c
    src/crypto/ed25519/ed25519.c
    src/crypto/x25519/x25519.c
    src/crypto/p256/p256.c
    src/crypto/opaque_dsso.c
    src/crypto/rng/rng.c
)

# Core Consensus, Wire, Storage & Networking C99 Sources
set(CONSENSUS_SRCS
    src/time/clock.c
    src/net/virtual_transport.c
    src/consensus/duel_state.c
    src/consensus/branch_resolver.c
    src/consensus/dda.c
    src/crypto/vdf.c
    src/net/event_loop.c
    src/net/k2_net.c
    src/net/peer_mesh.c
    src/net/reactor.c
    src/wire/parser.c
    src/wire/json_token.c
    src/wire/binary_codec.c
    src/rpc/json_rpc.c
    src/rpc/http_rpc_server.c
    src/storage/block_store.c
    src/ledger/state.c
    src/ledger/shard_routing.c
    src/ledger/pending_transfer.c
)

add_library(determ_core STATIC ${CRYPTO_SRCS} ${CONSENSUS_SRCS})

# DSF variant for deterministic simulation tests
add_library(determ_core_dsf STATIC ${CRYPTO_SRCS} ${CONSENSUS_SRCS})
target_compile_definitions(determ_core_dsf PUBLIC DETERM_DSF_ENABLED)

# Node Executable
add_executable(determ-node src/determ_node.c)
target_link_libraries(determ-node PRIVATE determ_core)

# C99 Tests
enable_testing()

add_executable(test-k2-posw tests/test_k2_posw.c)
target_link_libraries(test-k2-posw PRIVATE determ_core_dsf)
add_test(NAME test-k2-posw COMMAND test-k2-posw)

add_executable(test-k2-duel tests/test_k2_duel.c)
target_link_libraries(test-k2-duel PRIVATE determ_core)
add_test(NAME test-k2-duel COMMAND test-k2-duel)

add_executable(test-dsf-k2-duel tests/test_dsf_k2_duel.c)
target_link_libraries(test-dsf-k2-duel PRIVATE determ_core_dsf)
add_test(NAME test-dsf-k2-duel COMMAND test-dsf-k2-duel)

add_executable(test-k2-net-rpc tests/test_k2_net_rpc.c)
target_link_libraries(test-k2-net-rpc PRIVATE determ_core)
add_test(NAME test-k2-net-rpc COMMAND test-k2-net-rpc)

add_executable(test-binary-codec tests/test_binary_codec.c)
target_link_libraries(test-binary-codec PRIVATE determ_core)
add_test(NAME test-binary-codec COMMAND test-binary-codec)

add_executable(test-peer-mesh tests/test_peer_mesh.c)
target_link_libraries(test-peer-mesh PRIVATE determ_core)
add_test(NAME test-peer-mesh COMMAND test-peer-mesh)

add_executable(test-block-store tests/test_block_store.c)
target_link_libraries(test-block-store PRIVATE determ_core)
add_test(NAME test-block-store COMMAND test-block-store)

add_executable(test-dda tests/test_dda.c)
target_link_libraries(test-dda PRIVATE determ_core)
add_test(NAME test-dda COMMAND test-dda)

add_executable(test-qpc-clock-overflow tests/test_qpc_clock_overflow.c)
target_link_libraries(test-qpc-clock-overflow PRIVATE determ_core)
add_test(NAME test-qpc-clock-overflow COMMAND test-qpc-clock-overflow)

add_executable(test-http-rpc tests/test_http_rpc.c)
target_link_libraries(test-http-rpc PRIVATE determ_core)
add_test(NAME test-http-rpc COMMAND test-http-rpc)

add_executable(test-ledger-dsso tests/test_ledger_dsso.c)
target_link_libraries(test-ledger-dsso PRIVATE determ_core)
add_test(NAME test-ledger-dsso COMMAND test-ledger-dsso)

add_executable(test-fuzz-ledger tests/fuzz_ledger.c)
target_link_libraries(test-fuzz-ledger PRIVATE determ_core_dsf)
add_test(NAME test-fuzz-ledger COMMAND test-fuzz-ledger)

add_executable(test-k2-duel-fallback tests/test_k2_duel_fallback.c)
target_link_libraries(test-k2-duel-fallback PRIVATE determ_core_dsf)
add_test(NAME test-k2-duel-fallback COMMAND test-k2-duel-fallback)

add_executable(test-opaque-dsso tests/test_opaque_dsso.c)
target_link_libraries(test-opaque-dsso PRIVATE determ_core_dsf)
add_test(NAME test-opaque-dsso COMMAND test-opaque-dsso)

add_executable(test-triple-entry-ledger tests/test_triple_entry_ledger.c)
target_link_libraries(test-triple-entry-ledger PRIVATE determ_core_dsf)
add_test(NAME test-triple-entry-ledger COMMAND test-triple-entry-ledger)

add_executable(test-fuzzer-parser tests/fuzzer_parser.c)
target_link_libraries(test-fuzzer-parser PRIVATE determ_core)
add_test(NAME test-fuzzer-parser COMMAND test-fuzzer-parser)

add_executable(test-pending-transfer tests/test_pending_transfer.c)
target_link_libraries(test-pending-transfer PRIVATE determ_core)
add_test(NAME test-pending-transfer COMMAND test-pending-transfer)

add_executable(test-rpc-pending-transfer tests/test_rpc_pending_transfer.c)
target_link_libraries(test-rpc-pending-transfer PRIVATE determ_core)
add_test(NAME test-rpc-pending-transfer COMMAND test-rpc-pending-transfer)

add_executable(test-shard-routing tests/test_shard_routing.c)
target_link_libraries(test-shard-routing PRIVATE determ_core)
add_test(NAME test-shard-routing COMMAND test-shard-routing)

add_executable(test-rpc-shard-routing tests/test_rpc_shard_routing.c)
target_link_libraries(test-rpc-shard-routing PRIVATE determ_core)
add_test(NAME test-rpc-shard-routing COMMAND test-rpc-shard-routing)
