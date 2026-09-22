# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Determ Contributors
#
# Sovereign C99 Unikernel Execution Environment
# Monolithic Pure C99 Toolchain Configuration

cmake_minimum_required(VERSION 3.16)
project(determ_c99_node C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Enforce strict bare-metal C99 warning compliance
if(MSVC)
    add_compile_options(/W4 /WX /TC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -Werror -pedantic -Wshadow -Wstrict-prototypes)
    add_definitions(-D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -D_DEFAULT_SOURCE)
endif()

option(DETERM_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(DETERM_ASAN "Enable AddressSanitizer" OFF)

if(DETERM_UBSAN)
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined)
endif()
if(DETERM_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

include_directories(include src tests)

# Core Cryptography C99 Library Sources
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
    src/wire/parser.c
    src/wire/json_token.c
    src/wire/binary_codec.c
    src/ledger/state.c
    src/ledger/shard_routing.c
    src/ledger/pending_transfer.c
)

if(NOT WIN32)
    list(APPEND CONSENSUS_SRCS
        src/net/event_loop.c
        src/net/k2_net.c
        src/net/peer_mesh.c
        src/net/reactor.c
        src/rpc/json_rpc.c
        src/rpc/http_rpc_server.c
        src/storage/block_store.c
    )
endif()

add_library(determ_core STATIC ${CRYPTO_SRCS} ${CONSENSUS_SRCS})
add_library(determ_core_dsf STATIC ${CRYPTO_SRCS} ${CONSENSUS_SRCS})
target_compile_definitions(determ_core_dsf PUBLIC DETERM_DSF_ENABLED)

# Target Platform Link Libraries
set(EXTRA_LIBS "")
if(WIN32)
    list(APPEND EXTRA_LIBS ws2_32 bcrypt)
elseif(UNIX AND NOT APPLE)
    list(APPEND EXTRA_LIBS rt pthread)
endif()

# C99 Test Suites
enable_testing()

macro(determ_add_test test_name source_file)
    add_executable(${test_name} ${source_file})
    target_link_libraries(${test_name} PRIVATE determ_core ${EXTRA_LIBS})
    add_test(NAME ${test_name} COMMAND ${test_name})
endmacro()

macro(determ_add_dsf_test test_name source_file)
    add_executable(${test_name} ${source_file})
    target_compile_definitions(${test_name} PRIVATE DETERM_DSF_ENABLED)
    target_link_libraries(${test_name} PRIVATE determ_core_dsf ${EXTRA_LIBS})
    add_test(NAME ${test_name} COMMAND ${test_name})
endmacro()

# Portable Test Targets
determ_add_test(test-k2-duel tests/test_k2_duel.c)
determ_add_dsf_test(test-k2-duel-fallback tests/test_k2_duel_fallback.c)
determ_add_test(test-dda tests/test_dda.c)
determ_add_test(test-qpc-clock-overflow tests/test_qpc_clock_overflow.c)
determ_add_test(test-binary-codec tests/test_binary_codec.c)
determ_add_test(fuzzer-parser tests/fuzzer_parser.c)
determ_add_test(test-shard-routing tests/test_shard_routing.c)
determ_add_test(test-pending-transfer tests/test_pending_transfer.c)

# Specialized Test Targets
add_library(ed25519_bounded_impl OBJECT tests/test_ed25519_bounded.c)
target_compile_definitions(ed25519_bounded_impl PRIVATE ED25519_BOUNDED_IMPL=1)

add_executable(test-ed25519-bounded tests/test_ed25519_bounded.c $<TARGET_OBJECTS:ed25519_bounded_impl> src/crypto/sha2/sha512.c src/crypto/secure_zero.c src/crypto/ct.c)
target_link_libraries(test-ed25519-bounded PRIVATE ${EXTRA_LIBS})
add_test(NAME test-ed25519-bounded COMMAND test-ed25519-bounded)

add_executable(test-dsf-k2-recovery sim/k2_recovery_model.c tests/test_dsf_k2_recovery.c)
target_include_directories(test-dsf-k2-recovery PRIVATE sim)
target_compile_definitions(test-dsf-k2-recovery PRIVATE DETERM_DSF_ENABLED)
target_link_libraries(test-dsf-k2-recovery PRIVATE determ_core_dsf ${EXTRA_LIBS})
add_test(NAME test-dsf-k2-recovery COMMAND test-dsf-k2-recovery)

if(NOT WIN32)
    # Determ Node Executable
    add_executable(determ-node src/determ_node.c)
    target_link_libraries(determ-node PRIVATE determ_core ${EXTRA_LIBS})

    determ_add_dsf_test(test-execution-env tests/test_execution_env.c)
    determ_add_dsf_test(test-k2-posw tests/test_k2_posw.c)
    determ_add_test(test-k2-net-rpc tests/test_k2_net_rpc.c)
    determ_add_test(test-peer-mesh tests/test_peer_mesh.c)
    determ_add_test(test-block-store tests/test_block_store.c)
    determ_add_test(test-http-rpc tests/test_http_rpc.c)
    determ_add_test(test-ledger-dsso tests/test_ledger_dsso.c)
    determ_add_dsf_test(test-opaque-dsso tests/test_opaque_dsso.c)
    determ_add_dsf_test(test-dsf-k2-duel tests/test_dsf_k2_duel.c)
    determ_add_dsf_test(test-triple-entry-ledger tests/test_triple_entry_ledger.c)
    determ_add_dsf_test(fuzz-ledger tests/fuzz_ledger.c)
    determ_add_test(test-rpc-shard-routing tests/test_rpc_shard_routing.c)
    determ_add_test(test-rpc-pending-transfer tests/test_rpc_pending_transfer.c)

    # Compatibility aliases for legacy targets
    add_custom_target(determ DEPENDS determ-node)
    add_custom_target(determ-wallet DEPENDS determ-node)
    add_custom_target(determ-light DEPENDS determ-node)
    add_custom_target(determ-cryptotest DEPENDS test-ed25519-bounded)
    add_custom_target(determ-dsf DEPENDS test-dsf-k2-duel)
    add_custom_target(d5rp DEPENDS test-k2-duel)
    add_custom_target(determ-dsso DEPENDS test-ledger-dsso)
else()
    # Compatibility aliases for Windows MSBuild
    add_custom_target(determ DEPENDS test-k2-duel)
    add_custom_target(determ-wallet DEPENDS test-k2-duel)
    add_custom_target(determ-light DEPENDS test-k2-duel)
    add_custom_target(determ-cryptotest DEPENDS test-ed25519-bounded)
    add_custom_target(determ-dsf DEPENDS test-k2-duel)
    add_custom_target(d5rp DEPENDS test-k2-duel)
    add_custom_target(determ-dsso DEPENDS test-k2-duel)
endif()
