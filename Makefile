# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Determ Contributors
#
# Monolithic Makefile for Determ Zero-Dependency C99 Architecture.
# Strict C99 compilation with zero third-party dynamic libraries.

CC ?= cc
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic -O3 -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -DNDEBUG
INCLUDES = -Iinclude -Isrc -Itests

# Operating System specific libraries (Windows: -lws2_32, Linux: -lrt -lpthread)
LDLIBS ?=
ifeq ($(OS),Windows_NT)
    LDLIBS += -lws2_32
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        LDLIBS += -lrt -lpthread
    endif
endif

BUILD_DIR = build
BIN_DIR = bin

# Core C99 Cryptography Sources
CRYPTO_SRCS = 	src/crypto/secure_zero.c 	src/crypto/ct.c 	src/crypto/aes/aes_core.c 	src/crypto/sha2/sha256.c 	src/crypto/sha2/sha512.c 	src/crypto/sha2/hmac.c 	src/crypto/sha2/hkdf.c 	src/crypto/sha2/pbkdf2.c 	src/crypto/chacha20/chacha20.c 	src/crypto/chacha20/poly1305.c 	src/crypto/chacha20/chacha20_poly1305.c 	src/crypto/chacha20/xchacha20_poly1305.c 	src/crypto/ed25519/ed25519.c 	src/crypto/x25519/x25519.c 	src/crypto/p256/p256.c 	src/crypto/opaque_dsso.c 	src/crypto/rng/rng.c

# Core Consensus, Wire, Storage & Networking C99 Sources
CONSENSUS_SRCS = 	src/time/clock.c 	src/net/virtual_transport.c 	src/consensus/duel_state.c 	src/consensus/dda.c 	src/crypto/vdf.c 	src/net/event_loop.c 	src/net/k2_net.c 	src/net/peer_mesh.c 	src/net/reactor.c 	src/wire/parser.c 	src/wire/json_token.c 	src/wire/binary_codec.c 	src/rpc/json_rpc.c 	src/rpc/http_rpc_server.c 	src/storage/block_store.c 	src/ledger/state.c

ALL_CORE_SRCS = $(CRYPTO_SRCS) $(CONSENSUS_SRCS)
ALL_CORE_OBJS = $(ALL_CORE_SRCS:%.c=$(BUILD_DIR)/%.o)

NODE_BIN = $(BIN_DIR)/determ-node
TEST_DUEL_BIN = $(BIN_DIR)/test-k2-duel
TEST_NET_RPC_BIN = $(BIN_DIR)/test-k2-net-rpc
TEST_BINARY_CODEC_BIN = $(BIN_DIR)/test-binary-codec
TEST_PEER_MESH_BIN = $(BIN_DIR)/test-peer-mesh
TEST_BLOCK_STORE_BIN = $(BIN_DIR)/test-block-store
TEST_DDA_BIN = $(BIN_DIR)/test-dda
TEST_HTTP_RPC_BIN = $(BIN_DIR)/test-http-rpc
TEST_LEDGER_DSSO_BIN = $(BIN_DIR)/test-ledger-dsso
TEST_FUZZ_LEDGER_BIN = $(BIN_DIR)/fuzz-ledger

CFLAGS_DSF = $(CFLAGS) -DDETERM_DSF_ENABLED
BUILD_DIR_DSF = $(BUILD_DIR)/dsf
ALL_CORE_DSF_OBJS = $(ALL_CORE_SRCS:%.c=$(BUILD_DIR_DSF)/%.o)
TEST_DSF_K2_DUEL_BIN = $(BIN_DIR)/test-dsf-k2-duel

.PHONY: all clean test check

all: $(NODE_BIN) $(TEST_DUEL_BIN) $(TEST_DSF_K2_DUEL_BIN) $(TEST_NET_RPC_BIN) $(TEST_BINARY_CODEC_BIN) $(TEST_PEER_MESH_BIN) $(TEST_BLOCK_STORE_BIN) $(TEST_DDA_BIN) $(TEST_HTTP_RPC_BIN) $(TEST_LEDGER_DSSO_BIN) $(TEST_FUZZ_LEDGER_BIN)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(NODE_BIN): $(ALL_CORE_OBJS) $(BUILD_DIR)/src/determ_node.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(TEST_DUEL_BIN): $(ALL_CORE_OBJS) $(BUILD_DIR)/tests/test_k2_duel.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(TEST_NET_RPC_BIN): $(ALL_CORE_OBJS) $(BUILD_DIR)/tests/test_k2_net_rpc.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(TEST_BINARY_CODEC_BIN): $(ALL_CORE_OBJS) $(BUILD_DIR)/tests/test_binary_codec.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(TEST_PEER_MESH_BIN): $(ALL_CORE_OBJS) $(BUILD_DIR)/tests/test_peer_mesh.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(TEST_BLOCK_STORE_BIN): $(ALL_CORE_OBJS) $(BUILD_DIR)/tests/test_block_store.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(TEST_DDA_BIN): $(ALL_CORE_OBJS) $(BUILD_DIR)/tests/test_dda.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(TEST_HTTP_RPC_BIN): $(ALL_CORE_OBJS) $(BUILD_DIR)/tests/test_http_rpc.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(TEST_LEDGER_DSSO_BIN): $(ALL_CORE_OBJS) $(BUILD_DIR)/tests/test_ledger_dsso.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(TEST_FUZZ_LEDGER_BIN): $(ALL_CORE_DSF_OBJS) $(BUILD_DIR_DSF)/tests/fuzz_ledger.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS_DSF) $^ -o $@ $(LDLIBS)

$(BUILD_DIR_DSF)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_DSF) $(INCLUDES) -c $< -o $@

$(TEST_DSF_K2_DUEL_BIN): $(ALL_CORE_DSF_OBJS) $(BUILD_DIR_DSF)/tests/test_dsf_k2_duel.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS_DSF) $^ -o $@ $(LDLIBS)

test: all
	@echo "Running test-k2-duel..."
	@./$(TEST_DUEL_BIN)
	@echo "Running test-k2-net-rpc..."
	@./$(TEST_NET_RPC_BIN)
	@echo "Running test-binary-codec..."
	@./$(TEST_BINARY_CODEC_BIN)
	@echo "Running test-peer-mesh..."
	@./$(TEST_PEER_MESH_BIN)
	@echo "Running test-block-store..."
	@./$(TEST_BLOCK_STORE_BIN)
	@echo "Running test-dda..."
	@./$(TEST_DDA_BIN)
	@echo "Running test-http-rpc..."
	@./$(TEST_HTTP_RPC_BIN)
	@echo "Running test-ledger-dsso..."
	@./$(TEST_LEDGER_DSSO_BIN)
	@echo "Running fuzz-ledger..."
	@./$(TEST_FUZZ_LEDGER_BIN)
	@echo "Running test-dsf-k2-duel..."
	@./$(TEST_DSF_K2_DUEL_BIN)

check: test

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
