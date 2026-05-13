// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Unchained Contributors
#pragma once
#include <unchained/types.hpp>
#include <string>

namespace unchained::crypto {

struct NodeKey {
    PubKey                  pub{};        // Ed25519 public key
    std::array<uint8_t, 32> priv_seed{};  // Ed25519 seed
};

NodeKey   generate_node_key();
void      save_node_key(const NodeKey& key, const std::string& path);
NodeKey   load_node_key(const std::string& path);
Signature sign(const NodeKey& key, const uint8_t* data, size_t len);
bool      verify(const PubKey& pub, const uint8_t* data, size_t len, const Signature& sig);

inline Signature sign(const NodeKey& key, const std::vector<uint8_t>& v) {
    return sign(key, v.data(), v.size());
}
inline bool verify(const PubKey& pub, const std::vector<uint8_t>& v, const Signature& sig) {
    return verify(pub, v.data(), v.size(), sig);
}

} // namespace unchained::crypto
