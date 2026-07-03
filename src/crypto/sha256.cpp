// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// §3.15 backend swap (2026-07-03): SHA256Builder runs on the in-tree C99
// FIPS 180-4 engine (src/crypto/sha2/sha256.c) instead of OpenSSL EVP.
// SHA-256 is a fixed function — same input bytes, same digest — and the C99
// engine is validated byte-equal against OpenSSL (CAVP KATs + the §Q9
// cross-validation gate in `determ test-sha2-c99`), so every consensus
// artifact (block hash, tx root, merkle/state root, genesis hash) is
// byte-identical across backends; the pinned goldens in
// `determ test-consensus-vectors` prove it at test time. The big-endian
// integer encodings in append(uint64_t/int64_t) below are the
// consensus-critical part of THIS file and are unchanged.
#include <determ/crypto/sha256.hpp>
#include <determ/crypto/sha2/sha2.h>
#include <cstring>

namespace determ::crypto {

struct SHA256Builder::Impl {
    determ_sha256_ctx ctx;
};

SHA256Builder::SHA256Builder() : impl_(new Impl) {
    determ_sha256_init(&impl_->ctx);
}

SHA256Builder::~SHA256Builder() {
    delete impl_;
}

SHA256Builder& SHA256Builder::append(const uint8_t* data, size_t len) {
    determ_sha256_update(&impl_->ctx, data, len);
    return *this;
}

SHA256Builder& SHA256Builder::append(uint64_t v) {
    uint8_t buf[8];
    for (int i = 7; i >= 0; --i) { buf[i] = v & 0xFF; v >>= 8; }
    return append(buf, 8);
}

SHA256Builder& SHA256Builder::append(int64_t v) {
    return append(static_cast<uint64_t>(v));
}

Hash SHA256Builder::finalize() {
    Hash out{};
    determ_sha256_final(&impl_->ctx, out.data());   // zeroizes the ctx
    return out;
}

Hash sha256(const uint8_t* data, size_t len) {
    return SHA256Builder{}.append(data, len).finalize();
}

Hash sha256(const Hash& a, const Hash& b) {
    return SHA256Builder{}.append(a).append(b).finalize();
}

Hash sha256(const Hash& a, const std::string& s) {
    return SHA256Builder{}.append(a).append(s).finalize();
}

} // namespace determ::crypto
