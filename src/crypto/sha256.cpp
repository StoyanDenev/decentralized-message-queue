// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Unchained Contributors
#include <unchained/crypto/sha256.hpp>
#include <openssl/evp.h>
#include <stdexcept>
#include <cstring>

namespace unchained::crypto {

struct SHA256Builder::Impl {
    EVP_MD_CTX* ctx;
};

SHA256Builder::SHA256Builder() : impl_(new Impl{EVP_MD_CTX_new()}) {
    if (!impl_->ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(impl_->ctx, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("EVP_DigestInit_ex failed");
}

SHA256Builder::~SHA256Builder() {
    EVP_MD_CTX_free(impl_->ctx);
    delete impl_;
}

SHA256Builder& SHA256Builder::append(const uint8_t* data, size_t len) {
    EVP_DigestUpdate(impl_->ctx, data, len);
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
    unsigned int len = 32;
    EVP_DigestFinal_ex(impl_->ctx, out.data(), &len);
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

} // namespace unchained::crypto
