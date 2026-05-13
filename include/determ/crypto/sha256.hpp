// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/types.hpp>
#include <chrono>

namespace determ::crypto {

class SHA256Builder {
public:
    SHA256Builder();
    ~SHA256Builder();
    SHA256Builder(const SHA256Builder&) = delete;
    SHA256Builder& operator=(const SHA256Builder&) = delete;

    SHA256Builder& append(const uint8_t* data, size_t len);
    SHA256Builder& append(const Hash& h)       { return append(h.data(), 32); }
    SHA256Builder& append(uint8_t b)           { return append(&b, 1); }
    SHA256Builder& append(uint64_t v);
    SHA256Builder& append(int64_t v);
    SHA256Builder& append(const std::string& s) {
        return append(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
    Hash finalize();

private:
    struct Impl;
    Impl* impl_;
};

Hash sha256(const uint8_t* data, size_t len);
Hash sha256(const Hash& a, const Hash& b);
Hash sha256(const Hash& a, const std::string& s);

inline Hash sha256(const std::vector<uint8_t>& v) { return sha256(v.data(), v.size()); }
inline Hash sha256(const Hash& h)                  { return sha256(h.data(), 32); }

} // namespace determ::crypto
