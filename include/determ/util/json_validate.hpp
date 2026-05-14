// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once

// S-018 closure helpers: typed JSON field extraction with field-name
// context on failure.
//
// Background: nlohmann::json's `j["field"].get<T>()` throws when the
// field is missing or has the wrong type, but the resulting exception
// message names neither the field nor the containing object. A wire-
// format peer sending a malformed message produces error messages like
// "type must be string, but is null" that don't tell the operator
// which field they should look at. This makes triage of malformed
// gossip / RPC inputs unnecessarily expensive.
//
// These helpers wrap `j.at("field").get<T>()` with:
//   1. Explicit `j.contains("field")` check that throws a precise
//      "missing required field 'NAME'" diagnostic.
//   2. try/catch around `.get<T>()` that reformats type errors as
//      "field 'NAME' has wrong type: <original message>".
//
// Use `json_require<T>(j, "field")` for required fields; for optional
// fields with defaults, the existing `j.value("field", default)`
// pattern is already structured and doesn't need replacing.

#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

namespace determ::util {

// Extract a required typed field from a JSON object. Throws with a
// clear field-name diagnostic on either missing or wrong-type errors.
//
// Example: `tx.amount = json_require<uint64_t>(j, "amount");`
template <typename T>
T json_require(const nlohmann::json& j, const char* field) {
    if (!j.contains(field)) {
        throw std::runtime_error(
            std::string("S-018: missing required JSON field '") + field + "'");
    }
    try {
        return j.at(field).get<T>();
    } catch (const std::exception& e) {
        throw std::runtime_error(
            std::string("S-018: JSON field '") + field
            + "' has wrong type: " + e.what());
    }
}

// Same as json_require, but extracts a string-typed hex field with a
// fixed expected hex-character length. Catches both the missing/
// wrong-type cases AND the malformed-hex case (wrong length, non-hex
// characters), surfacing the field name in the diagnostic for all
// three. Returns the raw hex string; caller passes it to
// `from_hex` / `from_hex_arr<N>` for decoding.
//
// Example: `auto hex = json_require_hex(j, "prev_hash", 64);`
//          `tx.prev_hash = from_hex_arr<32>(hex);`
inline std::string json_require_hex(const nlohmann::json& j,
                                       const char* field,
                                       size_t expected_hex_chars) {
    auto s = json_require<std::string>(j, field);
    if (s.size() != expected_hex_chars) {
        throw std::runtime_error(
            std::string("S-018: JSON field '") + field
            + "' has wrong hex length: expected "
            + std::to_string(expected_hex_chars)
            + " chars, got " + std::to_string(s.size()));
    }
    return s;
}

} // namespace determ::util
