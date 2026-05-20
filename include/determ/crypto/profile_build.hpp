// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// Build-time crypto profile (per docs/proofs/CRYPTO-C99-SPEC.md §2.Q10).
//
// One source of truth for the link-time cryptographic posture. The value
// is driven by CMake `-DDETERM_CRYPTO={modern|fips|universal}` and reaches
// this header through the DETERM_CRYPTO_PROFILE_BUILD compile definition.
//
// A node refuses to start if the genesis bundles a `CryptoProfile` the
// linked binary cannot satisfy — see `check_genesis_compatibility()` below.
// `UNIVERSAL` is permissive (CI / DSF / cross-validation) and breaks the
// FIPS module boundary; production FIPS deployments must use `FIPS`.

#pragma once
#include <cstdint>
#include <string_view>
#include "determ/chain/params.hpp"

#ifndef DETERM_CRYPTO_PROFILE_BUILD
#  error "DETERM_CRYPTO_PROFILE_BUILD undefined — root CMakeLists.txt must set it"
#endif

namespace determ::crypto {

enum class ProfileBuild : uint8_t {
    MODERN    = 0,
    FIPS      = 1,
    UNIVERSAL = 2,
};

inline constexpr ProfileBuild profile_build =
    static_cast<ProfileBuild>(DETERM_CRYPTO_PROFILE_BUILD);

inline constexpr std::string_view to_string(ProfileBuild p) {
    switch (p) {
        case ProfileBuild::MODERN:    return "modern";
        case ProfileBuild::FIPS:      return "fips";
        case ProfileBuild::UNIVERSAL: return "universal";
    }
    return "unknown";
}

// Returns nullptr if the linked binary can run a chain with the given
// genesis crypto profile; otherwise returns a diagnostic string explaining
// the mismatch. Caller emits the message + exits.
inline const char* check_genesis_compatibility(chain::CryptoProfile genesis_cp) {
    if (profile_build == ProfileBuild::UNIVERSAL) return nullptr;
    const bool ok =
        (profile_build == ProfileBuild::MODERN && genesis_cp == chain::CryptoProfile::MODERN) ||
        (profile_build == ProfileBuild::FIPS   && genesis_cp == chain::CryptoProfile::FIPS);
    if (ok) return nullptr;
    if (profile_build == ProfileBuild::MODERN) {
        return "binary built with DETERM_CRYPTO=modern cannot run a FIPS-profile chain; "
               "rebuild with -DDETERM_CRYPTO=fips";
    }
    return "binary built with DETERM_CRYPTO=fips cannot run a MODERN-profile chain; "
           "rebuild with -DDETERM_CRYPTO=modern";
}

} // namespace determ::crypto
