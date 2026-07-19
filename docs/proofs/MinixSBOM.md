# Minix Software Bill of Materials (SBOM) — TACTICAL audit manifest

**Status: SHIPPED (factual dependency manifest; ratchet-verified).** The
auditable Bill of Materials for every artifact linked into a Determ build — the
concrete deliverable the minix "TACTICAL" posture ([MinixTacticalProfile.md](MinixTacticalProfile.md)
§3, §7 step 7) is built to satisfy. It is kept factually true by
`tools/test_minix_sbom.sh` (a ratchet that fails if any pinned fact here drifts
from `CMakeLists.txt` / the vendored source), so this is a *verified* manifest,
not prose.

- **SBOM author:** Determ Contributors (generated + maintained in-tree).
- **Timestamp:** 2026-07-19 (this revision).
- **Format:** authoritative content is this table (NTIA minimum elements below);
  a CycloneDX / SPDX-JSON export is a mechanical follow-on, deferred with the
  owner-gated audit-standard decision (`MinixTacticalProfile.md` §8).
- **Scope:** the linked-artifact set of the four shipped binaries — `determ`
  (daemon), `determ-wallet`, `determ-light`, `determ-dsf` — plus the
  test-only `determ-cryptotest` oracle.

## 1. NTIA minimum elements

| Component | Supplier | Version / unique ref | Source | SHA-256 / pin | License | Role | TCB | Minix disposition |
|---|---|---|---|---|---|---|---|---|
| **nlohmann/json** | nlohmann | 3.11.3 (single-include) | VENDORED in-tree: `third_party/nlohmann/json.hpp` | `9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6` | MIT | JSON config / RPC / wire / snapshot serialization | **IN** (linked into `determ`, `determ-wallet`, `determ-light` — NOT `determ-cryptotest`, whose TUs never include `third_party`) | **Phase-1 vendored + byte-ratcheted.** Phase-2 in-tree replacement `determ::djson` is byte-parity-proven vs nlohmann (corpus + real daemon surfaces + differential fuzz — `DetermJsonParitySoundness.md`); the consumer swap is owner-gated. |
| **OpenSSL** | OpenSSL Project | 1.1.1w | FetchContent build via the `janbar/openssl-cmake` wrapper, `GIT_TAG 1.1.1w-20231130` (`CMakeLists.txt`) | pinned by git tag (FetchContent) | OpenSSL License + SSLeay License (dual, permissive BSD-style) | **TEST-ORACLE ONLY** — the `test-*-c99` dual-oracle cross-validation in `determ-cryptotest` | **OUT** — consumed by NO production/daemon binary; only `determ-cryptotest`, gated by `option(DETERM_BUILD_CRYPTOTEST)`. `-DDETERM_BUILD_CRYPTOTEST=OFF` (the tactical build) never even fetches the OpenSSL sources. `determ.exe` contains zero "openssl" strings. | Test-oracle split DONE (`MinixTacticalProfile.md` §6). The daemon/wallet/light link **zero** OpenSSL. |
| **janbar/openssl-cmake** | janbar (build wrapper) | tag `1.1.1w-20231130` | FetchContent: `https://github.com/janbar/openssl-cmake.git` | pinned by git tag | build wrapper (license per its repository) | CMake build scaffolding for the OpenSSL test-oracle | **OUT** — build-time only, under the same `DETERM_BUILD_CRYPTOTEST` gate | Retire alongside OpenSSL once the C99 crypto is the sole oracle. |
| **determ-crypto-c99** | Determ Contributors | in-tree (this repo) | `include/determ/crypto/**`, `src/crypto/**` | tracked in git; per-primitive dual-oracle + KAT (`docs/proofs/`, `tools/vectors/`) | Apache-2.0 (repo `LICENSE` + `NOTICE`; per-file `SPDX-License-Identifier: Apache-2.0` on the `src/crypto` C++ wrapper `.cpp` + the newer C modules — the from-scratch C99 `.c` core is covered by the repo `LICENSE`) | ALL production crypto (hash, Ed25519/X25519/P-256, AEAD, KDF, ML-DSA, entropy) | **IN** (static lib linked into `determ`, `determ-wallet`, `determ-light`, `determ-cryptotest`) | The C99 / from-scratch goal — **done** for the crypto TCB. This is the minix ideal (auditable, in-tree). |
| **ws2_32 / wsock32 / crypt32** | Microsoft (Windows SDK) | OS-native (platform) | Windows system libraries | vendor-audited (OS) | Microsoft SDK terms | Winsock sockets (ws2_32/wsock32) + OS cert/CryptoAPI surface (crypt32) | **Platform** (KEEP) | Platform, vendor-audited — out of the from-scratch TCB by design. |
| **bcrypt** | Microsoft (Windows SDK) | OS-native (platform) | Windows CNG (`BCryptGenRandom`) | vendor-audited (OS) | Microsoft SDK terms | OS entropy source (§3.15 RNG shim) | **Platform** (KEEP) | Linked `PUBLIC` by `determ-crypto-c99` on Windows. |
| **pthread** | system libc / POSIX | OS-native (platform) | System C library | vendor-audited (OS) | system libc terms | POSIX threads (Linux/*BSD/macOS) | **Platform** (KEEP) | Platform, vendor-audited. |

## 2. Dependency relationships (linked-artifact graph)

- `determ` (daemon) → determ-crypto-c99, nlohmann/json (INTERFACE), OS-native
  {ws2_32, wsock32, crypt32 | pthread}. **Zero OpenSSL.**
- `determ-wallet` → determ-crypto-c99, nlohmann/json, OS-native {ws2_32, crypt32
  | pthread}. **Zero OpenSSL.**
- `determ-light` → determ-crypto-c99, nlohmann/json, OS-native {ws2_32, crypt32
  | pthread}. **Zero OpenSSL.**
- `determ-dsf` → single-TU simulator, **no link dependencies** (no OpenSSL, no
  determ core, no nlohmann on the link line beyond std).
- `determ-cryptotest` (TEST-ONLY, gated by `DETERM_BUILD_CRYPTOTEST`) →
  determ-crypto-c99 (the implementation under test), **OpenSSL** (`crypto`, the
  oracle), OS-native {crypt32 | pthread}. **No nlohmann/json** — its TUs include
  only `determ/crypto/*` + `openssl/*` + std, and `third_party` is not on its
  include path. This is the SOLE OpenSSL consumer in the tree.

## 3. TCB boundary (what an auditor signs against)

- **In the trusted computing base (from-scratch, in-tree, auditable):**
  determ-crypto-c99 (all production crypto) + the Determ source itself.
- **In the TCB but VENDORED (single third-party source header):** nlohmann/json
  — byte-pinned by SHA-256, and on a proven path to full replacement by the
  in-tree `determ::djson`.
- **OUT of the production TCB entirely:** OpenSSL + the janbar wrapper —
  test-oracle-only, build-gated OFF for the tactical profile, linked by no
  shipped binary.
- **Platform (vendor-audited, out of the from-scratch TCB by design):** the
  OS-native libraries.

**Consequence (the minix end-state):** with `DETERM_BUILD_CRYPTOTEST=OFF`, the
whole build depends on **zero third-party source libraries** except the single
vendored nlohmann header — only OS-native APIs + the from-scratch C99 crypto.

## 4. How this stays true (provable, not prose)

`tools/test_minix_sbom.sh` (FAST) verifies the load-bearing facts in §1 against
the live tree: the vendored `nlohmann/json.hpp` SHA-256 matches the pin here AND
its embedded MIT + v3.11.3 provenance is present; the OpenSSL `GIT_TAG` here
matches `CMakeLists.txt`; every `FetchContent_Declare` CMake makes is documented
here (no undocumented third-party *source* dependency); the
`DETERM_BUILD_CRYPTOTEST` gate exists **AND** the OpenSSL fetch sits inside it
**AND** exactly one bare `crypto` link token exists tree-wide (the cryptotest
oracle — so no shipped binary links OpenSSL, the §3 OUT-of-TCB claim); the repo
`LICENSE`/`NOTICE` are Apache-2.0 and every `src/crypto` C++ wrapper `.cpp`
carries the per-file SPDX marker; and the `determ-cryptotest` link block pulls no
nlohmann (matching §2). **Scope bound:** the guard covers the FetchContent
*source* set plus the per-binary facts enumerated above — it does not diff the
full `target_link_libraries` graph, so a recorded fact WITHIN that scope that
drifts from the tree turns the ratchet RED, but an entirely new OS-native
`target_link_libraries` entry is out of scope (add its §1 row by hand). The
sibling build-invariant ratchet (`tools/test_minix_dependency_surface.sh`) pins
the same source set from the include side. Cross-references
`MinixTacticalProfile.md` §2/§6/§7.
