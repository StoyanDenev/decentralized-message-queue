# A2 Phase 6: liboprf vendoring — Windows MSVC porting notes

## Status

**Integration scaffolding in place; actual build blocked on MSVC VLA support.** Gated behind `-DDETERM_VENDOR_OPRF=ON` in `CMakeLists.txt`. Default build is clean; the wallet ships with the Phase 5 stub adapter.

## What works

- `FetchContent_Declare(oprf …)` populates the source tree from `github.com/stef/liboprf` master.
- `wallet/oprf_shim/arpa/inet.h` portability stub resolves `#include <arpa/inet.h>` to `winsock2.h` on Windows (Unix path uses `#include_next` to fall through to the system header).
- CMake target `oprf` declares the right source files (oprf.c + utils.c), links libsodium + ws2_32, suppresses `_CRT_SECURE_NO_WARNINGS` for liboprf's `strncpy`/`fopen` usage.

## What blocks

**C99 Variable-Length Arrays (VLAs).** MSVC `cl.exe` does not support them. liboprf uses VLAs in both source and header files; the header VLAs cascade into compile errors at every consumer translation unit.

Confirmed VLA sites (line numbers from upstream master at vendoring time):

### `src/oprf.h`
None (header doesn't declare VLAs in function signatures).

### `src/oprf.c`
- Line 170: `uint8_t dst_prime[len + sizeof "HashToGroup-"VOPRF"-"]` — depends on runtime `len`.
- Line 186: `uint8_t msg_prime[len + sizeof "EvalNoBlind-"VOPRF"-"]` — depends on runtime `len`.

### `src/toprf.h`
- Line 48: `void toprf_keygen(const uint8_t t, const uint8_t n, uint8_t shares[n][TOPRF_Share_BYTES])` — `n` is parameter, not compile-time constant.
- Line 66: similar `[k]` parameter.
- Line 81: similar.
- Line 104: `uint8_t responses[TOPRF_Share_BYTES][n]`.
- Line 123, 150, 168, 202–203: more `[n]` / `[k]` parameter arrays.

### `src/toprf.c`
- Pervasive — every threshold-protocol function uses VLAs for the `[n][...]` matrices.
- Lines 171, 177, 181, etc.: `responses[n]`, `indexed_indexes[T]`, `indexes[T]`.

## Phase 6 completion paths

### Path A: patch upstream sources via in-tree fork
Replace each VLA with `_alloca` on Windows + `alloca` on Unix, wrapped in a portable macro:

```c
#ifdef _WIN32
  #include <malloc.h>
  #define DET_STACK_ALLOC(type, name, n) type *name = (type*)_alloca((n) * sizeof(type))
#else
  #include <alloca.h>
  #define DET_STACK_ALLOC(type, name, n) type *name = (type*)alloca((n) * sizeof(type))
#endif
```

Header declarations need conversion from `T name[n][m]` to `T* name`. Each call-site needs adjustment to the new pointer type. Estimate: 1–2 days of careful porting + retesting against the upstream's existing test vectors.

### Path B: fork liboprf into the repo
Hard fork the relevant subset (oprf.c + utils.c + toprf.c headers) into `wallet/liboprf-fork/` with VLA patches applied. Pin to a known-good upstream revision. Upside: no FetchContent runtime dependency, easier to MSVC-fix in-tree. Downside: divergence from upstream over time, manual sync work.

### Path C: link a different OPAQUE library
Re-evaluate the binary-language decision. `opaque-ke` (Rust, by Meta, audited by NCC Group) builds cleanly on Windows MSVC via cargo. Cost: wallet binary becomes Rust or wraps Rust crates via C-FFI. Significant architectural change — undermines this session's C-only direction.

### Path D: accept Unix-only OPAQUE build
Keep the integration scaffolding; document that real-OPAQUE recovery is Unix-only in v1.x. Windows users continue using the Phase 5 stub or the Phase 3 passphrase scheme. The wallet's `is_stub()` flag already gates production use.

## Recommendation

Path A or B in a future cycle dedicated to MSVC porting. Path D is acceptable as a stopgap given Windows is not the primary determ deployment platform (Linux servers are).

## Repro

```bash
# Default build — clean:
cmake -B build && cmake --build build --config Release

# Attempt liboprf vendoring on Windows MSVC — fails on VLAs:
cmake -B build -DDETERM_VENDOR_OPRF=ON
cmake --build build --config Release --target oprf
# Expect: ~50+ C2057 / C2466 / C2133 errors at oprf.h, toprf.h, oprf.c

# Attempt liboprf vendoring on Unix (untested in this commit but
# expected to work given upstream's autotools build runs on Linux):
cmake -B build -DDETERM_VENDOR_OPRF=ON
cmake --build build --config Release --target oprf
# Expect: clean build, oprf.a static library produced
```
