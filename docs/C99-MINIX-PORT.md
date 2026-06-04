# Determ — C99 / Minix Reference-Implementation Plan

**Status:** design target (planning). **Goal:** a portable **C99** implementation of
Determ whose build + test is **sufficient on Minix 3** — i.e. no C++, no heavy
external dependencies, only ISO C99 + POSIX/BSD sockets + vendored crypto, built
with a plain `Makefile`.

**Sequencing (decided 2026-06):** Ubuntu/Linux (WSL2) is the working build + CI
environment for all development from here on. The C99 reimplementation lands against
the frozen spec on Ubuntu first; **Minix bring-up + validation is deferred to after
v3** — Minix is the eventual portability *proof*, not a day-one build constraint. The
code is written to the C99 / no-heavy-deps discipline throughout (so Minix stays
reachable), but "builds + tests on Minix" is verified as a post-v3 milestone, not
gating earlier work.

This is a **clean-room reimplementation guided by the existing spec**, *not* a port
of the C++17 tree. The current implementation (`src/`, `wallet/`, `light/`) stays as
the **reference oracle**: the C99 build is validated byte-for-byte against it at every
phase. When the two diverge on any canonical byte string, the C99 build is wrong.

---

## 1. Why C99 + Minix

- **Minimal, auditable TCB.** No C++ runtime, no STL, no exceptions/templates; the
  entire program is readable C99 a single auditor can hold in their head. For a
  security-critical payment + identity L1 this is a feature, not an aesthetic.
- **Microkernel host.** Minix 3's isolation model (drivers/servers in user space,
  tiny trusted kernel) complements a chain whose own security argument is about
  minimizing trust.
- **Portability as a forcing function.** "Builds on Minix with `cc -std=c99`" is a
  hard constraint that bans every platform-specific shortcut. What builds on Minix
  builds everywhere (Linux, BSD, macOS) — and trivially, with one `Makefile`. It also
  eliminates the Windows/MSBuild/file-lock pain this project hit (see the daemon-reaper
  episode): C99 + `make` has none of it.

## 2. Target environment (Minix 3)

- **Compiler:** clang/LLVM (Minix 3 system compiler) and/or `pkgsrc` gcc. Build with
  `-std=c99 -pedantic -Wall -Wextra`.
- **Userland:** NetBSD-derived libc + tools; `make`; BSD sockets; `select()`/`poll()`;
  `/dev/urandom`.
- **ABI:** assume **ILP32** (32-bit) as the floor — `size_t`/pointers are 32-bit. Use
  `<stdint.h>` fixed-width types (`uint64_t` is fine); never assume 64-bit pointers.
- **Endianness:** i386 is little-endian, but **all** wire/hash serialization is already
  explicit-endian in the spec (`u64_be`, `u64_le`), so byte output is endianness-
  independent by construction. Keep it that way — no raw struct memcpy onto the wire.
- **Disallowed:** C++; GNU/Clang extensions unless `#if`-guarded with a portable
  fallback; `__int128` (not ISO C99 — use paired `uint64_t`); threads where avoidable
  (prefer a single-threaded reactor; Minix pthreads exist but are best avoided in the
  TCB path).

## 3. Dependency-elimination budget

| Today (C++17) | C99 / Minix-sufficient replacement |
|---|---|
| `std::map` / `std::set` / `std::vector` / `std::string` | small C container kit (§5): dynamic byte buffer, sorted-key array map, hash set, growable vector |
| OpenSSL + libsodium | **vendored C99 crypto**: SHA-256 (FIPS 180-4 ref), SHA-512 + Ed25519 (TweetNaCl-class, ~700 LoC, public-domain, RFC 8032-interoperable), HMAC-SHA256 (RFC 2104) |
| `nlohmann::json` | the **binary codec** (already shipped) is the canonical wire; JSON only for human/config I/O via a tiny tokenizer (jsmn-class) — or a hand CLI printer. The C99 node speaks binary, not JSON, on the wire. |
| asio | BSD sockets + a single-threaded `select()`/`poll()` reactor |
| CMake / MSBuild | a plain POSIX `Makefile` (per-OS socket shim behind one `#if`) |
| `std::thread` async workers (chain.save, gossip) | synchronous in the reactor, or `fork()` for the snapshot write; no shared-memory threading in the TCB |
| `__int128` supply math | paired `uint64_t` (hi,lo) with checked add — already the pattern (`checked_add_u64`) |
| CSPRNG (libsodium) | `open("/dev/urandom")` read; single small wrapper |

**Wallet crypto is the high-risk sub-budget** (Argon2id, Shamir, OPAQUE/OPRF). Argon2
and Shamir-over-GF(256) have clean portable-C references; **OPAQUE/OPRF is the hardest
piece** and is the natural candidate to defer or gate as an optional module. The core
node + payment path needs only SHA-256 / Ed25519 / HMAC, which are all small and
standardized.

> **Likely seed:** the off-limits `src/crypto/universal/` subtree is, by its name, the
> portable-C crypto path — it should be the starting point for the vendored primitives
> rather than starting from scratch.

## 4. The parity harness (the load-bearing risk reducer)

The spec is fully byte-specified (`PROTOCOL.md` §4.1 `signing_bytes`, §4.3
`block_digest`, §4.1.1 the 10 state-root namespaces, the binary codec, §11 snapshot).
That makes clean-room C99 tractable **and** gives a free oracle:

- Add a `--emit <fixture>` mode to BOTH the C++ reference and the C99 build that prints
  the canonical bytes (hex) for: `tx` wire, `block_digest`, `signing_bytes`,
  `compute_state_root`, a serialized snapshot, committee selection, HMAC/SHA/Ed25519
  vectors.
- A `diff` of the two outputs over a shared fixture corpus **must be empty**. This is
  the gate for every phase below — the C99 build is "correct" exactly when its bytes
  match the C++ reference (which is itself locked to `PROTOCOL.md` + the proofs).
- Seed the corpus from the existing `determ test-*` fixtures and RFC test vectors
  (SHA-256/HMAC/Ed25519 known-answer tests).

This converts a risky rewrite into an incremental, continuously-verified one.

## 5. C container kit (write once, in C99)

The bulk of the porting labor is replacing STL. A deliberately tiny kit covers it:

- `buf_t` — growable byte buffer (the wire/hash workhorse; append u8/u32be/u64be/bytes).
- `vec_t` — growable pointer/struct array.
- `map_t` — sorted-key (`bytes → bytes`) map with deterministic iteration (this is what
  the state-root namespaces need; iteration order **is** consensus-relevant, so sorted).
- `set_t` — membership set (cross-shard receipt dedup `i:`).
- `hex` + `slice` helpers; `arena`/explicit-free discipline (no GC, no RAII — every
  alloc has one owner and one free site).

Determinism note: `map_t` MUST iterate in sorted-key order to match the C++ `std::map`
that `build_state_leaves` relies on — this is a correctness requirement, not a style
choice.

## 6. Module map (C++ unit → C99 module)

| C99 module | Replaces | Difficulty |
|---|---|---|
| `c99/crypto/` | OpenSSL/libsodium use in `src/crypto/` | low (standardized, vendored) |
| `c99/codec/` | binary codec + `to_json`/`from_json` wire paths | low–med (byte-exact, parity-gated) |
| `c99/types/` | `Transaction`, `Block`, messages, `GenesisConfig` | med (structs + encode/decode) |
| `c99/chain/` | `Chain` apply, `build_state_leaves`, `compute_state_root`, snapshot | **high** (the stateful core) |
| `c99/consensus/` | committee selection, producer digest, validator gates, fork choice | **high** |
| `c99/net/` | asio gossip + RPC → sockets + `select()` reactor | med–high |
| `c99/cli/` | `main.cpp` dispatch, wallet, light | med |

"Pure" modules (crypto, codec, hashing, state-root) are easy and parity-checkable in
isolation; the "stateful" core (chain apply, consensus) is where the effort concentrates.

## 7. Phased sequencing (each phase gated on byte-parity vs the C++ reference)

- **Phase 0 — scaffolding.** `Makefile`, the §5 container kit, hex/buffer utils,
  `/dev/urandom` CSPRNG, and the §4 parity-harness skeleton (`--emit` on both sides).
- **Phase 1 — crypto + hashing.** SHA-256, SHA-512, Ed25519, HMAC-SHA256.
  *Gate:* RFC known-answer vectors **and** byte-match the C++ reference's `test-sha256`
  / `test-ed25519` / HMAC outputs.
- **Phase 2 — types + binary codec.** Encode/decode `Transaction`/`Block`/messages.
  *Gate:* wire bytes byte-identical to the C++ binary codec on the fixture corpus
  (round-trip + cross-impl).
- **Phase 3 — chain state machine.** Apply rules, the 10 state-root namespaces,
  `compute_state_root`, `serialize_state`/`restore_from_snapshot`.
  *Gate:* `state_root` + snapshot bytes identical to the C++ reference over a scripted
  block sequence (reuse the `test-snapshot-*` / `test-state-root-*` fixtures).
- **Phase 4 — consensus.** Committee selection (Fisher-Yates), producer
  `block_digest` + `signing_bytes` population, validator gates, `resolve_fork`.
  *Gate:* digests, selection sets, and signatures match the reference.
- **Phase 5 — net + CLI.** BSD-socket gossip + RPC reactor, daemon loop, then
  wallet/light CLIs. *Gate:* a C99 node and a C++ node interoperate on one chain;
  integration tests pass on **both Linux and Minix**.

## 8. Hard parts & honest risks

- **Ed25519 constant-time.** TweetNaCl is compact + portable but not the fastest; verify
  side-channel posture is acceptable for the signing path, or use a vetted ref10-class
  impl. Interop is guaranteed (RFC 8032 is deterministic), so this is a quality, not a
  correctness, decision.
- **Wallet recovery crypto (OPAQUE/OPRF).** The single hardest dependency to render in
  minimal C99; recommend gating it as an optional module and shipping the node + payment
  + light path first.
- **Minix performance/RAM.** Minix 3 is not a performance target; expect slower builds
  and runtime. The design must stay single-threaded-reactor and modest in memory.
- **Spec must be frozen per targeted feature set.** Parity needs a fixed target — the
  C99 reimplementation tracks a **frozen** subset of `PROTOCOL.md`; v2 features
  (threshold randomness, DSSO, etc.) get their own later C99 phases, not a moving target.
- **Size.** The C++ tree is tens of kLoC; this is a multi-month reimplementation, not a
  sprint. The parity harness is what keeps it from being a multi-month *gamble*.

## 9. Scope of the "final C99 version"

In: the C99 node (consensus + apply + state-root + binary wire + sockets), `determ-light`
core (header/committee/state-proof verify, trustless reads), and the offline wallet
signing path. Deferred/optional: OPAQUE-based wallet recovery, and all v2 roadmap
features until each gets its own parity-gated C99 phase.

## 10. Cross-references

- `docs/PROTOCOL.md` — the byte-level wire / digest / state-root spec the C99 build is
  validated against (the single source of truth for the parity harness).
- `docs/proofs/` — the invariants (FA / FA-Apply / S-0xx) the C99 build must preserve;
  each proof's cited `file:line` moves from `src/` to `c99/` as phases land.
- `src/crypto/universal/` — likely portable-C crypto seed (§3).
- the shipped binary codec (`test-binary-codec`, `test-tx-binary-codec`) — the canonical
  C99 wire format (§3, Phase 2).
- `tools/reap_daemons.sh` — on Minix/Linux the daemon-reaper uses `pkill -x`; the whole
  Windows file-lock failure class does not exist there.
