# Minix — minimal-dependency tactical profile (design + dependency audit)

**Status:** design / scoping doc (FUTURE-tier). Goal set by the owner (2026-07-07):
make a **minimal, fully-auditable dependency footprint the main goal** so a
**"tactical" build profile** can be audited for military/defense use. NO code yet —
this is the survey+design artifact that gates implementation, in the same
survey→design→byte-invariant-increments discipline as
[ClockInjectionSeam.md](ClockInjectionSeam.md). The networking track shares the
`net::Transport` seam scoped for DSF §Q2. **Networking backend DECIDED (owner
2026-07-07): native IOCP (Windows) + epoll/kqueue (POSIX), NO transport library
(no libevent2, no asio) — §4.3.**

## 1. Goal

"Minix" = minimize and fully vet the external dependency footprint of the Determ
daemon so a **TACTICAL** profile build can pass a military/defense audit: known
provenance + SBOM for every linked artifact, minimal unvetted third-party code
(prefer from-scratch / vetted C), reproducible builds, a documented TCB boundary,
and **preserved consensus determinism** (byte-identical digests + state roots
across every swap).

**Minix is UNCONDITIONAL long-term architecture, NOT a build switch (owner
2026-07-07).** The dependency minimization is the actual code path for *every*
build — there is no `#ifdef MINIX`, no runtime profile flag, one binary with one
set of code paths. It is the long-term direction of the C99 / from-scratch ethos,
extended from the crypto TCB (already done — `determ-crypto-c99`) to the whole
external-dependency surface. The "TACTICAL profile" is a posture / audit LABEL
(a documented dependency + TCB boundary + SBOM an auditor signs against), exactly
as CryptoProfile (MODERN / FIPS) is a posture label and not a code switch (one
binary, all algorithms). Nothing in this track is gated on a profile.

## 2. External dependency inventory (verified against CMakeLists.txt)

The ENTIRE third-party **source** dependency set is exactly three FetchContent'd
libraries. Everything else is in-tree from-scratch or OS-native.

| Dependency | Provenance | Role | Minix disposition |
|---|---|---|---|
| **asio** 1.30.2 | `chriskohlhoff/asio` ([CMakeLists.txt:38](../../CMakeLists.txt)) | Daemon networking — P2P gossip + JSON-RPC server; header-only C++ templates | **REPLACE → native async I/O: IOCP (Windows) + epoll/kqueue (POSIX), no transport library** |
| **nlohmann_json** | FetchContent `json` ([CMakeLists.txt:47](../../CMakeLists.txt)) | JSON for config / RPC / snapshot serialization; single-header C++ | **REPLACE** (in-tree reader) or **vet + freeze** |
| **OpenSSL** 1.1.1w | `janbar/openssl-cmake` ([CMakeLists.txt:29](../../CMakeLists.txt)) | **Test-oracle only** — `test-*-c99` cross-validation in main.cpp; linked to the daemon only because main.cpp is one TU | **SPLIT** the oracle into a separate test binary → daemon links zero OpenSSL |
| `determ-crypto-c99` | in-tree, from scratch ([CMakeLists.txt:92](../../CMakeLists.txt)) | ALL production crypto (hash, Ed25519, AEAD, KDF, entropy) | **KEEP** — already the minix ideal (the C99 goal, done) |
| ws2_32 / wsock32 / crypt32 / bcrypt (Win), pthread (Unix) | OS-native | Sockets, OS entropy, threads | **KEEP** — platform, vendor-audited |

**Consequence:** removing/swapping the three FetchContent libs leaves the daemon
depending on **zero third-party source libraries** — only OS-native APIs + the
from-scratch C99 crypto. That is the minix end-state.

## 3. What "military-auditable" implies (the tactical profile)

- **Provenance + SBOM** for every linked artifact (git tag, hash, license).
- **Minimal unvetted code** in the TCB; prefer from-scratch/vetted C over large
  C++ template libraries.
- **Reproducible, deterministic builds** — already partially held by the
  cross-toolchain golden-vector gate + scoped UBSan gate (`tools/ci_local.sh`).
- **A documented audit boundary** — exactly which source is in the TCB.
- **Preserved consensus determinism** — byte-identical digests + state roots, gated
  by `test-consensus-vectors` + FAST + the native cluster tests.

## 4. Networking track — asio → native async I/O (IOCP + epoll/kqueue)

### 4.1 The `net::Transport` seam (shared with DSF §Q2)

Introduce a `net::Transport` interface; `AsioTransport` (today) → native
`IocpTransport` (Windows) + `EpollKqueueTransport` (POSIX) behind the same
interface, with **no third-party transport library**. This keeps the swap
contained to one seam and is the SAME abstraction scoped for §Q2's
`VirtualTransport` (deterministic testing) — one seam serves both minix and DSF
testability.

### 4.2 Determinism safety (the key de-risker)

Networking is **not digest-bound**: the apply / state-commitment path
(`chain.cpp`) is clock- and network-free, and only `proposer_time` +
the ±30s freshness gate touch wall time (see
[ClockInjectionSeam.md](ClockInjectionSeam.md) §1). Therefore **swapping the
transport cannot fork the chain** as long as message *semantics* (wire bytes,
ordering guarantees, the S-043 proposer-time gossip recompute) are preserved. This
makes the swap a large-but-contained I/O change, not a consensus-logic rewrite.

### 4.3 Backend decision — DECIDED (owner 2026-07-07): zero networking library

**No libevent2, and no transport library of any kind.** The transport is native
async I/O per platform behind the `net::Transport` seam:

- **Windows:** IOCP (I/O Completion Ports) — the native proactor/completion model.
- **Linux:** epoll (edge- or level-triggered readiness).
- **macOS / *BSD:** kqueue.

Rationale: maximum auditability — **zero third-party transport dependency**: no C++
template library (asio) and no third-party C library (libevent2, whose Windows/IOCP
backend is also its least battle-tested part, and which would add its own CVE
surface + a C↔C++ FFI boundary). The cost is more native per-platform code (three
backends) to write and audit; `determ-light` already proves raw sockets are viable
in this tree.

**Proactor/reactor note (design-critical).** IOCP is a **proactor** (you post a
read and receive a completion carrying the data); epoll/kqueue are **reactors**
(you receive a readiness signal, then perform the read yourself). The
`net::Transport` interface must therefore expose a **proactor-style completion
API** (`async_read` / `async_write` with completion callbacks) that maps directly
to IOCP and is emulated over epoll/kqueue (readiness → perform the syscall → invoke
the callback) — the same internal shape asio uses. Designing the seam
proactor-first avoids a rewrite when the IOCP backend lands.

## 5. JSON track — nlohmann_json → in-tree

JSON is used for config, RPC, and snapshot serialization. **Confirm before
swapping** whether any of these feed a consensus commitment: the block digest is
over the **binary** codec (not JSON), and the state root is over binary state
leaves — but snapshot round-trip byte-determinism is separately tested
(`test-snapshot-*`), so the replacement reader must reproduce the exact snapshot
byte-format. Options: a hand-rolled minimal reader (parses only the fixed
config/RPC/snapshot schemas) vs. vet + freeze the single-header nlohmann_json (it
is already a single vendored header — a lighter audit than asio/OpenSSL).

## 6. OpenSSL track — test-oracle split

Move the `test-*-c99` oracle subcommands out of `main.cpp` into a dedicated test
binary (e.g. `determ-cryptotest`) that links OpenSSL. The daemon then links **zero
OpenSSL** while retaining the independent cross-check (valuable — it is how the C99
crypto is known correct). This is the cleanest OpenSSL removal and loses nothing.

## 7. Phased plan

1. **Design (this doc)** — owner-review + scope decision.
2. **The `net::` seam, byte-invariant, asio still underneath** — introduce the
   interfaces slice by slice. **STARTED: the `net::Timer` slice SHIPPED
   (`be24c3e`)** — `include/determ/net/timer.hpp` (asio-free interface) +
   `AsioTimer` backend; Node's contrib/block-sig/grace deadline timers now go
   through it. Validated byte-invariant: goldens reproduce, FAST 197/0, and a
   live 5-node/K=3 cluster (`test_weak_3node`) reaches height 11 in ~3s with head
   agreement + committee rotation (liveness intact), both new headers GCC-13
   clean. Remaining slices behind the same pattern: `net::EventLoop`
   (io_context: run/stop/post), then `net::Transport` (acceptor + sockets +
   resolver). Gate for each: native cluster tests + goldens unchanged.
3. **Native backends behind the seam** — `IocpTransport` (Windows) +
   `EpollKqueueTransport` (POSIX), no third-party library; validate cluster
   liveness + goldens byte-identical + the S-043 wire-roundtrip-verify per message
   type.
4. **Cut asio** — remove the FetchContent dep; daemon networks on native IOCP +
   epoll/kqueue only.
5. **JSON track** (§5). 6. **OpenSSL split** (§6). 7. **Tactical profile** — the
   posture label + SBOM + audit-boundary doc + reproducible-build attestation.

## 8. Open owner decisions

- **Scope:** networking-only / all-3-libs / all-3 + a formal TACTICAL profile.
- ~~Networking backend~~ — **DECIDED (2026-07-07): native IOCP + epoll/kqueue, no
  transport library** (§4.3).
- **JSON:** hand-rolled reader vs. vet + freeze nlohmann_json.
- **Audit standard:** what does "military audit" target concretely (FIPS-adjacent,
  Common Criteria EAL, a bespoke procurement checklist)? — drives the rigor bar.

## 9. Risks

- The networking rewrite touches the **S-043 gossip / proposer-time** path — every
  signer/verifier commitment needs a wire-roundtrip-verify test per message type at
  ship time (the S-043 lesson).
- **Three native backends** (IOCP + epoll + kqueue) to write + audit, behind one
  proactor-style seam — correct handling of proactor (IOCP completion) vs reactor
  (epoll edge/level-trigger, kqueue) semantics.
- Native async **buffer-lifetime / threading** care (IOCP overlapped buffers must
  outlive the completion; edge-triggered epoll must drain the socket fully).
- JSON reader must be **schema-exact** and reproduce snapshot byte-format.
- **Reproducible-build determinism** must hold across the new toolchain/deps.
- This is **consensus-adjacent + owner-gated**; each increment ships behind the
  golden-vector + FAST + native-cluster gates, byte-invariant where it touches the
  digest/state surface.
