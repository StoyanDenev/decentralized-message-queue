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
| **nlohmann_json** | **VENDORED in-tree** at `third_party/nlohmann/json.hpp` (v3.11.3 single-include; SHA-256 byte-ratcheted) | JSON for config / RPC / snapshot serialization | **PHASE 1 DONE** (vendor + freeze; FetchContent deleted); phase-2 in-tree `determ::json` stays owner-gated (§5) |
| **OpenSSL** 1.1.1w | `janbar/openssl-cmake` FetchContent — now wrapped in `option(DETERM_BUILD_CRYPTOTEST)` | **Test-oracle only** — the §Q9 dual-oracle handlers live in the separate `determ-cryptotest` binary | **SPLIT DONE (§6)** — the daemon links ZERO OpenSSL (zero openssl strings in determ.exe); a tactical build with `OFF` never even fetches OpenSSL |
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

### 4.3b Status — slices SHIPPED

`net::Timer` (`be24c3e`), `net::EventLoop` (`16ae94c`), and **`net::Transport`
slice A (`b1c9228`) — the GOSSIP path (Peer + GossipNet) now runs entirely
through the asio-free proactor Transport interface** (`transport.hpp`:
Connection with EXPLICIT exactly-N/whole-span/no-overlap completion contracts,
Acceptor, Transport; `asio_transport.hpp` backend; `peer.hpp`/`gossip.hpp` no
longer include asio). Gate: 3-target build + goldens + BOTH live clusters
(`test_weak_3node` head agreement; `test_multinode` height 330+, no fork) +
FAST + GCC-clean interface header + the ratchet (transport.hpp pinned
asio-free). A draft→verified **`test-net-seam` contract test** pins the
Timer/EventLoop semantics in-process (the verify stage caught a real Windows
flake: asio's waitable-timer thread queues SUCCESS completions independently of
run(), so to-be-cancelled deadlines must be unreachable). **Slice B remaining:
RpcServer + the dapp_subscribe subscriber socket (the synchronous consumers —
§4.4 awkward fits 1-2), then the native IOCP/epoll/kqueue backends, then cut
asio** (including the CLI sync clients).

### 4.4 Transport surface survey (completed — the remaining raw-asio consumers)

A full read of `src/net/peer.cpp`, `src/net/gossip.cpp`, `src/rpc/rpc.cpp`, and
the subscriber path in `src/node/node.cpp` established the surface a
`net::Transport` must cover:

**Consumers + patterns.**
- **Peer** (gossip framing): 4-byte big-endian length prefix baked into
  `Message::serialize`/`serialize_binary` (`messages.cpp:17-23/63-70`,
  `kMaxFrameBytes` 16 MB); exactly ONE `async_read` outstanding (header →
  body → dispatch → loop) and ONE `async_write` pump over a `write_mutex_`-guarded
  unbounded `write_queue_`; every handler captures `shared_from_this()`;
  `set_option(keep_alive)` (S-026); dual size caps (framing ceiling at
  `peer.cpp:64` + per-type `max_message_bytes` at `peer.cpp:90`, S-022).
- **`async_connect` free fn** (`peer.cpp:151-167`): resolver → connect →
  wrap-in-Peer, shared_ptrs pinned across the async gap.
- **GossipNet**: perpetual `async_accept` loop (move-in-socket overload),
  `peers_mutex_` guarding the peer set; **nested lock order
  `peers_mutex_ → write_mutex_`** (broadcast sends while holding `peers_mutex_`).
- **RpcServer**: `async_accept` (separate-socket overload) + `asio::post` of a
  **fully synchronous blocking session** (`read_until('\n')` / `write`) — a
  newline-delimited protocol, NOT the gossip framing; each session occupies a
  loop thread for its lifetime (assumes a thread POOL).
- **dapp_subscribe**: the RPC session hands its socket to the node
  (`node.cpp:3305`); a dedicated per-subscriber thread does synchronous
  `asio::write` with `SO_SNDTIMEO` via `native_handle()` (`node.cpp:3326-3337`);
  the kill-on-overflow hook (SS-3) **closes the socket from another thread to
  break an in-flight blocking write** — a load-bearing liveness mechanism (FB71).
- **CLI blocking clients** (`rpc.cpp:306-351`, `main.cpp` headers/snapshot/raw
  clients): private io_contexts, fully synchronous — portable to a trivial
  sync-socket helper independently, but on the "cut asio" checklist.

**Interface shape (agreed direction):** `Connection` (async_read exactly-N /
async_write whole-span with `(ec, n)` completions, `close()` idempotent +
callable cross-thread, `remote_endpoint()` noexcept, `set_keep_alive`,
`set_send_timeout`) + `Acceptor` (`async_accept → shared_ptr<Connection>`) +
`Transport` (`listen(port, localhost_only)`, `async_connect(host, port, cb)`).
Framing stays entirely in Peer — Transport is byte-stream only.

**Awkward fits to resolve in the design:** (1) the two synchronous consumers
(RPC session `read_until`, subscriber blocking write) need either a sync
`read_some/write_all` pair on the seam or an async refactor; (2) the
cross-thread `close()`-breaks-blocking-write contract must hold on native
backends (IOCP: `CancelIoEx`/`closesocket`; POSIX: fd shutdown while blocked in
`send`); (3) native backends must reproduce asio's "same-operation completions
never overlap" guarantee (Peer's single-outstanding-read safety depends on it —
currently an UNDOCUMENTED invariant, must become an explicit `Connection`
contract); (4) IOCP overlapped buffers must outlive completions (pin in the
`Connection` or mirror the `shared_ptr` capture); (5) the POSIX
readiness→completion emulation must loop until exactly-N bytes transfer
(edge-triggered epoll must fully drain) or Peer's fixed-length framing breaks
silently; (6) Peer's write queue is UNBOUNDED (unlike the subscriber's
kill-on-overflow) — a bounded-queue decision belongs to the rewrite.

## 5. JSON track — nlohmann_json → in-tree (SURVEYED)

A full usage survey (~975 references, 60+ files, all three binaries) settled
the confirm-before-swapping question. **TWO sites require byte-exact canonical
JSON serialization across implementations:**

1. **CONSENSUS DIGEST — `hash_abort_event()` SHA-256s `claims_json.dump()`**
   ([producer.cpp:350](../../src/node/producer.cpp)), and that hash feeds
   `compute_block_digest` via the abort view root (producer.cpp:667-672) — i.e.
   the K-of-K-signed block digest of any abort-carrying block depends on
   nlohmann's canonical dump bytes (sorted keys, compact separators). The light
   client MIRRORS the same dump-hash ([verify.cpp:84](../../light/verify.cpp)).
   A one-byte writer divergence forks consensus on abort-carrying chains.
2. **RPC HMAC** over `method+"|"+params.dump()` computed independently by the
   server ([rpc.cpp:51-56](../../src/rpc/rpc.cpp)) and by wallet/light clients —
   a mixed-implementation fleet must dump byte-identically (pinned by
   `test-rpc-auth-hmac`, which explicitly guards an ordered_json/bump swap).

Everything else is schema-only: the state root is over BINARY domain-prefixed
leaves (not JSON bytes) and `restore_from_snapshot` re-verifies it against the
committee-signed header; config/genesis/RPC shapes/snapshots need fidelity, not
cross-implementation byte-equality. The wire is JSON-heavy (wire v0 pure JSON;
the v1 "binary" envelope wraps `payload.dump()` for every type except
TRANSACTION; HELLO always JSON). **The used subset is narrow:** bool, u8-u64
ints, ASCII/hex strings, arrays, sorted-key objects; doubles appear ONLY in
node Config (never on a wire/digest path); zero
ordered_json/json_pointer/CBOR/msgpack/SAX usage; nlohmann's throw-on-invalid-
UTF-8 dump behavior is load-bearing (fail-closed on binary leaf keys).

**Two-phase plan:** **PHASE 1 SHIPPED (`23ac341`):** the single header is
vendored at `third_party/nlohmann/json.hpp` (v3.11.3), the FetchContent is
deleted (the fetch set is down to {asio, openssl-when-cryptotest}), and the
dependency ratchet byte-pins the vendored header by SHA-256 — the minix
whole-source-in-repo/offline-build bar, zero consumer changes, all JSON
contract pins (HMAC, config/genesis/hello/snapshot determinism) green. PHASE 2
(owner-gated, ~1-2 weeks): in-tree `determ::json` behind an API-compatible
shim — FEASIBLE given the narrow subset, but 1.5-3 KLOC of consensus-adjacent
code gated by dual-oracle dump-equality over a corpus that MUST include
claims_json abort arrays + HELLO + Block::to_json + RPC params + snapshots,
the existing pin tests, AND a mixed-fleet cluster test (one node per
implementation) exercising abort events; the parser needs a depth cap +
strict UTF-8 (it is the outermost consumer of every peer-supplied byte).

## 6. OpenSSL track — test-oracle split (SHIPPED `217191a`)

Executed exactly as designed (byte-invariant, zero coverage lost): all 11
moved outputs diffed BYTE-IDENTICAL against pre-split baselines; both in-place
C99 swaps PASS; the operator battery routes per-command (26/26); the ratchet
is a ZERO-exception pin; FAST 203/0, goldens, and a live cluster all green —
and `determ.exe` contains zero "openssl" strings. The design as implemented:
a new top-level `cryptotest/main.cpp` (mirroring `wallet/`, `light/`) with a
small dispatcher plus the **11 pure-oracle handlers moved VERBATIM** (stdout
byte-identical so wrapper summary-pins stay green): `test-{aes,ed25519,frost,
x25519,p256,p256-h2c,sha3,blake2b,xchacha,chacha20,sha2}-c99`, together with
their help lines and the openssl includes (the vestigial `rand.h` include drops
entirely). The **2 mixed handlers stay in determ and are de-OpenSSL'd in
place**: `test-rpc-auth-hmac` swaps its local OpenSSL HMAC lambda to
`determ_hmac_sha256` (a truer mirror of the production rpc.cpp path; the
HMAC-vs-OpenSSL cross-check lives on in the moved `test-sha2-c99`), and
`test-ed25519-vectors` derives the pubkey via `determ_ed25519_pubkey_from_seed`
checked against the embedded RFC 8032 constant (the RFC hex stays the
independent anchor). CMake: `determ-cryptotest` links determ-crypto-c99 +
crypto + nlohmann (no asio); `determ` drops `crypto` from its link list and the
openssl include dir; the OpenSSL FetchContent + the new target wrap in
`option(DETERM_BUILD_CRYPTOTEST ... ON)` so a tactical/SBOM build with `OFF`
never even fetches OpenSSL sources. Wrappers: a `DETERM_CRYPTOTEST` block in
tools/common.sh (cloned from the DETERM_LIGHT pattern); 11 wrappers flip
`$DETERM` → `$DETERM_CRYPTOTEST`; ci_local.sh + operator_crypto_selftest.sh
route PER-COMMAND (its battery mixes moving and staying subcommands). The
dependency-surface ratchet check 3 then tightens to a ZERO-exception pin
(no openssl includes anywhere in src/). Risks: the R59 all-targets-build
lesson applies directly (4 binaries after the split); moved handlers' stdout
must stay byte-identical (the stale-summary-pin lesson); the two in-place
edits are behavior-relevant, mitigated by the already-validated C99 calls.
The daemon then links **zero OpenSSL** while retaining the independent
cross-check (how the C99 crypto is known correct).

## 7. Phased plan

1. **Design (this doc)** — owner-review + scope decision.
2. **The `net::` seam, byte-invariant, asio still underneath** — introduce the
   interfaces slice by slice. **STARTED: the `net::Timer` slice SHIPPED
   (`be24c3e`)** — `include/determ/net/timer.hpp` (asio-free interface) +
   `AsioTimer` backend; Node's contrib/block-sig/grace deadline timers now go
   through it. Validated byte-invariant: goldens reproduce, FAST 197/0, and a
   live 5-node/K=3 cluster (`test_weak_3node`) reaches height 11 in ~3s with head
   agreement + committee rotation (liveness intact), both new headers GCC-13
   clean. **The `net::EventLoop` slice ALSO SHIPPED (`16ae94c`)** —
   `event_loop.hpp` (asio-free: `run()` with a multi-thread contract, `stop()`,
   `post(fn)`) + `AsioEventLoop` owning the io_context with a TRANSITIONAL
   `raw()` accessor for not-yet-abstracted consumers (GossipNet, AsioTimer,
   RpcServer); Node's worker threads, stop, and the recursion-breaker post go
   through it, and the member reorder fixed destruction order (gossip_'s
   acceptor/sockets now destruct before the loop). Same full gate green
   (goldens + live cluster + FAST + GCC-clean headers). A **dependency-surface
   ratchet guard** (`tools/test_minix_dependency_surface.sh`, FAST) pins the
   FetchContent set to exactly {asio, json, openssl}, keeps the seam interface
   headers asio-free, and keeps OpenSSL confined to the test oracle.
   Remaining slice behind the same pattern: `net::Transport` (acceptor +
   sockets + resolver — surface surveyed in §4.4). Gate: native cluster tests +
   goldens unchanged.
3. **Native backends behind the seam** — `IocpTransport` (Windows) +
   `EpollKqueueTransport` (POSIX), no third-party library; validate cluster
   liveness + goldens byte-identical + the S-043 wire-roundtrip-verify per message
   type.
4. **Cut asio** — remove the FetchContent dep; daemon networks on native IOCP +
   epoll/kqueue only.
5. **JSON track** (§5 — **phase 1 SHIPPED** `23ac341`: vendored + byte-ratcheted;
   phase-2 determ::json owner-gated). 6. **OpenSSL split** (§6 — **SHIPPED**
   `217191a`: the daemon links ZERO OpenSSL; determ-cryptotest is the sole
   OpenSSL consumer, skippable via DETERM_BUILD_CRYPTOTEST=OFF).
   7. **Tactical profile** — the
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
