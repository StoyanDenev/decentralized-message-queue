# Minix — minimal-dependency tactical profile (design + dependency audit)

**Status:** design + LIVE status doc. Goal set by the owner (2026-07-07):
make a **minimal, fully-auditable dependency footprint the main goal** so a
**"tactical" build profile** can be audited for military/defense use. The
networking track shares the `net::Transport` seam scoped for DSF §Q2.
**Networking backend DECIDED (owner 2026-07-07): native IOCP (Windows) +
epoll/kqueue (POSIX), NO transport library — and as of §4.5e the track's
END-STATE HOLDS: asio is DELETED from the tree; the daemon networks on
native IOCP/epoll only, and the whole third-party source dependency set is
{OpenSSL}, test-oracle-only, skippable via DETERM_BUILD_CRYPTOTEST=OFF.**

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
| ~~asio~~ | **DELETED (§4.5e)** — was `chriskohlhoff/asio` FetchContent | (was) daemon networking | **DONE: replaced by native IOCP (Windows) + epoll reactor (POSIX) behind the net:: seam; the ratchet pins a tree-wide zero-asio-includes check** |
| **nlohmann_json** | **VENDORED in-tree** at `third_party/nlohmann/json.hpp` (v3.11.3 single-include; SHA-256 byte-ratcheted) | JSON for config / RPC / snapshot serialization | **PHASE 1 DONE** (vendor + freeze; FetchContent deleted); **phase-2 inc.1 DONE** (in-tree `determ::djson` module + dual-oracle byte-parity gate, additive/library-only — §5); the consumer swap onto it stays owner-gated |
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

**§Q2 SHIPPED.** The third backend exists: `VirtualEventLoop` /
`VirtualTransport` / `VirtualNetwork` (`include/determ/net/virtual_transport.hpp`
+ `src/net/virtual_transport.cpp` — pure std, zero OS includes, identical TU on
every platform, contract-pinned by `test-net-virtual` and the dependency
ratchet), and `Node` gained the Clock-pattern loop/transport injection ctor
(inject both or neither; defaults construct the platform-native pair —
byte-invariant for every existing caller). The payoff harness is
`test-fa-liveness-virtual`: five real `Node`s reach consensus in one process
over in-memory pipes ([RealEngineFAHarness.md](RealEngineFAHarness.md) §5).
The backend also gained a deterministic **fault model**
(`VirtualNetwork::set_loss`/`partition`/`heal`, whole-frame granular,
byte-invariant default) driving `test-fa-partition-virtual`'s partition +
loss scenarios ([AdversarialTransportHarness.md](AdversarialTransportHarness.md)).
Timers are still wall-clock; a virtual-TIME loop is the backend's next
evolution (deterministic, then adversarial, schedules) — which also unblocks
a reliable loss-liveness gate + the deterministic S-048 reproduction.

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
run(), so to-be-cancelled deadlines must be unreachable). **Slice B SHIPPED
(`2c026ae`) — RpcServer + the dapp_subscribe subscriber socket (the two
synchronous consumers, §4.4 awkward fit (1)) now run through `Connection`
too.** Both are thread-per-connection blocking session models, not
callback-driven, so `Connection` gained a synchronous half alongside slice
A's async half: `write_all(buf,n)->bool`, `read_line(out)->bool`,
`set_send_timeout(ms)` (the interface shape §4.4 had already anticipated —
`set_send_timeout` was listed there before this slice existed). This is a
deliberate scoping choice, not a redesign: awkward fit (1) is resolved with
a sync escape hatch on the EXISTING seam; the full async migration of these
two consumers is deferred to fit (2)/(3)/(5)'s resolution once a native
backend actually lands (a real async rewrite of a thread-per-connection
model is pointless to do twice). `Transport::listen` gained an explicit
`localhost_only` bool with NO default (a virtual function default argument
resolves on the caller's static type, which is unsafe across an abstract
base — every call site, including GossipNet's, now passes it explicitly).
Gate: 5-target build clean, goldens, net-seam contract test, a LIVE
`test_dapp_subscribe` 3-node cluster run (13/13 — catch-up replay, seq
contiguity, backpressure observability, all exercising the FB71 path
through the new Connection), FAST 203/203, GCC-clean header compile, and a
5-lens adversarial review (FB71 liveness, rate-limit-by-IP security,
lifetime/concurrency, byte-behavior parity, build hygiene) that surfaced
zero code findings. **Remaining: the native IOCP/epoll/kqueue backends
(design in §4.5; IOCP increment 1 SHIPPED — §4.5b; CLI sync clients also
already off asio via net::SyncClient), then cut asio** (fit (6)'s Peer
write-queue bound decision rides the Windows daemon cutover; the Asio*
backends are deleted last).

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

**Awkward fits to resolve in the design:** (1) **RESOLVED (slice B,
`2c026ae`)** — the two synchronous consumers (RPC session `read_until`,
subscriber blocking write) got a sync `write_all`/`read_line`/
`set_send_timeout` triple on `Connection`, not an async refactor (deferred
to the native-backend step, §4.5); (2) the
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

### 4.5 Native backend design (pre-implementation — gates the phase 3 build)

A forward-looking design pass (no code yet — this is the gate before writing
`IocpTransport`/`ReactorTransport`) resolved awkward fits (2)-(5) concretely
enough to implement against:

**File layout.** `iocp_event_loop.{hpp,cpp}` + `iocp_transport.{hpp,cpp}`
(Windows); one SHARED `reactor_event_loop.{hpp,cpp}` + `reactor_transport.{hpp,
cpp}` for BOTH POSIX backends, parameterized over a 4-primitive `Reactor`
policy (`detail/epoll_reactor.{hpp,cpp}` / `detail/kqueue_reactor.{hpp,cpp}` —
create-queue-fd, register/modify interest, wait, interpret-event). Everything
else — `recv`/`send`/`connect`/`accept`, the read/write state machine, the
`close()`-synthesizes-abort logic — is byte-identical POSIX and shared; the
`.hpp`/`.cpp` split (unlike today's header-only `asio_*.hpp`) keeps
`<Windows.h>`/`<sys/epoll.h>`/`<sys/event.h>` out of every other TU's
transitive includes. CMake prunes `src/net/{iocp,reactor,detail/*}*.cpp` from
`SOURCES` per-platform via the same `if(WIN32)`/`elseif(APPLE)`/`elseif(UNIX)`
idiom already used elsewhere in `CMakeLists.txt` — only the `determ` daemon
target is affected (wallet/light/cryptotest use explicit file lists, not the
`src/` glob).

**IOCP.** One heap-allocated `IoOperation{OVERLAPPED ov; WSABUF; IoCb cb;
shared_ptr<IocpConnection> pin; total_requested/transferred; base}` per
in-flight op, self-owning until its completion is dequeued. **WSARecv/WSASend
do NOT guarantee N bytes per completion** even under IOCP (a proactor for the
syscall, not for "exactly N") — `async_read`'s exact-N contract needs the
SAME loop-until-N discipline as the POSIX backends, just driven by
completions: advance the `WSABUF` and re-issue on partial transfer, using the
SAME `OVERLAPPED` (safe — the prior call already completed). `AcceptEx`/
`ConnectEx` are extension functions resolved once via `WSAIoctl`
(`SIO_GET_EXTENSION_FUNCTION_POINTER`); both need `SO_UPDATE_ACCEPT_CONTEXT`/
`SO_UPDATE_CONNECT_CONTEXT` before `shutdown`/`getpeername` behave (a
well-documented but easy-to-miss requirement). `AsioAcceptor`'s convenience
ctor sets `SO_REUSEADDR` by default (confirmed against the vendored asio
source) — `IocpAcceptor`/the POSIX reactors must replicate this explicitly or
silently regress restart-after-crash rebind behavior (a gap the golden-vector
gate would NOT catch — only a live restart-timing test would). `close()` uses
`CancelIoEx(handle, NULL)` (NOT the older thread-scoped `CancelIo` — the
cross-thread FB71 contract needs the ALL-pending-ops variant, the same call
asio itself uses for this); critically, `CancelIoEx` only REQUESTS
cancellation — the pending op's `IoOperation` must not be freed until its
(now-aborted) completion is actually dequeued through
`GetQueuedCompletionStatus`, or the kernel can still be writing into freed
memory. `net::EventLoop`'s existing multi-thread `run()` contract is already
phrased in IOCP's image (`event_loop.hpp:21-24`) — this backend needs the
LEAST new invention relative to the shipped interface.

**epoll/kqueue.** A resumable per-connection `ReadOp`/`WriteOp` state machine:
attempt the syscall immediately (data may already be buffered), park on
`EAGAIN` by registering readiness interest, resume from the partial offset on
the next wakeup — the same "loop until N, then complete" shape as IOCP, just
split across possibly-many wakeups. **The multi-thread hazard IOCP does NOT
have:** with `net::EventLoop::run()`'s N-threads-service-one-loop contract, two
threads' `epoll_wait`/`kevent` calls CAN return the same ready fd
simultaneously (documented epoll/kqueue behavior) — without one-shot interest
(`EPOLLONESHOT` / `EV_ONESHOT`), two threads could split ONE logical N-byte
read between them and silently deliver bytes out of order with no error and
the right total count. Since Peer's framing carries consensus-relevant gossip
messages, this is a genuine silent-corruption class, not a crash — recommend
`EPOLLONESHOT`+level-triggered as the starting combo (edge-triggered as a
later perf pass). **`close()` from another thread has no blocked syscall to
interrupt** (the fd is always non-blocking) — the epoll/kqueue analogue of
`CancelIoEx` is "synthesize the pending op's aborted completion right now,"
serialized against a REAL completion by an explicit `op_mu_`/`active`-flag
guard so exactly one of {real completion, close-synthesized abort} ever fires
— new correctness surface IOCP gets for free from the kernel and POSIX must
build by hand.

**Recommended order:** IOCP first (validates the interface on the easier
backend, using existing Windows FAST + both live clusters), then epoll
(exercisable locally via WSL2 + the `ubuntu-latest` CI leg), then kqueue last
(shares most code with epoll, but **there is currently no macOS CI runner or
dev-box access at all** — ship it design-review-only until that's provisioned,
don't silently treat it as equally gated). Only after all three are live +
gated does cutting asio (phased plan step 4) become safe.

### 4.5b Status — IOCP increment 1 SHIPPED (`b1c5056`) + cut-asio CLI clients

`IocpEventLoop` + `IocpTimer` + `IocpTransport` implement the full seam
(Windows-only TUs, CMake-pruned on POSIX; public headers opaque-handle only
per the §4.5 layout rule). **The daemon stays on the Asio* backends** —
increment 1 is the backend + `test-net-native` (22 in-process assertions:
every test-net-seam pin against the native types, PLUS loopback
accept/connect, a 1 MiB async exactly-N round trip, the sync
write_all/read_line carry contract, and BOTH §4.5 abort contracts:
cross-thread `close()` aborts a pending async read via CancelIoEx AND a
blocked sync write). Two DELIBERATE deviations from the §4.5 design, both
empirically driven:

1. **`write_all` is an overlapped WSASend waited on a port-skipping
   (low-bit `hEvent`) event, not a plain blocking send.** Probed on the dev
   box: a thread blocked in raw `send()` is NOT reliably woken by a
   cross-thread `closesocket` — the pre-seam/asio path was silently bounded
   by `SO_SNDTIMEO` alone (production: 5s). With the event design,
   `close()`'s CancelIoEx aborts the in-flight send in ~0ms — §1.6's
   "native makes the stuck-writer release strictly cleaner" prediction,
   realized for the SYNC path too. (Probe also showed loopback AFD absorbs
   exactly one full overlapped send of any size synchronously — the FB71
   contract test loops 4 MiB chunks so the second genuinely pends.)
2. **No ConnectEx** — `async_connect` resolves + candidate-loops a BLOCKING
   connect on a short-lived helper thread (a blocking connect on an
   overlapped-capable socket is mode-independent), matching asio's
   try-every-resolver-result behavior (which ConnectEx-on-first-result
   would have silently dropped) with far less machinery. The helper threads
   are TRACKED and joined by `~IocpTransport` — the enforcement mechanism
   for §4.5's "loop must outlive any in-flight connect" (every consumer
   destroys the transport before the loop; Node's member order guarantees
   it).

Gate: 5-target build, MinGW GCC 13 `-Wall -Wextra -Werror` on all new TUs,
goldens, test-net-native 22/22, FAST 204/204, live `test_weak_3node` +
`test_dapp_subscribe`, ratchet extended (iocp_*/sync_client headers pinned
asio-free). A 41-agent 5-lens adversarial review (op lifetime/UAF, threading
races, Winsock API contracts, CLI parity, seam conformance) confirmed 8
findings — all fixed pre-commit (SIGPIPE parity on POSIX sends, an
acceptor-ctor socket leak, a test-only dangling-promise path, the two items
above, and a destructor-drain grace poll for kernel-propagating aborted
completions).

**The cut-asio CLI migration also SHIPPED in the same commit**: §4.4's
"CLI blocking clients" item is DONE — `net::SyncClient`
(include/determ/net/sync_client.hpp, from the proven light/rpc_client
pattern) replaced asio in `rpc_call`, both gossip-frame fetchers
(`headers --peer`, `snapshot fetch`), and the dapp-subscribe stream reader;
`src/rpc/rpc.cpp` and `src/main.cpp` no longer include asio at all.

### 4.5d Status — the epoll reactor SHIPPED (`593ed56`): the POSIX daemon
### is native too — NO asio type is constructed by the daemon on ANY platform

`ReactorEventLoop`/`ReactorTimer`/`ReactorTransport` implement the seam on
epoll per the §4.5 design (POSIX-only TUs, CMake-pruned on Windows; the
kqueue policy split waits for a BSD/macOS gate): EPOLLONESHOT interest with
registry-pinned dispatch (the close-races-completion serialization built by
hand), resumable park-on-EAGAIN op state machines, the destructor-deferred
::close(fd) that closes the fd-reuse stale-event hazard, poll()-parked sync
half whose FB71 release is a plain cross-thread shutdown() (free on POSIX),
and the tracked-thread candidate-loop connect shared with the IOCP design.
The deadline-timer engine was extracted into a shared `net::TimerService`
(both native loops delegate). `test-net-native` was genericized — the SAME
22-assertion body runs against per-platform aliases and passed FIRST TRY on
the reactor — and `native.hpp`'s POSIX branch flipped: the daemon now
constructs Reactor* on POSIX and Iocp* on Windows. The Asio* backends
survive ONLY as test-net-seam's contract pins until §7 step 4 deletes asio.

**The 27-agent adversarial review earned its cost again: 2 real HIGH bugs
the live clusters missed, both fixed pre-commit.** (1) run() executed
posted closures inline mid-batch — a blocking posted closure (RpcServer
sessions block for the connection's LIFETIME) held that thread's
already-dequeued EPOLLONESHOT events hostage with NO possible re-delivery,
silently freezing a gossip peer caught in the same batch; fixed with
two-pass dispatch (all socket events before the single level-triggered wake
entry). (2) stop() wrote a fixed 64 semaphore units vs Node's
hardware_concurrency() run() threads — a >64-core host would hang at
shutdown; fixed with IocpEventLoop-parity threads_in_run_ tracking. Both
are exactly the class §4.5's risk list predicted for the reactor: correct
per-fd logic, wrong loop-level orchestration — invisible to small fast
clusters, real on big or unlucky deployments.

Gate: Windows (5-target build, 22/22 on IOCP, live cluster, FAST 204/204)
AND Linux/WSL2 GCC 13 (build clean, 22/22 on the reactor, live
test_weak_3node + test_multinode + test_dapp_subscribe on the
REACTOR-NATIVE daemon, ci_local FAST + guards). The ratchet now pins all
reactor_* headers + timer_service.hpp asio-free.

### 4.5c Status — increment 2 SHIPPED (`6cd99de`): the Windows daemon
### runs on native IOCP

The cutover: `include/determ/net/native.hpp` is a per-platform selector —
`NativeEventLoop`/`NativeTimer`/`NativeTransport` alias the `Iocp*` types
on Windows and the `Asio*` types on POSIX (flips when the epoll/kqueue
reactor lands; the asio branch is deleted with §7 step 4). Node declares
its loop/transport/timers by the aliases and constructs them uniformly
(`transport_(loop_)`, `timer_(loop_)` — AsioTimer/AsioTransport gained
loop-taking ctors matching the Iocp shape), so the WINDOWS daemon's entire
networking stack — gossip, RPC accept/session, dapp_subscribe streaming
(FB71 now rides IocpConnection's CancelIoEx event-abort write), and all
three consensus deadline timers — is transport-library-free. `node.hpp`
no longer includes asio; the remaining asio consumers in the tree are
exactly the three `Asio*` backend headers (POSIX daemon + the
test-net-seam contract pins). Member order guarantees destruction safety:
loop_ first-declared/last-destroyed; ~IocpTransport joins in-flight
connect helpers before the loop dies. Gate (all on the IOCP-native
daemon, first try): goldens byte-identical, BOTH live clusters, live
test_dapp_subscribe 13/13, FAST 204/204, GCC-clean selector header,
ratchet green.

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
contract pins (HMAC, config/genesis/hello/snapshot determinism) green.

**PHASE 2 INCREMENT 1 SHIPPED (additive/library-only): the in-tree module
`determ::djson` + its dual-oracle byte-parity gate.**
`include/determ/json/json.hpp` is a header-only, **dependency-free** JSON value
model with a strict recursive-descent parser + a canonical compact serializer
whose `dump()` is designed to match nlohmann's default byte for byte on the
consensus/HMAC subset (sorted-key objects, arrays, bool, null, u64/i64 ints,
ASCII/UTF-8 strings). The load-bearing property is established EMPIRICALLY:
nlohmann is the frozen reference, already linked in the `determ` binary, so
`determ test-determ-json` (`tools/test_determ_json.sh`, FAST) MEASURES parity —
`determ::djson::parse(s).dump() == nlohmann::json::parse(s).dump()` byte for
byte — over a corpus that includes the two byte-critical shapes (the abort
`claims_json` array + RPC `params`), plus round-trip idempotence, key-sort
canonicalization, strict-UTF-8 fail-closed on dump (both impls throw),
parse-rejection AGREEMENT on malformed peer input (both impls reject), and the
peer-facing depth-cap + strict-UTF-8 hardening §5 anticipated. Soundness record
+ non-claims: [DetermJsonParitySoundness.md](DetermJsonParitySoundness.md)
(DJP-1..7). The namespace is `determ::djson` (not `determ::json`) because the
tree's pervasive `using json = nlohmann::json;` + `using namespace determ;`
would otherwise make the bare name `json` ambiguous. Increment 1 changes NO
production serialization path (goldens byte-identical; dependency ratchet green
— the module includes no nlohmann; only the in-binary test does, as the oracle).

**PHASE 2 INCREMENT 2 SHIPPED (additive/test-only): real-surface parity.**
`determ test-determ-json-surfaces` (`tools/test_determ_json_surfaces.sh`) proves
determ::djson byte-reproduces the daemon's ACTUAL serialization — for each real
object it emits (Transaction, Block incl. an abort-carrying block, AbortEvent +
claim, EquivocationEvent, GenesisAlloc, `Chain::serialize_state` snapshot, RPC
params, gossip envelope) it asserts `determ::djson::parse(obj.to_json().dump())
.dump() == obj.to_json().dump()`. This is the parse+dump byte-parity on real
shapes the swap needs (the build+dump path is covered by inc.1's builder
assertion); node `Config` doubles stay the one out-of-scope surface
(DetermJsonParitySoundness NC-1/NC-3). Additive — no consumer swapped.

**PHASE 2 REMAINING (owner-gated): the CONSUMER SWAP.** Swapping the two
byte-critical sites (and the wider nlohmann surface) onto `determ::djson` behind
an API-compatible shim — 1.5-3 KLOC of consensus-adjacent code, gated by
widening the dual-oracle dump-equality corpus to HELLO + `Block::to_json` + full
snapshots + the existing pin tests, AND a mixed-fleet cluster test (one node per
implementation) exercising abort events. Increment 1 built + proved the module
the swap needs; the swap itself stays owner-gated. **The inc.1 adversarial
review surfaced a hard SWAP-BLOCKER (DetermJsonParitySoundness.md NC-1): a
double IS adversarially reachable on the abort-event digest (`claims_json` is
stored VERBATIM from peer JSON with unknown members kept; the per-claim sig
covers only typed scalars), so the swap must FIRST close double dump-parity —
either a shortest-round-trip `dump_double` matching nlohmann byte for byte, or
re-canonicalizing `claims_json` from typed `AbortClaimMsg` fields before hashing
(which also hardens the pre-existing weakness that the abort digest binds
attacker-injectable non-semantic bytes even today under nlohmann). The gate
WITNESSES the current double gap so it cannot be forgotten.** **The abort-site
fork vector is now CLOSED (`AbortDigestCanonicalizationSoundness.md`):
`hash_abort_event` canonicalizes the claims (strips unknown members) before
hashing, so no attacker double reaches that serializer — the swap-blocker
narrows to a swap *robustness* item (RPC-HMAC double divergence fails auth
CLOSED, not a fork).**

## 6. OpenSSL track — test-oracle split (SHIPPED `217191a`)

Executed exactly as designed (byte-invariant, zero coverage lost): all 11
moved outputs diffed BYTE-IDENTICAL against pre-split baselines; both in-place
C99 swaps PASS; the operator battery routes per-command (25/25 — was 26/26
until the register-B2 FROST purge removed test-frost-c99, 2026-07-09); the ratchet
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
   `net::Transport` SHIPPED in two slices: **slice A (`b1c9228`)** — the
   gossip path (Peer/GossipNet) — and **slice B (`2c026ae`)** — RpcServer +
   the dapp_subscribe subscriber, via a synchronous escape-hatch on
   `Connection` (§4.3b, §4.4 fit (1)). Gate: native cluster tests + goldens
   unchanged, both slices.
3. **Native backends behind the seam — DONE on both gated platforms:**
   IOCP SHIPPED (`b1c5056` §4.5b + the `6cd99de` cutover §4.5c) and the
   epoll reactor SHIPPED with its POSIX cutover in one increment
   (`593ed56`, §4.5d) — the daemon constructs ZERO asio types on any
   platform, gated by both live clusters + goldens + FAST on each
   platform's native binary. Remaining in this step: kqueue only
   (design-review-only until a BSD/macOS gate exists — §4.5).
4. **Cut asio — DONE (`a1348f3`, §4.5e)**: the FetchContent dep, the three
   `Asio*` backend headers, and `test-net-seam` (superseded by
   `test-net-native`'s identical pins on the REAL backends) are deleted;
   the ratchet pins FetchContent=={openssl} + a tree-wide
   zero-asio-includes check. (The CLI-blocking-clients slice had already
   shipped in `b1c5056` via `net::SyncClient`.) Gate: both platforms
   reconfigured + rebuilt from scratch, full battery green on each.
4b. **Virtual backend + Node injection — DONE** (`e79c94a` seam,
   `d073ff3` backend, `0dfdd39` harness; §4.1 "§Q2 SHIPPED"): EventLoop
   grew interface-level `timer_schedule`/`timer_cancel` (the two identical
   per-backend timers collapsed into one `net::LoopTimer` over the abstract
   loop); `Node` takes an optional loop+transport pair (Clock pattern,
   byte-invariant defaults); the pure-std `VirtualTransport` backend +
   `test-net-virtual` contract battery; and `test-fa-liveness-virtual` —
   3 real Nodes reaching byte-identical consensus in one process, which
   also caught + fixed the latent `run()`/`stop()` double-join race
   (`Node::join_loop_threads()`).
5. **JSON track** (§5 — **phase 1 SHIPPED** `23ac341`: vendored + byte-ratcheted;
   **phase-2 inc.1 SHIPPED**: the in-tree `determ::djson` module + dual-oracle
   byte-parity gate, additive/library-only; the consumer swap stays owner-gated).
   6. **OpenSSL split** (§6 — **SHIPPED**
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
- **The epoll/kqueue `close()`-races-a-real-completion hazard has NO IOCP
  analogue** (§4.5): IOCP gets exactly-once completion delivery from the
  kernel for free even under `CancelIoEx`; the POSIX reactors must build that
  guarantee by hand (an `op_mu_`/active-flag serialization) or risk a missed
  completion (hang) or a double-fired one (use-after-free) — this asymmetry
  means the two POSIX backends carry correctness surface the Windows backend
  structurally cannot have, and deserves its own stress test (rapid
  connect/close churn) before either is trusted, not just the shared
  golden-vector/cluster gate.
- **kqueue has zero CI coverage today** (`.github/workflows/ci.yml` runs only
  `ubuntu-latest`/`windows-latest`, no `macos-latest`) — ship kqueue as
  design-review-only until a macOS runner exists; don't silently gate it as
  equally validated as the other two.
- JSON reader must be **schema-exact** and reproduce snapshot byte-format.
- **Reproducible-build determinism** must hold across the new toolchain/deps.
- This is **consensus-adjacent + owner-gated**; each increment ships behind the
  golden-vector + FAST + native-cluster gates, byte-invariant where it touches the
  digest/state surface.
