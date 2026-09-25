> **TIER: NEAR-TERM — accepted engineering constraints; whole-target assurance remains open.** Roadmap index: [ROADMAP.md](../ROADMAP.md).

# ADR 006: C99 Memory Ownership, Lifetime and Bounds

**Date:** 2026-09-25
**Status:** ACCEPTED for the constraints below. Scoped fixes and their evidence are
recorded separately; this is not a declaration of structural immunity or a qualified
unikernel. [Decision Log](../proofs/DECISION-LOG.md) remains authoritative.

## 1. Audit baseline and scope

The public GitHub `main` branch was pinned to
[`6a131af3a96fa20e81d54e3d7057ac28bd1345c7`](https://github.com/StoyanDenev/decentralized-message-queue/commit/6a131af3a96fa20e81d54e3d7057ac28bd1345c7).
The GitHub API returned that SHA; a direct `main` event-loop download matched it.
All 123 `.c`/`.h` files under `src/`, `include/` and `sim/` matched the downloaded
public snapshot. The archive SHA-256 was
`191a90c1374b38183b94f53cc7d7e6805a224b38157a9d861c4adabb73dc0096`.
This pins provenance, not assurance coverage. C++ implementations were excluded
from this audit and patch scope.

Review concentrated on network/event lifetimes, wire and RPC parsing, state and
consensus array bounds, crypto allocation arithmetic and failure propagation,
and deployment claims. Allocation searches cover the C99 inventory; they are not
a formal proof of every function or call chain. The C99 service is currently a
hosted POSIX/libc experiment. A statically linked executable is not automatically
freestanding, and no reviewed boot/device/interrupt implementation exists here.

The requested Linux CVEs motivate checking vulnerability classes, not a finding
that Determ contains those Linux bugs. CISA's official KEV record added
CVE-2024-1086 on 2024-05-30 with a 2024-06-20 remediation deadline (binding on
federal civilian agencies under BOD 22-01); that record does not support the
prompt's claim of a new emergency directive. The
[official catalog](https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json)
and the [NVD record for CVE-2024-0582](https://nvd.nist.gov/vuln/detail/CVE-2024-0582)
(an io_uring use-after-free that is not KEV-listed) describe Linux-specific
issues, not an immunity standard for C99.

## 2. Findings and reachability

These findings refer to the pinned baseline. The implementation and validation
record below identifies which defenses are present in this working tree.

| ID | Concrete baseline defect or blocker | Reachability and limit |
|---|---|---|
| M1 | `wire_tx_encode` adds `4 + pq_auth_len` in the u32 expression domain; `wire_dhf1_record_encode` similarly adds `40 + block_frame_len`. `UINT32_MAX` can make a small capacity pass before a huge copy, even on a 64-bit host. Other variable-size encoders add `size_t` lengths before checking. The record iterators' existing `off >= total_len` pre-checks already excluded the wrap for a real buffer; they are restated with the same helper. | Unsafe codec API boundaries. Current pending transfers fix `pq_auth_len` to zero and the live mesh bounds envelopes; a remote memory-corruption path through the stock daemon was not demonstrated. |
| M2 | `peer_mesh` calls user callbacks before compacting its receive buffer. A callback that disconnects/reconnects the same static slot resets its cursor; the old handler can subtract its old frame size from the new cursor and pass an underflowed size to `memmove`. Reactor and mesh events carry reusable pointers/indices without incarnation identity. | Reproducible through the callback interfaces. Stock node callbacks only log; no claim that an unauthenticated packet alone triggers callback replacement in the stock daemon. Static allocation did not prevent this temporal-aliasing defect. |
| M3 | `reactor_send` checks `tx_len + len` after a potentially wrapping addition; reactor close invokes a callback before retiring its slot. K2 cleanup wipes negative descriptor sentinels back to zero. | API-level oversized send, callback reentry and repeated-close defects. A second close can close descriptor zero or a reused resource. No production consensus change is involved. |
| M4 | JSON numeric conversion wraps; `get_block` uses `strtoull` beyond token bounds and can accept a token outside its params object. Some RPC branches return `snprintf`'s required length rather than bytes written. HTTP NULL-config initialization leaves descriptors uninitialized. | The direct RPC API accepts a byte span without a trailing NUL. The HTTP buffer supplies a NUL, limiting physical over-read there, but does not make token-boundary parsing correct. Small-output API callers and failed-init cleanup expose the other defects. |
| M5 | HKDF/PBKDF2 and the separate OPAQUE-3DH schedule ignore fallible HMAC returns and may consume uninitialized or stale output as key/MAC material. PBKDF2's ceil can wrap on 32-bit and its maximum block loop can wrap. | Ordinary allocation-failure paths, plus boundary arithmetic. Output on any reported failure must not be used as a key. No change to the successful algorithms or transcript formats is required. |
| M6 | Argon2's block-count multiplication can wrap a 32-bit allocation; P-256 concatenation sizes and Pedersen balance counts lack complete overflow preflight. | For Argon2, `m_cost=4194304` KiB can wrap a 32-bit byte count to zero before block writes. Other extreme-length cases are API-boundary defects; remote input of those sizes was not demonstrated. |
| M7 | Mesh/reactor/HTTP socket writes lack the K2 driver's per-socket/per-call SIGPIPE defense; HTTP ignores nonblocking-setup failure. | SIGPIPE is a process-termination protection gap, not memory corruption. Remote timing through the stock HTTP path was not established. Publishing a blocking socket after setup failure violates the event-loop contract. |
| M8 | Eight crypto C files and `src/dapp/d5draw.c` use heap allocation; hosted network/storage/RPC use libc/POSIX. P-256 lazily initializes writable global constants; large crypto/ledger stack objects need an actual stack budget. | Target-admission blockers. Single-owner current execution does not demonstrate a concurrent race; parallel shards, callbacks, interrupts and DMA need explicit ownership/synchronization. These blockers are not removed by fixing M1–M7. |

The eight heap-using crypto files are `argon2/argon2id.c`, `ed25519/ed25519.c`,
`p256/p256.c`, `pedersen/balance.c`, `sha2/hmac.c`, `sha2/hkdf.c`, `sha2/pbkdf2.c`
and `chacha20/chacha20_poly1305.c`, all beneath `src/crypto/`. Ed25519 uses its
bounded stack path for the current short C99 transfer preimage, but retains a
heap fallback for larger messages. Network peers, reactor slots, HTTP clients,
consensus state and pending-ledger entries already use bounded storage; there is
no dynamically allocated peer object to replace with another arena.

## 3. Accepted constraints

1. **Target allocation and ownership.** No heap allocation in the freestanding
   image. Each fixed pool has a capacity, one owner, lifetime states and explicit
   exhaustion behavior. Reuse ends the old logical lifetime even when its C object
   remains allocated. A stale pointer or descriptor is not made valid by clearing
   the storage. Hosted/reference allocation remains outside target qualification;
   remove it by reviewed caller-owned workspaces or streaming primitives, not by
   silently truncating inputs or introducing hidden global scratch races.
2. **Captured incarnation identity.** A readiness event carries the registration's
   immutable integer cookie, combining a bounded slot index with a monotonically
   increasing generation. Compare it with the current slot before dispatch and
   again after any callback that can retire/reuse the slot. Do not read a generation
   from a mutable slot and label it as the event's original identity. Refuse
   generation exhaustion rather than wrapping. Retire state before close callbacks.
3. **Bounds before access.** Given a real input object of extent `n`, establish
   `off <= n` and `need <= n - off` before forming `base + off`, copying, or advancing.
   For products use `count <= SIZE_MAX / element_size` before multiplication. Cast
   wire integers into the intended arithmetic domain before adding constants.
   An unsigned `sum = a + b; if (sum < a)` check can detect one addition's wrap,
   but it does not validate capacity, the source object or an earlier narrower
   addition. Remaining-capacity checks prove representability before the addition.
4. **Publication and errors.** Reject framing/preflight errors before publishing
   output. Check each fallible crypto and platform operation. An API that can leave
   partial output on internal failure must document that output as unusable.
   Outside callbacks, failed initialization of a supplied lifecycle object
   establishes closed descriptor sentinels before returning; callback-rejected
   reactor/mesh initialization leaves storage unchanged. Close is idempotent
   after initialization under the object's ownership contract.
5. **Concurrency and platform boundary.** These adapters are single-owner and
   non-recursively polled; callers do not directly modify internal lifecycle/cursor
   fields. The nested-dispatch guards are module-wide flags, one for all reactors
   and one for all meshes, so one thread owns every instance in the process: a
   second thread polling another mesh would race on the flag, which is outside
   the contract, not merely unsynchronized. Borrowed receive views do not survive callbacks or slot
   reuse. C99 supplies neither thread atomics nor DMA coherency; `volatile` and
   `memset` do not provide either. The future platform must supply reviewed device
   ownership, interrupt synchronization, stack bounds, time, entropy and persistence.
6. **Claims follow evidence.** No assertion of immunity, absence of all UAF/OOB,
   complete constant time or a secure MicroVM follows from a static arena, one
   guard, ASan/UBSan or a green finite test. Independent review and meaningful
   falsify-on-mutant gates accompany each implemented rule.

## 4. Local arguments and implementation obligations

**Cursor arithmetic.** If `0 <= off <= n <= SIZE_MAX` and `need <= n - off`, then
`off + need <= n` and the addition is representable. Every copied index
`off + i`, for `0 <= i < need`, is below `n`. A separate capacity proof is required
for the destination. Null/length consistency, object extent, non-overlap, lifetime
and absence of concurrent modification remain caller/platform preconditions.
No numerical check can validate an arbitrary pointer supplied by a caller.

**Allocation arithmetic.** If the positive element size is `s` and
`count <= SIZE_MAX / s`, then `count*s <= SIZE_MAX`. The allocator still may fail;
no element is accessed until allocation succeeds. For a count sum, prove every
addition before the product check. This prevents an undersized allocation caused
by arithmetic; it does not admit heap use to the freestanding target.

**Event lifetime.** During one initialized loop lifetime, a fresh registration
consumes a generation that is never reused. Its cookie encodes one in-range slot.
An event for a retired registration cannot equal the cookie of that slot's later
occupant, even if the OS reuses the FD. A matching event establishes only the
current incarnation; state, ownership and callback-return checks still apply.
Callback reentry into polling/reinitialization is refused, so an old dispatch
batch cannot survive a reset of the generation namespace. Teardown/reinitialization
outside dispatch discards the old kernel queue. The hosted adapter relies on its
`uintptr_t`/OS-user-data round trip; a freestanding backend must preserve this
integer identity under its own ABI contract.
This does not authenticate an arbitrary caller-supplied FD or extend the lifetime
of a pointer retained by application code. Finite generation exhaustion refuses
new registrations; it is a safety bound, not a progress guarantee. The budget is
`UINTPTR_MAX >> 8` registrations per initialized lifetime: 2^56 − 1 on a 64-bit
host, but 2^24 − 1 on a 32-bit host, and the mesh consumes one generation for
every accepted inbound connection before any HELLO. On a 32-bit host an
unauthenticated peer can therefore exhaust the budget by reconnecting (about an
hour at 5,000 connections per second), after which the mesh refuses every
connection until it is closed and re-initialized. That is an availability limit,
recorded open in SECURITY.md; a per-slot generation that may wrap between
dispatch batches would remove the lifetime cap but amends constraint 2 and needs
its own review. The "teardown discards the old kernel queue" step also assumes
the real event loop: under `DETERM_DSF_ENABLED` the process-global
`determ_dsf_poll_hook` survives a re-initialization, so a virtual event carrying
a pre-reinit cookie could alias the restarted generation space. No DSF test
marks readiness with reactor or mesh cookies today; the argument does not cover
that seam.

**Failure propagation.** A KDF/handshake step is reached only after its preceding
HMAC returned success. On failure, cleanup wipes owned secret scratch and returns
failure without using the missing result. An already written output prefix is
not a successful key; callers must honor status. Algorithm conformance, compiler
erasure behavior and side-channel qualification are separate properties.

## 5. Validation and remaining work

Independent reviewers examined crypto, parser/RPC, network lifetime changes,
fault-injection harnesses and documentation. The review corrected recursive
reactor polling, failed-init wording and incomplete instrumentation. Validation
uses `tools/ci_local.sh`; the relevant boundaries are the real codec functions,
network dispatch/callback lifecycle, RPC byte-span interface and crypto callers.
Recorded runs on 2026-09-25 for the audit snapshot before the pre-commit review
(§6 records the review and the committed snapshot):

| Profile / command | Result |
|---|---|
| Darwin arm64, Apple Clang 21, `--c99` | 26/26 targets passed. |
| Linux aarch64, Clang 18.1.3, `--c99` | 26/26 targets passed. |
| Linux aarch64, GCC 13.3, `--c99-sanitize` | 26/26 targets passed; the five changed boundary harnesses were rerun after final instrumentation/width fixes, then the final network test was rerun after its SIGPIPE coverage correction. |
| Linux GCC 13.3, `--c99-mutants` | 187/187 rejected after fresh successful builds; two kqueue-specific cases skipped. |
| Darwin Apple Clang 21, `--c99-mutants` | 187/187 rejected after fresh successful builds; two epoll-specific cases skipped. |
| `--docs-only` | All 16 coherence guards passed. |

At that snapshot the 189 configured variants comprised 142 inherited cases and 47
new audit cases; §6 adds 17 review cases.
Each new case requires an assertion marker and exit 1. The inherited runner gap
for legacy harnesses without markers is unchanged: some non-assertion failures
can count there, as the Decision Log already records. These totals do not prove
all statements needed for memory safety. Backend skips reflect real semantics:
kqueue emits separate read/write events, and epoll itself rejects duplicate FDs.
Across the two profiles all 47 new cases were exercised on their applicable
backend. No production compiler/target qualification follows from these runs.

Test-only copy/allocator/HMAC adapters turn extreme lengths and injected failures
into controlled assertions; ordinary integration tests still execute real copies,
sockets and cryptographic operations. A crash, failed build or missing tool is not
counted as a new mutant's successful rejection.

The crypto test object alone disables fortified string-header substitution:
otherwise the host header can inline `__memcpy_chk` under the renamed test
function and bypass its assertion adapter. The ordinary crypto library retains
its host hardening. The first Linux mutation run exposed this as a crash and
was rejected as evidence. A separate OPAQUE mutation initially failed to compile
because it removed the only use of a cleanup label; the corrected mutation keeps
the label referenced while ignoring the actual failure code. Neither failed run
was counted as a killed mutant.

**Real 32-bit boundary execution.** GCC 13.3 compiled ELF32 ARM EABI5 hard-float
objects with `-O3` and the strict C99 warnings; QEMU user-mode 8.2.2 ran the crypto
bounds test against an ARM32 glibc 2.39 sysroot. All 276,504 assertions passed,
including the actual 32-bit `SIZE_MAX` paths (no redefinition or simulation).
Separate fresh-build mutations deleting Argon2's byte-allocation guard and
restoring PBKDF2's `(outlen + hLen - 1) / hLen` each failed by the test's assertion
marker and exit 1 before invalid memory access. The maximum `UINT32_MAX`-block
PBKDF2 loop endpoint remains an arithmetic argument, not a 137 GB execution test.

Reproduction requires the `gcc-arm-linux-gnueabihf`, `g++-arm-linux-gnueabihf`,
`libc6-dev-armhf-cross` and `qemu-user` packages in a disposable hosted environment.
Copy the current source/build/test directories into an isolated snapshot. In that
snapshot alone, prefix the ordinary test invocation in `tools/ci_c99.sh` with
`qemu-arm -L /usr/arm-linux-gnueabihf`, then run:

```sh
CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ \
  bash tools/ci_local.sh --c99 --c99-test test-c99-crypto-bounds \
  --build-dir build-arm32 --jobs 2
```

Only this crypto target was executed under ARM32 emulation, without sanitizers.
It is neither physical-hardware evidence nor freestanding/constant-time
qualification. The default 64-bit CI jobs do not execute these width-specific
branches; repeat this check when changing their arithmetic or guards.

These fixes do not implement a freestanding networking stack, eliminate every
crypto allocation, resolve parallel P-256 initialization, provision device/stack
memory, or close the combined consensus resource decisions. Those remain governed
by [C99-MINIX-PORT](../C99-MINIX-PORT.md) and
[ADR-004 §9](ADR-004-Fault-Model.md). DNS-rebinding defenses, peer handshake deadlines,
descriptor-exhaustion scheduling and authenticated production consensus remain
separate recorded work. The architecture may adopt memory-safety constraints now;
it cannot truthfully adopt the requested claim of complete structural immunity.
Another open integrity issue was recorded without modifying storage: after a
manifest rename succeeds but directory fsync fails, the old in-memory height can
make a retry truncate the now-referenced block. Production storage needs an
explicit fail-closed/reopen contract. EOF combined with readable data can also
drop the final buffered network bytes; the lifetime fixes do not resolve that
availability behavior.

## 6. Independent review before commit (2026-09-25)

Three independent reviewers examined the uncommitted change set before it was
committed: the wire codec, JSON and RPC/HTTP changes; the network lifetime
changes; and the crypto error paths. None found a memory-safety defect in the
production changes. Every valid input still encodes to the same bytes (a 3,000-
iteration differential run over every encoder differed only in the new
NULL-with-length rejection), and 1,106 oracle-checked crypto outputs (HKDF,
PBKDF2, expand_message_xmd, OPRF, Argon2id, Pedersen balance, OPAQUE-3DH) matched
both the baseline and independent implementations. Resolved before commit:

- **C2-h regression (blocking).** The OPAQUE client had started to write
  `server_mac_ok = 0` before its NULL-argument check. That reverses the gated
  2026-09-17 contract that a NULL-argument rejection leaves every output untouched
  (C2-h): the C++ FAST gate `test-dsso-opaque3dh` failed two assertions, and the
  new C99 test asserted the opposite contract. Validation now comes first, then
  the reset, before any fallible step; the C99 test asserts C2-h. The earlier
  record ran only the C99 modes; the full `ci_local.sh` FAST run exposes it.
- **Guards without a killing test.** Added: exact-capacity edges for the
  transaction's base size, its pq prefix and DHF1's short capacity; truncated
  records for both record iterators; the first rejected sizes of the
  expand_message_xmd and OPRF-finalize preflights and RFC 9380's 8,160-byte
  bound; an oversized `reactor_send` on an empty queue; the queued-flush SIGPIPE
  path; a contributor's refused second connect; `get_block` returning the
  requested height and refusing a string height; and the C2-h contract both
  ways. A watchdog reports a spinning reentrant `reactor_run` as an assertion
  failure instead of a timeout. Each of the 17 new mutation cases is killed by its
  harness's assertion marker and exit status 1 after a fresh build.
- **Callback on a failed connect.** `peer_mesh_connect` failures had started to
  call `on_disconnect` for an index the caller never received, so a
  reconnect-on-disconnect policy could recurse on a persistent setup failure.
  The slot is now released without a callback (`mesh-connect-failure-silent`).
- **Records.** §3.5 and the headers state that the module-wide dispatch guards
  confine every reactor and mesh to one thread per process; §4 states the 32-bit
  generation budget, its remote trigger and the DSF-seam limit of the event
  argument; `json_rpc.h` says a negative return may leave a truncated prefix;
  `sha2.h` says HMAC `out` may alias `msg`, which PBKDF2 relies on. Header comments
  that called a retired registration zero were corrected, the OPAQUE 3DH role
  comments lost in the refactor were restored, and an unobservable
  `out_len > NH` guard in the OPAQUE HKDF-Expand was removed. The combined
  read/write stale-event case now waits for delivery before stepping, and the
  failed-init test puts a probe on descriptor 0 so that a stray `close(0)` is seen.

**Recorded, not fixed** (pre-existing unless stated; each needs its own increment
and review):

- `determ_json_find_key` accepts a key string in value position, so
  `"params":{"note":"height","height":5}` is refused and
  `"tag":"params","params":{"height":5}` falls back to height 0. The new
  same-parent rule never rejects a genuine pair.
- The generic RPC methods echo a string `id` unquoted, which is invalid JSON.
- `wire_bundle_vdf_input` (`src/wire/parser.c`) writes reveal A before checking
  that reveal B fits; `out_written` is set only on success.
- OPRF `derive_key` and `finalize` truncate the two-byte length prefix of inputs
  over 65,535 bytes instead of rejecting them as RFC 9497 requires.
- The event loop's unsupported-platform stub uses descriptor 0 as its poll handle,
  so reactor, mesh and K2 close paths close fd 0 on such hosts.
- `reactor_run` spins if polling fails persistently (the reactor serves only
  tests and the fuzzer).
- The 32-bit mesh generation budget (§4), open in SECURITY.md.
- The width-specific Argon2 allocation and PBKDF2 ceiling guards run only in the
  manual ARM32 reproduction (§5); no recurring CI job exercises them.
