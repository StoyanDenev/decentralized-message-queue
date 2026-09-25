> **TIER: FUTURE — post-1.0, non-authoritative.** Design-stage; does NOT describe shipped code and is NOT coherence-maintained against src/ — EXCEPT §0, which records the in-tree C99 code as it is and is kept coherent with it. Roadmap index: docs/ROADMAP.md

# Determ — Freestanding C99 Target and Reference Migration

**Controlling target (owner, 2026-09-24):** a single-address-space unikernel/MicroVM
with strict freestanding C99, no libc or external crypto/network library, and no
heap allocation. Use static storage, fixed-capacity pools and bounded stack scratch.
This replaces the older POSIX/libc and growable-container deployment plan in this
file. Compiler-provided type/limit headers are allowed; they are not runtime libraries.

**Status:** the target is not implemented. §0 records the hosted code that exists;
§11 records the completed foundation examples and their bounded evidence. Linux,
Darwin and optional Minix/POSIX adapters are hosted build/reference/test environments,
not dependencies of the target image. Minix bring-up is no longer the deployment
gate. The Decision Log and CURRENT FRONT still control work sequencing.

**Adopted development plan (2026-09-24):** [ADR-004 §8.4](decisions/ADR-004-Fault-Model.md#84-adopted-development-plan-2026-09-24)
combines two unanimous co-creators and reviewed K-of-K validation/encoding/persistence
principles with the selected K=2 election, recovery and checkpoints. The initial
receiver/resource contract now exists in ADR-004 §9 / FB76; its unresolved budget
composition and owner decisions gate dependent production work (§13). §7 maps
component dependencies. The 2026-09-25 extension in §14 adds the full local C/C++
audit, PQ/identity design and regulatory evidence work from ADR-008; §12 is the
updated Claude handoff. Adoption does not close protocol proofs or qualify the
target image.

The existing C++ implementation (`src/`, `wallet/`, `light/`) remains the reference
for unchanged protocol behavior while components are ported and verified. Compare
their canonical bytes and semantics under §0's retirement rule. A separately decided
protocol change follows its own specification and proofs; it must not be forced to
reproduce superseded reference behavior. Parity alone proves neither memory safety
nor compatibility with the new target's dependency and side-channel requirements.

---

## 0. Status on 2026-09-23 — what exists, and the retirement rule

**Owner decision 2026-09-23 (DECISION-LOG):** the migration to C99 proceeds by this
plan — port, prove parity, then retire. A C++ component is deleted only after its C99
replacement passes the same test vectors and a differential parity gate against the
C++ reference **in CI**, and the deletion is its own commit. The 2026-09-22 deletion of
the whole C++ tree (838819f3) broke that rule and was reverted.

**What the in-tree C99 code is.** The `determ-node` tree (`src/determ_node.c`,
`src/{consensus,net,rpc,storage,ledger,wire,time}/`) was not built by the phases of §7.
It is a separate experiment built around the proposed K=2 design (ADR-004): a local
two-party commit/reveal attempt (FB74, `K2_VDF_Soundness.md`), a repeated-work
evaluator, a bounded pending inbox, an in-memory transfer ledger and POSIX
networking/RPC. It builds as strict ISO C99 (`determ_c99_strict` in CMake; GCC and
Clang), and CI runs 27 targets with each compiler, again under ASan + UBSan with GCC
(crypto library included), plus an isolated mutation gate (`tools/ci_local.sh --c99` /
`--c99-sanitize` / `--c99-mutants`). Against this plan it stands at:

| C++ component | C99 counterpart | State |
|---|---|---|
| Crypto primitives (`src/crypto/**`) | `determ-crypto-c99` | done as hosted code (predates the experiment; used by the C++ binaries); not admitted to the freestanding target as a whole (§3, CRYPTO-C99-SPEC) |
| DSSO identity service | `dapps/dsso` over `src/crypto/dsso/opaque3dh.c` | done (hosted C99; not target-qualified) |
| D.5 random-selection DApp | `src/dapp/d5*.c`, `dapps/d5-random-selection` | done (hosted C99; not target-qualified) |
| Transaction / block wire codec | `src/wire/binary_codec.c` | partial — envelope, HELLO, transaction (in the D23 layout; C++ carries the pre-D23 layout since the 2026-09-23 revert), BLOCK_SIG, CONTRIB, the request/status, abort, equivocation, SHARD_TIP and receipt-bundle frames, and DMF1/DBK1/DHF1 records; no Block body decoder; no differential parity gate against the C++ codec |
| Block / transaction validation | none | not started |
| Chain state apply + state root | `src/ledger/state.c` (transfer-only, in memory, not integrated) | skeleton |
| Chain storage + replay (DMF1/DBK1/DSN1) | `src/storage/block_store.c` (different layout, no replay) | skeleton |
| Genesis (DGC1) | none | not started |
| Committee selection / registry | `src/ledger/shard_routing.c` (routing query only) | not started |
| Producer / rounds / aborts / evidence | none (the K=2 attempt is a different protocol, not a port) | not started |
| Mempool | `src/ledger/pending_transfer.c` (signature/route/chain-id checks; no balance or nonce) | partial |
| Gossip / sync / networking | `src/net/*.c` (framing, HELLO, dedup; no relay, no sync) | skeleton |
| RPC | `src/rpc/*.c` (loopback-only, a few methods) | skeleton |
| Daemon / CLI (`src/main.cpp`) | `src/determ_node.c` | skeleton |
| Wallet, light client, DSF simulator | none | not started |
| Cross-shard receipts / beacon | none | not started |

**Where the protocol itself changes** (ADR-004 PoSW, D23 chain identity, …) parity is
judged against the decided specification and its test vectors, not against C++ bytes,
and the change goes design-and-prove first (DECISION-LOG doctrine). The C99 pending
inbox already verifies the decided D23 preimage; the C++ reference will match it only
when D23 re-lands soundly.

**C99 memory/lifetime audit (2026-09-25).**
[ADR-006](decisions/ADR-006-C99-Memory-Safety.md) records the pinned public-main
baseline, concrete fixes, preconditions and evidence. The static reactor and mesh pools
now carry immutable registration cookies, reject generation wrap and revalidate
incarnations after callbacks. Codec/RPC sizes are preflighted, failed setup preserves
closed sentinels, and crypto callers propagate HMAC failures. Hosted crypto allocation,
stack budgets, P-256 initialization ownership and the platform boundary remain target
admission work; neither these changes nor zeroing a pool prove complete memory safety.
The consensus implementation order and open resource decisions remain unchanged.

**Build note.** The root `Makefile` that briefly existed was never run by CI and did not
build on Linux (`usleep` is not declared under POSIX.1-2008; it built on Darwin only); it
was removed on 2026-09-23. The plain
`Makefile` described by the earlier plan was for Minix bring-up. CMake currently
enforces ISO C99 + `-Wall -Wextra -Werror -pedantic` on the experiment's GCC and Clang
targets. A hosted build passing those checks is not a freestanding link or boot test.

---

## 1. Why freestanding C99

- **Explicit dependencies.** No C++ runtime, STL, libc or external target libraries.
  Audit generated helper calls and the complete target link, not just source includes.
- **Bounded memory.** Fixed capacities and checked ownership make allocation and
  exhaustion explicit. A flat address space supplies no process-isolation fallback;
  removing an allocator does not itself prove memory safety.
- **Portable core, explicit platform boundary.** Keep protocol and crypto in strict
  ISO C99. Boot, device access, entropy, time and persistence need reviewed platform
  contracts. Hosted adapters support testing; each target needs its own validation.

## 2. Target environment and hosted adapters

- **Compiler:** audited GCC/Clang profiles with `-std=c99 -pedantic-errors` and
  freestanding flags; §11 and CRYPTO-C99-SPEC §9 define artifact checks. Optional
  compiler/assembly adapters are separately identified, never implicit portable-C99
  guarantees. No compiler profile qualifies another one automatically.
- **Runtime:** no guest libc, POSIX processes, BSD socket library or hosted OS API in
  the target image. A platform boundary supplies device I/O, entropy, monotonic time,
  synchronization and persistent storage using bounded buffers and reviewed contracts.
- **Memory:** no `malloc`, `calloc`, `realloc` or `free`; no input-sized stack arrays
  or unbounded recursion. Capacities, stack depth and exhaustion behavior are explicit.
- **ABI:** retain ILP32 portability as a source constraint, using fixed-width integer
  types and checked `size_t` arithmetic. Actual ABI, byte width, alignment and ISA
  assumptions must be stated for each validated target; do not assume 64-bit pointers.
- **Endianness:** encode canonical bytes explicitly; no native-struct wire overlay.
- **Hosted adapters:** Minix/POSIX may use libc, sockets, `select()`/`poll()` and
  `/dev/urandom` solely in the retained reference or test host. Those adapters and
  test runtimes are excluded from the freestanding link and its assurance claims.

## 3. Dependency-elimination budget

| Today (C++17) | Freestanding C99 target replacement |
|---|---|
| `std::map` / `std::set` / `std::vector` / `std::string` | bounded container kit (§5): caller-owned byte span, fixed-capacity vector, sorted map and set; explicit exhaustion |
| OpenSSL + libsodium | **vendored C99 crypto**: SHA-256 (FIPS 180-4 ref), SHA-512 + Ed25519 (TweetNaCl-class, ~700 LoC, public-domain, RFC 8032-interoperable), HMAC-SHA256 (RFC 2104) |
| `nlohmann::json` | the **binary codec** (already shipped) is the canonical wire; JSON only for human/config I/O via a tiny tokenizer (jsmn-class) — or a hand CLI printer. The C99 node speaks binary, not JSON, on the wire. |
| asio | bounded I/O/reactor interface with a reviewed device backend; socket backend for hosted tests only |
| CMake / MSBuild | host build tools emit a freestanding image and dependency/link-map evidence; the build tool is not a target runtime |
| `std::thread` async workers (chain.save, gossip) | bounded reactor work and explicit persistence completion; no `fork()` or process runtime in the target |
| `__int128` supply math | paired `uint64_t` (hi,lo) with checked add — already the pattern (`checked_add_u64`) |
| CSPRNG (libsodium) | reviewed platform entropy interface, fail-closed on failure; `/dev/urandom` is a hosted adapter only |

**Crypto admission is per operation.** Existing portable-C code is input to review,
not automatic qualification. Current Argon2id has data-dependent addressing and
cannot meet the new target's strict secret-independent-address requirement as it
stands. Its hosted keyfile callers remain reference behavior; a compatible, proved
target solution is required before that functionality is admitted. No replacement
KDF or format is selected here. OPAQUE/OPRF, signing, hashing and all other secret
processing need their own memory, dependency and side-channel evidence.

## 4. The parity harness (the load-bearing risk reducer)

Use a frozen, explicitly scoped specification (`PROTOCOL.md` signing bytes,
digests, state-root namespaces, binary codec and snapshot rules) for each component:

- Add a `--emit <fixture>` harness to the C++ reference and C99 implementation that
  emits canonical binary artifacts for: `tx` wire, `block_digest`, `signing_bytes`,
  `compute_state_root`, a serialized snapshot, committee selection, HMAC/SHA/Ed25519
  vectors.
- For unchanged behavior the two outputs over a shared fixture corpus must match.
  Authorized protocol changes use the decided specification and new vectors under
  §0. Neither matching outputs nor a green test closes a proof obligation by itself.
- Check receiver/apply invariants, bounded resource behavior, runtime dependencies
  and the reviewed compiler/target profiles separately. Text/hex renderings are
  non-authoritative diagnostic views of the binary fixtures.
- Seed the corpus from the existing `determ test-*` fixtures and RFC test vectors
  (SHA-256/HMAC/Ed25519 known-answer tests).

This converts a risky rewrite into an incremental, continuously-verified one.

## 5. C container kit (write once, in C99)

The bulk of the porting labor is replacing STL. A deliberately tiny kit covers it:

- `buf_t` — caller-owned byte span with length/capacity; checked append fails without
  partial publication when capacity is exhausted.
- `vec_t` — fixed-capacity pointer/struct array; insertion never grows backing storage.
- `map_t` — bounded sorted-key (`bytes → bytes`) map with deterministic iteration (this is what
  the state-root namespaces need; iteration order **is** consensus-relevant, so sorted).
- `set_t` — bounded membership set (cross-shard receipt dedup `i:`).
- `hex` + `slice` helpers; fixed storage/pool slots with one owner and a specified
  return-to-pool transition. No heap allocation/free calls, backing-store growth or
  hidden allocator.

Capacity is a local resource limit unless a separate consensus rule explicitly
makes it one. A full pool must produce a defined local refusal/backpressure path;
it must not silently change transaction validity or ledger semantics. Persistent
state, replay and snapshots require bounded-memory storage access; no assumption
that the entire lifetime ledger fits in a static RAM array is made.

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
| `c99/net/` | asio gossip + RPC → bounded reactor/platform I/O; hosted socket adapter | med–high |
| `c99/cli/` | `main.cpp` dispatch, wallet, light | med |

Crypto, codec, hashing and state-root modules can be checked in isolation; their
qualification is still required. Stateful apply and consensus need composition,
recovery and persistence proofs in addition to per-module checks.

## 7. Component dependencies under the adopted development plan

[ADR-004 §8.4](decisions/ADR-004-Fault-Model.md#84-adopted-development-plan-2026-09-24)
controls the sequence: review/save the starting work, develop the receiver/resource
contract and arguments, then implement the smallest proved surviving component.
The phases below describe dependencies and parity obligations; they do not require
porting the entire old consensus or building unused scaffolding before that design
work. Select actual paths and callers from the current tree rather than creating
the illustrative §6 directory map wholesale. A primitive may be independently
qualified earlier; production integration waits for its protocol dependencies.
The independent audit/assurance track in §14 follows those same gates; it does not
change consensus rules or bypass ADR-004 §9.6. Its crypto inventory supplements
Phase 1: the primitives listed below are parity dependencies, not the final PQ
algorithm policy.

- **Phase 0 — required foundations.** Freestanding build/link audit, the subset of
  §5 bounded storage and checked buffers needed by the reviewed caller, platform
  contracts and hosted adapters, and §4 parity checks. The whole target's boot/device
  backend remains to be built. Avoid an unused general container framework.
- **Phase 1 — crypto + hashing.** SHA-256, SHA-512, Ed25519, HMAC-SHA256.
  *Gate:* RFC known-answer vectors **and** byte-match the C++ reference's `test-sha256`
  / `test-ed25519` / HMAC outputs.
- **Phase 2 — types + binary codec.** Encode/decode `Transaction`/`Block`/messages.
  *Gate:* unchanged formats are byte-identical to the C++ binary codec on the fixture
  corpus (round-trip + cross-impl); approved changes use the reviewed specification
  and vectors. Neither the teaching QF frame nor a prototype layout is automatically
  the production format.
- **Phase 3 — chain state machine.** Apply rules, the 10 state-root namespaces,
  `compute_state_root`, `serialize_state`/`restore_from_snapshot`.
  *Gate:* unchanged `state_root` + snapshot bytes match the reference over a scripted
  block sequence (reuse the `test-snapshot-*` / `test-state-root-*` fixtures). Changed
  rules require their own reviewed apply/replay and crash arguments and vectors.
- **Phase 4 — selected consensus components.** Reuse qualified validation, signed
  context and canonical encoding principles; implement the decided two-producer
  election, joint receipt, external witness recovery and checkpoint rules only after
  the relevant ADR-004 proof gates. *Gate:* reference parity for unchanged survivors;
  reviewed changed-specification tests and receiver/apply mutants for replacements,
  plus the composition arguments. There is no requirement to first port the old
  sampler, producer-only abort rule or fork choice solely to discard it.
  [ADR-004 §9](decisions/ADR-004-Fault-Model.md#9-one-shard-receiver-state-and-resource-contract-2026-09-24)
  specifies the one-shard receiver contract (proofs in FB76). Its first component,
  the streaming stake-quorum verifier of §9.7, is a verification primitive qualified
  ahead of its callers under the rule above (§13); components that depend on the open
  decisions D1–D8 wait for them.
- **Phase 5 — platform integration.** Bounded gossip/RPC reactor and device backend,
  then target wallet/light interfaces. *Gate:* unchanged protocol surfaces
  interoperate through a hosted adapter and changed surfaces satisfy their reviewed
  specifications; the actual MicroVM image passes boot,
  dependency, memory/ownership, persistence and relevant side-channel checks.
  Optional Minix/POSIX tests provide portability evidence, not a substitute for that
  gate. This implements the adopted design-and-prove sequence, subject to §0's
  retirement rule and the still-separate deployment decision.

## 8. Hard parts & honest risks

- **Crypto assurance.** Algorithm conformance, correct C semantics and secret-independent
  compiled control/address traces are separate obligations. Test vectors do not
  guarantee any of them for every input; generated-code review and target evidence
  are required. Existing Argon2id is not admitted by the strict target contract.
- **Wallet recovery crypto (OPAQUE/OPRF).** The single hardest dependency to render in
  minimal C99; recommend gating it as an optional module and shipping the node + payment
  + light path first.
- **Platform and RAM.** Specify bounded reactor work, device ownership, stack and
  memory budgets on the actual target. A MicroVM still depends on its hypervisor,
  device model and hardware; flat guest memory magnifies corruption consequences.
- **Spec must be frozen per targeted feature set.** Parity needs a fixed target — the
  C99 reimplementation tracks a **frozen** subset of `PROTOCOL.md`; v2 features
  (threshold randomness, DSSO, etc.) get their own later C99 phases, not a moving target.
- **Size.** The C++ tree is tens of kLoC; this is a multi-month reimplementation, not a
  sprint. The parity harness is what keeps it from being a multi-month *gamble*.

## 9. Scope of the "final C99 version"

Target scope: the C99 node (consensus + apply + state-root + binary wire + platform
I/O), `determ-light` core (header/committee/state-proof verification, trustless reads),
and the offline wallet signing path, each admitted only with the target's dependency,
memory and side-channel evidence. Passphrase KDF admission remains unresolved as in
§3. OPAQUE-based wallet recovery and v2 roadmap features keep their separate gates.

## 10. Cross-references

- `docs/PROTOCOL.md` — the reference byte-level wire / digest / state-root spec for
  unchanged behavior. ADR-004 and its reviewed increments specify approved changes;
  the Decision Log resolves conflicts.
- `docs/proofs/` — reviewed invariants (FA / FA-Apply / S-0xx) for unchanged
  survivors. Approved changed rules require re-derived arguments and vectors;
  update evidence and citations to the actual surviving source paths as increments
  land, without automatically inheriting a reference proof's closure.
- `docs/proofs/CRYPTO-C99-SPEC.md` — current crypto inventory, target admission
  limits and per-compiler side-channel evidence (§3, §9).
- the shipped binary codec (`test-binary-codec`, `test-tx-binary-codec`) — canonical
  reference bytes for unchanged formats (§3, Phase 2). Approved changed formats need
  their own reviewed specification and vectors before becoming C99 production wire.
- `tools/reap_daemons.sh` — on Minix/Linux the daemon-reaper uses `pkill -x`; the whole
  Windows file-lock failure class does not exist there.

## 11. Freestanding unikernel foundation (owner goal, 2026-09-24)

**Status: architecture guidance and executable examples, not a shipped unikernel or
production security certification.** The owner requests a single-address-space
MicroVM/unikernel target with strict C99, no libc, external crypto/network library or
dynamic allocation. The owner's subsequent instruction makes this the controlling
target over the former hosted Minix/POSIX deployment plan; hosted adapters remain
reference/test facilities. It does not bypass §0's port-then-retire rule.
The protocol synthesis in ADR-004 §8 continues separately; completeness of its
high-level proofs is not a premise of these examples.

### 11.1 Trust boundary and architecture

A guest without a monolithic OS omits that OS's guest attack surface. It still trusts
its startup code, drivers, device model, hypervisor, firmware, compiler and relevant
hardware behavior. In flat guest memory, a corruption may reach every guest secret
and control object; it does not logically imply a host escape. DMA, interrupts,
speculation, shared caches, timing, power/EM observation and fault injection need
explicit treatment. Removing libc or the heap is not a proof of memory safety.

Use a small platform boundary and a freestanding protocol core:

1. Platform code owns boot/linker layout, bounded RX/TX descriptors, entropy,
   monotonic time, durable storage and interrupt/DMA synchronization. It validates
   descriptor ownership and physical capacity before supplying a pointer/count to C.
2. Ingress checks the public framing and copies into a caller-owned bounded object.
   No pointers into a recycled RX slot escape this call. Invalid frames are dropped
   without partially publishing a message. Rate-limit diagnostics and work queues.
3. Authentication and protocol validation check signatures/MACs, identities, replay
   rules and the actual parent state. Framing success grants no authority. Parse
   bounded public lengths before authentication when necessary, but do not apply
   state, reveal secrets or execute an unauthenticated command.
4. Only a fully validated operation reaches deterministic state apply. Parser output
   and speculative replay state remain separate from the authoritative ledger.

Use fixed-capacity arrays/pools, reject on exhaustion, and budget every byte:
RX/TX buffers + parser output + crypto scratch + state + queues + stacks, including
interrupt stack usage and maximum call depth. No recursion, input-sized VLA or
unbounded work-list growth in the ingestion path. Static memory needs ownership:
for a single reactor, transfer a slot from device ownership to parser ownership and
back only after completion. Mask interrupts or use a separately reviewed platform
handoff as required; ISO C99 supplies no thread-atomic or DMA-coherency primitive.
`volatile` is not a substitute for either. Multicore, interrupt reentry or concurrent
DMA writes invalidate a single-owner proof unless the platform rules exclude them.

### 11.2 Executable, bounded frame example

Read the heavily commented [header](examples/freestanding_core.h) and
[implementation](examples/freestanding_core.c). They are teaching code, deliberately
outside `src/`: **QF is an example frame, not a new Determ wire format**. The frame
is at most 256 bytes: two magic bytes, version, type, big-endian 16-bit payload
length, big-endian 16-bit shard number, then at most 248 opaque payload bytes.
The parser accepts only version 1, types 1/2 and an exact total length. A shard
number here is merely decoded; production eligibility is a separate validation.

The core uses only the freestanding headers `<stddef.h>`, `<stdint.h>` and `<limits.h>`
for type and limit declarations; it calls no runtime C library function. With GCC on a
hosted toolchain, `<limits.h>` reaches the C library's `limits.h` through
`#include_next`, so the example needs those headers at build time (not at run time):
under `-nostdinc` with only GCC's own include directory it does not compile, while
Clang's own headers suffice. A `UINT8_MAX` guard in place of the `CHAR_BIT` check
would remove that dependency; it changes the example and needs new §11.6 evidence. The target must have 8-bit bytes and
the exact-width integer types the example requires. It uses no string/memory
library function, allocation, wire-struct overlay, packed struct or unaligned
integer dereference. Layout/endianness is decoded byte by byte. Never send the
in-memory output structure verbatim: padding is not wire data. A successful parse
zeroes payload bytes beyond `payload_len`; only the first `payload_len` bytes are
part of the accepted message.

For a static single-reactor integration, keep one RX array and one `fg_frame`
outside the stack. Only the platform adapter may fill RX, and it must return the
actual received extent after ownership transfer. Call `fg_parse_frame(rx, n,
&parsed)`; dispatch only on return 1. Before asynchronous consumers retain a
message, transfer ownership of a separate bounded output slot instead of reusing
`parsed`. A pointer/count supplied by an attacker does not establish a C object.

**Preconditions of the memory proof:** the non-null input designates at least `n`
readable bytes; output designates one live writable `fg_frame`; the two objects do
not overlap; no other actor changes either during the call. Null pointers are
rejected by the parser. A length exceeding the frame cap is rejected before any
input read. Hardware/MMIO addresses and stale/free pool pointers are outside this
API contract. Neither C nor a numeric range check can validate an arbitrary pointer.

### 11.3 Bounds and failure-atomicity argument

Let H = 8, C = 256, P = C − H = 248, n be the actual received extent and L the
decoded payload length. All bounds are public; early rejection is appropriate.

1. Check H <= n <= C before any header load. Every header index j satisfies
   0 <= j < H <= n. Read u16 values with unsigned byte arithmetic; do not cast a
   wire address to a `uint16_t *` or shift a promoted signed value past its range.
2. The checked n − H <= P and required L == n − H imply L <= P. The subtraction
   is defined without unsigned wrap because n >= H. Check before copying or
   publishing output. An attacker
   cannot make a truncated payload pass by wrapping an unchecked H + L addition.
3. At copy iteration i, 0 <= i < L <= P. Therefore the destination index is
   smaller than its array extent, and H + i < H + L = n <= C. This addition cannot
   wrap on a supported target. Each source/destination access is within its live
   object. The loop counter remains bounded by P and terminates.
4. Every rejecting branch precedes output writes. A rejected frame leaves the
   output's prior contents unchanged; callers must still honor the return value.
   A successful parse publishes fields plus L payload bytes and zeroes the tail;
   that second loop visits only L <= i < P, also within the output array. There
   is no later error path. This is function-level failure atomicity under the ownership
   precondition, not crash atomicity or synchronization with concurrent readers.

For general cursors the same invariant is `off <= n` and `need <= n - off` before
forming `base + off` or advancing `off`. For repeated records check
`count <= remaining / record_size` (record_size > 0) before multiplication. Do not
prove safety with a condition such as `off + need <= n` that may already have
wrapped. Stack limits, object lifetimes and aliasing are separate proof obligations.
The applicable C rules are object access and array-relative pointer arithmetic
(WG14's [C99 consolidated draft, §§6.5 and 6.5.6](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1256.pdf)).

### 11.4 Fixed-length equality and erasure

The same example provides `fg_equal32` and `fg_wipe`. Equality reads all 32 bytes
from each valid input, accumulates XOR differences with OR, and returns a normalized
equal/not-equal result. The public length is fixed. The accumulator d is zero exactly
when every pair of bytes is equal and always lies in 0..255. Thus d + 255 <= 510
fits even a 16-bit unsigned int, and `(d + 255U) >> 8` is zero for d = 0 and one
otherwise; XOR with 1 yields the stated result without signed overflow. In
the C source, loop control and indexed addresses depend only on the public index.
The equality result is intentionally observable, not a hidden secret.

This is a source-level trace argument, not a universal machine-timing guarantee.
Use it for 32-byte tags or byte strings; it is **not Ed25519 verification**. That
requires decoding, scalar/group checks, hashing and the verification equation.
Do not compare a received signature to a locally generated signature as a substitute.

`fg_wipe` writes zero through a volatile unsigned-character lvalue for each byte of
a live writable object. Its length is public and must fit that object; NULL is
permitted only with zero length. The loop stays in bounds and overwrites exactly
that span. Volatile stores address dead-store elimination under the implementation's
volatile rules; they do not wipe register copies, compiler spills elsewhere, device
buffers, caches, snapshots or previous copies. Keep secret lifetimes and copies
small, inspect the optimized caller as well as the helper, and specify platform
erasure requirements separately. No C99 keyword guarantees physical erasure.

The [crypto specification](proofs/CRYPTO-C99-SPEC.md) records compiler profiles,
optional nonportable barriers and the distinction between source trace, generated
code and measured side channels. The existing `determ_secure_zero` calls libc
`memset`; these examples do not claim the whole crypto library is freestanding.

### 11.5 Evidence and release obligations

Run `bash tools/ci_local.sh --freestanding-examples`. It builds the examples freshly,
runs functional/boundary checks and isolated falsify-on-mutant cases, and retains
compiler metadata, emitted assembly and dependency evidence. The `c99` job of
`.github/workflows/ci.yml` runs it on pushes to `main`, pull requests and manual runs
(ubuntu-24.04, x86-64, the runner's GCC and Clang). A toolchain or sanitizer runtime it
lacks is printed as NOT VERIFIED and the step still passes; CI keeps the log, not the
evidence directory, so a qualification record needs a local run. Instrumented tests of
loop visits can detect an introduced early return but do not prove constant time
for the uninstrumented binary. Hosted test allocations and sanitizer runtimes are
test apparatus, not linked target dependencies. These checks do not boot a MicroVM.

For **each** compiler/version, optimization and LTO setting, target ABI/ISA and
hardware configuration proposed for deployment, require this evidence:

| Property | Evidence and limit |
|---|---|
| Memory safety | Review the object/ownership preconditions and arithmetic argument; boundary/adversarial tests and ASan/UBSan exercise executions; a whole-ingress proof includes the driver, pool, stack and callers. Sanitizer success alone is not that proof. |
| No runtime dependencies | Inspect the final link map and undefined symbols for libc, allocation and compiler support helpers; inspect startup and all other objects too. Freestanding compilation alone cannot promise a self-contained image. |
| Data-independent execution | Inspect optimized, uninstrumented caller and callee instructions for secret-dependent branches, addresses and variable-latency operations. Repeat after compiler/flags/CPU changes, inlining, vectorization or LTO. Source appearance and debug traces are insufficient. |
| Timing leakage | Use paired secret classes, mismatch positions and distributions, controlled public inputs, sufficient samples and stated noise/measurement limitations; inspect any detected difference. A statistical pass cannot establish absence of all leakage. |
| Erasure | Verify stores survive in the final artifact even when the caller never reads the buffer again; inspect copies/spills and the target's visibility/persistence model. A read-back test alone makes stores live and cannot test dead-store elimination. |
| Fault/side-channel boundary | State treatment of interrupts, DMA, cache sharing, speculative execution, power/EM, fault injection and hypervisor access. Constant control/address traces do not close every item. |

No unsupported compiler/ISA or untested LTO setting inherits qualification from a
nearby build. A missing tool is reported as unverified coverage, not a passed test.
The deliverable is a foundation and an evidence procedure; production deployment
requires the missing platform contracts, linked image and protocol proofs.

### 11.6 Recorded example validation (2026-09-24)

`tools/ci_local.sh --freestanding-examples` completed successfully on Darwin 25.6.0,
arm64. All 16 documentation guards passed. The four independently built profiles
were Apple Clang 21.0.0 (`clang-2100.3.34.2`, target
`arm64-apple-darwin25.6.0`) and Homebrew GCC 16.2.0 (target
`aarch64-apple-darwin25`), each at `-O2` and `-O3`. Common core flags were:

```text
-std=c99 -pedantic-errors -Wall -Wextra -Werror
-ffreestanding -fno-builtin -fno-stack-protector -fno-lto
```

Disabling stack protection isolates this example's runtime dependencies; it is
not a recommendation to remove a production mitigation. LTO was disabled.
Each profile passed 452,306 ordinary assertions, 722,741 assertions in the
instrumented trace build, and its ASan/UBSan run. All four core objects and
`-nostdlib` relocatable links had no unresolved references (the relocatable link of
one object that already has none re-checks the object audit; it is not independent
evidence, and the gate reports its status only in `report.json`). These links do not
include boot code, drivers or a production executable.

Six isolated mutants per profile compiled successfully and then failed a test
assertion (24 total): accepting a short header, accepting an oversized frame,
accepting trailing bytes, wrong shard endianness, early-exit comparison, and
omitting wipe stores. The first two mutate rejection behavior without deliberately
accessing invalid memory. None is claimed as an exhaustive memory-corruption or
machine-timing test; compile failures and crashes do not count as assertion kills.

Independent source review and review of the uninstrumented object disassembly
found no input-byte-dependent branch or address in `fg_equal32` for these four
artifacts. Clang emitted fixed loads and reduction; GCC at `-O2` used a fixed
two-iteration vector loop and at `-O3` unrolled it. `fg_wipe` retained byte stores
controlled by public length. A separate same-translation-unit caller, which
wipes a local 32-byte array and never reads it afterward, retained all 32 zero
stores: unrolled under Clang, a fixed loop under GCC. Thus the erasure observation
does not rely on a test reading the wiped bytes back.

The reviewed core object's SHA-256 identifies the scope of each observation:

| Profile | Core object SHA-256 |
|---|---|
| Clang `-O2` | `aa91f9e24d8dc1581a5ec0ccf74ce8240f01111b24ea0433c497c5bb1cdaff2c` |
| Clang `-O3` | `24bb7fd6324dd738759f2c4463cc0144f4a460fa3eb3499684cd0108a942b8fa` |
| GCC `-O2` | `9b22b8bffff4b0ceb2d566ad04796ba4fc59729f3390d1e2011072419db7a010` |
| GCC `-O3` | `e1ab01b727793e80cc27a026618ff069494012524c0f2ea7a3d0c9d55119ea45` |

Tested core source SHA-256:
`9b80f795858db60902f08ad536e5271a032967a23f4ab95eab22eecd2086ded8`.
The other committed gate inputs (SHA-256, checked against the commits of 2026-09-24):
header `aa30ae2a11fa3b92a5edca4e3c5a278f10c05ddf39c36cc57a88bda0b14b5db7`, test
`6e4cd9a9d8cb895480394fa6c645afae7ca69718e518025bfab3e99a8a7d4df0`, gate
`87966f79884afd6bba35c14ec8888eadc9e0254eda49bddf2a1f09823f27d430` and the
`tools/ci_local.sh` it ran under, `afade32a918fd0ed7d321f7a11544cef5e0c11997c67a6d63537b5037a77a228`.
The local report and command logs are retained under
`/var/folders/3w/8ys8lvtj6qbdkgwsd89kfmfr0000gn/T/determ-freestanding-examples-v3zal_8a/`;
`report.json` records compiler paths, flags, source/gate hashes and artifact hashes,
including the dead-caller objects. This temporary directory is not a permanent
repository artifact; rerun the command above to reproduce the evidence.

**Not established:** a formal machine-code constant-time proof, hardware timing
or other leakage measurements, LTO behavior, a linked MicroVM image, other
compiler/ISA profiles, or whole-ingress/whole-protocol memory safety. The source
invariants and these bounded artifact observations do not imply those claims.

## 12. Claude commit and development handoff (2026-09-24)

**Updated 2026-09-25:** the owner asks to add the audit/rewrite/compliance prompt to
the plan, for later execution by Claude. This update changes documentation only.
It preserves the earlier authorization for Claude to make reviewed local commits
and continue development. It does not execute that authorization in this task.

The prompt below implements ADR-004 §8.4, §14 of this plan and
[ADR-008](decisions/ADR-008-Regulatory-Compliance-and-C99-Rewrite.md). Re-read the
working tree before starting; the inventory is a dated observation. Adoption is
not proof of consensus, target qualification or regulatory conformity.

```text
Act as a Principal Systems Security Engineer and Applied Cryptographer. Work in
/Users/stoyandenev/Desktop/sauromatae. Review and save the relevant existing work,
then continue the adopted development plan. Use local files; do not git pull or
fetch a replacement baseline. Do not skip the retained C++ reference.

Read CLAUDE.md CURRENT FRONT (AGENTS.md points to it), the latest entries of
DECISION-LOG.md, ADR-004 §§6.1, 7, 8.4 and 9, C99-MINIX-PORT §§0, 7 and 11–14,
ADR-006, ADR-008, SECURITY.md, CRYPTO-C99-SPEC target-admission rules and ADR-005's
current status. Paths are under docs/, docs/decisions/ or docs/proofs/ as linked here.
The Decision Log wins conflicts. Preserve historical decisions and open findings.

The selected direction remains two unanimous co-creators over one canonical,
receiver-validated body/context, joint receipt, selected election/VDF, external
failure witnesses, local 3B timeout and checkpoint settlement. Reuse sound K-of-K
validation/encoding/durable-publication principles. Joint receipt does not inherit
union's one-member inclusion guarantee. H0 CLOSED / H1–H21 DECIDED does not mean
proved. ADR-004 §9 / FB76 already records the fixed-budget incompatibility and
pending X1, D1–D8/refusal decisions; do not restart that work or silently select
limits. stake_quorum is a qualified primitive, not production integration.

The final target is strict freestanding C99 in a single-address-space unikernel/
MicroVM: no libc, external target runtime libraries or heap. Hosted references,
platform adapters and test oracles remain outside it. Source style, static pools,
volatile, barriers, compiler flags and green tests do not prove whole-program
memory safety or universal constant time. Current Argon2id and libc-backed crypto
helpers are not admitted to the target. Do not weaken that requirement implicitly.

1. Inspect and preserve the starting state.
   At the 2026-09-25 handoff, main was 6a131af3a96fa20e81d54e3d7057ac28bd1345c7.
   The earlier restoration/foundation was already committed. The ADR-006 C99 audit
   fixes, headers, tests, CI changes and docs were uncommitted, followed by this
   documentation-only ADR-008/plan update. cats.json and top100.json were staged
   independently. Inspect staged/unstaged/untracked changes separately; use current
   evidence rather than assuming this list is still exact. No blanket reset,
   stash, git add ., git add src/ include/ docs/, commit -a or whole-index commit.
   Prior /tmp audit reports/scripts are historical snapshots, not the current
   commit manifest. Review the actual diff and preserve unrelated index entries.

2. Review, verify and make scoped local commits of relevant starting work.
   First confirm with git status/log what is already committed. If any part is
   still uncommitted, separate the prior audit implementation from this plan
   adoption and subsequent development in dependency order. Include each change's actual tests and docs;
   test the exact proposed commit snapshot so unstaged fixes cannot mask defects.
   Independently review consensus/apply/wire/evidence changes before committing,
   regardless of gate colour. Local commits of reviewed relevant work and later
   qualified increments remain authorized. No push, merge, deployment, reference
   deletion or certification claim is authorized by this handoff.

3. Execute §14.1's coverage-backed audit before selecting new patches.
   Inventory the whole local repository. Read the relevant C and C++ code, headers,
   tests, builds and documentation, including network, parsing, ledger/consensus,
   crypto, identity and persistence paths. Track every file's review/disposition;
   list exclusions and outstanding coverage. Confirm/refute every preliminary
   allegation with real callers, arithmetic/lifetime arguments and reproductions
   where feasible. Distinguish a target dependency blocker from a reachable defect.
   Reuse ADR-006 rather than duplicating it. The existing, sufficient reveal-bundle
   bound and the QPC fix must not be reported as new bugs. Record the applicable regulatory/profile
   evidence in ADR-008; an unspecified CISA directive is not a mandate.

4. Follow §14.2's sequence: memory/lifetime, temporal/state/persistence, crypto/PQ,
   credential/privacy design, then target and operational qualification. Within
   each step choose the smallest confirmed surviving defect or required component.
   Define the caller contract, proof assumptions, bounds and failure transitions;
   obtain independent adversarial review; then implement exact C99 changes in the
   real files, with receiver/apply regression and falsify-on-mutant gates. Fix a
   surviving C++ consensus/logic defect separately when justified; do not spend
   proof effort hardening an abstraction scheduled for deletion. Keep hosted parity
   for unchanged behavior and reviewed specification vectors for approved changes.
   Do not combine a full rewrite, PQ suite replacement and credential scheme into
   one compliance commit. No placeholder APIs or renamed prototypes as production.

5. Keep decisions and evidence explicit.
   PQ parameter/profile/hybrid choices, credential proof scheme and applicable
   operator/wallet roles must be specified and reviewed before dependent code.
   OPAQUE authentication is not credential selective disclosure. Preserve the
   no-escrow/no-master-key rule, no post-genesis migration, and the requirement for
   secret-independent target crypto. Record incompatibilities for owner decision;
   continue independent work rather than inventing authorization or weakening a
   goal. ADR-004's unresolved production dependencies still gate consensus and
   sharding. Local socket timeouts do not grant replacement/finality authority.

6. Validate each increment through tools/ci_local.sh.
   Select the affected documented modes below, run them separately, report compiler
   paths/versions and confirm a fresh build before trusting mutants. Any change
   under src/crypto/ or include/determ/crypto/ also runs the default mode (FAST):
   the C++ reference links the same C99 crypto library, and ADR-006 §6 records a
   contract regression that only a C++ gate caught. A new mutant
   must trigger the intended assertion, not a build failure, crash or timeout.
   Missing tools are not passes. Preserve CRLF in CRYPTO-C99-SPEC.md and append-only
   Decision Log history. Do not weaken guards. Converge README, SECURITY, protocol,
   proof and plan records as each actual behavior changes; distinguish decisions,
   implementation, proof, bounded tests and target qualification.

Finish with commit hashes/scope, audit coverage and findings, exact checks and
limits, independent-review resolutions, pending decisions and the next concrete
increment. Make no absolute safety, PQ, compliance or certification claim without
its precise evidence. Continue authorized independent development after saving
the starting work; do not stop at the initial commits.
```

Verification entry points for that prompt (separate invocations; compiler paths are
the installed paths observed for this handoff and must be checked when reused):

```bash
bash tools/ci_local.sh --docs-only
bash tools/ci_local.sh --freestanding-examples
bash tools/ci_local.sh --tla
bash tools/ci_local.sh --jobs 4
CC=clang bash tools/ci_local.sh --c99 --jobs 4
CC=/opt/homebrew/bin/gcc-16 bash tools/ci_local.sh --c99 --jobs 4
CC=/opt/homebrew/bin/gcc-16 bash tools/ci_local.sh --c99-sanitize --jobs 4
bash tools/ci_local.sh --c99-mutants --jobs 4
git -c core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol diff --check
git -c core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol diff --cached --check
```

The TLA mode does not run the documentation guards. The standalone freestanding
mode must not be combined with the other CI modes. These are verification entry
points, not a statement that the current audit/plan snapshot has been revalidated
by this documentation-only handoff. §11.6 records the prior example evidence and
its limits; Claude must report results for the actual snapshots it commits.

## 13. Combined-design receiver components (2026-09-24)

[ADR-004 §9](decisions/ADR-004-Fault-Model.md#9-one-shard-receiver-state-and-resource-contract-2026-09-24)
is the one-shard receiver contract, and its arguments are in
[OneShardReceiverContract.md](proofs/OneShardReceiverContract.md) (FB76). Components land
one increment at a time, each with its proof, independent review and gates. A component
that has no production caller yet is a primitive qualified ahead of its callers (§7). Its
production integration waits for the decisions listed in ADR-004 §9.6.

### 13.1 `stake_quorum`: streaming two-thirds-of-stake verification

- **Files.** `include/determ/consensus/stake_quorum.h` and `src/consensus/stake_quorum.c`,
  with the test `tests/test_stake_quorum.c`. The freestanding audit is
  `tools/check_no_undefined.cmake`, with its canary `tests/freestanding_audit_canary.c`.
- **Contract (FB76 Lemma Q).** Once the caller has absorbed the last entry of a
  certificate's framing, `sq_finish` accepts exactly the canonical certificates:
  - snapshot indices strictly increase and stay below N;
  - every signature is valid under the caller's verifier, which must return exactly 1
    for a valid signature;
  - the signers hold at least two thirds of the stake. The module compares 3·sum with
    2·W exactly, as 128-bit values built from shifts and additions.

  The state is O(1). An out-of-order or out-of-range entry is refused before any
  verification. A rejection is final, and an entry offered after an accepting finish
  turns the verdict into a rejection: a caller that finished too early is told so if it
  offers a further entry, but not if it stops reading. The key and stake arrays are
  borrowed and must not change from validation to the last finish. `sq_begin` copies the
  snapshot's fields, so the snapshot object may be reused.
- **Freestanding.**
  - The module includes only `<stddef.h>` and `<stdint.h>`. It makes no library call,
    allocates nothing and keeps no global state. Its source has no 64-bit division or
    multiplication; the only multiplication is the `size_t` key offset, a shift. A
    compiler may still call a helper: Clang 18 turns the shift-and-add comparison into a
    64-bit multiply that calls `__aeabi_lmul` on ARMv6-M and ARMv8-M Baseline. The audit
    below decides each target profile.
  - Building `test-stake-quorum` with GCC or Clang, as every full `--c99`,
    `--c99-sanitize` and `--c99-mutants` run does, also compiles the module with
    `-ffreestanding -fno-builtin -fno-stack-protector -fno-lto -fno-sanitize=all` (plus
    `-fno-pic` on ELF), with interprocedural optimization off. The build fails if `nm -u`
    finds an undefined symbol in that object. A build with global `--coverage` therefore
    fails here: Clang 18 cannot exclude coverage per target, and GCC's
    `-fprofile-exclude-files` is not used.
  - On ELF targets the build also fails if the object defines writable data. COFF and
    Mach-O `nm` report section and literal-pool symbols that would misfire, so on those
    formats "no global state" rests on inspection.
  - The same audit must flag the canary, which calls an external function and defines
    writable data, so each active check is shown able to fail.
  - The audit covers only the configured compiler and target. Here that was x86_64 Linux
    with GCC 13.3.0 and Clang 18.1.3 in CMake's Release configuration. The 32-bit
    addressability check in `sq_snapshot_init` is compiled out on 64-bit targets, so no
    gate executes it.
  - By hand, `nm -u` also found nothing at `-O0` to `-O3` and `-Os` for GCC and Clang on
    x86_64, and for Clang on i686, armv7, riscv32, aarch64 and x86_64 MinGW (with
    `-fno-pic`), and GCC `-m32`. On i686, Clang's default PIE object references
    `_GLOBAL_OFFSET_TABLE_`, as does a `-fPIC` object from either compiler. Clang on
    ARMv6-M and ARMv8-M Baseline needs `__aeabi_lmul` (above).
- **Caller obligations (ADR-004 §9.7).**
  - The statement bytes follow D5; the snapshot follows D6 and holds no small-order
    key.
  - Every receiver uses one Ed25519 variant.
  - 1 ≤ W ≤ 2^64 − 1 and N ≤ 2^32 − 1, and every signature pointer names 64 bytes.
  - The snapshot given to `sq_begin` is one that `sq_snapshot_init` accepted, or a copy
    of its fields.
  - `sq_finish` is called only after the last framed entry.
- **Gates.** `test-stake-quorum` is a portable `--c99` target. It checks:
  - the quorum comparison against an independent formulation (32-bit halves and
    multiplication) for every W up to 200,000 at the boundary, all pairs of 17 edge
    values, and 2,000,000 random pairs;
  - snapshot and argument validation, including a zero stake first, later or alone, and
    each of `sq_begin`'s defensive checks on its own, with outputs unchanged on failure;
  - a total the fixture sums itself;
  - W = 2^64 − 1 exactly;
  - exact-threshold boundaries, including stake-not-head-count cases;
  - order, duplicate and range rejection without verification;
  - binding of each signature to its signer's key and to the statement;
  - terminal verdicts, a repeated finish after acceptance, and late entries of every kind
    after an accepting finish (duplicate, out of range, NULL signature);
  - changed stakes, and reuse of the snapshot object;
  - the verifier's return-value contract, and that it receives the caller's context and
    a non-NULL signature;
  - an exhaustive differential check for up to five members with stakes 1–3: every
    subset and every single corrupted signature;
  - 30,000 randomized differential cases with up to 64 members, totals near 2^64, and
    injected reorderings, duplicates, out-of-range indices and bad signatures;
  - a 70,000-member snapshot, including all 70,000 signing;
  - real Ed25519 signatures from the hosted library.

  `--c99-mutants` adds 35 cases for this target. Each must fail with the harness's
  assertion marker and exit status 1, so a crash or a signal never counts as a kill here,
  unlike the gap the DECISION-LOG records for the older harnesses. Mutants that delete
  a NULL check on `acc` or `snapshot`, or `sq_snapshot_init`'s check on `stakes`, or
  that let `UINT32_MAX` through a wrapping range check to the stake read, can only
  crash, so they are not listed.
- **Not established.**
  - a production caller;
  - the D5 encoding and the D6 snapshot;
  - the Ed25519 variant that receivers use;
  - a freestanding Ed25519 (the hosted verifier allocates for messages over 448 bytes);
  - the audit on profiles other than those above;
  - constant-time properties, which are not needed because all inputs are public.

## 14. Local audit, regulatory alignment and target qualification (2026-09-25)

**Adopted scope, not completed work.** This section schedules the supplied prompt
for Claude. [ADR-008](decisions/ADR-008-Regulatory-Compliance-and-C99-Rewrite.md)
records the corrected regulatory premises and accepted long-term goals. No new
runtime implementation, full-repository audit or compliance assessment is claimed
by this planning update. The prior C99 audit remains separately scoped by ADR-006.
Use this existing plan, the Security ledger and proof records; do not create a
competing master plan. This track can advance independently while the unresolved
ADR-004 §9.6 decisions gate production consensus and sharding.

### 14.1 First deliverable: local coverage and hypothesis record

**Status (2026-09-25).** The first record is ADR-006 §7: four independent
reviews, the allegation dispositions below confirmed or refuted with evidence,
and a findings table whose Medium rows are SECURITY.md S-118–S-121 and the C99
storage row. `tools/audit_coverage.tsv` gives every tracked file a disposition
and `tools/test_audit_coverage.sh` (a `--docs-only` guard) keeps it complete and
fails when a reviewed file changes without being re-reviewed. At that commit 186
files were reviewed for a stated scope (96 of them crypto files, for R4's
inventory questions only), 7 partially and 1,363 were pending, including the C++
consensus/apply path, the wallet and light clients and the simulation harness;
the record says so rather than claiming full coverage. The per-finding record is
ADR-006's review appendix.

Pin HEAD and the reviewed working-tree diff. Inventory all repository files, then
record each as reviewed, pending, generated/data with a reviewed producer/consumer,
or excluded with a reason. Inspect C/C++ sources and headers, plus wallet/light,
DApps, simulation, tests, build/CI and documentation that affect target behavior.
A keyword scan is an inventory aid, not a complete audit. Completion requires an
explicit disposition for every file and substantive review of every in-scope code
path; report outstanding coverage instead of claiming to have read everything.

Extend ADR-006's audit record and existing proof/security records with the coverage
map and evidence. For each finding record the actual symbol/path and baseline,
caller/reachability, input trust, violated invariant, severity, reproducer or
reasoned counterexample, existing mitigations, planned C99 owner and verification
gate. Mark allegations CONFIRMED, REFUTED, ALREADY FIXED, TARGET BLOCKER or UNRESOLVED
with scope; do not equate `shared_ptr`/allocation/fragmentation with a proved UAF.

These are verified entry points for the future audit, not its completed coverage:

| Surface | Real local entry points and migration questions |
|---|---|
| Wire and reveals | `src/wire/parser.c`, `include/determ/wire/parser.h`, `src/wire/binary_codec.c`; reference `src/net/binary_codec.cpp`, `src/net/messages.cpp`, `src/chain/block.cpp`. Derive bounds at each framing layer and validate lengths before conversion/copy/publication. |
| Network and RPC | `src/net/reactor.c`, `peer_mesh.c`, `event_loop.c`, `k2_net.c`, `src/rpc/http_rpc_server.c`, `json_rpc.c`, `src/determ_node.c`; reference `src/net/gossip.cpp` and `include/determ/net/`. Trace descriptor/slot ownership, callbacks, queues, reads/writes and shutdown/error paths. |
| Consensus, ledger and durability | `src/consensus/duel_state.c`, `stake_quorum.c`, `src/ledger/state.c`, `pending_transfer.c`, `shard_routing.c`, `src/storage/block_store.c`; reference `src/node/node.cpp`, `producer.cpp`, `validator.cpp`, `src/chain/chain.cpp` and their headers. Map validation/apply/replay boundaries and which behavior survives the selected design. |
| Crypto and PQ callers | `src/crypto/` and `include/determ/crypto/`; ML-DSA under `mldsa/`; reference `src/crypto/pqauth.cpp`, `src/chain/pq_tx_auth.cpp`, `light/pq_sign_tx.cpp`. Inventory algorithms and actual consumers, including optional and failure paths; reconcile stale library-only claims with callers. |
| Identity | `src/crypto/dsso/opaque3dh.c`, `include/determ/crypto/dsso/opaque3dh.h`, `dapps/dsso/` (including the relying-party PID verifier `dsso_pid.c`), `tools/verify_opaque3dh.py`; existing `proofs/v2.25-DSSO-DAPP-SPEC.md` §11–12, `proofs/DssoPidVerification.md` and privacy/view-key designs. Separate authentication, account recovery and credential presentation. |
| Clock/platform | `include/determ/time/clock.h`, `src/time/clock.c`, `tests/test_qpc_clock_overflow.c`, transport adapters and build definitions. Verify monotonicity/overflow/units and actual platform coverage. |

**Disposition of the preliminary claims at planning time:**

- Two capped 65,536-byte reveals in the current bundle need
  `4 + 65536 + 4 + 65536 = 131080` bytes. `MAX_BUNDLE_SIZE = 131104` already fits
  that layout; the claim that it necessarily overflows is refuted for this bundler.
  K2 transport has a separate 65,536-byte payload / 65,548-byte frame bound; do not
  infer that every bundle fits one transport frame. Derive the production layout
  and caller relationship before changing either capacity.
- Integer overflow is a real audit class, but expression width matters:
  `4 + uint32_length` can wrap even with a 64-bit destination. ADR-006 M1 and
  M3–M6 already record scoped fixes; recheck the remaining C++/C callers and 32-bit
  branches. Never claim an attacker-supplied length proves remote exploitability
  without the ingress-to-copy path and allocation/capacity preconditions.
- C99 network pools are already static and their callback lifetime fixes are
  recorded in ADR-006. C++ containers/ownership remain to be audited; eight crypto
  C files, `src/dapp/d5draw.c` and `dapps/d5-random-selection/d5rp.c` still allocate. No heap does not imply no libc,
  correct object lifetime or bounded stack use.
- Missing mesh handshake deadlines, HTTP idle-slot exhaustion and descriptor
  exhaustion spins are recorded OPEN in SECURITY.md. Inventory all admission,
  handshake, read/write and shutdown paths before claiming Slowloris resistance.
  Existing local attempt deadlines (T+1s commits, T+2s reveals) and the experimental
  10s response wait do not implement the adopted production 3B recovery rule.
- `EAGAIN`/`EWOULDBLOCK` means no progress is available now. A blocking descriptor,
  busy retry, unbounded handler or synchronous storage/crypto work can starve the
  service loop; an error return itself is not proof of a freeze. Check partial
  I/O, interrupted calls, readiness changes and callback reentry on each backend.
- QPC conversion already uses checked split arithmetic and saturation, with
  `tests/test_qpc_clock_overflow.c` and mutations. Preserve/revalidate that fix;
  audit call sites and other clock/deadline arithmetic instead of replacing it
  from the obsolete `(ticks * 1B) / freq` premise.
- ML-DSA primitives and C++ PQ callers exist. No ML-KEM or SLH-DSA implementation
  was found in the scoped source/header/wallet/light/DApp search; verify full
  coverage before treating absence as a repository-wide result. The OPAQUE core
  uses a house-tagged P-256/3DH transcript and does not claim arbitrary-stack wire
  interoperability. Neither fact establishes an EUDI wallet or full PQ system.

### 14.2 Development sequence and deliverables

Complete the coverage/hypothesis record first, then progress in the following
order, one reviewed increment at a time. A decision-dependent step may produce
its design and explicit pending choices while an independent step proceeds. Do
not treat this order as authority to bypass consensus proof gates or to postpone
an independently confirmed severe surviving defect merely for convenience.

| Step | Required design and implementation deliverable | Evidence before calling the increment complete |
|---|---|---|
| A — local audit and applicability | §14.1 coverage; confirmed/refuted allegations; map each retained C++ behavior to its C99 replacement/dependency; fill ADR-008's clause/profile/role/control evidence matrix | File/symbol evidence, exploit preconditions and reproduction limits; explicit pending files/roles; independent review of findings; no invented mandate or blanket safety claim |
| B — spatial and lifetime safety | Caller-owned arenas/workspaces where needed, generation-checked handles and ownership; checked length/count conversion and subtraction-based cursors; bounded stack; no standard memory/string calls in target code | Invariants and proof/model of every reachable acquire/use/release/reuse and error transition, including generation exhaustion and delayed events; exact-boundary/truncation/extreme-length/width tests; receiver-level mutants; unchanged-byte parity where required |
| C — temporal, phase and durable-state safety | Reviewed per-connection monotonic deadlines and progress policy; bounded admission/queue/CPU work; nonblocking transport/device contract; authenticated phase transitions; crash-safe publication/recovery | Slow-drip/idle/full-pool/partial-I/O/backpressure/descriptor-exhaustion schedules, clock endpoints, reordered/replayed/stale events, callback reentry, torn-write/fsync-failure/restart traces; assertions at the actual receiver/apply/publication boundary |
| D — crypto and PQ qualification | Complete algorithm/caller/key-lifecycle inventory; reviewed target workspace APIs; applicable ML-KEM/ML-DSA integration plan and decision on SLH-DSA's role; version/errata/parameter/hybrid policy before dependent code | Independent KAT/conformance and failure tests; canonical encoding/replay/context binding; worst-case sizes/workspace/stack/verification budgets; compiler/ISA leakage and erasure evidence; module-validation status separately stated |
| E — identity and disclosure | Extend v2.25-DSSO-DAPP-SPEC §11–12 and DssoPidVerification.md (the existing relying-party verifier side) and the privacy design with any holder/issuer credential layer and precise selective-disclosure/ZK requirements; choose reviewed scheme/profile before structs/messages | Issuer trust and claim authenticity, holder binding, consent, verifier challenge/audience and replay defenses, revocation freshness, metadata/linkability and collusion analysis; tampered/unrequested/replayed/revoked/over-disclosure tests and applicable interoperability evidence |
| F — integrated target and operations | Actual freestanding image and native device/event backend, deployment trust boundary; signed/reproducible release and dependency inventory; operator incident/backup/recovery/vulnerability processes | Linked-image dependency/heap/symbol and stack audits, boot/device/interrupt/DMA tests, sustained bounded-resource failure/recovery tests, scoped formal evidence, target leakage assessment and the applicable external conformity process |

**Contract details that must not be lost between design and implementation:**

- Bounds proofs require a live object with the claimed extent, `offset <= capacity`
  and `length <= capacity - offset` before pointer formation or copies. Check
  count-times-element and integer narrowing in their actual types. Prefer single-
  evaluation C99 helpers to unsafe arithmetic macros. Reject invalid/unknown frames
  before state mutation, and define output/state on every failure.
- A generation counter only prevents stale reuse while identity cannot repeat.
  Define wrap/exhaustion refusal, callback retirement ordering and event snapshots;
  raw borrowed pointers still need a lifetime. Pool, queue, stack and DMA ownership
  proofs are separate. Avoid a generic arena framework without a real caller.
- Timeouts use a specified monotonic source, units and overflow policy. Bound total
  handshake/frame lifetime as well as any idle/progress allowance, so trickled bytes
  cannot extend occupancy forever. Set reviewed service budgets rather than borrowing
  TCP defaults. Define fairness/refusal and loss assumptions; finite slots cannot
  guarantee availability against an unbounded adversary.
- Read/write progress, retry and phase changes are explicit transitions. Bound
  EINTR/retry and accept loops; check setup failures, partial writes and `EAGAIN`.
  Include synchronous crypto/storage/logging and wakeup storms in the loop's work
  budget. Single-threaded code still has reentry, stale events and interrupt/DMA
  interleavings. Keep local timeouts separate from consensus validity decisions.
- Storage must resolve the existing manifest-rename/directory-fsync ambiguity
  (SECURITY.md / ADR-006) before production integration; retry must not truncate a
  block referenced by a visible manifest. Design crash and reopen behavior first.
- PQ integration must cover classical dependencies in authentication, DH/OPRF,
  recovery, credentials and consensus assumptions as well as transactions. Adding
  ML-DSA does not make P-256/Ed25519/X25519 or a VDF post-quantum. Do not choose
  hybrid composition, replacements or signature-only substitutes for key exchange
  without a reviewed construction. No settled wire/state format is silently changed.
- Algorithm conformance and transcript proofs do not establish secret-independent
  machine-code traces. Apply §11 and CRYPTO-C99-SPEC target admission; document each
  compiler, flags, ISA, public/secret input boundary and leakage model. If the goal
  and an existing primitive conflict, record the blocker rather than relabel it.
- An identity proof reveals its selected claim/predicate, not necessarily zero
  plaintext bytes. Specify exactly what is disclosed and to whom; minimize disclosed
  attributes and correlation. Do not promise unlinkability from a stable holder
  key or reusable proof. No new master key, escrow or compelled disclosure; retain
  the qualified forward-secrecy limits of voluntary view-key disclosure.

### 14.3 Commit and completion discipline

The later implementation deliverables are exact patches in real files, with highly
commented local invariants and proof/test references where they aid review. Each
increment follows design/proof → independent adversarial review → implementation
and falsify-on-mutant gates at the enforcing layer → applicable `ci_local.sh` modes
→ independent final-diff review → scoped local commit. Update canonical docs to
actual behavior; do not close an entire vulnerability class with a single gate.

Use §12's commit authorization and preserve unrelated staged work. The supplied
blanket `git add src/ include/ docs/` and omnibus `feat(compliance)` commit are
replaced by explicit reviewed paths/hunks and truthful per-increment messages.
Before each commit, inspect the staged diff and verify that exact snapshot. No
commit may claim full compliance, quantum security, immunity or completed C++
retirement unless the relevant evidence and retirement gate actually exist.

Report completed coverage, confirmed/refuted/fixed/open findings, landed patches,
proof assumptions, tests and residual limits separately. Keep ADR-008's evidence
matrix current. A code audit does not complete operator governance, wallet
certification or cryptographic module validation. The final target, production
consensus/sharding, reference retirement and deployment each retain their own
acceptance gate. Independent work can proceed while a specific dependent decision
remains pending.
