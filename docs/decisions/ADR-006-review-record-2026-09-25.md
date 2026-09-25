> **TIER: PROCESS / ARCHIVE.** Per-finding record of the 2026-09-25 local coverage review (C99-MINIX-PORT §14.1); retained as evidence for the fix increments, NOT coherence-maintained. ADR-006 §7 and docs/SECURITY.md carry the current status. Roadmap index: docs/ROADMAP.md

# ADR-006 appendix: 2026-09-25 coverage review, finding by finding

**Provenance.** Four independent reviews (R1–R4) and one review of the record
itself (R5) read the source of commit `0cbc3861` (tree `97b19e03`). Each ran
its experiments in a scratch directory that is not committed: sanitizer builds
(GCC 13.3 ASan+UBSan, Clang 18 trap sanitizers), `-m32` builds, differential runs
against independent oracles, and fault injection by symbol wrapping. The
evidence column summarizes what was actually run; a fix increment commits its
own gate. Statuses: CONFIRMED (evidence given), REFUTED, ALREADY FIXED, TARGET
BLOCKER (not a reachable defect today; blocks freestanding admission) and
UNRESOLVED. Severity is the reviewer's.

**Errata applied here.** R3-02 said CHAIN_RESPONSE is discarded; it is not:
`Node::on_chain_response` consumes it (`src/node/node.cpp`, assigned where the
gossip callbacks are wired). Only SNAPSHOT_RESPONSE and HEADERS_RESPONSE have no
handler. R3-01 and the SNAPSHOT_RESPONSE pre-authentication residual were
already recorded in the Decision Log entry "D2 inc7c LANDED" (2026-09-16); the
S-118 empty-tag case was noted, unregistered, in RpcIngressGateAudit.md.

## R1 — hosted C99 services

Scope, read in full: `block_store.c`, `state.c`, `pending_transfer.c`,
`shard_routing.c`, `duel_state.c`, `dda.c`, `clock.c`, `event_loop.c`,
`virtual_transport.c`, `parser.c`, `d5draw.c`, `d5codec.c`, `determ_node.c` and
their headers. All in-scope tests pass under GCC ASan+UBSan; `-m32
-Wconversion` shows two guarded narrowings; a 400,000-input fuzz of the D5 codecs
was clean.

- **R1-01 — CONFIRMED, Medium.** `block_store_open` (`src/storage/block_store.c`)
  treats any `stat()` failure on the manifest (EIO, ESTALE, ELOOP, EINTR on FUSE)
  as absence and atomically re-initializes it at height 0. Reachability: node
  start-up with `--data-dir`; environmental errors only, no remote trigger.
  Invariant: open never publishes over a durable manifest. Evidence: with one
  injected EIO, a height-2 store reopened at height 0, and an append at height 0
  replaced `0.blk`; the stock binary under an `LD_PRELOAD` shim rewrote the
  manifest to height 0. Fix: fail with `BLOCK_STORE_ERR_IO` unless `errno ==
  ENOENT`. Gate: include the real source with a `stat` interceptor; EIO must
  return ERR_IO with the manifest bytes unchanged. Open design point: ENOENT
  beside an existing `0.blk` may deserve CORRUPT_MANIFEST.
- **R1-02 — CONFIRMED, Low.** `block_store_append_block` accepts an all-zero
  head hash that `block_store_open` then refuses (CORRUPT_MANIFEST). Tests are the
  only callers. Fix: reject a zero hash before creating the block file.
- **R1-03 — CONFIRMED, Low.** `determ_node.c` parses `--port`, `--p2p-port`,
  `--rpc-port` and peer ports with `atoi` and casts to `uint16_t`: `--rpc-port
  70000` listened on 4464, `-1` on 65535, `65536` disabled both services.
  Unknown options and missing values are ignored. Fix: strict decimal 1..65535,
  exit 1 on unknown options, check `peer_mesh_connect`'s result.
- **R1-04 — CONFIRMED, Low.** The unsupported-platform event-loop stub returns
  from poll immediately (a 100 % CPU spin in every caller loop) and uses fd 0
  as its handle, so close paths close descriptor 0. It does not compile under
  the strict flags (unused `timeout_ms`). Fix: `#error` for unsupported
  platforms; a future `poll(2)` backend must honour timeouts and use -1.
- **R1-05 — CONFIRMED, Info.** `signal()` binds to one-shot System V semantics
  under `_POSIX_C_SOURCE` (`__sysv_signal`); use `sigaction`.
- **R1-06 — CONFIRMED, Info.** The service loop polls mesh and HTTP
  sequentially (a median 50 ms GET latency with an idle mesh); VDF completion runs
  on the loop (121 ms + 53 ms); K2's `send_all` can hold the loop for up to 2 s.
  Input to the §14.2 step C budgets.
- **R1-07 — UNRESOLVED, Info.** Clock-source failures are unchecked at several
  call sites (an indeterminate `timespec`, a possible division by a zero
  timebase, a clock stuck at a constant never expiring K2 deadlines, a division
  by a zero elapsed time in the benchmark). Not reachable on Linux.
- **R1-08 — CONFIRMED, Info.** The DSF seam drops an oversize queued receive
  silently, clears readiness on poll and ignores which loop it serves, so DSF
  runs cannot show level-triggered behaviour.
- **R1-09 — TARGET BLOCKER.** External symbols per file (for example
  `block_store.c`: open, read, write, fsync, rename, unlink, mkdir, stat,
  snprintf); stack frames up to 65,920 B (`run_benchmark`, a 64 KiB VDF arena)
  and about 33 KB for the ledger root computations; objects that must never be
  automatic (`k2_aggregator_t` 459,200 B, `duel_state_machine_t` 262,360 B).
- **R1-10 — Info.** Storage notes: block-file directory entries are not ordered
  before the manifest rename by POSIX; no inter-process lock; leftover temporary
  manifests; open validates every block file; the D5 decoders publish partial
  outputs before failing.
- **Allegations:** the reveal-bundle overflow and the EAGAIN "freeze" REFUTED;
  QPC overflow ALREADY FIXED (`48daed3f`) and revalidated over 20,000,000 cases
  against a 128-bit reference.

## R2 — DApp C code facing external formats

Scope, read in full: `dapps/dsso/` sources and headers except the generated
vectors (and `authn_selftest.c`, partly), and `dapps/d5-random-selection/`. The
four DSSO selftests pass on x86_64 and i386 under ASan+UBSan and Clang trap
sanitizers; 20 M JSON mutants, 3.5 M base64url and 500 K inflate differential
cases (against zlib) and 20 K mutated presentations found no memory error.

- **R2-01 — CONFIRMED, Medium (S-121).** The pseudonym is derived from the raw
  JSON token of the PAN claim, escapes and quotes included
  (`dsso_pid_subject_material`), not the unescaped value DssoPidVerification §4.1
  specifies. Evidence: binding `920417/0000` and `920417\/0000` (one subject)
  gave two pseudonyms; re-affirming with the other spelling failed. Trust:
  issuer-authored bytes. Fix: unescape with `dsso_json_string`, length-prefix,
  scrub. Gate: both spellings, equal pseudonyms, the second account refused.
- **R2-02 — CONFIRMED, Low.** `pol->now - iat` and `pol->now - kb_iat`
  (`dsso_pid.c:626,631`) overflow for `INT64_MIN`, which is undefined behaviour
  and bypassed the age check (UBSan reported it; the result was DSSO_OK).
  `kb_iat` is holder-supplied. Fix: compare in unsigned arithmetic after an
  ordering check; gate under `-fno-sanitize-recover`.
- **R2-03 — CONFIRMED, Low.** `auth_ok` computes `now - auth->at`
  (`dsso_bind.c:57-58`) before the MAC check; `at = INT64_MIN` with a valid MAC
  never expires. Same fix and gate.
- **R2-04 — CONFIRMED, Low.** One trust lookup serves PID signing and status
  lists, so a status-list key can sign PIDs at the anchor's maximum assurance.
  Fix: key-usage bits on anchors.
- **R2-05 — CONFIRMED, Low.** A present but non-integer `nbf` is treated as
  absent. Fix: reject it.
- **R2-06 — CONFIRMED, Low.** `dsso_json_member` compares the caller's key as an
  escaped body, so the disclosure-shadowing check misses names with escapes.
- **R2-07 — CONFIRMED, Low.** The 4 KiB disclosure buffer and the parsed
  holder-key and status buffers are not scrubbed; the raw identifier stayed on
  the dead stack after a successful bind.
- **R2-08 — CONFIRMED, Low.** Unbound records keep `in_use`, so after 32
  bind/unbind cycles no account can bind until restart.
- **R2-09 — CONFIRMED, process.** No sanitizer profile instruments `determ-dsso`
  or `d5rp` for undefined behaviour, which is why R2-02 and R2-03 stayed
  invisible.
- **R2-10, R2-11 — TARGET BLOCKER.** Every DSSO HMAC allocates (`hmac.c`), one
  of them before authentication; `d5rp` allocates five times per draw.
  `pid_verify_inner` uses about 60 KB of stack and `dsso_bind_commit` about
  22 KB.
- **R2-12..R2-18 — Info.** Partial outputs contrary to two header contracts; a
  NULL policy leaves the result unzeroed; D5 RP publishes a count before a later
  failure; the JSON reader accepts invalid UTF-8; the status URI reaches the
  fetch callback unvalidated; `dsso_loa` is defined in two headers; revoked
  device slots are reused (already recorded in DssoAuthenticationAssurance.md).

## R3 — C++ network and wire ingress

Scope, read in full: `src/net/` C++ transports, codec, gossip and peer code,
`src/rpc/rpc.cpp`, and the relevant headers; the codec parts of `block.cpp`, the
decode side of `chain.cpp` and DGC1 in `genesis.cpp`.

- **R3-01 — CONFIRMED; Info on 64-bit, High on an ILP32 build (recorded
  2026-09-16, not fixed).** `wf_need` and `bf_need` bound attacker-chosen u32
  lengths additively (`binary_codec.cpp:843`; `block.cpp:1666,1723,1812`); with a
  32-bit `size_t`, `off + flen` wraps and a 4 GB window reaches the decoder.
  Evidence: an ILP32-width model of both idioms. The HEADERS decoder already
  uses the subtractive form. Fix: `flen > len || off > len - flen` at the four
  sites. A port requirement for the C99 Block decoder.
- **R3-02 — CONFIRMED, Medium (S-119; corrected, see errata).** `Peer::read_body`
  decodes every frame before HELLO, the role filter and the per-IP rate limit.
  A 16 MB SNAPSHOT_RESPONSE rebuilds a full `Chain`, may recompute the S-033 state
  root and re-serializes a JSON DOM, and is then dropped (no handler); a
  CHAIN_RESPONSE is decoded (up to about 55,000 blocks) and then consumed. A
  valid frame keeps the connection open, so the work repeats. Fix: meter or
  admit before the typed decode, and refuse SNAPSHOT_RESPONSE when nothing asked
  for it.
- **R3-03 — REFUTED.** Count-driven reserve blow-up: Block-frame counts are
  16-bit and byte-backed; witness nesting is depth ≤ 2.
- **Lifetime.** No proved use-after-free or iterator invalidation in the
  transports, event loops or gossip teardown read. S-085, S-082's residual and
  S-064 are still live and were not re-reported.

## R4 — crypto library, callers and post-quantum inventory

Scope: every file under `src/crypto/` and `include/determ/crypto/`, and crypto
call sites across `src/`, `wallet/`, `light/`, `dapps/` and `cryptotest/`, for
callers, heap, libc, globals, stack and secret-dependent control flow and memory
access. Not a correctness proof.

- **R4-01 — CONFIRMED, Medium (S-118).** `hmac_sha256_hex` returns an empty
  string when HMAC fails, and `verify_auth` accepts an empty `auth` against it
  (`src/rpc/rpc.cpp`). Evidence: with `malloc` failing inside the real
  `hmac.o`, a large request with `"auth":""` was accepted. HMAC fails only when
  its allocation fails; the request's own allocations must succeed first.
- **R4-02 — CONFIRMED, Medium, latent (S-120).** The OPAQUE-3DH preamble appends
  `cred_request` and `cred_response` without lengths. Evidence against the real
  `opaque3dh.c`: client 10/90 and server 80/20 byte splits with different client
  nonces gave `server_mac_ok = 1`, equal session keys and an accepted client MAC.
  The server nonce and both ephemeral keys must match. Tests are the only
  callers.
- **R4-03 — CONFIRMED, Low (also ADR-006 §6).** OPRF `derive_key`, `blind` and
  `finalize` truncate lengths over 65,535 bytes instead of rejecting them.
- **R4-04 — CONFIRMED, Low.** `derive_key` accepts any seed length; `(S ‖ 0002,
  "")` and `(S, 0000)` derive the same key.
- **R4-05 — CONFIRMED, Low (API).** `determ_ed25519_sign` hashes a caller-supplied
  public key; signing one message under two keys reveals the scalar. Every caller
  derives the key from the seed.
- **R4-06 — TARGET BLOCKER.** ML-DSA signing emits `idiv`/`sdiv` on secret data
  at `-Os`/`-Oz`, and SampleInBall's work depends on rejected, secret-derived
  challenges.
- **R4-07 — TARGET BLOCKER.** Range-proof and IPA scalar helpers branch per byte
  on secret bits (the amount); the balance prover branches on the blinding.
- **R4-08 — TARGET BLOCKER.** Argon2id's modular reductions of secret-derived
  words need runtime division helpers on i386 and ARMv7-M.
- **R4-09 — TARGET BLOCKER.** Worst stack paths: aggregated range proving about
  207 KB, ML-DSA signing 173 KB, consensus `ctx_bundle_verify` about 125 KB,
  ML-DSA verification 111 KB.
- **R4-10 — TARGET BLOCKER.** P-256's unsynchronised lazy initialization
  includes the SSWU function-local statics.
- **R4-11 — TARGET BLOCKER.** Exactly eight crypto C files allocate; every size
  computation is guarded.
- **R4-12..R4-18 — Low/Info.** Non-constant-time C++ `scalar_valid`; permissive
  Ed25519-to-X25519 conversion contrary to its header; an unprefixed D5 context
  hash; no ChaCha20/GCM message-length limits; ML-DSA APIs without key lengths
  (an ASan overflow with a short key; production checks the length first); CT
  prover randomness bound only to `nonce_seed ‖ tx_nonce`; unwiped residues.
- **R4-19, R4-20.** The ADR-006 M5/M6 fixes verified; S-115, S-001, S-103/S-117
  and S-091 already recorded.
- **Post-quantum inventory.** No ML-KEM or SLH-DSA anywhere (every non-doc file
  searched for names, FIPS numbers and constants); ML-DSA-44/65/87 authenticate
  only PQ_TRANSFER, through `pqauth::verify` in block validation and mempool
  admission. Ed25519 consensus and transaction signatures, X25519 chat, P-256
  commitments, OPRF, OPAQUE and ES256 remain classical.

## R5 — review of the record itself

- **R5-01 — CONFIRMED, Low.** The loopback RPC server parses each request line
  with the vendored JSON parser before authentication; a 16.7 MB nested-array
  line took about 615 MB of RSS and 2.4 s (about 38×). RPC binds to loopback by
  default and the 16 MiB line cap (RpcIngressGateAudit row 7) bounds the input
  but not the parse amplification. D2 step 2 deletes the parser.
- The record's own corrections (the CHAIN_RESPONSE erratum, earlier-record
  citations, the stale-row rule, data dispositions) are applied in ADR-006 §7.
