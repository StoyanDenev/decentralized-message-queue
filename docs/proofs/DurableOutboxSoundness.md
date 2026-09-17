# DurableOutboxSoundness — the `determ-light outbox` sender-side delivery contract (OB-1..OB-6)

**Status.** SHIPPED (increment 1, 2026-09-16): `light/outbox.{hpp,cpp}`, `light/outbox_cli.cpp`,
`light/outbox_selftest.cpp`; gates `tools/test_light_outbox.sh` (FAST) + `tools/test_light_outbox_live.sh`.
Scope of increment 1: `TRANSFER` (optional ≤128-byte A4 payload) from a DAK1 anonymous keyfile. Not in this
increment: `DAPP_CALL` (needs a registered-domain key — a DNK1 loader in `determ-light` — and inherits the
S-069 eligibility caveat), any node-side change.

**Problem.** No client path persisted a signed transaction: `verify-and-submit`, `submit-tx` and `bulk-send`
sign, call `submit_tx` once and forget (`light/main.cpp` cmd_verify_and_submit; `wallet/main.cpp` bulk-send);
the only retry loop in the tree re-tries on the substring "nonce" (`src/main.cpp:2218-2239`, node-custodial
RPCs). A crash, a lost reply or a daemon restart lost the message, and a naive re-send with a fresh nonce
turned one message into two. Separately, no observable distinguished *in a block* from *applied*:
`chain.cpp:987/1688` skip an underfunded tx without advancing the nonce, and delivery never consults the apply
result (S-063; DECISION-LOG 2026-08-14 D4).

**Companion facts (verified at HEAD).** F1 `hash = SHA256(signing_bytes)`, no expiry / chain binding in the
signed bytes (`src/chain/block.cpp:20-37`, `include/determ/chain/block.hpp:317-351`). F2 canonical tx frame
`Transaction::encode_frame/decode_frame` (`block.cpp:150-266`). F3 `submit_tx` recomputes the hash, rejects a
stale nonce, verifies the signature, applies mempool policy and replace-by-fee; identical bytes while pending
→ "incumbent tx at (from, nonce) has equal-or-higher fee" (`src/node/node.cpp:4606-4709`); it does **not** run
the verifier's per-tx rules (those run at build, `node.cpp:2848-2872`, and evict silently). (The node runs `mempool_admit_check`
BEFORE the incumbent check, `node.cpp:4680-4690`, so identical bytes re-sent into a full mempool or past a
per-sender quota read as a retryable rejection, not "incumbent" — the slot stays sendable either way. Since
S-079, 2026-09-16, that policy also rejects — definitively, "mempool: unaffordable (S-079)" — a transaction the
sender cannot fund at the daemon's head together with its other pending ones, so such bytes are never `queued`;
and a pending transaction a LATER head leaves unfundable is evicted at the next build, like a verifier
rejection.) F4 the
mempool has no TTL (`node.hpp:725-775`). F5 the verifier enforces `tx.nonce == expected` and no balance rule for
TRANSFER/DAPP_CALL (`validator.cpp:884-887`); the producer debits TRANSFER provisionally (`producer.cpp:1333-
1336`) and has no DAPP_CALL arm, and its admission predicate evicts what the head cannot fund (S-079,
`Node::tx_admit_locked`). F6 apply skips an underfunded tx without advancing the nonce (`chain.cpp:987,
1688`), so one hash can be included twice. F7 delivery scans the block body only (`node.cpp:4183-4227,
4452-4501`). F8 `tx` returns the LATEST inclusion or null (`node.cpp:3795-3821`); no RPC exposes an apply result.
F9 `verify_tx_inclusion` proves membership by the block's own committee sigs (`light/verify_tx_inclusion.cpp:56-
262`; it does not itself require K of them, so INCLUDED — a non-final state — can rest on fewer; FINALIZED
cannot: the successor binding enforces the K-of-K rule); `committee_bound_state_root(h)` requires a committee-signed header h+1 whose `prev_hash` equals the
recomputed hash of the served block h (`light/trustless_read.cpp:640-757`); `read_account_trustless` proves
(balance, next_nonce) at index `view.height-1` under the same rule. F10 S-048: two committee-signed blocks can
exist at one height and nodes reorg at depth 1 (`docs/proofs/BoundedReorgDesign.md`).

## 1. The record and the write primitive

One outbox directory per (sender, chain): `outbox.meta` (DOM1: genesis_hash ‖ sender ‖ nonce_floor ‖ SHA-256),
one `<nonce:020>.msg` per reserved nonce (DOX1), `outbox.lock`, transient `*.tmp`. A DOX1 record is an
IMMUTABLE section (genesis, sender, nonce, type, created, idempotency key, 1..8 alternates = `{kind, msg_id,
fee, tx_hash, frame}`) with its own SHA-256, followed by a STATUS section (state, apply, attempts, backoff,
outcome, note, inclusion/finality heights, counters) hashed together with the immutable hash. Every bound is
refused, never clamped; every alternate's frame is self-validating on load (`decode_frame`, hash recompute, nonce
and sender equal the slot's). `msg_id = SHA256("DTM-OUTBOX-MSG-v1" ‖ genesis ‖ sender ‖ nonce ‖ hash(original))[0:16]`.
The record stores signed bytes only — never a key, never a plaintext note.

Durable write (`durable_write_new` / `durable_write_replace`, `light/outbox.cpp`): write `<path>.<pid>.tmp` →
flush to stable storage (`fsync`; on Darwin `fcntl(F_FULLFSYNC)` with `fsync` as the fallback where the
filesystem refuses it; `FlushFileBuffers` on Windows) → publish — create-new via `link(2)` for a new slot (an
acknowledged record can never be overwritten; on filesystems without hard links the directory lock plus an
existence check followed by `rename` keep the contract), atomic replace via `rename(2)` for an update; Windows
uses `MoveFileExW` without / with `REPLACE_EXISTING` — → flush the directory (POSIX; a failure to open or flush
it throws). Windows has no directory flush: the file's bytes are flushed before the publish and NTFS journals
the rename itself (`MOVEFILE_WRITE_THROUGH`'s documented flush covers only the cross-volume copy case) — the
Windows guarantee is therefore "bytes flushed, rename journaled". Any failure (including ENOSPC and an fsync
error) discards the temp file and throws; nothing is acknowledged.

## 2. Claims

| Claim | Statement | Enforced at | Gate |
|---|---|---|---|
| **OB-1** Durable acknowledgement | `queued locally …` (or `queued_locally:true`) is printed only after the record's bytes have been flushed to stable storage and published under the final name, and — on POSIX — the directory entry flushed. The guarantee is one copy on one device under a storage stack that honours fsync; it is not replication and does not survive the device. | `cmd_enqueue` order: `write_slot_new` then print (`light/outbox_cli.cpp`); `durable_write_impl` | `test_light_outbox.sh` B (crash points `before_write`/`after_write`/`after_fsync` ⇒ no ack, no record; `after_publish` ⇒ record, no ack; an update crash keeps the old record) + C (strace order `fsync(tmp) < publish < fsync(dir) < write(ack)`, Linux) |
| **OB-2** Stable identity, no silent second message | A slot re-sends only the bytes stored in it (`submit_due` has no signer and no key); every alternate of a slot carries the slot's nonce; the ledger applies at most one tx per (from, nonce) (F5/F6). New bytes enter a slot only through `replace`, which keeps `msg_id` on a fee bump and records a new `msg_id` on a re-issue; all alternates stay watched. | `light/outbox.cpp` submit_due, `parse_immutable` (nonce/sender pinned per frame), `cmd_replace` | `selftest-outbox-core` 2 (identical hash re-sent after a lost reply; one application), 3 (re-armed slot re-sends the same hash), 7 (fee-bump attribution); `test_light_outbox_live.sh` 2, 4 |
| **OB-3** Truthful status | SUBMITTED ⇐ a daemon reply `queued` naming this slot's hash, or "incumbent", only. INCLUDED ⇐ `verify_tx_inclusion` INCLUDED at h with h beyond the verified state index. FINALIZED ⇐ INCLUDED at h ≤ verified index **and** `committee_bound_state_root(h)` returns the inclusion block's own recomputed hash. APPLIED ⇐ FINALIZED and next_nonce proven `> N` at index ≥ h (under A1). SKIPPED ⇐ FINALIZED and next_nonce proven `== N` at index ≥ h. CONSUMED/UNLOCATED ⇐ next_nonce proven `> N`, no probe was unverifiable, and this daemon located no CANONICAL inclusion of any alternate — the verdict names what it did serve (nothing; an orphaned body carrying the bytes; a hint to a block without them; or an inclusion the record had already proven SKIPPED — that one can never be re-labelled APPLIED). CONSUMED is final for sending but is probed again on every pass and upgraded to FINALIZED/APPLIED when a daemon locates the canonical inclusion. An unverifiable probe (transport hiccup, an odd hint, a body that fails verification) leaves the slot unchanged and exits 3, never a terminal verdict; with several alternates a spent nonce is attributed only when EVERY alternate's probe verified. Which alternate is attributed comes from the daemon's per-alternate hints (A2); the proven part is that one of the slot's bytes consumed the nonce. A timeout is UNKNOWN, never a failure; no daemon string ever yields a permanent failure. | `reconcile_all`, `verify_and_bind`, `classify_submit_error` (`light/outbox.cpp`) | `selftest-outbox-core` 1, 3, 4, 5 (head ≠ final), 5b (a stale served block is refused by the binding and re-arms), 5c (an unverifiable probe never yields CONSUMED), 6, 11 (a proven skip is never APPLIED), 12 (attribution withheld until every alternate verifies), 13 (an orphaned body with the nonce spent → CONSUMED, then upgraded); `selftest-outbox-classify`; live 1, 5 |
| **OB-4** Recovery without loss or duplication | Every command reloads the records; UNKNOWN and SUBMITTED slots are re-sent (identical bytes — F3 makes that idempotent); a lost reply ends the submit run so no later slot is classified from a desynchronised stream. A recorded inclusion is re-verified directly on every pass: when the successor binds a different block, or the served body does not chain into the committee-signed successor, the slot re-arms (a SUBMITTED slot whose head inclusion vanished simply re-sends on its cadence). A skip is counted once per canonical inclusion (not per pass; a re-issue starts a fresh budget without re-counting the earlier alternate's inclusion) and re-arms only while the verified balance covers amount+fee and at most `MAX_SKIPS` times; a spent nonce is never re-armed (a re-send could only be stale); a stale nonce is resolved by reconcile; a corrupt status section is rebuilt as UNKNOWN, a corrupt immutable section is quarantined with its nonce still reserved, an unreadable `outbox.meta` is rebuilt from an intact record (its nonce floor is lost: rebuilt as 0, which only loses a refusal); FINALIZED/APPLIED and CONSUMED slots are never re-stamped. Nothing is removed except by `prune`. | `Outbox::load`, `submit_due`, `reconcile_all`, `cmd_recover` | core 2b, 3, 3b, 3c, 3d, 4, 5, 5b, 10, 13; `test_light_outbox.sh` D; live 2, 3 |
| **OB-5** Bounded storage, never silent eviction | `--max-messages` (default 256, hard max 4096) is checked before any write; a write failure (ENOSPC path) leaves no record and no ack; accepted slots are never evicted; `prune` removes only slots whose nonce is **proven** consumed (FINALIZED/APPLIED, or CONSUMED with `--include-unlocated`) and bumps `nonce_floor` durably before removing the file, then drops quarantined files below the floor (sequential nonces: everything below it is consumed); an explicit `--nonce` below the floor is refused, so a pruned nonce can never be re-reserved. The nonce hint at enqueue is the committee-verified `next_nonce` (`read_account_trustless`), never the daemon's bare word, so no daemon can steer a reservation above what the chain will reach. A reused `--idempotency-key` is refused with the slot's existing identity (exit 8), so a caller retrying after a crash between the publish and the acknowledgement learns what it already holds. | `cmd_enqueue`, `cmd_prune` | `test_light_outbox.sh` E, G, H; live 1 (verified hint), 5 |
| **OB-6** Concurrency | Mutating verbs hold an exclusive `fcntl(F_SETLK)` / `LockFileEx` lock on `outbox.lock` (released by the OS on death; same-host only); a locked-out worker exits 5 without writing; a new slot is published with create-new semantics; `status` is lock-free, read-only and never deletes (on Windows it opens records with `FILE_SHARE_DELETE`, so a concurrent replace never hits a sharing violation). | `Lock`, `durable_write_new`, `cmd_status`, `read_file` | `test_light_outbox.sh` F (through the binary's own lock path on every platform); live 6 |

Falsify-on-mutant record (each mutant applied alone; every one turned `test_light_outbox.sh` RED on
2026-09-16): M1 ack printed before the publish → B; M2 record hash checks skipped → D + selftest-outbox-record;
M4 "incumbent" classified as a rejection → classify + core 2; M5 an inclusion beyond the verified index marked
FINALIZED → core 5; M5b the successor binding skipped inside `verify_and_bind` → core 5b; M6 APPLIED on
inclusion without the nonce proof → core 3; M7 the cap checked after the write → E; M8 prune removing a
non-terminal slot → H; M9 the temp-file fsync removed → C; M10 a skip counted per reconcile pass → core 3b;
M11 the submit run continuing after a lost reply → core 2b; M12 an unverifiable probe not blocking a terminal
verdict → core 5c; M13 the once-per-inclusion test made after `finalized_height` moves to the new inclusion (a
later skipped inclusion never counted, the cap unreachable) → core 3c and every APPLIED leg; M14 a proven-skipped
inclusion attributed APPLIED → core 11; M15 a spent nonce attributed with an alternate's probe unanswered → core
12; M16 the orphan re-arm applied to a spent nonce → core 13; M17 CONSUMED never probed again → core 13 (no
upgrade); M18 the once-per-inclusion test also requiring a counted skip (a re-issue re-counts the earlier
inclusion) → core 3d. A "retry re-signs with a fresh nonce" mutant is not expressible: the submit core holds no
key (OB-2 is structural), and core 2/3 pin the re-sent hash.

## 3. Assumptions

- **A1 single signer.** The outbox directory is the only signer for its key while any slot is non-terminal.
  Violated (another wallet, a second outbox for the same key), a nonce can be consumed by foreign bytes; the
  outbox reports STALE then CONSUMED/UNLOCATED (live gate 5); an inclusion the record has proven SKIPPED is
  never re-labelled APPLIED when foreign bytes later spend the nonce (core 11).
- **A2 daemon negatives are untrusted.** Every positive (inclusion, finality, nonce, balance — including the
  nonce hint at enqueue) is committee-verified through the existing readers; "not found" is the daemon's word
  and is labelled as such, and a CONSUMED slot is re-examined on every pass so a better daemon can still
  locate the applying bytes.
  The genesis pin at every network command recomputes the served block 0 (`pin_daemon_genesis`), a guard
  against an honest misconfiguration, not a substitute for chain binding in the signed bytes (F1).
- **A3 inherited from the readers.** The static genesis committee (`build_genesis_committee`, no
  `--track-registry`), S-033 `state_root` active, timer-driven blocks (`--wait` bounded), and the open residuals
  R-1 (cross-round double-sign) and R-4 (`2K > N(h)`) — a successor-bound block is final exactly to the extent
  the K-of-K rule holds.
- **A4 environment.** The storage stack honours fsync (`F_FULLFSYNC` on Darwin); the outbox directory is on a
  local filesystem (the lock's semantics are same-host; hard-link-less filesystems get the lock-guarded
  existence check + rename); one outbox directory per key.

## 4. Delivery semantics and non-claims

Transport to a daemon is at-least-once (identical bytes). Ledger application is at-most-once per nonce (F5/F6),
and exactly-once **iff** the slot reaches FINALIZED/APPLIED — liveness is not guaranteed (partition, consensus
stall, underfunding, a validator-rule eviction the daemon never reports, F3/F4). Consumer receipt is not a
property of this increment: every canonical inclusion is observable through `dapp_messages` / `dapp_subscribe`
(F7), but nothing here proves a consumer acted on it. No exactly-once end-to-end claim is made. A released
transaction cannot be cancelled or expired (F1/F4): `replace` can only add a competing alternate at the same
nonce. The wire carries no chain identifier; a signed tx is valid on any chain where (from, nonce) matches — a
consensus/wire change outside this increment (pre-genesis only, no-migrations).

Consumer obligations (a DApp or any reader of `dapp_messages` / `dapp_subscribe`): **C1** a delivered frame
proves inclusion in a committee-signed block — not payment, not application (S-063); read value effects from
verified state. **C2** deduplicate persistently by `tx_hash`, not only by `(block_index, tx_index)`: one hash can
be included twice (F6). **C3** commit the dedup marker atomically with the business effect or make the effect
idempotent on `tx_hash`; a crash between effect and marker is re-delivered on reconnect. **C4** redial with
`--since` and expect overlap. **C5** a frame from the head block is not canonical until a committee-signed
successor binds it (F10), and `(block_index, tx_index)` can be reused with different content after a
same-height reorg.

## 5. Interface (exit codes)

`outbox enqueue|submit|reconcile|status|replace|prune|recover` — 0 ok; 1 error (nothing acknowledged; also a
load/decode/write error on any verb); 3 a slot or `outbox.meta` is CORRUPT / a reconcile leg UNVERIFIABLE; 4
outbox full; 5 locked; 6 wrong chain or sender; 7 daemon configuration (HMAC required, non-Determ daemon); 8 the
`--idempotency-key` is already held (its slot is printed; nothing written). Steady state: a
loop of `submit; reconcile` (re-send cadence 60 s per SUBMITTED slot, backoff min(300 s, 2·2ⁿ) on rejections;
a lost reply ends a submit run early). `reconcile --wait` re-reads at most twice when the trustless read's
cleartext cross-check races a block that touched the sender (DECISION-LOG 2026-09-16 F-4) and otherwise exits
1 on it. Test seams, all environment-gated and documented in `outbox.hpp`: `DETERM_LIGHT_OUTBOX_CRASH_POINT`,
`DETERM_LIGHT_OUTBOX_INJECT=write_fail|drop_response`, `DETERM_LIGHT_OUTBOX_HOLD_LOCK_S`,
`DETERM_LIGHT_OUTBOX_TRACE`.
