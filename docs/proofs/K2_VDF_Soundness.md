# K2_VDF_Soundness — C99 experiment contracts and consensus blockers

**Status:** Current implementation contract; no production-consensus security proof.
**Correction date:** 2026-09-22. The former zero-bias, absolute-liveness and unique-block
theorems in this file are withdrawn for the counterexamples below. Their presence in
an earlier revision was not evidence that the C99 node implemented those properties.
The append-only [Decision Log](DECISION-LOG.md) records the correction and its scope.

## 1. Implementation boundary

There are two implementations in this repository. The `determ` CMake target still
builds the C++ chain/node. The C99 `determ-node` executable is an experimental pair
computation and networking harness. It does not implement authenticated membership,
producer election, validated block admission, transaction execution on accepted
blocks, branch adoption, or durable reorganization. Its output is not a finalized
ledger block. The C++ consensus proofs do not establish properties of the C99 path.

The C99 evaluator in `src/crypto/vdf.c` is a custom AES/SHA-256 computation with a
64 KiB arena. `vdf_verify` repeats evaluation. It is not a Wesolowski/Pietrzak
construction or a succinct proof verifier. No reduction establishes sequential
hardness, ASIC resistance, or a hardware-independent minimum duration. Iteration
counts and local benchmarks cannot supply such a proof.

## 2. Refuted claims

**R1 — enforced blindness against a colluding pair.** Both participants know both
payloads before starting the local timer. They can evaluate candidates before
publishing commitments and choose one. A deadline measured after that work does not
erase knowledge. Independent candidates may also be evaluated concurrently. Hash
commitment binding is not a proof of output unpredictability or unbiasedness.

**R2 — absolute liveness.** A strict two-reveal rule cannot produce a successful
result when either required participant remains silent. A timeout can terminate a
local attempt with failure. It cannot make the missing reveal exist. Explicit retry
does not guarantee a successful retry or elect a replacement participant.

**R3 — unique canonical block.** A signer can authenticate two different messages
without breaking signature unforgeability. A unique output for one input does not
imply unique inputs or agreement between nodes seeing different histories. Comparing
supplied integers is not authenticated branch validation, adoption, or convergence.

**R4 — economic exclusion of grinding.** ADR-004's argument needs a proved bound on
honest chain growth relative to adversarial growth. No such bound follows from an
exclusive pair, undefined eligibility, or unvalidated iteration totals. This remains
an open proof obligation, not a replacement proof for R1 or R3.

## 3. Retained local-attempt contract

The supported unit is one caller-started local attempt with an Aggregator and a
Contributor. Role names identify slots, not authenticated identities.

1. Starting an attempt clears commitments, reveals and result state. Commitments
   are SHA-256 of exact payload bytes. Each role commits at most once.
2. Both commitments are required before entering the reveal phase. Either role
   commitment is accepted only before 1,000 ms from the attempt start.
3. Reveals must be nonempty, within the 65,536-byte role limit, hash to the stored
   role commitment, and arrive before 2,000 ms from the same attempt start. A
   caller-supplied validity flag cannot authorize a mismatched opening.
4. Two valid reveals produce `BE32(len_A) || A || BE32(len_B) || B`. One reveal
   never produces a successful two-party evaluation. Polling after the applicable
   deadline returns terminal failure for missing input.
5. Networking and the CLI propagate terminal failure. A library caller may start
   another local attempt explicitly; this is not committee rotation, global liveness,
   consensus recovery or an authenticated global round-number protocol.
6. The Aggregator evaluates the assembled input at the fixed prototype work count
   and sends a 32-byte output. The Contributor reports receipt of unauthenticated
   bytes after the reveal-window message; it does not receive the Aggregator reveal
   or independently recompute that output. Receipt is not proof of successful remote
   evaluation. Neither endpoint credits a ledger, finalizes a height, or persists
   that output as a validated block.

Deadlines are checked when the caller polls or submits input, under a monotonic
clock and a regularly serviced event loop. They are not authenticated time facts
about a remote peer. Commitments do not bind an authenticated session, chain, parent,
height, shard or membership snapshot. This transport is unsuitable for adversarial
production deployment until those rules are designed and verified.

**Binding argument (local state-machine ingress).** A different accepted opening to one commitment must have the
same SHA-256 digest, requiring a collision/second preimage. This is a payload-binding
claim only: it proves neither peer identity nor low-entropy payload secrecy, and a
malicious committer can still abort.

**Assembly bound.** Each accepted payload is at most 65,536 bytes, so the framed
input is at most 131,080 bytes. The surviving bundler checks role limits, pointer/length
consistency and output capacity before writes. Establishing the bound before adding
framing overhead prevents 32-bit `size_t` overflow.

## 4. Deterministic difficulty helper

The DDA helper is a function of supplied predecessor history, not a C99 network
block-acceptance rule. Its caller must supply contiguous, independently validated
same-branch millisecond timestamps and work, and restore the tracker on reorganization.

It holds eleven timestamps for ten intervals. Zero is a valid first anchor. With
fewer than two timestamps the average is the 3,000 ms target; otherwise it is
`(newest - oldest) / (timestamp_count - 1)`, saturated to the return type. Calibration
increases work by 50% below target and decreases it by at most 5% above target,
within the existing iteration bounds.

Recording a header checks its work against the expectation derived from unchanged
predecessor state and requires a strictly increasing timestamp. Failure changes no
state. Success appends the timestamp and accepted work. Identical supplied histories
therefore produce identical expectations. This does not prove timestamp honesty:
monotonically inflated producer timestamps can drive difficulty down. Timestamp-validity
rules, proof validation and chain ingestion are prerequisites for production use.

## 5. Portable clock arithmetic

QPC conversion computes `floor(ticks * 1,000,000,000 / frequency)`, saturated at
`UINT64_MAX`; zero frequency returns zero. The portable implementation avoids
intermediate overflow; the Windows clock calls the same tested helper. Saturation
prevents wraparound, but does not extend the representable lifetime of a nanosecond
counter or establish global synchronization.

## 6. Removed surfaces and remaining blockers

The unused stream bundler is removed; the bounded bundler remains. The socket-byte
evidence predicate, empty polling loop, slashing flag and unvalidated fork-choice
helpers are removed. None had a production consensus caller. No evidence verification,
slashing, authenticated broadcast or secure fork choice is claimed as a replacement.
The existing C++ evidence path is unaffected.

Production PoSW requires decisions and proofs for authenticated membership and Sybil
resistance; prior-state-derived exclusive-pair eligibility, attempt timing, receiver
checks and recovery; canonical challenge/context binding; a delay construction and
explicit hardness assumptions; timestamp validity;
validated cumulative work; transaction/state validity; data availability; synchronization;
atomic branch adoption, persistence and recovery. The
[sharding design gate](../decisions/ADR-005-Temporal-Sharding.md) depends on these
obligations and cannot remove them by adding shard identifiers. The owner's VDF
election requirement delays knowledge of the next state-derived pair; it does not
supply an independent replacement proof or authorize that pair to act early.

## 7. Verification boundary

Run C99 checks through `tools/ci_local.sh --c99`, select targets with `--c99-test`,
and run isolated falsification through `--c99-mutants`. Build success must precede
execution of the selected binary. A failed build does not count as a rejected mutant.
Unsupported platform cases must be reported distinctly from passes.

These gates assert the local contracts above. They do not prove successful progress
against a withholding pair, global safety, finality, unbiased randomness, sharding
security, or production Windows networking. Independent review and recorded execution
results remain necessary; green tests cannot certify an unspecified protocol.

**Recorded execution (2026-09-22, Darwin arm64):** `ci_local --c99 --jobs 4` passed
16 targets after a successful build; `--c99-mutants --jobs 4` rejected 18/18 isolated
mutants after successful fresh builds; `--docs-only` passed 16 guards. Source and
design review were independent of test color. These results establish only the
stated checks; Linux/Windows runtime and the C++ FAST suite were not run in this pass.

## 8. C99 ledger self-transfer contract

The standalone ledger is not connected to C99 network block acceptance. For a
validated self-transfer with amount `a`, fee `f`, starting balance `b` and fee
accumulator `F`, provided `F + f` is representable, apply writes `b - f`, the
transaction nonce, and `F + f`. The existing validation still requires the
representable gross debit `a + f <= b`. Conservation follows directly:
`(b - f) + (F + f) = b + F`. The receiver is the same account, so applying a
second receiver write would overwrite the debit and is forbidden. A maximum
balance self-transfer with zero fee succeeds without a spurious receiver-overflow
failure. A repeated nonce or insufficient gross balance rejects without mutation.

`test-triple-entry-ledger` checks these outcomes at `ledger_apply_tx`, including
full-state equality after rejection. Isolated mutations restore the aliasing bug,
charge the gross debit, or omit the nonce update. This closes the self-transfer
defect only; accumulated-fee overflow is addressed separately in §10. Portable
state/transaction root encoding still requires correction before broader claims.

## 9. C99 ledger nonce exhaustion

The transaction verifier rejects a sender nonce of `UINT64_MAX` before adding
one. For every smaller sender nonce `n`, `n + 1` is representable and is the only
accepted transaction nonce. The final `UINT64_MAX - 1` to `UINT64_MAX` transition
therefore remains valid, while wrapping to zero cannot reopen the nonce sequence.
Apply calls this verifier before any write. The signed boundary regression checks
both layers and bytewise unchanged state after rejected wrapped, repeated and stale
nonces. Its isolated mutant removes the exhaustion guard.

## 10. C99 accumulated-fee preflight

After transaction verification and before receiver registration or balance writes,
apply requires `fee <= UINT64_MAX - total_fees`. The subtraction is representable
for every accumulator value; the check ensures the subsequent addition cannot
wrap. This discharges §8's representability precondition for accepted transactions.
On failure no account is created and no state is changed. Exact fit and a zero fee
at an already maximal accumulator remain accepted if the transaction is otherwise
valid. The gate checks self, existing-recipient and new-recipient paths, including
full-state rejection snapshots and mutations removing or overrestricting the guard.
The standalone transaction verifier checks sender-local conditions; accumulated
fees are an apply-level condition, not a claim of complete block admission.

## 11. Bounded recovery model contract

The separate `sim/k2_recovery_model.c` receiver/replayer exercises one common anchor,
at most eight candidate records, four transactions per candidate and four selected
blocks. It calls the real sender-signature verifier and `ledger_apply_tx`; pair
identity/authority and joint receipt are immutable trusted fixture facts. The
136-byte model header binds original-parent context and ordered canonical signing-byte
body commitment. It is not a production header, public DH proof or VDF construction.
The native ledger-root helpers are not used for this commitment.

The supported domain selects valid anchor children by distinct included transaction
count descending, then full fixed-width big-endian header value ascending. Subsequent
parents have at most one valid child. Conflicting root messages at the same
sender/nonce and ambiguous descendant branches return unsupported without publishing
partial state. Opposite input orders can remain different outside that domain;
these exclusions do not resolve the open production comparison rules.

Every candidate is replayed on its own immutable ancestry. Selected state is rebuilt
from the common anchor and published atomically; losing descendants are retained
under their original parents. Requeued omissions are deduplicated, individually
revalidated at the selected state and filtered by smaller data hash for ready
same-sender/nonce alternatives. Queue membership does not assert joint executability.
Journal replay reconstructs state in memory and invalidates preparations made before
restore; it does not implement durable filesystem recovery.

Given the same immutable fixtures and anchor, collision-free commitments for the
supplied data, a common finite input set within the arena bounds, eventual complete
delivery, no conflicting root bodies and unique valid descendants, original-parent
replay yields the same validity set. Deterministic root order and unique descendants
then yield the same selected history and ledger state. This is a conditional
finite-model argument, not a production convergence or reachability proof.
[DSF-SPEC §10.4](DSF-SPEC.md#104-bounded-c99-fork-recovery-model) gives the assumptions,
publication contract and test scope. `test-dsf-k2-recovery` includes fixed negative
and correction scenarios plus eight seeded delivery schedules, each run twice.
Independent arithmetic checks state; receiver/replayer mutants challenge the model
rules. Execution results require successful fresh builds through `tools/ci_local.sh`.
No seed coverage closes the outstanding cryptographic, timing, membership,
availability, complete-history or cross-shard proof obligations.
