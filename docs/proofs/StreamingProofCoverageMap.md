# StreamingProofCoverageMap — verification-coverage map for the v2.20 streaming subsystem

> **Status: coverage map (R55) — verification status of the v2.20 streaming-subsystem claims.**

This document is a **completeness critic** over the v2.20 streaming subsystem (R53
`dapp_subscribe` delivery + R54 `dapp_subscribers` observability). For **every** claim the
subsystem's two proofs assert — `StreamingSubscriptionSoundness.md` (SS-1..SS-6) and
`StreamingObservabilityReadOnly.md` (SO-1..SO-4) — it states, honestly, **how** that claim is
verified: machine-checked in TLA+, argued in prose with a code citation, exercised by a live
regression, or composed from another proof. Its purpose is to let an auditor see at a glance
what is **proven** versus what is **asserted**, and which claims are prose-only — future
machine-check candidates.

This map **references and classifies**; it does not restate the claims. Read the two source
proofs for the arguments; read the TLA modules for the checked invariants; read the regression
for the runtime assertions. The rows below only say, per claim, **where** its verification
lives and **what kind** it is.

**Scope and honesty note.** The streaming subsystem's guarantees are **systems arguments**
(lock ordering, single-writer discipline, bounded queues, gate ordering), not cryptographic
reductions — v2.20 adds no new primitive, no consensus change, no chain-state change. Exactly
TWO components are exhaustively machine-checked: the per-subscriber backpressure/kill protocol
(**FB71** `tla/SubscriberBackpressure.tla`) and the catch-up/live **partition** (SS-2) via
**FB72** `tla/SubscriberCatchupPartition.tla` (R55 — TLC-green, 1346 distinct states; the
non-atomic-capture mutant falsifies INV_NoGap with the gap-at-N trace). Everything else is
prose+code or composed. This document does not overclaim: a claim is listed as machine-checked
**only** where a `.tla` module at HEAD checks it.

**Companion documents.** `StreamingSubscriptionSoundness.md` (SS-1..SS-6 — the delivery
contract being mapped); `StreamingObservabilityReadOnly.md` (SO-1..SO-4 — the observability
read being mapped); `tla/SubscriberBackpressure.tla` (FB71 — the machine-checked backpressure
companion); `tla/SubscriberCatchupPartition.tla` (FB72 — the machine-checked SS-2 partition
companion, R55); `tools/test_dapp_subscribe.sh` (the live regression); `docs/proofs/README.md` (the
proofs index whose FB/companion tables this map's classifications mirror);
`OperatorToolingReadOnly.md`, `S014RateLimiterSoundness.md`, `RpcAuthHmacSoundness.md`
(the proofs SO-1 / SS-5 compose); `docs/V2-DESIGN.md` §v2.20 (the source spec).

---

## §1. Verification-method legend

Each claim below is tagged with exactly one **primary** method (and, where applicable, the
proof(s) it composes). The four methods:

- **TLA-machine-checked FB##** — a TLC-checked `.tla` module at HEAD asserts an invariant that
  is the machine form of the claim. Exhaustive over the module's small scope, with recorded
  non-vacuity (falsify-on-mutant) probes.
- **prose+code-cite** — a design argument in the source proof, pinned to `src/` files by name
  (no line numbers, per the streaming-family citation discipline). Not machine-checked; its
  soundness rests on the argument plus the cited code matching it.
- **regression-test** — a runtime assertion in `tools/test_dapp_subscribe.sh` exercises the
  live behavior end-to-end on a 3-node cluster.
- **composed-from &lt;proof&gt;** — the claim is discharged by consuming a theorem from a
  companion proof, not re-proved here.

A claim may carry more than one method: e.g. SS-1 is **prose+code** for the structural argument
**and** partially **TLA-machine-checked** (FB71's seq-monotonicity arm) **and**
**regression-tested** (the live `seq`-contiguity assertion). The table names the primary method
and lists the corroborating ones in Evidence.

---

## §2. Coverage table — SS-1..SS-6 (delivery contract)

| Claim | Statement (one line) | Verification method | Evidence |
|---|---|---|---|
| **SS-1** | Per-connection `seq` is `0,1,2,…` gapless-or-dead; single writer stamps `seq`, no cross-thread assignment. | prose+code-cite **+** TLA-machine-checked (FB71) **+** regression-test | `StreamingSubscriptionSoundness.md` SS-1 (P-2 single-writer argument, `src/node/node.cpp` `subscriber_session`); FB71 `tla/SubscriberBackpressure.tla` `INV_NoSilentGap` (wire-`seq` arm: `seqCtr = Len(delivered)` and `delivered[i].seq = i-1`); `tools/test_dapp_subscribe.sh` (live `seq` contiguous 0..3 + stable `sid`). |
| **SS-2** | Catch-up `[since, H)` ∪ live `[H, ∞)` partitions the event space — no gap, no overlap; `H` captured atomically with registration under `state_mutex_`. | **TLA-machine-checked FB72** (R55) **+** regression-test | `StreamingSubscriptionSoundness.md` SS-2 (P-1/P-3 atomic capture-and-register, `src/node/node.cpp` `rpc_dapp_subscribe` + `on_block_finalized_for_subscribers`); `tla/SubscriberCatchupPartition.tla` (FB72 — INV_NoGap / INV_NoOverlap, the non-atomic-capture mutant falsifies INV_NoGap); `tools/test_dapp_subscribe.sh` (catch-up replay `subscribed → dapp_call → live`, seq 0..2, and the SS-2 gap-freedom cross-check: streaming catch-up == `dapp-messages` poll). |
| **SS-3** | Kill-vs-drop: a live connection is `seq`-contiguous or observably dead; silent frame loss is impossible. | TLA-machine-checked (FB71) **+** prose+code-cite | FB71 `tla/SubscriberBackpressure.tla` `INV_NoSilentGap` + `INV_KillOnOverflow` + `INV_KilledFailClosed` (+ M1 drop-oldest mutant falsifies, non-vacuity); `StreamingSubscriptionSoundness.md` SS-3 (enqueue case analysis, `src/node/node.cpp` kill path). Backpressure-kill is **not** triggered live in the regression (see §5). |
| **SS-4** | Bounded resource envelope: `SUBSCRIBER_MAX_PER_NODE × SUBSCRIBER_BYTES_MAX = 256 × 16 MiB = 4 GiB` worst case + operator levers. | prose+code-cite | `StreamingSubscriptionSoundness.md` SS-4 (per-growth-site enforcement argument); `docs/V2-DESIGN.md` §v2.20 constants table. The product arithmetic itself is **prose only** — not modeled (FB71 abstracts the byte cap to a frame count and models one subscriber; the global-product bound is out of its scope). |
| **SS-5** | Every pushed frame is causally preceded by a subscribe that passed S-014 consume then S-001 HMAC verify; no unauthenticated frame path. | prose+code-cite **+** composed-from `S014RateLimiterSoundness.md`, `RpcAuthHmacSoundness.md` | `StreamingSubscriptionSoundness.md` SS-5 (P-4 gate ordering, `src/rpc/rpc.cpp` `handle_session`); composes T-1/T-2/T-3 and the S-001 closure. The gate-**ordering** argument is prose; `tools/test_dapp_subscribe.sh` exercises validation refusals (unknown domain / since-beyond-head, normal error envelope, no takeover) but not the auth-ordering itself. |
| **SS-6** | Reconnect: no matching event is lost across a disconnect+reconnect seam (client redials with `since = last_block` INCLUSIVE, dedups by `(block_index, tx_index)`). Plus the non-claims: node trusted for content, payload confidentiality unchanged, heartbeat timing public. | reconnect no-loss → **TLA-machine-checked FB73** (R56) **+** regression-test; the non-claims → prose+code-cite / composed-from `V2-DAPP-DESIGN.md` §10 | `StreamingSubscriptionSoundness.md` SS-6; `tla/SubscriberReconnectSeam.tla` (FB73 — INV_NoLoss / INV_NoDup; the EXCLUSIVE-since mutant falsifies INV_NoLoss, validating the inclusive-since decision `src/main.cpp` `eff_since = last_block`); `tools/test_dapp_subscribe.sh` (`--since B` inclusive / `--since B+1` exclusive boundary). The payload-confidentiality / node-trusted arms remain **boundary statements** (nothing to machine-check), payload posture inherited from `V2-DAPP-DESIGN.md` §10. |

## §3. Coverage table — SO-1..SO-4 (observability read)

| Claim | Statement (one line) | Verification method | Evidence |
|---|---|---|---|
| **SO-1** | `dapp_subscribers` is chain-state read-only — no mutation, never takes `state_mutex_`; joins the READ set, tool inherits OT-1/OT-2. | prose+code-cite **+** composed-from `OperatorToolingReadOnly.md` | `StreamingObservabilityReadOnly.md` SO-1 (Q-2 no-mutation argument, `src/node/node.cpp` `rpc_dapp_subscribers`); composes OT-1/OT-2 (READ-set membership + tool inheritance). |
| **SO-2** | Non-perturbing: reading `queue_depth`/`seq`/`killed` neither dequeues nor re-`seq`s nor reorders; writer stays sole mutator (SS-1 preserved). | prose+code-cite **+** composed-from `StreamingSubscriptionSoundness.md` (SS-1, SS-3) | `StreamingObservabilityReadOnly.md` SO-2 (Q-2 reader-appends-nothing argument, `src/node/node.cpp` `rpc_dapp_subscribers` vs `on_block_finalized_for_subscribers`); relies on SS-1's single-writer P-2 and SS-3's writer/hook-owned kill. |
| **SO-3** | Lock-ordering safety: reader takes `subscribers_mutex_` → `Subscriber::mu`, strictly below `state_mutex_`, never up-locks — deadlock-free. | prose+code-cite | `StreamingObservabilityReadOnly.md` SO-3 (Q-1/Q-3 wait-for-graph argument vs hook/writer/subscribe). **Prose reasoning, not a modeled deadlock-freedom proof** — no TLA lock-order model exists for the reader; the argument is an informal no-reverse-pair check (see §5). |
| **SO-4** | Disclosure boundary: exposes only operator-facing roster/backpressure metadata; no `DAPP_CALL` payload plaintext; S-001-gated; non-claim: live snapshot, not a linearizable instant. | prose+code-cite **+** composed-from `docs/SECURITY.md` §S-001, `V2-DAPP-DESIGN.md` §10 | `StreamingObservabilityReadOnly.md` SO-4 (field-by-field schema argument, response schema §1.1); HMAC gate composed from §S-001; payload-privacy from §10. `tools/test_dapp_subscribe.sh` asserts the observability snapshot shape (count/max/`kills_backpressure`, per-row `sid`/`queue_max`/`killed`) but not the disclosure boundary. |

---

## §4. Machine-checked vs prose-only summary

**Machine-checked (a `.tla` companion at HEAD or landing R55):**

- **SS-1** (writer-`seq` monotonicity arm) and **SS-3** (kill-vs-drop, in full) → **FB71**
  `tla/SubscriberBackpressure.tla`. FB71 exhaustively checks `INV_NoSilentGap`,
  `INV_BoundedQueue`, `INV_KillOnOverflow`, `INV_KilledFailClosed` plus three temporal
  properties over the producer/writer/adversarial-client interleavings, with recorded
  falsify-on-mutant non-vacuity (drop-oldest → `INV_KillOnOverflow` falsifies; no-bound →
  `INV_BoundedQueue` falsifies; two reachability probes falsify as designed).
- **SS-2** (catch-up/live partition) → **FB72** `tla/SubscriberCatchupPartition.tla` (R55).
  TLC-green (1346 distinct states, depth 11): `INV_NoGap` (every matching index in `[since, head)`
  is catch-up-replayed ∪ live-enqueued — no missed events) + `INV_NoOverlap` (the boundary `H` is
  covered by exactly one side — exactly-once) + `INV_HeadMonotone`, with the temporal
  all-eventually-delivered property. Falsify-on-mutant non-vacuity: the non-atomic
  capture-then-register mutant falsifies `INV_NoGap` with the concrete gap-at-`H` trace (the race
  the shared-before-unique `state_mutex_` discipline prevents); an inclusive catch-up bound
  falsifies `INV_NoOverlap`.

**Prose+code (design argument pinned to `src/`, not machine-checked):**

- **SS-4** (resource-envelope arithmetic — the `256 × 16 MiB` product bound; FB71 abstracts the
  byte cap to a frame count and models a single subscriber, so the global product is prose).
- **SS-5** (auth/rate-limit **ordering** — gate sequence in `handle_session`; the limiter and
  HMAC soundness are composed, the *ordering* is argued).
- **SS-6** reconnect no-loss → **FB73** `tla/SubscriberReconnectSeam.tla` (R56): the cross-reconnect
  seam is machine-checked (INV_NoLoss + the EXCLUSIVE-since mutant validating the inclusive-since
  choice). The remaining SS-6 arms (node-trusted-for-content, payload confidentiality) are boundary
  statements, not positive properties.
- **SO-1, SO-2, SO-4** (read-only / non-perturbing / disclosure — Q-1..Q-4 systems arguments;
  SO-1/SO-2/SO-4 each compose a companion theorem but the streaming-reader-specific step is
  prose).
- **SO-3** (lock-ordering / deadlock-freedom — **prose reasoning over the wait-for graph, not a
  modeled deadlock-freedom proof**).

**Regression-tested (live assertions in `tools/test_dapp_subscribe.sh`):**

- SS-1's `seq`-contiguity + stable `sid` (live subscribe: `subscribed → live → heartbeat`,
  seq 0..3);
- SS-2's catch-up replay ordering (`subscribed → dapp_call → live`, seq 0..2) and the topic
  filter (chat call invisible to a `--topic rpc` subscription);
- SS-5's validation-refusal path (unknown domain / since-beyond-head ride the normal RPC error
  envelope, socket not taken over, exit 2) and the `queue_max` server-side clamp echo;
- SO-1/SO-4's observability snapshot shape (`dapp-subscribers` reflects the live subscriber
  fleet: count/max/`kills_backpressure`, per-row `sid`/`queue_max`/`killed`).

---

## §5. Gaps / future machine-check candidates (honest)

This is the completeness-critic's list of what is **argued but not exhaustively checked**. None
of these is a known defect — they are the boundary between proven and asserted.

1. **SS-2 partition — machine-check CLOSED (R55).** The atomic capture-and-register /
   no-gap-no-overlap partition — the streaming feature's central "no missed events" guarantee —
   is now machine-checked by **FB72** `tla/SubscriberCatchupPartition.tla` (TLC-green, 1346
   distinct states). Its non-vacuity mutant (non-atomic read-then-register → a gap at index `H`)
   falsifies `INV_NoGap` with the exact race the shared-before-unique `state_mutex_` discipline
   prevents. *Closed by FB72 (R55) + the `test_dapp_subscribe.sh` gap-freedom cross-check.*

2. **SS-3 backpressure-kill is machine-checked but NOT live-triggered.** FB71 exhaustively
   checks the kill protocol, but `tools/test_dapp_subscribe.sh` deliberately does **not** drive
   an organic queue overflow (it would require saturating the TCP send buffer — tens of
   thousands of frames at test block rates). The kill/write-timeout paths are exercised only
   incidentally at node-shutdown in cleanup. *Candidate: a targeted slow-consumer overflow
   regression (deterministic backpressure trigger) to corroborate FB71 at runtime.*

3. **SS-4 resource-envelope arithmetic is prose.** The `256 × 16 MiB = 4 GiB` product bound is
   argued per-growth-site, not modeled: FB71 abstracts the 16 MiB byte cap to a frame count and
   models one subscriber, so neither the byte-ceiling arm nor the global `SUBSCRIBER_MAX_PER_NODE`
   multiplication is machine-checked. *Candidate: a multi-subscriber admission/envelope model
   (or a two-ceiling enqueue arm in FB71).*

4. **SS-5 auth-ordering is prose.** The gate **sequence** (S-014 consume → S-001 HMAC verify →
   dispatch → takeover-last) is argued from `handle_session`, not modeled; the limiter (T-1/T-2/T-3)
   and HMAC (S-001 closure) soundness are composed, but their *ordering* relative to the streaming
   takeover is not a checked invariant. *Candidate: an RPC-admission-ordering TLA module (a
   sibling `RpcAdmissionOrdering.tla`, noted in FB71's cross-references as out-of-scope).*

5. **SO-3 lock-ordering / deadlock-freedom is prose reasoning, not a modeled proof.** The
   three-lock order `state_mutex_ → subscribers_mutex_ → Subscriber::mu` and the reader's
   bottom-two-levels-only, no-up-lock discipline are argued as a no-reverse-pair wait-for-graph
   check, not verified by a deadlock-freedom model. *Candidate: a lock-order TLA model covering
   reader/hook/writer/subscribe (would also strengthen SS-2's P-1 premise).*

6. **SO-4 cross-subscriber non-linearizability is a documented non-claim, not verified.** The
   report is a best-effort per-row scan; that it is a freshness caveat (never a safety one) is
   argued in prose. *Not a machine-check candidate — it is a deliberate limitation, listed for
   completeness.*

**Bottom line.** Of the ten claims, **SS-1 (partial) and SS-3** are machine-checked at HEAD
(FB71); **SS-2** is machine-checked as of R55 (FB72, in parallel); the remaining seven are
prose+code, four of them composing a checked companion. The live regression corroborates the
`seq`/`sid`/catch-up/topic-filter/observability surfaces but not the backpressure-kill, the
resource product bound, the auth ordering, or the lock ordering — those are the honest
prose-only frontier and the standing machine-check candidates above.

---

## §6. References

### Mapped proofs (sources of truth — classified here, not restated)
- `StreamingSubscriptionSoundness.md` — SS-1..SS-6, the v2.20 (R53) `dapp_subscribe` delivery
  contract.
- `StreamingObservabilityReadOnly.md` — SO-1..SO-4, the R54 `dapp_subscribers` read-only
  observability note.

### Machine-checked companions
- `tla/SubscriberBackpressure.tla` (FB71) — kill-on-overflow / no-silent-gap / stuck-writer
  release; the machine form of SS-3 and SS-1's `seq`-monotonicity arm.
- `tla/SubscriberCatchupPartition.tla` (FB72) — the catch-up/live partition; the machine form
  of SS-2, authored in parallel this round (R55).

### Regression
- `tools/test_dapp_subscribe.sh` — the live 3-node regression (subscribe / heartbeat / seq /
  sid / catch-up replay / topic filter / `dapp-subscribers` observability).

### Composed companions
- `S014RateLimiterSoundness.md` (T-1/T-2/T-3), `RpcAuthHmacSoundness.md` — composed by SS-5.
- `OperatorToolingReadOnly.md` (OT-1/OT-2) — composed by SO-1.
- `V2-DAPP-DESIGN.md` §10 — payload-privacy posture inherited by SS-6 / SO-4.
- `docs/SECURITY.md` §S-001 (HMAC auth), §S-014 (rate limiter) — the gates SS-5 / SO-4 compose.

### Spec + index
- `docs/V2-DESIGN.md` §*v2.20 — Streaming subscription RPC* — the source spec.
- `docs/proofs/README.md` — the proofs index whose FB/companion status columns this map mirrors.

### Implementation sites (file + function; lines intentionally unpinned)
- `src/node/node.cpp` — `rpc_dapp_subscribe`, `on_block_finalized_for_subscribers`,
  `subscriber_session` (delivery), `rpc_dapp_subscribers` (observability).
- `src/rpc/rpc.cpp` — `handle_session` (gate ordering + dispatch + takeover).
