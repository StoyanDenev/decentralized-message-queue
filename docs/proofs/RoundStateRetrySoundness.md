# RoundStateRetrySoundness — the S-047 round-state retry is consensus-invisible (safety) and delivers conditional progress under fair loss (liveness)

This document is the soundness proof for the S-047 fix (`docs/SECURITY.md` §S-047, shipped commit `a9ac214`): the one-shot consensus broadcasts that wedged a survivor cluster on a single missed message are replaced by a **periodic re-broadcast of the full stored round state** driven off the re-armed phase timers. The fix is `Node::rebroadcast_round_state_locked()` (`src/node/node.cpp:1245-1253`) plus the two re-arming handlers `Node::handle_contrib_timeout()` (`:1255-1297`) and `Node::handle_block_sig_timeout()` (`:1299-1352`). We prove two things: **(S)** the retry adds *zero* consensus-visible behavior — every relayed byte was already broadcast, author-signed, and is dropped by an existing receiver dedup path — and **(L)** under a fair-lossy link model the retry makes each round finalize or form a genuine abort quorum, i.e. the height advances. The liveness result is explicitly **conditional** (fair loss + a reachable quorum), not a claim under permanent partition of a quorum — that boundary is the designed S-044 / FA9 territory.

**Companion documents.** `AbortCascadeLiveness.md` (S-044/S-045) — the abort-claim quorum `abort_claim_quorum() = max(2, K−1)` (`include/determ/chain/params.hpp:140`) and the `aborts_gen` generation gate this retry re-uses; match its register. `S006ContribMsgEquivocation.md` — the S-006 contrib-equivocation detector whose false-positive-freedom under resend is proved in L-1.3 here. `Preliminaries.md` (F0) — assumption **A1** (Ed25519 EUF-CMA, §2.2), **A2** (SHA-256 collision resistance, §2.1), honest-validator clauses **H2** (single-sign per (height, gen)) and **H5** (gossip relay: a node re-broadcasts every message it verifies — the retry is a *scheduled* instance of H5). `UnderQuorumMerge.md` (FA9) + `docs/SECURITY.md` §S-044 — the permanent-partition boundary. `RealEngineFAHarness.md` + `docs/SECURITY.md` §S-047 — the `test-fa-liveness-virtual` failover harness that found the wedge (5/12 → 0 wedge-mode failures post-fix). `include/determ/net/timer_service.hpp:14-21` — the cancel-races-expiry window that makes the phase gate necessary. `docs/SECURITY.md` §S-048 — the minority-partition boundary of §4.

---

## 1. Model

### 1.1 Round state and the relay

At a fixed height the node holds three per-round message buffers, all cleared by `reset_round()` (`src/node/node.cpp:1857-1868`) and by block accept (`:1976-1979`):

- `current_aborts_` — the adopted `AbortEvent`s (chain-ordered; hash-chained per `AbortCascadeLiveness.md` §1.3);
- `pending_contribs_` — Phase-1 `ContribMsg`s, keyed by signer domain;
- `pending_block_sigs_` — Phase-2 `BlockSigMsg`s, keyed by signer domain.

`rebroadcast_round_state_locked()` re-emits **exactly** these buffers, in order: every abort event (`:1247-1248`), then every stored contrib (`:1249-1250`), then every stored block sig (`:1251-1252`). It constructs no new message: each `net::make_*` call re-serializes an object already resident in the buffer. It is invoked from both timeout handlers after the phase gate, alongside a re-arm of the same timer (`:1282-1286` Phase 1; `:1334-1338` Phase 2).

### 1.2 Message classes and their receiver admission

| Class | Author binding at receiver | Dedup / idempotency site |
|---|---|---|
| `AbortEvent` | each inline claim verified against the **claimer's** registered key (`:1467-1472`); quorum floor `abort_claim_quorum()` re-checked (`:1450-1451`, `:1474`) | `existing.event_hash == ev.event_hash` → `return` (`:1441-1442`) |
| `ContribMsg` | `make_contrib_commitment(msg)` verified against **signer's** key (`:2255`, `:2281-2282`) | keyed insert `pending_contribs_[msg.signer]` (`:2373`); a same-signer duplicate is diverted to the S-006 core-commit gate (`:2315-2371`) |
| `BlockSigMsg` | digest verified against **signer's** key (`:2420`, `:2458`); revealed secret checked vs Phase-1 commit (`:2471-2479`) | membership + keyed insert `pending_block_sigs_[msg.signer]` (`:2416-2418`, `:2481`); pre-phase arrivals bounded-buffered (`:2400-2407`) |

Every admission path first gates on `(block_index, prev_hash)` equal to the receiver's head (`:1436-1438`, `:2240-2243`, `:2413-2414`), so a relay that arrives at a peer already past this height is dropped as stale, not mis-applied.

### 1.3 Fair-loss link model

**Assumption FL (fair loss).** Each broadcast of a message `m` from an honest node to an honest peer is delivered independently with some probability `p > 0` per attempt, and delivery events across attempts are independent. Equivalently: a message that is re-attempted infinitely often is delivered infinitely often (a.s.). FL captures transient loss, reordering, and the height/generation transients of §3; it does **not** assume a synchronous bound, and it explicitly excludes a *permanent* cut (that is §3.4's boundary).

---

## 2. Safety — the retry is consensus-invisible

**Theorem T-1 (safety).** For every honest receiver, processing a retry-relayed message produces the same post-state as if the message had never been re-sent: no new digest is computed, no new signature is admitted, no `current_aborts_` / `pending_contribs_` / `pending_block_sigs_` entry changes value, and no equivocation evidence is fabricated. The retry therefore introduces no consensus-visible behavior. T-1 follows from L-1.1–L-1.5.

**Lemma L-1.1 (byte-identical resend).** Each relayed entry is a re-serialization of a *stored, already-broadcast, author-signed* message — not a re-sign. The relay reads the buffer object and calls the same `net::make_*` serializer used at original broadcast (`:1247-1252`); no field is recomputed and the author's `ed_sig` is copied verbatim. Hence the wire bytes, the message digest, and the signature are identical to the original. *No new signature is ever produced by the retry path* (contrast the claim path, which is separate — §2, L-1.5). ∎

**Lemma L-1.2 (dedup drops the resend).** A byte-identical resend reaching a receiver that already admitted the original is dropped on all three classes:
- **AbortEvent** — the receiver scans `current_aborts_` for `event_hash` equality and returns on match (`:1441-1442`). The `event_hash` is a function of the event's content (A2 collision resistance), so an identical resend collides and is idempotent.
- **ContribMsg** — insertion is a domain-keyed map write (`:2373`); a resend from an already-present signer takes the `existing != end` branch (`:2315`) and never overwrites with different content (L-1.3). A first-time delivery of a *previously lost* contrib is admitted normally — that is the intended healing, not a state change relative to the one-shot design's *intended* end-state.
- **BlockSigMsg** — same-signer resend re-writes `pending_block_sigs_[signer]` with the identical value (`:2481`); the map key makes it idempotent, and the per-signer buffer cap (`:2398-2407`) bounds pre-phase spam. ∎

**Lemma L-1.3 (no S-006 false positive).** A resent `ContribMsg` can never be mistaken for S-006 equivocation. On a same-signer duplicate, `on_contrib` compares the **v1 CORE commit** — `make_contrib_commitment(block_index, prev_hash, tx_hashes, dh_input)` — of the stored and incoming messages (`existing_core` at `:2338-2340`, `new_core` at `:2341-2342`) and only raises evidence when `existing_core != new_core` (`:2343`). For a byte-identical resend the two core commits are equal by construction (L-1.1), so the gate is false and the handler falls through to the idempotent `return` at `:2370`. Crucially the comparison is over the CORE commit and **not** the full F2-view-bound commit: the code comment at `:2328-2337` states that a member's F2 view of pool-fed inputs "legitimately VARIES across re-rounds at the same height … reconciled by intersection downstream, not equality here," so a receiver that refreshed its F2 view between rounds is not mis-flagged — the retry, which never mutates the stored core fields, is a fortiori safe. (This is the exact invariant `S006ContribMsgEquivocation.md` proves for genuine equivocation; the retry lives strictly inside its "identical core ⇒ no evidence" clause.) ∎

**Lemma L-1.4 (relaying others' messages cannot forge).** The relay re-emits messages authored by *other* nodes (a Phase-2 member re-sends the dead member's pre-death contrib, §3). This is sound because every class is verified at the receiver against its **author's** registered key, independent of who relayed it: abort-event claims against each claimer's key (`:1467-1472`), contribs against the signer's key (`:2281-2282`), block sigs against the signer's key (`:2458`). Under A1 (Ed25519 EUF-CMA) a relaying node that is not the author cannot alter any signed field without invalidating the signature, and an unsigned alteration to `(block_index, prev_hash)` is rejected by the head gate (§1.2). A Byzantine relay therefore gains nothing a plain peer lacks: it can re-deliver bytes that already exist, or withhold — neither forges consensus state. This is precisely the H5 gossip-relay contract of `Preliminaries.md`, exercised on a timer rather than on receipt. ∎

**Lemma L-1.5 (no stale-round leak).** The retry cannot leak a timer action into a later round. Each handler is phase-gated on entry — `handle_contrib_timeout` returns unless `phase_ == CONTRIB` (`:1259`); `handle_block_sig_timeout` returns unless `phase_ == BLOCK_SIG` (`:1310`) — and both the relay and the re-arm sit *after* that gate. The gate is required because `cancel()` may lose a race against an already-popped deadline (`include/determ/net/timer_service.hpp:14-21`, `:62-73`): a stale fire can land after its cancel. But every round-ending transition first moves `phase_` away from the gated value and cancels the timers: `enter_block_sig_phase` sets the phase and `contrib_timer_.cancel()` (`:975-976`), `try_finalize_round` `block_sig_timer_.cancel()` (`:1153`), `reset_round` sets `phase_ = IDLE` (`:1867`), and the block-accept path clears `current_aborts_` and cancels both timers before `reset_round` (`:1976-1979`). Hence a stale expiry that survives the cancel finds `phase_` no longer matching and returns at `:1259` / `:1310` before touching any state — and even the separately-emitted abort *claim* (not part of the relay) carries its own `(round, missing)` and is quorum-checked, so a stale claim cannot form a spurious event either. ∎

*Proof of T-1.* L-1.1 gives byte-identity and "no new signature"; L-1.2 gives idempotent admission on all three classes; L-1.3 rules out the one path (S-006) that could turn a resend into new evidence; L-1.4 shows relaying others' messages re-delivers but cannot forge; L-1.5 confines every timer action to its own round. Composing, the post-state after a retry equals the post-state without it. ∎

---

## 3. Liveness — conditional progress under fair loss

### 3.1 The one-shot wedge (why a retry is needed)

**Lemma L-3.1 (one-shot single-loss wedge).** Under the pre-fix one-shot design a *single* permanent loss wedges the round. Three modes were reproduced by `test-fa-liveness-virtual`'s failover phase (kill 1 of 5; `docs/SECURITY.md` §S-047):
1. **Lost claim volley.** The two live committee members' abort claims are lost/mistimed; both stay in `CONTRIB` forever — never `IDLE`, so `check_if_selected` never re-selects them — while off-committee nodes drop the claims on the in-committee guard. No timer re-emits, so the volley is never retried.
2. **Missed hash-chained abort event.** A member that misses one `AbortEvent` during a height/generation transient can never adopt later events: they hash-chain and committee-validate against the receiver's `current_aborts_` (`:1448-1474`), and the `aborts_gen` gate (`:2248`) then splits the members into different generations that mutually drop each other's contribs.
3. **Asymmetric death.** The crashing member's last contrib/sig reaches only some peers, splitting the two survivors across Phase 1 / Phase 2 so their claims land in different `(round, missing)` buckets and the `max(2, K−1) = 2` floor (`include/determ/chain/params.hpp:140`) can never assemble from two divergent claimers. ∎

### 3.2 The retry re-attempts every message

**Lemma L-3.2 (eventual delivery under FL).** While the round is unfinished the owning phase timer re-arms every period — `tx_commit_ms` in Phase 1 (`:1283-1286`), `block_sig_ms` in Phase 2 (`:1335-1338`) — and each fire calls `rebroadcast_round_state_locked()`, re-emitting the full stored round state (L-1.1). A member remains in its phase (and thus keeps re-arming) until the round finalizes or resets (L-1.5), so each stored message is re-attempted infinitely often as long as the round is open. By FL (§1.3) each such message is therefore delivered to each honest peer a.s. In particular the asymmetric-death contrib/sig held by a surviving Phase-2 member is re-seeded to the peers that missed it — healing mode 3 — and a generation-behind receiver adopts the abort tail sequentially (`:1247-1248` in chain order; each adoption re-derives the committee the next event's claimers were drawn from), healing mode 2. ∎

**Lemma L-3.3 (convergence to a common (phase, generation)).** Once (by L-3.2) every honest committee member has received every other member's stored contribs, block sigs, and abort events, all honest members hold the same `current_aborts_` (dedup by `event_hash`, L-1.2, makes adoption order-insensitive), hence the same `aborts_gen = current_aborts_.size()`, hence the same generation gate value at `:2248`; and each member that has all K contribs advances to Phase 2 (`:2375-2377`) while each with all K sigs finalizes (`:2490-2491`). The committee thus converges to a single `(phase, generation)` rather than remaining split. ∎

### 3.3 Conditional liveness

**Theorem T-2 (conditional round progress).** Assume FL (§1.3) and that a quorum of the current committee is honest and reachable (each member's messages are, by FL, infinitely-often delivered to each other member). Then the round makes progress: it either (a) finalizes — all K contribs converge (L-3.3), Phase 2 assembles the required sigs, and `try_finalize_round` appends the block, advancing the height — or (b) forms a *genuine* abort quorum — the `abort_claim_quorum()` floor of distinct honest claimers against a common `(round, missing)` is met (the claims, re-attempted by the same timers and delivered by FL, land in the same bucket once L-3.3 aligns the members), an `AbortEvent` is adopted, `reset_round()` + `check_if_selected()` re-selects a committee excluding the missing member, and the next round runs. In case (b) the excluded-member argument of `AbortCascadeLiveness.md` T-1 bounds the number of exclusions before either a viable committee finalizes or the shard reaches its designed under-quorum boundary. Either way the height is not permanently wedged. ∎

### 3.4 Boundary (what T-2 does *not* claim)

T-2 is conditional on FL **and** a reachable honest quorum. It is **not** a liveness claim under a permanent partition that removes a quorum: if fewer than the required members are ever reachable, no retry cadence can manufacture the missing signatures, and recovery is the designed S-044 / FA9 path — the `max(2, K−1)` floor makes K=2 a crash-stop posture (`docs/SECURITY.md` §S-044) and below `k_bft` the recovery is the operator-initiated `MERGE_EVENT` under-quorum merge of `UnderQuorumMerge.md` (FA9), not an automatic rescue from inside the wedged shard. The retry closes the *transient-loss* wedge (L-3.1); it deliberately does not, and cannot, close the *permanent-partition* boundary.

---

## 4. Scope / non-goals

The retry heals a node that is **participating in the round** but missed a message. It does **not** address a node partitioned *away* from the round:

- **No periodic re-sync probe.** The catch-up `STATUS_REQUEST` is emitted once, at boot grace (`src/node/node.cpp:659`), inside a one-shot grace timer; it is not re-armed on a period. A node that falls behind after boot and whose sync attempt fails has no analogous retry — recovery there is operational (restart / resync), not automatic. This is intentional: the S-047 retry is a *round-layer* delivery mechanism, not a *chain-sync* mechanism.
- **Minority-fork recovery is out of scope.** A node that already applied a minority same-height block cannot reorg onto the majority tail (append-only sync; `resolve_fork` unwired) — that is the separate, owner-gated **S-048** defect (`docs/SECURITY.md` §S-048). The S-047 harness measures the two together only because both surface in the same failover loop; post-fix the residual wedge-mode failures are S-048, not S-047. The retry neither fixes nor worsens S-048 (T-1: it is consensus-invisible).

---

## 5. Implementation cross-reference

| This document | Source |
|---|---|
| Relay of full round state | `src/node/node.cpp:1245-1253` |
| Re-arming Phase-1 handler + phase gate | `src/node/node.cpp:1255-1259`, `:1282-1286` |
| Re-arming Phase-2 handler + phase gate | `src/node/node.cpp:1299`, `:1310`, `:1334-1338` |
| AbortEvent dedup + inline-claim author verify | `src/node/node.cpp:1441-1442`, `:1450-1451`, `:1467-1474` |
| Contrib admission + S-006 core-commit gate | `src/node/node.cpp:2281-2282`, `:2315`, `:2338-2343`, `:2370-2373` |
| Core-vs-F2-view comment (no false positive) | `src/node/node.cpp:2328-2337` |
| Generation gate (`aborts_gen`) | `src/node/node.cpp:2248` |
| BlockSig admission + per-signer bound | `src/node/node.cpp:2416-2418`, `:2481`, `:2398-2407` |
| Round/round-end cancels (no stale leak) | `src/node/node.cpp:975-976`, `:1153`, `:1867`, `:1976-1979` |
| Cancel-races-expiry window | `include/determ/net/timer_service.hpp:14-21`, `:62-73` |
| Abort-claim quorum floor | `include/determ/chain/params.hpp:140` |
| One-shot `STATUS_REQUEST` (scope boundary) | `src/node/node.cpp:659` |
| Assumptions A1/A2/H2/H5 | `docs/proofs/Preliminaries.md` (§2.1/§2.2, H2 line 140, H5 line 146) |

---

## 6. Status

- **S-047: ✅ Mitigated** (`docs/SECURITY.md` §S-047, commit `a9ac214`). Safety: T-1 — the retry is consensus-invisible (byte-identical resend, idempotent dedup on all three classes, no S-006 false positive, relay-cannot-forge, no stale-round leak). Liveness: T-2 — conditional round progress under fair loss and a reachable honest quorum; the permanent-partition case is the designed S-044 / FA9 boundary (§3.4).
- **Validation anchors (per §S-047).** Golden consensus vectors byte-identical (consistent with T-1); `test-fa-liveness-virtual` failover loop went 5/12 permanent wedges → 0 wedge-mode failures (residual = S-048); `tools/test_weak_3node.sh` green. This document formalizes that narrative; it does not add a new test.
- **Non-goals** (§4) are explicit: no periodic re-sync probe (`src/node/node.cpp:659`), and minority-fork recovery is S-048-adjacent and owner-gated.
