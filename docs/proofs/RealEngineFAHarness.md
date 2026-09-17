# Real-Engine FA Harness — closing F-1/FA4 over the actual consensus engine

> **RE-DERIVED 2026-09-17 (sequence step 3c; owner decisions D4 + D13, DECISION-LOG 2026-09-16).**
> The §2 harness CONTRACT (real chain, real apply, seeded RNG, per-block assertions, non-vacuity,
> negative control, determinism) is unchanged and is what this document proves. What changed is the
> INVARIANT each trace asserts: increment 1's equivocation trace and increment 2's abort trace were
> INVERTED when the consequences were removed (D4 removed the equivocation forfeiture + deregistration;
> D13 retired the Phase-1 abort deduction). Both tables below are updated to what the shipped gates
> assert; the pre-2026-09-16 rows are shown as HISTORICAL so the inversion is legible.

**Status:** increments 1-5 SHIPPED (`test-fa-{equivocation,abort,cross-shard,multi-event,merge}-trace`) — the apply-level event-family sweep is COMPLETE (§4); the FA4 liveness slice OPENED with increment 6, `test-fa-liveness-virtual` (§5) — real multi-node liveness+agreement in process; increment 7 added `test-fa-partition-virtual`. The adversarial-schedule (virtual-time) remainder has since SHIPPED as the DETERMINISTIC scheduler family, [DeterministicSchedulerDesign.md](DeterministicSchedulerDesign.md) increments 1-9 — its OWN numbering, distinct from this doc's — `test-fa-adversarial-deterministic` + `test-fa-crash-deterministic` with per-step FA checkers and fault witnesses. This is the
**self-contained path** chosen by the owner (AskUserQuestion, 2026-07-07) for the
DSF §Q1/§Q2 goal: rather than link the real engine into `determ-dsf` (which would
drag asio + OpenSSL and reverse its self-contained property — see
[ClockInjectionSeam.md](ClockInjectionSeam.md) §6), the real-engine Byzantine-trace
properties are exercised by `test-fa-*` subcommands **inside the `determ` binary**,
which already links the real `Chain`/apply path. **`determ-dsf` is never touched
and stays 100% self-contained.**

## 1. Why a separate harness (and where it lives)

The DSF toy scenarios (`sim/`, increments 1-6) exercise the *checker patterns* for
the production invariants FA1/A1/FA6/FA7 over a TOY `SimState` — they do NOT run
the real consensus engine, so proof gaps **F-1** ("Option 2 DSF still outstanding;
analytic proofs cover but no random-Byzantine fuzz") and **FA4** (liveness /
trace-level properties) stay open against the real code
([UnitTestCoverageMap.md](UnitTestCoverageMap.md) §F-1).

The real engine is already linked by the `determ` binary. `test-supply-invariant-fuzz`
([src/main.cpp](../../src/main.cpp)) demonstrates the pattern: a seeded SplitMix64
PRNG drives a multi-block trace of randomized TRANSFER/STAKE/UNSTAKE txs through
the **real** `Chain::append` apply path and asserts the A1 economic invariant
(`expected_total() == live_total_supply()`) after every block. **So the economic
A1 trace is already covered on the real engine.** The FA harness generalises this
to the **consensus-Byzantine** invariants (the equivocation evidence channel, abort/escalation,
cross-shard receipt conservation) — the genuine F-1/FA4 gap.

## 2. Harness contract

Each `test-fa-*` subcommand:

1. Builds a real `Chain` from a `GenesisConfig` (real genesis, real apply).
2. Drives a fixed-length multi-block trace, each block carrying Byzantine events
   injected via the real block-apply path (`Chain::append`).
3. Uses a **seeded, counter-based SplitMix64** — no wall clock, no OS RNG — so the
   whole run is byte-reproducible.
4. Asserts trace-level invariants **after every block** (not just at the end).
5. Is **non-vacuous** (asserts the adversarial condition actually occurred) with a
   **negative control** (an event-free block does not move the tracked quantity)
   and a **same-seed determinism** check (identical final `compute_state_root()`).

## 3. Increment 1 — equivocation evidence neutrality (`test-fa-equivocation-trace`)

A never-slashed author + K=6 distinct-stake validators. Over 48 blocks, each block
injects an `EquivocationEvent` for a randomly-chosen validator (a mix of FRESH
targets and DUPLICATE re-submissions). Invariants checked after every block:

| Invariant (at HEAD, since D4) | Assertion |
|---|---|
| Stake neutrality | no validator's `stake()` moves on equivocation evidence |
| Registry neutrality | no validator's `registrant()` moves on equivocation evidence |
| Counter neutrality | `accumulated_slashed()` stays 0 for the whole trace |
| **Twin equality** | a twin chain applying the SAME blocks WITHOUT the events reaches the same `compute_state_root()` after every block |
| A1 conservation | `expected_total() == live_total_supply()` after every block |
| Non-vacuity / positive control | the record really is in the appended block (the trace would otherwise assert neutrality about nothing) |
| Determinism | same seed ⇒ identical final `compute_state_root()` |

**HISTORICAL — what this trace asserted before 2026-09-16.** Fresh-slash forfeit (`stake() → 0`);
fresh-slash deregistration (`inactive_from != UINT64_MAX`); fresh-slash accounting
(`accumulated_slashed() +=` the pre-slash stake); idempotence (a duplicate does not double-slash);
monotonicity and exact total of `accumulated_slashed()`; a negative control that an event-free block
leaves the counter unchanged. Every one of those is now vacuous by construction — which is precisely
why the trace was rewritten around a twin chain rather than left asserting `0 == 0`.

Observed run (HISTORICAL, pre-D4): **6 fresh slashes + 42 idempotent duplicates over 48 blocks**, all
assertions green; full-run output byte-identical across invocations. Gated by
`tools/test_fa_equivocation_trace.sh` (FAST). No consensus code is modified — the
harness only READS the real engine through existing public `Chain` APIs.

## 4. Increments 2-5 (SHIPPED) — the full apply-level event-family sweep

All four follow the §2 contract; each was drafted + adversarially verified
against the real Chain APIs by an independent reviewer before integration, and
each full run is byte-identical across invocations.

| Increment | Subcommand | Trace property (against the REAL apply) | Observed adversarial run |
|---|---|---|---|
| 2 — abort / suspension (S-032) | `test-fa-abort-trace` | **Since D13:** a Phase-1 `AbortEvent` moves NO stake — every validator's stake equals its genesis value and `accumulated_slashed == 0` after every block; the `abort_records` cache is exact per domain (Phase-2 rounds never recorded); every non-`b:` state leaf equals an abort-free TWIN chain applied alongside, with the `b:` leaf present only on the aborted chain (the per-block positive control); A1 per block. *HISTORICAL: it used to assert a `min(SUSPENSION_SLASH, stake)` deduction with floor-at-0, driving one small-stake validator full → PARTIAL → floored-ZERO.* | the forced-repeat target keeps its 25 stake (the retired deduction would have drained it to 0) |
| 3 — cross-shard conservation (FA7) | `test-fa-cross-shard-trace` | TWO real chains (source shard A + dest shard B); real cross-shard TRANSFERs emit outbound receipts on A, B applies inbound receipts including adversarial DUPLICATE re-submissions — no-double-credit (`applied_inbound_receipts` dedup), no-credit-without-debit, two-chain conservation, per-chain A1 analogs, dual-chain state-root determinism | 48 unique credits, 23 duplicate rejects, 27 withheld/in-flight |
| 4 — multi-event composition (FA-Apply-15) | `test-fa-multi-event-trace` | blocks carrying RANDOM MIXES of TRANSFERs + `EquivocationEvent`s + `AbortEvent`s simultaneously; a shadow model mirrors the real apply rules (fees to creators, nonce monotonicity, stake never underflows — and, since D4/D13, the abort branch increments `abort_records` while moving no stake and the equivocation branch is inert, so `accumulated_slashed` is frozen at 0); joint A1 per block | 57 transfers, 16 equivocations (6 fresh / 10 dup), 15 aborts, 21 multi-kind blocks |
| 5 — merge-event lifecycle | `test-fa-merge-trace` | `MergeEvent` BEGIN/END lifecycle over randomized topology per the real apply semantics — fresh BEGINs, duplicate BEGINs, valid ENDs, stale ENDs, bad-partner rejects; A1 per block | 14 fresh BEGINs, 5 dup BEGINs, 12 valid ENDs, 9 stale ENDs, 8 bad-partner rejects |

Gated by `tools/test_fa_{abort,cross_shard,multi_event,merge}_trace.sh` (FAST).

## 5. What this closes, and what remains

Increments 1-5 close the **apply-level** F-1 slices for every major consensus
event family: the FA6 equivocation evidence channel, S-032 abort/suspension accounting, FA7
cross-shard receipt conservation, FA-Apply-15 multi-event composition (the
canonical F-1 target alongside FA4), and the merge-event lifecycle — each as a
seeded randomized-Byzantine multi-block trace over the REAL `Chain::append`
apply path, complementing `test-supply-invariant-fuzz`'s economic A1 trace.

**The FA4 liveness slice — increment 6 SHIPPED (`test-fa-liveness-virtual`),
adversarial scheduling remains.** Liveness (height progress under adversarial
*scheduling* — timeouts, abort cascades, escalation) is a property of the
networked `Node` phase machine, not of the apply path; a real-engine FA4
harness needs to drive a real `Node` under controlled time/transport — the
[ClockInjectionSeam.md](ClockInjectionSeam.md) §Q1 clock plus the minix
`net::Transport` seam ([MinixTacticalProfile.md](MinixTacticalProfile.md) §4;
the same seam serves both goals). Increment 6 delivers the TRANSPORT half:
`Node` gained a §Q2 loop/transport injection seam (pair-enforced, defaults =
platform-native, byte-invariant), and `test-fa-liveness-virtual` runs FIVE
real `Node` instances — full production stack: GossipNet wire codec,
HELLO/STATUS handshake, contrib/block-sig rounds, committee selection, chain
apply, GET_CHAIN sync — in one process over an in-memory `VirtualTransport`
(`include/determ/net/virtual_transport.hpp`), in test_weak_3node's
live-validated 3-of-5 shape (`epoch_blocks=1` per-block committees), across
three phases: liveness+agreement (blocks 1..3 byte-identical on all five),
FAILOVER (destroy one node; majority of survivors must keep finalizing via
abort/reselection), and REJOIN (the identity restarts on fresh substrate,
syncs the survivors' chain, and adopts an outage block byte-identically).

The harness immediately paid for itself with three REAL findings no other
surface could catch (live cluster tests never kill a node mid-run): the
`run()`/`stop()` double-join teardown race (`Node::join_loop_threads()`);
**S-047** (High-liveness, mitigated) — every consensus round message was a
one-shot broadcast, so one missed claim / hash-chained abort event / contrib
(in particular a crashing member's asymmetrically-delivered last messages)
wedged the chain permanently even at 4/5 honest-alive — closed by the
re-arming retry tick `Node::rebroadcast_round_state_locked()` (relays the
full stored, author-signed round state; byte-identical, receiver-deduped,
zero wire/digest change; failover loop 5/12 wedges → 0/14); and **S-048**
(Medium, OPEN, owner-gated) — the abort-vs-finalize race can strand one node
on a validly-signed minority same-height block that append-only sync can
never reorg (`Chain::resolve_fork` exists per S-029 but is unwired); the
harness classifies that mode and prints a `KNOWN-OPEN S-048` marker instead
of flaking. See SECURITY.md §S-047/§S-048.

**Increment 7 — adversarial NETWORK (`test-fa-partition-virtual`).** The same
5-node cluster over the virtual backend, now with a deterministic fault model
(`VirtualNetwork::set_loss`/`partition`/`heal`, whole-frame granular,
byte-invariant default —
[AdversarialTransportHarness.md](AdversarialTransportHarness.md)). The hard
gate is PARTITION SAFETY: a {4}|{1} delivery partition; the loss-free majority
keeps finalizing (the S-047 abort/reselect routes around the isolated node),
the isolated node freezes below quorum and never forks (consistent prefix). A
non-gating LOSSY-LINKS diagnostic then surfaces the round's key finding —
**sustained loss induces timing skew that triggers the OPEN S-048 same-height
fork**, which the S-047 retry re-delivers messages for but cannot **reorg**.
So "no fork / reliable liveness under loss" is not assertable while S-048 is
open, and the reliable loss-liveness gate + the deterministic S-048
reproduction are precisely the virtual-TIME follow-on below.

Wall-clock timers still drive the rounds, so the harness is *hermetic but not
yet deterministic*: the remaining FA4 work is a virtual-TIME evolution of the
backend (deterministic schedules, then ADVERSARIAL schedules —
delayed/reordered delivery, partition, timeout injection), which also unblocks
the S-048 reorg fix's regression test. Until then adversarial-scheduling
liveness remains covered by the per-block slices (`test-required-block-sigs`
etc.), the analytic proof (`Liveness.md`), and the live cluster tests.
