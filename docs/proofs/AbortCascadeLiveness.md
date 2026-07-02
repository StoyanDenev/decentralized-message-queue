# AbortCascadeLiveness — abort-exclusion wedge conditions and BFT-escalation reachability (S-044 / S-045 analysis)

This document is the formal analysis of the two liveness findings registered in `docs/SECURITY.md` §S-044 (K=2 committees wedge permanently under timing skew — High) and §S-045 (BFT escalation unreachable under multi-member abort exclusion — was Medium, upgraded to High per T-4) — **both now Mitigated** (see the status update below and §8). It derives the wedge conditions mathematically from the pre-fix code (T-1, T-2), proves the small-committee corollaries (T-3, T-4), tabulates the margins for every profile (T-5), and analyzes the safety interaction of each candidate fix — (F-a) abort-claim quorum floor, (F-b) abort decay, (F-c) formation-failure counting — against the existing proof corpus (FA1 `Safety.md`, FA4 `Liveness.md`, FA5 `BFTSafety.md`, FA6 `EquivocationSlashing.md`, the FA-Apply abort pipeline `AbortEventApply.md`, and the trigger-soundness composition `S025BFTEscalationSoundness.md`). The shipped fix is F-a + θ=1 default + the `web` M=4/K=3 retune.

**Status update (2026): the fixes derived here SHIPPED.** S-044 and S-045 are now **Mitigated** (`docs/SECURITY.md` §S-044/§S-045). The authorization decision landed on the composite this document recommended in §4.4: **F-a** (abort-claim quorum floor `max(2, K−1)`) + a **θ=1 default** (the §4.3 / T-4 counter-reachability fix, chosen over the heavier F-c formation-failure certificate once θ=1 proved to make the counter always reachable) + the **`web` profile retune** M=3/K=2 → M=4/K=3. **F-b** (wall-clock decay) was rejected on the §4.2 determinism grounds. The theorems below (T-1..T-5) and the §4 fix analysis are retained as the *derivation of why the shipped fix is correct*; where a theorem describes the pre-fix behavior it is now historical (the wedge conditions it characterizes are the ones the fix removes). §8 records the post-fix status per finding.

Unlike most documents in this series, the central results are *negative* liveness results about the implementation as shipped: under conditions that the FA4 liveness model does not capture, the chain reaches a state from which no round can ever start. T-2 makes the model gap precise; finding F-3 below flags it for the FA4 maintainers.

**Companion documents.** `Preliminaries.md` (F0) — §2.0 canonical assumption labels (**A1** Ed25519 EUF-CMA, **A2** SHA-256 collision resistance), §4 honest-validator behavior (**H2** single-sign, **H5** gossip relay), §5 block validity (**V3** creator selection, **V8** block-digest quorum, **V10** abort certificates), §6 committee selection; `Liveness.md` (FA4) — Theorem **T-4** (probabilistic liveness), Lemma **L-4.2** (geometric expectation), Lemma **L-4.3** (BFT escalation bound, four trigger gates); `BFTSafety.md` (FA5) — Theorem **T-5** (BFT-mode conditional safety under `f_h < |K_h|/3`), Lemma **L-5.1** (quorum intersection `≥ 2Q − |K_h|`), Corollary **T-5.1** (slashing recovery); `Safety.md` (FA1) — Theorem **T-1** (MD-mode fork freedom), unaffected by everything here; `EquivocationSlashing.md` (FA6); `AbortEventApply.md` (FA-Apply-11) — **T-A1** (Phase-1 proportional abort slashing), **T-A3** (S-032 `abort_records_` cache); `S025BFTEscalationSoundness.md` — the 4-gate trigger soundness composition and its `A_premature` / `A_late` adversary families (that document proves the trigger fires only when it *should*; this document proves the regimes in which it *cannot* fire at all); `UnderQuorumMerge.md` (FA9) — the R7 recovery for pools below `k_bft`; `docs/SECURITY.md` §S-044 + §S-045 (canonical finding text + live evidence); `tools/test_web_hybrid.sh`, `tools/test_regional_shards.sh`, `tools/test_weak_3node.sh`, `tools/test_bft_escalation.sh` (empirical anchors, §5). A TLA+ companion state machine, `tla/AbortEscalation.tla`, is written in the same batch as this document (model-check pending, like the rest of the FB series).

---

## 1. The model

Every element below is pinned to the shipped source. All citations were re-verified against the working tree at authoring time.

### 1.1 Pool, exclusion set, committee sizes

- **Pool `P`.** The eligible validator set at the current height: registered, active, staked, non-suspended, region-filtered (`Node::check_if_selected`, `src/node/node.cpp:729`; pool assembly with the R4 refugee extension ends at the `k_target` line). Chain-baked suspension is applied *upstream* of `P`, in the registry build (`src/node/registry.cpp:40-64` — Phase-1-only abort records via the S-032 cache; see `AbortEventApply.md` T-A3). Write `N := |P|`.
- **Exclusion set `E`.** The set of distinct domains appearing as `aborting_node` in the in-memory per-height list `current_aborts_`. Built fresh on every selection attempt at `src/node/node.cpp:762-768` (`for (auto& ae : current_aborts_) excluded.insert(ae.aborting_node);` at `:763`). The available pool is `avail := P \ E` (`:764-768`).
- **Committee sizes.** `k_target := cfg_.k_block_sigs = K` (genesis-pinned; `src/node/node.cpp:756`). `k_bft := (2K + 2) / 3 = ⌈2K/3⌉` (`:778`). The round's effective size `k_use ∈ {k_target, k_bft}`.
- **Total abort counter.** `total_aborts := current_aborts_.size()` (`src/node/node.cpp:777`). Note: this counts *events*, while `E` counts *distinct members* — `total_aborts ≥ |E|`, and the gap matters (T-4).

### 1.2 The escalation conjunction and the silent return

`check_if_selected` flips the round to BFT mode iff all four gates hold (`src/node/node.cpp:781-784`):

```
avail < k_target  ∧  cfg_.bft_enabled  ∧  total_aborts ≥ cfg_.bft_escalation_threshold  ∧  avail ≥ k_bft
```

in which case `k_use = k_bft` and `round_mode = BFT` (`:785-786`). Then, unconditionally:

```
if (avail_domains.size() < k_use) return;        // src/node/node.cpp:788
```

This return is **silent and terminal for the attempt**: no timer is armed, no message is sent, no state changes. `check_if_selected` is the *only* caller of `start_contrib_phase` (`src/node/node.cpp:814` → `:822`), and it is itself invoked only on discrete events: boot grace (`:615`), abort-quorum formation (`:1309`), gossiped-abort adoption (`:1362`), block accept (`:1945`), and sync catch-up (`:2445`). There is **no retry timer**. The genesis default for the threshold was `5` when this analysis was written (the wedge conditions below derive from that value); the S-045 fix lowered it to **`1`** (`include/determ/chain/genesis.hpp`, loader `src/chain/genesis.cpp`, node-config mirror `src/node/node.cpp`), which is what makes the counter always reachable (§4.3, §8). The `θ = 5` figures in T-2.1 / T-4 / T-5 below therefore characterize the *pre-fix* regime.

### 1.3 The abort-claim pipeline (the only writers of `current_aborts_`)

1. **Claim generation** happens *only* inside a running round: the Phase-1 timer handler `handle_contrib_timeout` (`src/node/node.cpp:1180`, claim stored + broadcast at `:1194-1195`) and the Phase-2 timer handler `handle_block_sig_timeout` (`:1200`, claim at `:1231-1232`). A node claims only if it is itself in the current committee and is not the missing member. No round ⇒ no timers ⇒ no new claims.
2. **Quorum formation** (`Node::on_abort_claim`, `src/node/node.cpp:1239`): claims are bucketed per `(round, missing_creator)` (`:1268-1270`); the quorum is

   ```
   q := current_creator_domains_.size() − 1 = k_use − 1        // src/node/node.cpp:1274-1276
   ```

   gated at `:1277`. On quorum, an `AbortEvent` is assembled with `ts = now_unix()` (`:1280`; **seconds** granularity — `include/determ/types.hpp:93-96`) and an `event_hash` that is either `compute_abort_hash(round, missing, ts, rand)` for the first event or chained off the previous event's hash (`:1283-1284`); it is appended to `current_aborts_` (`:1295`) and gossiped as a self-contained certificate (`:1306`), followed by `reset_round()` + `check_if_selected()` (`:1308-1309`).
3. **Gossip adoption** (`Node::on_abort_event`, `src/node/node.cpp:1312`): an incoming event is deduplicated **by exact `event_hash`** (`:1322`), then its inline claim set is independently validated against the same `q = k_use − 1` quorum (`:1329-1331`, distinct-claimer recount at `:1354`) before being appended (`:1357`) with the same `reset_round()` + `check_if_selected()` tail (`:1361-1362`).

Two structural consequences used repeatedly below: **(C1)** because each surviving committee member assembles its *own* `AbortEvent` with its *own* local timestamp, two assemblies of the same logical abort yield *distinct* `event_hash` values iff their second-granularity timestamps (or prior chains) differ — and then cross-adoption appends *both*, so one aborted round can contribute up to `k_use − 1` counter increments while excluding only **one** distinct member; **(C2)** if the survivors assemble within the same second from the same chain state, the events collide on `event_hash` and dedup to one. The counter's growth beyond `|E|` is therefore *timing-dependent* (finding F-2).

### 1.4 The clear site and the generation gate

- `current_aborts_.clear()` has exactly **one** call site: block accept, inside `apply_block_locked` (`src/node/node.cpp:1856`, immediately after the registry rebuild at `:1855`). `reset_round` (`:1737-1748`) clears the per-round buffers and returns the phase to `IDLE` but touches neither `current_aborts_` nor `current_creator_domains_`. No decay, no expiry, no per-entry timeout. (The state is in-memory only: a process restart zeroes it — see §5.4.)
- **Generation gate:** an incoming `ContribMsg` is dropped unless `msg.aborts_gen == current_aborts_.size()` (`src/node/node.cpp:2116`). Any transient divergence in two peers' `current_aborts_` lengths (e.g., one adopted a duplicate event the other deduplicated, per C1/C2) makes their Phase-1 contributions mutually invisible until gossip convergence — the **cascade amplifier**: dropped contribs look like straggles, straggles produce claims, claims produce events, events grow `E`.

### 1.5 The validator mirror (why every candidate fix is consensus-critical)

The producer-side selection and escalation logic is mirrored byte-for-byte on the validation side: committee reconstruction excludes `b.abort_events` aborters and remixes the seed identically (`src/node/validator.cpp:112-128` in `check_creator_selection`, `:61`; MD/BFT committee-size consistency `m == k_full` / `m == k_bft` at `:97-103`); the abort-certificate check `check_abort_certs` (`:196`) replays the *per-event* escalation decision with the same four gates, using the event index `i` as the at-event abort count (`:262-267`), rejects under-pooled events (`:270`), and requires **exactly** `q = (committee size at event) − 1` claims — `ae.claims_json.size() != needed` is a hard reject (`:285-288`). The within-committee BFT quorum `Q = ⌈2·k_bft/3⌉` lives in `producer.cpp::required_block_sigs` (`src/node/producer.cpp:583-595`). Any change to `q`, to the contents of `current_aborts_`, or to gate 2's inputs therefore changes block validity (V3/V10) and must land on producer and validator simultaneously — the central caveat of §4.

---

## 2. Wedge theorems

### Theorem T-1 — Round blocking

**Claim.** At a fixed height, no consensus round can start iff `|P \ E| < k_use`, where `k_use = k_bft` if the four-gate conjunction of §1.2 holds and `k_use = k_target` otherwise. Equivalently, all rounds are blocked iff

```
|E|  >  N − k_use .
```

**Proof.** (⇐) If `avail = |P \ E| < k_use`, `check_if_selected` returns at `src/node/node.cpp:788` before `select_m_creators` (`:803`) and `start_contrib_phase` (`:814`). Since `:814` is the unique call site of `start_contrib_phase` (§1.2), no round starts on this node. The committee derivation is deterministic and identical across honest peers (Preliminaries §6; validator mirror §1.5), and `E` converges across peers via the gossiped abort certificates (§1.3 step 3, H5), so the same inequality blocks every honest peer.

(⇒) If `avail ≥ k_use`, the gate at `:788` passes, a committee is selected, and any node that finds itself a member arms the contrib phase. The only other early exits (`:730-731` not-in-sync / non-IDLE phase, `:812` not-selected) are per-node and transient; at least the selected members proceed. ∎

**Remark (no self-recovery).** Because `check_if_selected` is purely event-driven and the blocking state generates none of its triggering events (no rounds → no aborts → no accepts), `|E| > N − k_use` is a **fixed point**: the node set stays in `IDLE` forever absent external intervention. This is the "silently returns forever" of SECURITY.md §S-044.

### Theorem T-2 — Counter freeze and escalation reachability (S-045)

**Claim.** Suppose rounds are blocked per T-1 with `k_use = k_target` (escalation gates not satisfied). Then:

1. *(Freeze)* `total_aborts` can grow only by the bounded residue of in-flight duplicate adoptions (C1) and then is frozen forever: rounds are the sole source of new `AbortClaimMsg`s (§1.3 step 1), and both append paths (`:1295`, `:1357`) require a fresh claim quorum from the current height's committee context.
2. *(Reachability)* BFT escalation is reachable at this height iff there is a moment at which simultaneously
   `total_aborts ≥ bft_escalation_threshold` **and** `|E| ≤ N − k_bft`
   (gates 2 and 4; gates 1 and 3 are the deployment flag and the already-assumed `avail < k_target`). Since every aborted round adds **one** new distinct member to `E` (one `missing_creator` per quorum bucket, `:1268`) while adding between 1 and `k_use − 1` counter increments (C1/C2), escalation requires the abort *events* to **concentrate** on at most `N − k_bft` distinct members for long enough that the event count reaches the threshold. If instead the aborts spread across more than `N − k_bft` distinct members before the counter reaches the threshold, gate 4 fails at every subsequent evaluation, no round runs, the counter freezes below the threshold (part 1), and the height is permanently wedged.

**Proof.** Part 1 is the closure argument of §1.3: `handle_contrib_timeout` / `handle_block_sig_timeout` run only under an armed round timer; with the phase parked in `IDLE` no timer is armed (`reset_round`, `:1737-1748`, cancelled timers at `:1857-1858` on the accept path); a gossiped `AbortEvent` is appended only if it carries a valid `q`-quorum of claims bound to the current `(block_index, prev_hash)` (`:1328-1354`) — such claims were producible only while a round was running. The in-flight residue is bounded by the duplicate assemblies already broadcast (at most one per survivor of the last aborted round, C1).

Part 2 restates the conjunction of §1.2 with `avail = N − |E|`, plus the growth accounting: distinct-member growth of `E` is 1 per aborted round; counter growth per aborted round is `μ_r ∈ [1, k_use − 1]` (C1/C2). Escalation fires at the first evaluation where `Σ μ_r ≥ threshold` while `|E| ≤ N − k_bft`. ∎

**Corollary T-2.1 (pure-distinct climb bound).** If no duplicate adoption occurs (`μ_r = 1` always — the deterministic worst case, C2), then `total_aborts = |E|` and escalation at threshold `θ` requires `θ ≤ N − k_bft`, i.e. a pool of at least

```
N  ≥  θ + k_bft .
```

At the genesis default `θ = 5`: K=3 needs `N ≥ 7`; K=4 needs `N ≥ 8`; K=5 needs `N ≥ 9`. **No shipped profile's nominal pool satisfies this** (T-5 table) — at nominal pool sizes, reaching the default threshold relies entirely on the timing-dependent duplicate-adoption surplus, or on operators tuning `θ` down (as `tools/test_bft_escalation.sh` does, §5.2).

### Theorem T-3 — K=2 corollary (S-044)

**Claim.** For `K = 2` (the shipped `web` profile, the `determ init` default):

1. *(No corroboration)* the abort-claim quorum is `q = k_use − 1 = 1` (`src/node/node.cpp:1274-1276`): a single committee member's local timeout observation immediately forms a quorum against its peer — no second observer is required. Both members can single-claim each other in the same round (mutual exclusion).
2. *(No escalation headroom — structural)* `k_bft = ⌈2·2/3⌉ = (2·2+2)/3 = 2 = K`, so gates 3 and 4 demand `avail < 2 ∧ avail ≥ 2` — **unsatisfiable**. BFT escalation is unreachable at K=2 for *every* pool size and *every* threshold, including `θ = 0`. (This is sharper than S-045's frozen counter: at K=2 the escalation arm is dead code.)
3. *(Permanent wedge at two exclusions)* by T-1 with `k_use = k_target = 2` forced by part 2, all rounds block as soon as `|E| > N − 2`. For the web posture's nominal pool `N = 3` (`include/determ/chain/params.hpp:142`), **any 2 distinct single-straggle exclusions at one height are a permanent wedge**; for the mutual-exclusion case of part 1, a single round can produce both.
4. *(Cascade amplifier)* each abort event advances `current_aborts_.size()` and thereby the required `aborts_gen` (`src/node/node.cpp:2116`). Peers that disagree transiently on the event list (C1/C2 dedup races, gossip skew) drop each other's contribs, making healthy members appear silent; at `q = 1` every such appearance converts directly into a new exclusion. The amplifier needs no Byzantine actor — ordinary timing skew suffices, which is exactly the live observation (§5.1).

**Proof.** Part 1 and the formulas in part 2 are arithmetic on the pinned definitions (`:756`, `:778`, `:1274-1276`); unsatisfiability of `avail < 2 ∧ avail ≥ 2` is immediate. Part 3 instantiates T-1. Part 4 is the gate at `:2116` plus part 1. ∎

### Theorem T-4 — Single-dead-member soundness (and its limits)

**Claim.** Let exactly one pool member be persistently dead and let all abort events at the height target only that member (so `|E| = 1`, `avail = N − 1` permanently). Then the escalation gates 3+4 are satisfiable iff

```
N − 1 ≥ k_bft        (gate 4)        and        N − 1 < K        (gate 3, i.e. N ≤ K — the minimal-pool posture; for N > K an MD round simply runs without the dead member),
```

and escalation actually fires iff additionally the counter reaches the threshold: `total_aborts ≥ θ`. With `|E|` pinned at 1, the counter exceeds 1 **only** via duplicate adoption (C1): the single aborted round yields at most `k_use − 1 = K − 1` events (one per survivor, distinct-timestamp case). Hence single-dead-member escalation at the minimal pool `N = K` is reachable iff

```
K − 1 ≥ k_bft   is false for K ∈ {2,3} … —  precisely:   N − 1 ≥ k_bft   ∧   θ ≤ achievable T ≤ K − 1 .
```

**Reconciliation with the green `tools/test_bft_escalation.sh`.** The test is M=K=3, N=3, kill one node. `avail = 2 = k_bft ≥ k_bft` ✓ and `avail = 2 < 3 = K` ✓. Its genesis pins `"bft_escalation_threshold": 1` (`tools/test_bft_escalation.sh:84`), so the **first** abort event already meets gate 2 and the BFT 2-of-3 round proceeds — fully consistent with this theorem, and the test is sound evidence that the trigger and the BFT round machinery work when the gates are satisfiable. What the test does **not** evidence is reachability at the **default** threshold: at `θ = 5`, the same scenario freezes at `total_aborts ≤ 2` (one event per survivor, K−1 = 2) by T-2 part 1 — a permanent wedge even though only one member is actually dead and `avail = k_bft` would make a BFT round viable. (See also finding F-1: the test's header comment at `:3` and log line at `:149` say "threshold=2", contradicting the pinned genesis at `:84`.)

**Proof.** Gate arithmetic as in T-2 part 2 with `|E| = 1` fixed. The counter ceiling at `N = K` follows because after the single exclusion `avail = K − 1 < k_target` blocks every further MD round (T-1), so no further claim generation exists (T-2 part 1); the only events are the survivors' independent assemblies of the one logical abort, at most `K − 1` of them, fewer on second-granularity timestamp collision (C2). ∎

### Theorem T-5 — Margin table for the shipped profiles

Profile postures from `include/determ/chain/params.hpp` (cluster `:138`, web `:142`, regional `:146`, global `:150`, tactical `:178`; the `*_test` profiles mirror M/K exactly, `:201-239`). Nominal pool `N = M`; `q = K − 1`; `k_bft = (2K+2)/3`. "MD margin" = `N − K` (distinct exclusions tolerable with MD rounds still formable); "escalation headroom" = `N − k_bft` (max `|E|` with gate 4 satisfiable); "wedge at D" = `N − K + 1` (min distinct exclusions that block all MD rounds, T-1); "permanent at D" = `N − k_bft + 1` (min distinct exclusions past which even BFT is unviable; R7/operator territory).

| Profile | M=N | K | q | k_bft | MD margin `N−K` | Escalation headroom `N−k_bft` | Wedge at `|E| =` | Permanent at `|E| =` | Escalation at default θ=5, nominal pool? |
|---|---|---|---|---|---|---|---|---|---|
| `web` (`params.hpp:142`) | 3 | 2 | **1** | 2 = K | 1 | 1 (but structurally dead, T-3.2) | 2 | 2 | **Never** (T-3.2: gates unsatisfiable at any θ) |
| `regional` (`:146`) | 5 | 4 | 3 | 3 | 1 | 2 | 2 | 3 | Not by pure-distinct climb (needs N ≥ 8, T-2.1); duplicate surplus can reach θ=5 only with ≥ 2 aborted rounds × 3 survivors all distinct-second (T-2, C1) |
| `cluster` (`:138`) | 3 | 3 | 2 | 2 | **0** | 1 | **1** | 2 | **Never** at θ=5 (counter ceiling 2 < 5, T-4); reachable at θ ≤ 2 |
| `global` (`:150`) | 7 | 5 | 4 | 4 | 2 | 3 | 3 | 4 | Not by pure-distinct climb (needs N ≥ 9); duplicate surplus can reach θ=5 across ≤ 3 aborted rounds |
| `tactical` (`:178`) | 3 | 3 | 2 | 2 | **0** | 1 | **1** | 2 | Same as cluster |

Readings. (i) `web` is the worst on every axis *and* is the `determ init` default — single-claim quorum, zero escalation arm, wedged at 2 exclusions that one round of mutual claims can produce (T-3). (ii) The two strong M=K=3 postures (`cluster`, `tactical`) have **zero** MD margin: the *first* exclusion already blocks MD rounds, and rescue then hinges entirely on escalation, which the default threshold makes unreachable (T-4) — the S-045 shape. (iii) Even the rosiest shipped posture (`global`) cannot reach the default threshold by distinct exclusions alone (T-2.1) and wedges permanently at 4 distinct exclusions out of 7. (iv) Pools larger than nominal M relax everything linearly — operators running `N > M + θ` validators above the committee size are outside the frozen-counter regime for single-member faults.

---

## 3. FA4 model gap (why the liveness theorem missed this)

`Liveness.md` T-4 Step 4 concludes `Pr[indefinite stall] = 0` from a geometric-retry argument: L-4.2 models the round sequence as i.i.d. Bernoulli trials, and L-4.3 bounds the BFT fallback. Both lemmas carry an **implicit** assumption that a next trial always exists. The implementation violates that assumption: the exclusion set `E` is monotone within a height (single clear site `src/node/node.cpp:1856`), each failed trial *removes a member from the trial population*, and at `|E| > N − k_use` the trial sequence terminates (T-1) — the process is an absorbing chain, not a Bernoulli sequence. L-4.3's trigger analysis correctly lists the four gates but evaluates the trigger probability *conditional on rounds running*; T-2 shows the conditioning event itself dies. FA4's conclusions stand for the regimes where `N − K` margin absorbs the abort spread (large pools, T-5 reading iv); they do not hold for the minimal-pool postures. Registered as finding **F-3** (§6) for the FA4 maintainers; this document does not edit `Liveness.md`.

---

## 4. Candidate-fix analysis

All three candidates are consensus-critical (§1.5): each changes V10 and/or V3 inputs, so producer and validator must change in lockstep, with a height-gated activation or a genesis parameter for mixed-version networks. None is shipped. Per `docs/SECURITY.md` §S-044/§S-045, shipping any of them requires explicit authorization.

### 4.1 (F-a) Abort-claim quorum floor `q' = max(2, K−1)`

**Mechanism.** Replace `needed = committee_size − 1` with `needed = max(2, committee_size − 1)` at the three quorum sites: producer formation (`src/node/node.cpp:1274-1276`), gossip adoption (`:1329-1331`/`:1354`), and the validator's exact-count check (`src/node/validator.cpp:285-288` — note this check is `!=`, an *equality*, so the validator change is not optional; an F-a producer's 2-claim cert at K=2 would otherwise be rejected as `claim count != M-1`). Preliminaries §5 V10 ("carries K−1 distinct, valid AbortClaimMsg signatures") would need the same edit.

**Effect on K ≥ 3: none.** `max(2, K−1) = K−1` for `K ≥ 3`, so every theorem above, FA4's trigger analysis (L-4.3), and the FA5/FA6 pipelines are bit-for-bit unchanged. F-a is purely a K=2 semantic change. In particular F-a does **not** touch T-2's frozen counter — S-045 remains fully open under F-a alone.

**Effect on K = 2 — derived honestly.** The committee is `{x, y}`; a claim's `claimer` must differ from `missing_creator` (`src/node/node.cpp:1254` on the claim-ingest path; adoption-side reject at `:1340` inside the inline-claim loop), so against a given missing member there exists exactly **one** eligible claimer. A 2-claim quorum is therefore **unsatisfiable**: under F-a, no abort event can ever form at K=2. Consequences, in order:

- T-3 collapses: `E` stays empty, no exclusion, no `aborts_gen` advance (the gate at `:2116` compares against a never-growing list), no cascade. The S-044 wedge-by-cascade is eliminated.
- In exchange, a *genuinely* dead member halts the height **forever**: MD finalization needs K-of-K Phase-1 unanimity and K nonzero Phase-2 sigs (V8, Preliminaries §5), the dead member never contributes, no abort can reseat the committee (none can form), and escalation is structurally dead anyway (T-3.2). K=2 becomes a crash-stop 2-of-2 unanimity system: **halt-by-single-death** instead of **wedge-by-cascade**.

**Which is preferable, and why.** Halt-by-single-death is the better failure mode for K=2, on three grounds. (1) *Trigger narrowness:* the cascade fires under ordinary timing skew with **all members healthy** (the §5.1 reproductions wedged clusters whose every member was alive); the F-a halt fires only on an actual member failure — strictly rarer, and an event the operator must respond to regardless. (2) *Diagnosability:* a stalled 2-of-2 chain with one dead node is operationally obvious; the cascade wedge presents as "healthy nodes, silent chain" with the cause buried in `aborts_gen` drift. (3) *Epistemic honesty:* with one observer, a "quorum of 1" never corroborated anything — at K=2 the abort machinery only ever laundered a single node's opinion into a consensus-grade exclusion; F-a removes a mechanism that could not deliver its design intent at that size. The residual cost — no automated reseat at K=2 — is real but is precisely what the K ≥ 3 interim guidance already concedes (SECURITY.md §S-044): K=2 cannot simultaneously have abort-based reseating and skew robustness. F-a makes the safe half of that trade the default rather than the cascade.

**Proof-corpus interaction.** FA1 T-1 (MD fork freedom) is signature-counting on block digests — abort certs play no role; unaffected. FA5/FA6 unaffected (K=2 never escalates, before or after). FA4: for K=2, T-4's MD-only bound T-4' applies with the added caveat that `p` must now be read as *persistent*-failure probability (transient straggles no longer consume a round permanently — they just retry on the same committee), which *improves* the effective geometric bound. `AbortEventApply.md` T-A1 slashing: no abort events at K=2 ⇒ no Phase-1 abort slashing at K=2 — acceptable, since with q=1 that slashing was single-accuser anyway (arguably a fairness bug in its own right).

### 4.2 (F-b) Wall-clock decay / expiry of `current_aborts_` entries

**Mechanism (as proposed).** Drop entries older than a window `W` from `current_aborts_`, shrinking `E` and reopening committee formation; bounded wedge instead of permanent wedge.

**Interaction with FA6 / suspension — the safe part.** Chain-baked consequences are untouched by construction: suspension derives from `chain.abort_records()` via the registry build (`src/node/registry.cpp:40-64`, Phase-1-only, S-032 cache; `AbortEventApply.md` T-A3), i.e. from abort events already **applied in finalized blocks**, a different data structure from the in-memory pre-finalize list. Equivocation slashing (FA6) keys off `EquivocationEvent`s, untouched entirely. Decay of the in-memory list erases neither. The one apply-side consequence: a decayed event never reaches `b.abort_events`, so its T-A1 proportional Phase-1 slash and its `abort_records_` increment never happen — the abort-deterrent weakens by exactly the decayed entries. Tolerable, but it must be stated.

**The disqualifying problem: non-determinism.** `current_aborts_` is a *consensus input*: the committee at each step is derived by excluding its members and mixing its `event_hash` chain into the seed (`src/node/node.cpp:763`, seed-mixing loop at `:799`; validator replay `src/node/validator.cpp:112-128`, `:246-276` keyed on the **full** `b.abort_events` sequence). Wall-clock decay runs on unsynchronized local clocks: two peers will disagree, around every expiry boundary, about (a) the exclusion set (different committees derived — V3 mismatch between a producer that decayed and a validator that hasn't), and (b) the list *length* — which is the `aborts_gen` the contrib gate compares (`:2116`). Decay therefore *manufactures* the precise desync that §1.4 identifies as the cascade amplifier; in the wedged state there are no finalized blocks to re-anchor on, so the divergence has no convergence mechanism. This is the same class of producer/validator formula divergence that the S-043 regression demonstrated to be a total-outage bug. A deterministic variant (decay keyed to block height or round counter) is not available in the wedged state — no blocks and no rounds advance any shared counter (T-2 part 1). **Verdict:** F-b in its wall-clock form is unsound as a consensus change; at most it could be re-cast as an explicit *operator action* (a signed, gossiped "height-retry" message with its own quorum rule), which is a different, larger design.

**Re-straggle loop risk (even if determinism were solved).** Decay re-admits the excluded member; if the straggle cause persists (the member is dead or chronically slow), the next round re-excludes it after one timeout: a livelock with period ≈ `W` + round-timeout, consuming an abort event per cycle — which, note, *would* eventually push `total_aborts` past any threshold (the counter is fed again) and trigger escalation where viable. That coupling (decay feeds the counter that F-c wants fed) is the one genuinely attractive property of F-b, and it is available more cheaply and deterministically via F-c directly.

### 4.3 (F-c) Counting failed committee-formation attempts toward `bft_escalation_threshold`

**Mechanism.** Treat each blocked formation attempt (the silent return at `src/node/node.cpp:788`, plus a retry timer to generate attempts while wedged — without a timer there are no attempts to count, §1.2) as an increment toward gate 2, either into `total_aborts` directly or into a parallel counter OR-ed into gate 2.

**Liveness effect — it unfreezes T-2 exactly where unfreezing is sound.** In the frozen case (`k_bft ≤ avail < k_target`, counter below threshold), attempts now accumulate; once the (attempt + abort) count reaches `θ`, gates 2–4 all hold and the BFT round runs. The conditional wedge of T-2 part 2 is eliminated; the *permanent* wedge (`avail < k_bft`) is untouched, correctly — below `k_bft` the BFT committee itself is unstaffable and the designed recovery is R7 under-quorum merge (FA9; note that R7 is driven by `MERGE_EVENT` transactions applied in finalized blocks, `src/chain/chain.cpp:931`, i.e. operator-initiated and dependent on a still-live absorbing chain — it is not an automatic rescue from inside the wedged shard) or operator action. At K=2, gates 3∧4 remain unsatisfiable (T-3.2): **F-c does not address S-044**; it is the S-045 fix and composes with F-a (which is the K=2/S-044 fix), as SECURITY.md §S-045 already notes.

**Safety check against FA5.** `BFTSafety.md` T-5's bound is conditional only on (A1), (A2), (B1) `f_h < |K_h|/3` *within the escalated committee*, and (B2) FA6 slashing; the proof (L-5.1 intersection `≥ 2Q − |K_h|`, L-5.2 honest-intersection) consumes the committee size `|K_h| = k_bft` and the V8 quorum `Q` — **it nowhere consumes the reason escalation was triggered.** Escalating more often therefore widens the set of blocks whose safety is conditional (the FA5-vs-FA1 trade of BFTSafety §5.1: more blocks rely on B1, fewer on FA1's unconditional clause) but does not weaken the bound on any individual BFT block: at the escalation point the committee is still `k_bft = ⌈2K/3⌉` drawn from the abort-adjusted pool, `Q = ⌈2·k_bft/3⌉` still intersects per L-5.1, and T-5.1's slashing recovery still backstops B1 violations. The FA4 L-4.3 trigger condition changes (gate 2's input set grows) while its finalize condition is untouched. This is the same conclusion S025BFTEscalationSoundness reaches for legitimate threshold *tuning* — F-c is, in effect, deterministic auto-tuning of gate 2's patience in the regime where the original counter is provably starved (T-2).

**The real cost: gate 2's validator mirror breaks.** The producer/validator agreement on escalation is currently enforced because the validator *recomputes* the at-event abort count from the block itself — `i >= bft_escalation_threshold_` over the `b.abort_events` index (`src/node/validator.cpp:262-267`; the byte-for-byte mirror S025BFTEscalationSoundness §"producer-validator mirror" pins as proof obligation T-5 there). Formation failures leave **no on-chain artifact**: a block escalated under F-c would carry fewer abort events than the threshold, and every honest validator would reject its consensus mode (or, if the validator check were naively relaxed, a Byzantine producer could claim arbitrary phantom failures and **unilaterally force BFT mode**, needing only `Q < K` signatures thereafter — re-opening precisely the `A_premature` forced-escalation attack that S025's gate-2 theorem closes; that WOULD weaken the effective safety posture and is not acceptable). F-c therefore requires a verifiable failure artifact — e.g., a `FormationFailureCert` carrying signatures from ≥ `k_bft` distinct pool members attesting "height h, abort-chain hash X, attempt n, pool view insufficient", baked into `b.abort_events`' replay sequence so the validator's per-event recount covers it. The signature floor makes phantom-failure forgery require corrupting `k_bft` members — at which point the adversary can stall the chain outright anyway, so the certificate adds no new power. Designing that certificate (wire format, V10-style validation, interaction with `aborts_gen`) is the actual work item of F-c; the counting rule itself is trivial.

**Composite recommendation surface (decision input, not a decision).** F-a (K=2 floor) + F-c (certified formation-failure counting) together close both findings' mechanisms with bounded, analyzable safety deltas: F-a is provably a no-op for K ≥ 3 and converts K=2's failure mode to the strictly-narrower halt-by-single-death; F-c's safety exposure reduces to FA5's existing conditional bound provided the failure certificate carries a `k_bft` signature floor. F-b (wall-clock decay) should be rejected in its proposed form on determinism grounds (§4.2). The K ≥ 3 deployment guidance remains in force regardless.

---

## 5. Empirical anchors

### 5.1 The three live reproductions (2026-06-11, per SECURITY.md §S-044)

All three ran at 2000/2000/1000 ms test timers — generous; the green M=K=3 siblings mint 50+ blocks under identical settings:

1. **`tools/test_weak_3node.sh` (historical K=2 forms, M=3 and M=4).** Logs showed: block #1 accepted → successive *single-claim* quorums against node4, node2, node3 in consecutive rounds → silence. The shipped test now runs K=3-of-5 and documents the cascade in its header (`tools/test_weak_3node.sh:7-17`): single straggle → 1-claim abort → `aborts_gen` desync drops contribs → further single-claim aborts → pool below K → permanent halt. This is T-3 parts 1+3+4 verbatim.
2. **`tools/test_web_hybrid.sh` (K=2-of-3, web posture).** Wedged at height 3–4. The test asserts boot/role/selection and carries the `KNOWN-BUG S-044` note in place of the sustained-production bar (`tools/test_web_hybrid.sh:118-129`, runtime note at `:171-173`) — the height ≥ 5 assertion is to be restored when S-044 closes.
3. **`tools/test_regional_shards.sh` (K=2-of-3, region-filtered committees).** Blocks 1–2 finalize with *correct* region-filtered committees, then cascade → wedge at height 3 (`tools/test_regional_shards.sh:154-162`). Notably, selection and finalization were correct in every pre-cascade block in all three reproductions — the defect is purely sustained liveness, as T-1's fixed-point reading predicts.

### 5.2 The green escalation case

`tools/test_bft_escalation.sh` (M=K=3, kill 1 of 3) demonstrates the single-dead-member escalation working end-to-end: MD aborts against the dead node, escalation to BFT 2-of-3 with designated proposer, sustained BFT block production. Per T-4 this is sound **and** threshold-dependent: the test pins `bft_escalation_threshold: 1` (`tools/test_bft_escalation.sh`), which is now ALSO the shipped genesis default (the S-045 fix — so the test validates reachability at the real default, not just a test-only pin). At the *pre-fix* default `θ = 5` the same M=K=3 topology froze at `total_aborts ≤ K−1 = 2 < 5` (T-4, T-2.1) — the wedge θ=1 removes.

### 5.3 Operational containment (superseded by the shipped fix; retained as posture guidance)

The items below were the interim containment while the findings were OPEN. Post-fix they are **defaults or non-issues**, but remain accurate as deployment posture:

- **K ≥ 3** is now the shipped `web` default (M=4/K=3). At K ≥ 3 the claim quorum is ≥ 2 (and F-a's floor is a no-op there) — a single straggle excludes nobody. K=3-of-4 and K=3-of-5 run green including kill-one-creator recovery (`tools/test_hybrid_liveness.sh`). K=2 is now a crash-stop posture (F-a), safe from the cascade but with no fault tolerance — choose K≥3 for that.
- The cluster tests' `KNOWN-BUG S-044` notes are **restored to production bars** as the fix ships (§5.1 / task).
- Pool provisioning is no longer required for single-member-fault escalation reachability: with the θ=1 default the counter reaches the threshold on the first abort, so escalation fires whenever `avail ∈ [k_bft, K)`. Provisioning `N ≥ K + 1` (MD margin) is still the most robust posture — the single-fault case then runs in strong MD mode without escalating at all (the new web 4/3 does exactly this).

### 5.4 In-memory character of the wedge

`current_aborts_` and `aborts_gen` are process state, not chain state. A *single* node restart does not clear the wedge (the restarted node returns at generation 0 and is gen-gated by its peers at `src/node/node.cpp:2116`, and vice versa); a *coordinated full-cluster* restart resets every node to an empty abort list at the same height and removes the wedge precondition, provided the original skew source is gone. (Structural observation from §1.4's pinned state; not exercised by a regression test.)

---

## 6. New findings registered by this analysis (flagged, not fixed)

- **F-1 (test doc drift, trivial but load-bearing for §5.2).** `tools/test_bft_escalation.sh` header (`:3`) and runtime log line (`:149`) both say `bft_escalation_threshold=2`; the pinned genesis says `1` (`:84`, section banner `:76` agrees). The green result is valid either way (both values are ≤ the achievable counter for the topology — threshold 2 would additionally depend on duplicate adoption, C1), but the header should match the genesis, and the dependence of the green result on a non-default threshold deserves an explicit comment.
- **F-2 (counter growth beyond `|E|` is timestamp-skew-dependent).** The only mechanism by which `total_aborts` exceeds the distinct-member count is cross-adoption of independently-assembled duplicate `AbortEvent`s, which collide (and dedup at `src/node/node.cpp:1322`) whenever the assembling survivors' `now_unix()` values fall in the same second from the same chain context (`:1280`, `:1283-1284`; `include/determ/types.hpp:93-96`). Escalation reachability at thresholds above the pure-distinct bound (T-2.1) therefore depends on sub-second scheduling accidents. Relatedly, SECURITY.md §S-045's "what works" sentence ("repeated aborts against the SAME member … the counter climbs to the threshold across rounds") is imprecise for the minimal-pool case: an already-excluded member cannot be re-aborted by fresh rounds at the same height (it is no longer selectable, `:763-768`), so the climb it describes is exactly this duplicate-adoption path (or requires `N > K`). The reconciled statement is T-4.
- **F-3 (FA4 model gap).** `Liveness.md` L-4.2/T-4 Step 4 assume an unbounded i.i.d. round-retry sequence; the implementation's monotone per-height exclusion set makes the retry process absorbing (T-1, T-2), so `Pr[indefinite stall] = 0` does not hold for the implementation in the minimal-pool regimes. FA4 needs either an explicit pool-margin assumption (e.g., "L6: `N − |E|` ≥ `k_use` is maintained throughout the height") or a cross-reference to this document's T-2 as the boundary of its validity. Flagged for the FA4 maintainers; `Liveness.md` is not edited here.

---

## 7. Implementation cross-reference

| This document | Source |
|---|---|
| Pool `P`, exclusion `E`, `avail` | `src/node/node.cpp:729` (`check_if_selected`), `:762-768`; suspension upstream `src/node/registry.cpp:40-64` |
| `k_target`, `k_bft`, counter | `src/node/node.cpp:756`, `:778`, `:777`; defaults `include/determ/chain/genesis.hpp:145`, `src/chain/genesis.cpp:173`, `src/node/node.cpp:88` |
| Escalation conjunction + silent return | `src/node/node.cpp:781-788` |
| Committee derivation + sole round entry | `src/node/node.cpp:803`, `:806-808`, `:814` → `:822` |
| Claim generation (only-in-round) | `src/node/node.cpp:1180`, `:1194-1195` (Phase 1); `:1200`, `:1231-1232` (Phase 2) |
| Claim quorum `q = k_use − 1` | `src/node/node.cpp:1239`, `:1268-1277` |
| Event assembly / chaining / broadcast | `src/node/node.cpp:1280-1295`, `:1306`; seconds clock `include/determ/types.hpp:93-96` |
| Gossip adoption + dedup + revalidation | `src/node/node.cpp:1312`, `:1322`, `:1329-1331`, `:1354`, `:1357` |
| Sole clear site; post-accept reselect | `src/node/node.cpp:1856`, `:1945`; `reset_round` `:1737-1748` |
| Generation gate (cascade amplifier) | `src/node/node.cpp:2116` |
| Validator mirrors (V3/V10) | `src/node/validator.cpp:61`, `:97-103`, `:112-128`, `:196`, `:262-270`, `:285-288`; `src/node/producer.cpp:583-595` |
| Profiles for T-5 | `include/determ/chain/params.hpp:138`, `:142`, `:146`, `:150`, `:178` |
| R7 merge (recovery below `k_bft`) | `src/chain/chain.cpp:931` apply; FA9 `UnderQuorumMerge.md` |
| Empirical anchors | `tools/test_weak_3node.sh:7-17`; `tools/test_web_hybrid.sh:118-129`; `tools/test_regional_shards.sh:154-162`; `tools/test_bft_escalation.sh:76-84` |

---

## 8. Status

- **S-044, S-045: ✅ Mitigated** (`docs/SECURITY.md` §S-044/§S-045). The composite recommended in §4.4 SHIPPED: F-a quorum floor + θ=1 default + web M=4/K=3.
- Shipped fix summary. **F-a** (abort-claim quorum floor `max(2, K−1)` via the shared `chain::abort_claim_quorum()` helper, applied at the producer-formation / gossip-adoption / validator sites): closes S-044 — no-op for K≥3, unsatisfiable at K=2 so no single-claim abort forms (crash-stop, not cascade). **θ=1 default** (was 5): closes S-045 — the counter reaches the threshold on the first abort event, so it can never freeze below θ; gate 1 still bars premature escalation when MD margin exists and F-a's floor bars single-node forced escalation (S025 `A_premature` stays closed). This is a lighter, fully-sound alternative to **F-c** (the formation-failure certificate), which proved unnecessary once θ=1 makes the counter reachable — F-c's `k_bft`-signature-floor certificate would still be required if a future change wanted escalation to fire on formation failures that produce *no* abort event, but no such requirement remains. **F-b** (wall-clock decay) — rejected (consensus non-determinism, §4.2). The **`web` profile** was retuned M=3/K=2 → M=4/K=3 so the init default has K≥3 + MD margin 1 (single faults handled in MD mode, no escalation dependence). Live-validated (`tools/test_bft_escalation.sh` θ=1 default) + regression-locked (`tools/test_s044_gate_surface.sh` rewritten to the FIX shape).
- Companion TLA+ state machine: `tla/AbortEscalation.tla` (written in the same batch; **model-check pending**, consistent with the FB-series status in `README.md`). It models §1's state machine (pool / exclusion set / counter / four gates / claim quorum / generation gate) and is expected to pin T-1–T-4 as invariants plus the wedge as a reachable deadlock state.
- New findings F-1 (test header drift), F-2 (timestamp-dependent counter growth + SECURITY.md S-045 wording imprecision), F-3 (FA4 i.i.d.-retry model gap) are flagged in §6 for their respective owners; none is fixed here.
