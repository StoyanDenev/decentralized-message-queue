# EligibilityFloorDesign — the S-051 suspension-pool-exhaustion halt and the owner decision on a deterministic eligibility floor

This is the **OWNER-DECISION design document** for **S-051** (`docs/proofs/AdversarialTransportHarness.md` §3.4): round-1 abort suspensions can shrink the eligible creator pool below the committee size K, after which **no committee forms, no round runs, and — because suspension expiry is measured in block index while the height is frozen — no suspension ever expires**: a permanent, uniform-height chain halt. Any fix is protocol surgery on the committee-eligibility rule, which exists in three code surfaces that must stay identical (divergence = state_root / committee fork), so per the one-design-doc-per-decision directive the options are laid out here and the choice is deferred to the owner. **STATUS: DECIDED — Option B (partial floor, fill to K), owner decision 2026-07-17, implemented same day. See §7 for the shipped record.**

**Companion documents.** `AdversarialTransportHarness.md` §3.4 — the empirical record (CI-contention round, 2026-07-15) that found S-051 and the harness-side mitigation that is currently the only defense. `RoundStateRetrySoundness.md` §3.4 + §4 — why the S-047 retry and the S-050 stall valve both sit *outside* this defect (§3.4: the valve heals rounds that run but wedge; §4: a node with no round timers never evaluates the valve — and S-051 prevents rounds from running at all). `AbortCascadeLiveness.md` (S-044/S-045) — the abort-claim quorum and escalation machinery that *produces* the suspensions. `UnderQuorumMerge.md` (FA9) — the operator-initiated under-quorum merge, the nearest existing recovery primitive (Option D). `docs/SECURITY.md` §S-043 — the producer/validator-asymmetry outage class that the mirror constraint of §2 exists to prevent.

---

## 1. The defect

### 1.1 The suspension mechanism (as shipped)

A Phase-1 (round == 1) `AbortEvent` baked into a finalized block increments a per-domain accumulator and stamps the block index (`src/chain/chain.cpp:1682-1689`: `ar.count++; ar.last_block = b.index;` — plus the `SUSPENSION_SLASH` stake deduction, `include/determ/chain/params.hpp:79`). The accumulator lives in `Chain::abort_records_`, which is **part of the state root** (leaf `"b:" + domain`; `include/determ/chain/chain.hpp:244-250`, `:258`, `:303`). Records are never deleted; expiry is computed at read time.

The eligibility filter turns the record into a selection suspension of length

```
len = min(BASE_SUSPENSION_BLOCKS * 2^min(count-1, MAX_ABORT_EXPONENT), MAX_SUSPENSION_BLOCKS)
```

with `BASE_SUSPENSION_BLOCKS = 10`, `MAX_SUSPENSION_BLOCKS = 10'000`, `MAX_ABORT_EXPONENT = 10` (`include/determ/chain/params.hpp:35-37`), so a domain's suspension ranges from 10 blocks (first abort) to the 10,000-block cap. A domain is suspended at height `at_index` iff

```
at_index <= ar.last_block + len        (src/node/registry.cpp:43-51, the test at :50)
```

**Expiry is a pure function of block INDEX**, by design — it is what makes the filter a deterministic function of chain state (`include/determ/chain/chain.hpp:929-934`).

### 1.2 The halt mechanics

Committee selection (`Node::check_if_selected`, `src/node/node.cpp:953-1044`) draws its pool from the suspension-filtered registry (`select_committee_pool` at `:967`, which on the unpinned path is `NodeRegistry::build_from_chain`'s output) and returns without starting a round when the pool cannot staff a committee: `if (avail_domains.size() < k_use) return;` (`:1017`). `k_use` is K (`cfg_.k_block_sigs`, `:985`) except under BFT escalation — and the escalation gate (`:1010-1013`) counts **in-flight** aborts (`current_aborts_.size()`, `:1006`), which is empty in the idle steady state, so escalation does not rescue a chain whose suspensions are already baked: the effective formation threshold is **pool ≥ K**.

The failure loop, as reproduced (`AdversarialTransportHarness.md` §3.4, S-051 paragraph):

1. Under CPU starvation, **spurious** round-1 abort quorums form against healthy creators (two starved nodes co-timing-out on a healthy third — the claims are honestly signed, the quorum is genuine, the target was innocent). Each baked event suspends its target for ≥ 10 blocks and doubles the next suspension.
2. Suspensions accumulate faster than the (starved, slow) chain appends blocks; the eligible pool at the head height drops below K.
3. `check_if_selected` returns at `node.cpp:1017` on **every node identically** (the pool is a deterministic function of the shared chain state), so no node starts a round. The halt is uniform-height by construction — the empirical signature is all nodes frozen at the same height.
4. **The S-050 valve cannot fire.** `maybe_stall_reset_locked` (`node.cpp:1608`) is reachable only from the two phase-gated round-timeout handlers (`:1648-1649`, `:1700-1701`); with no round started, `phase_` stays `IDLE` (`:955`), no phase timer is armed, and the valve's trip conditions are never even evaluated. The valve heals wedged *rounds*; S-051 prevents rounds from existing.
5. **No suspension ever expires.** Expiry needs `at_index > ar.last_block + len`, and `at_index` (the head height) is frozen at the halt height H while `ar.last_block ≤ H` with `len ≥ 10`. Nothing on any node ever changes again: restarts do not help (the records are chain state), governance `PARAM_CHANGE` cannot land (no blocks). Permanent halt.

On an EXTENDED chain (D3.3b pinned committees) the manifestation shifts to the **epoch fold**: the pinned selection path reads the frozen checkpoint members and applies no suspension re-check (`src/node/committee_pool.cpp:17-27`), so mid-epoch suspensions bite only at the next `freeze_epoch_committee` fold (`src/chain/chain.cpp:1830-1838`); a fold that bakes a pool < K kills the entire next epoch, and with no blocks there is no further fold — the same absorbing halt, entered at an epoch boundary.

### 1.3 Empirical record

Reproduced repeatedly under CPU-starvation loops (`AdversarialTransportHarness.md` §3.4): twice in 30 pre-mitigation runs of `test-fa-partition-virtual` (majority frozen at uniform heights 5,5,5,5 and 8,8,8,8), and still at roughly 1-in-12 under harsher-than-CI contention with the intermediate 1 s phase timers that were validated before the shipped mitigation (`src/main.cpp:27729-27749`, the harness's own timer comment). The shipped mitigation is **harness-side only** (2 s phase timers, `src/main.cpp:27748-27749`, push the spurious-abort rate into the far tail); it does not close the defect, and the harness self-diagnoses a recurrence by dumping per-node heights (uniform frozen height = S-051).

Note the aggravating economics: each spurious abort also slashes an *innocent* domain (`SUSPENSION_SLASH`, `chain.cpp:1690-1696`), so a starvation storm both empties the pool and drains honest stake toward the `MIN_STAKE` eligibility floor — a second, slower path to the same exhaustion under STAKE_INCLUSION.

---

## 2. The mirror constraint (why this is protocol surgery)

The suspension filter is not one function — it is **the same four-predicate rule implemented in three surfaces**, and every one of them is consensus-load-bearing:

1. **Node-side selection** — `NodeRegistry::build_from_chain` (`src/node/registry.cpp:25-78`; `is_suspended` lambda `:43-51`). Feeds `check_if_selected` (producer side, `node.cpp:967`) and every present-head pool read.
2. **Validator committee re-derivation** — the validator does not own a copy of the predicate; it re-derives committees from a `NodeRegistry` handed in by the node, built by the **same** `build_from_chain` at the incoming block's index (`src/node/node.cpp:2415`, `:2611`), consumed via `select_committee_pool` in `check_creator_selection` (`src/node/validator.cpp:83-99`) and `check_abort_certs` (`:256`). Identical-by-construction *today*; any floor rule that adds pool-level logic outside `build_from_chain` would break that construction.
3. **D3.3b frozen committee checkpoints** — `Chain::freeze_epoch_committee` (`src/chain/chain.cpp`) formerly carried a hand-hoisted **copy** of the predicate because `Chain` cannot depend on `node/`; the comment above it warned *"The two predicate bodies MUST stay byte-identical forever (a divergence forks the cc: leaf vs the live selection filter)."* **The Option-B implementation dissolves this drift vector**: both this surface and surface 1 now call ONE shared body (`include/determ/chain/eligibility_floor.hpp`), so the byte-identical-forever obligation is discharged by construction, not vigilance (§4 R2).

`params.hpp` already warns that this triple surface is the drift vector: the suspension constants were deliberately hoisted chain-visible *"so that BOTH the node-side selection filter (NodeRegistry::build_from_chain) and any chain-layer consumer (Chain::freeze_epoch_committee, D3.3b) read one authoritative definition — a divergence between the live filter and a frozen committee checkpoint would be a state_root fork"* (`include/determ/chain/params.hpp:26-34`).

Hard requirements on ANY floor rule, therefore:

- **R1 (purity).** The rule must be a pure deterministic function of committed chain state at `at_index` — no wall clock, no local view, no gossip-order dependence — or different nodes derive different pools and the committee/`state_root` forks (the S-043 producer/validator-asymmetry outage class, `params.hpp:135-139`).
- **R2 (three identical mirrors).** It must land identically in `build_from_chain`, the validator's derivation input, and `freeze_epoch_committee`. The proven pattern is ONE shared definition (the `bft_committee_size` / `abort_claim_quorum` precedent, `params.hpp:135-160`), not three parallel edits.
- **R3 (K visibility).** Any rule conditioned on "pool < K" needs K where the rule runs. K today is node/validator config (`cfg_.k_block_sigs`, `k_block_sigs_`) — **`Chain` does not hold it**. `freeze_epoch_committee` therefore cannot evaluate the trigger without K being pinned onto `Chain` as genesis state (precedent: `epoch_blocks_`, D3.3b step 1).
- **R4 (record semantics unchanged).** The floor should change how records are *read*, not how they are *written* — `abort_records_` is a state-root component (`chain.hpp:258`), and leaving the write path untouched keeps every existing block-apply byte-identical.

---

## 3. Options

All options share R1-R4 above. "Eligible pool" below means the four-predicate-filtered set of §2; "base-eligible" means the same set with the suspension predicate removed (registered + active-window + stake floor only, `registry.cpp:61-63`).

### Option A — ignore-all floor

**Mechanics.** If `|eligible| < K` at `at_index`, ignore the suspension predicate entirely for that height: the pool is the base-eligible set. One boolean, computable in a first pass; the per-domain predicate becomes `is_suspended(d) && !floor_active`.

**Pros.** Smallest possible change; trivially deterministic; trivially mirrorable (the trigger is one shared function of `(registrants_, stakes_, abort_records_, at_index, K)`); easiest to prove equivalent across the three surfaces; dormant in every state where the pool is healthy, so all existing goldens are untouched.

**Cons / attack analysis.** The floor is all-or-nothing: the moment it trips, **every** suspended domain returns at once — including the genuinely faulty domain whose round-1 timeouts caused the abort storm in the first place. That domain immediately re-enters selection, re-aborts, and re-suspends (count grows, window doubles), so the chain oscillates: one abort-heavy recovery round per suspension cycle. Under STAKE_INCLUSION the economics eventually remove a persistent offender (`SUSPENSION_SLASH` × 100 = `MIN_STAKE`); under DOMAIN_INCLUSION (`min_stake = 0`) there is no economic exit and the oscillation is unbounded. Worse, it hands an attacker a **suspension jailbreak**: an adversary who can engineer enough spurious suspensions against honest domains (the §1.3 starvation schedule is exactly that, weaponized) trips the floor deliberately and re-enters *all* of its own suspended domains simultaneously — the punishment mechanism switches off precisely when the adversary is most active.

### Option B — partial floor (lift in deterministic order until |eligible| == K)

**Mechanics.** If `|eligible| < K`, lift suspensions one domain at a time, in a **total order that is a pure function of chain state**, only until the pool reaches exactly K. Proposed order over the suspended-but-otherwise-base-eligible domains:

```
ascending (ar.count, ar.last_block, domain)
```

— lowest abort count first (least chronic offender), then least-recently-suspended, then lexicographic domain as the deterministic tiebreak. All three keys come from `abort_records_` + the domain string, both committed chain state (R1 satisfied); the sort is total (domain is unique), so every node lifts the identical subset.

**Pros.** Restores liveness with the **minimum** intervention: exactly `K − |eligible|` domains return, and the chronically faulty (high `count`) return **last** — a persistent offender stays out as long as any lighter-history domain can take its seat. The jailbreak of Option A is blunted to its minimum width, and the deterrence semantics of the suspension mechanism survive. Dormant in all healthy states (goldens untouched), like A.

**Cons / attack analysis.** More code, in the worst place: the filter stops being a per-domain predicate and becomes a **two-pass pool computation** (compute base-eligible and eligible sets, then augment), which restructures all three mirror surfaces — exactly the surgery `chain.cpp:767-772` warns about. Mitigation is mandatory, not optional: hoist ONE shared implementation (a chain-visible free function over `(registrants, stake-reader, min_stake, abort_records, at_index, K)`, the `params.hpp:135-160` precedent) and make all three surfaces call it; plus the R3 cost of pinning K onto `Chain`. Attack surface: an adversary running several *lightly*-suspended domains (count 1 each) gets them lifted before a *recently* once-suspended honest domain — but count-1 domains are indistinguishable from spurious-abort victims anyway, and the adversary had to eat a real abort + slash per domain to be in the queue at all; the ordering never lifts a high-count domain while a low-count alternative exists, which is the property that matters. Sub-decision for the owner: fill to **K** (restores full MD committees, recommended — matches the `:1017` formation threshold in the idle steady state) vs fill to `k_bft` (smaller intervention but strands the chain in escalation-dependent territory that §1.2 shows is not reachable from idle).

### Option C — time-based suspension expiry

**Mechanics.** Make `len` decay in time rather than block index, so suspensions expire even while the height is frozen: either (a) wall-clock at each node, or (b) block-timestamp-based (expiry measured against some on-chain timestamp reference).

**Cons / attack analysis — fails R1 twice.** (a) Wall-clock is an immediate non-starter: eligibility becomes a function of *when each node looks*, different nodes derive different pools at the same height, and the committee/`state_root` forks on the first disagreement. (b) Timestamp-based looks deterministic but has a bootstrap hole and a trust hole. Bootstrap: expiry needs a "now", and with the chain halted no new timestamp is ever committed — the only candidate "now" is the **proposed** block's own timestamp, making the eligible pool (and hence the committee that must sign that block) a function of a field the committee itself chooses: circular, and multi-valued. Trust: the validator bounds a block timestamp only to **±30 s of local wall-clock** plus the lower-median-of-proposer-times rule (`BlockValidator::check_timestamp`, `src/node/validator.cpp:1694-1725`; the ±30 s constant at `:1723`, the S-003 widening comment at `:1695-1704` is explicit that the wall-clock check is *"just a sanity bound, not a consensus-defining property"*). Building eligibility on it promotes the sanity bound into a consensus-defining input: a proposer can skew its timestamp anywhere inside the ±30 s window to flip a domain across the expiry edge — a committee-composition grinding vector — and honest nodes at the window's edges can *disagree about block validity itself* (one node's clock accepts the timestamp, another's rejects it) which today costs one block relay and under C would fork the pool. This option re-introduces exactly the clock trust that the block-index design of `registry.cpp:50` was chosen to exclude. Not recommended in either variant.

**Pros**, for completeness: it is the only option that preserves "a suspension always eventually ends" as a local property, and (b) requires no K plumbing (R3 moot). Neither outweighs the fork surface.

### Option D — do nothing + documented operational recovery

**Mechanics.** Accept the halt as a designed boundary (like the FA9 under-quorum posture, `UnderQuorumMerge.md`); document the recovery procedure and keep the harness mitigation.

**Cons — the recovery procedure does not actually exist inside the protocol.** FA9's `MERGE_EVENT` folds an under-quorum **shard** into a neighbor, driven by operators of a *live* adjacent chain; it does not apply to a halted SINGLE chain or a halted beacon, which have no live parent to merge into. Restarting nodes does nothing (§1.2 step 5: the records are chain state). Governance cannot act (no blocks). The honest description of D's recovery is **out-of-band chain surgery** — relaunch from an edited snapshot by operator consensus — which abandons the trustless-recovery story for this failure class and, per §1.3, is a class that plain CPU starvation (no adversary) has already reached three times. D's real content is a bet that the 2 s-timer harness mitigation generalizes to production timing profiles; the 20-50 ms tactical/cluster profiles (`params.hpp:207-262`) are *tighter* than the harness timers, not looser, so the bet is backwards for exactly the deployments that care most.

**Pros.** Zero protocol risk, zero code, zero re-verification. Correct choice only if the owner judges the starvation regime out-of-model for v1.1.

---

## 4. Recommendation

**Option B (partial floor, fill to K), with the shared-implementation mitigation made a hard precondition.** Rationale, honestly stated:

- A restores liveness but neuters the suspension mechanism at the worst moment (the jailbreak); B restores liveness while — by construction of the proposed ordering — lifting the *fewest, least-guilty* domains, so the deterrent survives (this is a design property of §3-B's sort order; §5.1's falsify-on-mutant fixture is what would turn it into a tested claim). The delta between A and B is precisely the property the suspension mechanism exists for.
- C fails the purity requirement R1 in both variants; it trades a rare liveness defect for a permanent safety/fork surface. That trade is backwards for this codebase's design axioms.
- D leaves a reproduced, adversary-free permanent-death mode in the flagship tactical/cluster profiles with no in-protocol recovery.

**B's costs, not minimized:** it is the most code of the three viable options; it converts a per-domain predicate into a pool-level computation across three consensus-load-bearing surfaces (§2 R2) — the exact drift vector `chain.cpp:767-772` warns about — and it requires pinning K onto `Chain` as genesis state (§2 R3), a small but real state-surface addition with its own serialization/load-param plumbing (D3.3b step-1 precedent). The mandatory mitigation is ONE chain-visible shared function (declared alongside the suspension constants in `params.hpp` or a sibling chain-layer header) that all three surfaces call, plus the three-mirror equivalence test of §5 as a permanent regression gate. If the owner rejects that plumbing cost, A is the fallback — it is strictly better than D and its jailbreak is at least bounded by the abort/slash cycle under STAKE_INCLUSION — with the DOMAIN_INCLUSION oscillation caveat of §3-A recorded as a known residual.

Owner sub-decisions if B is chosen: (1) fill target K vs `k_bft` (recommend K, per §3-B); (2) the total order (recommend `(count, last_block, domain)` ascending as specified — any total order over committed state is sound, but the count-first key is what keeps chronic offenders out longest).

---

## 5. Validation plan (applies to whichever option is chosen; scaled to A/B — C/D need none of the code gates)

Shipped status of each gate is recorded inline (**DONE** = executed and green for the Option-B implementation). The unit gate is `test-eligibility-floor` (`src/main.cpp`, wrapper `tools/test_eligibility_floor.sh`, FAST-suite member) — 39 assertions.

1. **Deterministic pool-exhaustion repro (new unit test, binary-side). — DONE.** `test-eligibility-floor` builds a 6-domain chain and bakes round-1 `AbortEvent`s via the REAL apply path (no state poking) until the eligible pool < K, then asserts: k==0 baseline = the pre-fix `{dD,dE}` exhaustion pool (the halt precondition); floored pool = exactly K members; the lifted subset = the hand-computed `(count,last_block,domain)`-order prefix (K=3 lifts `{dC}` since `(1,11,dC) < (1,12,dB) < (2,10,dA)`). **Falsify-on-mutant executed:** reversing the `std::sort` order turns exactly the lift-order assertions RED (then restored green).
2. **Three-mirror equivalence test (new, and permanent). — DONE.** For the exhausted state at every `(K, at_index)` in `{0,2,3,5,6} × {13,22,31}`, `NodeRegistry::build_from_chain` == `Chain::freeze_epoch_committee` domain-for-domain, plus `select_committee_pool`'s unpinned fallback == the registry pool. Permanent regression gate for §2 R2. **Also DONE — the unsigned-underflow witness:** because both mirrors call the *same* shared body they diverge identically inside the equivalence loop, so a direct surplus-with-candidates assertion (K=2, at=22: floor dormant, `need = k−eligible` never wraps) was added; it turns the `if (eligible >= k)` guard mutant (`>=`→`==`) RED where the equivalence loop alone could not.
3. **Frozen-checkpoint fold under exhaustion (EXTENDED). — DONE.** `test-eligibility-floor`'s EXTENDED section drives a real D3.3b epoch fold (`shard_count=4`, `epoch_blocks=8`, boundary index 7) with `dC` suspended, so the floor lifts `dC` into the frozen `cc:` checkpoint `{dA,dB,dC}` (a K=0 control fold freezes only `{dA,dB}`, proving the floor is materially active). It then `save()`s, binds the floor-active root into a post-boundary block, and re-derives via `Chain::load` with the 7th (K) param: the reload re-folds `{dA,dB,dC}` identically, `k_block_sigs()` round-trips, and `state_root` matches. **The fail-closed half:** a lost-K reload (7th param defaulted 0) folds the floor-*disabled* committee, mismatches the bound root, and is rejected at S-033 — not silently forked. Mutant-verified: dropping the manifest-branch `k_block_sigs_` load assignment turns the reload RED. This is the §5.3 "validator acceptance is the half of the mirror unit test 2 cannot see" gate, discharged in-process. **Snapshot parity:** K is also serialized into the snapshot (`serialize_state`, guarded non-zero) and restored by `restore_from_snapshot` — mirroring `epoch_blocks` — so a snapshot-bootstrapped EXTENDED node re-pins K before its next boundary fold; the test asserts the round-trip directly. (The node layer additionally config-pins K at the `chain_loaded` convergence label, genesis-authoritative, covering the load / snapshot-restore / genesis / legacy paths uniformly.)
4. **Byte-identity gates (expected UNCHANGED). — DONE.** The floor is dormant whenever the pool is ≥ K, which holds in every existing golden history: `test-consensus-vectors` byte-identical, `state_root`-determinism tests green, and the cross-toolchain gate (`tools/ci_local.sh`, WSL2 GCC) green — FAST 241/0 on MSVC and Linux (240 prior + the new `test_eligibility_floor` wrapper). No golden drift. (R4: the abort-record *write* path is untouched.)
5. **Live gate — the harness that found it. — PARTIAL (see §7).** The floor is dormant in `test-weak_3node` and the FA harnesses' default profiles (pools stay ≥ K), so those pass unchanged; the CPU-starvation S-051 *schedule* itself (1 s-timer loops, 8-12+ per platform, asserting zero uniform-frozen-height recoveries) is the one gate not yet re-run behind the shipped 2 s mitigation and is tracked as the residual live-validation item in §7.
6. **K-on-Chain plumbing round-trip. — DONE.** Covered by gate 3's `Chain::load`-with-K path (`k_block_sigs()` round-trips through save/load) plus the mutant that drops the load-branch assignment; mirrors the `epoch_blocks_` D3.3b step-1 coverage.

---

## 6. Implementation cross-reference

| This document | Source |
|---|---|
| Suspension constants + mirror warning | `include/determ/chain/params.hpp:26-37` |
| **Shared floor implementation (Option B): suspension formula + 4-predicate filter + fill-to-K lift** | `include/determ/chain/eligibility_floor.hpp` (`suspension_active` / `domain_eligible` / `eligibility_floor_lifted`) |
| Suspension length + block-index expiry test | `src/node/registry.cpp` (now via the shared `suspension_active`) |
| Four-predicate eligibility filter (node side) — now calls the shared body + floor lift | `src/node/registry.cpp` (`build_from_chain`) |
| K pinned onto `Chain` as genesis state (R3), load-param before replay | `include/determ/chain/chain.hpp` (`k_block_sigs()` / `set_k_block_sigs`); `src/chain/chain.cpp` (7th `load` param, all 3 branches); `src/node/node.cpp` (load call + post-convergence setter) |
| Abort accumulator write (round==1 only) + slash — UNCHANGED (R4) | `src/chain/chain.cpp:1682-1697` |
| `abort_records_` in state root ("b:" leaf) | `include/determ/chain/chain.hpp:244-250`, `:258`, `:303` |
| D3.3b frozen committee (`freeze_epoch_committee`) — now calls the shared body; drift warning discharged | `src/chain/chain.cpp` |
| Unit + three-mirror + EXTENDED-fold-replay gate | `test-eligibility-floor` (`src/main.cpp`), `tools/test_eligibility_floor.sh` |
| Epoch fold site | `src/chain/chain.cpp:1830-1838` |
| Pinned pool path (no suspension re-check mid-epoch) | `src/node/committee_pool.cpp:13-41` |
| Selection pool + formation threshold (`avail < k_use → return`) | `src/node/node.cpp:967`, `:1017` |
| Escalation gate counts in-flight aborts only | `src/node/node.cpp:1006-1016` |
| S-050 valve unreachable from IDLE | `src/node/node.cpp:955`, `:1608`, `:1648-1649`, `:1700-1701` |
| Validator committee derivation (registry built at block index) | `src/node/validator.cpp:83-99`, `:256`; `src/node/node.cpp:2415`, `:2611` |
| ±30 s timestamp sanity bound (Option C analysis) | `src/node/validator.cpp:1694-1725` |
| Shared-formula precedent (S-043 guard) | `include/determ/chain/params.hpp:135-160` |
| Empirical record + harness mitigation | `docs/proofs/AdversarialTransportHarness.md` §3.4 |

---

## 7. Status

- **S-051: DECIDED — Option B (partial floor, fill to K). Owner decision 2026-07-17; implemented same day.** Both §4 sub-decisions accepted: fill target = **K**; lift order = ascending **`(count, last_block, domain)`**.
- **Shipped surface.** ONE shared implementation `include/determ/chain/eligibility_floor.hpp` (`suspension_active` / `domain_eligible` / `eligibility_floor_lifted`), called by BOTH consensus mirrors — `NodeRegistry::build_from_chain` (`src/node/registry.cpp`) and `Chain::freeze_epoch_committee` (`src/chain/chain.cpp`) — which discharges the R2 drift warning by construction. K pinned onto `Chain` as `k_block_sigs_` (R3), threaded through the 7th `Chain::load` param (set before replay, all 3 branches), serialized into the snapshot (`serialize_state`/`restore_from_snapshot`, guarded non-zero — parity with `epoch_blocks`, so `restore_from_snapshot` is self-sufficient), and a single post-convergence node setter (`src/node/node.cpp`, covering the load / snapshot-restore / genesis / legacy paths uniformly). Abort-record write path untouched (R4).
- **Validation (§5).** Gates 1-4 + 6 **DONE and green**: `test-eligibility-floor` (39 assertions) covers the exhaustion repro, the three-mirror equivalence, the EXTENDED floor-active fold save→load→replay (with a fail-closed S-033 lost-K reload), the K round-trip through both `Chain::load` and `restore_from_snapshot`, and the surplus-underflow witness; three mutants executed RED then restored (sort-order reversal, the `>=` underflow guard, a dropped load-branch K assignment). FAST 241/0 on MSVC + WSL2 GCC; goldens byte-identical (floor dormant on all healthy history). Gate 5 (the live CPU-starvation S-051 *schedule* behind the 2 s harness mitigation) is the tracked residual — the floor is dormant in the default-profile live cluster, which passes unchanged; re-running the 1 s-timer starvation loops to observe active-floor recovery is owner-gated follow-up.
- **Left to the owner.** `docs/SECURITY.md` S-051 status flip (owner-owned file); the gate-5 starvation-schedule live re-run.
