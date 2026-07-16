# EligibilityFloorDesign — the S-051 suspension-pool-exhaustion halt and the owner decision on a deterministic eligibility floor

This is the **OWNER-DECISION design document** for **S-051** (`docs/proofs/AdversarialTransportHarness.md` §3.4): round-1 abort suspensions can shrink the eligible creator pool below the committee size K, after which **no committee forms, no round runs, and — because suspension expiry is measured in block index while the height is frozen — no suspension ever expires**: a permanent, uniform-height chain halt. Any fix is protocol surgery on the committee-eligibility rule, which exists in three code surfaces that must stay identical (divergence = state_root / committee fork), so per the one-design-doc-per-decision directive the options are laid out here and the choice is deferred to the owner. **STATUS: OPEN. No code has been changed.**

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
3. **D3.3b frozen committee checkpoints** — `Chain::freeze_epoch_committee` (`src/chain/chain.cpp:774-794`) carries a hand-hoisted **copy** of the predicate (`is_suspended` lambda `:776-784`) because `Chain` cannot depend on `node/`. The comment above it is explicit: *"The two predicate bodies MUST stay byte-identical forever (a divergence forks the cc: leaf vs the live selection filter)"* (`chain.cpp:767-772`).

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

1. **Deterministic pool-exhaustion repro (new unit test, binary-side).** Build a chain (K=3 profile) and bake round-1 `AbortEvent`s into applied blocks until the eligible pool at head < K. Assert: pre-fix behavior (pool < K, `build_from_chain` size < K — the current halt precondition) as the falsify-on-mutant baseline; post-fix, the floored pool has exactly K members, and (Option B) the lifted subset equals the expected `(count, last_block, domain)`-order prefix, verified against a hand-computed fixture. Falsify-on-mutant per the TLC-track standard: flip the sort key order in the fixture and require the test to go red.
2. **Three-mirror equivalence test (new, and permanent).** For the same exhausted chain state, assert byte-equal pools from (a) `NodeRegistry::build_from_chain(chain, h)`, (b) the validator path's `select_committee_pool(chain, reg, epoch, region)` on the unpinned branch, and (c) `Chain::freeze_epoch_committee(h)` member domains. Extend the existing `test-node-registry` surface (`src/main.cpp:39031` region) and the D3.3b fold assertions. This is the regression gate for §2 R2 and must outlive the fix.
3. **Frozen-checkpoint fold under exhaustion (EXTENDED).** Drive an epoch fold at a boundary where the pool is < K; assert the checkpoint members include the floored domains identically to the live filter, and that a block produced by the floored committee validates on a fresh node syncing from genesis (validator acceptance is the half of the mirror that unit test 2 cannot see — sync-replay covers it).
4. **Byte-identity gates (expected UNCHANGED).** The floor is dormant whenever the pool is ≥ K, which holds in every existing golden history — so: golden consensus vectors byte-identical, `state_root` determinism tests green, and the cross-toolchain gate (`tools/ci_local.sh`, WSL2 GCC — the gate that caught the last cross-toolchain `state_root` fork) green on both platforms. Any golden drift means the floor triggered where it must not: treat as a fix bug, never re-bless. (R4: the abort-record *write* path is untouched, so no EXTENDED-golden re-bless is expected or acceptable.)
5. **Live gate — the harness that found it.** `test-fa-partition-virtual` CPU-starvation loops per `AdversarialTransportHarness.md` §3.4, with the harness's 1 s-timer configuration restored for this gate (the 2 s mitigation deliberately suppresses the S-051 schedule; the fix must be validated against the schedule, not behind the mitigation). Per the standing rule for nondeterministic-liveness fixes: 8-12+ loops per platform, both platforms. Success criterion: zero uniform-frozen-height outcomes, and every starvation-induced pool dip recovers (floor forms a committee → rounds run → the S-050 valve is reachable again for anything that then wedges).
6. **If Option B:** the K-on-Chain plumbing gets its own load-param/serialization round-trip coverage (snapshot save/load with the pinned K, mirroring the `epoch_blocks_` D3.3b step-1 tests).

---

## 6. Implementation cross-reference

| This document | Source |
|---|---|
| Suspension constants + mirror warning | `include/determ/chain/params.hpp:26-37` |
| Suspension length + block-index expiry test | `src/node/registry.cpp:43-51` (expiry at `:50`) |
| Four-predicate eligibility filter (node side) | `src/node/registry.cpp:60-64` |
| Abort accumulator write (round==1 only) + slash | `src/chain/chain.cpp:1682-1697` |
| `abort_records_` in state root ("b:" leaf) | `include/determ/chain/chain.hpp:244-250`, `:258`, `:303` |
| D3.3b frozen-committee predicate copy + byte-identical warning | `src/chain/chain.cpp:767-794` |
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

- **S-051: OPEN — owner decision required.** No code has been changed by this document. The only shipped defense is the harness-side timer mitigation (`AdversarialTransportHarness.md` §3.4), which reduces reproduction frequency in the FA harness and does not protect production deployments.
- **The decision:** Option A / B / C / D per §3; recommendation is **B** (§4) with the shared-implementation precondition; A is the designated fallback if the B plumbing cost is rejected.
- **On acceptance:** implementation follows §5's gates; the three-mirror equivalence test (§5.2) becomes a permanent regression gate regardless of which option ships.
