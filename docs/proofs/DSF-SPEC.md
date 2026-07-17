> **TIER: FUTURE — post-1.0, non-authoritative.** Design-stage; does NOT describe shipped code and is NOT coherence-maintained against src/. Roadmap index: docs/ROADMAP.md

# Deterministic-Simulation Framework (DSF) — design specification

**Status:** design spec + **IMPLEMENTED (increments 1-12, owner-authorized R61).** The self-contained simulation core (virtual clock + deterministic scheduler + virtual-network fault SEAM + byte-stable trace + safety/liveness property loop) ships under `sim/` with the `determ-dsf` runner and **76 baked scenarios** (incl. the §Q5 randomized generator's EIGHT templates — 6 reliable-broadcast variants + a self-test (inc-4), 6 single-value-flood agreement variants + a self-test (inc-6), 6 monotone-ratchet variants + a self-test (inc-7), 6 quorum/threshold-commit variants + a self-test (inc-8), 6 receipt-conservation variants + a self-test (inc-9), 6 view-reconciliation variants + a self-test (inc-10), 6 crash/recover-replay variants + a self-test (inc-11, the first generated use of the crash/recover seam), and 6 partition/heal split-brain variants + a self-test (inc-12, the first generated use of the partition seam — the generator now exercises every fault dimension the simulator models)): 6 framework-demonstration (increment 1) + 14 adversarial (increments 2-3) covering the §Q7 families equivocation, cross-shard receipt conservation, selective-abort bias, BFT-escalation monotonicity, DKG threshold, F2 view-reconciliation, and partition quorum — each adversarial family paired with an `expect_violation` self-test proving its checker fires on a planted bug. **Increment 5 exposes the §Q5 generator on the command line: `--generate N --seed S [--template broadcast|agree|ratchet|quorum|conserve|recon|crashrec|partition]` registers N reproducible `gen_run_NN` variants drawn from S (count-parametric, generator-seed byte-stable + seed-varied), listable and runnable, each byte-identically replayable (§Q6) — the "CI runs N variants overnight; a failed variant's seed reproduces it bit-for-bit" contract, realized operationally by `tools/operator_dsf_sweep.sh`. Increment 6 adds the SECOND generator template (single-value-flood agreement, a §Q7 equivocation/partition checker family), increment 7 the THIRD (monotone ratchet / non-regression, a §Q7 BFT-escalation/commit-index checker family), increment 8 the FOURTH (quorum/threshold commit, a §Q7 DKG-threshold/BFT-pre-vote checker family), increment 9 the FIFTH (receipt conservation, the §Q7 FA7 no-double-credit checker family), increment 10 the SIXTH (F2 view reconciliation, the §Q7 no-phantom-evidence checker family), increment 11 the SEVENTH (crash/recover replay, the §Q7 non-idempotent-recovery checker family, on a deterministic per-follower crash schedule), and increment 12 the EIGHTH (partition/heal split-brain, the §Q7 partition-quorum checker family, on a deterministic majority-cut window), all selected via `--template`.** Determinism is byte-identical per (scenario, seed); gated by `tools/test_dsf_{core,inc2,inc3,inc4,inc5,inc6,inc7,inc8,inc9,inc10,inc11,inc12}.sh`. **STILL FUTURE:** the §Q1/§Q2 production dependency-injection (threading `time::Clock` + `net::Transport` through real Node/Validator/Producer) so scenarios drive the actual consensus engine, and the four production invariants (FA1/A1/FA6/FA7) — the toy SimState stands in for now. Resolves the design for S-035 Option 2. **Recommended sequencing: ship before Phase A** (rather than as a Phase D prerequisite as previously planned) — subsumes A10 NH1 Stage 1 streams 1 + 2, provides Byzantine coverage for every Phase A through D item as it lands.

**Companion documents:**
- `SECURITY.md` §S-035 — the underlying audit finding
- `plan.md` §A10 — NH1 Stage 1 testing infrastructure (DSF subsumes streams 1 + 2)
- `F2-SPEC.md`, `v2.22-PRIVACY-SPEC.md`, `Beaconless-v2-SPEC.md` — Phase A through D specs whose Byzantine-bug discovery DSF accelerates

---

## 1. Scope

DSF is a test harness that runs distributed-protocol code as if it were a single-threaded program, with three substitutions:

1. **Virtual clock** replaces wall-clock time. Time advances only when the test explicitly requests it.
2. **Virtual network** replaces real sockets. Messages travel through controlled queues; the test decides delivery order, latency, drop probability, partition topology.
3. **Scriptable actors** replace real validator processes. A test spawns K validator instances inside one process, instructs any subset to misbehave (drop messages, equivocate, withhold partial signatures, crash mid-round), and observes the entire system's response.

Defining property: **the same test inputs produce the same outputs every time**, regardless of host CPU speed, OS scheduling, or network conditions. A bug found in run N is reproducible in run N+1 with byte-identical state from a recorded seed.

The artifacts produced by DSF:
- A virtual-clock + virtual-network + scriptable-actor harness running real Determ consensus code
- A scenario DSL for expressing adversarial test patterns
- Property checkers running after every step (FA1, A1, FA6, FA7 invariants)
- A randomized scenario generator parameterized over committee size, network conditions, adversary strategy
- Replay tooling — any failed scenario reproducible from its random seed
- An initial scenario set covering known-interesting Byzantine cases

The DSF does NOT cover:
- Fuzz testing at wire-format level (A10 stream 3 handles this — different abstraction layer)
- Cross-implementation test vectors (A10 stream 4 handles this — serves cross-implementation compatibility)
- Real network performance benchmarking (DSF abstracts time; performance measurement requires real-clock testing)

---

## 2. Design decisions

### Q1: Virtual-clock interface

**Decision: replace `std::chrono::steady_clock::now()` call sites with a `time::Clock` interface; route all timer / deadline code through the interface.**

```cpp
namespace determ::time {

// Abstract clock interface. Production uses RealClock (wraps std::chrono).
// Tests use VirtualClock (test-controlled time advance).
class Clock {
public:
    virtual ~Clock() = default;
    virtual std::chrono::steady_clock::time_point now() const = 0;
    virtual void sleep_until(std::chrono::steady_clock::time_point when) = 0;
};

class RealClock : public Clock {
    // Production: passes through to std::chrono::steady_clock.
};

class VirtualClock : public Clock {
    // Tests: time advances only via advance(duration). sleep_until queues
    // a wake-up event in the simulator's event queue.
    void advance(std::chrono::milliseconds delta);
};

} // namespace determ::time
```

All Determ code that reads or sleeps on time consults the injected `Clock` instance. Production uses `RealClock`; DSF tests use `VirtualClock`.

**Implementation effort.** ~2-3 days for the interface + threading the dependency through Node, Validator, Producer, RPC, Gossip. Mechanical refactor; no semantic change for production builds.

### Q2: Virtual-network interface

**Decision: replace the `asio` socket layer with a `net::Transport` interface; production wraps asio, tests use `VirtualTransport`.**

> **Environment note (doc-consolidation inc.4 drift-repair).** This §Q2 decision was realised differently from the sketch below: `asio` was not wrapped but **deleted** from the tree. Production now runs the native `net::Transport` backends directly — `IocpTransport` (Windows) and `ReactorTransport` (epoll/POSIX) — with no third-party transport library; the `AsioTransport` shown below never became the production default. See `MinixTacticalProfile.md` §4 for the delivered design. The `VirtualTransport` half of the decision did ship (`include/determ/net/virtual_transport.hpp`).

```cpp
namespace determ::net {

class Transport {
public:
    virtual ~Transport() = default;
    virtual void send(PeerId to, Bytes msg) = 0;
    virtual void on_receive(std::function<void(PeerId, Bytes)> handler) = 0;
};

class AsioTransport : public Transport {
    // Production: real TCP sockets via existing asio code.
};

class VirtualTransport : public Transport {
    // Tests: messages enqueued into a simulator-controlled queue with
    // configurable per-link latency, drop rate, partition topology.
};

} // namespace determ::net
```

**Simulator-side controls.** Each VirtualTransport instance is wired to the central Simulator. Scenarios can:
- Reorder messages within a link's queue
- Drop messages probabilistically (configurable rate per link)
- Partition links bidirectionally or unidirectionally
- Replay or duplicate messages
- Tamper with bytes (signature-verification edge cases)

**Implementation effort.** ~1 week for the interface + asio wrap + virtual implementation + per-link control surface.

### Q3: Scenario DSL

**Decision: pure C++ scenario classes — no embedded scripting language.**

Scenarios are C++ classes that inherit from a base `Scenario` interface. The simulator runs them step-by-step, advancing virtual time and observing invariants.

```cpp
class SelectiveAbortScenario : public Scenario {
public:
    void setup(Simulator& sim) override {
        chain_ = sim.bootstrap_chain(K=3, M=3, profile=TACTICAL_TEST,
                                      epoch_blocks=20);
        sim.advance_to_block(19);  // one block before epoch boundary
        sim.member(2).behavior = SelectivelyAbortIfNot(favorable_subset_);
    }

    void run(Simulator& sim) override {
        sim.advance_to_block(100);
    }

    void check(const SimulatorState& state) override {
        EXPECT_NEAR(chi_squared_test(state.committee_distribution,
                                      uniform_expected_distribution),
                    1.0, 0.01);
    }
};
```

**Rationale.** Embedded scripting (Lua, Python) adds dependency + audit surface. C++ scenarios stay in the existing build system; reviewers read scenarios the same way they read other test code.

**Implementation effort.** ~3-5 days for the base interface + dispatcher + initial scenario harness.

### Q4: Property checkers

**Decision: invariant checkers run after every simulator step.**

Property checkers verify FA-track invariants continuously:

| Invariant | Source | Check |
|---|---|---|
| FA1 single-block-per-height | `Safety.md` T-1 | Every finalized height has exactly one K-of-K-signed block instance (apply-validating); two K-of-K-signed instances must produce different apply-validating state_roots. |
| A1 unitary supply | `EconomicSoundness.md` | `sum(account.balance) + sum(stake.locked) + sum(stake.unlocking) == genesis_total + accumulated_subsidy + accumulated_inbound - accumulated_slashed - accumulated_outbound` |
| FA6 equivocation slashing | `EquivocationSlashing.md` | Any committee member signing two conflicting blocks at the same height appears in the slashed set by the next epoch boundary. |
| FA7 cross-shard atomicity | `CrossShardReceipts.md` | For every cross-shard receipt observed on the destination shard, the corresponding outbound debit exists on the source shard, exactly once. |

Each scenario can additionally specify scenario-specific properties (e.g., "selective-abort attacker doesn't bias committee distribution").

**Implementation effort.** ~3-5 days for the invariant-checker framework + initial four checkers.

### Q5: Random scenario generator

**Decision: parameterized scenario generator that produces randomized variants from a seed.**

The generator accepts a seed and a scenario template, producing reproducible variants. Each variant is independent; CI runs N variants overnight.

```cpp
class RandomScenarioGenerator {
public:
    // Generate variants of "selective abort attack" with random
    // committee sizes, network latencies, adversary strategies.
    std::vector<std::unique_ptr<Scenario>> generate(
        ScenarioTemplate tmpl,
        uint64_t seed,
        size_t count);
};
```

**Reproducibility.** Every random choice routes through the seed. A failed variant prints its seed; the seed reproduces the variant bit-for-bit on any machine.

**Implementation effort.** ~3-5 days for the generator + 5 initial scenario templates.

**IMPLEMENTED (increments 4-6).** `sim/generator.hpp` — `draw_params(SplitMix64&)` draws a fault profile (followers/latency/jitter/drop/dup) as a pure function of a generator seed; `register_generated_scenarios(out, gen_seed, count, name_prefix, with_selftest, tmpl)` emits `count` reproducible variants of a `GenTemplate`. **Eight templates ship:** (a) `make_broadcast_variant()` — a reliable-broadcast template (leader re-broadcasts the issued total as an idempotent monotone `SET(total)`, follower keeps `count=max`) so every variant never overcounts and always converges; (b) `make_agreement_variant()` (increment 6) — a single-value-flood agreement template (leader floods one decision value V, follower latches the FIRST value first-write-wins) so every honest variant never splits (`agree_no_split`) and always decides (`agree_all_decided`); (c) `make_ratchet_variant()` (increment 7) — a monotone-ratchet template (leader ramps a ceiling and re-floods it, each follower keeps a monotone high-water mark and commits it) so every honest variant's committed value never regresses (`ratchet_no_regress`) and always advances to the ceiling (`ratchet_advanced`); (d) `make_quorum_variant()` (increment 8) — a quorum/threshold-commit template (a collector counts DISTINCT ack senders and commits once distinct ≥ K = ⌊N/2⌋+1) so every honest variant never commits below quorum (`quorum_no_early_commit`) and always reaches it (`quorum_commits`); (e) `make_conservation_variant()` (increment 9) — a receipt-conservation template (a source issues + re-floods unique-id receipts, each ledger credits EXACTLY ONCE keyed on receipt id — the FA7 applied-receipt-registry rule) so every honest variant never double-credits (`conserve_no_double_credit`) and always credits everything (`conserve_all_credited`); (f) `make_reconcile_variant()` (increment 10) — an F2 view-reconciliation template (two sources flood disjoint halves of a growing entry universe, each reconciler merges by union-keyed-on-entry-id — the no_phantom_evidence rule) so every honest variant never holds fabricated evidence (`recon_no_phantom`) and always merges the complete universe (`recon_complete`); (g) `make_crashrec_variant()` (increment 11) — a crash/recover-replay template (every follower crashes + recovers on a deterministic index-derived schedule under the drawn profile; kv persists, so the honest recovery does NOTHING and the re-flood heals the gap) so every honest variant never overcounts (`crashrec_no_replay`) and always converges with a provably non-vacuous crash path (`crashrec_all_converged` requires crashes == recoveries == followers); (h) `make_partition_variant()` (increment 12) — a partition/heal split-brain template (a minority-side quorum collector is link-cut from the ceil(N/2) majority for a deterministic window, leaving exactly K-1 reachable senders) so every honest variant never commits minority-side while partitioned (`part_no_minority_commit`) and both sides commit after the heal (`part_both_commit` requires healed==1). Each template carries a self-test proving a generated fault profile surfaces a real bug: `gen_overcount_selftest` (non-idempotent apply under forced dup) / `gen_disagree_selftest` (a Byzantine-equivocating leader) / `gen_regress_selftest` (a raw-committing follower under a Byzantine decreasing leader → the committed value drops below its high-water) / `gen_underquorum_selftest` (a raw-ack-counting collector under forced dup → commits at distinct=1 < K=2) / `gen_doublecredit_selftest` (a raw-delivery-counting ledger → credited exceeds issued at the first re-delivery) / `gen_phantom_selftest` (a reconciler fabricating an entry no source issued → caught on clean delivery) / `gen_replay_selftest` (a recovery procedure re-applying its journal on top of persisted state → count=10 > issued=5 at the recovery event) / `gen_splitbrain_selftest` (a minority quorum mis-set to K-1 → commits WHILE PARTITIONED). Increments 4/6/7/8/9/10/11/12 each baked 6 honest variants (`gen_broadcast_NN`/`gen_agree_NN`/`gen_ratchet_NN`/`gen_quorum_NN`/`gen_conserve_NN`/`gen_recon_NN`/`gen_crashrec_NN`/`gen_partition_NN`); **increment 5 wires the CLI** — `determ-dsf --generate N --seed S [--template broadcast|agree|ratchet|quorum|conserve|recon|crashrec|partition] [--list | --scenario gen_run_NN]` registers N `gen_run_NN` variants of the chosen template drawn from S (no self-test on this path). Two-seed model: fault PARAMETERS = f(generator seed); fault REALIZATION = f(run seed); the crash/partition schedules are pure functions of the topology (no PRNG); the `--generate N --seed S` form collapses both seeds to one for a single-command reproducible run. Gated by `tools/test_dsf_{inc4,inc5,inc6,inc7,inc8,inc9,inc10,inc11,inc12}.sh`; swept operationally by `tools/operator_dsf_sweep.sh`. **The eight templates are one code pattern (`GenTemplate` enum + `make_variant` dispatcher + a per-template planted-bug self-test twin) — consolidated with the documented recipe for the next one in [GeneratorTemplateFamily.md](GeneratorTemplateFamily.md).**

### Q6: Replay tooling

**Decision: failed scenarios are reproducible from a saved seed + scenario name.**

```bash
$ determ-dsf run --scenario selective_abort --seed 0xdeadbeef
[seed 0xdeadbeef] running selective_abort...
[step 1247] FAIL: invariant A1 violated at height 47
  state_dump.json saved
  trace.log saved
```

Re-running with `--seed 0xdeadbeef` reproduces the failure deterministically. State dumps + trace logs are byte-stable across runs of the same seed.

**Implementation effort.** ~2-3 days for the replay harness + state-dump format.

**IMPLEMENTED (increment 5).** The replay contract ships via the `determ-dsf` runner: `--scenario <name> --seed <hex|dec>` prints `[seed 0x…] running <name>…` and, on a violation, the reproducing `--scenario … --seed …` command + `--trace <path>`; the same (scenario, seed) yields a byte-identical trace on any host. For generated variants, `--generate N --seed S --scenario gen_run_NN` reproduces both the variant's fault profile and its realization from one command. (`--trace <path|-|off>` replaces the design-sketch state-dump file; the byte-stable trace subsumes it.) Gated by the run-determinism assertions in `tools/test_dsf_{core,inc2,inc3,inc4,inc5}.sh`.

### Q7: Initial scenario set

**Decision: ship with 30 initial scenarios covering known-interesting Byzantine cases.**

| Category | Example scenarios | Count |
|---|---|---|
| Selective-abort attacks | Single-member abort; coordinated K-1 abort; selective-by-randomness-outcome | 5 |
| Equivocation | Two-block equivocation; equivocation across shard partition | 4 |
| Network partition | Bidirectional partition; one-way partition; intermittent partition | 4 |
| Cross-shard | Receipt loss during merge window; double-credit race; cascade merge | 5 |
| DKG | Single-member silent commit; complaint-phase exclusion; below-threshold | 4 |
| F2 view reconciliation | Evidence pool divergence; receipt intersection-empty; timestamp out-of-window | 4 |
| BFT escalation | Persistent abort triggering escalation; sentinel-zero accounting; proposer rotation | 4 |

**Implementation effort.** ~1 week for the initial 30 scenarios. Each scenario is ~50-150 LOC.

---

## 3. Wire-format / API additions

DSF is a test-only framework; no on-chain wire-format changes. Internal API additions:

- `time::Clock` injection in Node, Validator, Producer, RPC, Gossip constructors
- `net::Transport` injection in Gossip constructor
- New `tools/dsf/` directory with simulator + scenarios
- New `determ-dsf` binary (test runner; not deployed in production builds)

---

## 4. Implementation work units

### 4.1 Virtual-clock abstraction (~2-3 days)

- Define `time::Clock`, `RealClock`, `VirtualClock`.
- Thread `Clock&` through `Node`, `Validator`, `Producer`, `RPC`, `Gossip` constructors.
- Replace `std::chrono::steady_clock::now()` call sites (grep-driven; ~30-50 sites).
- Verify production behavior unchanged via existing integration tests.

### 4.2 Virtual-network abstraction (~1 week)

- Define `net::Transport`, `AsioTransport`, `VirtualTransport`.
- Wrap existing asio socket calls in `AsioTransport`.
- `VirtualTransport` implements simulator-controlled message queues, per-link drop/latency/partition.
- Verify production behavior unchanged.

### 4.3 Scenario DSL + simulator core (~3-5 days)

- `Scenario` base class with `setup() / run() / check()` lifecycle.
- `Simulator` class orchestrating scenario execution: advance virtual time, dispatch messages via VirtualTransport, run validators, run property checkers.
- Scenario registration + dispatcher.

### 4.4 Property checker framework (~3-5 days)

- `Invariant` base class with `check(SimulatorState&) -> Result`.
- Initial four checkers (FA1, A1, FA6, FA7).
- Continuous-check mode: invariants run after every simulator step.

### 4.5 Random scenario generator (~3-5 days)

- `RandomScenarioGenerator` with seeded variant generation.
- 5 initial scenario templates (selective-abort, partition, DKG, F2, BFT-escalation).
- Reproducibility test: same seed → same variant.

### 4.6 Replay tooling (~2-3 days)

- `determ-dsf run --scenario NAME --seed HEX` runner.
- State dump + trace log on failure.
- Byte-stable across runs of same seed.

### 4.7 Initial 30-scenario set (~1 week)

- Categories per Q7: selective-abort, equivocation, partition, cross-shard, DKG, F2, BFT.
- Each scenario ~50-150 LOC.
- All scenarios pass against current production code (or, if they expose a real bug, the bug is tracked and the scenario marked as known-failure).

### 4.8 CI integration + docs (~2-3 days)

- Add DSF run to existing `tools/run_all.sh` (or new `tools/dsf_check.sh`).
- Documentation: `docs/DSF.md` — how to write scenarios, how to interpret failures, how to add invariant checkers.

---

## 5. Total estimated cost

| Sub-component | Effort |
|---|---|
| Virtual-clock abstraction | 2-3 days |
| Virtual-network abstraction | 1 week |
| Scenario DSL + simulator core | 3-5 days |
| Property checker framework | 3-5 days |
| Random scenario generator | 3-5 days |
| Replay tooling | 2-3 days |
| Initial 30-scenario set | 1 week |
| CI integration + docs | 2-3 days |
| **Total** | **~3-4 weeks** |

Matches S-035 Option 2 estimate. Schedule: ship **before Phase A starts** (Pre-Phase-A position in V2-DESIGN.md Recommended Sequencing).

---

## 6. Impact on A10 NH1 Stage 1

DSF subsumes A10's largest two streams:

| A10 stream | DSF subsumes? | Action |
|---|---|---|
| 1. Extend bash integration tests (~2 months) | **Yes.** | Retire. DSF scenarios provide strictly more thorough behavioral coverage including Byzantine cases bash tests can't drive. |
| 2. Property tests for invariants (~1 month) | **Yes.** | Retire. DSF's property checker framework runs invariants continuously after every step — more comprehensive than separate property tests. |
| 3. Wire-format fuzz tests (~2 weeks) | **No.** | Keep. Fuzz operates at raw-input level; complementary to DSF. |
| 4. Crypto + serialization test vectors (~1 month) | **No.** | Keep. Vectors serve cross-implementation compatibility; DSF doesn't replace this. |

**A10 revised scope:** streams 3 + 4 only, ~6 weeks total (down from ~3-4 months).

---

## 7. Risks and rollback plan

**Risk: Virtual-clock + virtual-network abstractions introduce subtle production bugs.** Threading `Clock&` and `Transport&` through every consensus path touches many files.

*Mitigation.* Mechanical refactor only. Production behavior is unchanged because `RealClock` and `AsioTransport` are pass-through wrappers. Existing 152 in-process unit tests + integration tests catch regressions immediately.

**Risk: Scenarios reveal real bugs in production code.** Likely outcome — DSF is built to find Byzantine bugs.

*Mitigation.* This is the intended behavior. Every revealed bug gets a tracking ticket + a regression test (the scenario itself). DSF design includes "known-failing scenario" support so a freshly-discovered bug doesn't block CI while it's being fixed.

**Risk: DSF maintenance overhead exceeds value.** If scenarios drift out of sync with protocol changes, the framework rots.

*Mitigation.* Treat DSF scenarios as first-class regression tests — every new v2.X feature pairs with a DSF scenario. Same discipline as the existing `tools/test_*.sh` pattern. Lightweight to maintain at the scenario level (~50-150 LOC each).

**Risk: Spec disagreement during review.** Q3 (C++ scenarios vs embedded scripting) and Q7 (initial 30-scenario set) are the most consequential choices.

*Mitigation.* Pre-implementation review per §8 below.

**Rollback plan.** If DSF introduces production regressions:
1. Revert the time::Clock + net::Transport threading commits.
2. Production builds return to `std::chrono::steady_clock` + raw asio calls.
3. DSF binary + scenarios remain available as a development tool decoupled from production.
4. Re-attempt with fewer call-site changes if the refactor surface was too large.

---

## 8. Decision review

This spec is recommended to be reviewed before implementation. Reviewers should confirm:

1. **Q1 + Q2 dependency-injection refactor.** Acceptable to thread `Clock&` and `Transport&` through 30-50 call sites? Alternative: global mockable singletons (smaller refactor, weaker dependency hygiene).
2. **Q3 C++ scenarios vs embedded scripting.** C++ scenarios stay in-tree and reviewable. Alternative: Lua or Python embedded for faster scenario authoring; trade-off is dependency + audit surface.
3. **Q4 four initial invariant checkers (FA1, A1, FA6, FA7).** Sufficient for v2 coverage? Additional candidates: FA2 (collaborative inclusion), FA5 (BFT-mode safety), FA8 (committee selection bias).
4. **Q7 initial 30-scenario set.** Right balance across categories? Should DKG / F2 scenarios get more weight given Phase A focus?
5. **Pre-Phase-A scheduling.** Accept ~3-4 weeks before Phase A starts (delays Phase A by that much in exchange for DSF coverage during Phase A development).
6. **A10 retirement of streams 1 + 2.** Accept that DSF replaces ~3 months of A10 work; A10 reduces to streams 3 + 4 (~6 weeks).

Once these are confirmed, implementation can proceed against §4 work units. Estimated 3-4 weeks from spec-review acceptance.

---

## 9. What this enables downstream

DSF with the initial 30-scenario set unlocks:

- **Byzantine-bug discovery during Phase A development.** v2.7 F2, v2.10 DKG, v2.12 cross-shard 2PC all ship with deterministic-simulation coverage rather than integration-test-only. Bugs caught in CI rather than in production.
- **A10 NH1 Stage 1 reduces to ~6 weeks** (streams 3 + 4 only). ~2-3 months of A10 work eliminated.
- **Phase D Beaconless v2 starts with DSF already in place.** Phase D's previously-listed DSF prerequisite is satisfied; Beaconless v2 implementation starts ~3-4 weeks earlier.
- **Regulatory-deployment compliance story.** "We ran 10⁹ adversarial scenarios with zero invariant violations" is a substantially stronger claim than "we have 30 integration tests that pass" — relevant for NH4 military-grade certification and Theme 8 / Theme 9 regulated-deployment positioning.
- **Cross-implementation compatibility.** Once Determ has a C99 rewrite (NH1 Stage 2, future), DSF scenarios run against both implementations and verify byte-identical behavior. Rewrite-portable testing — the original A10 goal — achieved more rigorously than A10 streams 1+2 would have delivered.

---

*End of specification.*
