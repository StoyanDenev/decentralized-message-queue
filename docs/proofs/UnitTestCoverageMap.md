> **TIER: PROCESS / ARCHIVE.** Deliberation/meta; retained for rationale but NOT coherence-maintained as part of the 1.0 set. Roadmap index: docs/ROADMAP.md

# UnitTestCoverageMap — Meta-proof: in-process unit tests ↔ FA / S closures

**Scope.** This is the meta-proof for S-035 Option 1: it formalizes the
coverage map between the 152 in-process `determ test-*` subcommands and the
FA-track safety theorems + S-* security findings + crypto / wire-format
primitives they pin.

**Sibling documents (do not duplicate; cross-link).**

- `docs/proofs/README.md` — full FA / FB / S list (theorems-as-claims)
- `docs/UNIT-TESTS.md` — per-test description (assertions + surface motivation)
- `docs/SECURITY.md` §S-035 — finding registration + Option 1 / 2 / 3 status
- `docs/CLI-REFERENCE.md` §"S-035 Option 1 seed" — per-subcommand surface
- `tools/test_*.sh` — wrappers (200 total; the 152 in-process subset wraps
  the `determ test-*` surface; the remaining wrappers are network-level
  integration tests outside the in-process scope of this proof)
- `tools/run_all.sh` — canonical self-counting source of truth for the
  in-process `determ test-*` subcommand total

---

## 1. Introduction — S-035 Option 1 closure goal

`docs/SECURITY.md` §S-035 registers the operational finding **"No unit
tests, no CI, no deterministic-simulation framework"** with three resolution
paths:

| # | Option | Status (in-session) |
|---|---|---|
| 1 | Per-feature unit tests (gtest/Catch2-shape) | 🟡 seeded with 152 in-process `determ test-*` subcommands; continues incrementally |
| 2 | Deterministic Simulation Framework (DSF) | 🔥 spec resolved (`docs/proofs/DSF-SPEC.md`) + **increments 1-6 shipped** (self-contained `sim/` core + `determ-dsf` + 34 baked scenarios incl. the §Q5 generator's TWO templates (broadcast + agreement) + the inc-5 §Q5/§Q6 `--generate N --seed S [--template broadcast\|agree]` CLI for reproducible `gen_run_NN` variants, `tools/test_dsf_{core,inc2,inc3,inc4,inc5,inc6}.sh`); §Q1/§Q2 consensus-injection + FA4 wiring pending |
| 3 | Path portability (`tools/common.sh`) | ✅ shipped |

**Closure goal for Option 1.** Every FA-track theorem AND every S-* closure
SHOULD be exercised by at least one in-process unit test that locks the
load-bearing surface against silent regression. The 136-subcommand seed is
the seed; the remaining gaps are the "extension targets" enumerated in
§3 below.

**Why a meta-proof.** §S-035's resolution table claims the 152 in-process
tests "cover the cryptographic foundations under every FA-track safety
proof." That claim has not been individually audited per-test against
per-FA / per-S item — it has only been asserted in aggregate. This proof
formalizes the asserted coverage map test-by-test, surfaces any gaps, and
records findings for the Option 1 seed's remaining work.

**Methodology summary.** §5 gives the construction; the key invariant is
that every test in `tools/test_*.sh` corresponding to an in-process
`determ test-*` subcommand maps to **at least one** target FA proof, S
finding, or named primitive ("crypto primitive — Ed25519 / SHA-256 /
Merkle"). Reverse-map (§4) reports test-count-per-target so coverage
imbalance is visible.

**Scope clarification — in-process vs network-level tests.** This proof
covers the 152 in-process subcommands wrapped by 136 of the 200
`tools/test_*.sh` scripts (specifically those whose body invokes
`$DETERM test-<name>`). The remaining shell scripts are network-level
integration tests (multi-node gossip, RPC round-trips, snapshot bootstrap
across peers) outside the FAST=1 in-process subset; they remain covered
by Option 1 / Option 2 in the form of end-to-end regression detection but
are NOT individually mapped in §2 because they don't correspond to a single
isolatable function under test.

---

## 2. Coverage map table

The table below maps each of the 152 in-process `determ test-*` subcommands
to its target FA / FB / S item or named primitive. Per-test descriptions
(assertion counts, surface motivation) live in `docs/UNIT-TESTS.md` §2 and
are NOT duplicated here.

**Reading the table.** Column 3 ("What it pins") names the single most
load-bearing safety / liveness / wire / economic invariant the test
defends; the FA-track column may include multiple comma-separated entries
when a single test pins a primitive (e.g., Ed25519) that cascades into
multiple FA theorems.

### 2.1 Cryptographic primitives (10 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-sha256` | crypto primitive — SHA-256 (under FA1 / FA2 / FA3 / FA6 / FA7 / FA8 / FA10) | FIPS 180-4 conformance + Preliminaries §1.3 BE encoding under every signing-bytes path |
| `test-ed25519` | FA1 / FA2 / FA5 / FA6 / FA7 / FA10 (every signature claim) | EUF-CMA primitive: RFC-8032 determinism, cross-key rejection, tampered-message rejection |
| `test-merkle` | FA1 (S-033 state commitment) | balanced + unbalanced + edge-case leaf sets; domain separation leaf vs inner |
| `test-merkle-proof-tampering` | FA1 / S-040 (CLOSED — leaf_count bound into root) | per-tamper rejection (value_hash / sibling / target_index / cross-proof-swap / forged leaf_count) |
| `test-committee-selection` | FA1 / FA2 / FA5 / FA8 (S-020 hybrid) | both rejection-sampling and partial-Fisher-Yates branches; seed-sensitivity |
| `test-shard-routing` | FA7 (cross-shard destination routing) | salted SHA-256 determinism + uniformity + salt-sensitivity |
| `test-shard-routing-determinism` | FA7 (cross-shard destination routing) | deterministic replay invariant on `shard_id_for_address` across (addr,count,salt) probes |
| `test-anon-address` | S-028 (case normalization) | wallet helpers — `is_anon_address` / `normalize_anon_address` / `parse_anon_pubkey` |
| `test-frost-types` | FB23 (FrostVerify TLA+) / v2.10 DKG | Point / FrostSig 32 / 64-byte type contract for FROST-Ed25519 |
| `test-encoding` | wire format foundation | `to_hex` / `from_hex` / `from_hex_arr<N>` round-trip + `to_string` enums + `now_unix` |

### 2.2 Chain commitment + identity (15 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-genesis-message` | chain identity | hash-mixing contract; backward-compat default-skips-mix; 256B size cap |
| `test-genesis-determinism` | chain identity / FA1 | `compute_genesis_hash` byte-identical across calls on same `GenesisConfig` |
| `test-genesis-sharded` | chain identity + S-039 lock-in | chain_role / shard_id distinct hashes; `initial_shard_count` NOT bound (S-039 gap pinned) |
| `test-genesis-with-region` | rev.9 R1 regional | region propagation Genesis→registry; `committee_region` binds into hash |
| `test-genesis` | chain identity + S-039 + S-018 | `compute_genesis_hash` + `make_genesis_block` + S-018 collection-type rejection |
| `test-make-genesis-block` | chain bootstrap / FA1 | sorted-creators determinism; `initial_balances` merge semantics |
| `test-state-root` | FA1 (state commitment) / S-033 / S-037 / S-038 | per-namespace sensitivity; order independence; invertibility |
| `test-state-root-determinism` | FA1 / S-033 | `compute_state_root` byte-identical across replays on equivalent mutation sequence |
| `test-state-root-namespaces` | S-033 / state_root | exhaustive 10-namespace mutation coverage (a/s/r/d/i/b/m/p/k/k:c) |
| `test-block-digest` | FA1 / S-030 D2 / v2.7 F2 | INCLUSION + EXCLUSION contract fencing FA1 Phase-2 signature target |
| `test-block-hash` | FA1 (chain identity) | full field coverage including Phase-2-reveal + zero-skip backward-compat |
| `test-domain-separation` | FA1 / domain separation | pairwise non-collision across 9 commitment hashes |
| `test-block-roundtrip` | wire format | full JSON round-trip + CRITICAL `compute_hash` invariance through round-trip |
| `test-block-accessors` | wire format / state | Block defaults + assignment preservation + compute_hash sensitivity |
| `test-chain-helpers` | FA1 / state view | read-side API surface + safety defaults (`balance(unknown)==0`) |

### 2.3 Block + chain integrity (10 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-chain-append` | FA1 / chain integrity | prev_hash continuity + transitivity (chain-anchor invariant) |
| `test-chain-prev-hash-link` | FA1 / chain integrity / FB30 | `prev_hash` rejection on mismatch + cascade-detection via reload (FB30 companion) |
| `test-chain-apply-block` | FA-Apply central path | genesis bootstrap + TRANSFER / STAKE / REGISTER apply branches |
| `test-chain-ctor-bootstrap` | Chain ctor / bootstrap | Chain() default empty + Chain(genesis) bootstrap; head() on empty throws |
| `test-chain-save-load` | Chain persistence / restart path / FA1 | save→load preserves every field byte-for-byte; idempotency |
| `test-block-validator-basic` | FA1 / safety+liveness | `validate()` entry — genesis short-circuit + 13 sub-check dispatch |
| `test-block-validator-extensive` | FA1 / FA2 / FA3 / FA6 / safety+liveness | extended sub-check coverage (tx commitments / equivocation / cumulative_rand) |
| `test-validator-config` | FA1 / operator config | `BlockValidator` public setters + validate() genesis short-circuit |
| `test-multi-block-chain` | chain continuity / snapshot foundation | N=10 prev_hash linkage + height monotonicity + A1 every block |
| `test-time-monotonicity` | FB29 BlockTimestampMonotonic | timestamp monotonicity + digest-exclusion contract |

### 2.4 Randomness + consensus arithmetic (7 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-block-rand` | FA1 / FA5 / FA8 (V8 randomness) | `compute_delay_seed` / `compute_block_rand` / `proposer_idx` / `required_block_sigs` / `count_round1_aborts` |
| `test-block-rand-distribution` | FA1 / V8 randomness | statistical uniformity sanity over `compute_block_rand` output distribution |
| `test-random-state` | V8 / S5 anti-cartel | `compute_dh_output[_m]` / `compute_abort_hash` / `chain_abort_hash` |
| `test-required-block-sigs` | FA1 / FA5 BFT quorum | MD(k) == k; BFT(k) == ceil(2k/3); BFT(k) ≤ MD(k) invariant for k ∈ [1,16] |
| `test-tx-root` | FA2 (censorship) | union semantics — defeats accidental intersection (note S-025 deletion) |
| `test-randomized-delay` | derive_delay / randomized activation | REGISTER active_from ∈ [h+1, h+10]; distribution coverage |
| `test-make-contrib-commitment-distinct` | FB24 / v2.7 F2 / MakeContribCommitmentBackwardCompat | v1-byte-identity (T-1) + DTM-F2-v1 replay-defense (T-2) |

### 2.5 Consensus messages (4 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-consensus-msgs` | FA1 (consensus messages) | ContribMsg + BlockSigMsg + AbortClaimMsg JSON round-trip + commitment hashes |
| `test-make-block-sig` | FA1 / Phase-2 sig | `make_block_sig` sign/verify + tampered-digest rejection + cross-signer distinctness |
| `test-view-root` | v2.7 F2 / FB22 view reconciliation | `compute_view_root` order independence + union monotonicity |
| `test-merge-event-codec` | R4 / FA8 / FA9 | BEGIN+END round-trip; rejection paths (too-short / invalid event_type / region_len > 32) |

### 2.6 Wire format (10 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-binary-codec` | A3 / S8 / S-022 | JSON + binary envelope round-trip; per-MsgType cap table golden vectors |
| `test-binary-codec-roundtrip-exhaustive` | A3 / S8 / wire format | exhaustive serialize→deserialize for every MsgType + edge-case body sizes |
| `test-tx-binary-codec` | S-002 / wire format | amount/fee/nonce preserved through binary path (pre-S-002 dropped these) |
| `test-tx-signing-bytes` | wire format / FA1 | byte-layout invariant — type at offset 0; amount/fee/nonce BE at [3..26] |
| `test-merge-event-bytes` | R4 / FA8 / FA9 | byte-layout — event_type at offset 0; shard_id LE at [1..4]; LE-vs-BE contrast lock |
| `test-merge-event-determinism` | R4 / FA8 / FA9 | encode replays produce byte-identical output for same input |
| `test-wire-types` | FA7 / V12 / FA3 / FA6 / S-018 | CrossShardReceipt / AbortEvent / EquivocationEvent / GenesisAlloc + S-018 strict-rejection |
| `test-enum-values` | wire format | every TxType / MsgType / ConsensusMode / ChainRole / ShardingMode / InclusionModel slot |
| `test-protocol-version-pinning` | wire format / migration gate | PROTOCOL_VERSION constant pinned; mismatch detection |
| `test-hello-handshake-determinism` | wire format / FA1 | HELLO envelope deterministic on same Config across replays |

### 2.7 Apply-path / state-machine tests (28 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-state-types` | FA3 / state semantics | UINT64_MAX sentinel consistency across AccountState / StakeEntry / RegistryEntry / DAppEntry |
| `test-atomic-scope` | A9 / FA-Apply | `Chain::apply_with_scope` nested-scope rollback primitive |
| `test-composable-batch` | A9 / atomic-batch | COMPOSABLE_BATCH all-or-nothing apply via `apply_with_scope` |
| `test-abort-event-apply` | FA-Apply-11 / FA6 / SUSPENSION_SLASH / S-032 | Phase-1 slash + Phase-2 no-slash + S-032 abort_records cache |
| `test-equivocation-apply` | FA-Apply-10 / FA6 | full stake forfeiture + registry deactivation + ghost-equivocator robustness |
| `test-equivocation-multi` | FA-Apply-16 / FA6 / dual mechanism | two equivocators same block; pre-deactivated re-equivocate edge |
| `test-unstake-deregister-apply` | FA-Apply-4 / stake lifecycle | UNSTAKE too-early refund; DEREGISTER → unlock_height; post-unlock UNSTAKE |
| `test-stake-accounting` | FA-Apply-4 / stake lifecycle | full state-machine invariants across STAKE → slash → DEREGISTER → UNSTAKE |
| `test-cross-shard-receipt-apply` | FA-Apply-9 / FA7 / rev.9 B3.4 | inbound credit + dedup contract under chain replay |
| `test-cross-shard-outbound-apply` | FA-Apply-13 / FA7 / rev.9 B3 | source-side debit; `accumulated_outbound` += amount; single-shard fallback |
| `test-cross-shard-atomicity` | FA7 (cross-shard atomicity) | dual-chain composition — src.outbound == dst.inbound conservation |
| `test-cross-shard-multi-receipt` | FA-Apply-9 / FA7 / rev.9 B3.4 mixed-direction | inbound + outbound + multi-receipt + cross-block dedup |
| `test-applied-receipt-restore` | FA-Apply-12 / rev.9 B3.4 / S-033 / S-037 | dedup-set survives snapshot serialize/restore |
| `test-param-change-apply` | FA-Apply-8 / A5 / FA10 | staging contract + activation at effective_height + hook-fire on unknown name |
| `test-subsidy-distribution` | FA-Apply-7 / E1/E3/E4 economics | FLAT / LOTTERY / E4 finite pool / dust-to-creator[0] |
| `test-merge-event-apply` | FA9 / R7 / EXTENDED-mode | BEGIN inserts; END removes on partner match; partner-ring constraint |
| `test-merge-event-apply-edge` | FA9 / R7 / lost-gossip + cycle | END-without-BEGIN; double-BEGIN idempotent; self-merge rejected |
| `test-supply-lifecycle` | FA11 / A1 / cross-cutting | end-to-end A1 invariant across mixed-tx lifecycle |
| `test-supply-invariant` | FA11 / A1 unitary supply | `live_total_supply == expected_total` formula on default Chain |
| `test-dapp-register` | v2.18 DApp substrate / FA-Apply-5 | domain creation + owner binding + topic registration + fee charging |
| `test-dapp-call` | v2.19 DApp substrate | payload-cap check; inactive-DApp rejection; cross-shard rejection |
| `test-dapp-state-transition` | FA-Apply-5 / DAppRegistryLifecycle / v2.18 | full create / update / deactivate lifecycle; replayed lifecycle → same state_root |
| `test-overflow-paths` | S-007 / overflow protection | TRANSFER receiver overflow + inbound receipt overflow + Phase-1 rollback |
| `test-multi-tx-block` | apply ordering / multi-tx | same-sender ascending nonces; wrong-nonce skip; insufficient-balance mid-block |
| `test-tx-edge-cases` | FA-Apply / TRANSFER corner cases | self-transfer; missing-sender forged-tx defense; balance == amount+fee boundary |
| `test-tx-payload-bounds` | FA-Apply per-tx payload bounds | REGISTER / STAKE / UNSTAKE payload-size apply gates |
| `test-empty-block-apply` | FA-Apply-7 / E3/E4 subsidy gate | empty creators[] subsidy gate; A1-safe degenerate path |
| `test-account-create-on-credit` | FA-Apply / state-map safety | `operator[]` auto-creation paths defended |

### 2.8 Replay / snapshot equivalence (5 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-snapshot-roundtrip` | snapshot / S-033 / S-037 / S-038 / FA-Apply-2 | serialize_state + restore_from_snapshot round-trip; state_root preserved |
| `test-snapshot-then-apply` | S-033 / S-038 / snapshot equivalence / FA-Apply-2 | restored chain operational — apply post-restore matches full-replay |
| `test-snapshot-defense` | S-018 / snapshot wire format | wrong-type collection rejection across every optional snapshot field |
| `test-snapshot-version-rejection` | snapshot / migration gate | version=1 required; missing/0/999/-1 rejected |
| `test-tx-replay-protection` | FA-Apply-3 / NonceMonotonicity / replay defense | strict-equality nonce gate; replay + future skipped without nonce bump |

### 2.9 Light-client + state-proof (2 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-state-proof` | v2.2 light-client / S-033 | inclusion + verify + non-membership; malicious-server defense |
| `test-state-proof-namespaces` | v2.2 light-client / S-033 namespaces | per-namespace proof generation across a/s/r/b/d; cross-namespace proof-swap rejection |

### 2.10 Governance + economics (3 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-pending-param-changes` | A5 governance / FA10 | `stage_param_change` + `pending_param_changes()` staging primitive |
| `test-fee-distribution-edge` | FA-Apply-6 / E1/E3/E4 / dust | 3-creator split; dust-to-creator[0]; zero-fee + zero-subsidy no-op |
| `test-nef-pool-drain` | FA-Apply-14 / E1 NEF | first-time REGISTER halves pool; re-REGISTER unchanged; geometric exhaustion |

### 2.11 Network / rate-limit (2 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-rate-limiter` | S-014 (RateLimiterSoundness) | shared `net::RateLimiter` token-bucket — disabled-mode + first-touch FULL + burst exhaustion + per-key independence |
| `test-rate-limiter-bucket` | S-014 / FB25 idle-bucket eviction | low-level bucket lifecycle + time-decay eviction + resurrection-safety |

### 2.12 Wallet / key (3 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-envelope` | FA12 / A2 / S-004 | AES-256-GCM + PBKDF2 AEAD wrapping; tamper rejection; fresh salt+nonce per encryption |
| `test-shamir` | FA12 / A2 Phase 1 | T-of-N reconstruction; T-1 below-threshold safety; degenerate thresholds |
| `test-anon-routing` | S-028 / anon-address integration | parse+normalize+route layers compose; case-variant routes to same shard |

### 2.13 Operator config + JSON validation (10 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-json-validate` | S-018 / JsonValidationSoundness / FB27 | foundation helpers `json_require<T>` / `_hex` / `_array` — error-message contract |
| `test-s018-json-validation` | S-018 wire-format foundation / FB27 | three-helper direct test; field-name diagnostics on missing / wrong-type / wrong-hex / non-array |
| `test-config-defaults` | S-001 / S-014 / operator defaults | `rpc_localhost_only=true` default (S-001 critical); 21 default-value assertions |
| `test-config-roundtrip` | operator UX | 32-field round-trip; permissive empty-JSON → defaults |
| `test-config-load-save` | operator config IO / persistence | file IO round-trip; mkdirp on save; malformed-JSON clean throw |
| `test-config-permissive` | operator config UX / forward-compat | unknown / future / typo'd fields silently accepted (dual of S-018) |
| `test-config-determinism` | operator config / determinism | Config save/load idempotency across cycles; field bind stability |
| `test-block-from-json-minimal` | S-018 / Block wire-format gate | 7 required Block fields pinned; field-name diagnostics on missing |
| `test-timing-profiles` | operator config | 5 production + 6 test profiles; round-timer values; test/prod separation invariant |
| `test-params-constants` | operator economy | MIN_STAKE=1000, UNSTAKE_DELAY=1000, SUSPENSION_SLASH=10; arithmetic invariant SUSPENSION_SLASH×100==MIN_STAKE |

### 2.14 Composition / interaction (4 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-resolve-fork` | S-029 / FA1 | BFT-mode fork-choice rule — heaviest sigs → fewer aborts → smallest hash |
| `test-block-event-composition` | FA-Apply-15 / Multi-event / FA6 stacking | TRANSFER + AbortEvent + EquivocationEvent + subsidy + inbound receipt one block |
| `test-node-registry` | FA8 R2 region committee / registry foundation | `NodeRegistry::build_from_chain` + `eligible_in_region` strict-equality |
| `test-merge-state` | FA9 / R7 / governance | merge_state read API + 3 R4 threshold setters round-trip |

### 2.15 Cross-cutting determinism (2 tests)

| Test name | FA proof / S finding | What it pins |
|---|---|---|
| `test-tx-signing-determinism` | wire format / FA1 / determinism | `Transaction::signing_bytes` byte-identical across replays for same Transaction |
| `test-transaction` | tx-level FA1 + S-018 | `Transaction::signing_bytes` + `compute_hash` + Ed25519 sign/verify + 10 TxType JSON round-trips |

**Total: 152 in-process tests across 15 categories.** (`tools/run_all.sh`
is the canonical self-counting source for the `determ test-*` subcommand
total; the per-category breakdown above enumerates an earlier 117-test seed
and is not re-enumerated here.)

---

## 3. Coverage gaps — extension targets

The following FA / FB / S items have **no paired in-process unit test** in
the current 136-test seed. Each is a candidate for the next round of
Option 1 seeding.

### 3.1 FA-track high-level proofs without in-process tests

| Item | Why no in-process test | Mitigation |
|---|---|---|
| FA4 Liveness | Liveness is a multi-block trace property, not a per-call assertion. Per-block liveness slices (e.g., `test-required-block-sigs` for the BFT-mode finalize-condition formula; `test-block-validator-basic` for the validator-rejection paths) cover the input invariants. | Liveness is the canonical Option 2 (DSF) target — multi-block randomized-Byzantine traces. The Option 1 seed cannot reach the full liveness statement at unit-test granularity by design. |
| FA10 Governance | `test-pending-param-changes` (staging primitive) + `test-param-change-apply` (apply-path activation) together pin the FA-Apply-8 mechanics conditional on the N-of-N threshold being met. The keyholder-threshold N-of-N signature path itself is exercised only by network-level `tools/test_governance_param_change.sh`. | Adding `test-governance-param-change` (in-process keyholder-sig threshold gate) is a ~½d extension. |
| FA11 EconomicSoundness — full theorem | `test-supply-invariant` + `test-supply-lifecycle` cover A1 conservation; `test-nef-pool-drain` covers E1 NEF; `test-subsidy-distribution` covers E3/E4. The full E1+E3+E4+A1 composition theorem (any tx sequence, any block sequence, any keyholder set) is not testable at unit-test granularity — would require multi-block trace coverage. | Composition coverage is on the DSF path (Option 2); per-component coverage is shipped. |

### 3.2 S-* findings without in-process tests

| Finding | Why no in-process test | Mitigation |
|---|---|---|
| S-001 RPC authentication HMAC | Auth path requires a live RPC server fixture (TCP socket bind, HTTP request handling); exercised by `tools/test_rpc_hmac_auth.sh`. `test-config-defaults` pins the `rpc_localhost_only=true` default, which is the load-bearing operator-facing default. | The HMAC handshake protocol itself is reducible to Ed25519 EUF-CMA (`test-ed25519`), so the cryptographic foundation IS covered; only the wire-level orchestration is network-only. |
| S-002 Mempool sig verify | Mempool admission requires a partial Node fixture (state mutex + admission queue); exercised by network-level `tools/test_mempool_bounds.sh`. The fixed-slot codec path that S-002 originally broke IS covered by `test-tx-binary-codec`. | The producer-side admission path is fixture-heavy (`~1d` effort per UNIT-TESTS.md §3.1). |
| S-003 Block timestamp window | Window is enforced by validator's `check_timestamp`; exercised by network-level integration tests. `test-time-monotonicity` covers the in-process companion — monotonicity contract + digest exclusion. | `test-block-validator-extensive` is the natural home for ±30s window assertions; ~½d extension. |
| S-006 ContribMsg equivocation | `on_contrib` detection path requires partial Node fixture; covered by `tools/test_equivocation_slashing.sh`. `test-equivocation-apply` covers the apply-side closure. | `test-equivocation-apply` + FB28 TLA+ companion together close the loop; in-process producer-side detection test would require Node fixture (~1d effort). |
| S-008 Bounded mempool | Mempool admission/eviction requires partial Node fixture; UNIT-TESTS.md §3.1 estimates ~1d. FB33 TLA+ companion ships the state-machine model. | Future Option 1 extension. |
| S-012 Snapshot bootstrap | `test-snapshot-roundtrip` + `test-snapshot-then-apply` + `test-snapshot-defense` together cover the in-process closure surfaces (state_root gate, S-018 wrong-type rejection). The "trust the source" attack vector specifically is closed by S-033/S-038 state_root binding — covered by `test-state-root` + `test-applied-receipt-restore`. | Effectively covered; no gap. |
| S-013 BlockSigMsg per-signer cap | Cap is enforced in `on_block_sig`; requires partial Node fixture. Documented as `tools/test_node_buffered_sigs.sh` network-level. | Future Option 1 extension. |
| S-014 RateLimiter | ✅ Covered — `test-rate-limiter` + `test-rate-limiter-bucket` together cover the shared helper + low-level bucket lifecycle including F-1 eviction (FB25 companion). |
| S-015 Async save | Async-save worker exception handling was removed by M-F closure (S-009/S-015/S-034); finding closed. | No coverage gap (finding closed). |
| S-016 Inbound-receipts non-determinism | Option 2 partial closure (CROSS_SHARD_RECEIPT_LATENCY time-ordered admission) is covered by integration tests; Option 1 (intersection variant) is the v2.7 F2 territory. | v2.7 F2 closes fully; no in-process test needed for Option 2 because the time-ordering is multi-block. |
| S-017 UNSTAKE divergence | Closed via Option 2 (producer + validator both gained unlock_height check). `test-unstake-deregister-apply` covers the apply-side; producer-side check is reducible to the same logic. | No coverage gap (finding closed; both layers tested via apply path). |
| S-019 Phase-2 timer R-arrival spoofing | Requires multi-node timing fixture; outside in-process scope. | Option 2 (DSF) target. |
| S-023 RPC send/stake balance check | Pre-check at RPC layer; exercised by network-level `tools/test_status_protections.sh`. | Future Option 1 extension when an RPC-layer test fixture is added. |
| S-024 DEREGISTER predictability | Accepted per auditor reclassification; no closure to test. | N/A. |
| S-025 dead-code intersection | Code is deleted; no surface to test. | N/A. |
| S-026 TCP keepalive | OS-level config; not testable in-process. | N/A. |
| S-027 Info leakage | Audit-pass closure + `log_quiet` flag; covered by code review, not unit test. | N/A. |
| S-030 D1/D2 | D1 closed via S-033 + S-038 (covered by `test-state-root` + `test-snapshot-then-apply`); D2 v2.7 F2 territory (covered by `test-view-root` + `test-make-contrib-commitment-distinct`). | Effectively covered. |
| S-031 Single global mutex | Concurrency / serialization is a runtime-performance characteristic; outside per-call unit-test scope. | N/A. |
| S-034 VDF cleanup | VDF removed entirely (S-009 closure); no surface. | N/A. |
| S-036 Under-quorum merge edges | EXTENDED-mode-only; covered by `test-merge-event-apply` + `test-merge-event-apply-edge`. v2.11 closes fully. | Effectively covered. |
| S-039 Genesis-hash gap | ✅ Covered — `test-genesis` + `test-genesis-sharded` lock in the CURRENT no-effect behavior with explicit `expect == base_hash` assertions for each unbound field. |
| S-040 Merkle leaf_count | ✅ Covered (S-040 CLOSED) — `leaf_count` is bound into the committed root via the root-wrapper hash `SHA256(0x02 ‖ be_u32(leaf_count) ‖ inner_root)`, so a forged count is rejected by `merkle_verify`. `test-merkle-proof-tampering` exercises every tampering path (sibling-hash / target_index / cross-proof-swap / forged leaf_count → all rejected). |

**Summary.** Out of 40 FA/S items, **3 in-process Option-1 extensions remain
worth pursuing** without architectural change: (a) RPC HMAC auth handshake
(S-001 wire-level), (b) Mempool admission/eviction (S-008), (c)
Governance keyholder-threshold gate (FA10 sig path). Everything else is
either: (i) ✅ already covered by an in-process test, (ii) covered by
network-level integration tests AND a reducible cryptographic primitive
(`test-ed25519` etc.), (iii) is an Option 2 (DSF) target by nature
(liveness, multi-node timing, partition injection), or (iv) is closed in
a way that has no testable surface (deleted code, accepted-as-posture,
OS-level config).

---

## 4. Reverse map — items by test count

For each major FA / FB / S item, the list of in-process tests that
exercise it. Items with high coverage (5+ tests) indicate well-defended
load-bearing surfaces; items with 0 tests indicate the gaps enumerated
in §3.

### 4.1 High coverage (5+ tests)

**FA1 (K-of-K mutual-distrust safety)** — 18 tests:
`test-sha256`, `test-ed25519`, `test-merkle`, `test-merkle-proof-tampering`,
`test-committee-selection`, `test-block-digest`, `test-block-hash`,
`test-block-rand`, `test-block-rand-distribution`, `test-required-block-sigs`,
`test-make-block-sig`, `test-consensus-msgs`, `test-tx-signing-bytes`,
`test-tx-signing-determinism`, `test-domain-separation`, `test-chain-append`,
`test-chain-prev-hash-link`, `test-block-validator-basic`,
`test-block-validator-extensive`, `test-validator-config`,
`test-multi-block-chain`, `test-time-monotonicity`. (The strongest
load-bearing theorem, deeply exercised because every signature, every
chain link, every block-digest field, every consensus message touches it.)

**S-018 (JSON schema validation)** — 8 tests:
`test-json-validate`, `test-s018-json-validation`, `test-snapshot-defense`,
`test-wire-types`, `test-block-from-json-minimal`, `test-genesis`,
`test-transaction`, `test-block-roundtrip`. (Every from_json path
transit through these helpers; 8 tests reflects the fan-out of S-018's
defense surface.)

**S-033 (state_root commitment)** — 6 tests:
`test-state-root`, `test-state-root-determinism`,
`test-state-root-namespaces`, `test-snapshot-roundtrip`,
`test-snapshot-then-apply`, `test-applied-receipt-restore`,
`test-state-proof`, `test-state-proof-namespaces`. (10-namespace state
commitment is the foundation under snapshot equivalence + light-client
proofs.)

**FA-Apply central path** — 7 tests:
`test-chain-apply-block`, `test-multi-tx-block`, `test-tx-edge-cases`,
`test-tx-payload-bounds`, `test-empty-block-apply`,
`test-account-create-on-credit`, `test-overflow-paths`. (Direct apply-loop
coverage; companion to each FA-Apply-N analytic.)

**FA7 (cross-shard atomicity)** — 5 tests:
`test-shard-routing`, `test-shard-routing-determinism`,
`test-cross-shard-receipt-apply`, `test-cross-shard-outbound-apply`,
`test-cross-shard-atomicity`, `test-cross-shard-multi-receipt`,
`test-anon-routing`. (Source + destination + composition + integration.)

### 4.2 Medium coverage (2-4 tests)

- **FA2 (censorship)** — `test-tx-root`, `test-committee-selection`, `test-view-root`, `test-make-contrib-commitment-distinct`.
- **FA3 (selective abort)** — `test-wire-types` (AbortEvent struct), `test-abort-event-apply`.
- **FA5 (BFT safety)** — `test-required-block-sigs`, `test-block-rand` (BFT proposer_idx), `test-resolve-fork`.
- **FA6 (equivocation slashing)** — `test-equivocation-apply`, `test-equivocation-multi`, `test-wire-types` (EquivocationEvent), `test-block-event-composition`.
- **FA8 (regional sharding)** — `test-committee-selection`, `test-genesis-with-region`, `test-node-registry`.
- **FA9 (under-quorum merge)** — `test-merge-event-codec`, `test-merge-event-bytes`, `test-merge-event-apply`, `test-merge-event-apply-edge`, `test-merge-event-determinism`, `test-merge-state`.
- **FA11 (economic soundness — A1)** — `test-supply-invariant`, `test-supply-lifecycle`, `test-subsidy-distribution`, `test-nef-pool-drain`, `test-fee-distribution-edge`.
- **FA12 (wallet recovery)** — `test-envelope`, `test-shamir`.
- **S-007 (overflow)** — `test-overflow-paths`.
- **S-014 (rate limiter)** — `test-rate-limiter`, `test-rate-limiter-bucket`.
- **S-020 (committee selection)** — `test-committee-selection`.
- **S-022 (wire-format caps)** — `test-binary-codec` (per-MsgType cap table), `test-binary-codec-roundtrip-exhaustive`.
- **S-028 (anon-address case)** — `test-anon-address`, `test-anon-routing`.
- **S-029 (fork choice)** — `test-resolve-fork`.
- **S-037 (DApp snapshot)** — `test-snapshot-roundtrip`, `test-snapshot-then-apply`, `test-dapp-state-transition`.
- **S-038 (state_root population)** — `test-state-root`, `test-state-root-determinism`, `test-snapshot-then-apply`.
- **S-039 (genesis-hash gap)** — `test-genesis`, `test-genesis-sharded`.
- **S-040 (Merkle leaf_count)** — `test-merkle-proof-tampering`.
- **FA-Apply-9 (CrossShardReceiptDedup)** — `test-cross-shard-receipt-apply`, `test-cross-shard-multi-receipt`.
- **A5 governance** — `test-pending-param-changes`, `test-param-change-apply`.
- **A2 wallet primitives** — `test-envelope`, `test-shamir`.
- **A9 atomic scope** — `test-atomic-scope`, `test-composable-batch`.
- **v2.18 DApp substrate** — `test-dapp-register`, `test-dapp-call`, `test-dapp-state-transition`.

### 4.3 Single-test coverage

- **FB22 (F2 view reconciliation)** — `test-view-root`.
- **FB23 (FrostVerify)** — `test-frost-types`.
- **FB24 (MakeContribCommitment)** — `test-make-contrib-commitment-distinct`.
- **FB25 (RateLimiter eviction)** — `test-rate-limiter-bucket`.
- **FB29 (BlockTimestampMonotonic)** — `test-time-monotonicity`.
- **FB30 (ChainPrevHashLink)** — `test-chain-prev-hash-link`.
- **S-002 (mempool sig verify)** — `test-tx-binary-codec` (the path S-002 originally broke).
- **S-004 (keyfile at-rest)** — `test-envelope`.
- **S-018 wire-format foundation** — `test-s018-json-validation` (direct), plus the 7 derivative tests in 4.1.
- **S-032 (registry rebuild cache)** — `test-abort-event-apply` (S-032 abort_records cache assertion).
- **v2.10 DKG / FrostVerify** — `test-frost-types`.
- **v2.2 light-client** — `test-state-proof`, `test-state-proof-namespaces`.

### 4.4 Zero coverage in 136-seed (per §3)

| Item | Status | Action |
|---|---|---|
| FA4 Liveness | Multi-block property — by-nature DSF target | Option 2 |
| S-001 RPC HMAC handshake (wire path) | Reducible to FA primitives | Future ext |
| S-008 Bounded mempool | Node fixture needed | Future ext |
| S-013 BlockSigMsg cap | Node fixture needed | Future ext |
| S-019 Phase-2 timer | Multi-node timing | Option 2 |
| S-023 RPC send balance check | RPC fixture needed | Future ext |
| FA10 N-of-N keyholder sig | Composes with `test-param-change-apply` | Future ext |

---

## 5. Methodology

The coverage map was constructed via the following procedure:

### 5.1 Test enumeration

```
grep -oE 'cmd == "test-[a-z0-9_-]+"' src/main.cpp | sort -u
```

Yields exactly **136 distinct in-process test names**. Each corresponds
to a paired wrapper at `tools/test_<feature>.sh` (with hyphens converted
to underscores; e.g., `test-block-rand` ↔ `tools/test_block_rand.sh`).

### 5.2 FA / FB / S enumeration

- **FA-track**: `docs/proofs/README.md` lines 21..47 (FA1..FA12 + FA-Apply-1..16).
- **FB-track**: `docs/proofs/README.md` lines 54..91 (FB1..FB33).
- **S-track**: `docs/SECURITY.md` `^### S-\d+` headings (S-001..S-040).
- **Primitives**: enumerated by examining test descriptions in
  `docs/UNIT-TESTS.md` §2 and SECURITY.md §S-035 resolution table.

### 5.3 Mapping construction

For each of the 136 tests:

1. Read the per-test description in `docs/UNIT-TESTS.md` §2 (canonical
   one-paragraph statement of what the test pins).
2. Cross-check with the `tools/test_<feature>.sh` wrapper's header
   comment (which cites FA / S references per UNIT-TESTS.md §5.6
   discipline rule).
3. Identify the most load-bearing FA / FB / S target (column 2 of §2
   tables); add comma-separated secondary targets when the test is a
   primitive used across multiple FA theorems (e.g., Ed25519 → FA1 +
   FA2 + FA5 + FA6 + FA7 + FA10).
4. Confirm the surface is named in either:
   - `docs/SECURITY.md` §S-035 resolution table (the canonical per-test
     FA-track column for the 100-seed milestone), or
   - `docs/UNIT-TESTS.md` §2's per-category tables (the canonical
     per-test surface tags for the 117-seed milestone), or
   - The per-test source-comment header in `src/main.cpp` (the
     ground-truth surface tag).

### 5.4 Reverse-map construction

For each FA / FB / S item enumerated in 5.2, scan §2's "FA proof / S
finding" column and collect every test naming it (primary or secondary).
The §4 reverse map presents the result grouped by count tier (5+, 2-4,
1, 0).

### 5.5 Gap identification

For each FA / FB / S item, query the reverse map:

- **Count == 0**: The item is in §3.1 / §3.2 with an explanation of why
  (multi-block property → DSF; Node fixture needed → future ext; deleted
  code → no surface; etc.).
- **Count == 1 with a fixture-heavy companion**: Considered "single-test
  coverage" in §4.3 — adequate for cryptographic primitives, marginal
  for state-machine properties (e.g., FB30 has only `test-chain-prev-hash-link`
  but the TLA+ model FB30 itself is the redundant check).
- **Count ≥ 2**: Considered adequately covered (multiple test angles
  defend the surface against regression).

### 5.6 Audit step

Discrepancies between SECURITY.md §S-035 row text and UNIT-TESTS.md §2
rows were resolved by treating UNIT-TESTS.md as authoritative for surface
descriptions and SECURITY.md as authoritative for FA-track tags (the
two have been threaded together per the in-session doc coherence sweep,
but UNIT-TESTS.md's category structure is the canonical per-test surface
map; SECURITY.md's flat table is the operator-facing summary).

---

## 6. Findings

### F-1 — Option 2 DSF still outstanding; analytic proofs cover but no random-Byzantine fuzz

**Statement.** FA4 (Liveness) and FA-Apply-15 (Multi-event composition)
are the canonical multi-block / multi-actor properties. Both have
analytic proofs (`Liveness.md`, `MultiEventComposition.md`) and TLA+
companions (FB7 Nonce / FB20 MultiEventComposition / etc.). But the
136-test seed cannot reach them at unit-test granularity — they are
trace properties over multiple blocks with adversarial scheduling.

**Per-block slices ARE covered.** `test-required-block-sigs` pins the
formula at the heart of the BFT-mode liveness L-4.3 argument;
`test-block-event-composition` pins the per-block multi-event apply
algebra; `test-multi-block-chain` pins the chain-wide continuity invariant
across N=10 blocks. The DSF would close the loop by simulating
randomized Byzantine actors over many traces and asserting the
trace-level properties hold.

**Resolution.** Option 2 (DSF) is spec-resolved at
`docs/proofs/DSF-SPEC.md` **and its framework has shipped (increments 1-6:
the self-contained `sim/` core + 34 baked scenarios incl. the §Q5 generator's
two templates (broadcast + agreement) + the inc-5 §Q5/§Q6 `--generate N --seed S
[--template]` reproducible-variant CLI).** It is the canonical
extension for trace-level properties. NOTE: the increment-1-6 DSF scenarios run
a TOY model, not the real consensus engine. **The real-engine closure path is now
DECIDED and STARTED (owner 2026-07-07: "keep DSF self-contained"):** rather than
link the real engine into determ-dsf, the multi-block randomized-Byzantine
CONSENSUS traces run over the REAL `Chain::append` apply path via `test-fa-*`
subcommands in the determ binary (`docs/proofs/RealEngineFAHarness.md`) — the
consensus-layer analog of `test-supply-invariant-fuzz` (which already covers the
ECONOMIC A1 trace over the real engine). **Increment 1 (`test-fa-equivocation-trace`)
closes a SLICE of F-1/FA4 for the FA6 equivocation-slashing invariant (slash-once
/ idempotence / A1 / determinism over 48 real-apply blocks).** F-1/FA4 remain OPEN
overall until the abort/escalation, cross-shard (FA7), F2, and FA4-liveness slices
have their own real-engine trace harnesses. The `time::Clock` seam
(`docs/proofs/ClockInjectionSeam.md`, increment 1 shipped) is only needed if a
future harness drives a real networked Node; the apply-level harnesses do not need it.

### F-2 — Per-FA-Apply test surface is comprehensive

**Statement.** Of FA-Apply-1 through FA-Apply-16 (the apply-path
correctness theorems documented in `docs/proofs/README.md` lines 33..51),
every numbered theorem has at least one paired in-process unit test
that pins its central state-transition contract:

| FA-Apply | Companion test(s) |
|---|---|
| FA-Apply-1 (BlockchainStateIntegrity) | `test-chain-prev-hash-link`, `test-chain-save-load` |
| FA-Apply-2 (SnapshotEquivalence) | `test-snapshot-then-apply`, `test-snapshot-roundtrip` |
| FA-Apply-3 (NonceMonotonicity) | `test-tx-replay-protection`, `test-multi-tx-block` |
| FA-Apply-4 (StakeLifecycle) | `test-stake-accounting`, `test-unstake-deregister-apply` |
| FA-Apply-5 (DAppRegistryLifecycle) | `test-dapp-state-transition`, `test-dapp-register` |
| FA-Apply-6 (FeeAccounting) | `test-fee-distribution-edge`, `test-chain-apply-block` |
| FA-Apply-7 (SubsidyDistribution) | `test-subsidy-distribution`, `test-empty-block-apply` |
| FA-Apply-8 (GovernanceParamChange) | `test-param-change-apply`, `test-pending-param-changes` |
| FA-Apply-9 (CrossShardReceiptDedup) | `test-cross-shard-receipt-apply`, `test-cross-shard-multi-receipt` |
| FA-Apply-10 (EquivocationSlashingApply) | `test-equivocation-apply`, `test-equivocation-multi` |
| FA-Apply-11 (AbortEventApply) | `test-abort-event-apply` |
| FA-Apply-12 (AppliedReceiptRestore) | `test-applied-receipt-restore` |
| FA-Apply-13 (CrossShardOutboundApply) | `test-cross-shard-outbound-apply`, `test-cross-shard-atomicity` |
| FA-Apply-14 (NefPoolDrain) | `test-nef-pool-drain` |
| FA-Apply-15 (MultiEventComposition) | `test-block-event-composition` |
| FA-Apply-16 (StakeForfeitureCascade) | `test-equivocation-multi` |

**Significance.** The FA-Apply track is the most regression-prone surface
because each apply-path branch is a state-mutation function that can
silently corrupt state if its invariants drift. Coverage here is the
strongest defense against latent corruption bugs (the class S-037 + S-038
were drawn from). Every FA-Apply-N has at least one paired test —
no apply-path theorem is uncovered.

### F-3 — Some FA-track high-level proofs lack in-process tests by nature

**Statement.** FA4 (Liveness) and the full FA11 economic-soundness
composition theorem are trace properties spanning multiple blocks and
adversarial scheduling. They cannot be tested at unit-test (per-call)
granularity by design.

**Per-step coverage is comprehensive** — for FA4 every input invariant
(`test-required-block-sigs` for BFT quorum formula; `test-block-rand` for
proposer_idx; `test-resolve-fork` for fork-choice) and for FA11 every
component (A1 + E1 + E3/E4) is covered — but the trace-level statement
itself remains an Option 2 target.

**Resolution.** This finding is informational, not a gap. The 136-test
seed is the foundation, not the closure. Option 2 (DSF) closes the
trace-level statements; Option 1 + Option 3 close the per-call surfaces.

### F-4 — Coverage imbalance: FA1 has 18 tests; some FA-Apply theorems have only 1

**Statement.** §4.1 reports FA1 has 18 paired tests; §4.2 / §4.3 report
single-test coverage for FA-Apply-11 (AbortEventApply), FA-Apply-12
(AppliedReceiptRestore), FA-Apply-14 (NefPoolDrain), and others.

**Interpretation.** This is structural, not a gap. FA1 is the
load-bearing safety theorem under every signature, every hash, every
chain link — its fan-out into 18 tests reflects the fan-out of its
defense surface (Ed25519 + SHA-256 + Merkle + committee-selection +
block-digest + chain-append + validator-config + multi-block-chain +
make-block-sig + consensus-msgs + tx-signing-bytes + ...).
FA-Apply-11..14 each cover a single apply-path branch (AbortEvent /
applied_receipts / NEF) that is structurally narrower. Single-test
coverage is adequate when the surface itself is narrow and the test
covers it exhaustively (e.g., `test-nef-pool-drain` has 18 assertions
across 8 scenarios — comprehensive within the surface).

**Resolution.** No action. Imbalance reflects surface size, not gap.

### F-5 — `test-binary-codec-roundtrip-exhaustive` extends `test-binary-codec`

**Statement.** Two tests pin the wire-format codec: `test-binary-codec`
covers per-MsgType cap table golden vectors + format-detection contract;
`test-binary-codec-roundtrip-exhaustive` extends with exhaustive
serialize→deserialize coverage across every MsgType + edge-case body
sizes.

**Significance.** The pairing structure (basic + exhaustive) is the
recommended pattern for wire-format surfaces per UNIT-TESTS.md §4.8
(byte-layout golden-vector pattern). Replication of the pattern to
other wire surfaces (Transaction binary codec, MergeEvent codec) is
already in flight — see `test-tx-binary-codec`, `test-merge-event-codec`,
`test-merge-event-bytes`.

---

## 7. Test-count milestone tracking

The 136-test seed grew across many in-session rounds. Key milestones
(`tools/run_all.sh` is the canonical self-counting source for the current
total):

| Milestone | Count | When | Reference |
|---|---|---|---|
| Initial seed | ~15 | S-035 Option 1 initial closure | Original `determ test-*` surfaces (atomic-scope, composable-batch, dapp-register, dapp-call, s018-json-validation, ed25519, sha256, merkle, committee-selection, shard-routing, anon-address, genesis-message, state-root, block-rand, rate-limiter) |
| Crossed 30 | ~30 | First doc coherence sweep | Block-digest / block-hash / binary-codec / wire-types / transaction / consensus messages added |
| Crossed 50 | ~50 | Snapshot + apply-path round | Snapshot equivalence tests added (snapshot-roundtrip, snapshot-then-apply, snapshot-defense, state-proof) + chain integrity tests (chain-append, chain-helpers, chain-apply-block) + state-types / state-root-namespaces |
| Crossed 75 | ~75 | Round 13-14 expansion | DApp lifecycle, equivocation multi, cross-shard composition (atomicity, multi-receipt, outbound-apply), supply-lifecycle |
| Crossed 100 | 100 | Round 25 milestone | SECURITY.md §S-035 row updated to "100 in-process subcommands; 1920 total assertions; FAST=1 100/100 PASS in <49s" |
| Crossed 110 | ~110 | Round 30-32 | Determinism family (state-root-determinism, tx-signing-determinism, merge-event-determinism, config-determinism, genesis-determinism, hello-handshake-determinism, shard-routing-determinism) |
| Current: 136 | 136 | Latest commits per CLAUDE.md MEMORY | Includes `test-time-monotonicity`, `test-chain-prev-hash-link`, `test-block-validator-extensive`, `test-protocol-version-pinning`, `test-rate-limiter-bucket`, `test-make-contrib-commitment-distinct`, `test-view-root`, `test-frost-types`, `test-merkle-proof-tampering`, `test-binary-codec-roundtrip-exhaustive`, `test-block-rand-distribution`, plus the light-client / cross-shard / determinism additions merged in subsequent rounds (`tools/run_all.sh` is the canonical self-count) |

**Cadence.** The seed grew by ~7-10 tests per round (each round is a
parallel-agent expansion + threader merge per the round 18..35 task
list). Each new test is paired with: (a) source addition in `src/main.cpp`,
(b) shell wrapper in `tools/test_<name>.sh`, (c) FAST=1 regex entry in
`tools/run_all.sh`, (d) `determ help` row, (e) `docs/UNIT-TESTS.md` row,
(f) `docs/SECURITY.md` §S-035 row, (g) `docs/CLI-REFERENCE.md` row,
(h) `docs/README.md` representative-tests row.

**Doc-coherence discipline.** The headline assertion count in
`docs/README.md` + `docs/QUICKSTART.md` + `docs/WHITEPAPER-v1.x.md`
abstract is bumped by the round-finisher commit; this is the
operator-facing milestone tracker.

**Looking forward.** The next mechanical extension targets per
UNIT-TESTS.md §3 are: (a) `test-governance-param-change` (~½d),
(b) `test-block-validator-equivocation` (NodeRegistry fixture, ~1d),
(c) `test-mempool-admit` (Node fixture, ~1d). Each closes one of the
F-1 / §3.2 zero-coverage items.

---

## 8. References

### Primary

- `docs/SECURITY.md` §S-035 — finding registration + Option 1 / 2 / 3
  resolution table; 136-test enumeration with FA-track tags.
- `docs/UNIT-TESTS.md` §2 — per-test surface description; canonical
  per-test motivation and assertion count.
- `docs/proofs/README.md` lines 21..91 — full FA-track + FB-track
  enumeration with one-line theorem statements.

### FA-track proofs cited by the coverage map

- `Safety.md` (FA1), `Censorship.md` (FA2), `SelectiveAbort.md` (FA3),
  `Liveness.md` (FA4), `BFTSafety.md` (FA5), `EquivocationSlashing.md`
  (FA6), `CrossShardReceipts.md` (FA7), `RegionalSharding.md` (FA8),
  `UnderQuorumMerge.md` (FA9), `Governance.md` (FA10),
  `EconomicSoundness.md` (FA11), `WalletRecovery.md` (FA12).
- `BlockchainStateIntegrity.md` (FA-Apply-1), `SnapshotEquivalence.md`
  (FA-Apply-2), `NonceMonotonicity.md` (FA-Apply-3),
  `StakeLifecycle.md` (FA-Apply-4), `DAppRegistryLifecycle.md`
  (FA-Apply-5), `FeeAccounting.md` (FA-Apply-6),
  `SubsidyDistribution.md` (FA-Apply-7), `GovernanceParamChange.md`
  (FA-Apply-8), `CrossShardReceiptDedup.md` (FA-Apply-9),
  `EquivocationSlashingApply.md` (FA-Apply-10), `AbortEventApply.md`
  (FA-Apply-11), `AppliedReceiptRestore.md` (FA-Apply-12),
  `CrossShardOutboundApply.md` (FA-Apply-13), `NefPoolDrain.md`
  (FA-Apply-14), `MultiEventComposition.md` (FA-Apply-15),
  `StakeForfeitureCascade.md` (FA-Apply-16).
- `JsonValidationSoundness.md` (S-018), `S014RateLimiterSoundness.md`
  (S-014), `S020CommitteeSelection.md` (S-020), `S029ForkChoiceSoundness.md`
  (S-029), `S033StateRootNamespaceCoverage.md` (S-033),
  `MakeContribCommitmentBackwardCompat.md` (v2.7 F2),
  `FrostVerifyDelegation.md` (FB23).

### Companion specifications

- `DSF-SPEC.md` — Deterministic Simulation Framework spec
  (Option 2 closure target).
- `IMPLEMENTATION-SEQUENCING.md` — phase-by-phase rollout order for
  remaining FA / S items.
- `MAINNET_READINESS.md` — production-readiness gates including
  Option 1 / Option 2 status.

### Source / test infrastructure

- `src/main.cpp` — every `test-<feature>` subcommand implementation;
  136 distinct branches under `cmd == "test-..."` (verified by
  `grep -cE 'cmd == "test-' src/main.cpp`).
- `tools/test_*.sh` — 200 wrappers total; the 152 in-process subset wraps
  the `determ test-*` surface (verified by cross-reference with the
  136 source-side entries).
- `tools/common.sh` — Option 3 path-portability layer
  (`DETERM` / `DETERM_WALLET` binary discovery, `PROJECT_ROOT`
  resolution).
- `tools/run_all.sh` — FAST=1 short-circuit regex covering the
  136-test in-process subset; the canonical self-counting source for the
  `determ test-*` subcommand total.

---

**End of UnitTestCoverageMap.md.**
