# Open Vulnerabilities + Resolution Options

State of v1 (rev.8 + sharding through B6.basic). Excludes vulnerabilities the Gemini rev.7 analysis raised but which have since been mitigated (blind-abort liveness via BFT escalation, linear-time sync via snapshot bootstrap, equivocation deterrence via full-stake forfeit). Those are documented in [PROTOCOL.md](PROTOCOL.md).

Each entry: **what's open**, **severity**, **why it's hard**, **options ranked from cheap-and-incomplete to expensive-and-complete**.

---

## 1. Hardware heterogeneity / constant-T fallacy

**What's open.** `delay_T` is a chain-wide genesis-pinned integer. It calibrates `T_delay ≥ 2 × T_phase1` on "standard consumer hardware." A capitalized adversary running an over-clocked SHA-256 ASIC executes the same `T` iterations in a fraction of the wall-clock budget, regaining the predictive-evaluation window the protocol was designed to close. Selective abort returns.

**Severity:** consensus-break. The protocol's primary cryptoeconomic defense (selective abort impossibility) silently weakens as commodity ASIC speed improves. Not exploitable today on small chains; becomes critical at production scale.

**Why hard.** `delay_T` is in `GenesisConfig`; adjusting it is a hard fork. SHA-256 is the most heavily-ASIC'd hash in existence — the gap between consumer CPU and a Bitmain-grade rig is multiple orders of magnitude.

**Options:**

| # | Option | Cost | Notes |
|---|---|---|---|
| 1 | **Coordinated `delay_T` bumps via hard fork on a schedule.** Treat T like difficulty on a slower clock — re-evaluate every 6-12 months against a published benchmark. | Low protocol effort; high coordination cost. | Doesn't *solve* the asymmetry, just keeps the gap below exploitable threshold. Acceptable for v1.x. |
| 2 | **Replace SHA-256 with a memory-hard delay function** (Argon2, scrypt-style sequential). ASIC speedup drops from 1000× to 10×. | Medium. Re-implement `delay_hash` worker; new constant-time benchmark. Hard fork. | Doesn't fully eliminate but compresses the asymmetry. |
| 3 | **Verifiable Delay Function (Wesolowski / Pietrzak class groups).** Real T is enforced by the proof, not the hash; verifier work is sub-linear. Still ASIC-vulnerable but the bound is mathematically tight. | High. Class-group arithmetic is heavy; library choice matters; proof verification cost on every block. | Active research; reference implementations exist but are not battle-tested in deployed L1s. |
| 4 | **zk-VDF (zero-knowledge VDF).** Prover commits to a sequential computation; verifier checks a SNARK in milliseconds regardless of T. Defeats ASIC asymmetry because the *output* must satisfy the SNARK constraint, not just be a hash chain. | Highest. SNARK setup, trusted ceremony or transparent SNARKs (~Halo2/Plonky2), prover cost dominates block production. | The "right" v2 answer cited in the Gemini doc's conclusion. Roughly 6+ months of focused work. |

**Recommended path:** Option 1 for v1.x (cheap, buys time). Option 2 (memory-hard) for v1.5. Option 4 for v2.

---

## 2. Buffer-and-replay memory exhaustion (BlockSigMsg flood)

**What's open.** `BlockSigMsg` packets that arrive before the local node's delay-hash completes are buffered (we can't verify the signature yet — `block_digest` depends on `delay_output` we haven't computed). An adversary floods the Phase-1 window with millions of syntactically-valid but cryptographically-fraudulent BlockSigMsgs. Each gets queued. When delay-hash completes, the node has to verify the entire bloated buffer; OOM crash before consensus thread can do useful work.

**Severity:** local DoS (single-node crash). Doesn't break consensus globally — peers that aren't being flooded continue. But coordinated flood across multiple committee members triggers cascading aborts.

**Why hard.** Pre-verification filtering is precisely what's *impossible* during the Phase-1 window — the digest depends on randomness we don't have yet.

**Options:**

| # | Option | Cost | Notes |
|---|---|---|---|
| 1 | **Bounded per-peer queue.** Each peer's buffered BlockSigMsg count capped at K (the committee size). Excess silently dropped. | Trivial. ~10 LOC in the gossip layer. | Limits per-peer impact but a botnet with N peers can still flood. |
| 2 | **Bounded total queue + LRU eviction.** Total buffered ≤ some constant × K. Oldest dropped first. | Trivial. | Fully bounds memory regardless of sender count. May drop legitimate sigs from slow peers if buffer fills. |
| 3 | **Cheap pre-filter: signer-domain check.** Reject BlockSigMsgs whose `signer` isn't in the current `registry_`. Free for non-members; requires a string lookup per packet, no crypto. | Low. | Forces attacker to spoof a registered domain (which means already-committed registry costs). Doesn't help if attacker controls a registered domain. |
| 4 | **Phase-1 windowed bound:** total buffered messages limited to some sane multiple of M_pool. After threshold, switch to "reject early-arrivals" instead of buffer. | Low-medium. | Sacrifices some optimization (early arrivals are rare on healthy networks). |
| 5 | **Mandatory peer rate-limiting** at TCP level (token bucket per peer). | Medium. Hooks into the Peer class's read loop. | Defends against flooding generally, not just BlockSigMsg-specific. Best long-term hygiene. |

**Recommended path:** Options 1+3 together. ~20 LOC; closes the immediate vector without sacrificing the legitimate buffer-and-replay optimization.

---

## 3. Rejection sampling K/N → 1 efficiency degradation

**What's open.** `select_m_creators` uses rejection sampling with a counter. Average cost is O(K) when K << N (eligible pool). After cascading suspensions shrink N toward K, rejection sampling explodes — every random pick collides, the counter advances, and the inner loop iterates many times per slot. At K = N - 1 the algorithm is O(K²) or worse in expectation.

**Severity:** latency / DoS amplification. Not a consensus-break, but during exactly the moments the chain is *already* under stress (mass suspensions), committee selection slows. Compounds with #2.

**Why hard.** Rejection sampling is the standard way to draw *m* distinct from *n*. Alternative: Fisher-Yates shuffle (O(N) deterministic). Both correct.

**Options:**

| # | Option | Cost | Notes |
|---|---|---|---|
| 1 | **Switch to Fisher-Yates** when K/N > some threshold (e.g., 0.6). Hybrid: rejection for sparse, shuffle for dense. | Trivial. ~30 LOC + threshold tuning. | Keeps the cheap O(K) path for the common case; bounded O(N) for stress conditions. |
| 2 | **Always Fisher-Yates.** | Trivial. | Slightly higher cost in the common case (K=3, N=100) but bounded everywhere. Simpler code. |
| 3 | **Reservoir sampling.** Algorithm L gives O(K log(N/K)). | Trivial. | Slightly more complex than Fisher-Yates with no real benefit at our scales. |
| 4 | **Seeded permutation table.** Cache a permutation of pool indices keyed by `(epoch_rand, shard_id)`. Lookup is O(K). | Medium. Cache invalidation logic. | Worth it only if committee-selection cost shows up in profiling. |

**Recommended path:** Option 1 (hybrid). One-evening fix.

---

## 4. Phase-2 timing spoofing via `peer_R_arrival_time`

**What's open.** The Gemini doc cites a timer formula `min(local_delay_done_time, peer_R_arrival_time) + block_sig_ms`. If the current implementation still uses any external-peer-derived input in the Phase-2 trigger timer, an adversary can inject a forged early "R arrived" signal and force honest nodes to advance to Phase 2 before they have a real `delay_output`. Honest node then signs garbage and gets suspended for what looks like its own fault.

**Severity:** depends on current implementation; needs an audit. If still present: griefing / suspension-of-honest-nodes vector. If already removed: false positive — close it.

**Why hard.** The optimization (advance Phase 2 the moment a peer's R arrives, not waiting for our own delay-hash) is a real latency win on healthy networks. Removing it costs ~T_delay of latency per block.

**Options:**

| # | Option | Cost | Notes |
|---|---|---|---|
| 0 | **Audit first** — check if the formula is still in the consensus event loop. The doc's claim is from rev.7. | Free. | Required first step. |
| 1 | **Pre-validate `R` cryptographically before trusting arrival.** Don't advance the timer on `R` until we've verified it produces the expected `block_digest` against at least one valid `BlockSigMsg`. | Low. | Defeats forged-R injection. Slight latency cost (one extra verify before timer fires). |
| 2 | **Local-clock only.** Drop `peer_R_arrival_time` from the formula entirely. Timer = `local_delay_done_time + block_sig_ms`. | Trivial. | Loses the latency optimization. Acceptable if the optimization isn't measurably winning. |
| 3 | **Quorum gate.** Advance only after `f` (some small number) of peers report `R` AND each report passes the cryptographic pre-validation. | Medium. | Best of both: fast path on healthy networks, robust under spoofing. |

**Recommended path:** Audit (Option 0) → if present, Option 1 or 3. ~1 day of work.

---

## 5. Determinism gap on `pending_inbound_receipts_` (B3.4 quirk)

**What's open.** Each destination-shard committee member passes their *local* `pending_inbound_receipts_` snapshot to `build_body`. If pools differ momentarily during bundle gossip, members produce different tentative blocks, K-of-K fails, round aborts and retries. Documented in B3.4 commit message as v2.x. Not exploitable but adds avoidable latency under high cross-shard traffic.

**Severity:** correctness-preserving latency tax. Pools converge through gossip; round retries until they do.

**Why hard.** True deterministic pool requires every committee member to either share the same view (impossible mid-gossip) or use a protocol-level merge (intersection or union via Phase-1 contrib).

**Options:**

| # | Option | Cost | Notes |
|---|---|---|---|
| 1 | **Phase-1 contrib intersection.** Each `ContribMsg` gains `inbound_keys: [(ShardId, Hash)]`. Block bakes only receipts in the intersection of all K members' lists. Block format extends with `creator_inbound_keys[]`. | Medium. ~3-4 hours. Block + ContribMsg + commitment hash + JSON I/O. | Strictly more conservative than UNION; deterministic. Receipts not in everyone's pool delay one round. |
| 2 | **Phase-1 contrib union with on-demand fetch.** Members lacking content for a key in the union fetch from a peer mid-Phase-2. | Higher. Adds a synchronous fetch in the consensus loop — risky. | Maximally inclusive but introduces new failure modes. |
| 3 | **Time-ordered admission.** Receipts only eligible for inclusion `>=N` blocks after first observed locally. By then gossip has propagated. | Trivial. | Doesn't fully eliminate but pushes the failure rate down to near zero in practice. Adds latency to every cross-shard transfer. |
| 4 | **Accept the latency tax.** Round retries are bounded; cross-shard traffic is light in v1. | Free. | What B3.4 currently does. |

**Recommended path:** Option 1 for v1.x. The ContribMsg/Block changes are localized and the determinism win is worth it.

---

## 6. Snapshot bootstrap is "trust the source"

**What's open.** B6.basic restores state directly from a snapshot file with one sanity check (recomputed `head_hash` must match the snapshot's claimed value). But the snapshot's `accounts`/`stakes`/`registrants` maps aren't cryptographically tied to the head — the receiver trusts that whoever produced the snapshot honestly serialized state. A malicious operator could ship a snapshot where Alice has 10× her real balance; the receiver can't tell.

**Severity:** trust-boundary issue, not a chain-break. The receiver's *own* chain after restore is internally consistent; they just disagree with the rest of the network. Detection happens fast (next block applied → balance check fails on transaction → divergent fork).

**Why hard.** Cryptographic verification needs a state root in the block header. That's a backward-incompatible block format change.

**Options:**

| # | Option | Cost | Notes |
|---|---|---|---|
| 1 | **Post-restore consistency check.** After restore, fetch the next ~10 blocks from peers and replay. If any replay produces state differing from what the snapshot claimed, roll back to genesis-replay. Currently planned but not implemented. | Low. ~50 LOC in Node::start. | Detects but doesn't prevent — receiver still trusts the source for the moments before the first block applies. |
| 2 | **Multi-source consensus.** Receiver fetches snapshots from N peers, accepts if at least M agree on every account/stake/registrant. | Medium. Need parallel fetcher + merge. | Strong without state roots; cost is N× bandwidth. |
| 3 | **State Merkle root in Block.** Each block commits to `SHA256(canonical_state)`. Snapshot includes the state; receiver verifies against the root in the snapshot's tail head. | High. Block format change → hard fork. New state encoding for canonical hashing (sort-and-hash). | The "right" v2 answer. Also enables light clients with state proofs. |
| 4 | **Sparse Merkle tree per state map.** Same as Option 3 but supports proof-of-inclusion for individual accounts (e.g., "prove Alice has balance X without full snapshot"). | Highest. SMT library + per-tx state-update proofs. | Enables true light clients. Probably v2.x. |

**Recommended path:** Option 1 immediately (closes the practical risk for v1). Option 3 for v2.

---

## 7. Sybil-via-low-MIN_STAKE (genesis parameter risk)

**What's open.** The Gemini doc raised this. If `min_stake` is set too low at genesis relative to the exogenous market price of the token, an attacker registers thousands of domains, gains majority control of M_pool, and biases committee selection.

**Severity:** parameter-tuning risk, not a code bug. STAKE_INCLUSION model only.

**Why hard.** Stake price is exogenous; the protocol can't know what the token is worth.

**Options:**

| # | Option | Cost | Notes |
|---|---|---|---|
| 1 | **Operator guidance.** Document recommended `min_stake` ranges in PROTOCOL.md or a separate operator's guide. Provide a calculator that takes block subsidy, target attack-cost, expected market cap as inputs. | Trivial. | Pushes the responsibility to the chain creator. |
| 2 | **Stake-price-anchored min_stake.** Make `min_stake` a function of recent block subsidy + cumulative_rand-derived oracle. Hard. | Medium-high. Requires an oracle or social consensus. | Ethereum dodges this with EIP-1559-style burn dynamics; DHCoin's design isn't fee-driven enough for the analog. |
| 3 | **Use DOMAIN_INCLUSION model.** Sybil resistance comes from DNS / external naming costs instead of stake. Already supported. | Free; just a genesis choice. | Solves the problem orthogonally for chains that prefer it. |

**Recommended path:** Option 1 (docs). Option 3 is already available for chains that don't trust stake-pricing.

---

## 8. Same-signer ContribMsg across abort-generations isn't flagged as equivocation

**What's open.** `node.cpp` ~line 1342 comment: *"Real equivocation detection requires generation tracking (planned for a future rev). For now, if we're still in CONTRIB phase and receive a duplicate from a signer we already have, ignore the new one."*

A creator that signs two `ContribMsg`s for the same height with different `dh_input`s under different `aborts_gen` values produces what looks like legitimate post-abort retries but could be exploiting the gap to bias the union tx-set.

**Severity:** unclear. The contrib commitment binds the dh_input to the (block_index, prev_hash, tx_hashes). Two contribs from the same signer with different (tx_hashes, dh_input) at the same height... actually that's allowed across abort generations. The current code defers detection.

**Why hard.** Distinguishing legitimate retries from malicious double-contribs requires tracking which abort-generation each contrib belongs to — currently `ContribMsg.aborts_gen` exists but isn't equivocation-checked.

**Options:**

| # | Option | Cost | Notes |
|---|---|---|---|
| 1 | **Generation-keyed storage.** Index `pending_contribs_` by `(signer, aborts_gen)`. Two contribs at the same `(signer, aborts_gen)` but different content → equivocation. | Low-medium. | Closes the gap mostly. |
| 2 | **Cross-generation hash binding.** ContribMsg commits to a chain of `(prev_aborts_gen_hash, current_dh_input)`, so an attacker can't backdate a contrib to a different generation. | Medium. ContribMsg field + commitment change. | Stronger but more invasive. |
| 3 | **Status quo.** Defer to a future rev; document explicitly. | Free. | What's currently shipped. Acceptable until #1 is needed. |

**Recommended path:** Option 1 for v1.1. Low cost, real correctness improvement.

---

## 9. No bounded reorg / fork-choice for BFT-mode blocks

**What's open.** When a BFT-mode round has multiple `bft_proposer` candidates (rare — should be deterministic, but mid-equivocation it can happen), the current code is "first-seen-wins." A node that observes proposer A's block first treats it as canonical; a node that observes B's first treats *that* as canonical. They disagree until the next finalized block.

**Severity:** transient inconsistency, self-healing. The finalized block at height H+1 picks one parent; the other becomes orphaned. No double-credit because apply is per-block.

**Why hard.** Bounded reorg requires a fork-choice rule. The K-of-K MD path doesn't need one (unanimity makes equivocation impossible without total collusion). BFT mode introduces the possibility because only `ceil(2K/3)` sigs are required.

**Options:**

| # | Option | Cost | Notes |
|---|---|---|---|
| 1 | **First-seen-wins (current).** | Free. | Acceptable for v1; equivocation-detection-and-slashing is the real defense. Once both proposers' sigs are seen by enough peers, slashing applies regardless of which fork "won." |
| 2 | **Heaviest-sig-set rule.** Block with more `creator_block_sigs` filled wins. Tie-broken by hash. | Low. | Trivial fork-choice. Bounded depth (1 block typically). |
| 3 | **Bounded reorg window.** Allow re-application of a different finalized block at height H if it has more sigs and is observed within W blocks. | Medium. Apply rollback path, undo state changes. | Real reorgs are expensive; risky. |

**Recommended path:** Status quo + slashing (Option 1). Option 2 if multi-proposer-BFT becomes common.

---

## 10. RPC has no rate limiting

**What's open.** `submit_tx`, `submit_equivocation`, `snapshot`, etc. all run with no cap. A misconfigured peer or hostile RPC client can flood with submissions or repeatedly fetch the full snapshot.

**Severity:** local DoS via RPC port. Doesn't break consensus.

**Why hard.** Not hard. Just hasn't been done.

**Options:**

| # | Option | Cost | Notes |
|---|---|---|---|
| 1 | **Per-method token bucket** in `RpcServer::dispatch`. Defaults: `snapshot` 1/min, `submit_tx` 100/sec, `submit_equivocation` 10/min, query methods uncapped. | Low. ~50 LOC. | Standard hygiene. |
| 2 | **Bind RPC to localhost by default**, require explicit config to expose externally. | Trivial. Already mostly the case via `127.0.0.1` literal. | Defense in depth. |
| 3 | **Auth tokens** for submit-class methods. | Medium. | Worth it if RPC is exposed to any untrusted network. |

**Recommended path:** Options 1+2 in one sitting. ~1 hour.

---

## Summary table

| # | Vulnerability | Severity | Recommended fix | Effort |
|---|---|---|---|---|
| 1 | Constant-T / ASIC fallacy | Consensus weakening over time | Coordinated T bumps now; memory-hard or VDF later | v1.x docs / v2 protocol |
| 2 | BlockSigMsg buffer flood OOM | Local DoS | Bounded queue + signer pre-filter | ~20 LOC |
| 3 | Rejection sampling under stress | Latency amplification | Hybrid Fisher-Yates | ~30 LOC |
| 4 | Phase-2 timer R-arrival spoof | Honest-node griefing (if present) | Audit + cryptographic pre-validate | ~1 day |
| 5 | Inbound-receipts pool determinism | K-of-K retry latency | Phase-1 contrib intersection | ~3-4 hours |
| 6 | Snapshot trust-the-source | Trust-boundary issue | Post-restore consistency check now; state root v2 | ~50 LOC now |
| 7 | Sybil via low MIN_STAKE | Parameter-tuning risk | Operator-guidance docs + DOMAIN_INCLUSION | docs |
| 8 | Cross-generation contrib equivocation | Unclear (deferred check) | Generation-keyed storage | low-medium |
| 9 | BFT-mode fork-choice | Transient inconsistency | Status quo + slashing | done |
| 10 | RPC no rate limit | Local DoS | Per-method token bucket | ~1 hour |

The cheapest cluster of wins (#2 + #3 + #5 + #6.1 + #10) is roughly one full focused day of work and closes the practical attack surface meaningfully. #1 and #6.3 are the two genuine v2-class items that need protocol evolution.
