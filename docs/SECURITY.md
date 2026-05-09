# DHCoin Security Posture

**Doc status:** Canonical. Reconciles the rev.7 [SECURITY_AUDIT.md](https://github.com/) findings with the in-tree [OPEN-VULNERABILITIES.md](OPEN-VULNERABILITIES.md) (now superseded by this file) against current code at rev.8 + rev.9 sharding through B6.basic.

**Methodology.** Each finding is verified against current source before classification. Findings the rev.7 audit raised that have since been mitigated are listed in §5. New issues visible in rev.9 code (sharding, snapshots) that the audit predates are included as first-class findings. Severity follows the audit's CVSS-style framing.

---

## 1. Executive summary

| | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| Open | **4** | **8** | **8** | **9** | **29** |
| Mitigated since rev.7 | — | — | — | — | **4** |
| v2 protocol-evolution | — | — | — | — | **2** |

**Top-of-list priorities for production deployment:**

- **S-001** RPC authentication missing (any network client controls the node)
- **S-002** Mempool accepts unverified signatures (DoS via sig-forgery flood)
- **S-003** Block timestamp window ±5s contradicts README ±30s (chain stalls under NTP drift)
- **S-004** Private keys written to stdout / unencrypted files
- **S-005** `delay_T` not in GenesisConfig (consensus divergence between misconfigured nodes)

The cheapest cluster of wins (S-001-localhost-only, S-002, S-005, S-007, S-008, S-013, S-014, S-023) is roughly **2 days** of focused work and closes the practical attack surface meaningfully.

---

## 2. Triage table

Sortable matrix of all open findings. Detailed entries below in §3-§6.

| ID | Sev | Title | File / Locus | Effort |
|---|---|---|---|---|
| S-001 | 🔴 Crit | RPC authentication missing | `rpc/rpc.cpp:13,52-89` | 1d basic / 3d TLS+HMAC |
| S-002 | 🔴 Crit | Mempool accepts unverified-sig transactions | `node/node.cpp:1353-1371` | 1-2d |
| S-003 | 🔴 Crit | Block timestamp window ±5s vs README ±30s | `node/validator.cpp:559-564` | 1d |
| S-004 | 🔴 Crit | Plaintext private key in `account create` output | `main.cpp:cmd_account_create` | 2d |
| S-005 | 🟠 High | `delay_T` not in GenesisConfig | `chain/genesis.{hpp,cpp}` | 1d |
| S-006 | 🟠 High | ContribMsg cross-generation equivocation undetected | `node/node.cpp:1342` | low-med |
| S-007 | 🟠 High | Integer overflow in subsidy distribution | `chain/chain.cpp:245-253` | 1d |
| S-008 | 🟠 High | Unbounded mempool growth | `node/node.cpp:1353` | 1-2d |
| S-009 | 🟠 High | Constant-T / SHA-256 ASIC fallacy | `crypto/delay_hash.cpp` | v2 protocol |
| S-010 | 🟠 High | Sybil via under-priced MIN_STAKE | `chain/params.hpp` | docs / DOMAIN_INCLUSION |
| S-011 | 🟠 High | Abort claim cartel via M-1 quorum | `node/node.cpp::on_abort_claim` | high |
| S-012 | 🟠 High | Snapshot bootstrap is "trust the source" | `chain/chain.cpp::restore_from_snapshot` | 50 LOC now / v2 root |
| S-013 | 🟡 Med | BlockSigMsg buffer flood OOM | `net/gossip.cpp` (buffered_block_sigs_) | ~20 LOC |
| S-014 | 🟡 Med | No rate limiting on gossip + RPC | `net/gossip.cpp`, `rpc/rpc.cpp` | ~50 LOC + per-IP buckets |
| S-015 | 🟡 Med | Delay-worker thread join blocks consensus path | `node/node.cpp:490` | 1-2d |
| S-016 | 🟡 Med | Inbound-receipts pool non-deterministic across committee | `node/producer.cpp::build_body` | 3-4h |
| S-017 | 🟡 Med | Producer/chain validation logic mismatch (UNSTAKE) | `node/producer.cpp` vs `chain/chain.cpp` | 2-3d |
| S-018 | 🟡 Med | JSON parsing without schema validation | all `from_json` | 2-3d |
| S-019 | 🟡 Med | Phase-2 timer R-arrival spoofing | (audit needed) | 1d audit + fix |
| S-020 | 🟡 Med | Rejection sampling O(K²) at K/N→1 | `crypto/random.cpp::select_m_creators` | ~30 LOC |
| S-021 | 🟢 Low | Chain file integrity not cryptographically verified | `chain/chain.cpp::load` | 1d |
| S-022 | 🟢 Low | 16 MB message limit too permissive (modulo snapshots) | `net/peer.cpp:38` | nuanced |
| S-023 | 🟢 Low | RPC `send`/`stake` skip balance check | `node/node.cpp:1816` | 1h |
| S-024 | 🟢 Low | Deregistration timing predictability | `chain/chain.cpp::derive_delay` | low priority |
| S-025 | 🟢 Low | `compute_tx_root_intersection` is dead code | `node/producer.cpp:146` | 5 min delete |
| S-026 | 🟢 Low | No connection timeout / keepalive on peer sockets | `net/peer.cpp` | 1d |
| S-027 | 🟢 Low | Info leakage in logs / verbose error messages | many | docs / runtime flag |
| S-028 | 🟢 Low | Hex parsing only accepts lowercase | `types.hpp:30-47` | trivial |
| S-029 | 🟢 Low | BFT-mode multi-proposer fork-choice undefined | `node/node.cpp::on_block` | bounded reorg |

---

## 3. Critical findings (open)

### S-001 — RPC authentication missing

**Severity:** Critical • **Status:** Open • **Sources:** Audit 1.1, OV-#10

**What's open.** The RPC server (`src/rpc/rpc.cpp:13`) constructs its acceptor with `tcp::v4()` — bound to all IPv4 interfaces, port-only. Dispatch (`rpc.cpp:52-89`) executes `submit_tx`, `register`, `stake`, `unstake`, `submit_equivocation`, `snapshot`, `account` query, and so on with no authentication, no TLS, no rate limit, and no localhost-only restriction by default.

**Impact.** Any network-reachable client can:
- Submit transactions debiting the node's domain balance (with the node's own key implicitly via `rpc_send`)
- Register the node's domain or alter its stake
- Trigger `submit_equivocation` floods
- Pull a full state snapshot

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Bind RPC to `127.0.0.1` by default**; require explicit config to expose externally. | Trivial. Constructor change in `rpc.cpp:13` to use `make_address("127.0.0.1")`. |
| 2 | **Per-method token bucket** in dispatch. Defaults: `snapshot` 1/min, `submit_tx`/`submit_equivocation` capped, query methods uncapped. | ~50 LOC. |
| 3 | **HMAC token in request envelope.** Client sends `{method, params, hmac}` where hmac is `HMAC-SHA256(shared_secret, canonical_request)`. Shared secret is config-pinned. | 1-2d. |
| 4 | **Mutual TLS** for any externally-exposed RPC. | 3d. Asio TLS layer + cert management. |

**Recommended.** Options 1 + 2 immediately (~1h total). Options 3 or 4 only if RPC must be exposed beyond loopback.

---

### S-002 — Mempool accepts unverified-signature transactions

**Severity:** Critical • **Status:** Open • **Sources:** Audit 1.4

**What's open.** `Node::on_tx` (`src/node/node.cpp:1353-1371`) accepts incoming transactions into `tx_store_` after only a stale-nonce check and a replace-by-fee check. **No `crypto::verify` is called** on this path. Signature verification only happens later in `BlockValidator::check_transactions` at apply time.

**Impact.**
- Mempool flood with valid-shape, invalid-signature transactions.
- Each fake tx is stored, gossiped, indexed by `(from, nonce)`, and iterated during block construction.
- Memory exhaustion + bandwidth amplification + producer time wasted resolving fake hashes.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Verify Ed25519 sig in `on_tx`** before insertion. For bearer addresses derive pubkey from the address; for registered domains lookup in `registry_`. | 1-2d. Hot path; benchmark. |
| 2 | **Verify hash + sig** as a cheap pre-filter (recompute `compute_hash()`, then verify). Same as `rpc_submit_tx` already does. | Subset of #1. |
| 3 | **Bounded mempool with sig-verify-on-eviction-attempt** (verify lazily but bound size first). | Cheaper at hot-path cost; still leaves the iteration risk. |

**Recommended.** Option 1. Same model `rpc_submit_tx` already uses (`node.cpp:1846` recomputes hash and rejects mismatches). Aligning `on_tx` is mostly copy-paste.

---

### S-003 — Block timestamp window ±5s contradicts spec

**Severity:** Critical (for liveness) • **Status:** Open • **Sources:** Audit 1.2

**What's open.** `BlockValidator::check_timestamp` at `src/node/validator.cpp:559-564` rejects any block with `|b.timestamp - now()| > 5`. The README spec text references ±30s. Under normal cross-region NTP drift, legitimate blocks get rejected as out-of-window.

**Impact.** False-positive aborts → suspension → cascading liveness failure on globally-distributed deployments.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Widen window to ±30s** to match the spec. | One-line change. |
| 2 | **Median-of-last-N timestamps** (Bitcoin-style) instead of wall-clock comparison. | Medium. Adds chain history dependency to validator. |
| 3 | **Drop wall-clock check entirely**, rely on round timing for ordering. | Trivial. Loses the timestamp-as-monotonicity-signal. |

**Recommended.** Option 1 immediately + update PROTOCOL.md to nail the canonical window. Option 2 is the v2 answer.

---

### S-004 — Plaintext private key in `account create` output

**Severity:** Critical • **Status:** Open • **Sources:** Audit 1.3

**What's open.** `cmd_account_create` in `src/main.cpp` emits the raw `priv_seed` either to stdout or to an unencrypted file, with no `chmod`, no passphrase prompt, no warnings beyond a string in the JSON.

**Impact.** Standard key-leak vectors: terminal scrollback, shell history, world-readable file, accidental commit, accidental log capture.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Refuse to write to stdout.** Require `--out`. Set `0600` on the output file (Windows: deny inheritable read for non-owner). | Trivial. |
| 2 | **Encrypt with passphrase** (libsodium `crypto_secretbox_easy` or OpenSSL EVP). Prompt for passphrase interactively. | 1-2d. |
| 3 | **Hardware-wallet integration** (BIP32 derivation from a hardware seed). | Out of scope for v1. |

**Recommended.** Option 1 immediately. Option 2 for v1.x. Document key-handling in `docs/QUICKSTART.md`.

---

## 4. High findings (open)

### S-005 — `delay_T` not in GenesisConfig

**Severity:** High (consensus-divergence) • **Status:** Open • **Sources:** Audit 3.9 (re-classified up from Medium)

**What's open.** `GenesisConfig` (`include/dhcoin/chain/genesis.hpp:78-105`) contains no `delay_T` field. `grep delay_T genesis.{hpp,cpp}` returns empty. `delay_T` is loaded from the per-node `Config` instead. Two nodes with different per-node `delay_T` will produce differently-validated blocks (the validator at `node.cpp:1446` uses `cfg_.delay_T`).

**Impact.** Consensus divergence between misconfigured nodes. The PROTOCOL.md claim that `delay_T` is "genesis-pinned" is **not enforced by code**.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Add `delay_T` to GenesisConfig**, plumb through to chain + validator. Reject node startup if `cfg_.delay_T != gcfg.delay_T`. | 1d. Block-format-compatible (it's a chain-wide constant, not per-block). |
| 2 | **Computed from chain ID + version** (deterministic, no config). | More invasive. |

**Recommended.** Option 1. This is a bug-bait waiting to happen.

---

### S-006 — ContribMsg cross-generation equivocation undetected

**Severity:** High • **Status:** Open • **Sources:** Audit 2.4, OV-#8

**What's open.** Block-level equivocation IS now closed-loop in rev.8 (BlockSigMsg over distinct digests at the same height → `EquivocationEvent` → full stake forfeit + deregister, see §5 below). But **ContribMsg-level equivocation across abort generations is still deferred**: the comment near `node.cpp:1342` says *"Real equivocation detection requires generation tracking (planned for a future rev). For now, if we're still in CONTRIB phase and receive a duplicate from a signer we already have, ignore the new one."* The `contrib_equivocations_` map declared in `node.hpp` is never written to.

**Impact.** A creator can present different `tx_hashes` lists (or `dh_input`s) to different peers at the same height, biasing the union tx-set seen by different members. Severity is bounded by the K-of-K signing of the ultimate block — divergent contribs cause K-of-K to fail and the round to abort, which is *itself* slashable via S-005's existing block-level path. So in practice this exploit converts to "force the chain to abort," which the BFT escalation path can recover from.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Generation-keyed `pending_contribs_`.** Index by `(signer, aborts_gen)`. Two contribs at the same key with different commitments → `ContribEquivocationEvent` → gossip + slash. | Low-medium. ~1d. |
| 2 | **Cross-generation hash binding.** ContribMsg commits to `prev_aborts_gen_hash || dh_input`, preventing backdating. | Medium. ContribMsg field + commitment change → block format implications. |
| 3 | **Status quo** (rely on K-of-K abort to neutralize the divergence; don't slash). | Free. Acceptable if BFT escalation reliably recovers. |

**Recommended.** Option 1 for v1.1.

---

### S-007 — Integer overflow in subsidy distribution

**Severity:** High • **Status:** Open • **Sources:** Audit 2.5

**What's open.** `chain.cpp:245-253` distributes `total_distributed = total_fees + block_subsidy_` across `b.creators` with no overflow check. With a malicious genesis or a long-lived chain accumulating fees, `+=` on `accounts_[domain].balance` can wrap.

**Impact.** Funds destruction or unauthorized minting. The genesis-config attack vector is most realistic — a chain operator setting an absurd `block_subsidy` produces wrap-around at apply time.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Saturating add** on every balance mutation: `balance = balance + delta; if (balance < delta) balance = UINT64_MAX;` | ~10 LOC, every credit site. |
| 2 | **`__builtin_add_overflow`** with hard reject (treat as invalid block). | ~10 LOC. Stricter than saturation. |
| 3 | **Sane-bounds check on genesis** (`block_subsidy < 10^18`, etc.) at startup. | Trivial. Doesn't catch slow accumulation. |

**Recommended.** Option 2 + Option 3. Half-day of work.

---

### S-008 — Unbounded mempool growth

**Severity:** High • **Status:** Open • **Sources:** Audit 2.6

**What's open.** `tx_store_` and `tx_by_account_nonce_` have no size cap. Replace-by-fee bounds *per-`(from, nonce)`* but not total. Combined with S-002 (no sig verification), this is a memory-exhaustion DoS.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Hard cap on `tx_store_.size()`** (e.g., 10,000 or 100 MB total). On full, evict lowest-fee. | 1-2d. |
| 2 | **Minimum fee threshold** rejected at `on_tx` / `submit_tx`. Threshold rises with mempool pressure. | 2-3d (fee-market dynamics). |
| 3 | **Per-sender quota** (max N pending txs per `(from)`). | Subset of #1. |

**Recommended.** Option 1 + Option 3 for v1.x. Fee market is v2.

---

### S-009 — Constant-T / SHA-256 ASIC fallacy

**Severity:** High (consensus-weakening over time) • **Status:** Open, v2 protocol • **Sources:** OV-#1, Gemini analysis

**What's open.** `delay_T` is genesis-pinned. SHA-256 is the most heavily-ASIC'd hash in existence; the gap between consumer CPU and Bitmain-grade hardware is multiple orders of magnitude. An attacker with optimized SHA-256 silicon executes the same `T` iterations in a fraction of the wall-clock budget, regaining the predictive-evaluation window the protocol was designed to close — selective abort returns.

Not exploitable today on small chains; becomes critical at production scale.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Coordinated `delay_T` bumps** via hard fork on a 6-12 month cadence. | Low protocol effort; high coordination cost. Doesn't *solve*, just keeps the gap below threshold. |
| 2 | **Memory-hard delay** (Argon2-style, scrypt-like). ASIC speedup drops 1000× → ~10×. | Medium. Re-implement worker. Hard fork. |
| 3 | **Wesolowski/Pietrzak VDF** (class-group). Verifier work sub-linear, T enforced by the proof. | High. Heavy crypto, library choice, proof verification cost per block. |
| 4 | **zk-VDF** (SNARK-based). Defeats ASIC asymmetry mathematically. | Highest. Likely 6+ months. |

**Recommended.** Option 1 for v1.x, Option 2 for v1.5, Option 4 for v2.

---

### S-010 — Sybil via under-priced MIN_STAKE

**Severity:** High (parameter-tuning risk) • **Status:** Open with mitigation alternative • **Sources:** Audit 2.2, OV-#7, Gemini analysis

**What's open.** `min_stake = 1000` default. If the chain creator under-prices stake relative to the exogenous market value of the token, an attacker partitions wealth across thousands of registered domains and dominates `M_pool`.

**Mitigation alternative present:** rev.9 introduced `InclusionModel::DOMAIN_INCLUSION` where Sybil resistance comes from external naming costs (DNS, registration fees with a TLD operator) instead of stake. STAKE_INCLUSION chains still need to set `min_stake` carefully.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Operator guidance doc** with a calculator: given `block_subsidy`, target attack cost, expected market cap, derive recommended `min_stake`. | Trivial. |
| 2 | **Stake-weighted committee selection** (proportional representation). Genesis → chain spec change. | Medium-high. Fairness analysis required. |
| 3 | **Use DOMAIN_INCLUSION** for any chain that doesn't have strong stake-pricing economics. | Free; just a genesis choice. |

**Recommended.** Options 1 + 3.

---

### S-011 — Abort claim cartel via M-1 quorum

**Severity:** High • **Status:** Open • **Sources:** Audit 2.3

**What's open.** Abort claims advance via M-1 matching signatures. An adversary controlling M-1 committee members can fabricate abort claims against the lone honest member, suspending them via the exponential-suspension path.

**Mitigated by:** stake economics (controlling M-1 is expensive at adequate `min_stake`); equivocation-detection provides separate slashing if the cartel signs blocks at the same height with different digests. So the realistic damage is bounded to "kick the honest member off the committee for a finite number of rounds."

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Status quo + adequate `min_stake` (S-010 #1)** | Free. |
| 2 | **External-witness requirement.** Suspension only triggers if the abort claims are also visible in the gossip mesh outside the committee. | Medium. Gossip-witness tracking. |
| 3 | **Reputation scoring.** Abort claims weighted by claimer's historical good behavior. | High. Reputation systems are notoriously gameable. |

**Recommended.** Option 1. The deeper fixes are not worth their complexity at v1 scale.

---

### S-012 — Snapshot bootstrap is "trust the source"

**Severity:** High (trust boundary, not chain-break) • **Status:** Open • **Sources:** OV-#6 (rev.9 addition)

**What's open.** B6.basic restores state directly from a snapshot file with one sanity check (recomputed `head_hash` must match the snapshot's claimed value). The `accounts`/`stakes`/`registrants` maps aren't cryptographically tied to the head — the receiver trusts the donor's serialization. A malicious donor could ship a snapshot where Alice has 10× her real balance.

**Detection is fast** — first applied block diverges. But the receiver's first-block window is unprotected.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Post-restore consistency check.** Fetch next ~10 blocks from peers and replay; on mismatch, roll back to genesis-replay. | ~50 LOC. |
| 2 | **Multi-source consensus.** Receiver fetches snapshots from N peers, accepts only if M agree on every entry. | Medium. Parallel fetcher. |
| 3 | **State Merkle root in Block.** Each block commits to `SHA256(canonical_state)`. Snapshot includes state; receiver verifies against the root in the snapshot's tail head. v2 protocol change. | High. Block format change → hard fork. Also enables light clients. |

**Recommended.** Option 1 for v1.x. Option 3 for v2.

---

## 5. Medium findings (open)

### S-013 — BlockSigMsg buffer flood OOM

**Severity:** Medium (local DoS) • **Status:** Open • **Sources:** OV-#2, Gemini analysis

**What's open.** `BlockSigMsg` packets that arrive before the local node's delay-hash completes are buffered (we can't verify the signature yet — `block_digest` depends on `delay_output` we haven't computed). An adversary floods the Phase-1 window with millions of valid-shape, fraudulent BlockSigMsgs. Each gets queued. When delay-hash completes, the node verifies the entire bloated buffer; OOM crash before consensus thread can do useful work.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Bounded per-peer queue** (each peer's buffered count ≤ K). | Trivial, ~10 LOC. |
| 2 | **Cheap pre-filter:** reject BlockSigMsgs whose `signer` isn't in current `registry_` (string lookup, no crypto). | Trivial. |
| 3 | **Bounded total queue + LRU eviction.** | Trivial. |

**Recommended.** Options 1+2 together. ~20 LOC.

---

### S-014 — No rate limiting on gossip + RPC

**Severity:** Medium • **Status:** Open • **Sources:** Audit 3.2, OV-#10

**What's open.** Gossip accept loop has no cap; broadcast fan-out amplifies; RPC handle_session is synchronous per connection. Same root issue as S-001 for RPC.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Per-IP token bucket** at the TCP accept layer + per-method bucket at RPC dispatch. | ~50 LOC. |
| 2 | **Concurrent-connection cap** per peer + global. | Subset of #1. |

**Recommended.** Option 1.

---

### S-015 — Delay-worker thread join blocks consensus path

**Severity:** Medium (latency amplification) • **Status:** Open • **Sources:** Audit 3.6

**What's open.** `start_delay_compute` (`node.cpp:490`) does `if (delay_worker_.joinable()) delay_worker_.join();` before spawning the new worker. The previous worker only checks `delay_cancel_` *after* finishing its full T iterations (`node.cpp:497`). If `reset_round` fires during a delay-hash, the join blocks for up to T_delay before the new round can start.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Cooperative cancellation** inside the inner loop: check `delay_cancel_` every N iterations. | Trivial, hot path. ~5 LOC. |
| 2 | **`std::jthread` with stop_token** (C++20). | Medium. Toolchain dependency. |
| 3 | **Detached worker** + atomic flag for completion publishing. | Medium. Lifetime management more delicate. |

**Recommended.** Option 1. Tune the check frequency so it doesn't measurably slow the inner loop.

---

### S-016 — Inbound-receipts pool non-deterministic across committee

**Severity:** Medium (correctness-preserving latency) • **Status:** Open • **Sources:** OV-#5 (rev.9 addition; B3.4 commit message)

**What's open.** Each destination-shard committee member passes their *local* `pending_inbound_receipts_` snapshot to `build_body`. If pools differ momentarily during bundle gossip, members produce different tentative blocks → K-of-K fails → round retries. Documented in B3.4 commit. Not exploitable but adds avoidable latency.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Phase-1 contrib intersection.** Each `ContribMsg` gains `inbound_keys: [(ShardId, Hash)]`. Block bakes only receipts in the intersection of all K members' lists. Block format extends with `creator_inbound_keys[]`. | Medium. ~3-4h. ContribMsg + Block + commitment hash + JSON I/O. |
| 2 | **Time-ordered admission.** Receipts only eligible `>=N` blocks after first observed locally. By then gossip has propagated. | Trivial. Adds latency to every cross-shard transfer. |
| 3 | **Status quo** (round retries until pools converge). | Free. |

**Recommended.** Option 1 for v1.x. Aligns with the existing tx_root mechanism.

---

### S-017 — Producer/chain validation logic mismatch (UNSTAKE)

**Severity:** Medium • **Status:** Open • **Sources:** Audit 3.5, 3.8

**What's open.** `producer.cpp::build_body` filters UNSTAKE on `lk < amount` only. `chain.cpp::apply_transactions` checks `unlock_height` AND refunds the fee if too-early. Validator (`check_transactions`) doesn't check unlock_height at all. So a tx the producer includes can silently fail at apply, with the chain layer doing what should be validator-layer work.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Unify into a shared `validate_tx_apply(...)` helper** called by both producer and validator. Move unlock_height check there. Drop the apply-time refund (fail = no inclusion). | 2-3d. |
| 2 | **Chain layer continues to refund**, but validator gains the unlock_height check too. | 1d. Less invasive but keeps the divergence. |

**Recommended.** Option 1.

---

### S-018 — JSON parsing without schema validation

**Severity:** Medium (cosmetic robustness) • **Status:** Open • **Sources:** Audit 3.3

**What's open.** All `from_json` calls use `j["field"].get<T>()` which throws on missing/wrong-type. Exceptions are caught at the gossip layer. Extra fields silently ignored.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Use `j.value()` everywhere** with sensible defaults. Explicit `j.contains()` checks for required fields. | 2-3d, mechanical. |
| 2 | **JSON Schema validator library** (`nlohmann::json_schema_validator`). | Medium. New dependency. |

**Recommended.** Option 1.

---

### S-019 — Phase-2 timer R-arrival spoofing

**Severity:** Medium (if vulnerability still present) • **Status:** Open, audit-needed • **Sources:** OV-#4, Gemini analysis

**What's open.** The Gemini analysis cites `min(local_delay_done_time, peer_R_arrival_time) + block_sig_ms` as the Phase-2 trigger formula and warns of forged-R injection. The current code may differ — needs an audit pass.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 0 | **Audit first.** Determine whether the formula is still in the consensus event loop. | Free. Required first step. |
| 1 | **Cryptographically pre-validate `R`** before allowing it to influence the timer. | Low. |
| 2 | **Local-clock only.** Drop `peer_R_arrival_time`. Timer = `local_delay_done_time + block_sig_ms`. | Trivial. Loses the latency optimization. |

**Recommended.** Option 0 → Option 1. ~1 day.

---

### S-020 — Rejection sampling O(K²) at K/N → 1

**Severity:** Medium (latency amplification under stress) • **Status:** Open • **Sources:** OV-#3, Gemini analysis

**What's open.** `select_m_creators` uses rejection sampling with a counter. Average cost is O(K) when K << N. After cascading suspensions shrink N toward K, every random pick collides; the inner loop iterates many times per slot. Compounds with S-013 under stress.

**Resolution options.**

| # | Option | Cost |
|---|---|---|
| 1 | **Hybrid Fisher-Yates** when K/N > 0.6; rejection sampling otherwise. | ~30 LOC. |
| 2 | **Always Fisher-Yates.** | Trivial. |

**Recommended.** Option 1 (hybrid). One-evening fix.

---

## 6. Low findings (open)

| ID | Title | Quick fix |
|---|---|---|
| S-021 | Chain file integrity not cryptographically verified | Store + verify a cumulative hash; or keep relying on apply-time validation (current de-facto defense). |
| S-022 | 16 MB message limit too permissive — but snapshots use it | Per-message-type limits: 1 MB for CONTRIB/BLOCK_SIG; 16 MB only for SNAPSHOT_RESPONSE / CHAIN_RESPONSE. |
| S-023 | RPC `send`/`stake` skip balance check | Pre-check balance before queueing. ~1h. |
| S-024 | Deregistration timing predictability (1-10 block grind window) | Acceptable per auditor's own re-classification. v2 could mix in a future block hash. |
| S-025 | `compute_tx_root_intersection` is dead code | Delete it or guard under `#ifdef DHCOIN_INTERSECTION_MODE`. 5 minutes. |
| S-026 | No connection timeout / keepalive | 30s timeout on idle peer connections. Add periodic keepalive. ~1d. |
| S-027 | Info leakage in logs / error messages reveal state | Configurable log levels; redact in production builds. |
| S-028 | Hex parsing only accepts lowercase | `is_anon_address` is canonical; downstream parsers should accept either case. Trivial. |
| S-029 | BFT-mode multi-proposer fork-choice undefined | Status quo (first-seen-wins) + slashing handles it. Heaviest-sig-set tiebreak if needed. |

---

## 7. Mitigated since rev.7 audit baseline

These rev.7-era findings have been addressed in current code. Listed for completeness so a reader of the prior audit knows what's done.

### M-A — Block-level equivocation closed-loop (was Audit 2.4 partial)

**rev.8 added** `EquivocationEvent` (two valid Ed25519 sigs over distinct digests at the same height by the same key) → `pending_equivocation_evidence_` → baked into next block → `apply_transactions` zeroes equivocator's stake AND sets `inactive_from = h+1`. External-submission path via `submit_equivocation` RPC. Verified end-to-end in [`tools/test_equivocation_slashing.sh`](../tools/test_equivocation_slashing.sh).

The narrower ContribMsg-level case is still open as S-006.

### M-B — Hybrid-mode K-of-M liveness gap → BFT escalation (was Audit 2.1)

**rev.8 added** per-height BFT escalation: after `bft_escalation_threshold` (default 5) round-1 aborts at the same height AND `bft_enabled = true`, the next round produces a `consensus_mode = BFT` block requiring `ceil(2K/3)` signatures plus a deterministic `bft_proposer`. The auditor's recommendation ("either disable hybrid mode or implement proper proposer rotation") was implemented as the second option. Verified in [`tools/test_bft_escalation.sh`](../tools/test_bft_escalation.sh).

### M-C — Linear-time sync barrier → snapshot bootstrap (was Gemini "fatal architectural flaw")

**B6.basic added** `Chain::serialize_state` + `restore_from_snapshot` + `dhcoin snapshot {create,inspect,fetch}` + `Config::snapshot_path` for fast-bootstrap. Receiver skips per-block replay; restores state directly. The cryptographic-zero-trust version still requires a state Merkle root in the block format (deferred to v2 — see S-012). Verified in [`tools/test_snapshot_bootstrap.sh`](../tools/test_snapshot_bootstrap.sh).

### M-D — Blind-abort liveness exploit → BFT escalation

The Gemini analysis's headline conclusion — "blind abort = systemic liveness problem; capitalized adversary can stall any specific transaction by burning suspension penalty" — is **substantially mitigated by M-B**. A single blind-aborting adversary can stall a transaction for ~5 rounds, then BFT mode kicks in and the chain proceeds without their signature. The exponential-suspension formula still applies but is no longer the only liveness guarantee.

---

## 8. Auditor-retracted findings (historical)

The rev.7 audit's §5 self-corrected three items:

- **Delay-hash atomicity** — auditor confirmed `delay_cancel_` and `delay_done_` are correctly `std::atomic<bool>`. Retracted. (A related thread-lifecycle issue is now S-015.)
- **Anonymous-account replay protection** — auditor confirmed nonce tracking is uniform across all account types. Retracted.
- **Deregistration timing severity** — auditor downgraded from Medium to LOW (now S-024).

These corrections are accepted; no current code review changed the verdict.

---

## 9. Cheapest path to "production-ready security posture"

If you fix only the items in this cluster, you close the bulk of practical attack surface:

| ID | Title | Cost | Cumulative |
|---|---|---|---|
| S-001 (option 1) | Bind RPC to localhost by default | trivial | 5 min |
| S-003 | Widen timestamp window to ±30s | trivial | 6 min |
| S-005 | Pin `delay_T` in GenesisConfig | 1d | 1d |
| S-002 | Verify sig in `on_tx` | 1-2d | 2-3d |
| S-007 | Saturating add in subsidy distribution | half-day | 2.5-3.5d |
| S-008 (option 1) | Hard cap on mempool size | 1-2d | 3.5-5.5d |
| S-013 | Bounded BlockSigMsg buffer + signer pre-filter | ~20 LOC | 3.5-5.5d |
| S-014 | RPC + gossip rate limiting | ~50 LOC | 3.5-5.5d |
| S-020 | Hybrid Fisher-Yates committee selection | ~30 LOC | 3.5-5.5d |
| S-023 | RPC pre-check balance | ~1h | 3.5-5.5d |
| S-025 | Delete dead `compute_tx_root_intersection` | 5 min | 3.5-5.5d |

**Total: ~4-6 focused days** to take the codebase from "rev.7 audit-flagged" to "high-bar v1 deployable" on every issue except the two genuine v2 protocol-evolution items (S-009 constant-T, S-012 trustless snapshot).

---

## 10. Cross-references

- [`docs/PROTOCOL.md`](PROTOCOL.md) — frozen v1 spec; the source of truth for hash inputs, message formats, consensus rules. Where this doc cites a specification claim, PROTOCOL.md is authoritative.
- [`docs/CLI-REFERENCE.md`](CLI-REFERENCE.md) — operator command surface.
- [`docs/QUICKSTART.md`](QUICKSTART.md) — operator walkthrough.
- The original [rev.7 SECURITY_AUDIT.md](https://) is preserved as historical context but **superseded by this file**. Where the audit and this file disagree, this file wins for current code; the audit wins for rev.7 archaeology.
- [`docs/OPEN-VULNERABILITIES.md`](OPEN-VULNERABILITIES.md) — predecessor of this file, now superseded.

---

## 11. Versioning

This document tracks current state at HEAD. As findings are mitigated, they move from §3-§6 to §7 with a brief note describing the fix. New findings are added with the next available `S-NNN` ID. The triage table in §2 is the canonical entry point for any review.
