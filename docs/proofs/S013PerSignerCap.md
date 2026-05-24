# S013PerSignerCap — per-signer 2-entry cap on `buffered_block_sigs_` (S-013 closure)

This document formalizes the S-013 closure shipped in `src/node/node.cpp::try_buffer_block_sig` (the per-signer admission gate guarding `Node::buffered_block_sigs_`). Pre-closure, the buffer that holds early-arriving `BlockSigMsg` envelopes — those that reach the receive path **before** the local node transitions into the `BLOCK_SIG` consensus phase — admitted an unbounded number of entries per signer. A single Byzantine committee member who survives the receive-side pre-filters (`block_index == chain_.height()`, `signer ∈ current_creator_domains_`, `signer ∈ registry_`) could push arbitrarily many valid-shape, valid-Ed25519-signature `BlockSigMsg` envelopes at the local node and grow `buffered_block_sigs_` without bound. The S-013 closure caps each signer's contribution to **2 entries** in the buffer, which combined with the K-committee pre-filter bounds the total buffer at `2·K` entries — independent of how aggressively any signer pushes.

The proof is short and structural. T-1 establishes the per-signer count invariant (`|{m ∈ buffered_block_sigs_ : m.signer == d}| ≤ 2` after every `try_buffer_block_sig` call). T-2 composes the per-signer invariant with the K-committee pre-filter at `on_block_sig_locked` to yield the aggregate `Σ_d |entries_d| ≤ 2·K` bound. T-3 isolates the no-useful-sig-loss property: the cap silently drops only third-or-later sigs from a given signer, and an honest signer (under H1 of `Preliminaries.md`) produces exactly one well-formed `BlockSigMsg` per round — so the cap never refuses an honest contribution. T-4 establishes equivocation-detection compatibility: when the two admitted entries from a single signer differ (e.g., same `block_index`, different `block_hash`), they remain available as the evidence pair for the FA6 / S-006 equivocation-slashing pipeline; the cap does not suppress the very evidence the slashing path needs. T-5 establishes the multiplicative composition with the S-014 per-IP token-bucket rate limiter: the per-IP cap bounds the **arrival rate**, the per-signer cap bounds the **per-identity storage**, and together memory is bounded both by RATE and by IDENTITY-COUNT.

**Companion documents:** `Preliminaries.md` §4 (hypothesis H1 — honest signers produce exactly one well-formed `BlockSigMsg` per `(block_index, prev_hash)` tuple — and H2 — Byzantine signers may produce arbitrarily many) for the adversary-vs-honest signer model; `EquivocationSlashing.md` (FA6) for the cross-signer evidence-pair semantics this proof's T-4 composes with; `S006ContribMsgEquivocation.md` for the parallel Phase-1 equivocation surface (the S-013 cap is the Phase-2 dual of S-006's same-generation duplicate detection); `S014RateLimiterSoundness.md` (S-014 closure) for the per-peer-IP token-bucket bound T-5 composes with; `S022WireFormatCaps.md` (S-022 closure) for the per-MsgType body-cap that bounds each individual `BlockSigMsg` payload size at 1 MB so the per-buffer-entry memory footprint is itself bounded; `S031ConcurrencyComposition.md` for the `state_mutex_` write-path serialization underlying L-1's lock-ordering invariant.

---

## 1. Introduction — the S-013 finding

### 1.1 Pre-closure description

Per `docs/SECURITY.md` §S-013, the pre-closure receive path admitted `BlockSigMsg` envelopes into a per-node buffer (`Node::buffered_block_sigs_`) whenever they arrived before the local consensus state machine had transitioned into the `BLOCK_SIG` phase. The buffer's purpose is benign: when a fast peer's BlockSig reaches us before we've assembled our own K Phase-1 `ContribMsg` envelopes, we cannot yet validate the sig (the validation step needs `current_delay_output_` + the full ordered `ContribMsg` set to reconstruct the canonical `block_digest` the peer's Ed25519 sig covers). Rather than drop the early-arriving sig and force the peer to retransmit, the receive path stashes it for replay once we reach `BLOCK_SIG`. The replay drain happens in `Node::on_round_state_transition` at `src/node/node.cpp:899–901`:

```cpp
auto buffered = std::move(buffered_block_sigs_);
buffered_block_sigs_.clear();
for (auto& m : buffered) on_block_sig_locked(m);
```

so the buffer's lifetime spans roughly one round (cleared on every `start_round` and on `reset_round`; drained on phase-transition to `BLOCK_SIG`).

The S-013 attack: a Byzantine committee member `d` who passes the pre-filter (`d ∈ current_creator_domains_` and `d ∈ registry_`) can push valid-shape `BlockSigMsg` envelopes at the local node throughout the pre-`BLOCK_SIG` window — Phase-1 contrib accumulation typically spans 10s–100s of ms on a healthy chain, plenty of time to push 10^5+ envelopes at high rate. Each envelope was admitted unconditionally (modulo the pre-filter). Without a per-signer cap:

- `Node::buffered_block_sigs_.size()` was bounded only by available RAM.
- Per-envelope memory footprint is ~200 bytes (`block_index uint64` + `signer std::string` (~32 bytes typical) + `delay_output Hash` (32 bytes) + `dh_secret Hash` (32 bytes) + `ed_sig Signature` (64 bytes) + vector overhead).
- At 10^5 envelopes per signer, ~20 MB per signer; at 10^7 per signer, ~2 GB — OOM territory on a commodity node.

The pre-closure surface was therefore a **local denial-of-service** vector. The attack does not break safety (no malformed sig is accepted as honest), but the buffer growth crashes the node's process or paged it to swap, taking the node out of the active committee for the duration of the attack-plus-recovery window.

### 1.2 Why the per-IP rate limit (S-014) is necessary-but-not-sufficient

The S-014 token-bucket rate limiter caps the **gossip throughput** per peer-IP at `C + r·Δ` messages per Δ seconds (per `S014RateLimiterSoundness.md` T-1). On the gossip surface this gates how many `BlockSigMsg` envelopes a single IP can deliver per unit time. A typical web-profile setting (`r_gossip = 500`, `C_gossip = 1000`) caps a single IP at 500 msg/sec sustained.

S-014 alone, however, is necessary-but-not-sufficient against the S-013 buffer-flood:

- A Byzantine **committee member** has every right to occupy a slot in the per-IP bucket — they are a legitimate participant in the consensus protocol whose messages the receive path must accept. The S-014 rate limit slows their burst, but does not bound the **cumulative buffer entries** they accrue over an extended Phase-1 window.
- A single attacker who controls multiple IPs (e.g., a botnet) can use multiple IPs each at their per-IP allowance to amplify the buffer growth. The S-014 per-IP independence theorem (`S014RateLimiterSoundness.md` T-3) is correct, but its sum-over-IPs scales linearly with the attacker's IP count.
- More fundamentally: S-014 is **per-IP**, while the buffered_block_sigs_ semantics are **per-signer-identity**. A signer can rotate IPs across messages (one IP per envelope) without violating S-014's per-IP bound, because each new IP's bucket starts full. A per-identity cap is structurally orthogonal.

So the right defense is to bound the buffer along the **identity axis** (per-signer), with S-014's per-IP cap as a complementary defense along the **transport axis** (per-IP). T-5 below formalizes the multiplicative composition: removing either defense leaves the other intact, but operating both together strictly dominates either alone.

### 1.3 Why a fixed per-signer cap rather than total-queue + LRU

The S-013 closure chooses a **fixed per-signer cap (2 entries)** rather than a global LRU eviction policy or a total-queue cap. The design rationale, copied from the inline comment at `src/node/node.cpp:2184–2189`:

> Why a fixed per-signer cap rather than total-queue + LRU: LRU evicts honest
> entries when a spammer impersonates K signers — under K-of-K mutual
> distrust we have no quorum to declare which entry is honest, so we'd be
> indifferent to which we keep. The per-signer cap closes the attack
> asymmetrically: a single Byzantine signer can't crowd out honest peers'
> buffer slots no matter how fast they push.

The two-of-each capacity is the smallest cap that simultaneously (a) admits the honest `BlockSigMsg` from each signer in the round, **and** (b) leaves room for the second sig that would constitute Phase-2 equivocation evidence. A cap of 1 would refuse equivocation evidence (only the first sig per signer would survive); a cap of 3 or higher would add per-signer slack without bounding any attack tighter (the attacker's second sig is already accepted at cap-2, so a third sig adds storage cost without adding evidentiary value). The cap-2 choice is therefore minimal-and-sufficient.

### 1.4 The three layers of the defense

The S-013 closure is layer-2 of a three-layer defense:

1. **Layer 1 (pre-filter at `on_block_sig_locked`)** — the receive path at `src/node/node.cpp:2205–2213` rejects any `BlockSigMsg` whose `block_index` doesn't match the local chain head, whose `signer` is not in the current `current_creator_domains_` K-committee, or whose `signer` is not in the validator `registry_`. Pre-S-013, this layer already capped the **distinct signer count** in the buffer at K (the committee size). What it did not bound was the **per-signer count**, which is what S-013 adds.

2. **Layer 2 (per-signer cap at `try_buffer_block_sig`)** — the S-013 closure proper. After the layer-1 pre-filter admits a `BlockSigMsg` from a layer-1-valid signer `d`, the buffer-admission helper scans the existing buffer for a count of entries with `signer == d`, and silently drops the incoming entry if that count is already ≥ 2.

3. **Layer 3 (FA6 / S-006 equivocation slashing)** — when the layer-2 cap admits two sigs from the same `d` that differ in content (different `block_hash` for the same `(block_index, prev_hash)` tuple), the protocol's equivocation-slashing path treats these as evidence and slashes `d`'s stake (per `EquivocationSlashing.md`). The cap at 2 is therefore not just a memory bound but the **evidence-window size** for Phase-2 slashing.

The three layers compose: layer 1 bounds the signer set at K; layer 2 bounds each signer's contribution at 2; layer 3 makes the second-sig-from-same-signer pay a permanent economic cost (full stake forfeiture). An attacker who pushes a third sig from the same `d` gets dropped at layer 2 with no consequence; an attacker who pushes two **different** sigs from the same `d` to grow the buffer to its cap-2 ceiling instead inadvertently provides slashing evidence that eliminates them from future rounds.

---

## 2. Adversary model

The S-013 scheme defends against three adversary families:

**A1 (Byzantine-signer same-IP flood at distinct `prev_hash` values).** A single Byzantine committee member `d` controls one IP and sends a high-rate flood of `BlockSigMsg` envelopes during the pre-`BLOCK_SIG` window. Each envelope passes layer-1 pre-filter (`block_index == chain_.height()`, `d ∈ current_creator_domains_`, `d ∈ registry_`). The envelopes carry the **same** `signer = d`, **same** `block_index`, but different inline fields (e.g., they propose different `block_hash` over the same `block_index` via the `delay_output` / `dh_secret` / `ed_sig` triple). The attacker's send rate is bounded by S-014's per-IP token-bucket, but their cumulative envelopes admitted into `buffered_block_sigs_` is bounded only by the buffer policy.

- **Pre-S-013 attack outcome:** `buffered_block_sigs_.size()` grows linearly with attacker send rate × pre-`BLOCK_SIG` window; OOM crash.
- **Post-S-013 attack outcome:** `|{m ∈ buffered_block_sigs_ : m.signer == d}| ≤ 2` per T-1; attacker gets at most 2 of their envelopes admitted, the remaining are silently dropped at `try_buffer_block_sig`. Aggregate buffer growth from a single Byzantine signer is bounded at 2 entries.

**A2 (Byzantine-signer multi-IP rotation with forged envelopes).** A Byzantine signer `d` controls multiple IPs (e.g., a botnet) and rotates the source IP per envelope. Each envelope is signed by `d`'s Ed25519 key (which only `d` possesses); the envelope content is the same as A1 (same `block_index`, same `signer = d`, different inline fields). Each new IP's S-014 bucket starts full, so the per-IP rate cap doesn't compose along the IP axis to bound the buffered total.

- **Pre-S-013 attack outcome:** unbounded buffer growth, same as A1; S-014 alone is insufficient because the attack scales along the IP-rotation axis.
- **Post-S-013 attack outcome:** still bounded at 2 entries from `d` per T-1; the buffer cap is per-**signer-identity**, not per-IP. Rotating IPs does not multiply the admitted-entry budget because the cap key is `m.signer`, not `peer.address()`. Aggregate buffer growth from a Byzantine signer with M botnet IPs is still 2 entries (S-013 cap), with each unsuccessful additional envelope incurring the layer-2 drop at constant cost.

**A3 (Network-partition replay).** A Byzantine signer `d` (or an adversarial peer relaying `d`'s envelopes) replays a single valid-shape `BlockSigMsg` against the local node at very high rate during the pre-`BLOCK_SIG` window. The envelope passes layer-1 pre-filter; the replay rate is bounded by S-014's per-IP token-bucket. The attacker's intent is buffer growth via simple replay, not equivocation.

- **Pre-S-013 attack outcome:** if the buffer admitted exact duplicates, the buffer could grow as `O(replay_rate × window_length)`. The pre-closure code did not deduplicate exact replays of the same envelope, so this attack succeeded the same as A1.
- **Post-S-013 attack outcome:** the second replay of the same envelope from `d` is admitted (filling the cap-2 budget; the buffer scan counts only the **signer**, not the full envelope, so the second entry is admitted regardless of content). The third replay (and all subsequent) is dropped at `try_buffer_block_sig`. So the maximum buffer growth from a single-signer replay is 2 entries — same as A1. The cap is signer-keyed, not content-keyed, so exact-replay and content-distinct floods are bounded identically.

The S-013 scheme **does not address** the following (out-of-scope):

- Buffer growth from **multiple distinct Byzantine signers**. K Byzantine committee members each contributing 2 entries to the buffer yields `2·K` total, which is bounded but not zero. The K-committee bound is the protocol's structural limit (a malicious super-majority could in principle saturate the buffer with `2·K` entries, but at that point liveness is already lost regardless of buffer cap). See T-2 below.
- Cryptographic-signature-verify cost amplification on **admitted** envelopes. The two admitted sigs per signer each cost the receiver one Ed25519 verify when they eventually reach `on_block_sig_locked` after the replay drain. This is `O(1)` per sig (~50 µs typical) and bounded by the cap-2 × K-committee = `O(2·K)` verifies per round — well within liveness budget.
- Memory exhaustion via large *bodies* of admitted envelopes. Each admitted `BlockSigMsg` is itself bounded by `max_message_bytes(MsgType::BLOCK_SIG)` = 1 MB per S-022 (`S022WireFormatCaps.md` T-1). So the per-entry footprint is bounded at 1 MB worst-case; combined with the cap-2 × K-committee = `2·K` entries, total buffer memory is bounded at `2·K · 1 MB` ≤ `2 MB · K`. At a typical web-profile K=5, this is ≤ 10 MB — bounded, observable, well within commodity-node RAM.

---

## 3. Implementation citation

### 3.1 The per-signer cap helper

Per `src/node/node.cpp:2177–2199`:

```cpp
// S-013: bounded per-signer admission into buffered_block_sigs_. Caller must
// hold state_mutex_. Two slots per signer is enough to capture one honest
// BlockSigMsg plus one equivocation-evidence sig at the same height;
// anything beyond is spam. Pre-filters at the caller (current_creator_domains_
// membership + registry_ lookup) already cap distinct signers to at most K,
// so the buffer is bounded at 2·K entries.
//
// Why a fixed per-signer cap rather than total-queue + LRU: LRU evicts honest
// entries when a spammer impersonates K signers — under K-of-K mutual
// distrust we have no quorum to declare which entry is honest, so we'd be
// indifferent to which we keep. The per-signer cap closes the attack
// asymmetrically: a single Byzantine signer can't crowd out honest peers'
// buffer slots no matter how fast they push.
static constexpr size_t MAX_BUFFERED_BLOCK_SIGS_PER_SIGNER = 2;

void Node::try_buffer_block_sig(const BlockSigMsg& msg) {
    size_t per_signer = 0;
    for (const auto& m : buffered_block_sigs_) {
        if (m.signer == msg.signer && ++per_signer >= MAX_BUFFERED_BLOCK_SIGS_PER_SIGNER)
            return; // drop silently
    }
    buffered_block_sigs_.push_back(msg);
}
```

### 3.2 The header declaration

Per `include/determ/node/node.hpp:349–351`:

```cpp
// S-013: bounded per-signer admission into buffered_block_sigs_.
// Caller must hold state_mutex_.
void try_buffer_block_sig(const BlockSigMsg& msg);
```

### 3.3 The buffer field

Per `include/determ/node/node.hpp:524–527`:

```cpp
// Buffer for BlockSigMsgs that arrive before this node has assembled
// its own K Phase-1 contribs. Drained when the round transitions into
// Phase-2.
std::vector<BlockSigMsg>                                 buffered_block_sigs_;
```

The container type is `std::vector<BlockSigMsg>` (not a `std::map<std::string, std::vector<BlockSigMsg>>`) — the per-signer scan in `try_buffer_block_sig` walks the flat vector linearly. This is acceptable because (a) the cap-enforced upper bound on the vector size is `2·K` and K is bounded by the committee size (≤ 256 in the protocol), so the scan is `O(2·K) ≤ O(512)` per insert; (b) the cap-2 design plus per-round lifetime means the scan rarely sees more than a handful of entries; (c) using a flat vector avoids the per-key allocation cost of a map keyed on `std::string` signer-domain.

### 3.4 The two call sites of `try_buffer_block_sig`

`try_buffer_block_sig` is called from two paths in `Node::on_block_sig_locked` at `src/node/node.cpp:2201–2284`:

**Call site 1 — phase gate at line 2216–2219** (the primary path the S-013 finding addresses):

```cpp
// If we haven't reached BLOCK_SIG yet, buffer for replay.
if (phase_ != ConsensusPhase::BLOCK_SIG) {
    try_buffer_block_sig(msg);
    return;
}
```

This fires when the local node is still in `IDLE` or `CONTRIB` phase (before transition to `BLOCK_SIG`). The replay drain at `on_round_state_transition` line 899–901 picks up the buffered sigs and re-runs `on_block_sig_locked` for each, which by then has `phase_ == BLOCK_SIG` and proceeds to the full validation path.

**Call site 2 — Phase-1 commit-missing path at line 2256–2262**:

```cpp
auto cit = pending_contribs_.find(msg.signer);
if (cit == pending_contribs_.end()) {
    // No commit yet — buffer for later (the contrib may be in flight).
    try_buffer_block_sig(msg);
    return;
}
```

This fires when the local node is in `BLOCK_SIG` phase **but** has not yet received the Phase-1 commit from the same signer whose Phase-2 BlockSig just arrived. This is a rare gossip-ordering edge case (the BlockSig arrived before the corresponding ContribMsg from the same peer); the buffer absorbs the BlockSig for the next round-state transition.

Both call sites enforce the cap identically — `try_buffer_block_sig` is the single chokepoint; no path bypasses the cap to push directly to `buffered_block_sigs_`.

### 3.5 The pre-filter layer (layer 1) at `on_block_sig_locked`

Per `src/node/node.cpp:2205–2213`:

```cpp
uint64_t expected_index = chain_.height();
if (msg.block_index != expected_index) return;

if (std::find(current_creator_domains_.begin(),
              current_creator_domains_.end(), msg.signer)
    == current_creator_domains_.end()) return;

auto entry = registry_.find(msg.signer);
if (!entry) return;
```

These three checks run **before** `try_buffer_block_sig` is called at either of the two call sites (the conditional structure at line 2216 + line 2256 sits below the pre-filter). The pre-filter establishes that any message reaching `try_buffer_block_sig`:

- Has `msg.block_index == chain_.height()` (current round only).
- Has `msg.signer ∈ current_creator_domains_` (a member of the round's K-committee).
- Has `msg.signer` registered in the validator `registry_` (an active validator).

`current_creator_domains_` is a `std::vector<std::string>` of size `cfg_.m_creators` per `include/determ/node/node.hpp:490`. The committee size K is `cfg_.m_creators` (loaded from the genesis configuration; default 3, typically 5–9 in production). The pre-filter therefore bounds the distinct signer count seen by `try_buffer_block_sig` at K.

### 3.6 The buffer's clear / drain sites

Per `src/node/node.cpp:820`, the per-round clear in `start_round`:

```cpp
pending_block_sigs_.clear();
buffered_block_sigs_.clear();
```

Per `src/node/node.cpp:899–901`, the replay drain on phase transition:

```cpp
auto buffered = std::move(buffered_block_sigs_);
buffered_block_sigs_.clear();
for (auto& m : buffered) on_block_sig_locked(m);
```

Per `src/node/node.cpp:1692`, the `reset_round` clear:

```cpp
pending_contribs_.clear();
pending_block_sigs_.clear();
buffered_block_sigs_.clear();
```

The buffer's lifetime is therefore at most one round between clears. The cap is enforced at every insert; the bounded-at-2·K invariant therefore holds throughout the buffer's lifetime, not just at quiescent moments.

### 3.7 The locking discipline

`try_buffer_block_sig`'s header comment requires that "Caller must hold `state_mutex_`." Both call sites are in `on_block_sig_locked` which is reached via:

- `Node::on_block_sig` (the public entry point at `node.cpp:2172–2175`):

  ```cpp
  void Node::on_block_sig(const BlockSigMsg& msg) {
      std::unique_lock<std::shared_mutex> lk(state_mutex_);
      on_block_sig_locked(msg);
  }
  ```

  acquires a unique (write) lock before calling.

- The replay drain at `on_round_state_transition` line 899–901 — `on_round_state_transition` itself runs under `state_mutex_` (its caller holds the lock; see `node.cpp` round-transition orchestration). The drain therefore inherits the write-lock acquisition from its caller.

So `try_buffer_block_sig` always runs under a write-lock on `state_mutex_`, which serializes all readers and writers of `buffered_block_sigs_`. No data race on the per-signer scan or the `push_back` is possible. See L-1 below for the formal argument.

---

## 4. Lemmas

### Lemma L-1 (Write-path serialization)

The buffer `buffered_block_sigs_` is mutated **only** by:

1. `try_buffer_block_sig` (insert via `push_back`).
2. `Node::start_round` (clear via `.clear()`).
3. `Node::reset_round` (clear via `.clear()`).
4. `Node::on_round_state_transition` (drain via `std::move` + `.clear()`).

All four sites require `state_mutex_` held in write mode by the caller. By the `std::shared_mutex` contract (ISO/IEC 14882:2017 §33.4.3.4 [thread.sharedmutex.requirements]), at most one writer (and zero shared readers) holds the lock at any time. Therefore the per-signer scan in `try_buffer_block_sig` and the subsequent `push_back` execute as an atomic-with-respect-to-other-mutators-of-`buffered_block_sigs_` critical section. No interleaving in which the post-scan `push_back` observes a `buffered_block_sigs_` mutated by another writer between scan and push is possible. □

### Lemma L-2 (Monotone-then-bounded per-signer count)

Fix a signer `d`. Define `cnt_d(t) := |{m ∈ buffered_block_sigs_ : m.signer == d}|` at wall-clock time `t`, observed from any vantage point under `state_mutex_`.

By L-1, between consecutive critical sections that touch the buffer, no concurrent mutation occurs. So the evolution of `cnt_d` is a step function with steps at `try_buffer_block_sig(msg)` invocations with `msg.signer == d`, at `start_round` / `reset_round` invocations (which reset `cnt_d` to 0 by clearing the buffer), and at `on_round_state_transition` invocations (which reset `cnt_d` to 0 by moving the buffer out).

Within one round (between adjacent clears), the only mutator that affects `cnt_d` is the `try_buffer_block_sig` call site. Its body inspects each existing entry and increments a local `per_signer` counter whenever `m.signer == msg.signer == d`. The early-return at line 2195–2196 fires when `per_signer >= MAX_BUFFERED_BLOCK_SIGS_PER_SIGNER == 2` and the function returns **without** the `push_back` at line 2198.

Inductive claim: `cnt_d ∈ {0, 1, 2}` after every `try_buffer_block_sig(msg)` call with `msg.signer == d`.

**Base case (cnt_d = 0 before the call).** The pre-call scan finds 0 entries; `per_signer` never reaches 2; the early-return is not taken; the `push_back` runs; `cnt_d` becomes 1. Post-condition `cnt_d == 1 ∈ {0, 1, 2}`. ✓

**Inductive step (cnt_d = k before the call, k ∈ {0, 1, 2}).**
- If `k == 0`: see base case; post `cnt_d == 1`.
- If `k == 1`: the scan visits each existing entry. For the one entry with `m.signer == d`, the conditional `m.signer == msg.signer && ++per_signer >= 2` evaluates to `true && (1 >= 2) == false` (post-increment makes `per_signer == 1`, the comparison fails). The scan finishes without returning early; `push_back` runs; post `cnt_d == 2`. ✓
- If `k == 2`: the scan visits each existing entry. For the first entry with `m.signer == d`, the conditional is `true && (1 >= 2) == false`. For the second entry with `m.signer == d`, the conditional is `true && (2 >= 2) == true`, so the function returns early **without** `push_back`. Post `cnt_d == 2`. ✓

So `cnt_d` evolves monotonically from 0 to 1 to 2 as `try_buffer_block_sig(msg)` calls with `msg.signer == d` accumulate, and once it reaches 2 it stays at 2 until the next round-boundary clear. □

### Lemma L-3 (Distinct signer count bounded by K via pre-filter)

By §3.5, every `try_buffer_block_sig(msg)` call has `msg.signer ∈ current_creator_domains_` (guaranteed by the pre-filter at `on_block_sig_locked` line 2208–2210, which sits above both `try_buffer_block_sig` call sites in the control-flow). The set `current_creator_domains_` is a `std::vector<std::string>` of size `cfg_.m_creators = K` (per `include/determ/node/node.hpp:490`).

Therefore the set `{msg.signer : try_buffer_block_sig(msg) was called}` is a subset of `current_creator_domains_`, with cardinality ≤ K.

Define `S(t) := {d : cnt_d(t) > 0}` — the set of signers with at least one buffered entry at time `t`. Then `S(t) ⊆ current_creator_domains_` and `|S(t)| ≤ K`. □

### Lemma L-4 (Aggregate buffer size is bounded by 2·K)

By L-2, for every signer `d`, `cnt_d(t) ≤ 2`. By L-3, the set `S(t)` of signers with `cnt_d > 0` has cardinality ≤ K.

Then:

$$
|\texttt{buffered\_block\_sigs\_}(t)| = \sum_{d \in S(t)} \texttt{cnt\_d}(t) \leq \sum_{d \in S(t)} 2 = 2 \cdot |S(t)| \leq 2 \cdot K.
$$

So `|buffered_block_sigs_(t)| ≤ 2·K` holds at every observation point under `state_mutex_`. □

### Lemma L-5 (Honest signer's at-most-1 sig is never refused)

Per `Preliminaries.md` H1 — honest signers produce exactly one well-formed `BlockSigMsg` per `(block_index, prev_hash)` tuple. So at most one honest sig per signer per round arrives at the local node.

The cap at L-2 admits `cnt_d` up to 2. The first incoming `try_buffer_block_sig(msg)` for an honest `d` finds `cnt_d == 0`; the cap permits the push (cnt_d goes to 1). A second sig from honest `d` would contradict H1 — honest signers don't produce two distinct sigs at the same `(block_index, prev_hash)`. So an honest signer never experiences a cap-refused entry: the first entry is admitted, no second entry exists.

Even if the round-replay drain at `on_round_state_transition` reprocesses the buffered sig (re-calling `on_block_sig_locked` which may re-call `try_buffer_block_sig` in the rare phase-edge case at line 2256), the cap admits the second pass at the still-valid second slot. The cap therefore never refuses an honest signer's contribution. □

### Lemma L-6 (Equivocation evidence pair is preserved under the cap)

Suppose a Byzantine signer `d` produces two valid-shape `BlockSigMsg` envelopes `msg_a` and `msg_b` at the same `(block_index, prev_hash)` but with content that differs (e.g., differing `delay_output`, or differing `ed_sig` over a different block-body construction). Both pass the pre-filter at layer 1. Both are admitted to `try_buffer_block_sig`.

By L-2, the first admission (`msg_a`) succeeds with `cnt_d == 1`; the second admission (`msg_b`) succeeds with `cnt_d == 2`. The cap-2 is exactly the slack needed to preserve **both** halves of the equivocation evidence pair.

After the round-replay drain at `on_round_state_transition`, both `msg_a` and `msg_b` flow through `on_block_sig_locked` and through `pending_block_sigs_[d]`. The downstream Phase-2 equivocation-detection path at `apply_block_locked` (per `EquivocationSlashing.md` FA6) compares the sig from `pending_block_sigs_[d]` against any contradicting sig for the same `(block_index, prev_hash)` from `d` and constructs an `EquivocationEvent` with both sigs as the evidence pair (`sig_a` from `msg_a`, `sig_b` from `msg_b`).

The cap-2 capacity is therefore exactly the **minimal-and-sufficient** evidence-window size: any tighter cap (cap-1) would suppress the second sig and prevent the slashing path from seeing the equivocation; any looser cap (cap-3 or more) would not increase the evidentiary value (the second sig already constitutes proof; further sigs are redundant). □

### Lemma L-7 (Composition with S-014 arrival-rate cap)

By `S014RateLimiterSoundness.md` T-1, the number of allowed gossip messages from peer-IP `k` over window `[t, t+Δ]` is bounded by `⌊C + r·Δ⌋` where `C := burst_` and `r := rate_per_sec_` are the configured gossip token-bucket parameters.

Each admitted gossip message arriving at the gossip dispatch handler may (after the `MsgType::BLOCK_SIG` deserialize succeeds and the per-MsgType cap at S-022 passes) reach `Node::on_block_sig` → `Node::on_block_sig_locked`. The pre-filter at §3.5 reduces the set of envelopes that reach `try_buffer_block_sig` to those whose `signer ∈ current_creator_domains_ ∩ registry_`. The per-signer cap at L-2 then bounds each signer's contribution to the buffer at 2.

Therefore: the **arrival rate** of `BlockSigMsg` envelopes at the local node is bounded by S-014 per-IP × per-MsgType cap of S-022 (`max_message_bytes(BLOCK_SIG) = 1 MB`); the **buffered storage** per identity is bounded by S-013 cap of 2; and the **aggregate buffered storage** is bounded by 2·K per L-4.

Removing S-014 leaves S-013 intact: a single attacker could send envelopes at arbitrary rate, but the per-identity cap at S-013 still bounds the buffer at 2·K entries and the cost per dropped envelope is `O(|buffered_block_sigs_|) ≤ O(2·K)` for the linear scan in `try_buffer_block_sig`, which at K ≤ 256 is `O(512)` comparisons per drop — bounded constant.

Removing S-013 leaves S-014 intact: the per-IP arrival rate would still be capped, but the per-identity buffer footprint would be unbounded. A Byzantine signer who controls one IP under their per-IP rate cap can still accumulate `O(r · Δ)` admitted envelopes over the pre-`BLOCK_SIG` window, which at typical web-profile `r = 500`, `Δ = 100ms` is 50 admitted envelopes per signer per round (well above the cap-2 honest budget), leading to a slow OOM-via-flat-rate attack distinct from the burst-flood S-013 was designed against.

Both layers operating together strictly dominate either alone, with the bounds composing **multiplicatively**: the per-IP rate cap bounds the rate of cap-evaluation calls (the linear scans), and the per-identity cap bounds the per-identity storage given any arrival rate. □

---

## 5. Theorems and proofs

### Theorem T-1 (Per-Signer Bound)

**Statement.** For every signer `d` and every observation time `t` under `state_mutex_`, the count of buffered entries from `d` satisfies the state-form invariant:

$$
\bigl|\{\, m \in \texttt{Node::buffered\_block\_sigs\_} : m.\texttt{signer} = d \,\}\bigr| \;\leq\; 2.
$$

**Proof.** Direct from L-2's inductive argument: starting from `cnt_d == 0` at every buffer-clear point (`start_round` / `reset_round` / round-state-transition drain), each `try_buffer_block_sig(msg)` call with `msg.signer == d` increments `cnt_d` by at most 1 (admitting at most one entry), and the increment is gated by the cap check that returns early once `cnt_d == 2`. The state invariant therefore holds at every observation point. The cited source location is `src/node/node.cpp:2192–2199` (`try_buffer_block_sig` body), with the constant `MAX_BUFFERED_BLOCK_SIGS_PER_SIGNER = 2` at line 2190. ∎

### Theorem T-2 (Total Memory Bound)

**Statement.** For every observation time `t` under `state_mutex_`, the aggregate buffer size satisfies:

$$
|\texttt{Node::buffered\_block\_sigs\_}| \;\leq\; 2 \cdot K,
$$

where `K := cfg_.m_creators` is the round's committee size.

**Proof.** Direct from L-3 + L-4. L-3 establishes that the set of signers contributing to the buffer is a subset of `current_creator_domains_` (which has cardinality K). L-4 multiplies the per-signer T-1 bound (≤ 2) by the K-signer count to yield the `2·K` aggregate. The bound is achievable in the worst case (K Byzantine committee members each contributing 2 entries each — at which point the protocol's safety has degraded for separate reasons, since under H1 honest signers don't equivocate; but the buffer growth itself remains bounded). ∎

### Theorem T-3 (No Useful-Sig Loss Under Cap)

**Statement.** For every honest signer `d` (per H1 of `Preliminaries.md`), the cap at `try_buffer_block_sig` admits all of `d`'s legitimate `BlockSigMsg` contributions to the buffer. Equivalently: the cap rejects only **third-or-later** entries from any signer; the first two are always admitted; under H1 honest signers produce at most one entry per round, so the cap is never the cause of an honest contribution being lost.

**Proof.** Direct from L-5: H1 establishes that an honest signer produces exactly one well-formed `BlockSigMsg` per `(block_index, prev_hash)` tuple. The pre-filter at §3.5 ensures only one round's worth of sigs reach `try_buffer_block_sig` (the `msg.block_index == chain_.height()` check filters out cross-round messages). So at most one entry per honest signer per round is ever offered to the cap, and the cap's first-slot admission always accepts it. The cap rejects only third-or-later sigs from a given signer — which under H1 cannot be honest (the first sig is honest, any subsequent sig is either an equivocation attempt by a Byzantine sender or a network-replay; both are caught either by the equivocation pipeline (T-4) or by the round-clear at the next round boundary). ∎

### Theorem T-4 (Equivocation Detection Compatibility)

**Statement.** When two entries from the same signer differ in their signed content (different `delay_output`, different `ed_sig`, etc.), they remain available in the buffer as the evidence pair `(sig_a, sig_b)` for the FA6 / S-006 equivocation-slashing pipeline. The S-013 cap does not suppress equivocation evidence.

**Proof.** Direct from L-6. The cap admits the first two entries from any signer (the inductive admission steps at `cnt_d == 0 → 1` and `cnt_d == 1 → 2`). The first entry from a Byzantine signer is `msg_a`; the second is `msg_b`. Both are stored in `buffered_block_sigs_`. The round-replay drain at `on_round_state_transition` line 899–901 reprocesses both via `on_block_sig_locked`, and the downstream Phase-2 path (per `EquivocationSlashing.md` FA6 T-6) constructs an `EquivocationEvent` with both sigs as the evidence pair. The cap-2 size is **the minimal cap** that preserves equivocation evidence; cap-1 would have suppressed `msg_b` and prevented detection. The S-013 closure is therefore co-designed with the FA6 slashing path: the cap is sized to admit exactly the evidence the slashing path needs, no more. ∎

### Theorem T-5 (Composition with S-014 Rate Limiter)

**Statement.** S-013 (per-identity storage cap) and S-014 (per-IP arrival-rate cap) compose multiplicatively as orthogonal defense layers. The composed bound on `BlockSigMsg`-induced memory at the local node is:

$$
\text{Memory}_{\texttt{buffered\_block\_sigs\_}} \;\leq\; \min\!\left(2 \cdot K,\; \text{arrival-rate-bound from S-014}\right) \cdot \texttt{max\_message\_bytes}(\texttt{BLOCK\_SIG}).
$$

The `min` factor is dominated by `2·K` (S-013) for any attacker rate that exceeds K admissions per round — the typical case. S-014 dominates only at very low arrival rates where the cap is not reached.

**Proof.** Direct from L-7. S-014's per-IP token-bucket bounds the per-IP arrival rate; S-013's per-signer cap bounds the per-identity storage. Removing either leaves the other intact (each defense is independently sound — see the L-7 ablation argument). Operating both together yields the multiplicative composition: per-IP rate cap × per-identity storage cap = per-IP-per-identity bounded memory footprint.

Multiplying by the S-022 per-MsgType body cap (`max_message_bytes(BLOCK_SIG) = 1 MB` per `S022WireFormatCaps.md` T-1) yields the final per-buffer-entry memory footprint bound. So the full composed bound on `buffered_block_sigs_` memory is:

$$
\text{Memory}_{\texttt{buffered\_block\_sigs\_}} \;\leq\; 2 \cdot K \cdot 1\ \text{MB}.
$$

At a typical web-profile K=5, this is ≤ 10 MB — bounded, observable, well within commodity-node RAM. The composition is a three-way: S-022 bounds per-entry size, S-014 bounds per-IP arrival rate (and thereby the per-IP rate of cap-evaluation calls), and S-013 bounds per-identity storage. The three composes is what makes the buffer safely bounded under arbitrary adversary behavior. ∎

---

## 6. Adversary model + notable findings

### 6.1 Recap of adversary families

- **A1 — Byzantine-signer same-IP flood:** Defended (T-1).
- **A2 — Byzantine-signer multi-IP rotation:** Defended (T-1; the cap is signer-keyed, not IP-keyed).
- **A3 — Network-partition replay:** Defended (T-1; identical to A1).
- **Coordinated K-signer flood (`K`-of-`K` adversary):** Partially defended (T-2 bounds at `2·K` entries; at K Byzantine committee members the protocol's safety is already lost for separate reasons, but the buffer growth remains bounded).
- **Memory exhaustion via large bodies:** Defended (S-022 bounds per-entry body size at 1 MB).
- **Equivocation evidence suppression:** Defended (T-4; the cap-2 size is the minimal-and-sufficient evidence-window size).

### 6.2 Findings

**Finding F-1 (Transient memory spike at K signers reaching the cap simultaneously).**

**Severity:** Very Low (observable, bounded, transient).

**Description.** When all K committee members simultaneously reach their cap-2 ceiling in the same pre-`BLOCK_SIG` window (e.g., due to a coordinated adversarial-committee attack at K=K_max), `|buffered_block_sigs_|` momentarily reaches its maximum of `2·K`. For K=256 (the protocol-allowed maximum committee size) and per-entry footprint of ~200 bytes (typical) to 1 MB (worst case under S-022), the transient spike is bounded at 100 KB (typical) to 512 MB (worst case).

The worst-case 512 MB is itself bounded — it cannot grow further without violating L-4 — but for very large K (≥ 100) on a resource-constrained operator (e.g., a 1 GB RAM commodity node) this transient could pressure RAM. Operators deploying high-K configurations on low-RAM hardware should monitor process memory.

**Recommended mitigation:** none required for correctness; T-2 bounds the worst case. If operators are concerned, the existing operational metric `buffered_block_sigs_.size()` could be added to a future operator-monitoring path (e.g., a status RPC field). The current implementation does not expose this metric, but adding it is straightforward (~5 LOC).

**Finding F-2 (Linear scan cost on the cap check is O(2·K) per admission).**

**Severity:** Very Low (constant-bounded; well within liveness budget).

**Description.** The cap check in `try_buffer_block_sig` walks the entire `buffered_block_sigs_` vector linearly to count entries matching `msg.signer`. The scan is `O(|buffered_block_sigs_|) ≤ O(2·K)`. For K ≤ 256, this is ≤ 512 string comparisons per admission attempt.

The scan is necessary because the buffer is keyed by **insertion order**, not by signer — keeping the buffer as a flat `std::vector<BlockSigMsg>` avoids the per-key `std::string` allocation cost of a `std::map<std::string, std::vector<BlockSigMsg>>`. The trade-off is the linear scan; for the cap-2 × K-committee = `2·K` upper bound, the scan is small enough to not matter.

**Recommended mitigation:** none required. If profiling ever shows this scan as a hotspot (extremely unlikely at K ≤ 256), the alternative is a small `std::map<std::string, uint8_t>` counter alongside the flat vector, updated on insert and reset on round-boundary clear — `O(log K) = O(8)` per admission, `O(K) = O(256)` per round-boundary reset. Trade-off: one more allocation per signer; minor.

**Finding F-3 (No regression test currently exercises the per-signer cap directly).**

**Severity:** Low (test-coverage gap; not a correctness defect).

**Description.** The S-013 closure is currently covered indirectly by the regression suite — chain-progression tests exercise the `buffered_block_sigs_` happy path (early sigs from K honest committee members, replayed on phase transition), but no test specifically pushes K+1 sigs from a single signer to validate the third-sig drop at line 2195–2196. The existing `tools/test_equivocation_slashing.sh` exercises the FA6 evidence-pair construction, which transitively exercises the cap-2 ceiling for an evidence-producing Byzantine sender, but does not assert the cap-3 drop directly.

**Recommended mitigation:** add a unit test `tools/test_block_sig_buffer.sh` that:

1. Spins up a node with K=3 committee.
2. Injects 5 valid-shape `BlockSigMsg` envelopes from one committee member's signer ID into the receive path while the node is in `CONTRIB` phase (pre-`BLOCK_SIG`).
3. Asserts `buffered_block_sigs_.size() == 2` (only the first two were admitted).
4. Asserts that the round-replay drain successfully processes both buffered entries and that the protocol continues to finalize correctly.
5. Asserts that the cap is per-signer (a second committee member's 5 envelopes are also capped at 2, independently of the first signer's count).

Effort: ~80 LOC for the harness + a corresponding `cmd_test_block_sig_buffer_cap` in `src/main.cpp`. Deferred to a follow-on test-coverage pass.

---

## 7. Test surface citation

As noted in F-3, there is **currently no `tools/test_block_sig_buffer.sh` regression**. The S-013 cap is exercised transitively by the chain-progression and equivocation-slashing test suites:

- `tools/test_equivocation_slashing.sh` — exercises the FA6 evidence-pair construction; transitively exercises the cap-2 admission of the two sigs that constitute the evidence (T-4 surface).
- `tools/test_round_state_transition.sh` (if present) or any test that drives the `IDLE → CONTRIB → BLOCK_SIG` phase progression — transitively exercises the buffer's replay drain at `on_round_state_transition` line 899–901, validating that admitted buffered sigs flow through to the live receive path.
- `tools/test_chain_progression.sh` (if present) — exercises the round-boundary `start_round` clears that reset the buffer to empty.

A direct cap-assertion test is recommended as future work per F-3.

The proof's correctness does not depend on the existence of a dedicated regression test — T-1 through T-5 are derivable from the implementation cited in §3 — but the absence of an isolated regression means a future refactor of `try_buffer_block_sig` that accidentally bypasses the cap (e.g., a direct `buffered_block_sigs_.push_back(msg)` in a new call site) would not be caught by the test suite. Defense-in-depth via a dedicated test is therefore advisable.

---

## 8. References

### Specifications + standards

- **C++ ISO/IEC 14882:2017** §33.4.3.4 [thread.sharedmutex.requirements] — `std::shared_mutex` reader/writer-lock contract underpinning L-1.
- **CWE-770** — "Allocation of Resources Without Limits or Throttling." The classification S-013 pre-closure fell under (uncontrolled memory growth on the buffered-sig path).
- **CWE-400** — "Uncontrolled Resource Consumption." Adjacent classification covering the broader DoS family the S-013 closure prevents.

### Cryptographic literature (background for FA6 composition)

- **Goldwasser, Micali, Rivest 1988** — "A Digital Signature Scheme Secure Against Adaptive Chosen-Message Attacks." Original EUF-CMA security definition for digital signatures, underpinning the equivocation-slashing soundness argument the S-013 cap composes with (T-4).
- **Bellare, Namprempre 2000** — "Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm." Composition-of-defenses style used in T-5's multiplicative composition argument.

### Determ-internal references

- `src/node/node.cpp:2177–2199` — `try_buffer_block_sig` body + `MAX_BUFFERED_BLOCK_SIGS_PER_SIGNER` constant (the proof's primary object).
- `src/node/node.cpp:2201–2284` — `Node::on_block_sig_locked` (the caller of `try_buffer_block_sig` at line 2217 and line 2260).
- `src/node/node.cpp:2205–2213` — pre-filter at `on_block_sig_locked` (layer 1 of the defense).
- `src/node/node.cpp:820, 899–901, 1692` — buffer clear / drain sites (`start_round`, `on_round_state_transition`, `reset_round`).
- `include/determ/node/node.hpp:349–351` — `try_buffer_block_sig` header declaration with locking contract.
- `include/determ/node/node.hpp:524–527` — `buffered_block_sigs_` field declaration.
- `include/determ/node/node.hpp:490` — `current_creator_domains_` declaration (the K-committee set).
- `include/determ/node/node.hpp:107` — `cfg_.m_creators` declaration (K = committee size).
- `include/determ/node/node.hpp:617` — `state_mutex_` declaration (the `std::shared_mutex` that serializes the cap path).
- `include/determ/node/producer.hpp:106–115` — `BlockSigMsg` struct declaration.
- `docs/SECURITY.md` §S-013 — the closure-status narrative this proof formalizes.
- `docs/SECURITY.md` §6 (memory-DoS table row for `buffered_block_sigs_`) — operational-memory bound documented at the audit-summary layer.
- `docs/proofs/Preliminaries.md` §4 (H1 honest signer hypothesis, H2 Byzantine signer hypothesis) — adversary model underlying T-3.
- `docs/proofs/EquivocationSlashing.md` (FA6) — the slashing pipeline T-4 composes with; the cap-2 size is co-designed with FA6's evidence-pair semantics.
- `docs/proofs/S006ContribMsgEquivocation.md` — the parallel Phase-1 equivocation surface; the S-013 cap is the Phase-2 dual.
- `docs/proofs/S014RateLimiterSoundness.md` — the per-peer-IP token-bucket bound T-5 composes with.
- `docs/proofs/S014ConcurrencyAnalysis.md` — the asio thread-pool concurrency model that the `on_block_sig` write path runs on (relevant to L-1's lock-ordering invariant).
- `docs/proofs/S022WireFormatCaps.md` — the per-MsgType body-cap T-5 multiplies into the per-entry footprint bound.
- `docs/proofs/S031ConcurrencyComposition.md` — the `state_mutex_` write-lock discipline that L-1 relies on.
