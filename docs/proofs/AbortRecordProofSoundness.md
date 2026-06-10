# AbortRecordProofSoundness — trust-minimized `b:`-namespace abort-record read soundness (`determ-light verify-abort-record`)

This document formalizes the security of the **trust-minimized abort-record read**: the `determ-light verify-abort-record --domain <D>` command lets an operator learn a node's `(count, last_block)` Phase-1 abort record from a *single untrusted daemon* and verify it locally against a committee-attested `state_root`, so that even a Byzantine daemon can neither inflate nor launder a node's abort history without detection. The read targets the `b:` (abort_records, the S-032 cache) namespace of the S-033 state-commitment surface — the trust-minimized complement to the daemon-trusting `operator_slashing_ledger.sh` for auditing committee instability and suspension slashing.

The trust posture is structural, not cryptographic: like the `s:` stake read (`StakeProofSoundness.md`), the command composes existing primitives — the committee's Ed25519 signature set binds `state_root` to the operator's pinned chain via the successor-block `prev_hash` chain (the S-042 `committee_bound_state_root` binding, `StateRootAnchorSoundness.md` SR-1), the sorted-leaves Merkle inclusion proof binds a single `b:` leaf to that root, and a local recompute of `SHA256(u64_be(count) ‖ u64_be(last_block))` hash-binds the daemon's human-readable `abort_records` cleartext to the proven leaf — into an end-to-end pipeline under a malicious-daemon adversary. No new cryptographic primitive is introduced. The claim is that an honest light client never **acts on** a `(count, last_block)` pair that is inconsistent with the genesis-pinned chain's `b:` leaf for the queried domain. Two properties distinguish this reader within the family and get their own theorems: the **key-bind** (AB-1 — the proof must be for *exactly* `"b:" + D`, the F-6 forge-class defense), and the **negative footing** (AB-3 — `NOT-RECORDED` is a daemon-asserted negative under (H-neg), per `NegativeVerdictSoundness.md`, never re-derived here).

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage resistance §2.1, **A3** = SHA-256 preimage §2.1) — this proof reduces to **A1** and **A2** only; `StakeProofSoundness.md` (the `s:` sibling and structural template — its SP-1/SP-2/SP-3 decomposition is mirrored here as AB-1's two binds + the inherited S-040 closure); `MerkleTreeSoundness.md` (MT-1 determinism, MT-3 collision-resistance inheritance, MT-4 inclusion-proof soundness — the cryptographic core AB-1's Merkle leg consumes; MT-5 positive-membership-only — the reason AB-3's negative is not cryptographic; §6.2 S-040 CLOSED — `leaf_count` bound into the committed root via the root-wrapper); `StateRootAnchorSoundness.md` (F6 — **SR-1** is exactly the committee-anchoring this reader routes through via `committee_bound_state_root`, plus SR-2 genesis-binding and SR-3 height-binding inherited for the walk); `WaitHoldAndWaitSoundness.md` (FB64 — the `--wait` seconds this command forwards into the binding is proven soundness-neutral there; AB-4 cites it, does not re-prove it); `NegativeVerdictSoundness.md` (**NV-2/NV-3** — the `b:` `NOT-RECORDED` is one of the eight state-proof daemon-asserted negatives that proof covers, footed on **(H-neg)**; **NV-4** — the no-negative-to-positive confinement AB-3 invokes; **NV-5/NV-5a** — the substring-matcher caveat and canonical-key locality); `S033StateRootNamespaceCoverage.md` (the 10-namespace coverage theorem — its table fixes the `b:` key + value-hash encoding); `LightClientThreatModel.md` (the malicious-daemon adversary `A_daemon`, T-L1 genesis anchor, T-L2 committee-sig head trust, T-L3 state-proof correctness, L-6 fail-closed exit); `docs/SECURITY.md` §S-032 (the abort_records cache) + §S-033 / §S-038 / §S-040 / §S-042 closure narratives; `docs/PROTOCOL.md` §4.1.1 (`b:` Merkle-leaf row) + §10.2 (`state_proof` RPC contract).

---

## 1. Scope

### 1.1 In scope

The `determ-light verify-abort-record --rpc-port P --genesis G --domain D [--json] [--resume] [--state F] [--wait N]` composite command, `light/main.cpp::cmd_verify_abort_record` (`light/main.cpp:2176-2380`, dispatched at `:7534`), which executes:

1. **Genesis anchor + committee-verified header walk** — `anchored_head(rpc, committee_seed, genesis, resume, state_path)` (`light/trustless_read.cpp:278-333`): always re-pins genesis via `anchor_genesis` (`:288`), then either a full `verify_chain_to_head` from block 0 (`:331`) or, with `--resume`, only the suffix above a cached anchor (fail-closed on a fork below the anchor). (T-L1 + T-L2.) An empty `vc.head_state_root` throws the "chain has not activated state_root (S-033)" diagnostic (`light/main.cpp:2215-2219`).
2. **`b:` state-proof fetch** — `rpc.call("state_proof", {{"namespace","b"},{"key",domain}})` (`light/main.cpp:2224-2225`). The daemon's `Node::rpc_state_proof` (`src/node/node.cpp:3363-3454`) serves the simple-namespace key shape `"b:" + key` (`:3390-3398`) and returns `(key_bytes, value_hash, target_index, leaf_count, proof, state_root, height)` in **one** JSON envelope (`:3443-3453`), computed under the daemon's `state_mutex_` read lock (`:3365`). An absent key returns `{"error":"not_found"}` (`:3434-3437`, from `Chain::state_proof`'s `nullopt` at `src/chain/chain.cpp:449`).
3. **Absence dispatch** — a `not_found`-marked error reply (substring matcher `err.find("not_found")`, `light/main.cpp:2229`) yields the `NOT-RECORDED` verdict (`:2234-2252`), tagged `negative_footing = "daemon_asserted"` in `--json` (the JSON initializer-list emission, `:2238-2244`, field at `:2243`), and **returns at `:2251` before any binding step runs**. Any other error throws (`:2230-2231`, fail-closed).
4. **Key-bind (step 3a)** — `proof.key_bytes` must equal, byte-for-byte, the hex of the locally-built canonical key `"b:" ‖ D` (`light/main.cpp:2254-2277`; mismatch throws at `:2271-2276`). This is the F-6-pattern bind (`NegativeVerdictSoundness.md` F-6): without it a Byzantine daemon could serve a valid proof for *some other* `b:` leaf and lie consistently in the cleartext, attributing an arbitrary committed `(count, last_block)` to `D` (§8, AB-F1).
5. **Merkle self-consistency** — `verify_state_proof(proof, {})` (`light/verify.cpp:330-394`), delegating to `crypto::merkle_verify` (`src/crypto/merkle.cpp:131-161`), which re-derives the leaf hash from the (now key-bound) `key_bytes` + `value_hash`, walks the sibling chain, and re-applies the S-040 root-wrapper with the caller-supplied `leaf_count` (`:158-161`) before comparing to the proof's claimed root.
6. **Committee anchoring of the claimed root (S-042)** — a stale-state gate (`proof_height < vc.height` throws, `light/main.cpp:2289-2294`), then `committee_bound_state_root(rpc, committee_json, anchor_index = proof_height − 1, wait_seconds)` (`:2302-2304`; helper at `light/trustless_read.cpp:335-437`): fetch the FULL block at the anchor index, recompute its `block_hash` locally, fetch + committee-sig-verify the successor header at index `proof_height` (`:408-415`), and require `successor.prev_hash == recomputed block_hash` (`:417-432`). The attested root must equal `proof.state_root` byte-for-byte or the command throws the SECURITY diagnostic (`light/main.cpp:2305-2310`). The `--wait` seconds forward only into this helper's hold-and-wait loop (`light/trustless_read.cpp:383-387`; FB64).
7. **Cleartext hash-bind** — fetch the daemon's `abort_records` cleartext (`light/main.cpp:2318-2322`; served by `Node::rpc_abort_records`, `src/node/node.cpp:2592-2621`), scan for `D` (`:2323-2332`); a proof-present-but-cleartext-absent reply throws `INCONSISTENT` (`:2333-2338`); otherwise recompute `SHA256(u64_be(count) ‖ u64_be(last_block))` (`:2340-2343`) and require equality with the proven `value_hash` or throw `TAMPERED` (`:2346-2355`). Only then is `RECORDED count=<c> last_block=<l>` emitted (`:2357-2374`). Every throw propagates to a non-zero exit (`:2376-2379`, L-6).

### 1.2 The `b:` leaf encoding (read off source)

From `Chain::build_state_leaves` (`src/chain/chain.cpp:342-348`):

```cpp
// abort_records_  (S-032 cache)
for (auto& [domain, ar] : abort_records_) {
    crypto::SHA256Builder b;
    b.append(ar.count);
    b.append(ar.last_block);
    leaves.push_back({k_with_prefix("b:", domain), hash_bytes(b)});
}
```

so for an abort record at `domain`:

$$
\text{key}_b(D) \;=\; \texttt{"b:"} \,\|\, D, \qquad
\text{value\_hash}_b(D) \;=\; H\big(\,u64\_be(\texttt{count}) \,\|\, u64\_be(\texttt{last\_block})\,\big),
$$

with `SHA256Builder::append(uint64_t)` serializing big-endian (`src/crypto/sha256.cpp:30-34`). The light client's recompute at `light/main.cpp:2340-2343` invokes the *same* `append(uint64_t)` overloads in the same order, so the two encodings are identical by construction, not by convention. This is the `b:` row of `PROTOCOL.md` §4.1.1.

**Population semantics (the AB-4 boundary).** A `b:` leaf exists for `D` iff `D` has at least one applied **Phase-1** abort: the only increment site is the apply-time loop over `b.abort_events` (`src/chain/chain.cpp:1307-1328`), which `continue`s past every event with `ae.round != 1` (`:1314`) and then bumps `abort_records_[ae.aborting_node].count` and sets `last_block = b.index` (`:1318-1320`). The serving comment on `Node::rpc_abort_records` states the same boundary explicitly: the cache is "incremented at apply time for every Phase-1 AbortEvent baked into a finalized block. Phase-2 aborts (timing-skew on healthy creators) are NOT tracked here" (`src/node/node.cpp:2582-2591`).

### 1.3 Out of scope (inherited)

- **Non-membership.** The sorted-leaves tree supports positive membership only (MT-5); `NOT-RECORDED` on `not_found` is the daemon-asserted negative AB-3 characterizes — it is **not** a proof of absence. This document defers entirely to `NegativeVerdictSoundness.md` (NV-2/NV-3) for that analysis.
- **Stale-state lies across invocations, multi-peer redundancy, transport encryption, RPC auth, genesis-only committee map.** Inherited verbatim from `LightClientThreatModel.md` §6. Within one invocation the stale-height gate + S-042 binding are sound.
- **How the record got there** — the FA5 abort mechanism, the suspension-slash economics (`chain.cpp:1321-1327`), and snapshot restore of the cache are apply-layer / S-032 / S-037-class concerns; this proof reads the *committed* `b:` leaf and does not re-prove its provenance.

---

## 2. Threat model and adversary

The adversary is `A_daemon` (`LightClientThreatModel.md` §2.1): the single RPC endpoint is fully adversary-controlled and may return arbitrary JSON (forged headers, forged proofs, forged `abort_records` cleartexts, mislabeled errors), drop or stall requests, and adapt across calls. Out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis`.

**Security goal.** Under `A_daemon`, an honest light client running `verify-abort-record --domain D` never acts on a `RECORDED (count, last_block)` pair inconsistent with the genesis-pinned chain's `b:` leaf for `D` at the verified height — and a forged `NOT-RECORDED` (which `A_daemon` *can* produce, AB-3) is never escalatable to a false `RECORDED`. "Acts on" means displays as authoritative or feeds a downstream decision (e.g., a slashing audit clearing or penalizing a node on its abort history). The negation form is fail-closed exit (L-6).

---

## 3. Verification primitives reused

The command reuses the family's four primitives unchanged — genesis anchor, committee-sig verify, header continuity (all inside `anchored_head`), and Merkle state-proof verify — plus the shared S-042 anchoring helper `committee_bound_state_root` that `verify-state-root`, `verify-registrant`, and the other binding consumers also route through. The only `b:`-specific elements are the namespace argument, the canonical-key construction `"b:" ‖ D`, and the `(count, last_block)` value-hash decode. Anchoring style note: this is the IDENTICAL S-042 anchoring `read_account_trustless` and `read_stake_trustless` use (stale-height gate, then `committee_bound_state_root` at `anchor_index = proof_height − 1` — `light/trustless_read.cpp:500-520` and `read_stake_trustless`'s equivalent gate + bind in `light/main.cpp`); all three discharge the same SR-1 obligation through the same helper. Since `rpc_state_proof` reports `height = chain_.height()` (the block count) and the live `compute_state_root()` (`node.cpp:3451-3452`), the block at index `proof_height − 1` is the head whose S-033/S-038-populated `state_root` field equals the proof's root on an honest chain; when that anchor is still the chain head, its successor does not exist yet and the binding fails closed immediately or holds-and-waits under `--wait` (FB64).

---

## 4. Security theorems

Throughout, let `D` be the queried domain, `R := state_root` at the anchor height, `n := leaf_count` of the tree `R` commits to, `K` the committee size, and `(count_T, last_T)` the true abort pair for `D` in the chain's committed state (true leaf value-hash `H(u64_be(count_T) ‖ u64_be(last_T))`).

### 4.1 Theorem AB-1 (key-bind + committee anchor: RECORDED is about the right leaf under the right root)

**Statement.** Under (A1) + (A2), in the S-033-active regime, if `verify-abort-record --domain D` emits `RECORDED`, then the Merkle-verified leaf is (i) the leaf with key **exactly** `"b:" ‖ D`, and (ii) committed under a `state_root` equal to the genuine committee-attested root of the operator's pinned chain at the anchor index, except with probability `≤ K·2⁻¹²⁸ + 2⁻¹²⁸ + log₂(n)·2⁻¹²⁸` per invocation.

**Proof.**

*(i) Key-bind.* `verify_state_proof` Merkle-verifies whatever `key_bytes` the daemon supplies — the leaf hash is recomputed over the served key (`light/verify.cpp:349-350`, `:378-380`), so a valid proof for a *different* `b:` leaf would pass the Merkle leg. Step 3a forecloses this: the verifier builds `"b:" ‖ D` locally from its own `--domain` argument (`light/main.cpp:2265-2268`) and requires `proof.key_bytes` to equal its hex byte-for-byte (`:2271`), throwing otherwise (`:2272-2276`). The daemon therefore has exactly two options: serve `key_bytes = "b:" ‖ D` (the canonical key — the bind passes and the Merkle leg now verifies a leaf hash incorporating that key), or fail closed. To pass the Merkle leg with the canonical key but a wrong `value_hash`, the daemon must make a forged leaf hash chain to the anchored root — an MT-4 extraction yields a SHA-256 collision, `≤ log₂(n)·2⁻¹²⁸` (A2). Namespace separation (the `"b:"` prefix is byte 0 of the KEY, which `merkle_leaf_hash` binds into the leaf preimage after the `0x00` domain tag and the `be_u32(key_len)` length prefix — `src/crypto/merkle.cpp:42-51`) prevents any cross-namespace masquerade for the same reason (`MerkleTreeSoundness.md` MT-2). The S-040 root-wrapper re-application inside `merkle_verify` (`src/crypto/merkle.cpp:158-161`) makes a forged `leaf_count` equally a collision, so the single-envelope sourcing of `leaf_count` is not load-bearing (the SP-3 closure, inherited).

*(ii) Committee anchor.* The root the Merkle leg verified against is the proof's *claimed* `state_root` — daemon-supplied until step 5 anchors it. The stale-height gate (`proof_height < vc.height` throws, `light/main.cpp:2289-2294`) pins the proof at or above the committee-verified head. `committee_bound_state_root` then performs the SR-1 binding at `anchor_index = proof_height − 1`: it recomputes `block_hash(anchor)` from the full served body (`light/trustless_read.cpp:356-364`), committee-sig-verifies the successor header at index `proof_height` against the genesis-seeded committee (`:408-415`), and requires `successor.prev_hash == recomputed block_hash(anchor)` (`:417-432`). By the SR-1 case split (`StateRootAnchorSoundness.md` §4.1, not re-derived here): a daemon that swapped the anchor's `state_root` field — which sits inside `signing_bytes(anchor)` and hence inside `block_hash(anchor)` — either keeps `block_hash(anchor)` unchanged (a SHA-256 collision, `≤ 2⁻¹²⁸`, A2) or changes it and must then exhibit `required ≤ K` committee signatures over a successor digest containing the new `prev_hash` (an Ed25519 forgery per member, `≤ K·2⁻¹²⁸`, A1). The command finally requires `attested == proof.state_root` byte-for-byte (`light/main.cpp:2305-2310`). Genesis- and height-binding of the walk itself (that the verified chain is the operator's pinned chain) are SR-2 + SR-3 + T-L1, inherited via `anchored_head`. Union bound over (i) + (ii) gives the statement.   ∎

### 4.2 Theorem AB-2 (cleartext hash-bind: the daemon cannot serve an honest proof and lie in the cleartext)

**Statement.** Under (A2), given AB-1's bound leaf, a `RECORDED` verdict reports `(count, last_block) = (count_T, last_T)`, except with probability `≤ 2⁻¹²⁸`. Specifically: a daemon serving the honest proof for `"b:" ‖ D` while lying in the `abort_records` cleartext is caught fail-closed by one of two gates.

**Proof.** The proof's `value_hash` is, by AB-1, the genuine committed `H(u64_be(count_T) ‖ u64_be(last_T))`. The verifier never trusts the cleartext: it recomputes `H(u64_be(count_A) ‖ u64_be(last_A))` over the daemon-asserted pair using the same big-endian `append(uint64_t)` serialization as the committed leaf (§1.2 — `light/main.cpp:2340-2343` vs `src/chain/chain.cpp:344-346`, both via `src/crypto/sha256.cpp:30-34`) and requires equality with the proven `value_hash` (`:2346`). If `(count_A, last_A) ≠ (count_T, last_T)`, the two 16-byte preimages are distinct (the encoding is injective: two fixed-width fields), so hash equality is a SHA-256 collision, `≤ 2⁻¹²⁸` (A2); otherwise the `TAMPERED` throw fires (`:2347-2355`). The complementary lie — proof present but the cleartext *omits* `D` entirely — is caught by the `INCONSISTENT` gate (`:2333-2338`): the verifier holds a committee-anchored proof that the leaf is committed, so an omitting cleartext is self-evidently a lie about one of the two surfaces, and the command throws rather than guessing. Both gates are fail-closed (non-zero exit, no verdict).

**The conjunction with AB-1 is essential (the F-6 lesson).** The value-hash bind alone proves the cleartext matches *the served leaf*; only the key-bind proves the served leaf is *`D`'s*. Pre-key-bind, a daemon could serve another node's genuine `b:` leaf plus a cleartext row `{domain: D, count: count_other, last_block: last_other}` — both gates pass, and `D` is attributed another node's record (e.g., laundering a heavily-aborted node behind a clean node's history, or smearing a clean node with an abuser's count). Single-leaf readers need BOTH binds; auditing one misses the other (`NegativeVerdictSoundness.md` F-6; finding AB-F1).   ∎

### 4.3 Theorem AB-3 (negative footing: NOT-RECORDED is daemon-asserted, confined, and tagged)

**Statement.** The `NOT-RECORDED` verdict is a **daemon-asserted negative**: it is sound iff the single-daemon negative-honesty premise **(H-neg)** holds, exactly per `NegativeVerdictSoundness.md` NV-2/NV-3 — `A_daemon` forges it unconditionally (probability 1, no broken assumption) by replying `not_found` for a genuinely-committed key. It is (a) machine-tagged, (b) key-local, and (c) never escalatable to a false `RECORDED`.

**Proof.** This proof *agrees with and cites* NV-2/NV-3 rather than re-deriving them: `verify-abort-record` is the `b:` row of that proof's eight-command state-proof regime, and every binding check of AB-1/AB-2 lives strictly *after* the absence dispatch — the `not_found` branch returns at `light/main.cpp:2251` before steps 3a/4/5/6 run, so none of the positive-path cryptography has any purchase on the negative (NV-2's bypass argument, verbatim). The three local properties:

(a) **Tagged.** The `--json` emission carries `"negative_footing": "daemon_asserted"` in the JSON initializer-list form (`:2238-2244`, field at `:2243`) — the machine-readable NV-6 clause-(3) marker (F-2 census: the one initializer-list-form emission among the family's ten); the non-JSON text says "daemon-asserted absence" (`:2247-2249`). A downstream consumer MUST treat it as "no membership proof obtained," never as authoritative absence (NV-6).

(b) **Key-local (NV-5a).** The query key is built locally from `--domain` verbatim (`:2224-2225`); the daemon has no input into *which* key the negative concerns. Node domains are exact byte-string identities on-chain, so no normalization applies (contrast the `a:`/`s:` anon-address canonicalization); a case-variant query names a genuinely different (typically absent) key and the verdict output echoes the exact string asked about (§8, AB-F3).

(c) **Confined (NV-4).** `count` and `last_block` are populated **only** inside the fully-bound positive branch (`:2323-2332`, reachable only after the key-bind, Merkle leg, and committee anchor all pass); the negative branch hard-codes `count: 0` with verdict `NOT-RECORDED` and returns. A forged negative therefore yields at worst a withheld answer (the fail-safe direction), never a fabricated `RECORDED` — to produce a false positive the daemon must forge a positive proof, which is AB-1/AB-2 (A1/A2-infeasible).

One NV-5 caveat carries over verbatim: the absence matcher is a **substring** test (`err.find("not_found")`, `:2229`) over the dumped daemon-chosen error string. This grants `A_daemon` no power it lacks under NV-2 (it could always reply a clean `not_found`), but an honest-but-buggy daemon emitting a composite error containing that token would be misread as absence (§8, AB-F2). Every non-`not_found` error throws (`:2230-2231`) — fail-closed, NV-5.   ∎

### 4.4 Theorem AB-4 (honest semantic boundary: what RECORDED means, and `--wait` neutrality)

**Statement.** On an honest chain, the verified `(count, last_block)` means exactly: `count` applied **FA5 Phase-1** (round = 1) AbortEvents attributed to `D` over the whole chain history as of the committee-verified anchor height, with `last_block` the index of the most recent block carrying one. It does **not** count Phase-2 timing-skew aborts, and `NOT-RECORDED` — even under (H-neg) — means only "no Phase-1 abort record," not "never misbehaved." The `--wait` flag changes none of this.

**Proof.** *Semantics.* The committed value is whatever `abort_records_` holds at root-computation time, and that map has a single increment site: the apply-time loop `for (auto& ae : b.abort_events) { if (ae.round != 1) continue; … ar.count++; ar.last_block = b.index; }` (`src/chain/chain.cpp:1313-1320`), inside the suspension-slashing block whose own comment fixes the policy ("Only Phase-1 aborts count … Phase-2 timing-skew aborts on healthy creators are not economically punished," `:1307-1312`). The serving RPC's comment restates it for the cleartext surface (`src/node/node.cpp:2588-2591`). So the leaf AB-1/AB-2 verify is, by construction, a Phase-1-only accumulator; Phase-2 aborts and equivocation events (a separate channel, FA6) are invisible to this namespace. The as-of point is the anchor height AB-1(ii) binds — the stale-height gate guarantees it is not below the verified head, so the answer is current to within the single-invocation race window the family accepts.

*`--wait` neutrality.* `wait_seconds` is parsed at `light/main.cpp:2190-2191` and forwarded **only** into `committee_bound_state_root` (`:2303-2304`), whose hold-and-wait loop (`light/trustless_read.cpp:383-387`) is the sole `max_wait_seconds`-dependent control flow. The proof envelope is captured at step 3, *before* the wait, and is never re-fetched; the wait only polls for the committee-signed successor that the head-anchor case lacks, and every post-loop check (successor sig verify, `prev_hash` binding) is identical for all wait values. FB64 (`WaitHoldAndWaitSoundness.md` WH-1..WH-6) proves this delta soundness-empty; with `--wait 0` (default) the head case fails closed immediately.   ∎

### 4.5 Corollary AB-E (end-to-end composition)

Under A1 + A2, `verify-abort-record --domain D` emits `RECORDED (count, last_block)` only for the genuine committed `b:` leaf of `D` under a committee-attested root anchored to the operator's pinned genesis. Composing T-L1 + T-L2 (`anchored_head` walk) with AB-1 (key-bind + SR-1 anchor + MT-4 inclusion) and AB-2 (cleartext bind), union-bounded per the family style:

$$
\Pr[A_{\text{daemon}} \text{ forges RECORDED}] \;\le\; (vc.\text{height} + 2)\cdot K \cdot 2^{-128} \;+\; \log_2(n)\cdot 2^{-128} \;+\; 2\cdot 2^{-128},
$$

(the header walk + successor sig-verify A1 terms; the MT-4 term; the SR-1 collision case + AB-2 cleartext collision). For practical chains (`vc.height ≤ 2³²`, `K ≤ 16`, `n ≤ 2⁶⁴`) this is `≤ 2⁻⁹²`, operationally negligible — the same order as the balance/stake reads, as expected: the pipeline differs from `stake-trustless` only in the namespace and the cleartext source RPC (both route through the same S-042 `committee_bound_state_root` anchoring). The `NOT-RECORDED` verdict carries **no** such bound — it is the (H-neg) row of `NegativeVerdictSoundness.md` §10, forgeable with probability 1 and confined by NV-4 to the fail-safe direction.   ∎

---

## 5. Composition with companion proofs

- **`StakeProofSoundness.md`** — structural template. AB-1(ii) plays SP-1's role (committee-anchored root via the same shared S-042 helper the stake read uses), AB-1(i)+the Merkle leg play SP-2's (with the key-bind made a first-class obligation — the F-6 lesson postdates SP-2's optional-cross-check framing), and the S-040 closure SP-3 records is inherited unchanged through `merkle_verify`'s root-wrapper re-application.
- **`StateRootAnchorSoundness.md` (F6)** — AB-1(ii) *is* SR-1 applied at `anchor_index = proof_height − 1`, executed by the same `committee_bound_state_root` helper that proof analyzes; SR-2/SR-3 inherited for the walk.
- **`WaitHoldAndWaitSoundness.md` (FB64)** — AB-4's `--wait` neutrality is a citation, not a derivation; this command's `committee_bound_state_root` call (`light/main.cpp:2303`) is one of the eleven direct binding sites in its (re-pinned) WH-6 census, so WH-1–WH-5 apply verbatim.
- **`NegativeVerdictSoundness.md`** — AB-3 is the `b:` instantiation of NV-2/NV-3 ((H-neg) footing), NV-4 (confinement), NV-5 (substring caveat), NV-5a (key locality), and NV-6 clause (3) (caller contract); the `negative_footing` tag is its F-2.
- **`MerkleTreeSoundness.md`** — MT-2/MT-4 under AB-1; MT-5 is why AB-3's negative cannot be cryptographic; §6.2 (S-040 CLOSED) under AB-1.
- **`S033StateRootNamespaceCoverage.md`** — coverage + disjointness guarantee the `abort_records_` map is committed through the `b:` namespace and no other, so the leaf AB-1 verifies is the genuine committed abort state.
- **`LightClientThreatModel.md`** — `A_daemon`, T-L1/T-L2/T-L3, L-6 fail-closed exit, §6 residual single-daemon limitations, all inherited.

---

## 6. Known limitations

All of `LightClientThreatModel.md` §6 applies (single daemon, no persistence beyond the `--resume` anchor cache, genesis-only committee map, no transport encryption). Specific to this reader:

### 6.1 NOT-RECORDED is not an absence proof

The load-bearing limitation, fully analyzed in `NegativeVerdictSoundness.md` and surfaced here as AB-3 + the `negative_footing` tag. A slashing audit MUST NOT clear a node because its abort record "does not exist" on a single daemon's say-so (NV-6's worked failure mode names exactly this scenario).

### 6.2 Phase-1-only semantics

A `RECORDED count` is a Phase-1 abort count, and `NOT-RECORDED` says nothing about Phase-2 timing-skew aborts or equivocation (AB-4). Operators auditing total node health must consult the equivocation channel (FA6 / `EquivocationSlashing.md`) separately.

### 6.3 Verbatim domain key

No normalization is applied to `--domain` (correct — node domains are exact byte-string identities). A typo'd or case-variant domain yields an honest `NOT-RECORDED` for the literal string asked about; the output echoes that string so the operator can see which key the verdict concerns (NV-5a).

---

## 7. Implementation cross-reference

Line numbers verified against the current tree at the time of writing.

| Theorem | Component | File:lines | Role |
|---|---|---|---|
| all | `cmd_verify_abort_record` | `light/main.cpp:2176-2380` (dispatch `:7534`) | The composite command; header comment `:2157-2175`. |
| AB-1, AB-E | `anchored_head` | `light/trustless_read.cpp:278-333` | T-L1 genesis pin + T-L2 committee-verified walk (full or `--resume` suffix); S-033 activation gate `light/main.cpp:2215-2219`. |
| AB-1(i) | step 3a key-bind | `light/main.cpp:2254-2277` | `proof.key_bytes == hex("b:" ‖ D)` byte-for-byte; the F-6-pattern bind. |
| AB-1 | `verify_state_proof` | `light/verify.cpp:330-394` | Parse proof JSON (`json_require*` validation `:346-361`), delegate to `merkle_verify` `:378-380`. |
| AB-1 | `merkle_verify` (+ S-040 wrapper) | `src/crypto/merkle.cpp:131-161` | Sibling-chain recompute; root-wrapper re-application with caller-supplied `leaf_count` `:158-161`. |
| AB-1(ii) | stale-height gate + root equality | `light/main.cpp:2287-2310` | `proof_height < vc.height` throws `:2289-2294`; `attested != proof_root` SECURITY throw `:2305-2310`. |
| AB-1(ii), AB-4 | `committee_bound_state_root` | `light/trustless_read.cpp:335-437` | S-042 binding: full-block recompute `:356-364`, successor sig verify `:408-415`, `prev_hash` bind `:417-432`, hold-and-wait `:383-387`. |
| AB-2 | `abort_records` fetch + INCONSISTENT gate | `light/main.cpp:2318-2338` | Cleartext scan `:2323-2332`; proof-present/cleartext-absent throw `:2333-2338`. |
| AB-2 | value-hash recompute + TAMPERED gate | `light/main.cpp:2340-2355` | `SHA256(u64_be(count) ‖ u64_be(last_block))` vs proven `value_hash`. |
| AB-2 | `b:` leaf encoding | `src/chain/chain.cpp:342-348` | The committed-side encoding the recompute mirrors. |
| AB-2 | `SHA256Builder::append(uint64_t)` | `src/crypto/sha256.cpp:30-34` | Big-endian u64 serialization shared by both sides. |
| AB-2 | `Node::rpc_abort_records` | `src/node/node.cpp:2592-2621` | Cleartext source: sorted `[{domain, count, last_block}]` from the S-032 cache. |
| AB-3 | `not_found` matcher + NOT-RECORDED branch | `light/main.cpp:2227-2252` | Substring matcher `:2229`; `negative_footing=daemon_asserted` (initializer-list form) `:2238-2244`; early return `:2251`. |
| AB-1, AB-3 | `Node::rpc_state_proof` | `src/node/node.cpp:3363-3454` | `b` simple-namespace key shape `:3390-3398`; `not_found` `:3434-3437`; single envelope `:3443-3453`. |
| AB-3 | `Chain::state_proof` | `src/chain/chain.cpp:435-462` | `nullopt` for an absent key `:449` → the RPC's `not_found`. |
| AB-4 | Phase-1-only increment | `src/chain/chain.cpp:1307-1328` | `ae.round != 1 → continue` `:1314`; `count++` / `last_block = b.index` `:1318-1320`. |
| AB-4 | Phase-2-not-tracked comment | `src/node/node.cpp:2582-2591` | The serving-side statement of the semantic boundary. |
| AB-4 | `--wait` plumbing | `light/main.cpp:2190-2191`, `:2303-2304` | Forwarded only into the S-042 binding (FB64). |

**Tests** (offline contract here; live legs are CI/WSL2 cluster legs):

| Test | Coverage |
|---|---|
| `tools/test_light_verify_abort_record.sh` | The command's offline contract: help advertises `verify-abort-record` with `--domain` + `--wait`; missing required flag → clean usage error (exit 1); bad `--wait` rejected; no-daemon read fails fast with **no** verdict emitted (no false RECORDED/NOT-RECORDED). Live legs (induce a Phase-1 abort → RECORDED with hash-bound pair; NOT-RECORDED + `negative_footing`; tamper → fail-closed) documented + SKIPPED offline, CI/WSL2. |
| `tools/test_light_negative_footing.sh` | The F-2 source-contract guard counting the `b:` initializer-list `negative_footing` emission among the family's ten. |
| `tools/test_merkle_proof_tampering.sh` + `determ test-merkle-proof-tampering` | MT-4 tamper rejection + S-040 forged-`leaf_count` rejection AB-1 inherits. |
| `tools/test_state_proof_namespaces.sh` / `tools/test_state_root_namespaces.sh` | Cross-namespace swap rejection / namespace-mutation-changes-root coverage the `b:` leaf shares. |

---

## 8. Findings

- **AB-F1 (key-bind gap in the initial landing — F-6 forge class, FIXED).** The initial `verify-abort-record` landing (commit `4e5446f`) shipped steps 1-6 *without* the step-3a key-bind: `verify_state_proof` Merkle-verifies whatever `key_bytes` the daemon supplies, and the cleartext hash-bind (step 6) binds the cleartext to the *served* leaf, not to `D`'s — so a Byzantine daemon could serve a valid proof for some other node's `b:` leaf plus a consistent cleartext row, attributing an arbitrary committed `(count, last_block)` to `D` (laundering a heavily-aborted node behind a clean record, or the reverse smear). This is precisely the F-6 forge class `NegativeVerdictSoundness.md` registered against `read_stake_trustless` the same day; the family-wide F-6 hardening added the bind at `light/main.cpp:2254-2277` (the canonical-key byte-compare, mirroring `verify-account` / `verify-registrant` / `verify-receipt-inclusion`). AB-1(i) is stated against the hardened code; the memory-note lesson stands: single-leaf readers need BOTH the key-bind and the value-hash-bind. Impact was light-client-local (no consensus effect); the live tamper legs (CI/WSL2) are the behavioral tripwire.
- **AB-F2 (substring absence matcher — honest boundary, documented).** The `not_found` classification is `err.find("not_found")` over the dumped daemon-chosen error string (`light/main.cpp:2229`), not exact equality — the NV-5 caveat applies: zero adversarial delta (a lying daemon can always emit a clean `not_found`), but an honest-but-buggy daemon emitting a composite error containing the token would be misread as absence rather than `UNVERIFIABLE`. Named so the boundary is a decision, not an oversight.
- **AB-F3 (verbatim domain key — honest boundary).** No normalization on `--domain` (correct for byte-exact node-domain identities, NV-5a): a case-variant or typo'd query is answered about the literal string, which the verdict output echoes. Operators comparing against registry listings should use the exact registered spelling.
- **AB-F4 (semantic boundary — Phase-1 only).** `NOT-RECORDED` ≠ "never misbehaved" even under (H-neg): Phase-2 timing-skew aborts are untracked by design (`src/node/node.cpp:2588-2591`) and equivocation lives in a different channel. A node-health audit needs more than this one namespace; AB-4 fixes the exact claim a verified `RECORDED` supports.

---

## 9. Status

- **Spec.** Complete (this document). Analytic; changes no code.
- **Implementation.** Shipped: `determ-light verify-abort-record` (`light/main.cpp::cmd_verify_abort_record`, landed in commit `4e5446f`, key-bind hardened per AB-F1/F-6); the `b:` namespace served by `Node::rpc_state_proof` (`src/node/node.cpp:3390-3398`) and committed by `Chain::build_state_leaves` (`src/chain/chain.cpp:342-348`); cleartext via `Node::rpc_abort_records` (`src/node/node.cpp:2592-2621`). Anchored by `tools/test_light_verify_abort_record.sh` (offline contract; live legs CI).
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision resistance) — per `Preliminaries.md` §2.0. The `NOT-RECORDED` negative additionally rests on the non-cryptographic (H-neg) premise (`NegativeVerdictSoundness.md` NV-3), tagged `negative_footing=daemon_asserted`.
- **Adversary model.** `A_daemon` (malicious single daemon). Out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis`.
- **Theorems.** AB-1 (key-bind + committee anchor — the proven leaf is `"b:" ‖ D`'s under an SR-1-anchored root); AB-2 (cleartext hash-bind — INCONSISTENT + TAMPERED gates force cleartext/leaf consistency, A2); AB-3 (negative footing — NOT-RECORDED is the `b:` instance of NV-2/NV-3, key-local per NV-5a, NV-4-confined, never upgradeable to a false RECORDED); AB-4 (honest semantic boundary — Phase-1-only counts as-of the verified anchor; `--wait` soundness-neutral per FB64). Corollary AB-E composes to `≤ 2⁻⁹²` end-to-end for practical parameters, matching the family bound.
- **Composes with.** `StakeProofSoundness.md` (SP-1/SP-2/SP-3 template), `StateRootAnchorSoundness.md` (SR-1/SR-2/SR-3), `WaitHoldAndWaitSoundness.md` (FB64), `NegativeVerdictSoundness.md` (NV-2..NV-6, F-2, F-6), `MerkleTreeSoundness.md` (MT-2/MT-4/MT-5, §6.2 S-040 CLOSED), `S033StateRootNamespaceCoverage.md`, `LightClientThreatModel.md`.
- **Known limitations.** §6.1 (negative is daemon-asserted — the family's MT-5 boundary, not specific to this reader), §6.2 (Phase-1-only semantics), §6.3 (verbatim key). None undermine the per-invocation positive-verdict soundness claim.

---

## 10. References

### Implementation sites
- `light/main.cpp:2176-2380` — `cmd_verify_abort_record` (key-bind `:2254-2277`; NOT-RECORDED branch `:2234-2252`; S-042 anchor `:2285-2310`; INCONSISTENT/TAMPERED gates `:2318-2355`).
- `light/trustless_read.cpp:278-333` — `anchored_head`; `:335-437` — `committee_bound_state_root`.
- `light/verify.cpp:330-394` — `verify_state_proof`.
- `src/crypto/merkle.cpp:131-161` — `merkle_verify` (S-040 wrapper `:158-161`).
- `src/crypto/sha256.cpp:30-34` — `SHA256Builder::append(uint64_t)` (big-endian).
- `src/chain/chain.cpp:342-348` — `b:` leaf encoding; `:435-462` — `Chain::state_proof`; `:1307-1328` — Phase-1-only apply-time increment.
- `src/node/node.cpp:2592-2621` — `Node::rpc_abort_records`; `:3363-3454` — `Node::rpc_state_proof`.
- `tools/test_light_verify_abort_record.sh` — offline contract anchor.

### Companion proofs
- `docs/proofs/Preliminaries.md` (F0) — §2.0 canonical labels (A1/A2/A3).
- `docs/proofs/StakeProofSoundness.md` — the `s:` sibling (SP-1/SP-2/SP-3).
- `docs/proofs/StateRootAnchorSoundness.md` (F6) — SR-1/SR-2/SR-3.
- `docs/proofs/WaitHoldAndWaitSoundness.md` (FB64) — `--wait` soundness-neutrality.
- `docs/proofs/NegativeVerdictSoundness.md` — NV-2/NV-3 ((H-neg)), NV-4, NV-5/NV-5a, NV-6, F-2, F-6.
- `docs/proofs/MerkleTreeSoundness.md` — MT-2/MT-4/MT-5, §6.2 (S-040 CLOSED).
- `docs/proofs/S033StateRootNamespaceCoverage.md` — `b:` row, coverage + disjointness.
- `docs/proofs/LightClientThreatModel.md` — `A_daemon`, T-L1..T-L4, L-6.

### Specifications
- `docs/PROTOCOL.md` §4.1.1 (`b:` Merkle-leaf row), §10.2 (`state_proof` RPC).
- `docs/SECURITY.md` §S-032, §S-033, §S-038, §S-040, §S-042.
- NIST FIPS 180-4 — SHA-256 (A2). RFC 8032 — Ed25519 (A1).

This document is `FB65` in the proof family.
