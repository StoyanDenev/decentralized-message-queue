# On-chain SHARD_TIP records — closing S-036 (D3 / v2.11)

**Status: MECHANISM DECIDED (§9) — implementing. D3.1 SHIPPED; D3.2 next.** Owner
forks F-1…F-4 were decided (see §5); the mandated adversarial design-review (§8)
found the F-4 trust model unsound (a validator cannot re-derive a source committee
at a past height — `NodeRegistry::build_from_chain` reads present-head caches,
`src/node/registry.cpp:25-78`); the owner then chose **full closure via per-height
reconstruction** (§8.1), and the feasibility Workflow resolved the mechanism (§9):
a `c:` epoch committee-checkpoint (M-B) + an `eligible_count` source-signed
digest-bound field (M-C) + a selection-pool pin — reconstruct committee-at-`h` with
zero replay, so S-036 is trustlessly **closed**. **§9 is the live design; §3–§8 are
the superseded design + review history (read §9 for the current plan).** The owner
authorized the work in the pre-launch register (D3, 2026-07-09). This remains the
design-review-first step the project mandates for shipped-consensus changes (cf.
[BoundedReorgDesign.md](BoundedReorgDesign.md) /
[DeterministicSchedulerDesign.md](DeterministicSchedulerDesign.md)).

Reference convention: bare `§` are this doc; `S-036`/`S-030` are `docs/SECURITY.md`;
`T-*` claims are `S036UnderQuorumMerge.md` / `UnderQuorumMerge.md`.

## 0. Scope — the one behaviour that must change, and the invariant that must not

**Must change.** A `MERGE_EVENT` BEGIN's under-quorum justification must become
**independently verifiable from committed, hash-anchored chain state** instead of
a self-asserted `evidence_window_start: u64` that points at nothing
([block.hpp](../../include/determ/chain/block.hpp) `MergeEvent`; apply
[chain.cpp](../../src/chain/chain.cpp) `MERGE_EVENT` branch). Concretely: for the
window `[evidence_window_start, evidence_window_start + merge_threshold_blocks)`,
a validator must confirm from on-chain records that the source shard's
`eligible_in_region(source_region)` sat below the `2K` safety floor for
`merge_threshold_blocks` contiguous blocks — the accept predicate of
`S036UnderQuorumMerge.md` T-5 — and that those records are attested by the
**source shard's own committee**, not by the beacon asserting on its behalf.

**Must NOT change (the hard invariant).**
- **Non-EXTENDED byte-neutrality.** A chain running SINGLE / `shard_count_ ≤ 1`
  is byte-identical pre/post D3: no new state-root leaves, no new tx acceptance,
  no `compute_block_digest` change, no new gossip on the wire. Every new path is
  gated behind the existing `sharding_mode_ != ShardingMode::EXTENDED` reject
  ([validator.cpp](../../src/node/validator.cpp) MERGE_EVENT branch) and the
  `shard_count_ > 1` apply guard.
- **Healthy-EXTENDED quiet.** An EXTENDED chain whose shards are all healthy and
  never distressed writes **zero** `t:` records (F-1 = on-demand-on-distress), so
  its `state_root` sequence is unchanged relative to a pre-D3 EXTENDED chain that
  never merges. The only new leaves appear when a shard is genuinely below `2K`.
- **No touch** to `resolve_fork` / `revert_head` / `maybe_reorg_to_locked` (A4),
  the `checked_add_u64` supply debits (S-049), Ed25519/PQ address forms (A5/A6),
  or the `merge_state_` `m:` namespace + its snapshot round-trip
  ([MergeStateSoundness.md](MergeStateSoundness.md)). D3 adds an **admission
  gate** in front of MERGE_BEGIN; it does not change what a merge *does* once
  admitted. The already-shipped refugee-pool extension
  (`validator.cpp` `check_creator_selection` / `check_abort_certs`) is downstream
  of merge state and unchanged.

## 1. The trust gap today (trusted vs verified)

`MERGE_EVENT = 7` ([block.hpp](../../include/determ/chain/block.hpp)) is a single
tx type; BEGIN vs END is the `event_type: u8` payload field (`0`=BEGIN, `1`=END),
not a TxType discriminator. A BEGIN carries exactly one piece of evidence: a u64
`evidence_window_start`. The shipped S-036 partial mitigation verifies only the
*arithmetic* consistency of that u64 (window lies in the committed past; no u64
overflow) — it does **not**, and cannot, verify that the under-quorum condition
actually held, because **no per-height eligible-count record is committed
anywhere**. Today's `SHARD_TIP = 13` gossip
([messages.hpp](../../include/determ/net/messages.hpp)) carries a *whole source
block* to beacon peers; `Node::on_shard_tip`
([node.cpp](../../src/node/node.cpp) ~1690-1797) validates it and stores it in
the **in-memory** `latest_shard_tips_` map ([node.hpp](../../include/determ/node/node.hpp)
~692-697) — never hashed into `state_root`, never snapshotted, lost on restart,
and per-node (non-deterministic across validators). The validator cannot replay
history against data that was never committed.

**The residual attack `A_beacon_forge`.** A captured beacon committee (the
co-signers *are* the adversary) proposes a shape-valid MERGE_BEGIN with a
past-bounded but historically-false `evidence_window_start` for a *healthy*
source shard. Every shipped gate passes. Consequence: the partner shard absorbs
the source's refugee validators into its creator/abort pool
(`validator.cpp` `check_creator_selection`), so the adversary gains committee
membership on another shard. Blast radius is bounded to one window-sized spurious
merge and FA1/FA7 safety is preserved ([MergeStateSoundness.md](MergeStateSoundness.md)),
which is why S-036 is a *spurious-merge-admission* flaw tracked to v2.11 rather
than a launch-blocking safety break.

## 2. The reusable core — do not rebuild

`Node::on_shard_tip` ([node.cpp](../../src/node/node.cpp) ~1690-1797) is already
the exact operation a tip-record verifier needs, and it is the **reference
implementation** for admission:

1. Independent committee derivation (does NOT trust the tip's self-claimed
   committee): epoch = `tip.index / epoch_blocks`; beacon randomness from
   `cumulative_rand` at the epoch anchor; `NodeRegistry::build_from_chain` +
   `eligible_in_region(shard_region)` for the pool; abort-event exclusion;
   `crypto::epoch_committee_seed(beacon_rand, shard_id)` mixed with each
   `abort_event.event_hash`; `crypto::select_m_creators`; the derived creators
   checked position-by-position against `tip.creators`.
2. K-of-K signature check: `compute_block_digest(tip)` + Ed25519 `crypto::verify`
   of each `creator_block_sigs[i]` against the derived member, requiring `k_full`
   (MD) or `bft_committee_size(k_full)` (BFT) valid sigs.

The light-client mirror (`light/verify.cpp` `verify_block_sigs` +
`light/trustless_read.cpp` `committee_bound_state_root` +
`verify_state_root_at`) is the trustless offline verifier the D3 tooling reuses.
The persistence pattern to copy verbatim is the cross-shard receipt dedup: the
`i:` state-root namespace + snapshot serialize/restore + `CrossShardReceiptDedup.md`
T-R1..T-R7. Sibling namespaces already in `build_state_leaves`: `r: d: i: b: m:
ak: al:`.

## 3. The decided design (F-1…F-4 folded in)

### 3.1 The record — a source-committee-signed distress attestation

A **`ShardTipRecord`** is a compact metadata record (NOT a whole block — that is
today's gossip). Carried fields:

| field | type | meaning |
|---|---|---|
| `source_shard_id` | u32 | the distressed shard `S` |
| `height` | u64 | the source-shard block height the attestation is for |
| `eligible_count` | u32 | `eligible_in_region(region(S))` at `height` |
| `region_len` / `region` | u8 + utf8≤32 | the source shard's region (binds the count's scope) |
| `committee_sig_root` | 32 B | a hash binding the source committee's K-of-K signature set over the attested tuple (see §3.3) |

The record's authority is **F-4 = source-committee-signed, beacon-transported**:
`committee_sig_root` binds the *source* shard committee's signatures over the
canonical attested message `H_attest = SHA256("determ-shardtip-v1" ‖
source_shard_id_be4 ‖ height_be8 ‖ eligible_count_be4 ‖ region)`. A captured
beacon may *transport* a record but cannot fabricate a false `eligible_count`
that carries a valid source-committee attestation — it lacks the source
committee's keys. This is the property that closes `A_beacon_forge`.

### 3.2 Carrier — F-3 = beacon block-summary field (no new TxType)

The beacon block gains a `shard_tip_records` summary field, populated from the
already-validated `latest_shard_tips_` pipeline
([node.hpp](../../include/determ/node/node.hpp) ~692-697, already documented as
feeding `BeaconBlock.shard_summaries`). The beacon includes a `ShardTipRecord`
for a source shard **only when that shard's latest validated tip shows
`eligible_count < 2K`** (F-1 = on-demand-on-distress) plus a sparse liveness
beacon (§3.5). The field is authenticated transitively by the beacon block's
existing K-of-K creator signature; no new tx, no fee/nonce, no new signature
surface. `compute_block_digest` treatment is the load-bearing detail — see §4.

### 3.3 State storage — F-2 = bounded `t:` ring, `revert_threshold_blocks` deep

Applying a beacon block folds its `shard_tip_records` into a new chain container
and emits a `t:` state-root namespace leaf per record (mirroring the `i:`
receipt-dedup pattern exactly):
- Leaf key `"t:" + source_shard_id_be4 + height_be8`; value
  `SHA256(eligible_count_be4 ‖ region ‖ committee_sig_root)`.
- Bounded ring: retain the last `revert_threshold_blocks` (default **200**,
  genesis-pinned but currently unused — this gives it its first consumer) records
  *per source shard*; older records are pruned deterministically (drop the
  lowest-`height` leaf for that shard when the ring overflows). 200 comfortably
  covers `merge_threshold_blocks` (100) + `merge_grace_blocks` (10).
- Snapshot serialize/restore + lazy atomic-apply capture, exactly as `i:`/`m:`.
- **Empty-set byte-neutrality:** zero records ⇒ zero `t:` leaves ⇒ unchanged
  `state_root` (the §0 healthy-EXTENDED invariant).

### 3.4 MERGE_BEGIN binding + verification (D3.4)

A new `validate_merge_event_historical`-style obligation, gated EXTENDED-only,
BEGIN-only, wired into the MERGE_EVENT branch after the shipped arithmetic
bounds:
- For the window `[evidence_window_start, evidence_window_start +
  merge_threshold_blocks)`, read the committed `t:` records for `source_shard`.
- **Accept** only if every height in the window carries a record attesting
  `eligible_count < 2K`, contiguously (`consecutive_stress_blocks ≥
  merge_threshold_blocks`) — the T-5 predicate.
- **Reject** if any in-window height carries a *healthy* (`≥ 2K`) attested record
  for the source shard (the "no live SHARD_TIP contradicting distress" clause),
  or if the window predates the retained ring (unverifiable ⇒ fail-closed), or if
  a required in-window record is absent (absence ≠ distress — see §3.5).

Because the `t:` records are committed beacon-chain state (each folded in by a
prior K-of-K-signed beacon block and bound into `state_root`), this check is
**deterministic across all beacon validators** — the property today's in-memory
`latest_shard_tips_` cannot provide.

### 3.5 Liveness beacon — distinguishing "silent" from "healthy"

On-demand-on-distress (F-1) means a healthy shard writes no records. To keep
"shard went silent" distinguishable from "shard healthy", the beacon also folds a
sparse healthy record (cadence ~`merge_threshold_blocks / 2`) for each tracked
shard whose latest tip is healthy. The MERGE_BEGIN verifier therefore treats a
window as *distress-covered* only when it holds contiguous sub-`2K` records with
**no** intervening healthy record — absence of a record inside a window that
should carry the sparse liveness beacon is itself evidence the shard was silent,
which (per the spec's `merge_threshold_blocks`-no-tip clause) is a legitimate
merge trigger, but is verified against the *presence pattern* of committed
records, never assumed.

## 4. The central soundness obligation (design-review focus)

**The one thing the adversarial review must break or bless.** The F-3 (beacon
transports) + F-4 (source committee attests) split means the beacon-chain
validator, at MERGE_BEGIN admission, must be able to trust that each in-window
`t:` record's `eligible_count` carried a valid *source*-committee attestation —
deterministically, from committed beacon-chain state, without re-fetching the
source shard's full history. Two candidate discharge points:

- **(V-commit) Verify at fold-in.** When a beacon block is applied, the record's
  source-committee attestation is re-verified via the §2 `on_shard_tip`
  derivation before the `t:` leaf is emitted; an unverifiable record makes the
  beacon block INVALID (fail-closed, all validators agree because the derivation
  is deterministic from the source headers the beacon block must also carry /
  reference). Then MERGE_BEGIN admission only checks record *presence + count*,
  trusting the fold-in gate. **Risk:** the derivation needs the source committee
  at `height`, i.e. the source registry at that height — is that reconstructible
  from committed beacon state at fold-in? (The beacon tracks source headers; the
  design must make the source-committee inputs on-chain, or carry them in the
  record.)
- **(V-admit) Verify at admission.** The record self-carries the derived source
  committee members' pubkeys + sigs, and the MERGE_BEGIN validator re-checks the
  Ed25519 sigs against the carried members. **Risk:** who binds the carried
  members to the *real* source committee at `height`? Without the source registry
  on-chain, this reduces to "the beacon that committed it said so" — reintroducing
  beacon trust unless the members are themselves derived from committed data.

**Working resolution (to be ratified by the review):** V-commit with the source
committee inputs made deterministic — the beacon block that folds in a record
must also commit (or reference by hash into already-committed beacon state) the
source header at `height` from which `on_shard_tip` derives the committee, so the
fold-in verification is a pure function of committed state and every beacon
validator recomputes the same accept/reject. This is the same "commit the inputs
so the check is deterministic" discipline S-038 applied to `state_root`. If the
review finds the source-header commitment is too heavy or circular, the fallback
is a **layered-trust** statement (records authenticated by the honest-majority
beacon committee that verified the source sig at fold-in, residual bounded to a
*sustained* captured-beacon-committee-over-the-window + source-key-compromise —
strictly harder than today's single-block fabrication) and S-036 is downgraded
from "closed" to "strongly mitigated", pending a possible 5th owner fork.

## 5. Owner forks — DECIDED (2026-07-12)

| Fork | Decision | Rationale |
|---|---|---|
| **F-1 cadence** | **On-demand-on-distress + sparse liveness beacon** | keeps healthy-EXTENDED `state_root` quiet (§0 invariant); verifier still gets contiguous window coverage. |
| **F-2 retention** | **Bounded ring = `revert_threshold_blocks` (200) per shard** | gives the genesis-pinned-but-unused scalar its first consumer; covers window+grace with margin; caps state growth. |
| **F-3 carrier** | **Beacon block-summary field** (not a new TxType) | reuses the already-validated `latest_shard_tips_ → shard_summaries` pipeline + the block's K-of-K sig; no fee/nonce/new-sig surface. |
| **F-4 trust anchor** | **Source-committee-signed, beacon-transported** | a captured beacon cannot forge a source-committee attestation over a false count — the property that actually closes `A_beacon_forge`. |

## 6. Increment plan (smallest-safe-first, A4.x style — each byte-neutral for non-EXTENDED, each gated)

| # | Increment | Gate |
|---|---|---|
| **D3.1** | **`ShardTipRecord` struct + encode/decode** — exhaustive decode gates mirroring `MergeEvent::decode` (size floor, field-range, region-len ≤ 32, exact trailing bytes). No apply, no validator wiring, no digest touch. | round-trip unit test (`determ test-shard-tip-record`): encode→decode equal; malformed / overlong / short / bad-region all → nullopt. FAST both platforms, count +1, zero golden/digest change. |
| **D3.2** | **`t:` state namespace + bounded ring + snapshot round-trip** — new `chain::` container; `build_state_leaves` emits `t:` leaves; serialize/restore in snapshot; ring prune deterministic. Empty-set emits zero leaves. | `test-shard-tip-namespace`: identical `state_root` across two nodes given identical record sets; **empty-set byte-neutrality** assertion; ring-overflow prunes the lowest height deterministically; genesis-roundtrip + snapshot-full-determinism guards green. Mirror `CrossShardReceiptDedup.md` T-R1..T-R7. |
| **D3.3** | **Beacon producer emission** — beacon folds distress + sparse-liveness `ShardTipRecord`s into its block from `latest_shard_tips_`; `compute_block_digest` treatment per §4 (the review's V-commit resolution). | LIVE EXTENDED cluster: records appear on-chain when a shard drops below `2K`; SINGLE/non-EXTENDED cluster: **zero** records + unchanged `state_root`; a beacon re-derives + accepts its own records. Goldens byte-identical for non-EXTENDED. |
| **D3.4** | **Validator historical-witness verification** — `validate_merge_event_historical` wired into the MERGE_EVENT BEGIN branch; consumes committed `t:` records via the §2 committee-derivation core; fail-closed on a window lacking contiguous sub-`2K` source-attested coverage. | the D3.5 repro red→green; existing `test_under_quorum_merge.sh` still green; FAST both platforms. |
| **D3.5** | **Deterministic S-036 falsifier** — `SeededRng` + `VirtualTransport`/`VirtualClock` harness: a healthy source shard + a captured beacon emitting a false-window MERGE_BEGIN → **rejected** post-D3.4; a genuinely-distressed source (contiguous sub-`2K` attested records) → **accepted**; FORGE / WINNER / REPLAY cases like `test-node-reorg-s048`. | red on the pre-D3.4 tree, green after; deterministic replay-twice-identical; LIVE EXTENDED merge still fires on legitimate distress. |
| **D3.6** | **Docs + proof** — this doc → `ShardTipMergeSoundness.md` (encode round-trip; `t:` state-root determinism; empty-set byte-neutrality; source-committee-attestation unforgeability; historical-accept-predicate soundness; blast-radius unchanged). Flip SECURITY.md S-036 v2.11 row + `S036UnderQuorumMerge.md` F-1 to CLOSED (or "strongly mitigated" per §4). Fix the stale `validator.cpp:772-776` proof citations. | proofs-index + link-check + doc-tier + citation-bounds guards green. |

The recurring gate is the project standard: **goldens byte-identical (non-EXTENDED) + FAST + LIVE EXTENDED cluster**, strengthened by the **deterministic S-036 falsifier** (D3.5) and an **adversarial review** of each consensus-touching increment (D3.3, D3.4) before commit.

## 7. Risks / open questions (for the design review)

- **§4 verification determinism** — the load-bearing question. Resolve V-commit
  vs V-admit + the source-committee-input commitment before D3.3.
- **`compute_block_digest` inclusion of `shard_tip_records`** — include (all
  beacons must agree on the exact record set per block → a determinism obligation
  on which tips are "latest" at build time) vs exclude-and-prev_hash-authenticate
  (the §Q6 hash-chain trick). The former is simpler to prove; the latter avoids a
  digest change on the beacon path. Decide in D3.3.
- **"Latest tip at build time" determinism** — `latest_shard_tips_` is populated
  by async gossip, so two beacons may hold different latest tips when they build.
  The fold-in set must be a deterministic function of committed state (e.g. only
  fold records whose source header is already committed/referenced), or the
  digest diverges. This couples to §4 and is the single most likely place a
  soundness bug hides.
- **Region binding** — `eligible_in_region` is region-scoped; the record must
  bind the region so a validator re-derives the same pool (handled: `region` is a
  signed field of `H_attest`).
- **Naming** — three things share "SHARD_TIP": the shipped whole-block gossip
  (`MsgType::SHARD_TIP=13`), the spec's `ShardTipPayload`, and this on-chain
  `ShardTipRecord` / `t:` namespace. Code must name the new record distinctly to
  avoid conflation.

## 8. Design-review outcome (2026-07-12) — the §3–§4 model is superseded; 5th owner fork

A 3-lens adversarial design-review (verification-determinism / digest-build-determinism /
byte-neutrality+threat-model) attacked this doc against the real code and returned
**GO for D3.1+D3.2, STOP before D3.3.** Its findings are code-grounded and change
the trust model:

1. **Retroactive committee re-derivation is impossible (kills V-commit, §4).**
   `NodeRegistry::build_from_chain(chain, at_index)` reads `chain.registrants()` /
   `chain.stake()` / `chain.abort_records()` — single per-domain maps holding the
   **current head** state (`src/node/registry.cpp:25-78`); `at_index` gates only
   the `active_from`/`inactive_from` window + suspension arithmetic, not the stake
   / superseded-registrant / abort **values**. So re-deriving a source committee
   for a past window height `h` computes it against *present* registry state →
   deterministic-but-wrong → false-rejects a legitimate merge on any shard whose
   pool churned since `h`. Committing the source *header* does not help (the missing
   input is the historical *registry*, not the header). The `§2` K-of-K check also
   consumes the full source block body (`tip.abort_events` + `compute_block_digest`
   over the whole block, `src/node/producer.cpp:619-672`), so re-verifying at
   admission would force committing whole source blocks across the window — the
   unbounded cost §3.1 rejects.

2. **The only sound scheme is contemporaneous fold-in + layered trust ⇒ S-036 is
   "strongly mitigated," not "closed."** When a fresh tip arrives `h ≈ height()`,
   so `build_from_chain(current)` *is* the correct committee — which is exactly why
   today's `on_shard_tip` is sound at gossip time. So: the beacon verifies the tip
   (§2 derivation + K-of-K) **contemporaneously at fold-in**, commits the *result*
   (`eligible_count` + the `t:` leaf) into `state_root`; at MERGE_BEGIN admission
   the validator **reads the committed leaves, re-deriving nothing**. Determinism at
   admission comes from "the leaf is committed + bound by a prior K-of-K beacon
   block," not from recomputation. The irreducible residual: *the honest-majority
   beacon committee that folded the leaf computed `eligible_count` correctly from
   its registry at fold-in.* This raises the bar from today's single-block
   fabrication to a **sustained captured beacon committee over the whole window** —
   a real improvement, but not trustless closure.

3. **F-4 is unimplementable AND misframed.** There is no source-committee signature
   over `eligible_count` (the source K-of-K signs `compute_block_digest`, which omits
   pool size; `tip.creators.size()` is always exactly `k`). And `eligible_count =
   eligible_in_region(source_region)` is a function of the **beacon's own committed
   registry**, so a *source*-committee attestation of it is not even the right anchor.
   **Resolution:** drop `committee_sig_root` as a purported source-attestation of the
   count; treat `eligible_count` as a **contemporaneously-verified determinism cache
   of committed beacon state**; the source tip's existing K-of-K sig retains one real
   job — proving the source shard was **alive** at `h` (distress-with-liveness vs
   silence) — and is described as such.

4. **Digest binding needs F2 reconciliation, not raw `latest_shard_tips_`
   (BLOCKING).** `latest_shard_tips_` is per-node async-gossip state
   (`node.hpp:692-697`), so two honest co-creators of the same K-of-K beacon block
   hold different sets → binding it raw into `compute_block_digest` diverges the
   per-creator digest → the block never gathers K-of-K → an **S-047-class liveness
   wedge** (the producer already warns about exactly this at `producer.cpp:610-618`).
   **The digest must bind a *reconciled* set:** each committee member commits a signed
   Phase-1 shard-tip view (like the inbound/eq/abort Phase-1 views, `node.cpp:984-1009`);
   assembly folds a `(shard_id, height)` record only if it appears in a threshold of
   the K views (**intersection** semantics, mirroring the inbound-receipt intersection
   at `validator.cpp:1372-1378`), gated by the same non-zero-view-root append the
   eq/abort fields use. This reconciliation mechanism is **net-new and outside
   F-1…F-4** — it is the substance of the 5th fork.

5. **Byte-neutrality + absence-semantics corrections (hold regardless of the fork).**
   (a) §0's "healthy-EXTENDED writes zero records / state_root unchanged" is falsified
   by the §3.5 sparse liveness beacon (it writes healthy `t:` leaves → `state_root`
   drift): the **hard byte-neutrality guarantee is scoped to NON-EXTENDED only**
   (SINGLE / `shard_count ≤ 1`); healthy MULTI-shard EXTENDED chains accrue periodic
   liveness leaves, which is acceptable since the launch posture is EXTENDED→SHARD_TIP
   (no pre-D3 EXTENDED production chain to stay byte-identical with). (b) The §3.4 vs
   §3.5 absence contradiction is a real attack: the beacon is the sole emitter (F-3),
   so it can **withhold** liveness records for a healthy shard to manufacture "silence"
   (`A_beacon_omit`, no key compromise needed). **Adopt uniform fail-closed: an absent
   required in-window record ⇒ REJECT**; the "silent shard" trigger cannot be anchored
   on beacon-controlled presence patterns (documented residual). (c) The F-3 carrier
   field does **not** exist yet (`shard_summaries` is a B3+ TODO comment; `block.hpp:367`,
   `node.hpp:696`) — it is a **net-new digest-bound `Block` field** whose non-EXTENDED
   byte-neutrality (empty-vector ⇒ no digest append) must be proven from scratch,
   mirroring the conditional-append at `producer.cpp:640-672`, and threaded through
   `compute_block_digest` / `Block::to_json`/`from_json` / the `light/verify.cpp` digest
   mirror.

**Cleared to implement now (byte-neutral, no digest/acceptance change):** D3.1
(`ShardTipRecord` struct + encode/decode) and D3.2 (`t:` namespace + bounded ring +
snapshot round-trip), after the §5(c) edit lands.

**The 5th owner fork (blocks D3.3+).** Ratify, as one decision: (a) **S-036 →
"strongly mitigated," not "closed"** (per finding 2); (b) the trust anchor is
**contemporaneous honest-majority-beacon verification at fold-in** — `eligible_count`
is a committed determinism cache, the source K-of-K proves liveness only (findings
2–3); (c) add the **F2-style signed-Phase-1-shard-tip-view + intersection
reconciliation** as the fold-in-set rule (finding 4). OR choose a different D3 scope
(defer the consensus half; ship only the D3.1/D3.2 substrate; or accept the current
partial mitigation for launch). Files the decision references:
`src/node/registry.cpp:25-78`, `src/node/producer.cpp:610-672`,
`src/node/node.cpp:1690-1797`.

### 8.1 Owner decision (2026-07-12) — FULL CLOSURE via per-height reconstruction

**The owner chose the largest scope: build the per-height historical-state
capability so a validator CAN retroactively re-derive a past committee — enabling
trustless S-036 *closure*, not merely strong mitigation.** This directly attacks
finding 1's root cause (present-head-only registry caches). With
`eligible_in_region(region)` reconstructible AS OF a past height `h`, the merge
validator re-derives the source committee at `h` deterministically from committed
state, re-runs the §2 K-of-K verification, and confirms the under-quorum predicate
without trusting the beacon — closing `A_beacon_forge` outright.

This **supersedes findings 1–3's "strongly-mitigated ceiling"**: that ceiling
existed *because* past state was unreconstructible; per-height reconstruction
removes the ceiling. Findings 4 (digest reconciliation of any beacon-committed
tip set) and 5 (byte-neutrality scoping, fail-closed absence, net-new-field
discipline) still stand and must be honored.

**The new design question (mechanism sub-round, §9).** "Per-height snapshots"
naively = O(heights × domains) state explosion; the affordable sound mechanism is
resolved in §9.

## 9. Mechanism decision (2026-07-12, feasibility-Workflow grounded) — Hybrid M-B + M-C

**M-A (pure replay) is REJECTED — unsound AND infeasible.** `restore_from_snapshot`
(`src/chain/chain.cpp:2189-2193`) rebuilds `blocks_` from only the tail
`header_count = 16` headers (`serialize_state` `:2015-2022`); a snapshot-bootstrapped
node physically lacks `blocks_[0..h]`, so `build_from_chain_at(h)` is *uncomputable*
there while a full-archive node computes it — wire that into MERGE_BEGIN admission
and two honest validators diverge = **consensus split**. Independently, one
admission needs ~100 committee re-derivations each O(h·T) = O(100·H·T) synchronous
per validator = a validation-path DoS. **The decisive constraint: every input to
the merge gate must travel inside committed state / the snapshot — that is the only
thing archive and snapshot nodes provably share.**

**The circularity is intrinsic and forces M-B.** Authenticating a source K-of-K sig
at `h` requires re-running `select_m_creators` (`src/crypto/random.cpp:70-86`, a pure
function of the *exact ordered eligible pool* at `h`) — which `build_from_chain`
cannot supply from present-head caches. M-C alone does NOT break this (a source-signed
count is only worth the verifier's ability to authenticate the signers = the same
historical-pool dependency, plus a rogue-registered-signer forge). The only artifact
that severs it is a **genesis-anchored, inductively-signed per-epoch committee /
eligible-set checkpoint committed into `state_root`** (M-B) — inherited through the
snapshot, it resurrects the design's V-commit path (finding 1 killed V-commit
*because* reconstruction was impossible; the checkpoint makes fold-in verification a
pure function of committed state).

**The two new on-chain artifacts (both gated `shard_count_ > 1` ⇒ non-EXTENDED emits
zero leaves ⇒ `state_root` byte-identical):**
- **(A) `c:` epoch committee/eligible-set checkpoint** — container
  `std::map<EpochIndex, EligibleSetSnapshot>` where the snapshot is the **ordered**
  `(domain, ed_pub, region)` eligible set as of the epoch anchor (the exact input
  `select_m_creators` consumes). Leaf `"c:" + epoch_be8` = `SHA256(canonical_encode(
  ordered_set))`. Folded at the epoch-rotation hook (`node.cpp:2125`), round-tripped
  through `serialize_state`/`restore_from_snapshot` like `merge_state_`; bounded ring
  (cover `revert_threshold_blocks`=200 back). Genesis pins epoch-0 (`K_0`); each
  checkpoint is folded by a beacon block signed by that epoch's committee,
  authenticated by the *prior* committed checkpoint — inductively back to genesis.
- **(B) `eligible_count: u32` source-signed digest-bound `Block` field** — the source
  committee computes `eligible_in_region(region)` at its own head (contemporaneously
  correct, finding 2) and K-of-K signs it via `compute_block_digest`. Net-new
  digest-bound field, **conditionally appended only when `shard_count_ > 1`**
  (mirroring the `producer.cpp:640-672` conditional-append), threaded through
  `compute_block_digest` / `to_json`/`from_json` / the `light/verify.cpp` digest
  mirror, with an empty-vector ⇒ no-append byte-neutrality proof. Turns finding 3 on
  its head: the count is now the source committee's *signed self-report*, and (A)
  makes those signers authenticatable at any past `h`.

**Load-bearing selection-pool pin.** Today the selection *randomness* is
epoch-anchored (`node.cpp:1716-1721`) but the selection *pool* is read at present head
(`node.cpp:1724` `build_from_chain(chain_, chain_.height())`) — so committee-at-`h`
drifts with mid-epoch churn and is NOT reconstructible from a single checkpoint. **Pin
the shard-committee pool to the epoch anchor** (`build_from_chain(chain_,
beacon_anchor_height)`) in the shard producer's selection and in `on_shard_tip` — this
makes committee membership epoch-stable ⇒ reconstructible from ONE `c:` checkpoint with
zero replay, and removes a latent present-head nondeterminism. ⚠️ **This is a
consensus-behavior change; its byte-neutrality claim (that it touches only the
EXTENDED/shard-scoped selection, not SINGLE-mode block production) MUST be verified
against the code at D3.3 before it lands** — if the pinned path is shared with
SINGLE-mode committee selection, this breaks the non-EXTENDED invariant + every
existing golden, and needs re-scoping.

### Revised increment plan (supersedes §6)

| # | Increment | Gate |
|---|---|---|
| **D3.1 ✅** | `ShardTipRecord` struct + encode/decode — **SHIPPED**. 49-byte base (source_shard_id·4 + height·8 + eligible_count·4 + committee_sig_root·32 + region_len·1 + region), exhaustive decode gates mirroring `MergeEvent::decode` (size floor, region-len ≤ 32, exact trailing bytes). No apply/validator/digest touch. | `test-shard-tip-record` (9 assertions): round-trip preserves every field; empty + max-32 region; all-0xFF no truncation; determinism; rejects < 49 / region_len>32 / size-mismatch. FAST 218/0 both platforms; zero golden change. |
| **D3.2** | `t:` state namespace + bounded ring + snapshot round-trip (CLEARED). Empty-set ⇒ zero leaves. | `test-shard-tip-namespace`: identical `state_root` across two nodes; empty-set byte-neutrality; deterministic ring prune; genesis-roundtrip + snapshot-full-determinism green. |
| **D3.3** | **`c:` epoch checkpoint namespace + the selection-pool pin** (load-bearing; MUST precede producer/gate work). Container + ordered-set canonical encode + `build_state_leaves` emission + snapshot round-trip + epoch ring prune, folded at `node.cpp:2125`; pin `on_shard_tip` + shard producer selection to the epoch anchor. **Verify the pin's non-EXTENDED byte-neutrality first.** | `test-epoch-checkpoint`: two nodes identical `state_root`; a **snapshot-bootstrapped** node reconstructs committee-at-`h` identical to a contemporaneous `on_shard_tip` derivation; non-EXTENDED emits zero `c:` leaves + byte-identical goldens; SINGLE-mode selection unchanged. Adversarial review (snapshot-inheritance + inductive anchor + pin scoping). |
| **D3.4** | **`eligible_count` digest-bound source-block field** — conditional-append gated `shard_count_ > 1`; threaded through digest/json/light mirror; source populates + K-of-K signs. | empty-vector ⇒ no digest append proven; non-EXTENDED goldens byte-identical; a source signs + a beacon re-derives the same digest; FAST both platforms. |
| **D3.5** | **Beacon producer emission (V-commit + F2 reconciliation)** — fold distress + sparse-liveness records from a **reconciled** tip set (signed Phase-1 shard-tip views + intersection, mirroring `validator.cpp:1372-1378` + the non-zero-view-root append `node.cpp:984-1009`); fold-in re-derives the source committee from `c:` + verifies source K-of-K over the block incl. `eligible_count`; unverifiable ⇒ beacon block INVALID; emit `t:` leaf. | LIVE EXTENDED: records appear when a shard drops below `2K`; SINGLE: zero records + unchanged `state_root`; two beacons with divergent `latest_shard_tips_` still produce the identical reconciled set (no S-047 digest wedge). Adversarial review of the reconciliation. |
| **D3.6** | **`validate_merge_event_historical` admission gate** in the MERGE_EVENT BEGIN branch (EXTENDED-only, BEGIN-only, after the shipped arithmetic bounds): read committed `t:` over the window; accept only on contiguous sub-`2K` source-attested coverage; **uniform fail-closed on any absent in-window record** (`A_beacon_omit`); fail-closed if the window predates the ring. | D3.7 repro red→green; `test_under_quorum_merge.sh` still green; FAST both platforms. |
| **D3.7** | **Deterministic S-036 falsifier** — `SeededRng` + virtual harness: healthy source + captured beacon false-window MERGE_BEGIN → **rejected**; genuinely-distressed source (contiguous sub-`2K` + checkpoint-authenticated sigs) → **accepted**; **rogue-registered-signer** → rejected by the `c:` selection check; **snapshot-node vs archive-node admission → identical verdict**. FORGE/WINNER/REPLAY cases. | red on pre-D3.6, green after; replay-twice-identical; LIVE EXTENDED merge still fires on legitimate distress. |
| **D3.8** | **Docs + proof** `ShardTipMergeSoundness.md` (encode round-trip; `t:`+`c:` determinism; empty-set/non-EXTENDED byte-neutrality; epoch-checkpoint inductive authentication back to `K_0`; source-count unforgeability; snapshot/archive admission agreement; historical-accept-predicate soundness; blast radius). Flip SECURITY.md S-036 + `S036UnderQuorumMerge.md` F-1 → **CLOSED**; fix the stale `validator.cpp:772-776` citations. | proofs-index + link-check + doc-tier + citation-bounds green. |

**Residual owner sub-fork: none.** The one candidate (full ordered eligible-set per
epoch vs a registry-delta + intra-epoch replay) is not a real fork — the delta option
reintroduces the exact snapshot-node history-absence break that kills M-A. Full ordered
set (bounded: ~1-2 epochs × one epoch's eligible domains) is the sound choice. The
selection-pool pin is inside the owner's authorized full-closure scope (EXTENDED-only,
no pre-D3 EXTENDED production chain) and is a net correctness improvement.

**D3.1 + D3.2 remain valid substrate under this mechanism and proceed now.**
