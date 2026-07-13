# On-chain SHARD_TIP records — closing S-036 (D3 / v2.11)

**Status: MECHANISM DECIDED (§9) — implementing. D3.1 + D3.2 + D3.3a SHIPPED; D3.3b next (the `sharding_mode==EXTENDED`-gated selection pin + epoch-rotation fold-in). See §9.2 for the feasibility-verdict corrections (gate on `sharding_mode==EXTENDED` not role; the pin READS the `cc:` checkpoint, not `build_from_chain(anchor)`; the leaf prefix is `cc:` not `c:`).** Owner
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
| **D3.2 ✅** | `t:` state namespace + bounded ring + snapshot round-trip — **SHIPPED**. `shard_tip_records_` map keyed by (source_shard_id, height); `build_state_leaves` emits a `t:` leaf per record (`SHA256(eligible_count ‖ region ‖ committee_sig_root)`); `add_shard_tip_record` enforces a per-shard ring of `revert_threshold_blocks`; serialize/restore + StateSnapshot field mirror `merge_state_`. Empty ring ⇒ zero leaves + omitted from the snapshot. | `test-shard-tip-namespace` (6 assertions): empty-set byte-neutrality; a record changes `state_root`; order-independent determinism; per-shard ring prune (lowest heights dropped); snapshot inheritance (restored chain = same records + same `state_root`); empty ring omitted. FAST 219/0 both platforms; snapshot-full-determinism + state-root goldens byte-identical. |
| **D3.3a ✅** | **`cc:` epoch committee-checkpoint substrate — SHIPPED.** `committee_checkpoints_` = `std::map<EpochIndex, {epoch_rand:32B, members:[{domain, ed_pub, region}]}>`; `add_committee_checkpoint` canonicalizes members domain-sorted + enforces a `kCommitteeCheckpointRing`(=16)-epoch ring; a `cc:` state-root leaf per epoch; serialize/restore + StateSnapshot field (snapshot inheritance). Empty ring ⇒ zero leaves ⇒ byte-identical. **Prefix is `cc:` (not `c:` — `k:c:` is the counter namespace, §9.2).** Populated only by D3.3b (EXTENDED). | `test-committee-checkpoint` (6 assertions): empty-set byte-neutrality; a checkpoint changes `state_root`; member-order-independent determinism (canonicalized); bounded ring; snapshot round-trip (restored chain = same checkpoints + same `state_root`); empty ring omitted. FAST 220/0 both platforms; state-root + snapshot goldens byte-identical. |
| **D3.3b-write ✅** | **Chain-layer epoch-rotation fold-in — SHIPPED** (steps 0-3; §9.3). The write-side that POPULATES the `cc:` ring on EXTENDED chains, inside `Chain::apply_transactions` (FR-1: the only mutator common to ctor-genesis + append + both store-reload replays). **step0** (`924859f`) hoisted the 3 suspension constants to `chain/params.hpp` (H-4 drift-fork guard). **step1** (`df89677`) pinned `epoch_blocks_` onto Chain (member + accessors + 6th `Chain::load` param set before replay + node wiring; a plain field, NOT a `const_leaf` — H-2). **step2+3** (`e221147`) added `Chain::freeze_epoch_committee(at_index)` (Option B private helper, build_from_chain's exact 4-predicate filter), the `__ensure_committee_checkpoints` lazy-capture lambda (H-1 reorg/rollback safety), and **Site A only**: freeze epoch `E` at the last block of `E−1` (`(b.index+1)%epoch_blocks_==0`, gated `shard_count_>1 && epoch_blocks_>0`, `epoch_rand=b.cumulative_rand`, `members=freeze_epoch_committee(b.index)`), placed before the S-033 recompute so the `cc:` leaf binds. **Site B (genesis epoch 0) was DROPPED**: the genesis ctor applies before the node sets `epoch_blocks_`/`shard_count_`, so a genesis fold would diverge bootstrap-vs-reload; the first checkpoint is epoch 1 at block `epoch_blocks−1`, and an absent epoch-0 checkpoint is fail-closed at the D3.6 gate (never a fork). `epoch_blocks_` round-trips through the snapshot, emitted only when non-zero (byte-neutral). | `test-committee-fold` (13 assertions): fold fires exactly at the boundary; freezes the right pool + `epoch_rand`; SINGLE never folds; `epoch_blocks==0` disables it; `cc:` leaf binds into `state_root` + a `Chain::load` replay re-folds identically (no S-033 throw); A4 revert+re-append idempotent. FAST **221/0 BOTH platforms** (MSVC + WSL2/GCC); every SINGLE/CURRENT golden byte-identical. |
| **D3.3b-read STEP 0 ✅** | **Shared `committee_pool` POOL + IDENTITY helpers — SHIPPED** (`3e35e0d`; §9.4 RP-2). `include/determ/node/committee_pool.hpp` + `.cpp`: `committee_pin_active` (gate == fold gate), `select_committee_pool` (POOL, frozen-only, region-filter mirroring `eligible_in_region`), `resolve_committee_member_pubkey` / `committee_member_registered` (IDENTITY, frozen-first + present-head fallback). Unwired ⇒ byte-neutral. | `test-committee-pin` (15 assertions): the gate (SINGLE/epoch-0 off); no-drift byte-equality with present-head (same domain order); the DRIFT FIX (a min_stake-raised present-head drops a member that the frozen pool + frozen-first pubkey keep valid). FAST 222/0 both platforms. |
| **D3.3b-read STEP 1+2 ✅** | **The selection PIN wiring — SHIPPED** (`be9303a`; §9.4 RP-1/RP-3, the first EXTENDED behaviour change). POOL pin at `check_if_selected` (node.cpp) + `check_creator_selection` (validator.cpp:86, epoch_index hoisted) + `check_abort_certs` (validator.cpp:234) via `select_committee_pool` (+ refugee branches); IDENTITY pin at the 6 validator block-acceptance sites (validator.cpp:69/161/326/362/388/482) via `resolve_committee_member_pubkey`/`committee_member_registered` (+`const Chain&` on 4 check-fn signatures) — mandatory because pool-only is fork/HALT-broken under mid-epoch drift (RP-1); genesis `sharding_mode=NONE ⇒ initial_shard_count==1` fail-closed guard (RP-4, NONE-arm only — CURRENT-multishard stays valid, the pin gates on `shard_count()` not `sharding_mode`). Review-driven fix: RPC previews `next_creators`/`rpc_committee` routed through `select_committee_pool` (operator-truth). | Build clean MSVC + WSL2/GCC; **FAST 222/0 BOTH platforms** (every SINGLE/CURRENT golden byte-identical — zero production regression); `test-committee-pin` proves the helper drift FIX; **adversarial Review Workflow (10 agents): ZERO confirmed fork/safety defects** (5 findings REFUTED as documented bounded-liveness asymmetries; 1 CONFIRMED RPC-preview drift FIXED). |
| **D3.3b-read STEP 3 ✅** | **Node gossip-identity pin — SHIPPED** (`0a85595`). The 5 node.cpp gossip verifiers (`on_abort_claim`, `on_abort_event`, `on_equivocation_evidence`, `on_contrib`, `on_block_sig_locked`) now resolve committee-member keys frozen-first via `resolve_committee_member_pubkey(chain_, registry_, current_epoch_index(), …)`, so a mid-epoch-drifted honest member keeps participating instead of being spuriously aborted per round (the bounded-liveness gap the STEP-1+2 review flagged — no fork). Present-head fallback preserves every prior behaviour. `on_shard_tip` (node.cpp:1747) beacon re-derivation DEFERS to D3.4/D3.5 (the beacon holds the wrong checkpoints — RP-3). | Build clean MSVC + WSL2/GCC; **FAST 222/0 BOTH platforms** (byte-neutral for SINGLE/CURRENT via the fallback — all FA-liveness/gossip tests unchanged). **The producer+validator+gossip identity/pool pin is now COMPLETE.** |
| **D3.3b-read EXTENDED gate ✅** | **The LIVE EXTENDED cluster gate — VERIFIED** (`3e01640`, `tools/test_extended_epoch_committee.sh`). A real 3-node multi-process SHARD+EXTENDED cluster (M=K=3 us-east, `initial_shard_count=3`, `epoch_blocks=4`) CROSSES epoch boundaries, so committee selection runs on the FROZEN `cc:` checkpoint (`committee_pin_active`==true). Verified run: height 16 / **epoch_index 4** (4 boundaries crossed), **all 3 nodes agree on a settled block — SINGLE head, NO FORK**, sustained liveness, committees well-formed K=3. This is the end-to-end proof that the producer-selected frozen committee == the one every validator re-derives. **D3.3b-read is now fully verified.** (Remaining nice-to-have, non-blocking: a unit-level block-acceptance DANGER/FIX under injected mid-epoch drift; the helper drift-FIX is already proven by `test-committee-pin`, and the live cluster exercises the frozen path end-to-end.) | SINGLE/CURRENT goldens byte-identical + FAST 222/0 both platforms + this LIVE EXTENDED boundary-crossing cluster (single head, no fork, epoch_index≥1). Shared harness pattern with the D3.5 beacon-emission gate. |
| **D3.4 ✅** | **`eligible_count` u32 digest-bound source-block field — SHIPPED.** A net-new `Block::eligible_count` = the source shard committee's contemporaneous `registry_.eligible_in_region(committee_region)` at the block head. Populated ONLY by `Node::current_source_eligible_count()` (node.cpp), gated **`chain_role==SHARD && sharding_mode==EXTENDED`** (RP-4/§9.2-pt2 — see the review-fix note below); threaded as a defaulted trailing `build_body` param to the 3 node.cpp producer sites. Bound with a zero-skip conditional append (`if != 0`, widened to u64, appended LAST) in ALL THREE digest/hash sites — `compute_block_digest` (producer.cpp), `light_compute_block_digest` (light/verify.cpp mirror), AND `Block::signing_bytes()` (block.cpp, shared into determ-light) — so the K-of-K committee signature attests the count AND it is part of block identity (the `signature_form`/`partner_subset_hash` precedent). `to_json`/`from_json` emit/parse only when non-zero (u32 range-guarded, fail-closed on overflow). A produced SHARD block always has eligible_count ≥ K ≥ 1, so zero is an unambiguous "unpopulated" sentinel. **The count is CONTEMPORANEOUS present-head eligibility (the distress metric), NOT the epoch-frozen D3.3b selection pool — finding-2 keeps these distinct.** Value-correctness vs the registry is deferred to D3.5 fold-in + D3.6 admission; D3.4 only BINDS it. | `test-eligible-count` (14 assertions): zero-skip wire round-trip (count 0 elided → byte-identical pre-D3.4 JSON); u32 range guard (2^32/2^40 fail closed); u32-max round-trip; hash + digest zero-skip identity (count 0 ≡ pre-feature) AND binding (count 3 ≠ count 0); tamper (forging 2→8 changes BOTH the signed digest and the block hash); determinism (equal blocks → identical digest). The two digest mirrors kept byte-parity by `test_block_digest_xbinary_parity.sh` (+ ELIGIBLE_COUNT token, 17-token canonical seq, SELFTEST green). **FAST 223/0 BOTH platforms** (MSVC + WSL2/GCC); every SINGLE/CURRENT block hash/digest/roundtrip/state-root golden byte-identical; adversarial-review Workflow (6-lens finders + per-finding refute-by-default verify) GO. |
| **D3.5** ⚠️ | **Beacon producer emission — SPLIT into Layer 1 (D3.5a-d, byte-neutral, ships now) + Layer 2 (D3.5e, OWNER-GATED) by the §9.6 feasibility finding.** ~~"fold-in re-derives the source committee from `c:` + verifies source K-of-K"~~ is **UNIMPLEMENTABLE as written** — the beacon holds only its OWN `committee_checkpoints_` (the beacon committee), and the compact `ShardTipRecord` carries no source block/sigs; re-deriving via `select_committee_pool`/`chain.committee_checkpoints()` inside `on_shard_tip` resolves the BEACON's own committee ⇒ a deterministic-but-semantically-WRONG accept. **Layer 1 (D3.5a `shard_tip_records` Block field + digest binding; D3.5b `t:` fold + reorg-safe lazy-capture; D3.5c BEACON&&EXTENDED-gated emission; D3.5d F2 reconciliation over an ACCUMULATING `pending_shard_tip_records_` buffer, full-content-hashed Phase-1 view, full-K intersection):** the source K-of-K rides the CONTEMPORANEOUS `on_shard_tip` check, and the beacon commits the RESULT (`t:` leaf) → S-036 **strongly mitigated**. **Layer 2 (D3.5e, the reopened 5th fork):** a `sc:` cross-chain source-committee-checkpoint transport + beacon-genesis per-shard `K_0^s` trust root → S-036 **closed**. | LIVE EXTENDED: records appear when a shard drops below `2K`; SINGLE/CURRENT: zero records + unchanged `state_root` (gate BEACON&&EXTENDED, never `shard_count()>1` — RP-4/§9.5 on the beacon side); two beacons with divergent tips produce the identical reconciled set (no S-047 wedge). Adversarial review of the reconciliation. |
| **D3.6** | **`validate_merge_event_historical` admission gate** in the MERGE_EVENT BEGIN branch (EXTENDED-only, BEGIN-only, after the shipped arithmetic bounds): read committed `t:` over the window; accept only on contiguous sub-`2K` source-attested coverage; **uniform fail-closed on any absent in-window record** (`A_beacon_omit`); fail-closed if the window predates the ring. | D3.7 repro red→green; `test_under_quorum_merge.sh` still green; FAST both platforms. |
| **D3.7** | **Deterministic S-036 falsifier** — `SeededRng` + virtual harness: healthy source + captured beacon false-window MERGE_BEGIN → **rejected**; genuinely-distressed source (contiguous sub-`2K` + checkpoint-authenticated sigs) → **accepted**; **rogue-registered-signer** → rejected by the `c:` selection check; **snapshot-node vs archive-node admission → identical verdict**. FORGE/WINNER/REPLAY cases. | red on pre-D3.6, green after; replay-twice-identical; LIVE EXTENDED merge still fires on legitimate distress. |
| **D3.8** | **Docs + proof** `ShardTipMergeSoundness.md` (encode round-trip; `t:`+`c:` determinism; empty-set/non-EXTENDED byte-neutrality; epoch-checkpoint inductive authentication back to `K_0`; source-count unforgeability; snapshot/archive admission agreement; historical-accept-predicate soundness; blast radius). Flip SECURITY.md S-036 + `S036UnderQuorumMerge.md` F-1 → **CLOSED**; fix the stale `validator.cpp:772-776` citations. | proofs-index + link-check + doc-tier + citation-bounds green. |

**Residual owner sub-fork: ⚠️ REOPENED (this §9 line was WRONG — see §9.6).** The
claim below addressed only the SHARD's self-verification (D3.3b, sound). It silently
assumed the same `cc:` machinery lets a BEACON re-derive a SOURCE shard's committee-at-
height — it does NOT (the beacon holds only its OWN `committee_checkpoints_`; three
independent code-confirmed causes in §9.6). So trustless S-036 closure needs a genuine
5th owner fork, and the owner's prior "full closure" mandate was made under this
falsified no-fork premise. Superseded text kept for provenance: ~~"The one candidate
(full ordered eligible-set per epoch vs a registry-delta + intra-epoch replay) is not a
real fork … the selection-pool pin is inside the owner's authorized full-closure scope
… a net correctness improvement."~~ (That remains true of the D3.3b SHARD pin; it is the
BEACON-verifies-SOURCE step that carries the reopened fork.)

### §9.5 D3.4 review + the RP-4 gate correction (2026-07-13) — `shard_count()>1` → `sharding_mode==EXTENDED`

The D3.4 adversarial-review Workflow (6 diverse-lens finders + per-finding refute-by-
default verify) surfaced ONE unanimous critical defect (confirmed by 5 lenses
independently, 6 confirmed findings, 1 refuted): the first-cut D3.4 gate keyed the
`eligible_count` self-report on **`chain_.shard_count() > 1`**, mirroring D3.3b's
`committee_pin_active`. That is WRONG for a byte-affecting field. **`ShardingMode::CURRENT`
is a shipped MULTI-shard mode** — `PROFILE_REGIONAL` (`params.hpp`) is `chain_role==SHARD
+ sharding_mode==CURRENT` with `shard_count>1`, and the CURRENT genesis arm permits
`initial_shard_count>1` (only NONE forbids it). So a CURRENT-multishard block passed the
bare `shard_count>1` gate → got a non-zero `eligible_count` → diverged its hash/digest/JSON
from the pre-D3.4 form → **broke every regional golden AND hard-forks a rolling upgrade of a
live regional cluster**. This is exactly the §9.2-pt2 warning ("gate on `sharding_mode ==
EXTENDED`, NOT `chain_role` / `shard_count_`") that RP-4 encoded but the first-cut helper
mis-implemented. **Fix:** `Node::current_source_eligible_count()` now gates on
`chain_role==SHARD && sharding_mode==EXTENDED` (the RP-4 assertion is NOT added to the
CURRENT genesis arm — that would wrongly forbid the supported PROFILE_REGIONAL; the gate,
not a genesis reject, is the fix).

**Ridealong — the same bug class in the shipped D3.3b fold.** The chain-layer epoch-committee
fold (`cc:` leaf, D3.3b-write) gates on `shard_count_>1 && epoch_blocks_>0` — and the Chain
CANNOT see `sharding_mode`. Since the node set `chain_.epoch_blocks_` *unconditionally*, a
CURRENT-multishard chain also folded a `cc:` leaf past its first epoch boundary → `state_root`
divergence (latent: the shipped `test-committee-fold` only exercised SINGLE, and
`test_regional_shards` never crossed block 1000). **Fix:** the node now hands the Chain a
non-zero `epoch_blocks` ONLY under EXTENDED (`chain_epoch_blocks = EXTENDED ? cfg_.epoch_blocks
: 0`), so under CURRENT the fold's own `epoch_blocks_>0` gate is false → no fold → no `cc:`
leaf → `committee_pin_active` false (no checkpoint) → the read pin falls back to present-head.
`chain_.epoch_blocks_` is consumed ONLY by the fold; `current_epoch_index()` reads
`cfg_.epoch_blocks` at the node, so the node's epoch counter is unaffected.

**Regression (the review's flagged coverage gap):** `tools/test_current_multishard_byte_neutral.sh`
— a live 3-node CURRENT (`sharding_mode=1`) + SHARD cluster, `initial_shard_count=3`, empty
region, `epoch_blocks=4`, crossing 4 epoch boundaries: asserts **no block carries
`eligible_count`**, the node's `epoch_index` advanced (non-vacuous), sustained liveness, and
NO fork. RED on the pre-fix tree, GREEN after. The EXTENDED twin
(`test_extended_epoch_committee.sh`) still folds + keeps a single head (fix preserves EXTENDED).
The refuted finding (a maximally-distressed EXTENDED block with live `eligible_in_region==0`
yielding `eligible_count==0`, indistinguishable from unpopulated) is a DOWNSTREAM D3.6
distress-detection semantics point (absence/0 = silence = a legitimate merge trigger per §3.5),
not a D3.4 byte-neutrality break — tracked for D3.6, out of scope here.

### §9.6 D3.5 feasibility finding (2026-07-13) — the reopened 5th owner fork + the Layer 1 / Layer 2 split

A code-grounded feasibility Workflow (4 probes + a high-effort resolver) on the D3.5 fold-in
soundness crux (§4) reached a decision-forcing conclusion: **full trustless S-036 closure is
NOT dischargeable on the shipped D3.1-D3.4 substrate**, and the §9 "Residual owner sub-fork:
none" line was WRONG (§9 corrected above). `Node::on_shard_tip` (node.cpp:1759-1866) cannot
reconstruct the SOURCE shard's committee-at-height as a pure function of committed BEACON state
— three independent, code-confirmed causes:
1. **Pool from the wrong registry.** It derives the pool from `build_from_chain(chain_,
   chain_.height())` (node.cpp:1793) — the BEACON's own registrants at PRESENT head — and
   verifies sigs against `beacon_reg.find(creator).pubkey` (node.cpp:1847) = "the beacon said
   so." Beacon and shard are separate state machines sharing only genesis; post-genesis each
   applies its own REGISTER/DEREGISTER/STAKE/UNSTAKE/slash, so the pools diverge (cross-chain
   delta tracking is the UNIMPLEMENTED "B2c.2-full", node.cpp:1670 — adversary-controllable).
2. **Per-chain suspension.** `abort_records()` is beacon-round-scoped, not shard-round-scoped,
   so even an identical registrant set yields a different eligible pool.
3. **No source trust root.** `committee_checkpoints_` is one per-chain map holding the BEACON
   committee (chain.cpp:293/1811); beacon genesis pins no per-source-shard `K_0^s`. The `cc:`
   checkpoint resurrects V-commit for a chain verifying ITS OWN committee (D3.3b) — NOT for a
   beacon verifying a SOURCE committee. (This is the conflation the §9 no-fork line made; the
   D3.3b-read STEP 3 row already deferred `on_shard_tip` to D3.5 for exactly this, RP-3.)

**Resolution — ship in two layers:**
- **LAYER 1 (D3.5a-d) — implementable NOW, byte-neutral, no new owner decision, a prerequisite
  for BOTH options.** The beacon verifies each source tip CONTEMPORANEOUSLY in `on_shard_tip`
  (post-D3.4 the K-of-K digest covers `eligible_count`), and commits the RESULT (`t:` leaf +
  count) into `state_root`; D3.6 admission re-derives NOTHING. The fold set is made deterministic
  across divergent beacon co-signers by transplanting the shipped F2 inbound-receipt machinery.
  Lands S-036 at **STRONGLY MITIGATED** (residual = a SUSTAINED captured-beacon-committee over
  the merge window + source-key-compromise + the source-registry-divergence attack + `A_beacon_omit`
  withhold — strictly harder than today's single-block fabrication).
  - **D3.5a ✅ SHIPPED** `std::vector<ShardTipRecord> shard_tip_records` Block field; empty-skip
    root (`compute_view_root` over per-record `SHA256(rec.encode())` via a `hash_shard_tip`
    helper) bound LAST in all 3 digest mirrors + `signing_bytes` + the parity guard (18th token,
    `SHARD_TIP_RECORDS`). Unpopulated (`build_body` does not set it yet) ⇒ byte-identical (twin of
    the D3.4 `eligible_count` step). `test-shard-tip-records` (15 assertions incl. order-independence
    + tamper); MSVC FAST 224/0; every block hash/digest/roundtrip/state-root golden byte-identical.
    Ridealong lessons: the per-record hash must be a `hash_shard_tip` HELPER, not an inline
    `SHA256Builder{}.append(...).finalize()` — the latter carries a `.append(`+`.finalize()` on one
    line that the xbinary-parity extractor misreads as a digest append + the terminal finalize;
    and `to_hex` has only `(ptr,len)`/fixed-array overloads (no `std::vector`), so encode() bytes
    hex via `to_hex(enc.data(), enc.size())`.
  - **D3.5b ✅ SHIPPED** `Chain::apply_transactions` folds `b.shard_tip_records` via the shipped
    `add_shard_tip_record` ring → `t:` leaves, placed before the S-033 recompute so the leaves
    bind into `state_root`; the reorg-safe `__ensure_shard_tip_records()` lazy-capture (twin of
    `__ensure_committee_checkpoints`) snapshots the pre-fold ring into `__snapshot` so both the
    failed-apply `catch` (`restore_state_snapshot`) and A4 `revert_head` (via `prev_head_snapshot_`)
    restore it — D3.2 already wired the `restore` side (chain.cpp:734-735). CONTENT-DRIVEN, NO
    `shard_count_` gate: an empty vector folds zero leaves (only a BEACON+EXTENDED producer
    populates it at D3.5c), so SINGLE/CURRENT stay byte-identical. `test-shard-tip-fold` (11
    assertions: content-driven fire on SINGLE, empty-set byte-neutral, a record changes state_root,
    Chain::load replay re-folds, revert_head rolls back the ring + re-append idempotent). FAST
    225/0; state-root + snapshot goldens byte-identical.
  - **D3.5c** the SOLE byte-affecting step: `build_body` populates the vector ONLY when
    `chain_role==BEACON && sharding_mode==EXTENDED` (copy the D3.4 gate verbatim — **never
    `shard_count()>1`**, which would hard-fork a legal CURRENT-multishard PROFILE_REGIONAL beacon).
  - **D3.5d** F2 reconciliation (else S-047 wedge): a NEW ACCUMULATING `pending_shard_tip_records_`
    keyed by (shard,height) (NOT `latest_shard_tips_`, a last-value register); signed Phase-1 view
    = FULL-CONTENT hash of each record tuple; **full-K `reconcile_intersection`** (never a
    threshold); new digest/contrib fields conditional-on-empty.
    - **D3.5d-i ✅ SHIPPED** — the SIGNED-VIEW SUBSTRATE (the S-043-class piece). `ContribMsg`
      gains `view_shardtip_root`/`view_shardtip_list`; `make_contrib_commitment` binds the root
      behind its own **`DTM-STV-v1`** domain tag AFTER the `DTM-TS-v1` proposer_time tail, ONLY
      when non-zero (every non-beacon / pre-D3.5 contrib keeps a byte-identical commitment); the
      msg-form overload carries it (covers `Node::on_contrib`); the validator field-form recompute
      (validator.cpp:200) passes `vr_at(b.creator_view_shardtip_roots, i)` — the S-043 symmetry
      edit. `Block` gains `creator_view_shardtip_roots`/`_lists`, emitted under their OWN
      `any_shardtip_root` gate (authenticated via `creator_ed_sigs` → `signing_bytes`, so NO
      compute_block_digest / light-mirror / parity-token change is needed — that is why the light
      digest is untouched). `validate_contrib_view_roots` was refactored into two INDEPENDENT
      presence-gated groups (F2 eq/abort/inbound V21-V24; shard-tip V21 cap + **V25** root==list)
      so a shard-tip-only contrib is not spuriously rejected by `compute_view_root([]) != Hash{}`.
      `build_body` pushes the per-creator view (empty until D3.5d-ii fills the buffer → byte-neutral).
      `test-contrib-wire-verify` extended 9→18 assertions (sign → wire → msg-form recompute →
      verify; the pre-D3.5 8-arg recompute REJECTS; transit tamper rejects; byte-neutral for
      non-shard-tip contribs; V25 accept/reject). FAST 225/0 both platforms; adversarial-review
      Workflow clean.
    - **D3.5d-ii** (next) the RECONCILIATION WIRING: the `pending_shard_tip_records_` buffer +
      `on_shard_tip` population; `make_contrib` Phase-1 call-site passes the buffer view;
      `build_body` folds `reconcile_intersection(b.creator_view_shardtip_lists)`; a new validator
      `check_shardtip_reconciliation` enforcing `shard_tip_records ⊆ intersection`.
- **LAYER 2 (D3.5e) — the reopened 5th OWNER FORK; do NOT proceed without owner GO.** A `sc:`
  cross-chain source-committee-checkpoint transport: source shards PUSH their K-of-K-signed per-
  epoch `cc:` checkpoints to the beacon; the beacon commits them under a new `sc:` namespace,
  inductively authenticated back to each source shard's genesis committee `K_0^s` **pinned into
  BEACON GENESIS** (a genesis-format change ⇒ a coordinated migration, NOT rolling-upgrade-neutral
  on an existing EXTENDED beacon), snapshot-inherited; `on_shard_tip` re-derives the source
  committee from `sc:[source,E].members` RE-SEEDED from committed `beacon_rand` (NOT the source
  `cc:.epoch_rand`, which is mis-set to the shard block's own rand, chain.cpp:1810). Upgrades
  S-036 strongly-mitigated → **CLOSED**.

**Owner decision (put to Stoyan):** **Option A** authorize the 5th fork (D3.5e `sc:` transport +
beacon-genesis `K_0^s` migration) → S-036 CLOSED, at the cost of a genesis migration + a new
cross-chain protocol + its own review + a live multi-shard→beacon cluster gate. **Option B** ship
Layer 1 only → S-036 STRONGLY MITIGATED, zero new trust root, no migration; correct SECURITY.md
S-036 + `S036UnderQuorumMerge.md` F-1 to "strongly mitigated" and widen the §4 residual to include
the source-registry-divergence attack. The prior "full closure" mandate was made under the now-
falsified §9 no-fork belief; Option A is its true cost, Option B the honest fallback. **Layer 1
(D3.5a-d) is a prerequisite either way.**

**Pre-code hazards (the D3.3b §9.2 analog — each would be a consensus bug):** the D3.5c emission
gate MUST be `BEACON&&EXTENDED` not `shard_count()>1` (RP-4 replayed on the beacon); D3.5b MUST add
the reorg-safe lazy-capture twin; the fold + Phase-1 view MUST read the accumulating
`pending_shard_tip_records_` (a (shard,height) key unanimous in Phase-1 can be non-materializable
at Phase-2 from the last-value `latest_shard_tips_` register → fork); the Phase-1 view element MUST
be a full-CONTENT hash (key-only lets source equivocation fold two different `t:` values behind one
unanimous key); use full-K intersection never a threshold; the shard→region map (`shard_committee_regions_`,
node.cpp:454) is manifest-FILE config not committed state — a region-filtered fold verdict needs it
committed to beacon genesis/state first; bind in ALL THREE digest mirrors + add the parity token;
D3.6 must fail-closed uniformly on any absent in-window record (`A_beacon_omit`, survives Layer 1,
closes only under Option A).

### §9.2 Feasibility-verdict corrections (2026-07-12) — three fixes to the §9 mechanism

A code-grounded feasibility Workflow verified the pin + specified the checkpoint and
surfaced three corrections that would otherwise have been consensus bugs:

1. **`build_from_chain(anchor)` does NOT reconstruct — the pin must read the `cc:`
   checkpoint.** `NodeRegistry::build_from_chain(chain, at_index)` gates only
   `active_from`/`inactive_from`; it reads `stake()` and `abort_records()` **present-head**
   (`src/node/registry.cpp:42-63`). So `build_from_chain(chain_, epoch_anchor)` evaluated at
   a later head still drifts if a member's stake/suspension changed mid-epoch — it does not
   achieve checkpoint-reconstructibility. The pin therefore sources the frozen member set
   from `committee_checkpoints_[current_epoch]` (D3.3a), not from a re-computation.
2. **Gate on `sharding_mode == EXTENDED`, NOT `chain_role == SHARD` / `shard_count_`.**
   `on_shard_tip` is BEACON-role-only (`node.cpp:1692`), so a `SHARD`-role gate would leave
   the beacon verifier (`node.cpp:1724`) on the present-head pool — the exact divergence the
   pin closes. `sharding_mode` is carried on both the node (`cfg_.sharding_mode`) and the
   validator (`sharding_mode_`), role-agnostic, and is `CURRENT` in SINGLE → every gated
   branch is skipped in SINGLE (byte-identical). CONFIRMED break case: with default
   `epoch_blocks=1000`, an unconditional pin gives a SINGLE golden under height 1000
   `epoch_anchor==0` → the genesis-only pool → a different committee (`select_m_creators` over
   a different `avail_domains`, `node.cpp:922`) → a different digest → every such golden breaks.
3. **Leaf prefix is `cc:`, not `c:`.** `c:` already appears as the A1 counter leaves
   (`k_with_prefix("k:","c:genesis_total")` → wire key `"k:c:…"`, `src/chain/chain.cpp`);
   a bare top-level `"c:"` is byte-safe (differs in byte 0) but a confusion footgun, so the
   checkpoint uses `cc:`. The §9 body's "`c:`" wording is superseded by `cc:`.

Fold-in timing (D3.3b): freeze epoch E's checkpoint when appending the **last block of epoch
E−1** (`(height+1) % epoch_blocks == 0`), so `head` == the rand-anchor block
`E·epoch_blocks − 1` and `build_from_chain(head)` is a contamination-free pure function whose
pool anchor equals the seed anchor (`current_epoch_rand`/`resolve_epoch_rand` read
`epoch_start − 1`). NOT the existing observability hook at `node.cpp:2120-2130`
(`height % epoch_blocks == 1`, one block too late — it would bake the present-head drift into
the leaf). Epoch 0 is folded at genesis (genesis-anchored, matching `current_epoch_rand`).

**D3.1 + D3.2 remain valid substrate under this mechanism and proceed now.**

### §9.3 Fold-in placement resolution (2026-07-12) — the D3.3b `cc:` populate must live in the CHAIN apply path

A second code-grounded Workflow (3 parallel probes + a resolver, all re-read against
the tree) resolved *where* the D3.3b fold-in mutates `committee_checkpoints_` and how
`epoch_blocks` reaches the Chain layer byte-neutrally. This supersedes §9.2's implicit
"`build_from_chain(chain_, height())` after append" phrasing with a precise, fork-safe
insertion.

> **AS-BUILT (D3.3b-write, shipped `924859f`/`df89677`/`e221147`):** implemented as
> **Site A only** — the genesis epoch-0 fold (FR-2 Site B below) was **DROPPED** because
> the genesis ctor applies before the node sets `epoch_blocks_`/`shard_count_`, so an
> epoch-0 fold would diverge bootstrap-vs-reload. The first checkpoint is therefore epoch
> 1 at block `epoch_blocks−1`; epoch 0 is uncheckpointed (fail-closed at the D3.6 gate,
> never a fork). Everything else below (FR-1, FR-3, FR-4, H-1..H-5) shipped as written.
> The read-side pin (steps 4-5) remains pending — see the D3.3b-read increment row.

**FR-1 — the fold-in MUST live inside `Chain::apply_transactions`, not a Node hook.**
`apply_transactions` (chain.cpp:765) is the *only* per-block mutator common to all five
committed-state paths: ctor-genesis (chain.cpp:47, **direct** call — bypasses `append`),
`Chain::append` (54), store-reload replay (2648), legacy `chain.json` replay (2717), and
the node append/reorg paths. `append` is **not** sufficient — the ctor and both `load`
loops call `apply_transactions` directly. The node hook `post_append_bookkeeping_locked`
(node.cpp:2037/2257) runs on the live/reorg paths only, so a node-side fold leaves
`committee_checkpoints_` empty after a chain-blocks-v1 reload → the `cc:` leaves (D3.3a,
already in `state_root`) differ → the S-033 recompute-and-reject (chain.cpp:1762-1774)
throws → **the node cannot reload its own EXTENDED chain.** CONFIRMED hard break.

**FR-2 — two insertion sites, pure functions of the block.**
- *Site A (steady state):* end of the `apply_transactions` try-body, before
  `publish_committed_view()` (chain.cpp:1805), gated
  `shard_count_ > 1 && epoch_blocks_ > 0 && (b.index + 1) % epoch_blocks_ == 0`; freeze
  epoch `E = (b.index+1)/epoch_blocks_` with `epoch_rand = b.cumulative_rand` (read off
  the block being applied — the rand anchor `E·epoch_blocks−1`, no `blocks_` lookup) and
  `members = freeze_epoch_committee(b.index)`.
- *Site B (epoch 0):* the genesis branch, before the early `return` (~chain.cpp:864),
  gated `shard_count_ > 1 && epoch_blocks_ > 0`; freeze epoch 0 (genesis-anchored).

**FR-3 — reorg is safe by construction.** `revert_head → restore_state_snapshot` already
restores `committee_checkpoints_` (chain.cpp:736-737, wired by D3.3a). A re-appended
resolve_fork winner re-enters `apply_transactions` with the same `b.index` / committed maps
/ `b.cumulative_rand` → identical `freeze_epoch_committee` output → identical `cc:` leaf →
`state_root` matches. `add_committee_checkpoint` overwrites `[E]` (idempotent) — **contingent
on hazard H-1 below.**

**FR-4 — eligible-set layering = Option B (a private Chain helper), NOT moving
`build_from_chain`.** `NodeRegistry::build_from_chain` (registry.cpp:25-78) reads only four
Chain accessors (`registrants()/stake()/min_stake()/abort_records()`) + `at_index` — a pure
function of committed Chain state. But *moving* it is over-scoped (~11 node/validator + ~30
test call sites consume the node-layer `NodeRegistry` return type → a layering inversion),
and `chain.cpp #include node/registry.hpp` closes a node→chain→node cycle. **Add instead a
~15-20-line private `Chain::freeze_epoch_committee(uint64_t at_index) const →
std::vector<CommitteeMember>`** that iterates `registrants_` applying the identical
4-predicate filter via `this->` and emits `CommitteeMember{domain, ed_pub, region}` straight
from the map key + `RegistryEntry`. The checkpoint is region-**UN**filtered; region-filter +
seed-mix stay on the read side. `select_m_creators` is untouched (it consumes the pool, it
does not freeze it). **`at_index = b.index` is the frozen, permanent convention** (block
applied but not yet in `blocks_`; a registrant with `active_from == b.index+1` is correctly
excluded until epoch E begins).

**Five fork-class hazards (all must be handled in D3.3b):**
- **H-1 (fork-class): add a `__ensure_committee_checkpoints()` lazy-capture lambda.**
  `apply_transactions` has ensure-lambdas for stakes/registrants/abort_records/merge_state/…
  (chain.cpp:779-814) but **none** for `committee_checkpoints_`. `create_state_snapshot`
  captures lazily (the `StateSnapshot` field is `std::optional`; restore at 736-737 only fires
  when `Some`). Without an ensure-lambda called *before* the fold mutates the map, a
  failed-apply rollback (catch at 1816) **or an A4 revert across an epoch boundary** will not
  restore the pre-fold map → `state_root` corruption. Easy to miss; itself fork-class.
- **H-2 (fork-class): `epoch_blocks` must be a genesis-pinned Chain member set BEFORE replay
  — threaded like `block_subsidy_`'s CONSTRUCTION path but, unlike `block_subsidy_`, NOT
  emitted as a `const_leaf`.** Today it is node/validator-only (`cfg_.epoch_blocks`,
  validator.cpp:103); it defaults to **1000**, never 0 (genesis.cpp:191, node.cpp:101) and is
  already genesis-hash-bound (genesis.cpp:469). Add `uint32_t epoch_blocks_{0}` to Chain and
  set it *before* the replay loops on every reloading path — ctor from `GenesisConfig`; a new
  `Chain::load` param at chain.cpp:2635-2638 / 2683-2695; serialize+restore in
  `serialize_state`/`restore_from_snapshot` before that path's own state_root verify
  (chain.cpp:2394-2399) — exactly the `block_subsidy_` "must be set before replay" precedent
  (chain.cpp:2691). A post-`load` node setter runs too late for the internal replay's S-033
  recompute. **CORRECTION to the resolver's own phrasing:** it said "mirror `block_subsidy_`
  … NOT a `const_leaf`," but `block_subsidy_` **IS** a `const_leaf` (chain.cpp:467). The
  intent stands and is what matters: `epoch_blocks_` must be threaded like `block_subsidy_`
  for *construction/load/snapshot* yet **must NOT be emitted as a leaf** — an unconditional
  `const_leaf("epoch_blocks", …)` would grow every CURRENT chain's leaf set by one → S-033
  throw on first reload (S-039 break). No leaf is needed; the `cc:` leaves already bind the
  freeze outcome.
- **H-3 (gate unification): the fold gate is `shard_count_ > 1` (chain-visible), and the D3.3b
  READ-side pin must gate on the SAME `chain_.shard_count() > 1`, not the node's
  `sharding_mode`.** `shard_count_` is already a Chain member set before replay AND already a
  `const_leaf` (chain.cpp:477), so the gate adds zero byte-surface and reuses the shipped
  "empty `cc:` ⇒ byte-identical" invariant (chain.hpp:403, main.cpp:11270). §9.2's point-2
  said gate on `sharding_mode==EXTENDED`; that is right for *role-agnosticism* but Chain
  cannot see `sharding_mode` during replay — so the authoritative predicate that `state_root`
  commits is `shard_count_ > 1`, and the read side must pin to it too. Add a fail-closed
  genesis-load assertion `(_sharding_mode==EXTENDED) ⇔ (shard_count > 1)` so no chain can have
  `shard_count>1` under a CURRENT-posture node.
- **H-4 (drift-fork): de-dup the three suspension constants.**
  `BASE_SUSPENSION_BLOCKS / MAX_SUSPENSION_BLOCKS / MAX_ABORT_EXPONENT` live ONLY in
  include/determ/node/registry.hpp:19-21. `freeze_epoch_committee`'s `is_suspended` filter must read the
  SAME definitions `build_from_chain` uses; a copied literal becomes a latent `state_root`
  fork the instant the node constants are retuned. Move them to
  `include/determ/chain/params.hpp` (already included by registry.cpp:5); both consumers
  reference the one definition.
- **H-5 (do NOT reuse the observability hook).** node.cpp:2125-2135 fires at
  `(height-1) % epoch_blocks == 0` (one block late, present-head, node-only) — the WRONG
  anchor. Leave it a pure log.

**Revised D3.3b step order:** (0) de-dup suspension constants → (1) pin `epoch_blocks_` onto
Chain (member + load-param + snapshot, no leaf) → (2) add the `__ensure_committee_checkpoints`
lambda → (3) add `freeze_epoch_committee` + the two fold sites → (4) pin the 3 read sites to
`committee_checkpoints()[E]`, gated `shard_count()>1`, + the genesis-load assertion → (5)
verify: an epoch-boundary reorg reproduces identical ring + `state_root`; a ≥2-epoch EXTENDED
chain reloads via chain-blocks-v1 with no S-033 throw; a `shard_count_==1` chain's `state_root`
stays byte-identical pre/post-D3.3b (extends main.cpp:11270). Gates: FAST both platforms +
LIVE EXTENDED cluster + EXTENDED-golden re-bless + 2-lens adversarial review before commit.

### §9.4 Read-side selection pin (2026-07-12) — the D3.3b-read design (two Workflows, code-grounded)

Two feasibility Workflows (3 parallel probes + a resolver each, all re-read against the
tree) resolved *how* committee SELECTION reads the frozen `cc:` checkpoint. The headline:
the increment table's "pin the 3 read sites" undercounted — pinning only the **pool** is
not merely liveness-broken but **fork/HALT-broken**, because creator IDENTITY (pubkey /
registration) still resolves present-head. **This §9.4 supersedes §9.2 point-2's
`sharding_mode`-gate wording** (the gate is the chain-visible `chain.shard_count()>1`).

**RP-1 — the halt hazard (why identity must move too).** The `registry` a validator uses is
`NodeRegistry::build_from_chain(chain, b.index)` (node.cpp:2034; reorg path 2222), and the
node's `registry_` is `build_from_chain(chain_, height())` (node.cpp:576/2066) — both
return **eligible-only** entries (registry.cpp:60-64), so `registry.find/contains(d)` is
null/false for any domain that deregistered / unstaked / abort-suspended present-head. Under
a pool-only pin, `b.creators` are drawn from the FROZEN set, which can still name such a
member → present-head `find` fails → the block is rejected by every validator → **shard
HALT** (or fork if peers resolve differently). So creator identity MUST also resolve from
the frozen `CommitteeMember.ed_pub`.

**RP-2 — two shared helpers, one gate (shipped STEP 0, `3e35e0d`).**
`include/determ/node/committee_pool.hpp` + `src/node/committee_pool.cpp`, all gated on
`committee_pin_active(chain,epoch) == chain.shard_count()>1 && epoch>=1 &&
committee_checkpoints().count(epoch)` (mirrors the fold gate exactly; chain-visible ⇒
replay-deterministic): (a) `select_committee_pool` — the POOL, **frozen-ONLY** (it defines
selection), region-filtered mirroring `eligible_in_region` exactly (empty ⇒ all; else
`==`; order-preserving — frozen members are domain-sorted like `build_from_chain`'s insert
order, so `select_m_creators` indices match); (b) `resolve_committee_member_pubkey` /
`committee_member_registered` — IDENTITY, **frozen-FIRST then present-head fallback** (a
mid-epoch-drifted member verifies on its frozen key; a non-committee / cross-epoch
equivocator stays slashable). Two different sets (pool = frozen-only, identity =
frozen∪present-head) ⇒ a single augmented registry cannot serve both. `test-committee-pin`
(15 assertions) proves the gate, the no-drift byte-equality with present-head, and the
DRIFT FIX. Off the pinned path (SINGLE, epoch 0, pruned epoch) everything falls back to
present-head, byte-identical.

**RP-3 — scope (three tiers).**
- **MANDATORY, ship atomically (fork-critical):** POOL pin at the 3 local-shard sites +
  refugee branches — `check_if_selected` (node.cpp:862,873), `check_creator_selection`
  (validator.cpp:86,96), `check_abort_certs` (validator.cpp:234,241); IDENTITY pin at the 6
  validator block-acceptance sites — `check_creators_registered` (69), tx-commitments (161),
  abort-cert claimer (326), equivocator (362), dh-secrets (388), block-sigs (482) — each
  via the shared helpers, adding `const chain::Chain& chain` to the 4 check-fn signatures;
  the genesis fail-closed assertion.
- **RECOMMENDED same increment (liveness, not fork-critical, deferrable):** IDENTITY pin at
  the 5 node.cpp gossip handlers (1450/1546/1574/2444/2609) — without them an honest
  drifted member is spuriously aborted every block for the rest of the epoch (bounded
  degradation, all nodes drop identically ⇒ no fork).
- **DEFERRED to D3.5 / OUT of scope:** `on_shard_tip` (node.cpp:1729) + `on_beacon_header`
  (1638) — the BEACON holds only `latest_shard_tips_` + its OWN `chain_`, whose
  `committee_checkpoints()` are the WRONG set; pinning it to the beacon's own checkpoints
  would be a BUG. It needs D3.4 `eligible_count` transport + D3.5 source K-of-K. Tx-sender
  `registry.find(tx.from)` (validator.cpp:645/678/893/1119) stays present-head. Informational
  displays (node.cpp:2135 log, 2888 next_creators) may stay present-head; `rpc_committee`
  (3156) is a recommended operator-truth mirror only.

**RP-4 — the genesis fail-closed assertion.** `sharding_mode` is a `NodeConfig` field
(node.hpp:129), NOT in `GenesisConfig`; `initial_shard_count` IS (genesis.hpp:214). Add to
the existing `switch(cfg_.sharding_mode)` at node.cpp:295-354: the EXTENDED arm already
throws on `initial_shard_count<3`; add `initial_shard_count>1 ⇒ throw` to the NONE and
CURRENT arms, giving `(sharding_mode==EXTENDED) ⇔ (shard_count>1)`. Pure startup throw —
never changes apply behavior (SINGLE byte-neutral). Caveat: it newly rejects any pre-existing
NONE/CURRENT genesis with `shard_count>1` (intended fail-closed) — audit fixtures first.

**RP-5 — the suspension-timing tradeoff (owner-relevant, but NOT a safety hole).** Per-epoch
freezing means abort-SUSPENSION (and mid-epoch deregister / unstake) of a frozen member
takes effect at the **next epoch boundary (E+1)**, not immediately — the member stays in
`checkpoint[E].members` and remains selectable for the rest of epoch E. This is **inherent to
the per-epoch checkpoint mechanism the owner authorized** (full closure via per-height
snapshots) and is **not a safety regression**: (1) equivocation — the safety-critical fault —
is still detected + slashed IMMEDIATELY and independently of committee membership
(`check_equivocation_events` verifies the two conflicting sigs cryptographically;
`on_equivocation_evidence` gossips it; apply forfeits full stake); (2) a member gone
unavailable mid-epoch is still excluded PER ROUND via the `current_aborts_` / `b.abort_events`
path (independent of the frozen pool); (3) BFT escalation still guarantees progress each
block. The ONLY delayed effect is the chain-baked exponential-backoff SUSPENSION that avoids
*re-selecting* a known-faulty (but non-equivocating) node — bounded to ≤ `epoch_blocks`
blocks of one-extra-abort-round-per-block before it takes hold at E+1. A bounded
liveness/throughput tradeoff, the standard epoch-committee posture (frozen validator set per
epoch; slashing immediate; membership changes at boundaries).

**Frozen-key liveness edge (STEP 1+2 adversarial review, `be9303a`):** the same
freezing means a committee member that ROTATES its Ed25519 key mid-epoch (REGISTER
over an existing domain overwrites `registrants_[from].ed_pub`, chain.cpp:1160) has
its blocks/sigs verified against the FROZEN pre-rotation key — so the producer signs
with the new key while every validator verifies against the frozen old key ⇒ its
blocks are rejected UNIFORMLY (all validators agree ⇒ no fork) until the next epoch
freezes the new key. Same bounded self-inflicted-liveness shape as
deregister/unstake/suspend, cryptographically sound (no forgery). Operator guidance:
do NOT re-key an EXTENDED validator mid-epoch. Likewise the 5 deferred node.cpp
gossip-identity sites (STEP 3) resolve signers present-head, so a drifted honest
member is aborted per round until the epoch ends — bounded, no fork (all nodes drop
identically); the review REFUTED it as a defect.

**Implementation steps (STEP 0 shipped `3e35e0d`):** STEP 0 ✅ the shared `committee_pool`
helpers + `test-committee-pin` (unwired, byte-neutral). STEP 1+2 (atomic) the POOL pin (3
sites) + IDENTITY pin (6 validator sites, +`const Chain&` on 4 signatures) + genesis
assertion. STEP 3 the 5 node.cpp gossip identity sites. Gates for STEP 1+2: FAST both
platforms (SINGLE byte-identical); `test-committee-pin` extended to block level (a produced
block naming a drifted frozen member passes `check_creator_selection` + `check_creators_registered`
+ `check_block_sigs` + `check_abort_certs`, and the pool-only variant REJECTS it); a fixture
audit (no NONE/CURRENT genesis with `shard_count>1`); a **LIVE EXTENDED cluster** (≥3
region-pinned shards, small `epoch_blocks`, mid-epoch registrant/stake/abort churn → single
head, zero stuck, drifted-but-frozen honest member keeps participating); EXTENDED-golden
**re-bless** (only drift-exhibiting goldens; SINGLE + drift-free EXTENDED stay byte-identical);
2-lens adversarial review — before commit.
