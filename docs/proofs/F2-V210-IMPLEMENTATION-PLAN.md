# v2.7 F2 + v2.10 implementation plan

**Status:** living plan. Sub-steps 0, 1, 3 (helpers only) shipped — see per-sub-step status tags below. v2.10 Phase A frost_verify also shipped as the first FROST primitive.

**Companion docs:**
- `F2-SPEC.md` — v2.7 F2 view-reconciliation design (9 open questions resolved)
- `v2.10-DKG-SPEC.md` — v2.10 threshold-randomness DKG ceremony spec (FROST-Ed25519 on curve25519 family)
- `S030-D2-Analysis.md` — closure analysis of S-030 D2 (apply-layer via S-033 + S-038 partial; consensus-layer via F2 below)

---

## Why a serial plan

These two items are the v1.x → production-deployment-ready gates. Unlike the prior 17 parallel rounds (which built operator tooling, formal proofs, TLA+ specs, wallet diagnostics — work that's intrinsically parallel because it touches disjoint files), v2.7 F2 + v2.10 both require modifying the SAME core files in `src/chain/`, `src/node/`, `src/net/`:

- `include/determ/node/producer.hpp` + `src/node/producer.cpp` — `ContribMsg`, `make_contrib_commitment`, F2 reconciliation
- `src/chain/block.cpp` + `include/determ/chain/block.hpp` — block signing_bytes binding new fields
- `src/node/node.cpp` — `on_contrib`, Phase-1 → Phase-2 transition, view assembly
- `src/node/validator.cpp` — V10/V11 + new V-checks for F2 reconciled fields + v2.10 threshold-sig verify
- `src/net/binary_codec.cpp` — wire-format extension
- `src/chain/genesis.cpp` — v2.10 epoch_public_key + dkg_status

Two agents editing any of these in parallel conflict. So the work is serial.

---

## v2.7 F2 — view reconciliation (~3-4 days estimated)

### Sub-step 0 — Foundation primitives ✅ shipped this session

- `compute_view_root(items)` — Merkle root over sorted SET of hashes
- `reconcile_union(member_lists)` — union dedup, censorship-resistant (one observer suffices)
- `reconcile_intersection(member_lists)` — conservative credit (one missing suppresses)
- Unit test `determ test-view-root` + `tools/test_view_root.sh` (22 assertions across 17 scenarios)
- File touchpoints: `include/determ/node/producer.hpp` + `src/node/producer.cpp` (additive only; backward-compat preserved)

### Sub-step 1 — Extend ContribMsg ✅ shipped

Added three new fields to `ContribMsg`:
- `Hash view_eq_root` — Merkle root over sender's equivocation_events pool snapshot
- `Hash view_abort_root` — Merkle root over sender's local abort observations
- `Hash view_inbound_root` — Merkle root over sender's inbound_receipts pool snapshot
- Plus the actual lists: `std::vector<Hash> view_eq_list`, `view_abort_list`, `view_inbound_list`
  - Each capped at 64 entries per F2-SPEC.md Q3 bandwidth budget (`F2_VIEW_LIST_CAP`)

JSON serialization shipped: optional fields (defaulted to empty + zero-hash when absent), backward-compat with v1 ContribMsg. S-018 wrong-type rejection on `view_eq_list` etc.

`make_contrib_commitment` extended with three optional view-root args (default `Hash{}`). Backward-compat preserved via the **all-zero short-circuit**: when all three view roots are zero, the commit hash is byte-identical to the pre-F2 commit. When any root is non-zero, the `DTM-F2-v1` domain separator is prepended before appending the three roots — prevents v1-sig replay under v2-envelope.

### Sub-step 2 — Producer-side population (~0.5 day, **partially shipped**)

Status:
- ✅ `make_contrib` signature extended with three optional view-list args
  (`view_eq_list`, `view_abort_list`, `view_inbound_list`, all default `{}`).
  When any non-empty, canonicalizes (sort+dedup) + computes Merkle roots +
  populates ContribMsg view fields + binds into the commit hash via the
  extended `make_contrib_commitment` (with `DTM-F2-v1` domain separator).
- ✅ `Node::on_contrib` receive-path updated to thread the message's
  view roots through commit re-derivation — sig-verify path AND the
  S-006 same-generation equivocation-comparison path both now use the
  F2-extended commit shape. v1 contribs (zero view roots) trigger the
  short-circuit and remain byte-identical to pre-F2.
- 🚧 Actual Phase-1 trigger site in `Node::start_contrib_round` still
  passes empty F2 lists (default args). When the snapshot-and-hash code
  lands (snapshot `pending_equivocation_evidence_` / `pending_abort_records_` /
  `pending_inbound_receipts_`, hash each entry, truncate to 64), it gates
  on `block_index >= chain_.genesis().v2_7_f2_active_from_height` and
  pumps the resulting Hash vectors into the existing `make_contrib` call.

The remaining work is local (a ~20-line patch in `Node::start_contrib_round`
plus per-record canonical-hash helpers). Gated by `v2_7_f2_active_from_height`
(already plumbed in `GenesisConfig`); defaults to 0 = active from genesis,
sentinel UINT64_MAX = explicit disable for legacy chains.

### Sub-step 3 — Validator-side V-checks ✅ helpers shipped, wire-in pending

Helpers shipped in `src/node/producer.cpp` as pure unit-testable functions:
- `validate_contrib_view_roots(msg, *reason)` — per-contrib V21..V24
- `derive_canonical_view_lists(contribs)` — applies F2-SPEC §Q1 rules (union for eq+abort, intersection for inbound)
- `validate_view_reconciliation(contribs, block_eq, block_abort, block_inbound, *reason)` — composite V21..V26

V-check assignment as shipped (refined from plan's original):
- V21: bandwidth cap — each `view_X_list.size() <= F2_VIEW_LIST_CAP` (F2-SPEC §Q3)
- V22: `view_eq_root == compute_view_root(view_eq_list)` (Merkle binding)
- V23: `view_abort_root == compute_view_root(view_abort_list)` (Merkle binding)
- V24: `view_inbound_root == compute_view_root(view_inbound_list)` (Merkle binding)
- V25: `block.equivocation_events == reconcile_union(K view_eq_lists)` AND `block.abort_events == reconcile_union(K view_abort_lists)`
- V26: `block.inbound_receipts == reconcile_intersection(K view_inbound_lists)`

v1-compat: if all roots zero AND all lists empty (pre-F2 ContribMsg), the helper returns PASS as a no-op — the validator's height-gate is responsible for deciding whether to accept pre-F2 contribs at the current height.

Wire-in into `src/node/validator.cpp` pending (sub-step 3 completion): call these from the existing V-check pass with `v2_7_f2_active_from_height` gating.

### Sub-step 4 — Migration gate (~0.5 day)

Genesis-pin `v2_7_f2_active_from_height` (uint64; default 0 = inactive). Once activated:
- Producer MUST populate view-roots + lists
- Validator MUST run V21..V26
- Pre-activation blocks remain bound to pre-F2 commit shape (backward-compat)

### Sub-step 5 — Tests (~0.5 day)

- `determ test-f2-reconciliation` — covers full Phase-1→Phase-2→validator round-trip
- `tools/test_f2_consensus.sh` — 3-node cluster with intentionally-divergent views, verify reconciled canonical lists match across all nodes
- Update `tools/test_equivocation_slashing.sh` to exercise the union path

### Sub-step 6 — Docs (~0.5 day)

- `docs/PROTOCOL.md` §6 (consensus protocol): document the extended ContribMsg + V21..V26
- `docs/SECURITY.md` §S-030: D2 closure update (consensus-layer now closed via F2)
- `docs/proofs/Safety.md` §5.3: BFT safety claim updated to drop the D2 footnote
- `docs/proofs/F2-SPEC.md` mark "Status: shipped" with commit ref

---

## v2.10 threshold randomness aggregation — FROST-Ed25519 DKG (~3 weeks estimated)

Per `v2.10-DKG-SPEC.md`, the work is decomposed into 6 phases:

### Phase A — FROST-Ed25519 primitives (2-3 days, **partially shipped**)

Status as of this commit:
- ✅ `frost_verify` — shipped, real implementation. Delegates to existing Ed25519 `verify` from `src/crypto/keys.cpp` per RFC 9591 §3 (aggregated FROST sigs verify as standard Ed25519 `(R||z)` sigs against the group pubkey). Round-trip + tamper-sig + wrong-key + tamper-msg + empty-msg test assertions in `test-view-root`.
- ✅ Header `include/determ/crypto/frost.hpp` — full API (types, structs, function signatures) per RFC 9591.
- 🚧 `frost_keygen_round1` / `frost_keygen_round2` / `frost_keygen_finalize` / `frost_sign_round1` / `frost_sign_round2` / `frost_aggregate` — scaffolded, throw `std::logic_error("v2.10 Phase A not yet implemented")`. PIN-tested.

Remaining: port the keygen/sign/aggregate primitives from `zcash/frost-ed25519` reference impl onto the already-vendored libsodium primitives (H1..H5 sub-hashes, polynomial eval in F_L, Lagrange interpolation, PoP Schnorr sig). Estimated 2-3 days for an experienced FROST implementer.

File touchpoints: `src/crypto/frost.cpp` only (header API is stable).

### Phase B — DKG protocol (1-1.5 weeks)

Three new gossip-layer message types:
- `DKGCommitMsg` — Round 1 commitments
- `DKGShareMsg` — Round 2 encrypted shares
- `DKGComplaintMsg` — Misbehavior accusations during ceremony

File touchpoints: `include/determ/net/messages.hpp`, `src/net/binary_codec.cpp` (wire format), `src/net/gossip.cpp` (dispatch), new `src/node/dkg.cpp` (ceremony state machine).

### Phase C — Epoch-boundary orchestration (3-5 days)

`Chain::current_epoch()` already exists (epoch_blocks-driven). New epoch-boundary hook: every `epoch_blocks` heights, kick off a fresh DKG ceremony OR a PSS refresh (membership-unchanged → refresh; membership-changed → fresh DKG).

Three new genesis-pinned constants:
- `v2_10_active_from_height` — migration gate
- `dkg_round_blocks` (per-profile: R=3 web/regional/global, R=5 tactical/cluster)
- `pss_refresh_blocks` — PSS cadence within an epoch

File touchpoints: `src/chain/chain.cpp`, `src/chain/genesis.cpp`.

### Phase D — Threshold-signature integration (3-5 days)

Replace `creator_dh_secrets` with `creator_partial_sigs`. Each committee member's Phase-2 reveal becomes a FROST partial signature over `(beacon_seed || height)`. `compute_block_rand` aggregates t partials into the canonical R.

File touchpoints: `src/node/producer.cpp` (Phase-2 reveal), `src/chain/block.cpp` (signing_bytes binding new field).

### Phase E — Failure-mode handling (3-5 days)

- Insufficient partials at FROST-aggregate time → fallback to v1 commit-reveal for this round
- Excluded validator tracked in `Block.dkg_excluded` (vec of domains)
- DKG ceremony abort → all committee members propose v1 fallback

### Phase F — Tests + docs (3-5 days)

- `determ test-frost-keygen` + `test-frost-sign` + `test-dkg-ceremony` (~80+ assertions)
- `tools/test_v2_10_threshold_rand.sh` (multi-node end-to-end)
- `tools/test_dkg_failure_modes.sh`
- `docs/PROTOCOL.md` §V8 randomness updates
- `docs/SECURITY.md` S-006 closure (selective-abort threat upgraded to threshold-rand mitigation)
- `docs/proofs/SelectiveAbort.md` (FA3) updated with threshold-aggregation argument

---

## Sequencing recommendation

1. **F2 first** (~3-4 days) — smaller, well-spec'd, isolatable. Ship + close S-030 D2 consensus layer.
2. **v2.10 second** (~3 weeks) — larger, more risk surfaces (DKG ceremony, threshold-sig math, FROST library port). The F2 changes give a stable base.

Each phase commits at sub-step boundaries — phased delivery means a failure or rethink at any step doesn't lose prior progress.

---

## Test coverage targets

Current FAST=1 suite: 99/99 PASS. Target after F2 + v2.10 fully shipped:
- +2 in-process tests (test-view-root ✅ shipped; test-f2-reconciliation; test-frost-keygen; test-frost-sign; test-dkg-ceremony)
- +5 shell-driven regression tests (consensus reconciliation, DKG ceremony, FROST round-trip, failure modes, threshold-rand integration)

Final FAST=1 target: 105/105 PASS (or whatever exact number lands).
