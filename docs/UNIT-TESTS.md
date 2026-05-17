# Unit Tests — Coverage Map + Extension Guide

This document is the comprehensive reference for the in-process unit-test
seed that closes S-035 Option 1. It explains the strategy, lists what is
covered, what is not yet covered, and how to add new tests.

**Cross-references:**
- `SECURITY.md` §S-035 — finding registration + status table
- `README.md` §"Behavioral test suite" — representative-tests table
- `CLI-REFERENCE.md` §"S-035 Option 1 seed" — per-subcommand surface
- `tools/run_all.sh` — `FAST=1` short-circuit for in-process subset
- `tools/common.sh` — path-portability layer (Option 3)

---

## 1. Strategy: `determ test-*` subcommands

Rather than introducing a separate test binary (gtest / Catch2 / doctest), 
each unit test is a subcommand of the main `determ` binary. Calling
`determ test-FEATURE` runs an in-process unit test, prints `PASS`/`FAIL`
lines per assertion, then exits with status 0 (all pass) or 1 (any fail).

Each subcommand has a paired shell wrapper at `tools/test_FEATURE.sh`
that invokes the subcommand and translates its output into the
existing `tools/run_all.sh` summary infrastructure (final-line `PASS:`/
`FAIL:` markers per the existing test convention).

### Why this approach (vs gtest)

| Constraint | Implication |
|---|---|
| MVP timeline; no CI runner committed | Adding gtest + CMake + a CI workflow is its own multi-day project; defers value. |
| Codebase is small (~17 KLOC) | Bespoke test commands are not significantly more code than gtest fixtures would be. |
| Tests must run on Windows + Linux + Mac | A single binary is portable by construction; gtest needs CMake target consistency. |
| Existing test infrastructure (`tools/test_*.sh`, `run_all.sh`) is mature | Reusing it avoids a parallel suite. |
| Cryptographic primitives are pure functions | They lend themselves to direct calls from main.cpp without fixtures. |

The trade-off is that a future migration to gtest is the operator's
choice — the assertions themselves are gtest-ready (each is a single
`check(cond, msg)` call analogous to `EXPECT_TRUE` / `ASSERT_TRUE`), so
the migration would be mechanical when the operator commits to CI.

### Output format

```
=== <surface name> ===
  PASS: <assertion description>
  PASS: <assertion description>
  ...
  PASS: <feature> all assertions
  PASS: <feature> unit test
```

(or `FAIL:` substituted for failed assertions + a non-zero exit.) The
`PASS: <feature> all assertions` line is the canonical aggregate
result; the wrapper's `PASS: <feature> unit test` translates it for
`tools/run_all.sh`.

### `FAST=1` mode

`FAST=1 bash tools/run_all.sh` short-circuits to just the in-process
subset (network-free, <12s end-to-end). Useful for tight iteration
during development. Each new test wrapper must be added to the
`ONLY_PATTERN` regex in `run_all.sh` so `FAST=1` picks it up.

---

## 2. Current coverage map

24 subcommands; 428 assertions; runs in <14s with no flakes.

### 2.1 Cryptographic primitives

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-sha256` | SHA-256 wrapper + `SHA256Builder` (10 assertions): NIST FIPS 180-4 published test vectors (empty input, "abc", 56-byte input exercising the >55-byte padding path), `SHA256Builder` ↔ one-shot equivalence, multi-piece incremental append correctness, **Preliminaries §1.3 big-endian uint64_t / int64_t encoding** that every signing-bytes / compute-block-digest / merkle-leaf-hash path depends on for cross-platform protocol determinism. | `tools/test_sha256.sh` | all hash claims |
| `determ test-ed25519` | Ed25519 sign/verify + `generate_node_key` (10 assertions): key-shape, sign+verify round-trip, tampered-message rejection, tampered-signature rejection, wrong-pubkey rejection, RFC-8032 determinism (same key+msg → same sig), empty-message edge case, distinct-key distinct-sig, cross-key verify rejection, 4 KB long-message streaming. Every signature claim in the protocol reduces to Ed25519 EUF-CMA. | `tools/test_ed25519.sh` | FA1 / FA2 / FA5 / FA6 / FA7 / FA10 |
| `determ test-merkle` | v2.1 Merkle primitives (10 assertions): `merkle_root` + `merkle_proof` + `merkle_verify` + `merkle_leaf_hash` + `merkle_inner_hash` over balanced + unbalanced + edge-case (empty / single-leaf) leaf sets. Round-trip, tampering detection (value_hash / sibling-hash / target_index), domain separation (leaf vs inner), determinism, sort-invariance. | `tools/test_merkle.sh` | FA1 |
| `determ test-committee-selection` | `crypto::select_m_creators` (S-020 hybrid: both rejection-sampling at 2K≤N AND partial-Fisher-Yates at 2K>N branches), `select_after_abort_m`, `epoch_committee_seed` (13 assertions): determinism, seed-sensitivity, branch coverage at both sides of the 2K vs N threshold, edge cases (K=N, K=1), distinct-without-replacement, in-range invariant, shard-salt sensitivity. | `tools/test_committee_selection.sh` | FA1 / FA2 / FA5 / FA8 |
| `determ test-shard-routing` | `crypto::shard_id_for_address` (salted SHA-256) (7 assertions): single-shard degenerate case, determinism, in-range invariant, salt-sensitivity, distribution uniformity (chi-squared sanity on 1000 addresses × 4 shards), case-sensitivity, empty-address handling. | `tools/test_shard_routing.sh` | FA7 |
| `determ test-anon-address` | Anon-address helpers (12 assertions): `is_anon_address` / `normalize_anon_address` / `parse_anon_pubkey` / `make_anon_address`. S-028 case-insensitive parsing (accepts lower / upper / mixed-case), invalid-input rejection, case-normalization to canonical lowercase, round-trip, registered-domain pass-through. | `tools/test_anon_address.sh` | wallet (S-028) |

### 2.2 Chain commitment + identity

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-genesis-message` | `GenesisConfig::genesis_message` hash-mixing contract (10 assertions): backward-compat default-skips-mix invariant, custom-yields-distinct-hash, empty-string-distinct-from-default, determinism under override, JSON round-trip, absent-key default-fallback, size cap enforcement (256B max), boundary acceptance. Locks operator-facing inscribed-message feature against silent regressions that would either break existing chain identity or allow chain-identity collisions. | `tools/test_genesis_message.sh` | chain identity |
| `determ test-state-root` | `Chain::compute_state_root()` commitment algebra (13 assertions): determinism (K-of-K consensus precondition), purity (no internal-state leak between calls), non-zero baseline (k: leaves always present), per-field sensitivity for every public `set_*()` that maps into a k:-namespace leaf, invertibility (change-then-revert returns to original root), cross-namespace distinction (no accidental collisions), order independence (setter call order doesn't affect root — leaves sorted internally). S-033 / v2.1 / S-037 / S-038 surface. | `tools/test_state_root_unit.sh` | FA1 (state commitment) |
| `determ test-block-digest` | `compute_block_digest` (FA1 Phase-2 signature target) (19 assertions): INCLUSION contract (every digested field — index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer, creators, creator_tx_lists, creator_ed_sigs, creator_dh_inputs — changes the digest when mutated) + EXCLUSION contract (S-030 D2 / Phase-2-reveal / v2.7 F2 territory fields MUST NOT change the digest: delay_output, creator_dh_secrets, cumulative_rand, abort_events, equivocation_events, state_root, partner_subset_hash, timestamp). "Fences" the digest at exactly the surface FA1 / S-030 D2 / v2.7 F2 assume. | `tools/test_block_digest.sh` | FA1 (signature target) |
| `determ test-block-hash` | `Block::signing_bytes()` + `Block::compute_hash()` — FA1 chain-anchor identity (16 assertions). compute_hash binds EVERY consensus-relevant field of the block including Phase-2-reveal fields and apply-time-recomputed state_root, so its output becomes prev_hash on every subsequent block. Covers determinism + purity, field-sensitivity for timestamp / delay_output / creator_dh_secrets / cumulative_rand / creator_block_sigs, zero-skip backward-compat for partner_subset_hash (R4 Phase 3) and state_root (S-033) — both bound only when non-zero so pre-feature blocks retain byte-identical hashes, creators[] ORDER sensitivity, and S-030 D2 chain-anchor distinction (two same-digest blocks differing in equivocation_events have different compute_hash outputs). | `tools/test_block_hash.sh` | FA1 (chain identity) |
| `determ test-genesis` | `compute_genesis_hash` + `make_genesis_block` — chain identity origin (19 assertions). Locks in chain_id sensitivity + the **S-039 diagnostic-UX gap** (m_creators / k_block_sigs / block_subsidy / min_stake / initial_shard_count / bft_enabled NOT bound into hash → discovered during test authoring; fix is wire-compat break, deferred to coordinated migration). Fields that ARE bound: shard_id, chain_role, suspension_slash + merge_threshold_blocks (when non-default), genesis_message, committee_region (when non-empty). make_genesis_block invariants (index 0, prev_hash zero, compute_hash matches). JSON round-trip preserves identity hash; oversized genesis_message rejected. | `tools/test_genesis.sh` | chain identity + S-039 |

### 2.3 Randomness + consensus arithmetic + tx-root

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-block-rand` | V8 randomness primitives (21 assertions): `compute_delay_seed` (Phase-1 inputs commitment), `compute_block_rand` (Phase-2 output), `proposer_idx` (BFT-mode designated proposer), `required_block_sigs` (MD vs BFT quorum), `count_round1_aborts` (suspension + escalation tally). Determinism + every-input-field sensitivity + creator_dh_inputs / ordered_secrets ORDER sensitivity (the committee-selection-order contract pairing Phase-1 commits with Phase-2 reveals — without this, a malicious gather could reorder reveals to bias future randomness), domain separation between the two hash functions, proposer_idx in-range invariant + abort-rotation mechanism + empty-committee short-circuit, required_block_sigs golden vectors for MD = K and BFT = ceil(2K/3) (K = 1..12), count_round1_aborts round-2 filter. | `tools/test_block_rand.sh` | FA1 / FA5 / FA8 |
| `determ test-tx-root` | `compute_tx_root` — K-committee union-of-tx-hashes commitment (10 assertions). Union semantics ({A,B} ∪ {B,C} == {A,B,C}, NOT intersection {B}), dedup, list permutation invariance, within-list order invariance, empty inner list invariance, sensitivity to added tx. **The FA2 censorship-resistance primitive** — regression to intersection (note S-025 deletion: intersection variant was removed) would silently let one member exclude txs. | `tools/test_tx_root.sh` | FA2 (censorship) |
| `determ test-random-state` | Random-state primitives in `crypto/random.cpp` — `compute_dh_output` (2-share fold) + `compute_dh_output_m` (M-share fold, current path) + `update_random_state` (per-block chain) + `compute_abort_hash` + `chain_abort_hash` (S5 anti-cartel — abort-dependent re-selection so attackers can't pre-plan abort sequences) + `genesis_random_state` (block-0 seed). 27 assertions: determinism + argument-order sensitivity + per-input sensitivity for each function. **Foundation layer below** test-block-rand's compute_delay_seed / compute_block_rand. The committee-selection-order contract for compute_dh_output_m + the aborting_node sensitivity in compute_abort_hash are the key invariants — without them, attackers could either reorder reveals or plan abort sequences to bias future selection. | `tools/test_random_state.sh` | V8 / S5 anti-cartel |

### 2.4 Consensus message surface

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-transaction` | `Transaction::signing_bytes` + `compute_hash` + Ed25519 sign/verify + JSON round-trip (28 assertions). signing_bytes determinism + per-field sensitivity for all 8 core fields, sig/hash EXCLUSION (would be circular — sender signs over their OWN signing bytes), compute_hash == SHA-256(signing_bytes) golden contract, real Ed25519 sign + tampered-tx-fails-verify round-trip, full JSON round-trip for TRANSFER + type-preservation for all 9 other TxType variants, S-018 strict-rejection, unique-tx-identity contract. | `tools/test_transaction.sh` | tx-level FA1 + S-018 |
| `determ test-merge-event-codec` | `MergeEvent::encode` / `::decode` (R4 under-quorum merge wire format; 19 assertions). BEGIN + END round-trips with empty-region preservation, size invariant, decode rejection paths (too-short / invalid event_type / region_len > 32 / size mismatch), determinism + per-field sensitivity, maximum-region (32 bytes) round-trip. | `tools/test_merge_event_codec.sh` | R4 / FA8 |
| `determ test-consensus-msgs` | ContribMsg + BlockSigMsg + AbortClaimMsg + their commitment-hash helpers (`make_contrib_commitment` + `make_abort_claim_message`); 28 assertions. Per-helper determinism + per-input sensitivity (including tx_hashes ORDER for contrib — sorted-ascending contract); round sensitivity in abort claim (defeats Phase-1 vs Phase-2 replay); domain separation between commitment hashes; full JSON round-trip for all three message types; make_contrib produces a sig that verifies under signer's pubkey via real Ed25519. | `tools/test_consensus_msgs.sh` | FA1 (consensus messages) |

### 2.5 Network surface

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-rate-limiter` | `net::RateLimiter` token bucket (S-014 surface — the shared helper used identically by RpcServer and GossipNet) (16 assertions): default-disabled bypass, configure(0,0) explicit-disable, configure(>0,>0) enables + getter round-trip, first-touch FULL invariant (legitimate callers don't get hit cold), burst exhaustion (4th consume fails at burst=3 same-instant), per-key independence (exhausting key A doesn't throttle key B — the central security property), reconfigure semantics, refill timing (100ms sleep at rate=20/s yields ≥1 new token), burst-cap invariant (long sleep at high rate does NOT exceed burst — defeats slow-leak attacks), 100-distinct-keys-at-scale. Unit-level counterpart to wire-level `test_rpc_rate_limit.sh` + `test_gossip_rate_limit.sh`. | `tools/test_rate_limiter.sh` | S-014 |
| `determ test-binary-codec` | Wire-format codec (A3 / S8 closure: JSON envelope v0 + binary envelope v1 + format-detecting dispatcher) + S-022 per-MsgType cap table (35 assertions): JSON envelope round-trip across HELLO + STATUS_REQUEST + TRANSACTION (with type + payload byte-for-byte preservation); binary envelope round-trip across STATUS_RESPONSE + CONTRIB via both `Message::serialize_binary` + `Message::deserialize` (format-detecting) and direct `encode_binary` / `decode_binary`; `is_binary_envelope` format-detection contract (returns true on binary magic byte, false on JSON `{`); malformed-input rejection (garbage bytes + truncated valid JSON); `max_message_bytes` golden vectors for all 19 enumerated MsgType variants (16 MB tier: SNAPSHOT_RESPONSE / CHAIN_RESPONSE; 4 MB tier: BLOCK / BEACON_HEADER / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE / HEADERS_RESPONSE; 1 MB tier: HELLO / CONTRIB / BLOCK_SIG / ABORT_CLAIM / ABORT_EVENT / EQUIVOCATION_EVIDENCE / TRANSACTION / STATUS_REQUEST / STATUS_RESPONSE / GET_CHAIN / SNAPSHOT_REQUEST / HEADERS_REQUEST + default-tight 1 MB fence for future MsgType additions — defeats new types slipping past the S-022 boundary). | `tools/test_binary_codec.sh` | A3 / S8 / S-022 |
| `determ test-wire-types` | Block-internal wire types JSON round-trip + S-018 strict-rejection (39 assertions). Covers `CrossShardReceipt` (FA7 / V12 source-side receipt — 10 fields), `AbortEvent` (FA3 abort certificate — 4 fields + claims subtree), `EquivocationEvent` (FA6 slashing evidence — 8 fields), `GenesisAlloc` (chain-identity allocation — 5 fields including R1 empty-region backward-compat + zero-stake legacy). S-018 strict-rejection lock-in for all four: missing required field throws with field-name diagnostic; wrong-length hex throws via `json_require_hex` length check. `CrossShardReceipt::from_json` was hardened in the same commit that shipped this test (previously permissive via `j.value()` defaults — defense-in-depth gap closed; now uses `json_require` / `json_require_hex` to match the rest of the S-018 surface). | `tools/test_wire_types.sh` | FA7 / V12 / FA3 / FA6 / S-018 |

### 2.6 Wallet / key surface

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-envelope` | `wallet/envelope.hpp` AES-256-GCM + PBKDF2-HMAC-SHA-256 AEAD wrapping primitive (A2 Phase 2 wallet recovery share envelopes + S-004 option 2 passphrase-encrypted keyfiles; 27 assertions). Encrypt/decrypt round-trip + envelope shape (salt + nonce + tag sizes); AEAD safety properties (wrong-pw / empty-pw / mismatched-AAD / tampered-ct / tampered-tag all fail; fresh salt + nonce per encryption → distinct ciphertexts from same plaintext+passphrase — defeats artifact-correlation attacks); serialize/deserialize canonical hex round-trip with bad-input rejection; empty-plaintext + empty-AAD edge cases. A regression here would silently weaken at-rest security for every encrypted wallet artifact. | `tools/test_envelope.sh` | A2 / S-004 |
| `determ test-shamir` | Shamir's Secret Sharing over GF(2^8) (`wallet/shamir.cpp`; A2 Phase 1 wallet recovery primitive; 18 assertions). T-of-N reconstruction (3-of-5 round-trip; all C(5,3) = 10 subsets verified; T+1 also works; T-1 doesn't reconstruct — the information-theoretic security property); share-shape invariants (distinct x-coordinates; no x=0 since Lagrange evaluates at x=0; y-size matches secret; fresh polynomial per split — two independent splits produce different shares); degenerate thresholds (T=1 = every share is the secret; T=N = all shares required); empty-secret edge case (split produces empty-y shares; combine rejects with nullopt per documented behavior); invalid-input rejection (threshold=0, threshold > share_count, empty share list, duplicate x, mismatched y-sizes). Unit-level counterpart to the network-level `test_wallet_shamir.sh` (wallet-binary CLI smoke test); both lock in the A2 Phase 1 primitive at different layers. | `tools/test_shamir.sh` | A2 Phase 1 |

### 2.7 Fork resolution

| Subcommand | What it tests | Wrapper | FA-track |
|---|---|---|---|
| `determ test-resolve-fork` | `Chain::resolve_fork` (S-029 BFT-mode fork-choice rule; 10 assertions). When two K-of-K-signed blocks are observed at the same height (only possible in BFT mode where the gather-quorum is ceil(2K/3) rather than K, so signature subsets can differ), resolve_fork picks the canonical tip deterministically: (1) heaviest sig set wins (max non-zero `creator_block_sigs`); (2) tie → fewer `abort_events` wins; (3) tie → smallest block_hash (lexicographic, deterministic across peers). Plus edge cases: identical blocks return first arg, zero-sigs still resolves without crash, sentinel-zero handling in BFT mode (zeros don't count toward weight), abort-tie-break beats hash-tie-break. A regression would either silently let the wrong block win (FA1 violation: peers diverge on canonical tip) or make resolution non-deterministic across nodes. | `tools/test_resolve_fork.sh` | S-029 / FA1 |

---

## 3. What's not yet covered (extension targets)

### 3.1 Cryptographic / consensus surfaces

| Surface | Function(s) | Why high value | Effort |
|---|---|---|---|
| Equivocation event verification | `validator::check_equivocation_events` | FA6 closure surface | ~1d (requires partial NodeRegistry fixture) |
| Bounded mempool | `Node::mempool_admit_check` / `mempool_make_room_for` (S-008) | Admission/eviction policy invariants | ~1d (needs partial Node fixture) |
| AbortClaimMsg verification | `validator::verify_abort_claim` | FA3 surface | ~½d |
| genesis_from_config end-to-end | full initial_state install + chain state seeding | Identity hash + seeded-state contract | ~½d (now that `test-genesis` covers compute_genesis_hash) |
| S-039 fix (operational params binding) | bind m_creators / k_block_sigs / etc. into compute_genesis_hash | Diagnostic-UX gap closure — fix is wire-compat break needing coordinated migration | ~½d code + coordinated rollout |
| Param-change application | `Chain::apply_param_change` (A5 governance) | governance correctness | ~1d |

### 3.2 Mid-level invariants

| Surface | Why | Effort |
|---|---|---|
| `Chain::append` validation paths | Locks chain-level acceptance/rejection invariants | ~1-2d (golden-block fixtures) |
| Abort-tally semantics | FA3 surface | ~½d |
| Fork resolution | S-029 surface | ~1d |
| Wallet keyfile encryption | A2 surface | ~1d |

### 3.3 Deterministic-simulation framework (Option 2)

A separate, larger investment. Would let us script Byzantine actors,
network partitions, clock skew, and verify global safety/liveness
invariants over many randomized executions. Estimated 3-4 weeks. Not
gated by Option 1 progress.

---

## 4. How to add a new unit test

### 4.1 Add the subcommand to `src/main.cpp`

Pick a feature name. The convention is hyphenated:
`test-<noun-phrase>`, e.g., `test-block-codec`.

Add a block in `src/main.cpp`:

```cpp
if (cmd == "test-FEATURE") {
    using namespace determ;
    // additional namespaces as needed
    int fail = 0;
    auto check = [&](bool cond, const char* msg) {
        if (cond) std::cout << "  PASS: " << msg << "\n";
        else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
    };

    // ... assertions ...

    std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
              << ": FEATURE " << (fail == 0 ? "all assertions" : "had failures")
              << "\n";
    return fail == 0 ? 0 : 1;
}
```

### 4.2 Add the wrapper at `tools/test_<feature>.sh`

```bash
#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for FEATURE.
# <one-paragraph description of the surface + safety motivation>
#
# <assertion-by-assertion enumeration>
#
# Run from repo root: bash tools/test_<feature>.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== <one-line surface description> ==="
OUT=$($DETERM test-FEATURE 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: FEATURE all assertions"; then
  echo ""
  echo "  PASS: FEATURE unit test"
  exit 0
else
  echo ""
  echo "  FAIL: FEATURE had assertion failures"
  exit 1
fi
```

### 4.3 Add to `FAST=1` regex in `tools/run_all.sh`

```bash
ONLY_PATTERN='test_(atomic_scope|...|FEATURE)\.sh$'
```

(Plus the comment-block enumeration above the regex.)

### 4.4 Add to `determ help` output

In `src/main.cpp` around the existing `determ test-*` help block, add a
two-line row describing the feature.

### 4.5 Add to docs

- `docs/CLI-REFERENCE.md`: row in the §"S-035 Option 1 seed" table.
- `docs/README.md`: row in the representative-tests table.
- `docs/SECURITY.md` §S-035: row in the surface/FA-track/assertions
  table; bump the headline assertion count.
- `docs/UNIT-TESTS.md` (this file): row in §2 corresponding to the
  surface category.
- Bump test counts in `docs/README.md` headline, `docs/QUICKSTART.md`
  §"Project layout", and `docs/WHITEPAPER-v1.x.md` abstract.

### 4.6 Verify

```bash
# Rebuild
cmake --build build --config Release --target determ

# Run just the new test
build/Release/determ.exe test-FEATURE  # Windows
build/determ test-FEATURE               # Linux/Mac

# Run the full FAST suite
FAST=1 bash tools/run_all.sh
```

### 4.7 Commit

Following the existing in-repo convention:

```
S-035 Option 1 seed: `determ test-FEATURE` — <one-line description>

<body explaining what the surface is, why it matters, and what the
assertions cover>

<files list>

Verified: FAST=1 suite N/N PASS in <Ts>.
```

---

## 5. Test discipline

These conventions distinguish a useful unit test from one that rots:

1. **One surface, one test.** Each subcommand covers a single API surface
   (one class, one set of free functions). Resist mixing.

2. **Deterministic inputs.** No `time()`, `random()`, or filesystem-dependent
   state in assertion inputs. Reproducibility across runs is the contract.

3. **Document the EXCLUSION list when relevant.** For functions where
   "fields A and B affect output, but C does not" is part of the design
   (compute_block_digest, signing_bytes), assertions must cover BOTH
   sides. Silent drift across the inclusion/exclusion boundary is a
   common regression source.

4. **Cover ORDER sensitivity where it matters.** Reordering items in
   committee-selection-order or sorted-leaves contexts is a tempting
   "harmless refactor" that breaks consensus. Lock it in.

5. **Cover backward-compat / zero-skip semantics.** Many fields are
   bound into hashes ONLY when non-zero (state_root, partner_subset_hash,
   genesis_message, region). The zero-skip is a backward-compat
   invariant; tests must include `zero == default` AND `non-zero changes
   output` assertions.

6. **Cross-reference the spec.** Every test description in this doc and
   in the wrapper's header comment should cite the relevant proof
   (FA-track), security finding (S-XXX), or design doc (proofs/SPEC.md)
   so future contributors understand why each assertion exists.

7. **Cap each subcommand at <5s.** Long-running tests belong in the
   network-level `tools/test_*.sh` corpus; the in-process subset's value
   is that `FAST=1` is fast enough to run after every save during
   development.
