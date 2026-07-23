# Consensus Validator + Apply-Path Gate-Gap Audit

**Status: register (a live backlog of ungated code reject-paths), NOT a runtime property.**
Companion to [ProofClaimGateTraceability.md](ProofClaimGateTraceability.md). That register
audited the `docs/proofs/` *claim* surface (which documented properties lacked an enforcing
gate). This one audits the **code** surface directly: security-relevant reject / fail-closed
branches in the consensus **validator** (`src/node/validator.cpp`, the ~19 `BlockValidator::check_*`
gates of `validate()`) and the **apply path** (`src/chain/chain.cpp` `apply_block`/`apply_tx`) whose
**silent removal or inversion would ACCEPT a forged/malformed block, certificate, or transaction** —
an *accept-widening* soundness regression — and that **no existing test would catch**.

The accept-widening blind spot is structural (the recurring lesson of the sister register): liveness,
byte-identity replay, golden-vector, and state-root-determinism gates all constrain the HONEST
direction; a reject-path whose removal only *widens* acceptance is invisible to every one of them
unless a **negative** test drives a would-be-rejected input through the real caller.

## 1. Method

A 2026-07-23 ultracode Workflow (`wf_eb293ab6-600`, 6 parallel finders over disjoint validator/apply
slices → a per-candidate adversarial verifier whose **default verdict was REFUTED** → a judge; 27
agents, ~3.0M tokens) enumerated the reject-paths, cross-checked each against the full test suite
(`tools/test_*.sh` + the in-process `determ test-*` subcommands), and excluded everything already
gated or already listed/closed in the sister register. It confirmed **19 genuine gaps of 21 deduped
candidates** — each with the exact test-passing surviving mutation. Ranked by `value_rank` (1 =
forged-block/cert/tx or fund-loss), then gate-cost. Sixteen of the nineteen are value_rank 1, and
all nineteen are FAST-gateable in-process (no live node) — the cheapest, both-platform class.

## 2. CLOSED (4 of 19) — `check_block_sigs` (×2) + per-tx sender-sig + commit-reveal binding

### 2a. BSIG-516 (per-signature block-signature authenticity)

**#3 BSIG-persig-verify-516** — `src/node/validator.cpp:516`, inside `check_block_sigs` (gate 9 of
`validate()`). Each COUNTED (non-sentinel) `creator_block_sig` must be a VALID Ed25519 signature over
the block digest:

```cpp
if (!verify(*pk, digest.data(), digest.size(), b.creator_block_sigs[i]))
    return {false, "block sig invalid: " + b.creators[i]};
```

**Consequence if silently removed:** every non-zero `creator_block_sig` is counted toward the
K-of-K / BFT quorum *without verification*, so a Phase-1 participant (who already holds the
`creator_ed_sigs` that clear the earlier gates) finalizes a fully-forged block carrying garbage
Phase-2 signatures with **zero real committee consent** — total consensus-safety collapse. It is
the textbook "well-tested helper called by an unenforced comparison" trap: `crypto::verify` is
KAT-tested, but nothing pinned the reject-branch that *calls* it. `test-required-block-sigs` pins
only the pure `required_block_sigs(mode,size)` helper (the quorum arithmetic), never the validator's
per-signature verify; `test-abort-cert-validation` reached gate 9 but its negative blocks died at
the earlier proposer checks (`:492`/`:496`), never at `:516` with a counted-but-invalid signature.

**Gate (in-process, both platforms).** Extended `test-abort-cert-validation` (reuses its
fully-signed BFT `ok` block that clears gate 9, with real keypairs): corrupt ONE **non-proposer**
slot to a **non-zero but invalid** signature (`creator_block_sigs[np][0] ^= 0x01`) and assert the
validator error contains `"block sig invalid"`. The existing fully-signed baseline (`!sig_err(e_ok)`)
is the non-vacuity positive control.

**The load-bearing subtlety (two traps avoided):** (a) the slot must be corrupted to a **non-zero**
value, never zeroed — a zeroed slot is skipped by the `:512` sentinel and would trip `:521` (the
DIFFERENT quorum gate, `"block signatures N < required"`), testing the wrong gate; (b) only the
signature bytes change (never a digest-bound field) and only a **non-proposer** slot, so the proposer
sig still verifies and `:516` is the UNIQUE gate that can reject the block. The assertion pins the
**specific** `"block sig invalid"` substring, not merely `!r.ok` — this is what makes it sound:

*Falsify-on-mutant (executed via a rebuilt `determ.exe`).* Mutating `:516` to
`if (false && !verify(...))` flips the assertion RED — and it does so *correctly despite a downstream
gate*: under the mutant the counted-without-verify block clears gate 9 and is then rejected by
`check_cumulative_rand` (`"cumulative_rand incorrect"`), so a vacuous `!r.ok` assertion would have
stayed GREEN (masked by defense-in-depth), whereas the specific-string assertion sees the wrong
error and fails. Counter-delta: exactly one assertion flips (PASS→FAIL, `got: [cumulative_rand
incorrect]`); the baseline and every other assertion stay GREEN. Reverted via
`git checkout src/node/validator.cpp` (committed clean this round), rebuilt → GREEN.

### 2b. BSIG-521 (block-signature quorum floor — the sibling gate)

**BSIG-quorum-count-521** — `validator.cpp:521`, the quorum gate immediately after the `:516`
per-signature loop in the same function: `if (signed_count < required) return {false, "block
signatures N < required M"}`. `required = required_block_sigs(mode, |creators|)` — full K-of-K in
MUTUAL_DISTRUST, `⌈2K/3⌉` in BFT. **Consequence if silently removed:** a block finalizes with fewer
valid signatures than the mode demands — one committee member (or any Phase-1 participant holding the
others' `creator_ed_sigs`) fills the rest with sentinel-zeros and *unilaterally* finalizes the block.
Same trap-2 shape as BSIG-516: `test-required-block-sigs` pins only the pure `required_block_sigs()`
helper, never the validator's *use* of it (the exact "well-tested helper called by an unenforced
comparison" pattern).

**Gate + falsify.** Same seam and `ok` block: zero **all non-proposer** slots so `signed_count`
drops to 1 (just the proposer, which the `:496` proposer-sig check still requires) — for any BFT
block (`required ≥ 2`) that is `< required`, so `:521` rejects; assert `"block signatures"`.
Robust to committee size (`signed_count == 1 < required` regardless of |creators|). Falsify via a
rebuilt `determ.exe`: `:521` → `if (false && signed_count < required)` flips **only** the BSIG-521
assertion RED (`got: [cumulative_rand incorrect]` — the same downstream gate, again requiring the
specific-string assertion, not `!r.ok`), while BSIG-516 stays GREEN (independent gates); counter-delta
= exactly one assertion; reverted, rebuilt → GREEN. With both closed, `check_block_sigs`'s two
load-bearing gates (per-signature validity + quorum count) are now fully pinned.

### 2c. VAL-tx-sender-sig (per-transaction SENDER Ed25519 authenticity)

**#1 VAL-tx-sender-sig** — `src/node/validator.cpp:685`, inside `check_transactions` (gate 11 of
`validate()`), in the per-tx loop's non-PQ (Ed25519) branch, after the sender pubkey `pk` is resolved
(registry lookup / `parse_anon_pubkey` / REGISTER payload):

```cpp
auto sb = tx.signing_bytes();
if (!verify(pk, sb.data(), sb.size(), tx.sig))
    return {false, "tx signature invalid from: " + tx.from};
```

**Consequence if silently removed:** every transaction is admitted **without authenticating its
sender** — anyone can forge a TRANSFER `from` any account (its balance is spent to an attacker-chosen
`to`) with an arbitrary signature. This is the single highest-value accept-widening in the register:
**universal fund theft.** It is invisible to every honest-direction gate — goldens, state-root, and
byte-identity all exercise *validly-signed* txs, so none notices that the reject-branch is gone; and
`crypto::verify` being KAT-tested proves the primitive, never the validator's *use* of it (trap-2).

**Gate (in-process, both platforms).** Extended `test-al3-unknown-tx-type`, whose genesis already
registers creator "alice" with `ed_pub = key.pub` and whose `run_type` lambda builds a signed
non-anon TRANSFER that clears every pre-`:685` guard (ZEROTH / confidential / S-049 overflow / PQ /
registry-present) and drives it through the `check_transactions_for_test` seam (a const forwarder to
`check_transactions` only). New leg: sign a valid alice→bob TRANSFER, then flip one byte of `tx.sig`
(`tx.sig[0] ^= 0xFF`) and assert the reject contains `"tx signature invalid"`; an honest-signed copy
of the same tx is the non-vacuity positive control.

**The load-bearing subtlety (two traps avoided):** (a) `tx.sig` is **NOT** folded into
`Transaction::signing_bytes()` / `compute_hash()` / `tx_root` / the block digest (`block.cpp:18-30`),
so a post-sign byte flip is invariant under every commitment — no tx_root or block-hash gate can
reject it first; and doubly so here, since the seam runs *only* `check_transactions` (never
`check_creator_tx_commitments` or `check_block_sigs`), making `:685` the UNIQUE gate the fixture
exercises. (b) The assertion pins the **specific** `"tx signature invalid"` substring, not `!r.ok`.

*Falsify-on-mutant (executed via a rebuilt `determ.exe`).* Mutating `:685` to
`if (false && !verify(...))` accepts the forged tx (the nonce check at `:690` passes — expected 0,
got 0 — and `check_transactions` runs no balance check), so `r.ok` becomes true and `r.error` is
empty: **both** VAL-tx-sender-sig assertions flip RED (a clean 2-assertion counter-delta) while all
four AL-3 asserts **and** the honest-sig positive control stay GREEN — proving the fixture reaches the
gate honestly and the RED is caused solely by the byte flip, not the fixture. Reverted via
`git checkout src/node/validator.cpp` (committed clean this round), rebuilt → GREEN. Robustness: even
if some hypothetical downstream gate rejected the forged tx with a *different* string, the specific
`"tx signature invalid"` substring would still be absent → still RED, so no downstream gate can
vacuously mask the removal.

### 2d. DHS-commit-reveal-bind (S-009 commit-reveal binding)

**#3 DHS-commit-reveal-bind** — `src/node/validator.cpp:423`, inside `check_creator_dh_secrets`
(gate 7 of `validate()`, at `:47`). Each revealed `creator_dh_secrets[i]` must hash (with committee
member i's pubkey) to the Phase-1-committed `creator_dh_inputs[i]`:

```cpp
Hash expected = SHA256Builder{}.append(b.creator_dh_secrets[i])
                               .append(pk->data(), pk->size()).finalize();
if (expected != b.creator_dh_inputs[i])
    return {false, "creator_dh_secret[" + std::to_string(i) + "] does not match commit"};
```

**Consequence if silently removed:** `creator_dh_inputs[i]` is the Phase-1 commit **signed** in
`creator_ed_sigs[i]`; the revealed secret feeds the block randomness beacon
(`delay_output = compute_block_rand(delay_seed, creator_dh_secrets)`). Without this bind a committee
member can substitute a **different** secret post-Phase-1 — grinding the block RNG over many candidate
secrets to bias committee/leader selection (the S-009 selective-abort / randomness-grinding attack).
The Phase-1 signature covers the *commit* (`make_contrib_commitment(..,creator_dh_inputs[i])`), never
the reveal, so only this recompute-and-compare pins the reveal to the commit.

**Gate (in-process, both platforms).** Extended `test-abort-cert-validation`, reusing its `build_block`
lambda (which already assembles a fully self-consistent committee block:
`creator_dh_inputs[i] = SHA256(secret‖pub)`, `creator_ed_sigs` over the commitments, `delay_seed` from
the inputs, `delay_output` from the secrets) plus the genesis / registry / `bv` scaffolding. New leg:
`Block b = build_block(...); b.creator_dh_secrets[0][0] ^= 0x01;` (flip ONE byte of creator 0's reveal,
leaving `creator_dh_inputs` / `creator_ed_sigs` / `delay_seed` untouched) → drive `bv.validate(b, c, reg)`
and assert the reject contains the index-qualified `"creator_dh_secret[0] does not match commit"`. An
un-mutated `build_block` copy is the positive control (asserts that string is absent — corroborated by
the pre-existing BASELINE which proves the clean block clears past this gate into `check_abort_certs`).

**The load-bearing subtlety (the specific-string discipline is essential here).** `check_creator_dh_secrets`
(`:47`) runs BEFORE `check_delay` (`:50`) and `check_block_sigs` (`:51`), and the earlier gates
(`prev_hash` / `registered` / `selection` / `tx_commitments`) read `creators` / `creator_dh_inputs`,
never the reveals — so with the gate present `:47` is the FIRST gate that can reject, emitting the unique
string. But under the mutant (`:423 → if (false && expected != …)`) the secret-substituted block is
**NOT accepted** — it flows to `check_delay`, whose `delay_output` check (`:446`) recomputes
`compute_block_rand(delay_seed, mutated_secrets) != stored delay_output` and rejects
`"delay_output mismatch (commit-reveal)"` (delay_output is a function of the secrets). So a vacuous
`!r.ok` assertion would stay GREEN (masked by the downstream binder); asserting the **index-qualified**
`"creator_dh_secret[0] does not match commit"` is what flips it RED — and the index qualifier also
avoids the substring collision with `"… does not match committed root"` (`:1488/1542/1604`).

*Falsify-on-mutant (executed via a rebuilt `determ.exe`).* The mutation flips ONLY the forged-secret
assertion RED (a clean 1-assertion counter-delta) while the positive control and the BASELINE stay
GREEN — proving the fixture reaches the gate honestly and the RED is caused solely by the secret
substitution. Reverted via `git checkout src/node/validator.cpp` (committed clean this round), rebuilt
→ GREEN. Design nailed by a parallel read-only analysis workflow (`wf_ff6477a8-a7d`) before any code
changed; every load-bearing claim re-verified against source.

## 3. The enumerated residual (15 open — a ranked FAST-gateable backlog)

Every row is a confirmed accept-widening with a named test-passing mutation; all are FAST-gateable
in-process. Closed one per directive, cheapest-value-first, exactly like the sister register.

| # | id | file:line | property (accept-widening consequence) | surviving mutation | val | cost |
|---|---|---|---|---|---|---|
| 4 | TXROOT-union-bind | validator.cpp:226 | tx_root == union(creator_tx_lists) — smuggle txs not in the committed root | `if (expected_root != b.tx_root)` → `if (false)` | 1 | trivial |
| 5 | EQV-sig-verify-forged-slash | validator.cpp:394 | equivocation sig-arm: slash only on a genuine double-sign — forge a slash of an honest validator | delete/short-circuit the `sig_a` reject arm | 1 | moderate |
| 6 | VAL-param-multisig-threshold | validator.cpp:827 | A5 governance multisig threshold — pass a PARAM_CHANGE with too few keyholder sigs | `if (good_sigs < param_threshold_)` → `if (false)` | 1 | trivial |
| 7 | VAL-param-distinct-keyholder | validator.cpp:820 | distinct keyholder indices — one keyholder counted N times toward threshold | drop the `seen_idx.insert(idx)` distinctness reject | 1 | trivial |
| 8 | VAL-batch-inner-sig | validator.cpp:1201 | COMPOSABLE_BATCH inner-tx sender authenticity — forge inner transfers | `if (!verify(ipk,..,it.sig))` → `if (false && ...)` | 1 | trivial |
| 9 | VAL-csr-field-match | validator.cpp:1412 | cross-shard receipt payload bound to its source TRANSFER — inflate a receipt amount | drop the amount clause from the disjunction | 1 | trivial |
| 10 | VAL-csr-size | validator.cpp:1396 | receipt COUNT bound to # cross-shard transfers — append unbacked receipts | `!=` → `>` (loop skips the extras) | 1 | trivial |
| 11 | VAL-inbound-f2-intersection | validator.cpp:1493 | F2 inbound-receipt authenticity (per-creator view intersection) — credit an unbacked inbound | delete the intersection enforcement | 1 | trivial |
| 12 | STAKE-balance-underspend | chain.cpp:1327 | STAKE value-conservation — stake more weight than the sender holds | `if (sender.balance < cost) continue;` → `if (false) continue;` | 1 | trivial |
| 13 | SR-declared-state-root-unbound | chain.cpp:1953 | S-033: declared state_root must equal the recomputed post-state | neuter the `computed != b.state_root` reject | 1 | trivial |
| 14 | DAPPCALL-balance-underspend | chain.cpp:1680 | DAPP_CALL value-conservation — spend more than held | delete `if (sender.balance < cost) continue;` | 1 | trivial |
| 15 | SHIELD-balance-underspend | chain.cpp:1026 | SHIELD value-conservation — mint a note worth more than the transparent debit | `if (sender.balance < cost) continue;` → `if (false) continue;` | 1 | trivial |
| 16 | VAL-inbound-f2-rootauth | validator.cpp:1486 | per-creator inbound view list bound to its Phase-1-committed root | neuter `compute_view_root(...) != root` | 2 | moderate |
| 17 | VAL-csr-src-block-index | validator.cpp:1410 | receipt src_block_index bound to the carrying block — misrepresent provenance | delete the `r.src_block_index != b.index` reject | 3 | trivial |
| 18 | VAL-timestamp-30s-window | validator.cpp:1772 | ±30s bound is the sole gate on a LEGACY block's (non-digest-bound) timestamp | `||` → `&&` (contradiction, reject dead) | 3 | moderate |

## 4. How to use this register

Same discipline as the sister register (§4 there): each row names a concrete accept-widening
mutation; close it by adding a NEGATIVE assertion (prefer EXTENDING an existing `test-*` subcommand
over a new one), then **falsify-on-mutant** — apply the named mutation, confirm the new assertion
turns RED **by counter-delta** (not merely the PASS line: a downstream gate can keep the block
`!r.ok`, so assert the SPECIFIC reject string), revert, confirm GREEN. Two traps to avoid, both
witnessed while closing BSIG-516: (1) a redundant check masked by a downstream guard (assert the
specific string, drive a fixture the target gate is UNIQUELY positioned to reject); (2) a well-tested
helper called by an unenforced comparison — gate the *caller* (`bv.validate()` via `err_of`), not the
helper.

**Non-claim.** This audit establishes *absence of an enforcing gate*, NOT the presence of a bug.
Every reject-path listed is believed correct in the current code; what is missing is the mechanism
that would catch it if it silently stopped rejecting.

## 5. Gate

A register, not a runtime property — no ratchet of its own. Anchored by the `src/node/validator.cpp`
+ `src/chain/chain.cpp` reject-paths it audits and refreshed by re-running the discovery Workflow.
Cross-references [ProofClaimGateTraceability.md](ProofClaimGateTraceability.md) (the sister
docs-claim register + the falsify-on-mutant discipline), `src/node/validator.cpp` (the `check_*`
gates), `Safety.md` / `BlockchainStateIntegrity.md` (the consensus-safety properties these gates
enforce).
