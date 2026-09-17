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

## 2. CLOSED (19 of 19 — REGISTER COMPLETE) — `check_block_sigs` (×2) + per-tx sender-sig + commit-reveal + tx_root-union + equivocation-slash + governance-multisig (×2) + batch-inner-sig + cross-shard-receipt-binding (×3) + F2-inbound-receipt-binding (×2) + apply-path value-conservation (×3) + declared-state-root + legacy-timestamp-window

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

### 2e. TXROOT-union-bind (block tx_root bound to the committee tx-lists)

**#4 TXROOT-union-bind** — `src/node/validator.cpp:226`, inside `check_creator_tx_commitments` (gate 4
of `validate()`). The block-header `tx_root` must equal the union of the committee's tx-hash lists:

```cpp
Hash expected_root = compute_tx_root(b.creator_tx_lists);
if (expected_root != b.tx_root)
    return {false, "tx_root mismatch with union(creator_tx_lists)"};
```

**Consequence if silently removed:** a producer can publish a `tx_root` in the header that does NOT
match the actual `creator_tx_lists` — smuggling transactions into (or misrepresenting) the block's
committed transaction set that downstream `tx_root`-trusting consumers (light clients, inclusion
proofs) would treat as canonical.

**A pre-existing test *mentions* this gate but does NOT pin it — the trap-1 case, caught and
documented.** `test-block-validator-extensive`'s "V4 alt" leg (`~main.cpp:50917`) builds a block with a
**garbage `creator_ed_sigs[0]`** and asserts the *disjunction* `"creator commit" OR "tx_root"`. The
zero signature trips the EARLIER creator-commit-sig gate (`:217`, `"creator commit sig invalid"`) so
the `|| "tx_root"` arm is **vacuous** — control flow never reaches `:226`. Verified directly: under the
`:226` mutant that V4-alt assertion stays GREEN. So `:226` was genuinely un-pinned; the disjunction was
false comfort.

**Gate (in-process, both platforms).** Extended `test-abort-cert-validation`, reusing its `build_block`
lambda whose block has **valid** commit sigs (so the `:217` loop passes) and `tx_root =
compute_tx_root(creator_tx_lists)`. New leg: `Block b = build_block(...); b.tx_root[0] ^= 0x01;` →
drive `bv.validate(b, c, reg)` and assert `"tx_root mismatch with union(creator_tx_lists)"`; an
un-mutated copy is the positive control. Because the commit-sig loop passes, the flipped header
`tx_root` is the UNIQUE thing `:226` can reject.

**The load-bearing subtlety (same shape as DHS).** `check_creator_tx_commitments` (`:46`) runs BEFORE
`check_delay` (`:50`) and `check_block_sigs` (`:51`), and the `:210-217` commit-sig loop reads only the
per-creator tx list (never `b.tx_root`), so with the gate present `:226` rejects first. Under the mutant
the bogus-`tx_root` block is NOT accepted — it is caught DOWNSTREAM by `check_delay`'s `delay_seed`
binder (`compute_delay_seed` folds `tx_root` → `"delay_seed mismatch"`), so a vacuous `!r.ok` would stay
GREEN; asserting the specific `"tx_root mismatch with union(creator_tx_lists)"` string is what flips it
RED.

*Falsify-on-mutant (executed via a rebuilt `determ.exe`).* `:226 → if (false && expected_root != …)`
flips ONLY the forged assertion RED (a clean 1-assertion counter-delta) while the positive control, the
BASELINE, and the pre-existing V4-alt leg all stay GREEN. Reverted via `git checkout` (committed clean
this round), rebuilt → GREEN. Structural twin of DHS-commit-reveal-bind (§2d) — same host, same
first-gate-then-delay-binder ordering — so closed by direct source-verification rather than a fresh
analysis workflow.

### 2f. EQV-sig-verify-forged-slash (equivocation evidence must be a genuine double-sign)

**#5 EQV-sig-verify-forged-slash** — `src/node/validator.cpp:394`, inside `check_equivocation_events`
(gate at `validate()` `:49`). An `EquivocationEvent` is *evidence*; the gate
requires BOTH signatures to genuinely verify against the equivocator's committee key over two distinct
digests:

> **Re-derived 2026-09-17 (step 3c).** When this audit was written the evidence drove a full-stake
> forfeit + deregistration at apply, and that is the harm every `Consequence` paragraph in this section
> measures. Owner decision D4 (2026-09-16, landed as O-1 step 3a) removed it: `Chain::apply_transactions`
> reads nothing from `b.equivocation_events`. **The gate itself is unchanged and still required** — the
> event is committed on-chain and is the declared INPUT to the L2 bond policy (D22), so an accepted
> forgery becomes a permanently recorded false accusation rather than a stake theft. Read every
> "slash" below as "produce a V11-accepted on-chain accusation"; the *severity ranking* of this section
> was set against stake theft and is not re-ranked here.

```cpp
Hash digest_a = compose(ev.index_a, ev.body_root_a);   // DERIVED, never carried
if (!verify(*ek, digest_a.data(), digest_a.size(), ev.sig_a))
    return {false, "equivocation_event[i] sig_a does not verify against equivocator's key"};
```

**UPDATE 2026-08-12 — the gate grew two arms and the digests became derived (S-052).** The audited
`:394` sig-verify arm survives verbatim in intent, but the surrounding gate was restructured to close
the rank-1 forged-slash hole this section's `Consequence` paragraph only half-saw. `EquivocationEvent`
no longer carries `digest_a`/`digest_b`; it carries `kind` plus a per-side opening
`(index, body_root)`, and the verifier DERIVES each digest under the kind's domain tag before
verifying. Two arms were added AHEAD of the sig-verify: a `kind > 1` fail-closed reject, and the
**height assert** `index_a == index_b == block_index`. Without the height assert, sig-verify alone was
*insufficient*: an attacker needed no forgery at all — replaying one honest validator's GENUINE
signatures from two DIFFERENT heights satisfied every arm audited above, including this one, and forged
a full-stake slash. The audit's own framing ("a producer can FORGE a slash … whose `sig_a` was never
actually signed") assumed forgery was the only route; it was not. Recorded rather than quietly patched,
per B3. Current gate: `src/node/validator.cpp:380`; the two new arms are pinned by two additional
mutants in the same fixture (delete the height assert; weaken it to `index_a == index_b`), each RED on
exactly its own arm.

**Consequence if silently removed:** a producer can FORGE a slash of an **honest** validator — submit
an `EquivocationEvent` whose `sig_a` was never actually signed by the named equivocator — and the
honest validator is punished for a double-sign it never committed. This is a *griefing / stake-theft*
primitive against any committee member.

**Genuinely un-pinned — a subtle trap-1 cleared.** Three suites *mention* the sig-verify reject but
none pins `:394`: `test-equivocation-evidence` asserts against a **local re-implemented** `verify_evidence`
lambda (not the validator); `test_light_verify_equivocation.sh` / `test_wallet_verify_equivocation.sh`
drive **separate binaries** with a different reject string; and the apply-path tests
(`test-equivocation-apply/-multi`) inject default sigs through `Chain::append`, which never runs
`check_equivocation_events`. `test_equivocation_slashing.sh` signs GENUINE sigs (the accept path,
through the `on_equivocation_evidence` RPC gate). No test populated `b.equivocation_events` on a real
`check_equivocation_events` call, so the mutant survives green.

**Gate — a new isolation seam (the sole production change of this round).** `check_equivocation_events`
is private and (unlike tx_root/dh) the block-sig digest binds `sig_a` on an F2-reconciled block, so an
Option-A "tamper after signing" fixture would be **masked** by `check_block_sigs` (`:51`) on an F2 block
— both original and mutant reject there, never reaching `:394`. So a byte-neutral const-forwarder seam
`check_equivocation_events_for_test(b, registry, chain)` was added to `validator.hpp` (the 5th instance
of the established `*_for_test` pattern), isolating `:394`. Fixture (hosted in
`test-abort-cert-validation`, reusing its n0..n3 genesis + `key_of`): build a GENUINE double-sign by
registered creator n0 (distinct digests `dA`/`dB`, `sig_a=sign(key_of("n0"),dA)`, `sig_b=sign(…,dB)`) —
clears `:382` (digests differ) `:385` (sigs differ) `:390` (n0 registered) `:394`/`:397` (both verify);
then `forged=ev; forged.sig_a[0] ^= 0xFF` so `:394` is the SOLE failing arm; assert the reject contains
`"sig_a does not verify against equivocator's key"`. The un-mutated event is the positive control
(asserts `r.ok` — proving the equivocator resolves present-head and the ACCEPT arm is non-vacuous).

*Falsify-on-mutant (executed via a rebuilt `determ.exe`).* `:394 → if (false && !verify(…))` makes the
forged event flow to `:397` (genuine `sig_b` verifies), the loop completes, and the gate returns
`{true,""}` — the **forged slash is ACCEPTED**. So `r.error` no longer contains the specific substring
→ the negative assertion flips RED (a clean 1-assertion counter-delta) while the positive control stays
GREEN. Reverted via `git checkout src/node/validator.cpp` (the seam lives in `validator.hpp` and is
kept). Design nailed by a parallel read-only analysis workflow (`wf_edd60f84-21c`) — including the
Option-A-masking and arg-order (`b, registry, chain`) traps — before any code changed.

### 2g. VAL-param-multisig — the A5 governance PARAM_CHANGE multisig (two gates)

**#6 VAL-param-multisig-threshold (`validator.cpp:827`) + #7 VAL-param-distinct-keyholder (`:820`)** —
both inside the `TxType::PARAM_CHANGE` case of `check_transactions`. A governance parameter change is
authorized by `param_threshold_` **distinct** keyholder signatures over the canonical
`(name ‖ value ‖ effective_height)` tuple:

```cpp
if (!seen_idx.insert(idx).second)                       // :820 distinct-keyholder
    return {false, "PARAM_CHANGE duplicate keyholder_index"};
if (verify(param_keyholders_[idx], sig_msg…, msig)) good_sigs++;
…
if (good_sigs < param_threshold_)                        // :827 threshold
    return {false, "PARAM_CHANGE signature threshold not met …"};
```

**Consequence if silently removed:** dropping `:820` lets one keyholder's signature be **replayed**
`param_threshold_` times (same `keyholder_index`), reaching the threshold with a **single key**;
dropping `:827` accepts a PARAM_CHANGE with **fewer than the required** (even zero) valid signatures.
Either is a single-key governance takeover — an attacker who compromises one keyholder (or none) can
push through any whitelisted parameter change (MIN_STAKE, SUSPENSION_SLASH, the keyholder set itself…).

**Genuinely un-pinned.** The only prior governance tests are a setter smoke-test (`v.set_governance_mode`
/ `set_param_keyholders` / `set_param_threshold` called for no-throw, no tx driven) and
`test-governance-param-determinism` (FA-Apply-8, a determinism check). No test drove a PARAM_CHANGE with
a duplicate index or a below-threshold sig set through the validator; the two reject strings are
asserted nowhere.

**Gate (in-process, both platforms).** Both gates share ONE fixture, hosted in
`test-abort-cert-validation` (reusing its n0..n3 genesis + `key_of`): a fresh `BlockValidator pv` with
`set_governance_mode(1)`, `set_param_keyholders({n0,n1,n2 pubkeys})`, `set_param_threshold(2)`. A
`run_pc(sigs)` helper builds a PARAM_CHANGE tx from registered sender **n0** (payload
`nlen‖name‖vlen_LE‖value‖eff_LE ‖ sigc ‖ {idx_LE16,sig}…`, name `"MIN_STAKE"` on the whitelist, each
keyholder signs the `sig_msg` prefix, the tx itself signed by n0 to clear the `:685` sender gate) and
drives it through the `check_transactions_for_test` seam. Three legs: **positive control** — 2 distinct
valid sigs `{(0,s0),(1,s1)}` → ACCEPTED; **:820** — `{(0,s0),(0,s0)}` (replay idx 0) → assert
`"duplicate keyholder_index"`; **:827** — `{(0,s0)}` (one sig `< 2`) → assert
`"signature threshold not met"`. Both arms are the LAST checks of the case, so under either mutant the
tx is cleanly ACCEPTED (no downstream masking).

*Falsify-on-mutant (executed via a rebuilt `determ.exe`, each gate INDEPENDENTLY).* `:820 → if (false &&
!seen_idx.insert(idx).second)` flips ONLY the distinct-keyholder assert RED (the threshold assert +
control stay GREEN — proving `:820` alone is load-bearing and the leg targets its own gate); separately
`:827 → if (false && good_sigs < param_threshold_)` flips ONLY the threshold assert RED. Reverted via
`git checkout src/node/validator.cpp` between passes. Both closed by direct source-verification (the
PARAM_CHANGE decode is authoritative and the encoding was cross-checked against the `submit-param-change`
builder) — no analysis workflow needed.

### 2h. VAL-batch-inner-sig (COMPOSABLE_BATCH inner-transaction authenticity)

**#8 VAL-batch-inner-sig** — inside the `TxType::COMPOSABLE_BATCH` case of `check_transactions`
(`src/node/validator.cpp`; `:1201` at audit time). A v2.4 atomic batch carries inner TRANSFERs
(since D2-inc4 `7bcd32d` as the canonical binary batch payload — `[u16 LE inner_count]` +
count × length-prefixed `Transaction` frames via the shared `decode_batch_payload`; at audit time
as a JSON array); each inner tx moves funds from its OWN `inner.from` account, so each must be
independently signed by that sender:

```cpp
auto sb = it.signing_bytes();
if (!verify(ipk, sb.data(), sb.size(), it.sig))
    return {false, "COMPOSABLE_BATCH inner[" + std::to_string(ii) + "] signature invalid from " + it.from};
```

**Consequence if silently removed:** a batch can carry FORGED inner transfers — the outer batch tx is
validly signed by *its* sender (who pays the fee), but the inner TRANSFERs would move funds out of
arbitrary victim accounts with no valid authorization. Batch-scoped fund theft.

**Genuinely un-pinned.** `test-composable-batch` exercises the *apply-path* semantics (all-or-nothing
rollback, balance/nonce effects) by driving **unsigned** inner txs through `Chain::append` — which
never runs `check_transactions`, so `:1201` is never reached. No test drove a signed/forged inner tx
through the validator; the reject string is asserted nowhere. (Same apply-path-vs-validator shape as the
EQV finding.)

**Gate (in-process, both platforms).** Hosted in `test-abort-cert-validation` (reuses n0..n3 + `key_of`),
packing via the shared codec (`chain::encode_batch_payload` since D2-inc4; at audit time inline JSON
`arr.push_back(it.to_json()); arr.dump()`). A `run_batch(forge)` helper: build one inner TRANSFER n1→n2 (fee 0,
signed by n1 — clears the type / fee / payload-size / registry gates ahead of `:1201`), optionally flip
one byte of the inner `sig`, pack it into `outer.payload`, then sign the OUTER `COMPOSABLE_BATCH` tx
(from n0) over that payload; drive `check_transactions_for_test`. Legs: **positive control** — validly
signed inner → ACCEPTED; **forge** — inner `sig[0] ^= 0xFF` → assert
`"COMPOSABLE_BATCH inner[0] signature invalid"`.

**The load-bearing subtlety (the outer-sig masking trap).** The inner sig lives INSIDE `outer.payload`,
and the outer `tx.sig` covers the payload (verified at `:685`). So the inner sig must be corrupted FIRST
and the outer RE-SIGNED over the mutated payload — otherwise the `:685` outer-sender gate rejects
`"tx signature invalid"` before `:1201` is reached (testing the wrong gate). `to_json`/`from_json`
roundtrip `sig` (`j["sig"] = to_hex(sig)` ↔ `from_hex_arr<64>`), so the corrupted inner sig survives the
pack→parse. `:1201` is the LAST inner check before `break`, so under the mutant the forged-inner batch
is cleanly ACCEPTED (no downstream masking).

*Falsify-on-mutant (executed via a rebuilt `determ.exe`).* `:1201 → if (false && !verify(…))` accepts
the forged-inner batch → the specific-string assertion flips RED (clean 1-assertion counter-delta) while
the positive control stays GREEN. Reverted via `git checkout`. Direct-verify (the batch decode is
authoritative and the packing matched the `pack_batch` helper) — no analysis workflow needed.

### 2i. VAL-csr cluster — the cross-shard-receipt binding gates (three gates)

**#10 VAL-csr-size (`validator.cpp:1396`) + #17 VAL-csr-src-block-index (`:1410`) + #9 VAL-csr-field-match
(`:1412`)** — all in `check_cross_shard_receipts`, which rederives the block's cross-shard TRANSFER
subset and binds each `cross_shard_receipts[i]` one-for-one to its source tx:

```cpp
if (cross.size() != b.cross_shard_receipts.size()) return {…,"cross_shard_receipts size …"};   // :1396
…
if (r.src_block_index != b.index)                   return {…,"src_block_index mismatch"};       // :1410
if (r.tx_hash != tx.hash || … || r.amount != tx.amount || …) return {…,"field mismatch with tx"};// :1412
```

**Consequence if silently removed:** `:1396` — a producer appends an **unbacked** receipt (count >
cross-tx count; the loop only iterates the tx count, so the extra rides through), crediting a
destination shard for a transfer that never happened; `:1410` — a receipt misrepresents its source
block height (provenance); `:1412` — a receipt's **amount** (or from/to/fee/nonce/tx_hash) diverges from
its source tx — i.e. **inflate a cross-shard receipt amount** so the destination shard over-credits.
Cross-shard supply-conservation break.

**Genuinely un-pinned.** `test-sr5-misroute-receipt` builds a *fully valid* cross-shard fixture but only
forges `dst_shard` (Theorem SR-5 misroute); its own comment notes the receipt "passes the src_shard /
size / src_block_index / field-match guards" without ever forging them. None of the three reject strings
is asserted anywhere.

**Gate (in-process, both platforms).** Three forge legs added to `test-sr5-misroute-receipt`, reusing its
`tx` / `make_receipt` / `c` / `v` and the `check_cross_shard_receipts_for_test` seam. The forges are
ORTHOGONAL — **size** (two receipts for one cross-tx → `"cross_shard_receipts size"`), **src_block_index**
(`r.src_block_index = 999` → `"src_block_index mismatch"`), **amount** (`r.amount = tx.amount + 1` →
`"field mismatch with tx"`) — so each is the UNIQUE gate that can reject its forge (the size forge is
caught only by `:1396` because the loop body examines only the valid index-0 receipt; the others match
every field except the one forged).

*Falsify-on-mutant (three INDEPENDENT rebuilt-`determ.exe` passes, one per gate — proving each is
separately load-bearing and each leg targets its own gate).* `:1396` `!=` → `>` (the register's faithful
"loop skips the extras" mutation) flips ONLY the size assert RED; `:1410 → if (false && …)` flips ONLY
src_block_index; `:1412` drop the `r.amount != tx.amount` clause flips ONLY field-match. The SR-5 legs and
the positive control stay GREEN in all three passes. Reverted via `git checkout` between passes.
Direct-verify (the receipt-binding logic is authoritative; the register named each mutation) — no analysis
workflow needed.

### 2j. VAL-inbound-f2 cluster — the F2 inbound-receipt admission binding gates (two gates)

**#11 VAL-inbound-f2-intersection (`validator.cpp:1493`) + #16 VAL-inbound-f2-rootauth (`:1486`)** inside
`check_inbound_receipts` — a DISTINCT function from the outbound `check_cross_shard_receipts` of §2i. When
F2 is active (`b.index >= chain.f2_active_from_height()`) and a block admits inbound cross-shard receipts,
the admitted set must be the deterministic committee-wide intersection of the K creators' Phase-1-committed
inbound views, and each carried per-creator view list must authenticate against its committed root:

- **:1493 intersection** — `if (!iset.count(hash_cross_shard_receipt(inbound_receipts[i]))) return "… not in
  committee-view intersection"`. Removing it credits an inbound receipt **no committee member witnessed** —
  an admitted inbound receipt CREDITS funds on this (destination) shard, so this is mint-from-nothing.
- **:1486 rootauth** — `if (compute_view_root(creator_view_inbound_lists[i]) != root) return "… does not
  match committed root"`. Removing it lets a producer **substitute a spoofed view list post-commit** to
  fabricate the intersection (the roots are bound into each creator's Phase-1 commit in
  `check_creator_*`), which then lets an unwitnessed receipt into the admitted set.

**Genuinely un-pinned.** No test builds `creator_view_inbound_lists` at all (the sole grep hit is a comment
that deliberately *avoids* the `":…does not match committed root"` substring); the F2 helper tests exercise
`compute_view_root` / `reconcile_intersection` in isolation but never drive `check_inbound_receipts`.

**Seam.** `check_inbound_receipts` is a *private* method, so a byte-neutral public const-forwarder
`check_inbound_receipts_for_test(b, chain)` (2-arg, no registry — the check reads only `b` + `chain`) was
added to `validator.hpp` (the 6th `*_for_test` instance, same pattern as `check_cross_shard_receipts_for_test`).
The seam bypasses `validate()`, so no block-sig/digest gate can mask a forged view list.

**Gate (in-process, both platforms).** A dedicated F2-inbound section appended to `test-sr5-misroute-receipt`
reuses its multi-shard `c` (`my_shard_id = 0`) and `v`, with `c.set_f2_active_from_height(0)`. A `make_inbound(seed)`
helper builds a shape-valid inbound receipt (`dst_shard = 0`, `src_shard = 1`, distinct `tx_hash` per seed).
The **positive control** — one receipt, both view lists `[H(r)]`, roots `compute_view_root([H(r)])` — is
ACCEPTED. The two forges are ORTHOGONAL: **:1493** carries *authenticated* lists (roots match) holding only a
DECOY hash, so the admitted receipt is absent from the intersection → `"not in committee-view intersection"`;
**:1486** SPOOFS the lists to include `H(r)` but carries the genuinely-committed roots (over a different list),
so the list fails root-auth → `"does not match committed root"` (and `H(r)` *is* in the spoofed intersection,
so `:1493` cannot mask it).

*Falsify-on-mutant (two INDEPENDENT rebuilt-`determ.exe` passes).* `:1493 → if (false && !iset.count(…))`
flips ONLY the intersection assert RED (control + rootauth GREEN); `:1486 → if (false && compute_view_root(…)
!= root)` flips ONLY the rootauth assert RED (control + intersection GREEN). `git checkout` between passes.
Direct-verify — the admission logic is authoritative; the register named each mutation — no analysis workflow.

### 2k. Apply-path value-conservation cluster — the balance-underspend gates (three gates)

**#12 STAKE-balance-underspend (`chain.cpp:1327`) + #14 DAPP_CALL-balance-underspend (`:1680`) + #15
SHIELD-balance-underspend (`:1026`)** in `apply_transactions` (the `Chain::append` apply path, a DIFFERENT
surface from every §2a-§2j gate, which live in the `validate()` path). Each per-tx case guards
`if (sender.balance < cost) continue;` immediately below its S-049 `amount+fee` overflow guard; removing it
lets `sender.balance -= cost` UNDERFLOW to ~2^64 while the mint still lands — locked consensus weight
(`stakes_[from].locked += amount`), a recipient credit (`accounts_[to].balance += amount`), or a phantom
confidential note (`accumulated_shielded_ += A`). This is the highest-impact class after fund theft: an
overspend that mints value the sender never held.

**★ WHY VALIDATOR TESTS MISS IT.** The apply path never re-runs the validator's balance check (the exact
apply-path-vs-validator gap behind the EQV + batch findings). And the A1 unitary-supply invariant asserted
at end-of-block is **mod-2^64 blind** ([[determ-a1-supply-invariant-mod2^64-blind]]): the −cost underflow and
the +mint are exact-2^64 complements, so `live_total_supply() == expected_total()` still holds and apply does
NOT throw — the sender is simply left holding the wrapped balance. So the falsifier is a value-conservation
observable, not a reject string: **"sender balance UNCHANGED after an overspend"** (throw-robust — a future
A1 tightening would surface as a throw, which must also read as not-conserved).

**Genuinely un-pinned.** No test drove an overspend STAKE/DAPP_CALL/SHIELD through `Chain::append` and
asserted the skip; the only pre-switch guard is the sequential-nonce check at `:970`.

**Gate (in-process, both platforms).** Three scenarios appended to `test-value-overflow-mint` (the sibling
that already pins the S-049 overflow guard one line above each target), reusing its `fresh_chain(bal)` /
`base_block(c)` / `balance()`/`stake()`/`next_nonce()` scaffolding. STAKE: an 8-byte-LE overspend (amount
1000 > balance 100) is skipped → stake 0, balance 100. DAPP_CALL: register an active DApp (an affordable
call FIRST proves the debit/credit path is live), then an overspend call → recipient uncredited, sender
unchanged. SHIELD: the balance guard sits ABOVE the payload-size / `determ_shield_verify` / dup-commitment
guards, so the forged tx must carry a GENUINELY VALID 98-byte note (`commit(A,r)` + P-256 balance PoK, the
`make_shield` recipe) for A = 1000 > balance 100 — a valid payload is REQUIRED or a downstream guard masks
the mutant.

*Falsify-on-mutant (three INDEPENDENT rebuilt-`determ.exe` passes).* Each `if (sender.balance < cost)
continue;` → `if (false && …) continue;` flips ONLY its own scenario RED; the affordable DApp control and
the other two conservation scenarios stay GREEN — proving each gate is separately load-bearing and that the
SHIELD payload genuinely reaches the debit past `determ_shield_verify` (a masked/invalid payload would leave
`:1026` un-falsifiable). Reverted via `git checkout` between passes. Host + per-type fixtures + masking
nailed by a 6-agent read-only analysis workflow (`wf_f76c5eb0-1b9`) before touching code.

### 2l. The final two — declared-state-root + legacy-timestamp-window (the register closers)

Two independent single-check gates on two different surfaces, closed together as the terminal round.

**#13 SR-declared-state-root-unbound (`chain.cpp:1953`)** in `Chain::append` (apply): a block carrying a
NON-ZERO `state_root` must equal `compute_state_root()` after apply, else append throws `"state_root
mismatch … (S-033)"`. Removing the reject lets a producer publish a FALSE post-state under an honest digest —
a validate-vs-apply divergence that light clients / fast-sync peers would trust. **Gate = two scenarios in
`test-chain-apply-block`** (reuses its genesis `cfg` + `Chain::append`, no seam — `compute_state_root()` is
public): a block declaring the CORRECT post-state (obtained by a deterministic dry-run on an identical
chain) is ACCEPTED; a block declaring an all-`0xFF` (non-zero, wrong) root is REJECTED with the SPECIFIC
`"state_root mismatch"` (throw-robust `catch`). Mutant `if (false && computed != b.state_root)` accepts the
false root → only the negative leg flips; the timestamp gate is untouched.

**#18 VAL-timestamp-30s-window (`validator.cpp:1772`)** in `check_timestamp`: the ±30s wall-clock bound
`if (diff > 30 || diff < -30) return reject` is the SOLE gate on a LEGACY block's (empty
`creator_proposer_times`) timestamp — the digest-bound median path only covers feature blocks. **Gate = a
section in `test-block-timestamp`** driving a new 1-arg `check_timestamp_for_test` seam under an injected
`VirtualClock` (via public `set_clock`): a timestamp at "now" and at the +30s boundary is ACCEPTED; a
timestamp ±1000s away is REJECTED with `"timestamp out of +-30s window"`. The register's `||` → `&&` mutation
makes the reject a dead contradiction → BOTH the future- and past-skew legs flip (both arms load-bearing),
controls + the state-root gate green. Direct-verify — both mutations are named by the register and both
checks are single-branch, so no analysis workflow. **This round closes the register: 19 / 19.**

## 3. The enumerated residual (0 open — REGISTER COMPLETE)

**The backlog is empty.** All 19 confirmed accept-widening reject-paths that `wf_eb293ab6-600` surfaced are
now closed as falsify-on-mutant negative tests (§2a-§2l), each verified on BOTH platforms (MSVC FAST + WSL2
GCC ci_local) with a clean per-gate counter-delta. Every gate was closed one cluster per directive,
cheapest-value-first. Any future accept-widening branch discovered in `validate()` / `apply_block` /
`apply_tx` opens a NEW row here and is closed by the same falsify-on-mutant method.

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
