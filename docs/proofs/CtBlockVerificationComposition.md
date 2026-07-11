> **TIER: NEAR-TERM — 1.0.x in-flight.** Composes the shielded-pool CT track (`ShieldedPoolSoundness.md`) + the light-client anchor family; local, not yet pushed. Not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# CtBlockVerificationComposition — `determ-light verify-ct-block --rpc`: block[H] is committee-attested AND its transactions[] are exactly those the committee signed AND every confidential tx carries a valid range/balance proof

This is the "what is proven vs. what is assumed-in-prose" honest accounting for the **`verify-ct-block`** subcommand of `determ-light` (`light/main.cpp:3267` `cmd_verify_ct_block`). The command is a **pure composition of three shipped, audited primitives** against a pinned genesis — it introduces **no new crypto, no new Merkle logic, no new signature logic**. It is the RPC-driven form of the offline sibling `block-verify` (`light/main.cpp:885` `cmd_block_verify`, which runs off a block+committee *file*): here the committee is **derived from the pinned genesis** (the untrusted-daemon posture) and the block is **fetched + anchored**, not supplied.

The command fetches block `H` from a **single, fully-adversarial** daemon (`A_daemon`, `LightClientThreatModel.md` §2.1) and, in one invocation, proves three things:

1. **ANCHOR** — header[H] chains to the pinned genesis by an unbroken `prev_hash` walk and is committee-attested, yielding a **committee-anchored `block_hash(H)`**. This is `verify_state_root_at` — the S-042 successor-binding primitive (`light/verify_state_root.hpp:116`, `light/trustless_read.cpp:547` `committee_bound_state_root`).
2. **BODY-PIN** — the **full** block the daemon serves recomputes to **exactly** that committee-anchored `block_hash(H)`. A doctored body (swapped or injected tx) changes `Block::compute_hash` → fail-closed. This is the same full-block-recompute trust step `trustless_read` / `verify-chain` already rely on (`light/trustless_read.cpp:236-244`, the SOUNDNESS PIN). It binds `transactions[]` to the committee signature.
3. **CT-PROOFS** — every confidential tx in the now-committee-authenticated body re-verifies its range/balance proof **client-side** via `verify_ct_transactions` (`light/verify_ct.cpp:141`, `light/verify_ct.hpp:57` — the A3 accept-rule mirror).

**Honest scope, unchanged from the primitives (stated up front, expanded in §5).** This proves **CRYPTOGRAPHIC validity + committee-attestation only**. Note-**SET** correctness — that each confidential input note was **unspent** (double-spend rejection) — is **NOT** established here. It stays anchored by the committee-signed `state_root` over the `cn:` state namespace, exactly as `verify_ct.hpp:19-25` declares for the underlying verifier. This command proves *the block is real and its CT proofs are valid*, **not** that its input notes were unspent.

**Inherited crypto (no new hardness assumption).** ANCHOR inherits `StateRootAnchorSoundness.md` (SR-1/SR-2) + `LightClientThreatModel.md` (T-L1/T-L2) — A1 (Ed25519 EUF-CMA) + A2 (SHA-256 collision). BODY-PIN inherits the `trustless_read` full-block-recompute pin — A2. CT-PROOFS inherits `ShieldedPoolSoundness.md` (SP-1/SP-6/SP-10/SP-11) and `ConfidentialTxBalanceSoundness.md` (CTB-3 etc.) — DL + Fiat-Shamir ROM over P-256. This document adds **zero** new assumptions; it draws the composition edges.

---

## 1. What the command does — the three-stage pipeline

Arguments: `--rpc-port`, `--genesis`, `--height` are required; `--wait <s>` and `--json` optional (`light/main.cpp:3272-3287`). The genesis file is loaded and the committee is **derived from it** (`build_genesis_committee`, `light/main.cpp:3291-3292`; defined `light/trustless_read.cpp:48`) — never a user-supplied committee file, so the trust root is the operator's pinned chain identity. `anchor_genesis` (`light/main.cpp:3298`; defined `light/trustless_read.cpp:56`) fail-closes if the daemon's block 0 ≠ `compute_genesis_hash(genesis)`.

```
(1) ANCHOR    sr = verify_state_root_at(rpc, committee_seed,           main.cpp:3301
                                        genesis_hash_hex, height, wait_seconds)
              if (!sr.ok) → exit 3   ("ANCHOR failed: …")             main.cpp:3303-3312
              ⟹ sr.block_hash_hex is the committee-anchored block_hash(H)

(2) BODY-PIN  full = rpc.call("block", {index: height})               main.cpp:3316
              fb   = Block::from_json(full)                           main.cpp:3333
              body_hash = to_hex(fb.compute_hash())                   main.cpp:3334
              if (body_hash != sr.block_hash_hex) → exit 3            main.cpp:3345-3357
              ⟹ the served body is EXACTLY the committee-signed block

(3) CT-PROOFS ct = verify_ct_transactions(full)                      main.cpp:3362
              ok = ct.ok()                                            main.cpp:3363
              return ok ? 0 : 3                                       main.cpp:3410
              ⟹ every SHIELD/UNSHIELD/CONFIDENTIAL_TRANSFER re-verified
```

Note the ordering is load-bearing: **BODY-PIN runs before CT-PROOFS**, so `verify_ct_transactions` walks a body that has *already* been recompute-matched to the committee-anchored hash. CT-PROOFS never runs against an unauthenticated body.

---

## 2. Claims (CTB-BLOCK-1 .. CTB-BLOCK-5)

**PROVEN-in-code** = enforced by shipped, sequential, fail-closed source at the cited `file:line`. **inherited-in-prose** = a reduction to a cited primitive theorem (proved in its home document). The command adds no new crypto; every hardness reduction bottoms out in a primitive proof.

### CTB-BLOCK-1 — ANCHOR yields a genesis-pinned, committee-attested `block_hash(H)`

**Statement.** After stage (1), `sr.block_hash_hex` is the `block_hash` of a header at height `H` that (a) chains to the **pinned** genesis by an unbroken `prev_hash` walk and (b) for `H > 0` carries `⌈K⌉`-of-`K` (MD) / `⌈2K/3⌉` (BFT-fallback) committee Ed25519 signatures over `light_compute_block_digest(H)`; for `H == 0` it is the genesis-hash match itself (block 0 carries no committee sigs by construction). A daemon cannot present a `block_hash(H)` the committee did not attest.

**Proven-in-code.** `verify_state_root_at` is called at `light/main.cpp:3301-3302` with the genesis-derived `committee_seed` and the recomputed `genesis_hash_hex`; on `!sr.ok` the command fail-closes with exit 3 (`light/main.cpp:3303-3312`) — it **never** proceeds on an unverified anchor. The primitive's trust argument is documented at `light/verify_state_root.hpp:25-49`: (1) genesis pin, (2) unbroken `prev_hash` chain from block 0 through H, (3) committee sigs over the digest. The `state_root`/`block_hash` at H is bound **transitively-forward** by the committee-signed successor via `successor.prev_hash == recomputed block_hash(H)` (`light/trustless_read.cpp:726-728`, `committee_bound_state_root` at `:547`).

> **Load-bearing (the anchor is the committee-bound hash, NOT the daemon field).** `sr.block_hash_hex` for `H ≥ 1` is set to the **recomputed** `block_hash` the successor's committee signature commits — surfaced out of `committee_bound_state_root` via its `out_committee_block_hash` param **only after** the `successor.prev_hash == recomputed_hex` binding check passes (`light/trustless_read.cpp` §6, write-once-on-success; captured into `res.block_hash_hex` at `light/verify_state_root.cpp` H≥1 branch). It is emphatically **NOT** the daemon-reported `block_hash` header FIELD — that field is committee-un-attested (the committee signs `compute_block_digest`, which does not bind a header's own `block_hash`), so pinning a body against it would be **circular**. Pinning against the committee-bound recomputed hash is what makes CTB-BLOCK-2 sound. (`H == 0` keeps the reported field, but it is pinned to the operator's **local** `compute_genesis_hash` by `walk_chain_to`'s genesis-anchored first page — the strongest anchor, not a daemon claim.)

**inherited-in-prose.** `StateRootAnchorSoundness.md` SR-1 (committee-anchored per-height root, transitive-forward) + SR-2 (genesis-binding); `LightClientThreatModel.md` T-L1 (genesis anchor, A2/A3) + T-L2 (committee-sig head trust, A1). Bound `≤ K·2⁻¹²⁸`.

**Evidence.** This is exactly the guarantee `verify-state-root` (`light/main.cpp:3156`) ships and `tools/test_light_verify_state_root.sh` exercises; `verify-ct-block` reuses the identical call, so its ANCHOR half inherits that test surface.

### CTB-BLOCK-2 — BODY-PIN binds `transactions[]` to the committee signature

**Statement.** The full block object the daemon returns for `H` (`rpc.call("block", {index: H})`) is parsed to a `determ::chain::Block` and its **recomputed** `block_hash = to_hex(fb.compute_hash())` must equal `sr.block_hash_hex` from CTB-BLOCK-1. On any inequality the command fail-closes (exit 3). Because `Block::compute_hash` is a function of the **entire** block body — including the `transactions[]` array — a daemon that swaps, injects, drops, or reorders any tx produces a different `compute_hash` and is rejected. Therefore a passing BODY-PIN certifies that `transactions[]` is **exactly** the committee-signed block body.

**Proven-in-code.** `light/main.cpp:3316` (fetch full block), `:3333-3334` (`Block::from_json` → `compute_hash`), `:3345-3357` (the `body_hash != sr.block_hash_hex` guard → exit 3, diagnostic "daemon served a body inconsistent with the signed header"). A malformed body that fails `Block::from_json` is caught and fail-closed at `:3335-3343` ("malformed full block"). This is the **same** full-block-recompute trust step the chain walk already relies on — `light/trustless_read.cpp:236-244` (the "SOUNDNESS PIN" comment): *"the full body's recomputed block_hash MUST equal the stripped header's block_hash … the committee cannot be made to sign a forged body (a doctored full block changes the digest and the K sigs fail), and the block_hash pin stops a daemon from substituting a differently-positioned but validly-signed block."*

**inherited-in-prose.** A body that recomputed to `sr.block_hash_hex` while differing from the genuine committee-signed body is a **SHA-256 collision** on `Block::compute_hash` — A2, bound `≤ 2⁻¹²⁸`.

**Evidence.** Structurally identical to the F-7 full-block fallback in `verify-chain` (`light/trustless_read.cpp:245-275`), whose `to_hex(fb.compute_hash()) == chained_hash` gate is the same pin exercised by `tools/test_light_verify_chain.sh`.

### CTB-BLOCK-3 — CT-PROOFS re-verifies every confidential tx client-side

**Statement.** `verify_ct_transactions(full)` walks `full["transactions"]` and, for each SHIELD (12) / UNSHIELD (13) / CONFIDENTIAL_TRANSFER (14) tx, re-runs the **same** cryptographic accept-rule the validator runs. `ct.ok()` is true iff **every** confidential tx's range/balance proof verifies; a block with zero CT txs verifies vacuously with an explicit `ct_txs == 0` count (the anti-silent-vacuity signal). The command's exit code is `ok ? 0 : 3`.

**Proven-in-code.** `light/main.cpp:3362-3363` (call + `ok = ct.ok()`), `:3410` (return `ok ? 0 : 3`). The verifier (`light/verify_ct.cpp:22-139`):
- **SHIELD** (`:39-55`) — payload must be 98 bytes; `determ_shield_verify(payload, len, tx.amount)` (`:46`) binds the commitment `C` to the **public** declared amount.
- **UNSHIELD** (`:56-81`) — the front-running defense is rebuilt **locally**: `ctx = unshield_spend_ctx_hash(from, to, nonce, amount)` (`:69`), then `determ_unshield_verify(payload, len, amount, ctx)` (`:71`) — a captured proof cannot be redirected because the light client derives `ctx` from the tx's own fields, never a carried digest.
- **CONFIDENTIAL_TRANSFER** (`:82-130`) — DCT1 header parse (`:86`), `tx.fee == bundle_fee` (`:91`), full range+balance verify `determ_ctx_bundle_verify` (`:97`), and the intra-bundle **duplicate-input** rejection (`:105-124`, a dup would claim 2× value — the load-bearing inflation guard, mirrored from the validator).
- **Fail-closed on malformed** (`:28-35`): an unparseable tx is a **FAILED** CT verdict (`is_ct=true`), never a skip — an attacker cannot hide a bad proof behind a malformed wrapper.
- **Non-CT vacuity** (`:131-138`): a non-confidential tx returns `is_ct=false, ok=true` and the block walk counts it in `total_txs` only.

**inherited-in-prose.** `ShieldedPoolSoundness.md` SP-1 (SHIELD binds C to public A), SP-6 (UNSHIELD context-bound proof defeats redirect), SP-10 (CONFIDENTIAL_TRANSFER hidden-amount soundness), SP-11 (duplicate-input inflation guard); `ConfidentialTxBalanceSoundness.md` CTB-3 (excess opens to zero ⟹ committed value fixed). DL + Fiat-Shamir ROM over P-256.

**Evidence.** This is the exact `verify_ct_transactions` surface `tools/test_light_ct_tx.sh` / `tools/test_light_ct_transfer.sh` exercise (per the A3 client-CT track); `verify-ct-block` reuses it verbatim over the BODY-PIN-authenticated body.

### CTB-BLOCK-4 — fail-closed at every stage; genesis-pin, head-bound, and `--wait` inherited

**Statement.** Every failure mode exits **non-zero** (3 for verification failures, 1 for arg/transport errors) with a diagnostic — the command **never** emits a bare daemon-reported result on failure: wrong `--genesis` (genesis pin mismatch), chain break / sig failure / height-beyond-head (ANCHOR), full-block fetch error or malformed body or BODY-PIN mismatch (BODY-PIN), any invalid CT proof (CT-PROOFS). The head-index behavior — when `H` is the chain head there is no committee-signed successor yet to bind it — is inherited from `verify_state_root_at`: with default `--wait 0` it fail-closes at the head, and `--wait <s>` polls up to `s` seconds for the successor block before binding (`light/verify_state_root.hpp:111-115`).

**Proven-in-code.** ANCHOR fail-closed `light/main.cpp:3303-3312`; full-block fetch error `:3317-3330`; malformed body `:3335-3343`; BODY-PIN mismatch `:3345-3357`; CT-PROOFS failure returns 3 with per-tx `ct_failures` `:3379-3385` / `:3403-3408`; arg/transport errors return 1 `:3284-3287`, `:3294-3297`, `:3411-3414`. `wait_seconds` is threaded into `verify_state_root_at` at `:3302`. This mirrors the sibling `verify-state-root`'s fail-closed discipline (`light/main.cpp:3224-3234`: *"Fail closed … NEVER emit a bare daemon-reported root"*).

**inherited-in-prose.** `LightClientThreatModel.md` L-6 (fail-closed exit); `StateRootAnchorSoundness.md` SR-3..SR-5 (height-binding / fail-closed / head-regime).

**Evidence.** The head-`--wait` semantics are the same ones `verify-state-root` / `balance-trustless` ship and `tools/test_light_verify_state_root.sh` covers.

### CTB-BLOCK-5 — additive; adds no new crypto

**Statement.** `verify-ct-block` is a pure sequencing of `verify_state_root_at` + a `Block::compute_hash` recompute + `verify_ct_transactions`. It defines no new digest, no new Merkle path, no new signature check, and no new hardness assumption. Its soundness is **structural** — the union of three already-proved reductions under one genesis anchor.

**Proven-in-code.** The whole of `cmd_verify_ct_block` (`light/main.cpp:3267-3415`) calls only pre-existing, separately-tested helpers; the design intent is recorded verbatim in the header comment `light/main.cpp:3241-3266`. No cryptographic primitive is defined in the command body.

**inherited-in-prose.** The three edges of §3; no independent bound is introduced.

---

## 3. Composition theorem (CTB-BLOCK-COMP)

**Theorem.** Fix a pinned `genesis` and a height `H`. If `verify-ct-block --rpc-port P --genesis <genesis> --height H` exits **0** against any (possibly adversarial) daemon on port `P`, then — except with probability `≤ (K+1)·2⁻¹²⁸` (A1 committee sigs ⊕ A2 body-hash collision) — all three hold simultaneously:

1. **(committee-attested)** There exists a block at height `H` on the operator's genesis-pinned chain whose `block_hash(H) = sr.block_hash_hex` is committee-attested (CTB-BLOCK-1).
2. **(exact body)** The `transactions[]` the daemon served for `H` are **exactly** the transactions in that committee-signed block — none swapped, injected, dropped, or reordered (CTB-BLOCK-2).
3. **(valid CT proofs)** Every confidential transaction in `transactions[]` carries a valid range/balance proof under its type's accept-rule — SHIELD binds C to its public amount, UNSHIELD's proof is context-bound to `(from,to,nonce,amount)`, CONFIDENTIAL_TRANSFER's DCT1 bundle satisfies range ∧ balance ∧ intra-bundle input-distinctness (CTB-BLOCK-3).

**Proof.** Compose the three edges. CTB-BLOCK-1 gives (1) and pins the trusted anchor `sr.block_hash_hex`. CTB-BLOCK-2 gives (2): a passing BODY-PIN reduces "the served body ≠ the committee-signed body" to a SHA-256 collision on `Block::compute_hash`. Because BODY-PIN runs **before** CT-PROOFS (`light/main.cpp:3345` precedes `:3362`), the body `verify_ct_transactions` walks in stage (3) is the committee-authenticated body of (2); CTB-BLOCK-3 then gives (3) over that authenticated body. Exit 0 requires all three stages to pass (each intermediate failure returns 3 — CTB-BLOCK-4), so exit 0 ⟹ (1) ∧ (2) ∧ (3). The failure probabilities are independent hardness instances (K committee-sig forgeries at `≤ K·2⁻¹²⁸`, one body-hash collision at `≤ 2⁻¹²⁸`; the CT-proof soundness is conditioned on the inherited DL/ROM assumptions and does not loosen the bound), so the union bound is `≤ (K+1)·2⁻¹²⁸`. ∎

---

## 4. The key adversarial argument (why a malicious daemon cannot cheat)

`A_daemon` controls the single RPC endpoint and may return arbitrary JSON. The two concrete attacks it would attempt:

- **Swap or inject a CT transaction** (e.g. substitute a SHIELD whose commitment secretly over-mints, or add a fabricated CONFIDENTIAL_TRANSFER). Any edit to `transactions[]` changes `Block::compute_hash(full)` (CTB-BLOCK-2), so `body_hash != sr.block_hash_hex` and the command fail-closes at `light/main.cpp:3345-3357` **before** CT-PROOFS ever runs. The daemon **cannot** forge the committee signature over a doctored body — that would break A1 (T-L2). So it can neither pass a doctored body off as authentic nor strip the sigs (the committee-anchored `block_hash` comes from `verify_state_root_at`, not from the served body).
- **Serve a genuine-but-different block at H** (a validly-signed block from another position). The `prev_hash` walk + successor-binding in CTB-BLOCK-1 pins `sr.block_hash_hex` to height `H` on the *pinned* chain; a differently-positioned block has a different `block_hash`, so BODY-PIN mismatches. (This is exactly the substitution the `trustless_read` SOUNDNESS PIN, `light/trustless_read.cpp:240-242`, is written to stop.)

A daemon that instead serves the **honest** block passes all three stages — the honest case is the only one that reaches exit 0. Withholding or stalling is an **availability** failure (fail-closed exit), not a soundness break: the client never acts on inconsistent data.

---

## 5. Honest scope (what this does NOT prove)

**This command establishes CRYPTOGRAPHIC validity + committee-attestation ONLY.** The honest limits are inherited verbatim from `verify_ct.hpp:19-25` and are not narrowed by the composition:

- **Note-SET / double-spend is NOT established here.** CT-PROOFS re-verifies each proof's internal math (range ∧ balance ∧ context-bind ∧ intra-bundle input-distinctness) but has **no** access to the live shielded-pool state, so it cannot check that a CONFIDENTIAL_TRANSFER's or UNSHIELD's input notes were **unspent** (that a spent note is not being replayed, or a never-shielded `C` referenced). A stateless verifier does not hold the unspent set. This remains the daemon apply-rule's job (`ShieldedPoolSoundness.md` SP-8 nullifier-erase, SP-11 pool-membership), anchored for the light client by the **committee-signed `state_root` over the `cn:` namespace** — exactly the split `verify_ct.hpp:19-25` declares: *"Composing both halves: CT-PROOFS here + SIGS (committee digest) + the cn: state proofs = the full A3 light posture."* The `cn:`-leaf half is out of scope for this command; obtain it via `verify-state-root` + a `cn:`-keyed state proof.
- **Intra-bundle distinctness ≠ pool-level distinctness.** The `:105-124` dedup catches a bundle listing the *same* note twice (structurally checkable without pool state), but it does **not** catch two *different* CONFIDENTIAL_TRANSFER txs (or a later tx) each spending the *same* pool note — that is a pool-state check (SP-11) the committee-signed `state_root` covers, not this verifier.
- **Amount/graph privacy is not a soundness claim.** SHIELD/UNSHIELD are amount-public on the ramp; UNSHIELD reveals which note was spent (`ShieldedPoolSoundness.md` NC-6). This command verifies validity, not privacy.
- **Single-daemon, static committee `K_0`.** Like the rest of the light family: one daemon per invocation (a truncated-tip lie is availability, not soundness); the committee is the genesis-seeded `K_0` (`light/trustless_read.cpp:48`), so a header signed by a post-genesis-registered creator outside `K_0` fail-closes (`LightClientCompositionMap.md` §6.1, §6.2).
- **Pre-S-033 / head-regime.** ANCHOR inherits the head-boundary fail-closed + `--wait` behavior (CTB-BLOCK-4); the `state_root`-anchored note-set half additionally requires S-033 + S-038 active on the chain.

None of these undermines the §3 theorem — every emitted "OK" certifies a **real, committee-signed** block whose CT proofs are individually **cryptographically valid**. They bound what "valid" covers: proof-validity + authenticity, not unspent-ness.

---

## 6. Cross-references

- [`ShieldedPoolSoundness.md`](ShieldedPoolSoundness.md) — SP-1 (SHIELD binds C to public amount), SP-6 (UNSHIELD context-bound spend proof), SP-8 (nullifier-erase double-spend, the note-set half out of scope here), SP-10/SP-11 (CONFIDENTIAL_TRANSFER hidden-amount soundness + duplicate-input inflation guard). The accept-rules CT-PROOFS mirrors.
- [`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md) — CTB-1..CTB-8, the P-256 range/balance/excess math CT-PROOFS re-runs (CTB-3 = excess opens to zero ⟹ committed value fixed).
- [`StateRootAnchorSoundness.md`](StateRootAnchorSoundness.md) — SR-1 (committee-anchored per-height root, transitive-forward via the signed successor), SR-2 (genesis-binding), SR-3..SR-5 (height-binding / fail-closed / head-regime). The ANCHOR half (`verify_state_root_at`).
- [`LightClientThreatModel.md`](LightClientThreatModel.md) — T-L1 (genesis anchor, A2/A3), T-L2 (committee-sig head trust, A1), L-6 (fail-closed exit). The `A_daemon` model.
- [`LightClientCompositionMap.md`](LightClientCompositionMap.md) — the light-client proof-family lattice; the {A1, A2} shared spine, the static-`K_0` and single-daemon shared limitations (§6).
- [`Preliminaries.md`](Preliminaries.md) §2.0 — A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision), A3 (preimage) assumption labels.
- Implementation: `light/main.cpp:3267` (`cmd_verify_ct_block`), `:3241-3266` (design header), `:885` (`cmd_block_verify`, the offline file-based sibling), `:3156` (`cmd_verify_state_root`, the anchor sibling); `light/verify_ct.cpp:22-156` + `light/verify_ct.hpp` (`verify_ct_transactions` / `CtVerifyResult` + honest-scope comment `:19-25`); `light/verify_state_root.hpp:25-49` + `light/trustless_read.cpp:236-244` (the BODY-PIN idiom) + `:547-640,726-728` (`committee_bound_state_root` successor-binding).
