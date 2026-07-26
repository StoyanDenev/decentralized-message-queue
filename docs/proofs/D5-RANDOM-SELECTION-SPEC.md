> **TIER: NEAR-TERM — D.5 is a post-v1.0 reference DApp (Bundle D, §5.1 chain-primitive DApps). NOT part of the 1.0-authoritative set.** Active-front build target (CLAUDE.md CURRENT FRONT item 2, after the DSSO CT/zeroization ship-gate G5+G6 closed 2026-07-26). Every primitive it uses is SHIPPED. This is the ratifiable BUILD spec (mirrors `D10-PROPERTY-REGISTER-SPEC.md`); §13 lists the OPEN decisions the owner must ratify before any code.

# D.5 — Government random-selection reference DApp

**Status:** DESIGN — owner chose "design-first" (2026-07-26). Design synthesized + adversarially verified (workflow `wf_4d036bff-772`: 3 framings → adversarial grounding/doctrine verification → synthesis). **No code until §13 is ratified** (the parameters are pre-genesis-free to change now, frozen once a deployment goes live — no migrations).
**License:** BUSL-1.1 orchestrator (`dapps/d5-random-selection/**`) + **Apache-2.0 citizen verifier** (the `verify-rand` / `verify-selection` / `d5_draw` surface lives in `determ-light` so any citizen verifies freely). See §13 D8.

## 0. Motivation

**The failure this DApp exists to prevent is the project's founding use case.** Bulgaria, 2011: a
regulation introduced random judge-assignment to court cases. The implementation in use is
**closed-source and its audit is classified** (`docs/MOTIVATION.md §1`); EU monitoring flags this
every six months without resolution. The threat model the open letter describes: government IT
compromised from within (potentially by hybrid-warfare actors), closed-source code that defeats
independent audit, insiders who erase traces, and **centralized RNG / IdP / record-keeping as
single points of capture**.

D.5 is the open, mutual-distrust answer — it distributes **every single point of capture** the
letter names, using only shipped Determ primitives:

| Captured today | Distributed by D.5 | Shipped mechanism |
|---|---|---|
| The RNG (closed-source, one operator) | K-of-K commit-reveal beacon; biasing needs K-of-K collusion | `Block::cumulative_rand` (MPDH) |
| The identity provider | t-of-n distributed SSO, no single trusted IdP | DSSO (v2.25), reference-RP integration |
| The records (silent rewrite / wipe) | append-only block stream, K-of-K-signed, no migrations | `DAPP_CALL` messages + `tx_root` |
| The audit trail (classified) | on-chain, citizen-visible, un-erasable below BFT | `LOG_AUDIT_ACCESS` (v2.24) |

**Deployment economics (licensing v3.1):** the Determ core is Apache-2.0 — a government runs the
chain at zero license cost on its own K-of-K nodes (e.g. judiciary, notary chamber, an independent
oversight body — mutually distrusting institutions). The D.5 orchestrator is the paid BUSL layer;
the citizen-verifier surface stays Apache-2.0 so any member of the public can independently refute
a draw. The state buys the protection, not the ability to check it.

## 1. Design in one line

D.5 is a **zero-consensus DApp-layer sortition** over the shipped commit-reveal beacon: a
registered court authority pre-commits (`case-open`) and freezes the eligible roster as
canonical-binary `DAPP_CALL` messages **before** a strictly-future `draw_height H`, selects the N
members with the smallest `SHA256(cumulative_rand[H] ‖ ctx ‖ member_id)`, publishes the result and
a `LOG_AUDIT_ACCESS` record — and **any citizen re-derives and can refute it** with the Apache
`determ-light` binary. **`consensus_change_required = false`**: no new tx-type, no new state leaf,
no new block field, no state-format change, no migration. The chain never *executes* the draw — it
only *orders* and *authenticates* the inputs; the draw is a pure function anyone can re-run.

## 2. Requirements

- **R1 Unbiasable randomness.** The selection seed cannot be predicted or steered by any single
  party. (Beaconless commit-reveal: `cumulative_rand[H]` is unknowable at commit time; biasing
  requires K-of-K collusion — see §13 D5 on committee composition.)
- **R2 Pre-commitment / anti-grinding.** The eligible roster and case parameters are frozen and
  block-timestamped **before** the seed is knowable, so no post-hoc roster manipulation and no
  "draw-until-favorable" grinding is possible without leaving permanent public evidence.
- **R3 Public re-derivability.** Any citizen, trusting no single party and using only open code +
  an untrusted node, re-derives the identical selection and refutes any published result that
  disagrees. Fail-closed: the verifier returns `SELECTED / NOT-SELECTED / UNVERIFIABLE`, never a
  false `SELECTED`.
- **R4 Audit compliance.** Each selection is bound to an on-chain, citizen-visible, un-erasable
  disclosure record (who disclosed, which selection, when) — by construction, not by policy.
- **R5 No PII on chain.** Only non-PII candidate identifiers / commitments; real-identity mapping
  stays off-chain.
- **R6 Additive-only.** No consensus change, no migration, no new state format — reuse shipped
  primitives exactly.

## 3. The ceremony

Height ordering, enforced by the verifier (§9), is **`h_r ≤ h_o < H < h_s`** (roster ≤ case-open
< draw-height < result).

0. **SETUP (one-time).** The authority publishes `DAPP_REGISTER=9` for its D.5 domain
   (`service_pubkey`, `endpoint_url`, `topics=['roster','case-open','result']` ≤32, retention,
   metadata; keyed by `tx.from` = signature-authenticated owner; `d:` leaf, 4-state active
   machine). It sets a standing 32-byte audit view-master via `ROTATE_AUDIT_KEY=15` (`ak:`+addr =
   `SHA256(pk)`). The chain-level `tx.from` signature on every subsequent `DAPP_CALL` is the
   **publicly-verifiable authority binding**.
1. **ELIGIBLE ROSTER** (`roster` topic, `DAPP_CALL=10`). The authority publishes the eligible pool
   as **non-PII candidate identifiers** (ratified form — §13 D2: `SHA256(national_id‖salt)`
   pseudonyms, or a `roster_root` over a sealed off-chain roster). Adds/removes are further
   `roster`-topic `DAPP_CALL`s; the eligible set at any height is the **deterministic fold of the
   roster-topic stream in canonical block order**.
2. **CASE-OPEN / commit-before-seed** (`case-open` topic, `DAPP_CALL=10`). The authenticated
   authority posts canonical-binary `{version, case_id, roster_cutoff_height, draw_height = H
   (strictly future), N primaries, M ordered alternates, draw_algo_version}` at height `h_o < H`,
   **before `cumulative_rand[H]` can exist** — the anti-grinding anchor. The **first** `case-open`
   per `case_id` is canonical; any later `case-open` for the same `case_id` is permanent public
   **evidence**, not a valid re-roll (enforced by the verifier, §8/§9, not by consensus).
3. **DSSO AUTH of the requesting official** (reference-RP integration). t-of-n OPAQUE login yields
   `sso_key`; the D.5 relying party (its `DAPP_REGISTER` `tenant_key`) accepts the dual-hash token
   `H2 == H2'` under **ratified Option-A freshness** (`audience == D.5 id`; `now−skew ≤ iat`;
   `exp > now`; `exp−iat ≤ T_max`; single-use nonce). The `case-open` `DAPP_CALL` carries
   `hash(accepted-token ‖ auditor-id)` as a commitment, **never** the bearer token. *(NOTE, §13 D6:
   DSSO is the reference RP integration that drives the later `sdk/rp` extraction — it is NOT the
   public authorization proof; against a compromised RP the token is citizen-opaque. The
   publicly-meaningful authorization is the chain `tx.from` signature + the `LOG_AUDIT_ACCESS`
   record.)*
4. **BEACON at `draw_height H`.** The committee produces block H;
   `cumulative_rand[H] = SHA256(cumulative_rand[H−1] ‖ delay_output[H])`,
   `delay_output[H] = SHA256(delay_seed ‖ secret_1..secret_K)`. It is **committee-authenticated
   once block H+1 is signed** (S-042 successor binding: `signing_bytes[H]` commit
   `delay_output`+`cumulative_rand`, and `block_hash[H]` is folded into `H+1.prev_hash` inside
   H+1's K-of-K-signed digest). No committee member could predict it at Phase-1 commit time;
   selective abort is defeated by re-roll + suspension slashing.
5. **DRAW** — the **one new pure function**, `d5_draw` (§4).
6. **RESULT** (`result` topic, `DAPP_CALL=10`) at `h_s > H`: canonical-binary `{version, case_id,
   H, cumulative_rand@H used, roster_cutoff_height, selected primary ids, ordered alternates,
   draw_algo_version}`. Redundant (any verifier recomputes it) but a fixed on-chain outcome anchor.
7. **AUDIT** (`LOG_AUDIT_ACCESS=16`). Fee-only tx (`amount==0`, `to==""`) with the exact 72-byte
   payload `epoch_u64_BE(8) ‖ auditor_pk(32) ‖ context_hash(32)`, where
   `context_hash = SHA256(case_id ‖ H ‖ roster_cutoff_height ‖ result_digest ‖ draw_algo_version)`.
   The tx **in chain history IS the record** (`al:`+addr = `SHA256(monotone count)`); built via
   `determ-light log-audit-access`.
8. **PUBLIC VERIFICATION** — §9.

## 4. The draw function `d5_draw` (the sole new gated primitive)

Pure C99, offline, no chain/net access (`d5draw.c` / `d5draw.h`, ~30–40 lines):

```
seed  S   = cumulative_rand[H]                                  (32 bytes)
ctx       = SHA256(domain ‖ case_id ‖ H ‖ roster_cutoff_height ‖ draw_algo_version)
for each eligible member id:  key(id) = SHA256(S ‖ ctx ‖ id)
selected  = the N members with the smallest key(id), ascending  (primary rank 0..N-1),
            then the next M as ordered alternates; tie-break on id bytes.
```

**Lowest-hash sortition** (§13 D1) is stateless per member, **order-independent** (the result does
not depend on roster ordering), and trivially light-recomputable — the same "deterministic given
the committee-authenticated block" property the subsidy lottery relies on
(`src/chain/chain.cpp:1720-1730`). `draw_algo_version` is a KAT-pinned byte, **frozen once a
deployment is live** (un-migratable). `ctx` domain-separation is load-bearing: it binds the draw to
this exact case + height + roster cutoff, and its omission is the primary falsify mutant (§11).

## 5. On-chain footprint (precise)

**Net new consensus/state surface: NONE.** Per deployment: one `DAPP_REGISTER=9` (writes the
shipped `d:` leaf, once) + one `ROTATE_AUDIT_KEY=15` (writes the shipped `ak:` leaf, once). Per
selection: `roster`-topic `DAPP_CALL=10` messages, one `case-open` `DAPP_CALL=10`, one `result`
`DAPP_CALL=10`, and one `LOG_AUDIT_ACCESS=16` (advances the shipped `al:` monotone-count leaf).

**Grounding precision** (a correction the design's own adversarial review flagged): a `DAPP_CALL`
writes **no DApp-namespace (`d:`) state leaf** and the chain never parses/executes the payload —
**but** the apply path does `charge_fee` + `sender.next_nonce++`, so account (balance/nonce) leaves
and `total_fees` always move. The correct claim is **"no `d:` leaf mutation,"** not "no state
mutation." The properties D.5 relies on — `tx_root` inclusion and block ordering = canonical DApp
message ordering — hold regardless. The randomness **reuses** `Block::cumulative_rand` (already in
every header; read exactly as the subsidy lottery reads it, `chain.cpp:1720-1730`) — no new block
field. **Single-shard only** (cross-shard `DAPP_CALL` rejected via `Chain::is_cross_shard`,
`chain.cpp:197`); the D.5 domain lives on one shard.

## 6. Reused primitives (all SHIPPED)

- `Block::cumulative_rand` — the MPDH commit-reveal beacon seed (`chain.cpp:1720-1730` precedent).
- S-042 successor binding — block H+1's K-of-K signature authenticates `cumulative_rand[H]`.
- `DAPP_REGISTER=9` / `DAPP_CALL=10` (topic + opaque canonical-binary payload; `d:` namespace;
  single-shard; block-ordered). Read RPC `dapp_messages(domain, from, to, topic)` (untrusted hint;
  completeness re-authenticated by the full-block walk — §8).
- `LOG_AUDIT_ACCESS=16` (72-byte disclosure record; `al:` monotone-count leaf) /
  `ROTATE_AUDIT_KEY=15` (`ak:` standing key). Client builders shipped in `determ-light`.
- DSSO t-of-n OPAQUE login → `sso_key`; RP dual-hash token `H2 = HMAC(tenant_key, HMAC(sso_key,
  challenge))` with Option-A freshness (the `test-dsso-login-e2e` acceptance logic).
- `determ-light` trustless-read: the committee-authenticated **full-block walk** with
  `track_registry` (`light/trustless_read.cpp:113-291`, full-block re-fetch pinned to the chained
  `block_hash` — the completeness-authenticating enumeration §8 needs); `verify-block-sigs`,
  `verify-state-root`, `verify-tx-inclusion`, `verify-dapp-registration`, `account-history`.
- `determ::c99` SHA-256 (draw key + ctx digest); the canonical binary codec (DECISION-LOG D2 — no
  JSON on wire/storage).

## 7. New surface (the whole build)

1. **`d5draw.c` / `.h`** — the pure lowest-hash sortition (§4). The single new *gated function*.
2. **`determ-light verify-rand <H>`** — the named gap ("no verify-rand subcommand"): composes
   `verify-block-sigs` + the S-042 successor-binding recompute → `cumulative_rand@H = <hex>,
   committee-authenticated: YES|UNVERIFIABLE`, **never false-YES**. Client-side, read-only,
   autonomous-safe, and reusable (D.1 Liberty Bell wants it too).
3. **`determ-light verify-selection`** — the composition verifier (§9): `verify-rand` for the seed
   + committee-authenticated full-block-walk **enumeration** of the complete `roster` + `case-open`
   streams for `case_id` up to H (authenticates set **completeness**, not just inclusion) +
   first-open-wins canonicalization (N>1 surfaced as evidence) + `h_o < H < h_s` ordering +
   `d5_draw` re-derivation + equality → `SELECTED / NOT-SELECTED / UNVERIFIABLE`, **never
   false-SELECTED**.
4. **Three canonical-binary payload codecs** (`roster`, `case-open`, `result`) — DApp-layer, D2
   (no JSON), KAT-pinned round-trip; the chain never parses them.
5. **`dapps/d5-random-selection/**`** (BUSL-1.1) — off-chain orchestrator + reference RP: DSSO
   dual-hash acceptance (Option-A freshness) outside the DSSO test harness; roster/case-open/result
   `DAPP_CALL` builders over shipped tx-signing; `LOG_AUDIT_ACCESS` emission. The RP-accept wiring
   is the genuinely new integration that later shapes `sdk/rp`.
6. **This spec** (`docs/proofs/D5-RANDOM-SELECTION-SPEC.md`).
7. **Three falsify-on-mutant gates** — §11.
8. **NOT in this build** (later front item): `sdk/rp` Apache-2.0 extraction — factored *out* of the
   working D.5 RP-accept logic, not designed ahead of a real caller.

## 8. Invariants + the two headline attacks defeated

The design's adversarial pass converged on two attacks the individual framings under-handled; both
are defeated at the **verifier**, with **zero consensus change**:

- **Commit-many-reveal-one grinding.** A compromised authority pre-commits several `case-open`s for
  one `case_id` and publishes only the favorable draw. **Defeated:** `verify-selection` enumerates
  **all** `case-open`s for `case_id` over the committee-authenticated full-block walk, enforces
  **first-open-wins**, and surfaces N>1 as permanent public **evidence**. (Consensus-enforced
  uniqueness is rejected under no-migrations — §13 D4.) Gated by mutant 3b (§11).
- **Roster-truncation false-SELECTED.** `verify-tx-inclusion` is an **inclusion** primitive, not a
  **completeness** one — an untrusted RPC withholding a `roster`-remove message would yield a false
  `SELECTED` for an excluded member. **Defeated:** the roster is materialized over the
  committee-authenticated **full-block walk** (`track_registry`, full-block re-fetch pinned to the
  chained `block_hash`, `trustless_read.cpp:113-291`), which authenticates set completeness. Gated
  by mutant 3a (§11).

## 9. Public verification (any citizen, Apache `determ-light`)

Against any untrusted/MITM node, trusting no single party (not the registrar, not any
operator-supplied committee file):

1. `verify-dapp-registration <domain>` → **ACTIVE** (signature-authenticated registered owner).
2. `verify-rand <H>` → `cumulative_rand@H` committee-authenticated via S-042 successor recompute,
   `VERIFIED | UNVERIFIABLE`, never false-VERIFIED — the seed is obtained trustlessly.
3. `verify-selection` → re-authenticates the seed; **enumerates** the complete `roster` +
   `case-open` streams for `case_id` up to H over the committee-authenticated full-block walk;
   asserts exactly one canonical first `case-open` at `h_o < H` (any N>1 surfaced as tamper
   evidence); re-runs `d5_draw` over the materialized roster + authenticated seed; asserts equality
   with the published result; enforces `h_o < H < h_s` → `SELECTED / NOT-SELECTED / UNVERIFIABLE`.
4. `verify-tx-inclusion` on the `LOG_AUDIT_ACCESS` tx + `context_hash` equality → the disclosure is
   on-chain and binds this exact selection.

Passing all four means the assignment is provably fair, unbiasable (short of K-of-K collusion),
pre-committed to a single canonical draw, and audited — fully re-derivable by anyone.

**Honest anchoring scope (§15):** every committee anchoring reduces to the shipped light-verify
trust root; state-root/beacon anchoring is against the **genesis** `committee_seed`, so on a chain
whose K-of-K signing committee has rotated since genesis the anchor is the genesis committee — a
pre-existing `determ-light` limitation **inherited, not introduced,** by D.5
(see [[determ-retroactive-committee-rederivation]]).

## 10. Audit binding (v2.24 as-shipped, no extension)

`ROTATE_AUDIT_KEY=15` sets/rotates/clears the oversight body's standing 32-byte audit view-master
(`ak:`+addr = `SHA256(pk)`). Per selection, `LOG_AUDIT_ACCESS=16` emits the exact 72-byte payload
binding the disclosure to that specific selection via `context_hash` (§3 step 7); fee-only,
account-signed, anon/bearer accounts admitted; the tx **is** the record and `al:`+addr =
`SHA256(monotone count)` proves the disclosure count is monotone (no silent deletion below BFT).

**B3 honesty (shipped non-claims carried forward, not papered over):** `LOG_AUDIT_ACCESS` proves
the owner **signed a disclosure statement**, not that a physical ceremony/access occurred; the
epoch is not consensus-bound; and there is **no light reader for `ak:`/`al:` preimages** in this
slice. The v1 citizen-visible audit binding is therefore exactly: `verify-tx-inclusion` proves the
`LOG_AUDIT_ACCESS` tx landed **and** its `context_hash` equals `SHA256` over the published result
fields. Whether signed-disclosure-only suffices for the regulator is §13 D7.

## 11. Falsify-on-mutant gates (three, FAST offline, both platforms)

Each mutant flips exactly one verdict; on a multi-mutant gate, revert ALL mutants and re-run
standalone green (the LVS light-verify discipline).

- **`test-d5-draw`** — pins `d5_draw(seed, roster, N, M)` to an exact selected-id vector via KAT
  vectors + an independent Python dual-oracle that must byte-match (MSVC == GCC byte-identical).
  **Primary mutant:** drop the `ctx` domain-separation (`SHA256(S‖ctx‖id)` → `SHA256(S‖id)`) →
  every key changes → selected set changes → KAT + oracle mismatch RED. Secondary: reverse the
  smallest↔largest comparison; off-by-one in N; truncate/reuse the seed.
- **`test-light-verify-rand`** — a MITM fixture serves a header whose `cumulative_rand@H` is
  swapped but whose successor block H+1's committee signature is **not** rebound to the swap.
  `verify-rand` MUST report `committee-authenticated: NO / UNVERIFIABLE`, never false-YES (mirrors
  LVS-1 empty-committee + `verify-tx-inclusion` never-false-INCLUDED). Mutant: remove the S-042
  successor-binding assertion → forged seed accepted → RED.
- **`test-light-verify-selection`** — the security-bearing composition gate: **(3a roster
  completeness)** an untrusted RPC truncates a `roster`-remove; the mutant materializing the roster
  from the truncatable `dapp_messages` hint (instead of the committee-authenticated full-block
  walk) emits a false SELECTED for an excluded member → gate RED. **(3b duplicate case-open)** two
  `case-open`s for one `case_id` before H; the mutant skipping first-open-wins accepts the
  favorable second draw → gate flips. **(3c ordering)** relax `h_o < H` to accept `h_o ≥ H` →
  post-hoc-roster case wrongly VALID → RED. **(3d roster binding)** alter one eligible id while
  keeping `roster_root`; the mutant skipping the root check flips VALID → RED.

D.5 end-to-end wiring is exercised separately on a 3-of-5 in-process/DSF fixture.

## 12. Increment plan (spec-first; each increment gated both platforms)

1. **This spec** + owner ratification of §13 **before any code** (params pre-genesis-free now,
   frozen once live).
2. `d5_draw` pure module + `test-d5-draw` (cheapest offline class; everything composes it).
3. Payload codecs (`roster` / `case-open` / `result`), D2 canonical binary, KAT-pinned round-trip.
4. `determ-light verify-rand <H>` + `test-light-verify-rand` (closes the named beacon-read gap).
5. `determ-light verify-selection` + `test-light-verify-selection` (all four mutants) — the
   security spine; green before the orchestrator ships.
6. `dapps/d5-random-selection` orchestrator + reference RP end-to-end on a 3-of-5 fixture (the
   reference RP integration that later defines `sdk/rp`).
7. Docs threading + register (CLI-REFERENCE rows; V2-DAPP-DESIGN / dapps catalog cross-ref; proofs
   index; claims + falsify tables). FAST + falsify-on-mutant green both platforms.
8. Ship gate: G5/G6 already green (2026-07-26). Then, as a **separate later front item**, extract
   `sdk/rp` (Apache-2.0) FROM the working D.5 RP-accept logic.

## 13. OPEN decisions for owner ratification (before code)

Each carries a recommendation; ratify one per row (or amend). Parameters marked *frozen-once-live*
are un-migratable after a deployment goes live.

- **D1 — Draw construction** (frozen-once-live via `draw_algo_version`). Options: (a) **lowest-hash
  sortition** (§4); (b) seeded Fisher-Yates over the canonically-sorted roster. **Recommend (a)** —
  stateless per member, order-independent, trivially light-recomputable, cleaner one-line
  ctx-drop falsify mutant; strictly smaller provable surface for identical uniform-subset semantics
  under the RO model.
- **D2 — Roster confidentiality.** Options: public-roster (plaintext non-PII ids); private-roster
  opt-in (commit `roster_root`, reveal after draw); ship both. **Recommend both — public default
  for judge assignment, private opt-in for jury pools.** Either way ids are non-PII pseudonyms
  (`SHA256(national_id‖salt)`), no real-identity map on-chain (D10 crypto-shred/GDPR precedent).
- **D3 — Anti-grinding lead Δ** (`h_o < H = h_o + Δ`; frozen-once-live). Options: Δ ≥ 1 block; Δ ≥
  one committee-epoch. **Recommend Δ ≥ one committee-epoch as defense-in-depth default** — but the
  spec states that unbiasability holds for **any Δ ≥ 1** (the H-committee's Phase-1 commits do not
  exist at `h_o`); the epoch gap is defense-in-depth (drawing committee ≠ committing committee),
  not a correctness requirement.
- **D4 — Multi-commit handling.** Options: (a) **verifier-enforced first-open-wins** + N>1 evidence
  (tamper-evidence, `consensus_change=false`); (b) consensus-enforced case-open uniqueness (a new
  accept rule — HEAVY, violates no-migrations). **Recommend (a)**; (b) rejected under
  no-migrations. Confirm tamper-**evidence** (not prevention) is acceptable for the regulatory
  model.
- **D5 — Committee composition** (deployment/governance, not code). Options: require ≥1 of the K
  committee institutions independent of the drawing authority; or state only the abstract "biasing
  needs K-of-K collusion." **Recommend requiring + documenting ≥1 independent (non-government)
  committee member as a load-bearing deployment assumption** — the declared adversary can plausibly
  operate the whole validator set, and without an independent member the unbiasability guarantee
  collapses to the commit-before-reveal ordering property alone.
- **D6 — DSSO's role.** Options: include as the reference-RP integration (drives `sdk/rp`), or drop
  from the slice. **Recommend include** — justified on the reference-RP mandate, NOT as public
  authorization proof (against a compromised RP the token is citizen-opaque; the publicly-meaningful
  authorization is the chain `tx.from` signature + the `LOG_AUDIT_ACCESS` record).
- **D7 — In-slice audit depth.** Options: signed-disclosure only (`verify-tx-inclusion` on
  `LOG_AUDIT_ACCESS` + `context_hash` equality); or add an in-slice `determ-light` reader for
  `ak:`/`al:` preimages. **Recommend signed-disclosure only for v1** (the preimage reader is a
  documented out-of-slice gap; if the regulator needs more it is a scoped follow-on).
- **D8 — License split + `verify-selection` home.** **Recommend BUSL-1.1 orchestrator +
  Apache-2.0 citizen verifier** (`verify-rand` / `verify-selection` / `d5_draw` in `determ-light`
  so any citizen verifies freely), matching `dapps/README` + licensing v3.1. `verify-selection` is
  homed in `determ-light` (it already links the codec + full-block walk + `verify-rand`).

## 14. Non-goals

- No new consensus rule, tx-type, discriminator, state leaf, or block field, and no state-format
  change (`consensus_change=false`; no-migrations untouched). The chain never *executes* the draw.
- No on-chain PII; only non-PII ids / commitments.
- No proof that the eligible pool was honestly or completely **assembled** — D.5 proves fairness
  *over the published roster* (and that the roster stream is complete + tamper-evident), NOT that a
  listed member is qualified or that the pool was not padded. Roster ground truth is an
  authority-side governance boundary, **mitigated** by the fully-public tamper-evident per-entry
  roster stream, not eliminated.
- No defense against full K-of-K committee collusion biasing the seed — the base-chain trust root;
  mitigated (not removed) by the ≥1-independent-member deployment assumption (D5).
- No enforcement of physical courtroom compliance — the chain makes divergence detectable and
  auditable, not preventable.
- No consensus-enforced case-open uniqueness — multi-commit is defeated by verifier-enforced
  first-open-wins + permanent public evidence (D4).
- No FROST / no signature-based or block-cosigned assertion token — DSSO stays the shipped
  dual-hash + Option-A freshness design ([[frost-deviation-discipline]]).
- No new randomness primitive / VDF / time-lock / VRF — the MPDH commit-reveal beacon is the sole
  seed source.
- No JSON on wire/storage — all payloads canonical binary (DECISION-LOG D2), KAT-pinned.
- No cross-shard operation — `DAPP_CALL` is single-shard only (`chain.cpp:197`).
- No in-slice light reader for `ak:`/`al:` preimages (D7).
- No `sdk/rp` extraction in this build — a later front item.

## 15. B3 accounting — proven vs inherited vs assumed

| Claim | Status |
|---|---|
| The draw is deterministic + uniform-subset over the roster given the seed | **Proven in code** — `test-d5-draw` KAT + dual-oracle byte-identity; falsify = ctx-drop mutant |
| A citizen obtains the seed trustlessly (committee-authenticated) | **Proven in code** — `test-light-verify-rand`; falsify = unbound-successor mutant |
| A published result is re-derivable + roster-complete + single-canonical-draw | **Proven in code** — `test-light-verify-selection` (mutants 3a–3d) |
| The seed is unbiasable | **Inherited** from the MPDH commit-reveal beacon (Beaconless-v2 / `SelectiveAbort.md`), **conditioned on** ≥1 independent committee member (D5) |
| Committee anchoring is sound | **Inherited** from the `determ-light` trust root, anchored at the **genesis** committee (rotation limitation stated, §9) |
| The audit record binds the selection | **Proven in code** for `context_hash` equality + on-chain inclusion; **assumed-in-prose** that a signed disclosure ⇒ a real access (v2.24 NC) |
| The eligible pool is honestly assembled | **Assumed / out-of-scope** — authority-side governance boundary (§14), mitigated by the tamper-evident roster stream |

## 16. Cross-references

- `docs/MOTIVATION.md` §1–§2 (founding use case + threat model).
- `docs/proofs/D10-PROPERTY-REGISTER-SPEC.md` (sibling reference-DApp spec this mirrors).
- `docs/V2-DAPP-DESIGN.md` (`DAPP_REGISTER`/`DAPP_CALL` substrate); `DAppRegistryLifecycle.md`,
  `DAppRegistryReadSoundness.md`.
- `docs/proofs/Beaconless-v2-SPEC.md`, `SelectiveAbort.md`, `FROST_DEVIATION_NOTICE.md`
  (commit-reveal beacon).
- `docs/proofs/AuditLayerSoundness.md` (v2.24 `LOG_AUDIT_ACCESS` / `ROTATE_AUDIT_KEY`).
- `docs/proofs/v2.25-DSSO-DAPP-SPEC.md`, `DssoThresholdOprfSoundness.md`,
  `DssoG5ConstantTimeReview.md` (the DSSO reference-RP identity layer).
- `docs/proofs/TxInclusionProofSoundness.md`, `StateRootAnchorSoundness.md`,
  `AccountHistorySoundness.md`, `LightVerifyGateAudit.md` (the light-verify trust root
  `verify-rand`/`verify-selection` compose).
