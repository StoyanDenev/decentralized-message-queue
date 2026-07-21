# DSSO §5 Assertion Freshness — resolving the verifier-side replay/expiry gap

**Status: DECISION ARTIFACT (owner ratification pending).** This document
resolves the open §5 freshness question the G4-assertion gate surfaced
(`DssoThresholdOprfSoundness.md` §6). It is **not** an edit to the authoritative
`v2.25-DSSO-DAPP-SPEC.md`; it states the gap precisely, lays out the resolution
options, and **recommends one** for the owner to fold into §5. Once ratified, it
fixes exactly what the owner-gated **G4 end-to-end** flow must enforce and gate.

Owner decision this resolves (answered **Q1 = A**, "resolve the freshness gap
first, then build G4-e2e"): *is the RP-side freshness obligation in-scope of the
DSSO spec (a normative MUST on the relying party), or delegated to the RP
integrator?* — and if in-scope, **which rule**.

## 1. The gap

The §5 relying-party token is the paper's dual-hash challenge-response over the
handshake-co-generated keys:

```
challenge = canonical length-prefixed (iss, sub, aud, iat, exp, nonce)
H1' = HMAC-SHA256(sso_key,    challenge)      # sso_key : login-session key
H2  = HMAC-SHA256(tenant_key, H1')            # tenant_key : RP registration key
RP accepts iff HMAC-SHA256(tenant_key, H1') == H2.
```

The accept rule is **stateless**, and the RP holds no `sso_key`, so it cannot
recompute `H1'`. Two freshness properties are therefore **not** provided by the
token in isolation (verified in the G4-assertion gate — the properties there are
*generation-side*, i.e. the honest IdP emits distinct tokens for distinct
inputs, not *verifier-enforced*):

- **Replay.** A network observer who captures a valid `(H1', H2)` can re-present
  it verbatim; it re-verifies (that IS token property 1).
- **Expiry.** The claim carries `iat`/`exp`, but the stateless check never
  compares them to a clock, so an expired claim's token still verifies.

Both are genuine — but neither is a defect in the *token*. Freshness is a
property of the RP's **verification context**, not of a keyed commitment.

## 2. Why the token alone cannot close it

A keyed commitment binds *content* (`sso_key, tenant_key`, and the claim fields)
— it proves the IdP authenticated exactly this claim for exactly this RP. It
says nothing about *when* or *how many times* the token is presented, because
those are not functions of the committed bytes. Making the token itself
one-time or time-limited requires either (a) RP state that remembers what it has
already accepted, or (b) an RP-contributed fresh input mixed into the challenge
before the token is minted. Both live at the RP/ceremony layer, which is exactly
why this is a G4-end-to-end obligation, not a G4-assertion (token) property.

## 3. Resolution options

### Option A — RP-enforced freshness (normative MUST on the relying party)

Keep the token exactly as specified (a pure keyed commitment; zero new
primitive, zero protocol-shape change). Add a normative §5 clause: a conforming
RP, on receiving `(challenge, H1', H2)`, MUST reject unless **all** hold:

1. `HMAC(tenant_key, H1') == H2` — the existing binding check.
2. `challenge.aud` equals the RP's own audience identifier (already implied by
   the `tenant_key` layer; made explicit so the RP checks the *cleartext* claim
   it is about to act on, not only the MAC).
3. `now − skew ≤ challenge.iat` and `challenge.exp > now` — clock check against a
   bounded `skew` (e.g. 60 s), with a bounded maximum lifetime (e.g.
   `exp − iat ≤ T_max`, e.g. 5 min).
4. `challenge.nonce` has **not** been accepted before within the `[iat, exp]`
   window — a single-use nonce cache the RP retains for at least `T_max + skew`.

This is the OIDC/JWT/SIWE-class replay+expiry discipline (`jti`+`exp`),
specialized to the dual-hash token. `sso_key`/`tenant_key` and the token bytes
are unchanged; the flow shape is unchanged.

**Trust note.** Under A the *freshness* guarantee rests on the RP behaving
(keeping a nonce cache + clock). The *authentication* guarantee (who the claim
is for, and that the IdP minted it) still rests only on the keys — an RP that
forgets to check freshness cannot be tricked into accepting a claim for the
wrong subject/audience, only a stale/replayed one for the *right* subject.

### Option B — Cryptographic freshness via an RP-contributed nonce

Change the flow so the RP issues a fresh server nonce `rp_nonce` to the client
*before* the token is minted, and fold it into the challenge
(`challenge.nonce := rp_nonce`). The token is then one-time **by construction**:
a replay presents a nonce the RP already retired, and the RP needs no `exp`
clock for replay (only for its own nonce-expiry bookkeeping). This is stronger
(freshness is enforced by the protocol, not by RP diligence) but **changes the
protocol shape**: it adds an RP→client challenge-issuance round-trip before the
assertion, which the current one-shot §5 token does not have.

## 4. Recommendation — **Option A**

Adopt **A**: keep the token a pure commitment and localize freshness to the RP
with a normative MUST (binding check + audience + clock + single-use nonce).

Rationale:
- **Minimalism / zero new primitive.** No token change, no new round-trip, no
  new crypto — it reuses the claim's existing `iat/exp/nonce` fields. This
  matches the DSSO KISS posture and the "build only the committed spec" discipline.
- **Standard and auditable.** It is the exact replay+expiry rule every
  production SSO (OIDC, SIWE) already mandates on the verifier; reviewers know it.
- **Separation of concerns holds.** Authentication is cryptographic (keys);
  freshness is operational (RP session state). Conflating them (Option B) buys a
  stronger property at the cost of a protocol round-trip the paper's design
  deliberately avoids.
- **B stays available** for a future profile if a deployment already has a
  challenge-issuance step (e.g. an interactive RP) — it is not precluded, just
  not the default.

If the owner instead prefers freshness to be a hard protocol property (not an RP
obligation), choose **B** and accept the extra round-trip.

## 5. What G4-end-to-end will enforce once ratified (assuming A)

The owner-gated `register → login → assertion → RP` live flow gains, at the RP
step, a small stateful verifier: a `nonce` set + a monotonic clock. The e2e gate
then asserts, beyond the existing binding check:

- a **replayed** token (same `(challenge, H1', H2)` presented twice) is accepted
  once and **rejected** the second time (nonce cache);
- an **expired** claim (`exp < now`) is **rejected** (clock);
- a **future/backdated** claim (`iat > now + skew`) is **rejected**;
- a **fresh, in-window, first-use** token is accepted.

These are the four freshness legs the current `test-dsso-assertion` explicitly
declares out of scope (its printed SCOPE NOTE). They join the login half
(`test-dsso-threshold-oprf` G1–G4-login) and the token soundness
(`test-dsso-assertion`) once the OPAQUE AKE that co-generates `sso_key` is built.

## 6. Scope

This is a **decision artifact**. The owner ratifies the chosen rule and folds
the normative clause into `v2.25-DSSO-DAPP-SPEC.md` §5 (the authoritative,
design-locked spec — untouched here). G4-end-to-end then builds against the
ratified §5, per the FROST-deviation discipline (build only the committed spec;
defer protocol design to the owner). Cross-refs:
[`DssoThresholdOprfSoundness.md`](DssoThresholdOprfSoundness.md) §6 (the residual
this resolves), [`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md) §5.
