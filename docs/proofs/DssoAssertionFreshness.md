# DSSO §5 Assertion Freshness — resolving the verifier-side replay/expiry gap

**Status: SUPERSEDED IN PART — the freshness rule below is IMPLEMENTED, but its
premise was wrong (2026-09-17, defect C6).** Option A was ratified by the owner
on 2026-07-21 and its four legs (audience, `iat`/`exp` window, bounded lifetime,
single-use nonce) are exactly what `dapps/dsso/assertion.c` now enforces. What
this document got wrong is §2 and the §3 "Trust note": it asserted that the
token "authenticates the claim" and that an RP forgetting freshness "cannot be
tricked into accepting a claim for the wrong subject/audience". **Both are
false**, and the round-11 audit recorded them as claim C6
(`v2.25-DSSO-DAPP-SPEC.md` §0.0(3)): the accept rule of the day
(`HMAC(tenant_key, H1'_presented) == H2_presented`) read neither `sso_key` nor
the claim, so any `tenant_key` holder minted a token for any subject, and one
honest token authenticated any substituted claim.

**§1.1 below states the mechanism as implemented.** The freshness legs are
unchanged; what changed is what they run ON — a claim the RP has authenticated,
rather than a cleartext it cannot. The options and rationale are retained as the
decision record, with the corrections marked inline.

Owner decision this resolves (answered **Q1 = A**, "resolve the freshness gap
first, then build G4-e2e"): *is the RP-side freshness obligation in-scope of the
DSSO spec (a normative MUST on the relying party), or delegated to the RP
integrator?* — and if in-scope, **which rule**.

## 1.1 The mechanism as implemented (2026-09-17, normative)

`dapps/dsso/assertion.{h,c}`, gate `determ-dsso selftest-assertion`
(`tools/test_dsso_assertion_module.sh`, FAST). `tenant_key` is held by the IdP
and that one RP — **never by a user** (`v2.25-DSSO-DAPP-SPEC.md` §1).

```
canon(claim) = LP("determ-dsso/assert/claim/v1")
             ‖ LP(iss) ‖ LP(sub) ‖ LP(aud) ‖ LP(sid)
             ‖ nonce(32) ‖ u64(iat) ‖ u64(exp) ‖ u64(reg_epoch) ‖ u64(key_epoch)

binder = HMAC-SHA256(sso_key,    LP("determ-dsso/assert/binder/v1") ‖ canon(claim))
tag    = HMAC-SHA256(tenant_key, LP("determ-dsso/assert/tag/v1")    ‖ canon(claim) ‖ binder)
```

The IdP delivers `tag` to the RP over the registered channel; the user presents
`(claim, binder)` and **no tag**. The RP accepts iff the epochs are its current
ones, the tag it recomputes over the PRESENTED claim and binder equals (constant
time, full 32 bytes) a delivered reference that has not expired, the
authenticated `sid` is the session this verifier is completing, the three clock
legs hold, and the nonce is unseen. Because `canon(claim)` is inside the outer
MAC, the claim the RP acts on is the claim the IdP asserted — which is the
premise §2 and §3 below wrongly assumed the old token already provided.

## 1. The gap

*(HISTORICAL, as of 2026-07-21. The rule quoted here is the one C6 falsified; §1.1
above is what ships.)* The §5 relying-party token is the paper's dual-hash
challenge-response over the handshake-co-generated keys:

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

A keyed commitment binds *content* — it says nothing about *when* or *how many
times* the token is presented, because those are not functions of the committed
bytes. **CORRECTION (2026-09-17, C6):** the sentence that stood here — "it
proves the IdP authenticated exactly this claim for exactly this RP" — was
FALSE of the rule shipped at the time. That rule MAC'd only the inner hash, so
it proved nothing about the claim, and its key was one every user held. It is
true of the §1.1 construction, where `canon(claim)` is inside the outer MAC and
the RP checks against an IdP-delivered reference. Making the token itself
one-time or time-limited requires either (a) RP state that remembers what it has
already accepted, or (b) an RP-contributed fresh input mixed into the challenge
before the token is minted. Both live at the RP/ceremony layer, which is exactly
why this is a G4-end-to-end obligation, not a G4-assertion (token) property.

## 3. Resolution options

### Option A — RP-enforced freshness (normative MUST on the relying party)

Keep the token a keyed commitment (zero new primitive). Add a normative §5
clause: a conforming RP MUST reject unless **all** hold:

1. the binding check. *(As written in 2026-07 this was
   `HMAC(tenant_key, H1'_presented) == H2_presented`, which is the C6 defect;
   §1.1 gives the rule actually implemented — the recomputed tag over
   `canon(claim) ‖ binder` must equal an IdP-delivered reference.)*
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

**Trust note — CORRECTED 2026-09-17.** Under A the *freshness* guarantee rests
on the RP behaving (keeping a nonce cache + clock). The claim that followed —
that an RP forgetting freshness "cannot be tricked into accepting a claim for
the wrong subject/audience, only a stale/replayed one for the *right* subject"
— was **FALSE** under the rule of the day and is the substance of C6(b): the
accept rule read no field of the claim, so the wrong subject and the wrong
audience were both reachable. Under §1.1 the corrected statement holds: the
authentication guarantee rests on the keys AND on `canon(claim)` being inside
the MAC, so an RP that skipped the freshness legs would be exposed to a
stale/replayed token for the right subject — and to nothing else.

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
- a **future/backdated** claim (`iat > now + skew`) is **rejected** — *this leg was
  CLAIMED here but NOT enforced until the round-11 DSSO audit (`wf_f1ca5dcc`):
  `rp_verify` bounded `iat` only from BELOW (`now − skew ≤ iat`), so a claim dated
  far in the future satisfied every condition (the whole `[iat, exp]` window is
  merely shifted forward, so the `exp − iat ≤ T_max` bounded-lifetime guard is
  nullified) and, once the RP evicted the nonce after its `T_max + skew` retention,
  the identical token replayed indefinitely — one honest login yielding a long-lived
  bearer credential. Closed by the upper bound `iat > now + skew → reject`, gated
  falsify-on-mutant by **E2E-7b** in `test-dsso-login-e2e`;*
- a **fresh, in-window, first-use** token is accepted.

All four legs are enforced today, in two places: `test-dsso-login-e2e` (E2E-6,
E2E-7, E2E-7b) gates them over the login composition, and — since 2026-09-17 —
`determ-dsso selftest-assertion` gates them in the shipped module over a claim
the RP has AUTHENTICATED, which is the part this document originally assumed and
did not have. `test-dsso-assertion`, whose printed SCOPE NOTE declared these legs
out of scope, is RETIRED: it asserted the pre-C6 accept rule as "C6 correctness".

## 6. Scope

**Resolved, and since 2026-09-17 implemented.** The owner ratified **Option A**;
its four legs are normative in `v2.25-DSSO-DAPP-SPEC.md` §5 and are enforced by
`dapps/dsso/assertion.c`. The accept rule they sit on is NOT the `H2 == H2'` rule
this document was written against — that rule was defect C6 — but the rewritten
§5.3 rule; see §1.1. This document is retained as the decision record (options +
rationale), with its two false premises corrected inline in §2 and §3. Cross-refs:
[`DssoThresholdOprfSoundness.md`](DssoThresholdOprfSoundness.md) §6 (the residual
this resolves), [`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md) §5.
