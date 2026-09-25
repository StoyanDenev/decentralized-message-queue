# DSSO threshold-OPRF soundness — Bundle-A gates G1 + G2 + G3 (+ the G4 assertion layer + the G4 OPAQUE-3DH AKE core)

**Status: SHIPPED (the math gate + the credential envelope + the RP assertion
module).** Backs the first three of the six §9 green gates of
[`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md), plus the assertion (RP-token)
layer of G4 (§6 below). Two gates:
- `determ test-dsso-threshold-oprf` (`tools/test_dsso_threshold_oprf.sh`, FAST) —
  G1/G2/G3 (the OPRF math + credential envelope).
- `determ-dsso selftest-assertion` (`tools/test_dsso_assertion_module.sh`, FAST)
  — the §5 RP assertion, security claim **C6**, as a MODULE
  (`dapps/dsso/assertion.{h,c}`) since 2026-09-17. It replaces
  `determ test-dsso-assertion`, which asserted the pre-C6 accept rule and is
  RETIRED; §6 below records what that gate proved and what it did not.

## 0.0 ⚠ Soundness corrections (2026-07-28, round-11 post-ship audit `wf_f1ca5dcc`)

Three claims below did **not** hold of shipped code. **All three are now closed**: the `iat` upper bound on 2026-07-28, and AKE-2 (the C2 fix) together with Property 3 and the §6 residual (the C6 fix) on 2026-09-17.

- **AKE-2 (§ "mutual authentication") was FALSE as stated — ✅ CLOSED 2026-09-17.** "`server_mac` … is verifiable only by a party that derived `Km2`, which requires **the server's** private DH contributions" — in fact **any** `(sk_s′, esk_s′)` pair worked, because the client's `pk_s` was an unauthenticated caller argument of `determ_opaque3dh_client`, the transcript (`hash_preamble`) bound **neither** static public key, and the credential envelope was sealed with **AAD = NULL** so it carried no `server_public_key`. An attacker holding only the victim's **public** `pk_c` impersonated the IdP and derived the same `sso_key` — **verified by executing the attack**, and re-executed against the shipped C before the fix. **Closed** by the RFC 9807 §4.1.1 `CleartextCredentials` binding + the removal of the `pk_s`/`pk_c` call arguments + the envelope AAD (v2.25-DSSO-DAPP-SPEC §0.0(2)); AKE-2 is restated below on what now holds, and the `pk_s`-authenticity assumption it always needed is now written down as a trust boundary instead of being silent.
- **Property 3 ("a token whose `H1'` came from a different `sso_key` does not verify — *(verifier-side)*") was FALSE — **CLOSED 2026-09-17**.** The rule of the day (the `rp_accept` lambda in the now-retired `test-dsso-assertion`) took **both** `H1'` and `H2` from the presenter and never touched `sso_key`; a complete token minted under a different `sso_key` verified **by construction**. Closed by the rewritten spec §5 and the module `dapps/dsso/assertion.c`: the RP compares its recomputed tag against a reference the IdP delivered, so being accepted requires the IdP's own `binder = HMAC(sso_key, ·)`. Gated by `determ-dsso selftest-assertion`, falsify-proven by mutants M1 (restore the unsound rule) and M2 (drop `sso_key` from the derivation).
- **The §6 residual marked RESOLVED by Option A was NOT resolved — **CLOSED 2026-09-17**.** Option A's four legs were evaluated on a cleartext claim the RP could not authenticate, so **claim substitution at presentation** survived all of them (the attacker rewrote `nonce`, `iat`/`exp`, and `sub`). Closed by putting `canon(claim)` inside the outer MAC (spec §5.2): the claim the RP acts on is now the claim the IdP asserted. Gated per field — subject, audience, session, nonce, `iat`, `exp`, issuer — by `determ-dsso selftest-assertion`, falsify-proven by mutants M3 (drop the audience from the binding) and M4 (drop the session id).
- **CLOSED (`e6bad81`):** the §6 "future" leg was listed as gated but the verifier bounded `iat` only from below; the upper bound now ships, gated falsify-on-mutant by **E2E-7b** in `test-dsso-login-e2e`.

## 1. What this proves, and what it does not

The DSSO "Sign-In With Determ" login (spec §4) is a **t-of-n, unordered
threshold OPRF**: the user Shamir-deals the OPRF key `k` over the P-256 scalar
field `Z_n`, each server `i` holds a share `k_i`, and on login the user blinds
the password to `B = r·H2C(pw)`, broadcasts it, and Lagrange-combines **any t**
of the responses `Z_i = k_i·B` back to `Z = k·B`. No server below `t` learns the
password; no fixed order; no server-to-server communication.

This document backs the gates that pin the **cryptographic math** of that login
before any ceremony code is written (G1–G3), plus the RP assertion token (§6):

- **G1 — t-of-n identity.** For every t-subset `S`, the Lagrange combination
  `Σ_{i∈S} λ_i·Z_i` equals the direct single-key evaluation `k·B`, and hence the
  finalized OPRF output is identical whichever `t` servers answer.
- **G2 — per-response DLEQ soundness.** Each `Z_i` carries an RFC 9497 VOPRF DLEQ
  proof against the server's published `PK_i = k_i·G`; a tampered response fails
  its proof, and — the load-bearing part — if admitted anyway it corrupts the
  combine, so the check is what protects the login (spec C4).
- **G3 — the credential envelope, composed with the login.** Spec §3 registration
  step 3 seals the user credential as `envelope = AEAD_{HKDF(y)}(cred)`. The AEAD
  key is derived from the OPRF output `y`, so the credential unseals with the `y`
  recovered from **any** t-of-n login — this is the whole point of the threshold
  OPRF, and it is the composition with G1. A **wrong password's** `y` fails the
  AEAD tag, so the credential stays sealed. Run for both profiles: MODERN
  XChaCha20-Poly1305 and FIPS AES-256-GCM. **G3 adds zero new production surface**
  — HKDF and both AEADs are already shipped + KAT-gated (`test-*-c99`), and the
  `y` it feeds to HKDF is produced by the same combine G1 proves identical.

The §5 **dual-hash assertion token** (the RP-facing half of G4) is gated in §6.
What remains out of scope: the **OPAQUE aPAKE handshake** that co-generates the
`sso_key` the assertion consumes (the design-sensitive AKE — owner-gated), the
full register→login→assertion→RP wiring as one live flow (G4 end-to-end), and the
constant-time / zeroization review of the secret scalar paths (G5/G6). G3 gates
the envelope's *crypto round-trip and password-binding*, not the AKE; the
production HKDF-info / AEAD-nonce / H1-H2 wire parameters are pinned at the
ceremony increment (mirroring how spec §5 pins the assertion wire format "at
implementation").

## 2. Zero new primitive

The threshold OPRF is **Shamir + Lagrange-in-the-exponent** (TOPPSS, JKKX 2017)
over primitives already shipped and KAT-gated:

- P-256 group ops — `point_mul`, `point_add`, `base_mul`, compress/decompress
  (§3.8c, `test-p256-c99`).
- P-256 scalar field `Z_n` — `scalar_mul_mod_n`, `scalar_inv_mod_n` (§3.9b), and
  the two additive ops this increment **exposes**: `scalar_add_mod_n`,
  `scalar_sub_mod_n`. These are not new arithmetic — they wrap the internal
  `sc_add_raw` / `sc_sub_raw` (already used by the field setup and SSWU paths)
  through the same big-endian ↔ limb conversion the other scalar publics use.
  This is the same "expose an existing internal op" move that shipped
  `point_add` + `hash_to_scalar` as OPRF enablers.
- RFC 9497 OPRF/VOPRF — `oprf_blind` / `oprf_evaluate` / `oprf_finalize` /
  `voprf_prove` / `voprf_verify` (§3.9b, `test-p256-oprf-c99`, appendix vectors
  via §3.13).

The additive ops operate on the **raw** (non-Montgomery) limbs: `sc_add_raw`
does a limb add then one conditional subtract of `n` (`a,b < n ⇒ a+b < 2n`, so a
single reduction suffices), and `sc_sub_raw` adds `n` back on borrow. `mul_mod_n`
needs the Montgomery domain because multiplication does; addition and subtraction
do not — hence the wrappers are the shorter `be_to_fe → sc_op → fe_to_be`, with
the standard `>= n` public-validity reject leaving the output untouched on `-1`.

Consistent with spec §2: *zero new primitives, zero new hardness assumptions.*
(Note the spec §2 table lists "Shamir over the P-256 scalar field" among the
shipped primitives; what was literally shipped are the *field ops* — the
byte-wise wallet Shamir is GF(2⁸), the FROST-library Shamir is over the Ed25519
field. The P-256 Shamir/Lagrange *combine* is the thin composition layer this
increment adds on top of the shipped field, which is what "zero new primitive"
means here.)

## 3. The gate

`test-dsso-threshold-oprf` (18 assertions):

1. **Scalar-op self-validation, oracle-free.** `(a+b)·G == a·G ⊕ b·G` and
   `(a−b)·G ⊕ b·G == a·G` tie the two exposed additive ops to the group via the
   shipped point ops — no external oracle needed; plus `a+0==a`, `a−a==0`,
   commutativity, and the `>= n` reject.
2. **G1 identity, exhaustive.** All `C(5,3)=10` subsets of a 3-of-5 sharing and
   all `C(3,2)=3` of a 2-of-3 sharing reconstruct `k·B` **and** the identical
   OPRF output — enumerated, not sampled. The subset counts are asserted
   (`==10`, `==3`) so a silently-skipped subset cannot read as coverage.
3. **Threshold realness.** A `(t−1)`-share subset does **not** reconstruct `k·B`
   (spec C1/C3): fewer than `t` shares interpolate the wrong polynomial at 0.
4. **G2.** Every honest response's DLEQ verifies; a byte-flipped `Z_i` fails its
   DLEQ (client discards it); and admitting the tampered response corrupts the
   combine (`≠ k·B`) — proving the DLEQ check is load-bearing, not decorative.
5. **G3, both profiles.** A t-of-n login recovers `y` (fed to HKDF as bytes, so
   the composition is genuinely exercised, not assumed from G1); the credential
   sealed under `y` unseals with that recovered `y` (MODERN XChaCha20-Poly1305
   and FIPS AES-256-GCM); and a **wrong password's** `y` fails the envelope AEAD
   tag so the credential stays sealed. A wrong password is first shown to yield a
   different OPRF output.
6. **G4 login (fault-tolerant), the login half of §9 G4.** The exact scenario the
   spec names — `n=5`, `t=3`, **one server crashed** (sends no response) **and
   one byzantine** (returns a bad DLEQ) in the **same** login. The client runs
   the §4-step-4 pipeline over the *available* responses (it does not know a
   priori which are honest): verify each DLEQ, discard the failures, Lagrange-
   combine the survivors. Three assertions: the filter admits **exactly** the
   `t=3` honest responses `{S0,S1,S2}` (the crashed one absent, the byzantine one
   rejected); combining those survivors recovers the reference OPRF output `y`
   (the login succeeds despite the two faults); and — load-bearing — combining
   the byzantine response instead (skipping the filter) breaks recovery, so the
   DLEQ filter is what makes the fault-tolerant login sound, not any 3 responses.
   This composes G1 (subsets reconstruct) and G2 (a bad response is detected)
   into the survivor-**selection** pipeline neither exercises alone. Out of scope
   here (owner-gated remainder of G4): the OPAQUE AKE that co-generates
   `sso_key`, and the RP assertion token (gated separately in §6).

The reference `k·B` is computed by the single-key `oprf_evaluate(k, B)` — an
independent path from the shares (`poly_eval`) and the combine (Lagrange), so G1
is a genuine cross-check, not a tautology.

## 4. Falsify-on-mutant (executed, each reverted)

The two exposed scalar ops are the only production surface, so they are the
falsify targets — and because G3 feeds the threshold-recovered `y` to HKDF, a
scalar mutation now cascades into G3 too:

| Mutation (`src/crypto/p256/p256.c`) | Result |
|---|---|
| `scalar_add_mod_n` body `sc_add_raw` → `sc_sub_raw` | the scalar-op self-check, **both** G1 assertions, **and** G3's login-recover + both unseal assertions turn RED (6 total) |
| `scalar_sub_mod_n` body `sc_sub_raw` → `sc_add_raw` | same signature |

Either mutation breaks the Shamir deal (Horner uses add) or the Lagrange
denominator (uses sub), so the combine no longer equals the independent `k·B`
reference; the group-tied self-check catches the op directly, and the wrong `y`
propagates to a wrong HKDF key so the G3 envelope no longer unseals — proving G3
is genuinely composed on the threshold math, not a standalone envelope
round-trip. (The G3 **wrong-password rejects** stay green under this mutation:
they don't depend on the shares, so they isolate the password-binding property.)

The G4-login block carries its own test-logic falsify (the byzantine server is
the only new fault surface): **neutralizing the byzantine tamper** (S3 now sends
an honest response) flips exactly the filter-exactness assertion (survivors
become `{S0,S1,S2,S3}`, count `≠ t`) and the load-bearing negative (combining
`{S0,S1,S3}` now *does* reconstruct) RED, while the middle assertion — combine
the first `t` survivors — stays green (they truncate to the honest prefix). That
clean directional split proves the gate rests on the byzantine actually being
detected, not on any three responses combining.

*Process note:* because these definitions are uncommitted while iterating, the
mutant loop must restore from a file backup, not `git checkout`, which would
revert the work under test.

## 5. Gate

`tools/test_dsso_threshold_oprf.sh`, in the FAST suite via `dsso_threshold_oprf`;
MSVC + WSL2 GCC. Cross-references
[v2.25-DSSO-DAPP-SPEC.md](v2.25-DSSO-DAPP-SPEC.md) (§4 login, §9 gates, C1/C3/C4)
and [CRYPTO-C99-SPEC.md](CRYPTO-C99-SPEC.md) §3.8c/§3.9b (the shipped P-256 + OPRF
stack this composes).

## 6. G4 (assertion layer) — the RP assertion, claim C6

**Rewritten 2026-09-17.** `determ-dsso selftest-assertion`
(`tools/test_dsso_assertion_module.sh`, FAST; 61 assertions) over the module
`dapps/dsso/assertion.{h,c}`. The full normative rule is
[`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md) §5, which this section does
not restate; what follows is only what this document owes a reader: what the
previous section claimed, why it was wrong, and where the claim now rests.

**What stood here until 2026-09-17.** Seven properties of the accept rule
`HMAC(tenant_key, H1'_presented) == H2_presented`, gated by the now-retired
`determ test-dsso-assertion`. Four of them (nonce commitment, claim commitment,
and the two halves of "audience binding") were *generation-side*: true statements
that an honest IdP emits distinct tokens for distinct inputs. Three were labelled
*verifier-side*, and of those, "session binding" was **false** — §0.0 above.

**Why the section was wrong, in one line.** Its accept rule was a pure function
of `tenant_key` and bytes the presenter chose, so a `tenant_key` holder could
satisfy it by running the honest minting algorithm with an `sso_key` of its own
(C6(a)), and it read no field of the claim, so one honest token authenticated any
substituted claim (C6(b)). Both were reproduced against the shipped lambda before
the fix. Generation-side properties cannot close either gap: they constrain the
honest producer, not the verifier.

**Where the claim rests now.** On spec §5.3: the RP recomputes
`HMAC(tenant_key, DS_TAG ‖ canon(claim) ‖ binder)` over the PRESENTED claim and
binder and accepts only if it equals — in constant time, over the full 32 bytes —
a reference tag the IdP delivered over the registered channel and that has not
expired; then that the authenticated `sid` is the session this verifier is
completing, then the three clock legs and the single-use nonce. Because
`canon(claim)` is inside that MAC, the claim the RP acts on is the claim the IdP
asserted; because the reference comes from the IdP, being accepted requires the
IdP's own `binder = HMAC(sso_key, ·)`. Each step is HMAC-SHA-256 — **zero new
primitive**, and the C6 backing is now PRF + collision resistance of a keyed hash
applied to an accept rule that actually reads both keys and the claim.

*Falsify-on-mutant (executed against a rebuilt binary, source restored after
each).* M1 restore the unsound rule (verify against a presenter-supplied `H1'`);
M2 drop `sso_key` from the derivation; M3 drop the audience from the binding;
M4 drop the session/request id; M5 skip the nonce-cache insert; M6 make the
pairwise subject a per-user constant; M7 truncate the tag compare. Each turns a
NAMED leg of the gate RED. The non-constant-time variant of M7 (`memcmp` for
`dsso_ct_equal`) is behaviourally indistinguishable and is therefore **not**
falsifiable by a functional gate; it is held by using the `dsso_core`-gated
`dsso_ct_equal`, and that is a weaker statement than the others here.

**Residual, unchanged by this fix.** The `binder` is a bearer secret in transit:
front-channel confidentiality is the deployment's, and single use + `T_max` + the
`sid` binding are what bound a stolen one. The IdP→RP reference channel is
authenticated by the registration, not by this module. A compromised IdP can
assert anything — the mutual-distrust property is a property of the *login*
(C1/C3/C4).

## 7. G4 (AKE core) — the OPAQUE-3DH session-key co-generation

The G4 assertion layer (§6) verifies the RP token *given* a shared `sso_key`. This
section closes the other half of the "given": the AKE that co-generates `sso_key`
between the client and the IdP. Spec §4 step 5 says *"the OPAQUE handshake
co-generates a shared session key"*; the owner selected **OPAQUE-3DH (RFC 9807
§6.4)** as that handshake (DECISION-LOG 2026-07-21). The module is
`src/crypto/dsso/opaque3dh.c` (`determ_opaque3dh_server` / `_client`); the gate is
`test-dsso-opaque3dh` (`tools/test_dsso_opaque3dh.sh`, FAST, both platforms).

**Scope.** This proves the AKE core — the 3DH + key schedule + transcript-MAC
mutual auth — in isolation. The `credential_request` / `credential_response` are
opaque transcript blobs here; the OPRF/envelope that fills them (G1/G2/G3, §3-5) is
composed in at the login layer in inc.2. So the claim is exactly: *both parties
derive the SAME `session_key` from the three DH values + the whole transcript, and
the two MACs bind that transcript so any tamper is detected.*

**Zero new primitive / zero new hardness assumption.** The construction is three
P-256 scalar mults (the 3DH: client-eph×server-eph, client-eph×server-static,
client-static×server-eph), an RFC-9807 / TLS-1.3 HKDF-Expand-Label schedule over
HKDF-SHA256, and HMAC-SHA256 — all shipped (`determ_p256_point_mul`/`_base_mul`/
`_point_compress` §3.8c, `determ_hmac_sha256` + streaming `determ_sha256` §3.1). No
new C surface beyond the composition module itself. Security rests on the standard
OPAQUE-3DH argument (RFC 9807; Gap-DH / ROM) — this doc does not re-derive it; it
gates the byte-level realization.

**AKE-1 (mutual agreement).** For an honest run, `client.session_key ==
server.session_key`. Both sides compute the same unordered triple of shared points
(the DH symmetry `a·(b·G) = b·(a·G)`) and hash the same transcript, so the key
schedule is a pure function of shared inputs. *Gate:* the "both parties derive the
SAME session_key" assertion.

**AKE-2 (mutual authentication) — restated 2026-09-17 on the v2 transcript.**
`server_mac = HMAC(Km2, SHA256(preamble))` is verifiable only by a party that derived
`Km2`, which requires `(dh1, dh2, dh3)` over the **transcript-bound** static keys:
`dh2` is `esk_c·t->server_public_key` on the client and `sk_s·epk_c` on the server, so
they agree only if the peer holds `sk_s` for the `server_public_key` the client
anchored — and the preamble, hence `Km2` itself, commits to that key through the
RFC 9807 §4.1.1 `CleartextCredentials` block. `client_mac = HMAC(Km3,
SHA256(preamble‖server_mac))` is symmetric and always required `sk_c`.

What the old text got wrong, and why it matters: **any** `(sk_s′, esk_s′)` reproduced
all three DH values against a client whose `pk_s` was attacker-supplied (`dh2 =
sk_s′·epk_c`, `dh3 = esk_s′·pk_c` need only the **public** `pk_c`), and the definite
article in "**the** server's private DH contributions" smuggled in an authenticity
assumption for `pk_s` that nothing supplied. Two things changed. (1) The static keys
are no longer call arguments: a party has exactly **one** slot for a static key and
that slot is MAC-covered, so there is no longer a way to run the DH over a key the
transcript does not name. (2) The authenticity assumption is now *discharged*, not
assumed: the same `CleartextCredentials` bytes are the AAD of the §3-step-3 envelope,
whose key is `HKDF(OPRF_k(pw))` — so recovering an authentic `pk_s` costs the password
plus ≥ `t` OPRF responses, the C1/C3 assumption this design already makes. The
residual (who authenticates `pk_s` at **enrolment**, before any envelope exists) is
the on-chain DSSO registration record read through the committee-authenticated light
client, and is written out — with its named gap — in spec §0.0(2).

*Gates:* "client verifies the server MAC" + "expected client MAC == client MAC" gate
agreement between two honest parties; the **C2-a…C2-g** arms gate the authentication
proper — an impersonator holding only `pk_c` is rejected, a server that holds the real
`sk_s` but claims a different static key is rejected although every DH value agrees,
a substituted `client_public_key` or identity is rejected, and the MAC comparison
covers all 32 bytes. Mutants M1–M6 each turn one of those arms RED.

**AKE-3 (transcript binding).** Every output is keyed on `SHA256(preamble)`, and
the preamble streams every wire field (context, the `CleartextCredentials` block —
both **static public keys** and both identities — both nonces, both ephemerals, both
credential blobs). A single changed field ⇒ a different key and a server MAC the
honest client rejects. *Gate (executed):* flipping `server_nonce` yields a DIFFERENT
`session_key` AND the honest client, fed that wrong-transcript server MAC over the
honest transcript, sets `server_mac_ok = 0`.

**AKE-4 (fail-closed).** NULL transcript / NULL nonce / over-length field / identity
ephemeral ⇒ `-1`, outputs untouched. *Gates:* the two NULL-edge assertions.

**Dual-oracle byte-freeze (v2).** The whole schedule was frozen python-first in
`tools/verify_opaque3dh.py` before any C existed, and the C reproduces the KAT
byte-for-byte. The v1 vectors are **retired** with the v1 encoding (no deployment
existed, so no login transcript had to reproduce, and a retained v1 path would have
left the impersonable construction compiled in as a downgrade target — spec §0.0(2)
"Permanence"); the tags moved to `DTM-DSSO-OPAQUEv2-` / `DTM-DSSO-OPAQUE3DH-v2-` /
`DTM-DSSO-CLEARCRED-v2-` so the encodings can never be confused. The v2 KAT:
`session_key = 669097b27b88b05eb468d46a00c4fb9b6f06d6d6696ec3b85ea61d1456cfc880`,
`server_mac = 5a86590c25a05a7c287eaf80ae21b3f11b7b162ec83c9f68425e95ced14381f7`,
`client_mac = 4de728062ab9344d0691f806fabbace1227c6c24407fedeb703201f90a3f3a35`,
plus the serialized `CleartextCredentials` block itself.
Two independent implementations (a from-scratch python P-256 ladder + hashlib HKDF,
vs the determ::c99 C stack) landing on the identical bytes is the soundness witness
for the encoding — the same discipline as §3.25 notekey and the Pedersen/OPRF KATs.

**Out of scope of §7 (later increments).** inc.2 (this doc §8) composes the
OPRF-recovered credential into `cred_request`/`cred_response`; inc.3 stitches the
three halves into the single end-to-end gate + the four §5 Option-A freshness legs.
G5/G6 (CT review + zeroization audit of the secret scalar paths) remain owner-gated.
Cross-ref `CRYPTO-C99-SPEC.md` §3.26, `v2.25-DSSO-DAPP-SPEC.md` §4/§9, `DssoAssertionFreshness.md`.

## 8. G4 (end-to-end) — the register → t-of-n login → OPAQUE-3DH AKE composition

Sections §1-§6 gate the login math (G1/G2), the envelope (G3), the fault-tolerant
login (G4-login), and the RP token (G4-assertion); §7 gates the AKE core in
isolation. This section closes the last gap: the pieces **compose** into the full
login and the security properties hold end-to-end. Gate `test-dsso-login-e2e`
(`tools/test_dsso_login_e2e.sh`, FAST, both platforms). **Zero new primitive** —
every operation is one of the already-byte-frozen pieces (OPRF/AEAD/HKDF/P-256/
opaque3dh); this is a *composition/property* gate, not a new byte-KAT.

**Credential model (owner decision 2026-07-21).** The client's long-term OPAQUE
credential is a **fresh P-256 keypair** `(sk_c, pk_c)` — the DSSO identity is
SEPARATE from the on-chain Ed25519 identity (no linkage), and single-curve P-256 is
what the OPAQUE-3DH `stat×eph` / `eph×stat` terms require. Spec §3's "Ed25519
keypair" predated the RFC-9807-standard AKE choice and is clarified to P-256 (spec
§2/§3, folded this increment; DECISION-LOG 2026-07-21). Registration mints
`(sk_c, pk_c)`, seals `sk_c` under `HKDF(y_reg)` into the envelope **with the RFC 9807
§4.1.1 `CleartextCredentials{pk_s, pk_c, server_identity, client_identity}` as AAD**
(C2, 2026-09-17 — byte-identical to the block the §7 AKE transcript binds), and the
server stores `pk_c` + its own static `(sk_s, pk_s)`. Login runs the threshold OPRF →
`y` → rebuilds the AAD from the `CleartextCredentials` fields the server sent →
unseals `sk_c` → runs the AKE with `cred_request = the OPRF blind` and
`cred_response = the combined OPRF evaluation ‖ the envelope`.

**E2E-1 (honest login).** A correct-password t-of-n login recovers `y = y_reg`,
unseals `sk_c`, and the AKE yields `client.session_key == server.session_key` with
both transcript MACs authenticating AND the recovered `sk_c` equal to the sealed
one. *Gate:* the "both parties derive the SAME sso_key … credential recovered"
assertion (which ANDs MAC agreement, key agreement, and `sk_c_rec == sk_c`).

**E2E-2 (password binding gates the whole login).** A wrong password yields a
different OPRF output `y' ≠ y_reg`, so the envelope AEAD tag fails and `sk_c` is
never recovered — the login **aborts before the AKE runs at all**. *Gate:* the
wrong-password unseal-fails assertion. This is the property that makes the login a
password-authenticated flow rather than an unauthenticated key exchange.

**E2E-3 (credential-transcript binding — the load-bearing composition claim).** The
`cred_request`/`cred_response` are not merely computed alongside the AKE; they are
**bound into the AKE transcript** (§7's preamble streams both). So a MITM who swaps
`cred_response` between the server and the client makes the client's transcript
differ from the server's, and the client rejects the server MAC (`server_mac_ok =
0`). *Gate (executed falsify):* deleting the `cred_response` update from the §7
`hash_preamble` flips EXACTLY this assertion RED (the swap stops mattering) while
E2E-1 stays green (both sides omit it identically) — the clean directional split
proves E2E-3 rests on the binding, not on the AKE running.
**Open finding (2026-09-25, SECURITY.md S-120):** the binding is not injective.
The preamble streams both fields without lengths, so a split that moves bytes
between `cred_request` and `cred_response` (with a different client nonce) keeps
the preamble bytes and `server_mac_ok = 1`. E2E-3 holds for a swap that changes
the concatenation, not for every change of the two fields.

**E2E-10 (C2 — the client's `pk_s` is AUTHENTIC, not merely bound).** Transcript
binding alone cannot create trust in a key the client learned from the attacker, so
the envelope AAD is where that trust comes from at login time. Substituting
`server_public_key` (or `client_public_key`, or an identity) in what the server sends
changes the AAD the client rebuilds, the AEAD tag fails, and the login **aborts
before the AKE** — the same failure shape as a wrong password, and for the same
reason: opening the envelope costs `pw` **and** ≥ `t` OPRF responses. *Gates:*
E2E-10a (substituted `pk_s` → abort), E2E-10b (substituted `pk_c` → abort), E2E-10c
(the honest pair still opens and authenticates). *Falsify (executed):* re-nulling the
AAD on both the seal and the open (mutant M7) flips E2E-10a/b RED while E2E-1..9 stay
green — the directional split proves E2E-10 rests on the AAD, not on the login
running. The enrolment-time half of the boundary (who authenticates `pk_s` before any
envelope exists) is the on-chain registration record read through the committee-
authenticated light client, with its named gap, in spec §0.0(2).

**E2E-4 (fault tolerance, end-to-end).** With `n=5, t=3`, one server crashed and one
byzantine (bad DLEQ), the client's survivor-selection pipeline (§5, G4-login) admits
exactly the honest `t=3`, and combining them recovers `y` → unseals `sk_c` → the AKE
succeeds. *Self-load-bearing:* had the byzantine response been admitted, the combine
would yield a wrong `Zc` → wrong `y` → the envelope unseal FAILS → no login. So the
DLEQ filter is what makes the fault-tolerant login sound, end-to-end.

**E2E-5..E2E-9 (inc.3) — the token is bound to the login's `sso_key`.** The same
`test-dsso-login-e2e` gate carries the composition through to an RP acceptance:
register → login → AKE → keyed-hash assertion accepted. Its local rule is the IdP
reference rule: the IdP computes `H2' = HMAC(tenant_key, HMAC(sso_key_real,
challenge))` from the login's co-generated key and hands it to the RP, which
accepts iff `HMAC(tenant_key, H1'_client) == H2'` **and** the freshness conditions
hold (audience match; `now − skew ≤ iat`; `exp > now`; `exp − iat ≤ T_max`;
single-use nonce cache).

> **This is NOT the normative §5 accept rule (corrected 2026-09-17).** That rule is
> the module `dapps/dsso/assertion.c`, gated by `determ-dsso selftest-assertion`
> (§6 above). The reference rule here closes C6(a) — a party without `sso_key`
> produces a different `H1'` — but NOT C6(b), because its accept predicate reads
> no field of the cleartext claim; the harness only appears to close it because it
> hands the same claim object to the IdP lambda and to the verifier lambda. What
> E2E-5..9 gate, and what they are kept for, is the LOGIN COMPOSITION: that the
> AKE's co-generated key reaches the RP-facing token at all. The module takes that
> key as a given input.

- **E2E-5 (accept):** the honest token minted under the login's real `sso_key`, fresh
  + in-window + audience-matched + unseen-nonce, is accepted.
- **E2E-6 (replay):** the same `(challenge, token)` presented a second time is rejected
  by the single-use nonce cache.
- **E2E-7 (freshness):** an expired (`exp ≤ now`), a stale (`iat < now − skew`), and an
  over-long-lifetime (`exp − iat > T_max`) claim are each rejected.
- **E2E-8 (audience):** a token whose `challenge.aud ≠` the RP's audience is rejected.
- **E2E-9 (session binding — the load-bearing composition claim):** an attacker WITHOUT
  the login's `sso_key` produces a different `H1'`, so `HMAC(tenant, H1'_atk) ≠ H2'` →
  rejected. This is what ties the RP acceptance to the AKE the login co-generated.
  *Executed falsify:* skipping the RP's `H2 == H2'` check flips EXACTLY E2E-9 RED (the
  attacker is accepted) while E2E-5 stays green — the clean directional split proves the
  gate rests on the session binding, not on the freshness/audience legs.

So `test-dsso-login-e2e` (18 assertions) gates the login composition end to end, and
together with `determ-dsso selftest-assertion` (61 assertions, the §5 rule) the G4
end-to-end gate is complete. The freshness legs discharge the
`DssoAssertionFreshness.md` verifier-side residual that a stateless token check
could not: the RP is stateful (nonce cache + clock window), so replay and expiry are
genuinely rejected — and, since 2026-09-17, over a claim the RP has authenticated.
**Remaining (owner-gated): only G5 (CT review) + G6 (zeroization)** audit the production
ceremony's secret handling once a production threshold-combine module exists — the
functional G4 flow is fully gated. Cross-ref `v2.25-DSSO-DAPP-SPEC.md` §3-6/§9,
`DssoAssertionFreshness.md`, `CRYPTO-C99-SPEC.md` §3.26.
