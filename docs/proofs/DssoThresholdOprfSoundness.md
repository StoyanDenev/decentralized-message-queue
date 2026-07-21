# DSSO threshold-OPRF soundness — Bundle-A gates G1 + G2 + G3 (+ the G4 assertion layer)

**Status: SHIPPED (the math gate + the credential envelope + the RP assertion
token).** Backs the first three of the six §9 green gates of
[`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md), plus the assertion (RP-token)
layer of G4 (§6 below). Two gates:
- `determ test-dsso-threshold-oprf` (`tools/test_dsso_threshold_oprf.sh`, FAST) —
  G1/G2/G3 (the OPRF math + credential envelope).
- `determ test-dsso-assertion` (`tools/test_dsso_assertion.sh`, FAST) — the §5
  dual-hash RP token, security claim **C6** (§6 below).

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

## 6. G4 (assertion layer) — the RP dual-hash token, claim C6

`determ test-dsso-assertion` (`tools/test_dsso_assertion.sh`, FAST; 7 assertions).

Spec §5 issues the relying-party token by the paper's **dual-hash
challenge-response** over co-generated keys — no signature, no FROST, no block
co-sign:

```
challenge = canonical length-prefixed (iss, sub, aud, iat, exp, nonce)
H1' = HMAC-SHA256(sso_key,    challenge)   # sso_key: the login-session key (given)
H2  = HMAC-SHA256(tenant_key, H1')         # tenant_key: the RP's registration key
RP accepts iff HMAC-SHA256(tenant_key, H1') == H2.
```

`H = HMAC-SHA256` (the shipped, KAT-gated keyed hash — **zero new primitive**;
`H(key, msg)` maps to HMAC, which avoids the length-extension pitfall of a bare
`SHA256(key‖msg)`). The seven properties gate security claim **C6** ("keyed-hash
challenge-response, PRF security of `H`, over PAKE-authenticated keys"):

1. **correctness** — an honest token is accepted (verifier-side).
2. **audience binding** — a token minted under RP-B's `tenant_key` is rejected
   under RP-A's, and vice versa (both directions): an SSO token is RP-scoped by
   the `tenant_key` layer, which `rp_accept` checks (verifier-side).
3. **session binding** — a token whose `H1'` came from a different `sso_key`
   does not verify (to accept a chosen `H1'` you need `HMAC(tenant_key, H1')`,
   i.e. `tenant_key`) (verifier-side).
4. **nonce commitment** *(generation-side)* — a fresh nonce yields a **distinct**
   token, and each `H2` is bound to its own `H1'` (neither cross-verifies).
5. **claim commitment** *(generation-side)* — mutating any of
   `iss/sub/aud/iat/exp` yields a **distinct** token, so no single token is valid
   for two claims (the IdP cannot be made to mint one token authenticating two
   claims).
6. **layer separation** — the bare inner `H1'` presented as the token is
   rejected: the `tenant_key` layer is mandatory, so an attacker who learns `H1'`
   but not `tenant_key` cannot forge `H2` (verifier-side).
7. **forgery** — an arbitrary 32-byte `H2` is rejected (verifier-side).

**What this proves, precisely.** The token is a sound keyed **commitment**:
unforgeable without the keys (1, 6, 7 + the HMAC-keying falsify below), and a
collision-resistant binding of `(sso_key, tenant_key, iss, sub, aud, iat, exp,
nonce)` (2–5). `sso_key` is a **given** handshake output — the OPAQUE AKE that
co-generates it is the owner-gated remainder of G4.

**Residual — verifier-side freshness is NOT gated (an adversarial-verification
finding, 2026-07-21).** The §5 accept rule is **stateless** (`HMAC(tenant_key,
H1') == H2`) and the RP cannot recompute `H1'` (it holds no `sso_key`). So the
token **in isolation** does not reject a *verbatim replay* of a captured
`(H1', H2)`, nor a claim *substituted at presentation* — properties 4/5 are
**generation-side** (the honest producer emits distinct tokens for distinct
inputs), not verifier-enforced. Verifier-side replay/expiry rejection needs RP
session state — an RP-issued **single-use nonce** plus an `exp`-vs-clock check —
which is a **ceremony/topology** property, part of the owner-gated G4 end-to-end
flow, not the token. This is flagged for a possible spec §5 clarification (the
accept rule as written omits the RP's freshness obligation). The gate prints this
scope explicitly and does not claim verifier replay-rejection.

*Falsify-on-mutant (executed, reverted via file backup).* This gate adds **zero
new production surface** (HMAC-SHA256 is shipped + KAT-gated), so the falsify
targets the shipped keyed hash: neutralizing the key in `determ_hmac_sha256`
(`src/crypto/sha2/hmac.c`, the short-key copy) flips **exactly** the two
key-dependent assertions — audience binding and session binding — while the
message-dependent ones (correctness, replay, claim binding, layer separation,
forgery) stay green. That directional signature is the point: the two properties
whose security *is* "the key matters" are the two that break when the key stops
mattering.
