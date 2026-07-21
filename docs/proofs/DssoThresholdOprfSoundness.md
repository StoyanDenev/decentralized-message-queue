# DSSO threshold-OPRF soundness — Bundle-A gates G1 + G2 + G3

**Status: SHIPPED (the math gate + the credential envelope).** Backs the first
three of the six green gates in
[`v2.25-DSSO-DAPP-SPEC.md`](v2.25-DSSO-DAPP-SPEC.md) §9. The gate is
`determ test-dsso-threshold-oprf` (`tools/test_dsso_threshold_oprf.sh`, FAST).

## 1. What this proves, and what it does not

The DSSO "Sign-In With Determ" login (spec §4) is a **t-of-n, unordered
threshold OPRF**: the user Shamir-deals the OPRF key `k` over the P-256 scalar
field `Z_n`, each server `i` holds a share `k_i`, and on login the user blinds
the password to `B = r·H2C(pw)`, broadcasts it, and Lagrange-combines **any t**
of the responses `Z_i = k_i·B` back to `Z = k·B`. No server below `t` learns the
password; no fixed order; no server-to-server communication.

This document backs the two gates that pin the **cryptographic math** of that
login before any ceremony code is written:

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

Out of scope here (later Bundle-A increments): the register→login→**dual-hash
assertion**→RP-accept end-to-end (G4), and the constant-time / zeroization review
of the secret scalar paths (G5/G6). In particular G3 gates the envelope's
*crypto round-trip and password-binding*, **not** the OPAQUE aPAKE handshake
(spec §4/§5) — that is the ceremony, a later increment, and the production
HKDF-info / AEAD-nonce wire parameters are pinned there (mirroring how spec §5
pins the H1/H2 assertion wire format "at implementation").

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

`test-dsso-threshold-oprf` (15 assertions):

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

*Process note:* because these definitions are uncommitted while iterating, the
mutant loop must restore from a file backup, not `git checkout`, which would
revert the work under test.

## 5. Gate

`tools/test_dsso_threshold_oprf.sh`, in the FAST suite via `dsso_threshold_oprf`;
MSVC + WSL2 GCC. Cross-references
[v2.25-DSSO-DAPP-SPEC.md](v2.25-DSSO-DAPP-SPEC.md) (§4 login, §9 gates, C1/C3/C4)
and [CRYPTO-C99-SPEC.md](CRYPTO-C99-SPEC.md) §3.8c/§3.9b (the shipped P-256 + OPRF
stack this composes).
