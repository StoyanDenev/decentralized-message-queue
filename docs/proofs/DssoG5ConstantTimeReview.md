> **TIER: NEAR-TERM — DSSO (v2.25) is a post-v1.0 DApp shipping at v1.1; NOT part of the 1.0-authoritative set.** This is the G5 ship-gate artifact for the DSSO D.5 packaging tail (owner directive 2026-07-26; CLAUDE.md CURRENT FRONT). Roadmap index: docs/ROADMAP.md.

# DSSO G5 — Constant-Time Review of the Secret-Scalar Paths

**Subject:** the DSSO (Sign-In With Determ, v2.25) crypto that touches SECRET scalars — the OPAQUE-3DH AKE
core (`src/crypto/dsso/opaque3dh.c`) and the P-256 secret-scalar primitives it and the DSSO threshold-OPRF
compose (`src/crypto/p256/p256.c`). This is the **G5 ship-gate** for D.5: a read-only constant-time review;
G5 itself made **no code change**. The G6 zeroization follow-ups it enumerated (§5) have since shipped —
byte-neutral, commit `cab12b2` (owner "full pass", 2026-07-26) — so the DSSO CT/zeroization ship-gate is
now closed on both halves.

**Method.** A 4-lens adversarial audit (workflow `wf_01d27b02`, read-only): (1) the OPAQUE-3DH composition;
(2) the P-256 scalar operations; (3) the P-256 field + point operations underneath the secret scalars; (4) a
secret-lifetime / zeroization cross-cut. Each lens defaulted to CLEAN and had to *name* a secret-dependent
branch / index / variable-time op to raise a VIOLATION. The two load-bearing verdicts — the Fermat scalar
inversion and the mod-n zeroization gaps — were then re-verified by direct read of `p256.c:468-540`.

**Threat model.** An attacker who can time (or micro-architecturally observe) either ceremony participant must
learn nothing about the secret scalars: the OPRF blind `r` and its inverse `r⁻¹`, the OPRF / service key `k`,
the OPAQUE static + ephemeral DH private scalars, the threshold-OPRF Shamir shares, and derived key material
(`prk` / `handshake_secret` / `session_key` / `Km2` / `Km3`). A constant-time **violation** is a data- or
memory-access pattern that depends on a secret *value*. Public data — on-wire lengths, SEC1 encodings,
validity/reject outcomes, fixed public exponents, the 1-bit auth result — may steer control flow freely.

---

## 1. Verdict

**The DSSO secret-scalar paths are CONSTANT-TIME on secrets. Zero timing / branch / secret-index violations.**
All four lenses returned CLEAN on the CT question; the only findings are **secret-lifetime (zeroization)
gaps**, which are *not* timing leaks and formed the **G6 worklist** (§5). The G5 constant-time ship-gate is
therefore **MET**; G6 (the byte-neutral zeroization pass) has since **shipped in `cab12b2`**, so both halves
of the DSSO CT/zeroization ship-gate are closed.

The whole surface reduces to a handful of load-bearing CT facts, each verified:

| # | Property | Where | Status |
|---|---|---|---|
| CT-1 | Secret scalar·point is a constant-time ladder (double-and-add-**always**, branchless mask `cswap`, over exception-free RCB complete addition — no add/skip fast path, no identity special-case) | `pt_scalar_mul` p256.c:264 over `pt_add` (RCB alg.4) p256.c:207 | ✅ |
| CT-2 | **Both** modular inversions are **Fermat** exponentiation over a **public** fixed exponent — **not** binary-GCD / extended-Euclid (the classic OPRF `r⁻¹` timing leak) | field `fe_inv` `a^(p-2)` p256.c:179; **scalar `determ_p256_scalar_inv_mod_n` `a^(n-2)` p256.c:482** (the OPRF `r⁻¹` in `oprf_finalize`) | ✅ |
| CT-3 | Every secret/secret-derived equality uses `determ_ct_memcmp` (no short-circuit), never `memcmp`/`==` | server-MAC verify opaque3dh.c:245; VOPRF challenge p256.c:1186 | ✅ |
| CT-4 | `hash_to_scalar` has **no** secret-dependent rejection-sampling loop (RFC 9380 hash-to-field, one branchless conditional-subtract) | `determ_p256_hash_to_scalar` p256.c:783 | ✅ |
| CT-5 | `be_lt` scalar range-check is a full 32-byte borrow chain with **no** first-differing-byte early return (the P256-CT-1 fix) | `be_lt` p256.c:287 | ✅ |
| CT-6 | The multi-scalar mul has **no** zero-scalar skip — a zero scalar runs the full ladder to `O` and folds uniformly (resolves the prior `ct-timing-probe` "p256-msm zero-skip" flag) | `determ_p256_msm_ct` p256.c:807 | ✅ |

CT-1/CT-2/CT-4/CT-5/CT-6 are the P-256 module's own properties, proven per-primitive in
[P256CryptoStackAudit.md](P256CryptoStackAudit.md) (§3 constant-time) and inventoried in
[ConstantTimeInventory.md](ConstantTimeInventory.md); this review confirms the **DSSO secret-scalar paths
reach exactly those primitives** and add no new secret-dependent control flow.

---

## 2. The secret-scalar surface

DSSO's secret scalars enter the crypto at three sites, all of which bottom out in the CT primitives above:

- **OPAQUE-3DH 3DH** — `dh_compress(out, scalar, point)` (opaque3dh.c:149) with the SECRET as the *scalar*
  (server: `esk_s`, `sk_s`, `esk_s`; client: `esk_c`, `esk_c`, `sk_c`), and `base_mul(epk, esk)` for the
  ephemeral public key. Both delegate to `determ_p256_point_mul` / `_base_mul` → the CT ladder (CT-1).
- **OPRF** (client blind/unblind, server evaluate/derive-key) — `oprf_blind` (secret input → SSWU → `r·P`),
  `oprf_evaluate` (`k·B`), `oprf_finalize` (`r⁻¹` via CT-2, then `r⁻¹·Eval`), `oprf_derive_key`. Secret
  scalars: the blind `r`, its inverse, the key `k`.
- **Threshold-OPRF Lagrange combine** — `determ_p256_scalar_mul_mod_n` / `_add_mod_n` over `Z_n` combine the
  public Lagrange coefficients `λ_i` with the SECRET Shamir shares (v2.25-DSSO-DAPP-SPEC §4/§9 G1; see
  [DssoThresholdOprfSoundness.md](DssoThresholdOprfSoundness.md)). The arithmetic is CT; the gap is lifetime
  (§5).

---

## 3. OPAQUE-3DH composition (opaque3dh.c) — constant-time

The AKE core is a pure composition of `determ::c99` primitives (P-256 scalar mult, HMAC-SHA256 HKDF with a
TLS-1.3/RFC-9807 Expand-Label schedule, streaming SHA-256 over the transcript). Every step is CT on secrets:

- **All branches / loop bounds are on PUBLIC data.** The length caps (`info_len>256`, `label_len>64`,
  `field_ok(len) ≤ MAX_FIELD`, `out_len>0xffff`), the `while (done < out_len)` and `if (context_len)` guards,
  and the null-pointer checks all key on on-wire field lengths / fixed constants — never a secret byte value.
  The `rc |= derive_secret(...)` error aggregate branches on the *aggregate* rc, whose components return `-1`
  only on a public label/length overflow (the labels are compile-time constants 15/10/9/9, out_len 32), so rc
  is constant (0) in operation and carries no secret.
- **The three 3DH ops** put the secret as the scalar and delegate to the CT ladder (§2, CT-1). The one
  data-dependent failure (`if (point_mul != 0)`) fires only on an off-curve / identity input — a *public*
  well-formedness condition, never a secret value.
- **The only secret comparison** — the client's server-MAC verify — uses `determ_ct_memcmp` (opaque3dh.c:245),
  and the `? 1 : 0` records only the already-computed CT result (the 1-bit auth outcome, inherently revealed).
  The client then computes `client_mac` **unconditionally** — the verify outcome drives no secret-dependent
  branch. (The server emits `expected_client_mac` for the caller's own CT check.)
- **Zeroization is complete on the secret material** on BOTH success and every reachable early-error return:
  `ikm[99]` (the staged DH secrets) — server exits :178/:182/:187/:189, client :229/:233/:240; `prk` +
  `handshake_secret` in `key_schedule` (:143-144, reached even on rc≠0); the DH point `p` in `dh_compress`
  (:151 fail, :153 success); `Km2`/`Km3` (server :195/:201-202, client :249/:255-256); `hkdf_expand`'s
  `buf`/`t` (:47-48). `determ_secure_zero` is a volatile-indirection scrub (see
  [P256CryptoStackAudit.md](P256CryptoStackAudit.md) §on the barrier), not subject to dead-store elimination.

Residual (non-secret, §5): the client's `expect_smac` (a public MAC *tag*) and two *unreachable* early-error
paths are not scrubbed — hygiene only, no secret exposed.

---

## 4. DSSO-used P-256 secret-scalar primitives — constant-time (cited)

The DSSO paths reach exactly the P-256 primitives whose CT is proven in
[P256CryptoStackAudit.md](P256CryptoStackAudit.md); this review confirms reachability + adds the DSSO-specific
observation for each. Direct-read spot-checks: `p256.c:264-276` (ladder), `p256.c:482-503` (scalar inverse).

- **Ladder** `pt_scalar_mul` (:264): per bit `pt_add(acc,acc,acc)` (double) + `pt_add(&tmp,acc,base)` +
  `pt_cswap(acc,&tmp,b)` where the secret bit `b` feeds ONLY the branchless `fe_cswap` mask (:140-144). No
  `if(bit)`, no zero-limb / identity fast path. `pt_add` is RCB algorithm-4 (a=−3), exception-free for
  `P+Q / P+P / P+O / P+(−P)` — a secret scalar cannot steer it into a variable-time case. Ladder scratch
  `tmp` scrubbed (:275); callers scrub the result.
- **Scalar inverse (OPRF `r⁻¹`)** `determ_p256_scalar_inv_mod_n` (:482) — **verified by direct read**:
  `e = N_BE; e[31] -= 2` (exponent `n−2`, a public compile-time constant), a fixed 256-bit loop with an
  unconditional `sc_mont_mul(acc,acc,acc)` square and a `if ((e[i]>>bit)&1) sc_mont_mul(acc,acc,am)` multiply
  gated on the **public exponent bit**. This is **Fermat, not binary-GCD/Euclid** — the #1 OPRF timing-leak
  class is absent. `am`/`acc`/`t` scrubbed (:500-501). The field inverse `fe_inv` (:179) is the same Fermat
  pattern (`a^(p-2)`).
- **`hash_to_scalar`** (:783): RFC 9380 `expand_message_xmd` → 48-byte uniform → wide reduction (one branchless
  conditional-subtract). No rejection loop whose count depends on a secret. `oprf_derive_key`'s counter loop
  (:959) re-draws only on an exactly-zero candidate (≈2⁻²⁵⁶) and is an offline key-gen op, not an online
  ceremony.
- **`be_lt` / `scalar_ok`** (:287): full-length borrow chain, no early return (CT-5); the `&&` in `scalar_ok`
  short-circuits only on `s==0` (a public reject, ≈2⁻²⁵⁶ for a real secret).
- **`msm_ct`** (:807): no zero-scalar skip (CT-6). **SSWU** hash-to-curve (:704): all selection via `fe_cmov`
  masks + public fixed exponents — no branch on the (possibly secret) input `u`.
- **VOPRF** `voprf_prove` (:1114): `s = r − c·k` via branchless mod-n Montgomery mul + `sc_sub_raw`; secret
  scratch (`km`, `ck`, `rfe`, `sfe`, point `T`) scrubbed; `voprf_verify` uses `determ_ct_memcmp` (:1186).

---

## 5. G6 worklist — secret-lifetime (zeroization) gaps, NOT CT violations

None of these affect timing; each is a secret buffer left on the stack, exploitable only via a *secondary*
memory-disclosure. Listed most-actionable first.

**STATUS: G6 APPLIED — all seven items shipped in commit `cab12b2` (owner "full pass", 2026-07-26).** Every
fix is a `determ_secure_zero` insertion on a path *after* the outputs are written (or an error/unreachable
path), so the change is byte-neutral: the dual-oracle KATs stay byte-identical on both platforms
(MSVC FAST + WSL2/GCC `ci_local`; `test-p256-oprf-c99` / `test-p256-{balance,confidential-tx}-c99` /
`test-p256-ctx-bundle` / `test-dsso-{opaque3dh,threshold-oprf,login-e2e}` all PASS). With G5 (this review) +
G6 (`cab12b2`) both closed, the DSSO CT/zeroization ship-gate for the D.5 packaging tail is MET.

| id | location | secret residue | sev | fix (byte-neutral) |
|---|---|---|---|---|
| G6-1 | `determ_p256_scalar_mul_mod_n` p256.c:468-480 | `am`,`bm`,`rm`,`t` — the threshold-OPRF `λ·share` product (and Bulletproofs witness) | med | `determ_secure_zero(am/bm/rm/t)` before `return 0`, matching the sibling `scalar_inv_mod_n` (:500-501) |
| G6-2 | `determ_p256_scalar_add_mod_n` p256.c:516-526 | `af`,`bf`,`rf` — the secret Lagrange partial sum / reconstructed secret | med | `determ_secure_zero(af/bf/rf)` before `return 0` |
| G6-3 | `determ_p256_scalar_sub_mod_n` p256.c:530-540 | `af`,`bf`,`rf` — documented use is the **public** denominator `x_j−x_i`, so CLEAN now | low | scrub for uniform discipline (safe if ever reused with secret operands) |
| G6-4 | `opaque3dh.c:243` client `expect_smac` | the expected server-MAC **tag** (equals the wire-public `server_mac`; `Km2` itself is scrubbed) | low | scrub before both returns for uniform hygiene; no secret exposed if omitted |
| G6-5 | `opaque3dh.c:186/237` key_schedule-fail branch | `Km2`/`Km3` on an **UNREACHABLE** failure path (labels are constant; the caps can't trip) | info | scrub `Km2`/`Km3` on the failure return (or inside `key_schedule` on rc≠0) for defence-in-depth |
| G6-6 | `oprf_finalize` p256.c:1039 store-fail `goto` | the unblinded point `r` on an **UNREACHABLE** store-failure path | info | add `determ_secure_zero(&r)` to the `cleanup` label |
| G6-7 | `hash_to_curve`/`sswu_map` p256.c:704/841 | `u0`/`u1` field elements + SSWU scratch derived from the (possibly secret) OPRF input | info | scrub the field intermediates, or document as low-value input-derived (preimage-resistant) |

**Consistency note:** G6-1/G6-2 are the load-bearing pair — the sibling `scalar_inv_mod_n` **does** scrub its
equivalents (citing the P-256 audit §3.3 Info), so these are inconsistencies with the module's own discipline,
not intentional exemptions.

---

## 6. Non-claim & cross-references

This establishes that the DSSO secret-scalar paths carry **no constant-time violation** and identifies the
zeroization hygiene follow-ups (G6); it is not a claim that any specific side-channel has been *exploited*,
nor a substitute for the empirical timing gate ([TimingProbeCTPQCoverage.md](TimingProbeCTPQCoverage.md)). The
per-primitive P-256 CT proofs live in [P256CryptoStackAudit.md](P256CryptoStackAudit.md) §3 and
[ConstantTimeInventory.md](ConstantTimeInventory.md); the DSSO protocol soundness in
[DssoThresholdOprfSoundness.md](DssoThresholdOprfSoundness.md), [OprfConformanceMap.md](OprfConformanceMap.md),
and [DssoAssertionFreshness.md](DssoAssertionFreshness.md); the DSSO spec in
[v2.25-DSSO-DAPP-SPEC.md](v2.25-DSSO-DAPP-SPEC.md).
