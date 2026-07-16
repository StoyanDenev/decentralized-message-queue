> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# §3.12 D2 — Timing-Probe CT/PQ Coverage: the integrated confidential-tx + post-quantum paths

**Status:** IMPLEMENTED (probe tranche 5, `src/main.cpp` `ct-timing-probe`
target table). D2 registers two new fix-vs-random targets on the INTEGRATED
confidential-tx (CT) proof-generation path — `p256-balance-prove`
(`src/main.cpp:13594`) and `rangeproof-prove` (`src/main.cpp:13604`) — one
level up from the tranche-3 P-256 primitives (`p256-base-mul` etc.). The
post-quantum (PQ) ML-DSA path is DELIBERATELY excluded from the fix-vs-random
target set (`src/main.cpp:13607-13617`); this document is the coverage
rationale for that split. It does NOT restate the probe engine — see
[TimingProbeDesign.md](TimingProbeDesign.md) §2 (method), §3 (architecture +
interpretation bands), §5 (statistical soundness). This is an engineering
coverage argument, not a security theorem.

**Subject:** why the two integrated-CT prove-functions are clean fix-vs-random
leak detectors while ML-DSA.Sign/Keygen are not — and why the PQ exclusion is
the correct call, an assurance routed through audit + KAT byte-identity rather
than a gap.

---

## 1. What D2 adds: two integrated-CT proof-generation targets

The tranche-1..4 targets probe cryptographic PRIMITIVES with a designated
secret (`p256-base-mul` secret = scalar, `ed25519-sign` secret = seed, etc.).
D2 goes one level up, to the two integrated confidential-tx PROVERS, and probes
the secret that a confidential transaction actually hides
(`src/main.cpp:13588-13606`):

| Target id | Prove-function | Secret under test | What that secret touches |
|---|---|---|---|
| `p256-balance-prove` | `determ_p256_balance_prove` (balance.h:44) | the blinding excess `x` | the `c·x mod n` multiply + `k + …` add ONLY |
| `rangeproof-prove` | `determ_rangeproof_prove` (rangeproof.h:46) | the amount `v` | `v·g` + the n-bit `l`/`r` decomposition |

### 1.1 `p256-balance-prove` — secret = the blinding excess `x`

The balance PoK proves knowledge of `x` such that `E = x·H`, via a Schnorr
proof of discrete log base `H`: `T = k·H ; c = hash_to_scalar(E ‖ T) ;
s = k + c·x mod n` (balance.h:40-43). The secret under test is the blinding
excess `x`. The probe holds the decodable point `E`, the nonce `k`, and all
public inputs FIXED across both classes and varies ONLY `x`
(`src/main.cpp:13715-13727` sets up a fixed `bal_E` = compress(3G), a fixed
nonzero `bal_k`, and a fixed `bal_x_fix`; `src/main.cpp:13824-13827` swaps in a
full-range rejection-sampled random `x` for the RND class). Because `k` is held
constant, the `T = k·H` point multiplication is byte-identical in both classes;
the ONLY class-dependent arithmetic is `s = k + c·x mod n` — a mod-n
multiply-add. **`x` never enters a point multiplication in `prove`** (the sole
point-mult, `k·H`, rides the secret NONCE `k`, which is pinned). A fix-vs-random
timing difference is therefore attributable to the mod-n `c·x` path.

### 1.2 `rangeproof-prove` — secret = the amount `v`

The range proof proves a Pedersen-committed `v ∈ [0, 2^n)` without revealing
`v` (rangeproof.h:1-14). The secret under test is the amount `v`. `v` enters
the prover via the value commitment `V = v·g + gamma·h` and via the n-bit
decomposition of `v` into the `l`/`r` polynomial vectors that drive the
Bulletproofs + inner-product argument — the surface that must not leak the
hidden value's magnitude through timing. The probe fixes ALL prover randomness
(`gamma`, `alpha`, `rho`, `tau1`, `tau2`, `sL`, `sR`) at `n = 32`
(`src/main.cpp:13728-13746`) and varies ONLY `v` between classes
(`src/main.cpp:13828-13832`: `rp_v_fix = 0x00c0ffee` for FIX vs a random
`[0, 2^32)` amount for RND). Every non-`v` input to `determ_rangeproof_prove`
is byte-identical across classes, so a between-class timing difference is
attributable to `v`.

### 1.3 Why these are CLEAN fix-vs-random detectors

Both prove-functions are **DETERMINISTIC in their inputs** — no rejection loop,
no data-dependent iteration count (balance.h:43 "Deterministic"; rangeproof.h:45
"Deterministic in (v, gamma, alpha, rho, tau1, tau2, sL, sR)"). A deterministic
function's total operation time is a function of its inputs alone; with every
input but the secret pinned byte-identical, any surviving between-class timing
difference is caused by the secret and nothing else. That is exactly the
condition under which the dudect fix-vs-random contrast (TimingProbeDesign §2)
is a sound leak detector: the confound that would otherwise dominate — a
data-dependent loop count — is absent by construction. (Contrast the PQ path,
§2, where it is present by construction.)

These two are the integrated-path analogue of the tranche-4.5 primitive target
`p256-msm-zeroskip` (`src/main.cpp:13585`), which empirically backed the
2026-07-06 zero-scalar-skip removal in the CT MSM (ConstantTimeInventory §2.10):
where `p256-msm-zeroskip` isolates ONE mechanism (the removed zero-term skip),
`p256-balance-prove` and `rangeproof-prove` exercise the full prover the CT MSM
sits inside, at the secret the transaction hides.

---

## 2. The PQ path is deliberately NOT a fix-vs-random target — and why that is correct

ML-DSA.Sign and .Keygen are **rejection-sampled**: ML-DSA.Sign is
Fiat-Shamir-WITH-ABORTS (sign.h:1-2), a top-level loop
`for (it = 0; it < SIGN_MAX_ITERS; it++)` (`src/crypto/mldsa/sign.c:130`) that
regenerates the candidate and restarts on any of the `chknorm` norm-bound
rejections (`src/crypto/mldsa/sign.c:159`, `160`, `164`); Keygen rejection-samples
`s1`/`s2` (rej_eta) the same way. The **iteration count is
secret-and-message-dependent by construction** — a documented FIPS 204 /
Dilithium property (MLDSAConformance.md NP-1: the Fiat-Shamir-with-aborts loop
"iterates a **secret-and-message-dependent** number of times — the canonical
ML-DSA behaviour. The number of rejections is observable through timing").

Consequences for a hypothetical `mldsa-sign` fix-vs-random target:

- The FIX class (one pinned `sk`, one pinned `M'`) sits at a single, fixed
  rejection count. The RND class (fresh random `sk` each measurement) averages
  over the geometric-ish distribution of rejection counts. The two classes
  therefore differ in MEAN total time for a reason that is **benign and public**
  — the reject count — not because of a key-dependent leak in the arithmetic.
- A Welch-t on that contrast would be **dominated by the rejection-count
  variance** and would grow a large |t| with `n` (TimingProbeDesign §5.3: a real
  between-class mean difference drives |t| ≈ δ·√(n/2)). But that large |t| would
  be MEANINGLESS as a leak signal: it measures the number of aborts, which is
  already a known, documented, non-exploitable timing observable — not an
  extraction channel on the signing key. The probe's interpretation bands
  (TimingProbeDesign §3.4) assume the null is "no secret-dependent difference";
  ML-DSA violates that null benignly, so the tool's output would be a false
  positive by construction, not a finding.

**The genuine PQ constant-time property is the PER-ITERATION arithmetic**, and
it is real: the inc.1 CT-hardening pass made the norm-bound machinery branchless
so that a REJECTED candidate leaks neither which coefficient nor how many
exceeded the bound — only the public per-iteration reject count survives.
`center()` (sign.c:39-44) is branchless — `a >> 31` masks, not branches — and
runs on the secret `z` during rejected rounds; `chknorm()` (sign.c:54-64) scans
ALL coefficients with no early return, accumulating the violation into `bad`
with a branchless `|t|` and sign-bit fold, and both are byte-identical to the
early-return form (ACVP sigGen KATs unchanged, sign.c:38, 53).

The assurance for THAT per-iteration property does not come from this probe. It
comes from **AUDIT + the ACVP KAT byte-identity**:

- **Audit:** the branchless-by-construction argument above, plus
  MLDSAConformance.md NP-1 (the NTT/reduction/packing control flow is on public
  indices only). NP-1 is also explicit that a full secret-path timing audit has
  NOT been performed and remains owner-gated before production signing — this
  document does not overstate the property.
- **KAT byte-identity:** the CT-hardened `center`/`chknorm` produce
  byte-for-byte the same signatures as the pre-hardening form, pinned against
  the NIST ACVP sigGen vectors (MLDSAConformance.md MC-2). Byte-identity is what
  lets the CT rewrite ride in without a functional regression.

This is **exactly the treatment the 3072-bit ff modexp already gets**: it is
NOT probed either — a single modexp op is tens-to-hundreds of ms, so the probe's
fixed 20000-sample calibration (`src/main.cpp:13880`) is impractical — and its
CT rests on audit + byte-identity rather than a timing run (the probe's own
exclusion comment, `src/main.cpp:13582-13584`, citing the audit +
byte-output-invariance assurance pattern that ConstantTimeInventory §2.10
establishes for the neighbouring pedersen CT MSM: "Byte-output-invariant (all 35
P-256 corpus vectors byte-equal) + independently audited"). The PQ exclusion is
the same category of decision, made for the same reason: a fix-vs-random Welch-t
is the wrong instrument for a rejection-sampled routine, so the assurance is
carried by audit + byte-identity instead. This is a routing decision, not an
un-probed gap.

---

## 3. Running and reading the two new targets

```
determ ct-timing-probe p256-balance-prove [--samples N] [--seconds S] [--csv F] [--json]
determ ct-timing-probe rangeproof-prove   [--seconds S | --samples N] ...
```

- `p256-balance-prove` is light (one Schnorr PoK per sample; batch 1). The
  default `--samples 200000` (`src/main.cpp:13634`) plus the fixed 20000-sample
  calibration (`src/main.cpp:13880`) runs in reasonable time.
- `rangeproof-prove` is **heavy** — a full `n = 32` Bulletproofs + inner-product
  argument per sample (batch 1). Use `--seconds S` or a small `--samples N` for
  a quick read (`src/main.cpp:13604-13606` register comment). The 20000-sample
  calibration alone is a real cost here; size the budget accordingly.

Interpretation bands are the shared §3.4 policy (`src/main.cpp:13926-13930`),
NOT redefined here:

| max \|t\| | Reading |
|---|---|
| ≤ 4.5 | no evidence of leakage at this sample size on this machine |
| 4.5 – 10 | quiet the host, double `--samples`, re-run — persistent/growing ⇒ leak |
| > 10 or growing with `n` | strong evidence of a secret-dependent difference — file a finding |

**Explicit non-claim:** `|t| ≤ 4.5` is NOT a constant-time proof. It is absence
of evidence at the measured sample size, on this machine, this compiler, these
flags, for this input-class design — never a guarantee
([TimingProbeDesign.md](TimingProbeDesign.md) §5.4, echoed at
`src/main.cpp:13930`). The probe complements the source-level audit
(ConstantTimeInventory §2.10 for the pedersen prover surface); it does not
replace it.

---

## 4. Coverage table

Every confidential-tx / PQ secret path, mapped to its probe target OR its
audit-anchor, with the honest status of each:

| Path | Secret | Assurance | Anchor | Status |
|---|---|---|---|---|
| Balance PoK — `determ_p256_balance_prove` | blinding excess `x` (→ `c·x mod n`) | fix-vs-random probe (deterministic prover) | `p256-balance-prove`, `src/main.cpp:13594` | Probe target LIVE; deterministic ⇒ clean detector |
| Range proof — `determ_rangeproof_prove` | amount `v` (→ `v·g` + n-bit `l`/`r`) | fix-vs-random probe (deterministic prover) | `rangeproof-prove`, `src/main.cpp:13604` | Probe target LIVE; heavy, budget with `--seconds` |
| CT MSM zero-scalar handling | which secret scalar is zero | fix-vs-random probe (one mechanism) | `p256-msm-zeroskip`, `src/main.cpp:13585`; ConstantTimeInventory §2.10 | Probe target LIVE; skip removed 2026-07-06, audited 6/6 SOUND |
| CT MSM / commit / P-256 scalar ops | value/blinding scalars | source audit + byte-output-invariance | ConstantTimeInventory §2.10 (35 P-256 vectors byte-equal) | Audited CT for honest inputs; `be_lt`/`sc_mont_mul` residuals per §4.1 |
| ML-DSA.Sign per-iteration arithmetic | `sk` coefficients (`z`/`r0`/`ct0` norms) | AUDIT + ACVP KAT byte-identity — NOT probed | sign.c:39-64 (`center`/`chknorm`); MLDSAConformance MC-2, NP-1 | Branchless by construction; full secret-path timing audit owner-gated (NP-1) |
| ML-DSA.Sign/Keygen total time | reject count (public observable) | not applicable — benign by construction | FIPS 204; sign.c:130,160; MLDSAConformance NP-1 | Deliberately NOT a fix-vs-random target (§2) |
| 3072-bit ff (Z_p*) modexp | secret exponent | audit + byte-identity — NOT probed (op too slow to calibrate) | probe exclusion comment `src/main.cpp:13582-13584` | Same routing as PQ: audit + byte-identity, not timing |

---

## 5. Status

- **`p256-balance-prove`, `rangeproof-prove`** — registered and runnable
  (`src/main.cpp:13594`, `:13604`). Both are clean fix-vs-random detectors
  because both provers are deterministic (§1.3). Per TimingProbeDesign §3.1 they
  are REPORTING targets, not pass/fail gates — out of `run_all.sh`, exit code
  never encodes a leak verdict.
- **`rangeproof-prove` cost** — heavy (`n = 32` Bulletproofs + IPA per sample);
  the 20000-sample calibration is a real cost. Budget with `--seconds` or a
  small `--samples`.
- **PQ path** — no fix-vs-random target, by design and correctly so (§2). Its
  per-iteration CT rests on the inc.1 branchless `center`/`chknorm` (audit) +
  ACVP KAT byte-identity (MLDSAConformance MC-2); a full secret-path timing
  audit is a SEPARATE, owner-gated step (MLDSAConformance NP-1), and ML-DSA has
  no in-tree consensus consumer today (NP-2).
- **Honest scope of any `≤ 4.5` result** — evidence, not proof; bounded by the
  §5.3 detectability floor for the `n` actually run, this machine, this build,
  these input classes (TimingProbeDesign §5.4). The `pedersen` module is claimed
  constant-time for a prover's own honest inputs only; the P256-CT-1 `be_lt`
  range-gate and the §4.1.5 multiply-latency residual still apply
  (ConstantTimeInventory §2.10, §4.1).

---

## 6. Cross-references

- [TimingProbeDesign.md](TimingProbeDesign.md) — the probe engine and policy
  this document extends: §2 (fix-vs-random method), §3.2/§3.3 (CLI + per-target
  generators), §3.4 (interpretation bands), §5.3 (sample floor), §5.4 (the
  negative-claim caveat). D2 adds targets, not machinery.
- [ConstantTimeInventory.md](ConstantTimeInventory.md) — §2.10 (pedersen CT MSM:
  the audit + byte-output-invariance precedent, and the `p256-msm-zeroskip`
  probe mapping), §2.9 (P-256 secret-path residuals incl. P256-CT-1 `be_lt`),
  §4.1 (the multiply-latency assumption).
- [MLDSAConformance.md](MLDSAConformance.md) — MC-2 (ACVP sigGen KAT
  byte-identity), NP-1 (rejection-loop timing dependence + no CT audit yet),
  NP-2 (no in-tree consumer).
- `include/determ/crypto/pedersen/balance.h` — `determ_p256_balance_prove`
  (`s = k + c·x mod n`; deterministic).
- `include/determ/crypto/pedersen/rangeproof.h` — `determ_rangeproof_prove`
  (`v` via `v·g` + n-bit `l`/`r`; deterministic).
- `include/determ/crypto/mldsa/sign.h` + `src/crypto/mldsa/sign.c` — Sign =
  Fiat-Shamir with aborts (data-dependent reject count); the inc.1 branchless
  `center` (sign.c:39) / `chknorm` (sign.c:54).
- `src/main.cpp` — the `ct-timing-probe` target table: tranche-5 targets
  (`:13588-13606`), the ML-DSA exclusion comment (`:13607-13617`), the ff-modexp
  exclusion comment (`:13582-13584`), the interpretation-band print
  (`:13926-13930`).

*End of coverage rationale. The two D2 targets are additive reporting tools; the
PQ exclusion is a routing decision (audit + KAT byte-identity), and the
production-grade ML-DSA secret-path timing audit remains owner-gated per
MLDSAConformance NP-1.*
