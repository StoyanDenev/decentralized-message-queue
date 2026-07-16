> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# §3.12 Timing-Probe Design — constant-time verification framework

**Status:** IMPLEMENTED (first tranche, same session as the design). The
IN-HOUSE path of §1 shipped — `determ ct-timing-probe` (src/main.cpp
dispatch): the §2 engine in full (interleaved fix-vs-random classes, rdtsc
with lfence serialization + steady_clock fallback, the pinned
{no-crop, 99.9, 99, 95, 90, 75, 50} crop ladder with calibration-pass
thresholds, Welford cells, max-|t|-over-pairs-and-crops reporting with the
§3.4 banding) plus six §4 targets: ct-memcmp (4 mismatch-position classes),
chacha-tag-verify, gcm-tag-verify, ed25519-sign, x25519, and the
sha256-content negative control; tranche 2 (same session) added aes-core,
chacha20-core, poly1305-key, ed25519-pubkey, sc-canonical (the five
boundary-scalar classes {0, L−1, L, 2L−1, random} of §4 target 7), and
hmac-key; tranche 3 added the P-256 module: p256-base-mul, p256-h2c,
p256-sc-mul (generators upgraded post-R47 to full-range [1, n) secret
scalars with an n-prefix FIX class — the original scalar[0] &= 0x0f masking
would have blinded the probe to P256-CT-1-class short-circuit leaks) plus
the rest of the §3.2 CLI surface (`--seconds`, `--batch`, `--csv`,
`--json`); tranche 4 added x25519-base, sc-muladd, hmac-sha512,
blake2b-keyed, pbkdf2 (the three tranche-4 FROST targets — frost-reconstruct/
frost-dkg/frost-sign-partial — were REMOVED with FROST itself in the B2 purge,
so no FROST id remains in the registry); a demonstration target
p256-msm-zeroskip (the 2026-07-06 CT zero-scalar-skip removal); and tranche 5
(D2) the two INTEGRATED confidential-tx proof-generation targets
p256-balance-prove (secret = the blinding excess x) and rangeproof-prove
(secret = the hidden amount v) — 23 live targets total, closing the §4 id
list except the dedicated `ghash` id (a static internal to aes_gcm.c,
exercised indirectly via gcm-tag-verify/aes-core; exporting it for measurement
alone was rejected per KISS) and the ML-DSA PQ path (deliberately not a
fix-vs-random target — it is Fiat-Shamir-with-aborts, so total-sign timing is
data-dependent by construction; its per-iteration CT rests on audit + ACVP KAT
byte-identity, the ff-modexp treatment — see TimingProbeCTPQCoverage.md). `--selftest` (the §5.5 bit-exact
statistics fixture) is in the regular suite as
`tools/test_ct_timing_selftest.sh`; measurement mode stays out of run_all.sh
per §3.1. First measured runs on the dev host (MSVC -O2, rdtsc): max |t|
1.3–4.2 across all targets, no evidence of leakage at the smoke sample sizes —
with one live demonstration of the §3.4 banding procedure: sc-canonical's
first run hit max |t| = 4.96 (evidence band) on a single (pair, crop) cell,
and the prescribed double-the-samples re-run collapsed it to 0.43 (an
environmental fluke, not a leak — a true leak grows like √n; with 10 pairs ×
7 crops this is §5.2's multiple-testing caveat materializing on schedule).
§5.4's negative-claim caveats remain in force. Remaining: the other §4
targets register in the same table as they are added; §1's dudect/ctgrind
VENDORING question (the third-party-code path) still awaits Stoyan's
authorization and is unaffected by the in-house implementation.

**Subject:** the design of Determ's constant-time (CT) verification framework —
CRYPTO-C99-SPEC.md §3.12, which today reads in full:

> ### 3.12 Constant-time verification framework (~3-5 days)
>
> - Vendor dudect or ctgrind
> - Integrate into CI
> - Per-primitive constant-time test
> - Reports + documentation

**Purpose:** turn that four-bullet placeholder into an implementable design that
(a) respects the house external-dependency discipline (§1), (b) serves the
numbered harness-target list in [ConstantTimeInventory.md](ConstantTimeInventory.md)
§5 (quoted in §4 below), and (c) is statistically honest about what a timing
probe can and cannot prove (§5).

---

## 1. Decision + DEVIATION FLAG: no third-party harness code without authorization

**⚠ EXTERNAL-CODE FLAG.** CRYPTO-C99-SPEC §3.12's first bullet says "Vendor
dudect or ctgrind". Both are third-party code: vendoring either means external
source entering the repo. Per the house external-dependency discipline — the
precedent recorded in [FROST_DEVIATION_NOTICE.md](FROST_DEVIATION_NOTICE.md)
§4 ("AI-introduced design elements that become load-bearing in long-lived
artifacts must be flagged as such" + the operational rule: identify as
AI-suggested, cite the property addressed, compare against DLT-native
alternatives, **defer to Stoyan for accept/reject**) — this document explicitly
states:

**Vendoring dudect or ctgrind awaits Stoyan's authorization. It is NOT assumed.**

The §3.12 spec bullet predates the deviation-notice discipline; this design
re-files the vendoring question under it rather than treating the bullet as
standing authorization. Two notes scope the decision:

1. The stakes are lower than FROST's. A measurement harness is *tooling*, not
   a chain primitive: it never touches the consensus path, the wire format, or
   the immutable v1.1 surface, and could be removed at any time without a
   migration. The four-bar test of FROST_DEVIATION_NOTICE §3 applies to chain
   primitives; the discipline that applies here is the §4 generalization
   (flag + compare + defer), which this section discharges.
2. An in-house alternative is cheap, because dudect is small precisely
   *because the method is simple*. dudect's fix-vs-random leakage detection
   (Reparaz, Balasch, Verbauwhede — "dude, is my code constant time?", DATE
   2017) is fully reconstructible from the published method: **two input
   classes** (fixed secret vs fresh-random secret, all public parameters
   pinned identical), **high-resolution timing** of each invocation (`rdtsc`
   on x86-64 / `QueryPerformanceCounter` on Windows where `rdtsc` is
   unavailable), **Welch's t-test** comparing the two timing distributions,
   and the **|t| > 4.5 threshold** as the evidence-of-leakage criterion (the
   TVLA-convention threshold the dudect paper adopts).

**Decision: design the IN-HOUSE probe (this document), implementable from the
published method with zero external code.** If Stoyan authorizes vendoring
dudect proper, the in-house probe's target table (§4) and interpretation
policy (§3.4, §5) carry over unchanged — only the measurement engine is
swapped; nothing in this design is wasted either way. ctgrind-style taint
analysis is out of scope regardless (§7) — it requires valgrind, a Linux/WSL2
leg, and is a different verification dimension (branch/index discipline, not
wall time).

---

## 2. The published method, restated as the implementable spec

For each target function with a designated SECRET parameter:

1. **Two classes.** Class FIX: the secret parameter is a pinned constant
   (published per target in §4.2 so runs are reproducible). Class RND: the
   secret parameter is freshly drawn from the CSPRNG for every measurement.
   All PUBLIC parameters — lengths above all — are byte-identical across both
   classes (ConstantTimeInventory §5: "because lengths are public by contract,
   classes must never differ in length").
2. **Interleaved random class assignment.** Each measurement flips a CSPRNG
   coin to choose FIX or RND. Interleaving (rather than measuring one class
   then the other) decorrelates class membership from environmental drift —
   frequency scaling, thermal state, scheduler interference — which would
   otherwise manufacture a bogus between-class difference.
3. **High-resolution timing.** Time each single invocation:
   - x86-64 (MSVC `<intrin.h>` / GCC-Clang): `__rdtsc()` with a serializing
     fence on each side (`_mm_lfence()` or `__cpuid`) so out-of-order
     execution cannot move the timed region across the timestamp reads.
   - Windows non-x86 fallback: `QueryPerformanceCounter`.
   - POSIX fallback: `clock_gettime(CLOCK_MONOTONIC)`.
   When the timer's granularity is coarse relative to the target (e.g.
   `determ_ct_memcmp` over 16 bytes is a handful of nanoseconds; QPC
   granularity is typically ~100 ns), the probe times a fixed batch of k
   identical invocations per sample. Batching is a fallback, not the default:
   it averages away short-lived effects, so prefer the cycle counter wherever
   available and record which timer + k each report used.
4. **Percentile cropping** (the dudect approach to tail noise). Timing
   distributions are heavily right-skewed: interrupts, page faults, and
   scheduler preemption produce a long tail that inflates variance and drowns
   small leaks. After a calibration pass, the probe derives crop thresholds at
   a fixed percentile ladder of the pooled distribution — this design pins
   {no-crop, 99.9, 99, 95, 90, 75, 50} — and maintains a separate t-test per
   crop level, each fed only the measurements below its threshold. The
   reported statistic is the **max |t| across crop levels** (a leak visible
   only in the cropped body of the distribution is still a leak).
5. **Incremental t-statistics.** Each (class, crop-level) cell keeps Welford
   running moments — `n`, mean `m`, sum of squared deviations `M2`, updated
   per sample in O(1) — so the probe runs for an arbitrary sample budget in
   constant memory and can print interim t-values while measuring.
   Welch's t between cells a and b:

   ```
   t = (m_a − m_b) / sqrt( s²_a/n_a + s²_b/n_b ),   s² = M2/(n−1)
   ```

6. **Threshold.** |t| > 4.5 on any cell pair = statistical evidence of a
   secret-dependent timing difference. |t| ≤ 4.5 = no evidence *at this sample
   size on this machine* — see §5.4 for exactly how little that proves.

---

## 3. Probe architecture: `determ ct-timing-probe <target>`

### 3.1 A REPORTING tool, deliberately NOT a pass/fail regression test

The probe is a new `determ` subcommand in the existing `src/main.cpp` dispatch
family (sibling of `test-ct-c99`), but with one deliberate break from that
family: **its exit code never encodes a leak verdict.** Exit 0 = measurement
completed (report printed); nonzero = usage or infrastructure error only.

Why it stays out of `run_all.sh` / FAST:

- **Timing verdicts are environmentally flaky.** The t-statistic depends on
  the machine, its load, frequency scaling, virtualization, and the sample
  budget. The same binary can report |t| = 3 on one run and |t| = 6 on the
  next on a noisy host. A CI gate on that is a coin-flip gate.
- **The house suite demands deterministic verdicts.** `tools/run_all.sh`
  auto-discovers every `tools/test_*.sh` and judges each from its single
  terminal `  PASS:` / `  FAIL:` marker (the FAIL-first marker discipline,
  enforced by `test_cluster_output_discipline.sh`). A probabilistic test
  poisons that contract: either it flakes red (and gets deleted or ignored —
  a guard that cries wolf protects nothing, per the `test_docs_link_check.sh`
  design note) or its threshold gets loosened until it can never fire.
- **Consequence for naming:** the operator wrapper, when implemented, must be
  `tools/operator_ct_timing_probe.sh` (the `operator_*.sh` reporting family),
  **never** `tools/test_ct_timing_probe.sh` — the `test_` prefix alone would
  pull it into `run_all.sh` auto-discovery.

The one deterministic piece that DOES belong in the regular suite is the
statistics engine itself: `determ ct-timing-probe --selftest` recomputes the
pinned Welch/Welford vector of §5.5 (pure arithmetic, no timing), and that
self-test can be folded into the `test-ct-c99` wrapper as an ordinary
deterministic assertion.

### 3.2 CLI shape

```
determ ct-timing-probe --list
determ ct-timing-probe <target> [--samples N] [--seconds S] [--timer rdtsc|qpc|monotonic]
                                [--batch k] [--csv FILE] [--json]
determ ct-timing-probe --selftest
```

- `--list` — enumerate the §4 target ids with their entry points and classes.
- `<target>` — one of the §4 ids (e.g. `ct-memcmp`, `aes-core`, `ed25519-sign`).
- `--samples` / `--seconds` — sample budget (whichever bound hits first;
  defaults sized per §5.3).
- `--csv` / `--json` — machine-readable per-cell dump (class pair, crop level,
  n per class, means, |t|) for archiving alongside the per-target build
  recipe (§6).

### 3.3 Per-target input generators

Each §4 target registers: (a) the secret parameter(s) under test, (b) the
pinned FIX-class value, (c) the RND-class generator, (d) the pinned public
parameters (lengths, messages, nonces), and (e) a per-iteration setup that is
EXCLUDED from the timed region (e.g. drawing the RND secret, message
buffers). Only the target function call sits between the timestamp reads.
Targets with multi-class designs beyond plain fix-vs-random (e.g. target 1's
four mismatch-position classes, target 7's five boundary scalars) register all
classes; the probe then reports max |t| over all class pairs at each crop
level.

### 3.4 How operators read the report

| max \|t\| (any cell pair, any crop) | Interpretation | Action |
|---|---|---|
| ≤ 4.5 | No evidence of leakage at this sample size, on this machine, for this build | Archive the report (CSV + build recipe); re-run on compiler/flag bumps per §6 |
| 4.5 – 10 | Evidence; could still be environmental on a noisy host | Quiet the machine (pin affinity, disable turbo if possible), double the sample budget, re-run; persistent or growing → treat as leak |
| > 10, or growing monotonically with n | Strong evidence of a secret-dependent timing difference | File a finding against the §4 target's named mechanism (each target maps to one — that is the inventory's localization property); fix before ship |

The 4.5/10 banding is house policy for triage, not part of the published
method: 4.5 is the published evidence threshold; the 10 band exists because a
true leak's |t| grows like √n (§5.3) while environmental flukes do not
reproduce — "re-run bigger and watch the trend" separates them.

---

## 4. Targets — the ConstantTimeInventory §5 list this probe serves

### 4.1 The normative list, quoted

[ConstantTimeInventory.md](ConstantTimeInventory.md) §5 ("What §3.12 must
measure") is normative for target selection; this design adds the measurement
machinery, not the target set. Quoted verbatim (pinned at the 2026-06-11
revision; the inventory wins on any future divergence):

> 1. **`determ_ct_memcmp`** — the keystone: fixed length (16/32/64), classes
>    {equal, differ-at-byte-0, differ-at-last-byte, differ-everywhere}; timing
>    must be indistinguishable across ALL four (position AND count invariance).
>    This converts `test_ct_c99.sh`'s functional pins into the timing claim.
> 2. **AES core** — `determ_aes256_encrypt_block` with fix-vs-random keys (fixed
>    plaintext) and fix-vs-random plaintext (fixed key); `determ_aes256_init`
>    fix-vs-random key. ctgrind: no taint reaches a branch/index — this is the
>    no-table S-box claim (`aes_sbox_ct`/`gf_mul`/`gf_inv`) under measurement.
> 3. **GHASH** — `ghash_mul` with fix-vs-random `H` and fix-vs-random `X`
>    (bit-pattern classes: all-zeros vs all-ones vs random, since the bit-serial
>    loop's masks are per-bit).
> 4. **AEAD decrypt rejection timing** — `determ_aes256_gcm_decrypt` AND
>    `determ_chacha20_poly1305_decrypt` with classes {valid tag, tag wrong in
>    byte 0, tag wrong in byte 15, tag fully wrong} at fixed lengths: rejection
>    time must be independent of the matching-prefix length (C1/C2 measured
>    end-to-end through the AEAD, not just the bare compare).
> 5. **ChaCha20/Poly1305 cores** — `chacha20_block` (via `determ_chacha20`,
>    fixed-length message) fix-vs-random key; `determ_poly1305` fix-vs-random
>    (r,s) key at fixed message length, plus message classes that force the final
>    conditional-subtraction mask both ways (h < p vs h ≥ p) to confirm the C5
>    masked select is time-invariant.
> 6. **Ed25519 secret path** — `determ_ed25519_pubkey_from_seed` and
>    `determ_ed25519_sign` (fixed message) with fix-vs-random seeds: covers the
>    cswap ladder (`scalarmult`/`sel25519`), `car25519`, `modL`, and the S
>    accumulation in one measurement. Scalar bit-pattern classes (low-Hamming vs
>    high-Hamming weight) specifically attack the ladder claim.
> 7. **`sc_lt_L` / `determ_ed25519_sc_is_canonical`** — classes {s = 0, s = L−1,
>    s = L, s = 2L−1, random}: the borrow chain must not vary with where the
>    first differing byte sits.
> 8. **X25519** — `determ_x25519` fix-vs-random scalar at a fixed public point
>    (and at the base point via `determ_x25519_base`); same Hamming-weight classes
>    as target 6. The low-order rejection branch fires only on attacker-chosen
>    public points, so exclude low-order points from the secret-class runs.
> 9. **FROST secret-bearing entry points** — `determ_frost_sign_partial`
>    (fix-vs-random share/d/e at fixed public xs/D/E/msg),
>    `determ_frost_dkg_share`/`frost_poly_eval` and `determ_frost_dkg_commit`
>    (fix-vs-random polynomial), `determ_frost_reconstruct` (fix-vs-random
>    shares at fixed xs). Verifies the "all secrets ride the §2.6 layer" claim
>    end-to-end; `determ_ed25519_sc_muladd` is the shared microbench target.
> 10. **Argon2id scoped check** — NOT whole-function dudect (data-dependent by
>     design, §4.1.2). Instead: ctgrind/memory-trace assertion that for
>     `pass == 0 && slice < 2` the sequence of `ref_index` values is identical
>     across two different passwords with identical (salt, costs) — the RFC 9106
>     §3.4 hybrid claim, measured rather than argued.
> 11. **Per-target re-validation** — re-run targets 2–9 on each non-x86-64
>     deployment architecture (ARM64 now; any 32-bit/embedded NH1 target later)
>     to discharge the §4.1.5 multiply-latency assumption; document per-target
>     results alongside the build recipes.
> 12. **Keyed-hash length-only dependence** — HMAC-SHA-256/512 fix-vs-random key
>     at fixed keylen/msglen, BLAKE2b keyed-mode fix-vs-random key, PBKDF2
>     fix-vs-random password at fixed pwlen: confirms §2.1/§2.2's "branches key
>     on lengths only" for the keyed consumers (the unkeyed hashes need no run —
>     no secret input exists).

(FROST scope note for target 9: per FROST_DEVIATION_NOTICE.md, FROST is
library-only, outside the v1.1 chain consensus path; its targets are probed
because the code ships in the stack, exactly the posture the inventory's §2.8
header takes.)

### 4.2 What the timing probe covers, and what it cannot

| Inventory target | Probe target id | Covered by THIS design? |
|---|---|---|
| 1 `determ_ct_memcmp` | `ct-memcmp` | Yes — 4 classes × lengths {16, 32, 64}; FIX classes are the mismatch patterns, derived from a pinned base vector |
| 2 AES core | `aes-core`, `aes-init` | Yes — timing leg. The "ctgrind: no taint reaches a branch/index" half is §7 out-of-scope |
| 3 GHASH | `ghash` | Yes — fix-vs-random H, plus X bit-pattern classes {all-zeros, all-ones, random} |
| 4 AEAD rejection | `aead-gcm-reject`, `aead-chacha-reject` | Yes — 4 tag classes, fixed lengths, decrypt timed end-to-end |
| 5 ChaCha/Poly cores | `chacha-block`, `poly1305` | Yes — incl. the h<p vs h≥p mask-forcing message classes |
| 6 Ed25519 secret path | `ed25519-pubkey`, `ed25519-sign` | Yes — fix-vs-random seed + low/high-Hamming scalar classes |
| 7 `sc_lt_L` | `sc-canonical` | Yes — the 5 boundary classes {0, L−1, L, 2L−1, random} |
| 8 X25519 | `x25519`, `x25519-base` | Yes — low-order public points excluded from secret-class runs per the inventory |
| 9 FROST entry points | `frost-sign-partial`, `frost-dkg`, `frost-reconstruct`, `sc-muladd` | Was yes (library-only scope note above); the FROST module was removed from the tree 2026-07-09 (register B2), retiring the FROST probe targets |
| 10 Argon2id scoped check | — | **No.** Not a timing claim at all: it is an address-trace identity assertion. Implementable in-house WITHOUT valgrind as a deterministic instrumented-build test (record the `ref_index` sequence for two passwords, assert byte-identical for pass 0 / slice < 2) — that variant IS deterministic and belongs in the regular suite, as a separate follow-up, not in this probe |
| 11 Per-target re-validation | (policy) | Yes — a re-run policy over targets 2–9, not a new target; see §6 |
| 12 Keyed-hash length-only | `hmac-sha256`, `hmac-sha512`, `blake2b-keyed`, `pbkdf2` | Yes — fix-vs-random key/password at pinned lengths |

Pinned FIX-class secret values (so any two runs of the probe are comparing
the same fixed distribution): each target's FIX secret is the byte pattern
`0x42` repeated to the secret's length, except where a target's class design
prescribes structured values (target 1's mismatch patterns, target 7's
boundary scalars, targets 6/8's Hamming-weight classes: all-zero-bits-legal
minimum-weight vs all-ones-legal maximum-weight after clamping). The
implementation must record every pinned value in the `--json` report so a
report is self-describing.

---

## 5. Statistical soundness

### 5.1 Why Welch's t-test (not Student's)

Student's t assumes equal variances in the two populations. Timing
distributions routinely violate that: the RND class aggregates over many
secrets and so mixes any secret-dependent timing modes (wider variance),
while the FIX class sits in a single mode. Welch's t uses per-class variances
(`s²_a/n_a + s²_b/n_b` in the denominator) and is valid under unequal
variances and unequal sample sizes — and with interleaved coin-flip class
assignment, n_a ≈ n_b but never exactly equal, which Welch also absorbs.
Degrees of freedom follow Welch–Satterthwaite, but at the probe's sample
sizes (§5.3) the t distribution is indistinguishable from normal and df
hardly matters; the engine computes it anyway for the self-test (§5.5).

### 5.2 The multiple-testing caveat

One full sweep evaluates MANY t-statistics: 21 probe target ids (§4.2), each
with up to 10 class pairs (C(5,2) = 10 for the five-class target 7; six for
the four-class targets 1/4) and 7 crop levels — order 10² to low-10³ tests
per sweep (≤ 21 × 10 × 7 = 1,470). Each test at threshold 4.5 has a two-sided
false-alarm probability of about 6.8 × 10⁻⁶ under the no-leak null (large-df
normal approximation; recomputed in-session: 2·P(Z > 4.5) = 6.795 × 10⁻⁶). By
the Bonferroni union bound, even 1,500 simultaneous tests give a family-wise
false-alarm rate ≤ 1,500 × 6.8 × 10⁻⁶ ≈ 1.0 × 10⁻² per sweep — the 4.5
threshold already absorbs this sweep's multiplicity. Two residual cautions:

- **Repeated sweeps multiply again.** A probe run weekly for years will
  eventually show a spurious 4.6 somewhere. That is exactly why §3.4's policy
  is "re-run bigger and watch the trend", not "one excursion = finding".
- The Bonferroni arithmetic assumes the null distribution is actually
  t/normal. Heavy correlation between measurements (e.g. periodic system
  noise) distorts it; interleaving (§2.2) and cropping (§2.4) are the
  mitigations, not a proof.

### 5.3 Minimum sample counts

For per-class sample size n (equal classes, pooled timing standard deviation
σ), the expected statistic for a true mean timing difference Δ = δ·σ is
|t| ≈ δ·√(n/2). Reaching the 4.5 threshold on a real leak of relative size δ
therefore needs roughly **n ≥ 2·(4.5/δ)² per class** (recomputed
in-session):

| Leak size δ (fraction of σ) | n per class to expect detection |
|---|---|
| 0.1 σ | ≥ 4,050 |
| 0.01 σ | ≥ 405,000 |
| 0.001 σ | ≥ 40,500,000 |

Design floor: default `--samples` is 10⁶ per target (≈ minutes for the fast
targets; the Ed25519/X25519/FROST ladders dominate wall time and may warrant
a lower per-target default with `--seconds` as the bound). Every report
prints n alongside |t| precisely because §5.4's negative claim is
meaningless without it.

### 5.4 What |t| ≤ 4.5 does and does NOT prove

It does NOT prove the function constant-time. It proves only: **at this
sample size (§5.3 row ⇒ the smallest leak it could plausibly have seen), on
this machine, this compiler, these flags, this input-class design, no timing
difference was detected.** Specifically out of reach:

- Leaks smaller than the §5.3 detectability floor for the n actually run.
- Leaks not excited by the chosen classes (a class design measures what it
  varies — e.g. fix-vs-random keys cannot expose a plaintext-dependent leak;
  that is why the inventory prescribes per-target class structure).
- Microarchitectural channels that do not move wall time on the measurement
  machine (port contention observed by a sibling hyperthread, cache-line
  granularity effects masked by the prefetcher, leaks only present on OTHER
  silicon — §6).
- Compiler outputs other than the one measured (§6).

Absence of evidence at measured sample size — never proof of constant time.
The probe complements, and does not replace, the source-level mechanism
audit (ConstantTimeInventory §2, C99CryptoStackAudit §4/§6–§8f); a formal
guarantee would need the §7 out-of-scope techniques.

### 5.5 Statistics-engine self-test (pinned vector, recomputed in-session 2026-06-11)

`--selftest` feeds both the batch formula and the Welford-incremental path
the integer-clean fixture:

```
class A samples: {10, 11, 12, 13, 14}      class B samples: {12, 13, 14, 15, 16}
mean_A = 12.0   s²_A = 2.5  (n_A = 5)      mean_B = 14.0   s²_B = 2.5  (n_B = 5)
Welch t  = (12.0 − 14.0) / sqrt(2.5/5 + 2.5/5) = −2.0   (exactly)
Welch–Satterthwaite df = (0.5+0.5)² / ((0.5)²/4 + (0.5)²/4) = 8.0   (exactly)
```

Both code paths must return t = −2.0 and df = 8.0 bit-exactly (all
intermediates are dyadic rationals — no rounding ambiguity). This is the one
deterministic assertion suitable for the regular suite (§3.1).

---

## 6. The object-code caveat: CT is a property of compiler output

Source-level discipline (every mechanism in ConstantTimeInventory §2) is an
argument about C; the timing behavior ships in the object code. A compiler is
free to turn a branchless mask-select into a conditional branch, or an
arithmetic S-box into a table, wherever the as-if rule permits. Consequences,
all already anticipated by the inventory:

1. **Probe per compiler/flags.** ConstantTimeInventory §5 (intro): "Measure
   the shipped optimizer output (`-O2 -fno-strict-aliasing` per spec Q6) — CT
   is an object-code property, so re-run per compiler/flag bump." Every probe
   report must therefore record compiler, version, target triple, and the
   exact flag set, and reports are invalidated by any change to those. (Spec
   Q6: "Compile with `-O2 -fno-strict-aliasing`".) Note the current Windows
   binary is MSVC-built — MSVC does not take `-fno-strict-aliasing`; the
   per-toolchain flag mapping is an implementation-time item to pin in the
   report format, and MSVC output must be probed in its own right, not
   assumed equivalent to GCC/Clang output.
2. **Per-architecture re-validation of the multiply assumption.**
   ConstantTimeInventory §4.1 item 5: "**64-bit multiply latency
   assumption** — `M`/`fmul` (gf[16] field), `poly1305_absorb`, `fBlaMka`,
   and `determ_ed25519_sc_muladd` multiply secret-valued limbs with the C `*`
   operator. On the mainstream targets (x86-64, ARM64) integer multiply is
   constant-latency; on some smaller cores (e.g. ARM Cortex-M0/M3 `MULS`,
   older PowerPC) it is operand-dependent." Inventory target 11 is the
   discharge mechanism: re-run probe targets 2–9 on each deployment
   architecture before relying on the assumption there, and archive the
   per-target reports alongside the build recipes. The probe's
   Hamming-weight classes (targets 6/8) and bit-pattern classes (target 3)
   are the ones that would catch an operand-dependent multiplier.
3. **Disassembly spot-check rider.** When a probe report accompanies a
   compiler bump, the implementation should pair it with a disassembly
   spot-check of the §2-named mechanisms (does `sel25519` still compile
   branchless? did the S-box gain a table?) — cheap, and it catches what an
   underpowered timing run cannot (§5.4).

---

## 7. Out of scope

1. **ctgrind-style taint analysis.** Mark secret buffers undefined
   (valgrind's client requests), let memcheck flag any branch or memory index
   that depends on them. Catches leak classes 1 and 2 of ConstantTimeInventory
   §1.1 structurally rather than statistically — valuable, and the natural
   discharge for the non-timing halves of targets 2 and 10 — but it requires
   valgrind, hence the Linux/WSL2 leg, and (if vendored as ctgrind proper)
   the same §1 authorization gate. Deferred to a separate design.
2. **Formal CT verification** (binary-level analyzers, verified-compilation
   approaches, constant-time-preserving compilers). The only route to a
   *proof* rather than §5.4's bounded negative; far beyond §3.12's scope.
3. **Non-timing side channels** — power, EM, fault injection. Out of scope
   for the software stack's verification framework entirely.
4. **CI integration** (the spec's second bullet). Explicitly NOT designed
   here, by §3.1's argument: a t-threshold gate in CI is a flaky gate. What
   CAN go to CI later: the `--selftest` assertion, and an advisory
   (non-gating) scheduled probe run that archives reports for trend review.

---

## 8. Cross-references

- [CRYPTO-C99-SPEC.md](CRYPTO-C99-SPEC.md) — §3.12 (the placeholder this
  design fills), §2.Q6 (CT discipline decision + build flags), §3.10 (the
  shared CT primitives), §2.Q3 (vendoring/provenance discipline that the §1
  flag extends to harness code).
- [ConstantTimeInventory.md](ConstantTimeInventory.md) — §5 (the normative
  target list, quoted in §4.1), §4.1 (justified residuals incl. item 5's
  multiply assumption), §2 (the per-mechanism claims a probe failure
  localizes to), §1.2 (public-length contract constraining class design).
- [C99CryptoStackAudit.md](C99CryptoStackAudit.md) — the adversarial
  source-level CT verdicts the probe complements (§5.4).
- [FROST_DEVIATION_NOTICE.md](FROST_DEVIATION_NOTICE.md) — §4, the
  external/AI-introduced-dependency discipline behind §1's flag; also the
  library-only scope of the target-9 FROST probes (module removed from the
  tree 2026-07-09, register B2 — those probe targets are retired).
- `include/determ/crypto/ct.h` + `tools/test_ct_c99.sh` —
  the functional pins for `determ_ct_memcmp`; target 1 converts them into the
  timing claim.
- `tools/run_all.sh` + `tools/test_cluster_output_discipline.sh` — the
  deterministic-marker discipline that keeps this probe OUT of the suite
  (§3.1).
- Reparaz, Balasch, Verbauwhede — "dude, is my code constant time?", DATE
  2017 (the published method §2 restates; no code from its implementation
  enters this repo without §1 authorization).

*End of design. Implementation may begin only after the §1 authorization
question is answered (vendor vs in-house); the in-house path needs no
authorization beyond this document's review, since it introduces no external
code.*
