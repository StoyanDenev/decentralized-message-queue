# Stake-Distribution Metrics — Nakamoto + Gini correctness (SD-1..SD-4)

Arithmetic-correctness and interpretation proof for the decentralization metrics
computed by `tools/operator_stake_distribution.sh`. This is **not** a cryptographic
proof: the script reads a validator→stake mapping over read-only RPC and reduces it
to two scalars (the Nakamoto coefficient and the Gini coefficient) plus a ranked
table. The theorems below establish that those scalars equal their textbook
mathematical definitions, that the integer arithmetic the script uses to dodge
floating-point boundary error is exact, and that the tool is read-only.

**Companion documents:** `Safety.md` (FA1 — K-of-K mutual-distrust safety, used in §1 + §5
to bound how far the Nakamoto coefficient may be read as a safety statement);
`Preliminaries.md` §2.0 (canonical assumption labels), §3.3 (honest-fraction bounds);
`BFTSafety.md` (FA5 — the `f_h < |K_h|/3` BFT-committee bound the script's header text
invokes); `S010S011SybilEconomics.md` (the stake-pricing floor the script header also
cites). Sibling operator tools: `operator_stake_concentration.sh` (Gini + top-N +
anomaly gating, **no** Nakamoto), `operator_balance_distribution.sh` (same Gini
sorted-form on balances), `operator_stake_audit.sh` (per-validator lock-state).

---

## 1. Scope

`tools/operator_stake_distribution.sh` is a one-glance decentralization health check.
Given a running `determ` daemon it:

1. fetches the chain head + K-of-K committee size `K` (the `status` RPC,
   `node.cpp::rpc_status` → `height` + `k_block_sigs`);
2. fetches the full validator→stake mapping (the `stakes` RPC,
   `node.cpp::rpc_validators()` materialized through the `stakes` CLI which adds a
   `rank` field), with **no** `--top` cap — both metrics need every entry;
3. computes the **Nakamoto coefficient** (the smallest number of top validators whose
   cumulative stake strictly exceeds `total/3`), the **Gini coefficient** (stake-share
   inequality on `[0,1]`), and a per-validator stake table sorted descending.

This document proves four properties of the computation:

- **SD-1** — the integer test `3·cumulative > total` returns the same Nakamoto
  coefficient as the real-valued `cumulative > total/3`, with **no** floating-point
  boundary error and correct handling of the exact-`1/3` tie;
- **SD-2** — sorting descending and accumulating yields the *minimum* count (greedy on
  the largest shares is optimal), and the function is well-defined on every edge case;
- **SD-3** — the script's sorted-form Gini equals the double-sum definition, and the
  computed value lies in `[0, 1−1/n] ⊂ [0,1)`;
- **SD-4** — the metric is computed purely from RPC reads; the script mutates no chain
  state and its exit code reflects only RPC health.

### 1.1 What the Nakamoto coefficient is and is **not** here

The script reports the `>1/3` Nakamoto coefficient as **THE** Nakamoto coefficient
because Determ's BFT-escalation safety argument turns on a `1/3` dishonest-weight
threshold (`f_h < |K_h|/3`; `Preliminaries.md` §3.3, FA5). The header comment in the
script (lines 5–16, 49–58) is careful, and so must this proof be:

> **The Nakamoto coefficient computed here is an *informational decentralization
> metric*, not a live safety threshold.**

The reason is the K-of-K mutual-distrust model. By `Safety.md` Theorem T-1 (FA1), an
**MD-mode** block is fork-free even if `f = N` — *every* committee member is Byzantine —
because two distinct finalized digests at one height require *every* committee member to
have produced two signatures over distinct digests (T-1 clause 2), which leaves a
slashable forensic trail (FA6) but does not break the at-most-one-finalized-digest
invariant for honest observers (Corollary T-1.1: with `≥ 1` honest member, `B = B'`).
Safety in MD-mode is therefore **unconditional in `f`** — it does not degrade as stake
concentrates. A Nakamoto coefficient of 1 (one validator holds `> 1/3` of stake) does
**not** mean that validator can fork an MD-mode chain.

Where the `1/3` reading *does* approximate a real bound is **BFT-escalation mode**: under
the 4-gate escalation (`Preliminaries.md` §3.3, `BFTSafety.md` §6), block safety requires
`f_h < |K_h|/3` *within the shrunk BFT committee* `|K_h| = ⌈2K/3⌉`. There, dishonest
weight crossing `1/3` of the relevant selection power is closer to a genuine safety
concern. §5 develops this nuance honestly and bounds the overclaim.

This document does **not** prove any safety property of Determ. It proves that the script
computes the two named metrics correctly and interprets them without overclaiming. The
safety theorems live in FA1 (`Safety.md`) and FA5 (`BFTSafety.md`); this proof *cites*
them, it does not extend them.

---

## 2. Definitions

Fix a validator set with stakes `x₁, …, x_n` where `n := |V|` and each `xᵢ ∈ ℤ≥0`
(stakes are non-negative `u64` integers; the script clamps negatives to 0 at
lines 228–229). Let `T := Σᵢ xᵢ` be the total stake.

### 2.1 Nakamoto coefficient

**Definition (Srinivasan 2017, "Quantifying Decentralization").** The Nakamoto
coefficient of a subsystem is the *minimum number of entities whose combined resource
share exceeds the control threshold* for that subsystem. For a threshold fraction
`θ ∈ (0,1)`, sort the entities by resource share descending as `x₍₁₎ ≥ x₍₂₎ ≥ … ≥ x₍ₙ₎`
and define

```
        Nθ  :=  min { k :  Σ_{j=1..k} x₍ⱼ₎  >  θ·T }
```

i.e. the fewest top entities whose cumulative share *strictly exceeds* `θ·T`.

The script uses **`θ = 1/3`** as the headline (`nakamoto_third`, line 272) and also emits
**`θ = 1/2`** as `nakamoto_half` (line 273) in `--json` for operators who want the
classic majority-takeover number alongside the BFT-threshold one. The `>` (strict)
choice matters at the boundary: a coalition that holds *exactly* `T/3` does not exceed
`1/3`, so it is *not* counted — the coalition able to *block/control* under a
`1/3`-Byzantine reading is the one strictly past the threshold. (Symmetrically for the
`1/2` variant: exactly `T/2` is not a majority.)

The script generalizes both via one helper `nakamoto(mult)` (lines 258–270) that returns
the minimum `k` with `cumulative · mult > T`; `mult = 3` gives the `>1/3` coefficient and
`mult = 2` gives the `>1/2` one. The equivalence `cum > T/mult ⟺ mult·cum > T` for
positive integer `mult` is exactly what SD-1 proves.

### 2.2 Gini coefficient

**Double-sum definition.** The Gini coefficient of a distribution `x₁, …, xₙ` with
`Σ xᵢ > 0` is the mean absolute difference normalized by twice the mean:

```
        G  =  ( Σᵢ Σⱼ |xᵢ − xⱼ| )  /  ( 2 · n · Σᵢ xᵢ )                    (G-def)
```

**Sorted-form identity.** For `x₍₁₎ ≤ x₍₂₎ ≤ … ≤ x₍ₙ₎` (ascending sort, 1-indexed),

```
        G  =  ( Σᵢ (2i − n − 1) · x₍ᵢ₎ )  /  ( n · Σᵢ xᵢ )                  (G-sorted)
```

an algebraically identical but `O(n log n)` form (one sort + one linear pass) versus the
`O(n²)` double sum. Both are standard (see references in §6).

**Which form the script uses.** `operator_stake_distribution.sh` uses **(G-sorted)**.
The implementation (lines 286–293) is literally:

```python
asc = sorted(v["stake"] for v in validators)
n = n_validators
wsum = 0
for i, s in enumerate(asc, start=1):          # i is 1-indexed
    wsum += (2 * i - n - 1) * s               # coefficient (2i − n − 1)
g = wsum / (n * total_stake)                  # divide by n·T
gini = 0.0 if g < 0.0 else g                  # clamp tiny negative FP residue to 0
```

This matches the sibling `operator_stake_concentration.sh` (lines 323–333) and
`operator_balance_distribution.sh` byte-for-byte in the inner loop. The `gini = None`
sentinel is returned when `n < 2` or `T = 0` (lines 285–286); see SD-3 edge cases.

---

## 3. Correctness theorems

### SD-1 — Nakamoto integer-exactness

**Theorem SD-1.** Let stakes `x₍₁₎ ≥ … ≥ x₍ₙ₎` be non-negative integers with cumulative
sums `Cₖ := Σ_{j=1..k} x₍ⱼ₎ ∈ ℤ≥0`, and let `T = Cₙ`. For any fixed positive integer
`mult` and any `k`,

```
        Cₖ  >  T / mult        ⟺        mult · Cₖ  >  T                     (SD-1.1)
```

where the left side uses exact rational comparison. Consequently the script's loop
(lines 263–266), which returns the first `k` with `mult·Cₖ > T`, returns exactly
`N_{1/mult} = min { k : Cₖ > T/mult }`. In particular for `mult = 3` the loop returns the
exact `>1/3` Nakamoto coefficient with **no** floating-point boundary error, and it
treats the exact-`T/3` tie correctly (a coalition holding precisely `T/3` is **not**
counted, by the strict `>`).

**Proof.** `mult` is a positive integer, hence `mult > 0`. Multiplying both sides of a
rational inequality by a strictly positive constant preserves the inequality and its
strictness:

```
        Cₖ > T/mult   ⟺   mult·Cₖ > mult·(T/mult)   ⟺   mult·Cₖ > T.
```

Both `Cₖ` and `T` are integers and `mult` is an integer, so `mult·Cₖ` and `T` are
integers; the comparison `mult·Cₖ > T` is an **exact integer comparison** with no
rounding. This is the substance of the float-drift avoidance: the naive alternative
`Cₖ > T/3` computes `T/3` in floating point first, and at the boundary `T = 3·Cₖ`
(coalition holds exactly one third) the rounded `float(T)/3.0` may land just below or
just above the true `T/3` depending on the residue of `T mod 3`, flipping the strict
comparison. A second naive alternative — integer-truncating `T//3` and testing
`Cₖ > T//3` — is also wrong at the boundary: for `T = 13000`, `T//3 = 4333`, and a
coalition with `Cₖ = 4334 < 13000/3 = 4333.33…` would falsely satisfy `4334 > 4333`. The
cross-multiplied form `3·Cₖ > T` sidesteps both: it never forms `T/3` at all.

Strictness handles the exact tie. If `Cₖ = T/3` exactly (only possible when `3 | T`), then
`3·Cₖ = T`, and `3·Cₖ > T` is **false** — the coalition at exactly one third is not
counted, matching the definition's `>` (a coalition must *exceed* the threshold to
control under a `1/3`-Byzantine reading). The loop continues to `k+1`.

The loop returns the first `k` satisfying the (exact, integer) predicate, scanning `k` in
increasing order over the descending-sorted list; that first index is by construction
`min { k : 3·Cₖ > T } = min { k : Cₖ > T/3 } = N_{1/3}` by (SD-1.1). ∎

**Implementation citation.** Lines 258–273:
`def nakamoto(mult): … if cum * mult > total_stake: return i`, invoked as
`nakamoto_third = nakamoto(3)` and `nakamoto_half = nakamoto(2)`. The script-header
comment at lines 242–253 states the same `cum/total > 1/3 ⟺ 3*cum > total` rationale this
theorem formalizes.

### SD-2 — Nakamoto monotonicity / well-definedness

**Theorem SD-2 (greedy optimality).** Accumulating over the **descending**-sorted stake
list yields the *minimum* number of validators whose cumulative stake exceeds `θ·T`.
That is, for any threshold `S := θ·T` (with `0 ≤ S < T` so a witness exists), no set of
`k−1` validators has total stake `> S` if the top `k−1` (largest) validators do not.

**Proof (exchange argument).** Let `k = N_θ` be the index the descending-accumulation
returns, so `C_{k−1} ≤ S < C_k` where `Cⱼ` is the cumulative sum of the `j` *largest*
stakes. Suppose for contradiction some set `A` with `|A| = m ≤ k−1` has `Σ_{i∈A} xᵢ > S`.
Order `A`'s members by stake descending; since each of the `m` largest stakes overall is
`≥` the corresponding-rank member of `A` (the top-`m` prefix maximizes the sum of any
`m` elements — a standard rearrangement fact for selecting the `m` largest of a
multiset), we have `C_m ≥ Σ_{i∈A} xᵢ > S`. But `m ≤ k−1` gives `C_m ≤ C_{k−1} ≤ S`
(cumulative sums are non-decreasing in the index since stakes are `≥ 0`), so `C_m ≤ S`,
contradicting `C_m > S`. Hence no set of size `≤ k−1` exceeds `S`, and `k` is the
minimum. The descending sort at line 232 (`validators.sort(key=lambda r: (-r["stake"],
r["domain"]))`, with the domain-ascending tie-break matching the `stakes` RPC order)
establishes exactly this descending prefix. ∎

**Well-definedness on the witness.** For `mult ≥ 1` and `T > 0`, `Cₙ = T` and
`mult·Cₙ = mult·T ≥ T`, with strict inequality `mult·T > T` whenever `mult ≥ 2` (so the
`>1/3` and `>1/2` coefficients always have a witness `≤ n`). The loop's post-loop
`return n_validators` (lines 267–270) is a guard that the comment correctly notes is
unreachable for `mult ≥ 2` with `T > 0`, since the full set always exceeds the threshold;
it returns the full count defensively.

**Edge cases (all matching the implementation).**

- **Single validator (`n = 1`, `T > 0`).** `C₁ = T`, and `3·C₁ = 3T > T`, so the loop
  returns `k = 1`. Nakamoto coefficient `= 1` — one validator trivially exceeds `1/3`.
  ✓ matches; the `concentration_note` (lines 307–308) additionally flags
  "single validator holds 100% of stake".
- **All-equal stakes (`xᵢ = c > 0` for all `i`).** `T = n·c`, `Cₖ = k·c`, and the test
  `3·k·c > n·c ⟺ 3k > n ⟺ k > n/3`. The minimum such integer is
  `k = ⌊n/3⌋ + 1` (equivalently `⌈(n+1)/3⌉`). For example `n = 3 ⇒ k = 2`;
  `n = 6 ⇒ k = 3`; `n = 9 ⇒ k = 4`. So a perfectly egalitarian pool has Nakamoto
  coefficient `⌊n/3⌋ + 1`, growing linearly with the pool size — the maximum
  decentralization the metric can report for a given `n`. (Note `c` cancels, so the
  value is independent of the common stake.)
- **Zero total (`T = 0`).** The helper short-circuits: `if total_stake <= 0: return 0`
  (lines 260–261). Both coefficients are `0` and the human report prints
  "Nakamoto coefficient: 0 (no stake to control)" (line 369), while the
  `concentration_note` flags the empty/zero-stake pool (lines 305–306). Reporting `0`
  (rather than an undefined / `n`) is the honest reading: there is no stake for *any*
  coalition to control, so "minimum entities to control `>1/3` of nothing" is vacuously
  zero.
- **Empty pool (`n = 0`).** Then `T = 0` as well, falling into the zero-total branch;
  coefficient `0`, and the report prints "(no validators registered)" (line 358).

### SD-3 — Gini bounds + sorted-form correctness

**Theorem SD-3a (sorted-form ≡ double-sum).** For any `x₁,…,xₙ` with `Σ xᵢ > 0`,
(G-sorted) equals (G-def).

**Proof.** It suffices to show the numerators match after sorting (the denominator
`2nΣxᵢ` in (G-def) versus `nΣxᵢ` in (G-sorted) differ by the factor `2`, which the
numerator identity below absorbs). Sort ascending so `x₍₁₎ ≤ … ≤ x₍ₙ₎`; the double sum is
invariant under relabeling, so

```
        Σᵢ Σⱼ |x₍ᵢ₎ − x₍ⱼ₎|  =  2 · Σ_{i<j} (x₍ⱼ₎ − x₍ᵢ₎)          (the matrix is symmetric;
                                                                    diagonal terms are 0)
```

Count how often each ordered value `x₍ᵢ₎` appears with a `+` versus `−` sign in
`Σ_{i<j}(x₍ⱼ₎ − x₍ᵢ₎)`. The value `x₍ᵢ₎` appears with a `+` sign once for each `j < i`
(there are `i−1` such pairs, where `x₍ᵢ₎` is the larger-index/larger value, contributing
`+x₍ᵢ₎`) and with a `−` sign once for each `j > i` (there are `n−i` such pairs,
contributing `−x₍ᵢ₎`). Hence its net coefficient is `(i−1) − (n−i) = 2i − n − 1`, giving

```
        Σ_{i<j} (x₍ⱼ₎ − x₍ᵢ₎)  =  Σᵢ (2i − n − 1) · x₍ᵢ₎.
```

Therefore `Σᵢ Σⱼ |x₍ᵢ₎ − x₍ⱼ₎| = 2 · Σᵢ (2i − n − 1) x₍ᵢ₎`, and

```
        G_def  =  ( 2 · Σᵢ (2i−n−1) x₍ᵢ₎ )  /  ( 2 n Σ xᵢ )
               =  ( Σᵢ (2i−n−1) x₍ᵢ₎ )  /  ( n Σ xᵢ )  =  G_sorted.        ∎
```

The script computes the right-hand `wsum = Σᵢ (2i−n−1)·x₍ᵢ₎` exactly in Python integer
arithmetic (no rounding in the numerator), then performs a single true-division by
`n·total_stake` (lines 290–292). The only floating-point operation is the final divide,
so the result carries at most one rounding step — well inside the two-decimal display
precision (`{gini:.2f}`, line 373).

**Theorem SD-3b (bounds).** With `n ≥ 1` and `T = Σxᵢ > 0`, the computed Gini satisfies

```
        0  ≤  G  ≤  1 − 1/n  <  1,
```

and `G = 0 ⟺` all stakes equal.

**Proof.**
*Lower bound and the equality case.* Pair the numerator `Σᵢ(2i−n−1)x₍ᵢ₎` with the
double-sum form `Σ_{i<j}(x₍ⱼ₎−x₍ᵢ₎)`. Each summand `x₍ⱼ₎ − x₍ᵢ₎ ≥ 0` for `i < j` (ascending
sort), so the numerator is `≥ 0` and thus `G ≥ 0`. It is `= 0` iff every pairwise
difference vanishes, i.e. all stakes equal. (The script's clamp `gini = 0.0 if g < 0.0`
at line 293 only catches a sub-ULP negative FP residue around the exact-zero case; the
mathematical value is already `≥ 0`.)

*Upper bound.* The Gini is maximized, for fixed `n` and `T`, by maximal concentration:
one validator holds all of `T` and the rest hold `0`. Then ascending stakes are
`x₍₁₎ = … = x₍ₙ₋₁₎ = 0`, `x₍ₙ₎ = T`. The numerator is `(2n − n − 1)·T = (n−1)·T`, so

```
        G_max  =  (n−1)·T / (n·T)  =  (n−1)/n  =  1 − 1/n  <  1.
```

No distribution exceeds this because the single-holder configuration maximizes every
pairwise difference simultaneously. Hence `0 ≤ G ≤ 1 − 1/n < 1` for all `n`, approaching
(but never reaching) `1` as `n → ∞`. ∎

**Edge cases (matching the implementation).**

- **`n < 2` or `T = 0`** → `gini = None` (lines 285–286). The human report prints
  "Gini coefficient: n/a (fewer than 2 validators or zero total stake)" (lines 370–371)
  and `--json` emits `"gini": null` (line 333). The header comment (lines 282–284)
  explains the choice: a single validator is trivially "perfectly concentrated", but the
  textbook ratio is `0` there (the lone `(2·1 − 1 − 1) = 0` coefficient), which would be
  *misleading*; the script reports `None` and lets the Nakamoto coefficient (`= 1`) carry
  the concentration signal. This is a presentation choice, not an arithmetic error: the
  formula's value at `n = 1` is genuinely `0` (SD-3b with `n = 1` gives the bound
  `0 ≤ G ≤ 1 − 1 = 0`, forcing `G = 0`), and the script declines to print that
  `0` because it is uninformative.
- **All-zero stakes with `n ≥ 2`** → `T = 0`, same `None` branch; the
  `concentration_note` flags "no stake in the validator set" (lines 305–306).

### SD-4 — Read-only soundness

**Theorem SD-4.** `operator_stake_distribution.sh` mutates no chain state. Every byte it
consumes comes from two **read-only** RPC calls, and its exit code is a function of RPC
health and argument validity alone — never of the distribution shape.

**Proof (by inspection of the script).** The script's only external interactions with the
daemon are:

1. `"$DETERM" status --rpc-port "$PORT"` (line 149) — the `status` RPC, read-only
   (returns `height`, `k_block_sigs`, etc.; mutates nothing). Parsed for `height`
   (lines 153–158) and `k_block_sigs` (lines 163–168).
2. `"$DETERM" stakes --json --rpc-port "$PORT"` (line 172) — the `stakes` RPC
   (`node.cpp::rpc_validators()`), read-only (returns the validator→stake array).

There are **no** `send`, `stake`, `unstake`, `register`, `submit_tx`, `submit_equivocation`,
`snapshot create`, or any other state-mutating invocation anywhere in the file. (Contrast
the sibling `operator_stake_concentration.sh`, which *does* call `snapshot create` +
`snapshot inspect` for its `min_stake_skew` anomaly — but even that is read-only with
respect to chain state, since `snapshot create` serializes existing state to a temp file
without altering the chain.) The only local writes are to a `mktemp` temp file holding
the already-fetched `stakes` JSON (lines 183–187), removed by the `EXIT` trap (line 186) —
this is a parse-channel convenience (the metric pass reads its Python program from a
`<<'PY'` heredoc, which consumes stdin, so the JSON must travel by a file path), not a
chain mutation.

**Exit-code policy.** The script exits `1` on: bad/missing `--rpc-port` (lines 136–139),
`status` RPC failure (lines 149–152), non-numeric height (lines 159–162), `stakes` RPC
failure (lines 172–175), temp-file creation failure (lines 183–185), JSON parse failure
(lines 207–212), or metric/render failure (lines 378–382). It exits `0` on every
successful run **regardless of how concentrated the distribution is** — the header (lines
80–84, 117–119) and usage banner state this explicitly: "a healthy RPC pipeline always
exits 0, regardless of how concentrated the distribution turns out to be". There is no
`--anomalies-only` / exit-`2` gate (that is the sibling concentration tool's job); this is
a purely informational report. Hence the exit code reflects only RPC health + argument
validity. ∎

---

## 4. Worked example — the test fixture

`tools/test_operator_stake_distribution.sh` seeds a live single-node chain with **five**
validators at known distinct stakes and asserts the metric values. The fixture
(lines 13, 94–95):

| Validator | Stake |
|-----------|-------|
| node1     | 4000  |
| node2     | 3000  |
| node3     | 2500  |
| node4     | 2000  |
| node5     | 1500  |
| **Total** | **13000** |

`n = 5`, `T = 13000`, and `T/3 = 4333.33…`.

### 4.1 Nakamoto coefficient = 2 (verified by SD-1 integer arithmetic)

Descending cumulative sums, with the exact integer test `3·Cₖ > T`:

| `k` | top-`k` validators | `Cₖ` | `3·Cₖ` | `> T = 13000`? | counted? |
|-----|--------------------|------|--------|----------------|----------|
| 1   | node1              | 4000 | 12000  | `12000 > 13000` → **false** | no |
| 2   | node1+node2        | 7000 | 21000  | `21000 > 13000` → **true**  | **yes → N₁/₃ = 2** |

Cross-check against the *real-valued* definition: `C₁ = 4000 < 4333.33… = T/3` (top-1 does
**not** exceed one third), and `C₂ = 7000 > 4333.33…` (top-2 does). Both readings agree on
`2`, exactly as SD-1 guarantees (`3·Cₖ > T ⟺ Cₖ > T/3`). The test asserts
`json nakamoto_coefficient == 2` (lines 248–249) and documents the same hand-trace in its
own comment (lines 90–93). This case is deliberately chosen so the answer is **2**, not
**1** — it exercises the accumulation loop (SD-2), not just the single-validator
shortcut.

Note the integer-truncation trap SD-1 warns about would *not* have bitten here
(`T//3 = 4333`, and `C₁ = 4000 < 4333` still gives "false"), but the float trap is real at
exact-third boundaries; the fixture's value `T = 13000` is `≢ 0 (mod 3)`, so it does not
sit on a tie — the tie behavior is covered analytically in SD-1 instead.

### 4.2 Gini coefficient ≈ 0.18 (verified by SD-3 sorted-form)

Ascending sort: `x₍₁₎…x₍₅₎ = [1500, 2000, 2500, 3000, 4000]`, `n = 5`, coefficients
`(2i − n − 1)` for `i = 1..5` are `−4, −2, 0, +2, +4`. The numerator:

| `i` | `(2i−6)` | `x₍ᵢ₎` | term |
|-----|----------|--------|------|
| 1   | −4       | 1500   | −6000 |
| 2   | −2       | 2000   | −4000 |
| 3   | 0        | 2500   | 0 |
| 4   | +2       | 3000   | +6000 |
| 5   | +4       | 4000   | +16000 |
| **Σ** |        |        | **12000** |

```
        G  =  12000 / (n · T)  =  12000 / (5 · 13000)  =  12000 / 65000  =  0.18461538…
```

which the script renders as `0.18` (`{gini:.2f}`). Cross-check via the double-sum form
(G-def): `Σᵢ Σⱼ |xᵢ − xⱼ| = 2·12000 = 24000` over the same data, and
`24000 / (2·5·13000) = 24000 / 130000 = 0.18461538…` — identical, confirming SD-3a on the
fixture. The bound holds: `0 < 0.1846 < 1 − 1/5 = 0.8`. The test asserts
`gini ∈ (0, 1)` for this unequal distribution (lines 224–225, 252–253), and the human
output shows the `0.18` line. ∎

### 4.3 Stake table

The descending table is `node1 (4000, 30.7%) > node2 (3000, 23.0%) > node3
(2500, 19.2%) > node4 (2000, 15.3%) > node5 (1500, 11.5%)`, where each share is
`stake·10000 // 13000` basis points rendered as `XX.X%` (lines 239–240, 351–353). The test
asserts the `--json` `stake_table` is sorted DESC and sums to `total_stake` (lines
218–221, 254–257). Per-validator shares need not sum to exactly `100.0%` because of the
floor-division residual — the script-header and the sibling tools share this convention
(lines 238–240).

---

## 5. Interpretation caveats

The Nakamoto coefficient computed here measures **stake concentration**, which under
Determ's consensus model carries different weight than in a generic PoW/PoS chain. To
restate §1.1 precisely and without overclaim:

- **MD-mode (default K-of-K mutual distrust):** safety is **unconditional in `f`**
  (`Safety.md` T-1; `Preliminaries.md` §3.3 — "Determ's K-of-K mutual-distrust safety
  holds even if `f = N` for MD-mode blocks"). A low Nakamoto coefficient — even `1` — does
  **not** mean an MD-mode chain can be forked by that coalition. Two distinct finalized
  digests at one height require *every* committee member to double-sign (T-1 clause 2),
  independent of how stake is distributed. In this regime the Nakamoto coefficient is a
  **decentralization-informational** metric: it tells an operator how skewed the
  selection weight is and how few actors dominate block production / liveness, but it is
  **not** a safety threshold. The script-header's phrasing "one actor can breach the
  Byzantine safety threshold alone" (line 310) is a *liveness/centralization* warning
  about block-production dominance, not a claim that MD-mode safety has been broken.

- **BFT-escalation mode (4-gate escalation):** here the `1/3` reading is closer to a real
  bound. Block safety requires `f_h < |K_h|/3` *within the shrunk BFT committee*
  `|K_h| = ⌈2K/3⌉` (`Preliminaries.md` §3.3; `BFTSafety.md` §6; the escalation gates
  `bft_enabled ∧ total_aborts ≥ threshold ∧ pool < K ∧ pool ≥ ⌈2K/3⌉`). When the chain is
  operating under BFT escalation, dishonest weight crossing `1/3` of the relevant
  selection power *can* threaten the conditional BFT-safety guarantee. There the Nakamoto
  coefficient approximates a genuine safety margin — but note two subtleties: (a) the
  metric is computed over **stake**, while committee selection is stake-*weighted* via
  Fisher-Yates (S-020) and the realized committee at any height is a *sample*, so stake
  share is a proxy for expected selection share, not the exact per-round committee
  composition; and (b) even in BFT mode, equivocation by the colluding set is slashable
  (FA6 / `EquivocationSlashingApply.md`), so crossing `1/3` enables an *attempt* that
  leaves a forensic trail and an economic penalty, governed additionally by the
  stake-pricing floor of S-010/S-011.

- **Why `>1/3` and not `>1/2`:** the script reports the `>1/3` coefficient as the headline
  because Determ's BFT argument is a `1/3`-Byzantine argument (not a `1/2`-majority one);
  the `>1/2` `nakamoto_half` is emitted alongside in `--json` for operators who also want
  the classic majority-takeover number (script-header lines 49–58). Neither is, on its
  own, an MD-mode safety statement.

**Bottom line.** Treat the reported Nakamoto coefficient as a decentralization
health-indicator. Read it as a (conditional, proxy) safety margin *only* when the chain is
in BFT-escalation mode, and even then in composition with the slashing + stake-pricing
defenses, never as a standalone bound. The arithmetic (SD-1..SD-3) is exact; the
*interpretation* is the part that requires the care above.

---

## 6. Cross-references

**Implementation:**
- `tools/operator_stake_distribution.sh` — the tool proved here (Nakamoto + Gini + table).
- `tools/test_operator_stake_distribution.sh` — the fixture test (§4); asserts
  `nakamoto_coefficient == 2`, `gini ∈ (0,1)`, `validators == 5`, `total_stake == 13000`,
  table sorted DESC + sums to total.
- `tools/operator_stake_concentration.sh` — sibling (Gini + top-1/3/10 + decile +
  `min_stake_skew` Sybil flag + anomaly-gated exit `2`); **does not** compute the Nakamoto
  coefficient. Shares the identical Gini sorted-form inner loop.
- `tools/operator_balance_distribution.sh` — same Gini sorted-form on account balances.
- `src/node/node.cpp` — `rpc_status` (height + `k_block_sigs`), `rpc_validators()` (the
  `stakes` source).

**Proof series:**
- `Safety.md` (FA1) — Theorem T-1 (K-of-K MD-mode fork-freedom unconditional in `f`;
  the basis for "Nakamoto here is informational, not a safety threshold").
- `BFTSafety.md` (FA5) — the `f_h < |K_h|/3` BFT-committee bound (`|K_h| = ⌈2K/3⌉`) the
  `1/3` reading approximates in BFT-escalation mode.
- `Preliminaries.md` §2.0 (canonical assumption labels A1=Ed25519 EUF-CMA,
  A2=SHA-256 collision, A3=SHA-256 preimage, A4=CSPRNG), §3.3 (honest-fraction bounds).
- `S010S011SybilEconomics.md` — the stake-pricing floor + cartel-defense the §5
  caveat composes with.
- `EquivocationSlashingApply.md` (FA-Apply-10) / `EquivocationSlashing.md` (FA6) —
  the slashing that penalizes a `>1/3` collusion attempt even in BFT mode.

**External:**
- B. Srinivasan & L. Lee, "Quantifying Decentralization", 2017 (the Nakamoto-coefficient
  definition — minimum entities to exceed a subsystem's control threshold).
- C. Gini, "Variabilità e mutabilità", 1912 (the Gini coefficient).
- The sorted-form identity `G = Σᵢ(2i−n−1)x₍ᵢ₎ / (n Σxᵢ)` is standard; see e.g. the
  mean-absolute-difference treatment in any inequality-measurement reference
  (Sen, *On Economic Inequality*, 1973, App. A).

**Note on assumptions.** This is an arithmetic-correctness proof; SD-1..SD-4 invoke **no**
cryptographic assumption directly. The cited A1/A2 references appear only transitively
via the safety theorems (FA1/FA5) that §1 + §5 reference to bound the *interpretation* of
the Nakamoto coefficient. The metrics themselves are pure functions of the integer stake
multiset returned by the read-only `stakes` RPC.

---

## 7. Status

**Tool shipped** (`tools/operator_stake_distribution.sh`, this session) with its fixture
test (`tools/test_operator_stake_distribution.sh`). Metrics verified:

- **SD-1** ✓ — the integer test `3·cumulative > total` equals the real-valued
  `cumulative > total/3` exactly, with no float boundary error and correct strict-tie
  handling (matches the script's actual `if cum * mult > total_stake` at lines 263–266).
- **SD-2** ✓ — descending-accumulation is greedy-optimal (minimum count); edge cases
  (single validator → 1, all-equal → `⌊n/3⌋+1`, zero total → 0, empty → 0) all match the
  implementation.
- **SD-3** ✓ — the sorted-form Gini equals the double-sum definition; computed value
  lies in `[0, 1−1/n] ⊂ [0,1)`; `n<2`/`T=0` → `None` sentinel as implemented.
- **SD-4** ✓ — read-only (only `status` + `stakes` RPCs); no chain mutation; exit code
  reflects RPC health + argument validity alone.
- **§4 fixture** ✓ — Nakamoto `= 2` and Gini `≈ 0.18` reproduced by hand and confirmed
  against `tools/test_operator_stake_distribution.sh`.
