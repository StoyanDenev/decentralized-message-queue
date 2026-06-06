# Economics configuration guidance — recommended operator defaults

**Audience.** Operators configuring v1.0 mainnet deployments. Foundation/SDK consumers planning DApp economics. Reviewers evaluating deployment economic integrity.

**Purpose.** Recommend a self-consistent economic configuration that keeps the base messaging layer cheap for global enterprise adoption while preserving validator incentives through deflation + priority tips. Captures the three-policy pattern from 2026-06-06.

**Coherence with other artifacts.**
- `WHITEPAPER-v1.x.md §8.2-8.4` — v1.x economic primitives the recommendations configure
- `Improvements.md §5.7` — Genesis-time economic-config validation (manifest hard-invariants for self-consistency)
- `Improvements.md §5.8` — EIP-1559-style base-fee + priority-tip mechanism (the new mechanism this guidance assumes; ships as Additive feature)
- `Improvements.md §9.6` — Three-layer monetization framing (chain + DApp + Foundation)
- `DAPP_SDK_GUIDANCE.md §7` — DApp-layer pricing patterns that compose with chain-level fees
- Memory `dlt-no-migrations-constraint` — per-deployment economic config is immutable at genesis

---

## 1. Recommended three-policy pattern

| Policy | Recommendation | Why |
|---|---|---|
| **1. Block subsidy** | **`block_subsidy = 1` (one dust unit per block)** — minimal but non-zero | Stops diluting token supply at any meaningful rate (1 dust × ~31M blocks/year at 1s block time ≈ 31M dust units/year — economically negligible); keeps the A1 unitary-supply invariant subsidy counter exercising the subsidy code path every block (defensive against subsidy code-path bitrot); ensures validators always receive something even if priority-tip flow temporarily dries up; eliminates hidden inflation tax while preserving subsidy-accounting paths |
| **2. Priority tip distribution** | 100% to active K-of-K committee, split evenly `1/K` per signing member (existing FLAT distribution mode with subsidy ≈ 0 reduces to this) | Aligns Phase-2 signature incentive symmetrically across K members; eliminates incentive to stall/veto/defect; even split is critical for K-of-K consensus efficiency |
| **3. Base fee with 50% utilization target** | Microscopic hard floor (e.g., `BASE_FEE_FLOOR ≈ 1` dust unit); algorithmic adjustment targeting 50% block capacity; **priority tip uncapped** | Keeps base cost at floor for telemetry/Web3-logging workloads; only rises algorithmically as spam-mitigation when blocks exceed 50% full; high-frequency actors bid in priority lane without dragging up base fee for everyone else |

This pattern is internally consistent: validators are compensated via macroeconomic deflation (token supply doesn't expand) + direct priority tips (operators pay when they have urgency), while standard users see microscopic base cost during normal operation.

---

## 2. Per-policy detail

### 2.1 Fixed block subsidy at minimum

**Concrete config:**
```
block_subsidy            = 1   (one dust unit per block — minimal but non-zero)
subsidy_pool_initial     = 0   (no finite-pool needed since subsidy is minimal anyway)
subsidy_mode             = FLAT  (1 dust split FLAT to K creators = creators[0] gets dust)
```

**Why 1, not 0.** A non-zero block_subsidy keeps the A1 unitary-supply invariant tracking subsidy as a first-class counter (`accumulated_subsidy_`) and exercises the subsidy mint path every block (defensive against subsidy code-path bitrot). Setting `block_subsidy = 0` is fully supported per `WHITEPAPER-v1.x.md §8.2` ("zero produces a fees-only chain") but skips the subsidy code paths entirely, leaving them untested in operational deployments. **Recommend `block_subsidy = 1`** as the canonical minimal value: economically negligible (~31M dust units/year at 1s blocks) but operationally safer.

**What this trades off.**
- ✅ No inflation; token supply stays bounded (or deflationary as txs burn or fees redistribute)
- ✅ Cost of network usage tied strictly to demand (priority tips), not validator-subsidization
- ✅ Aligns with public-interest framing per `MOTIVATION.md` — no monetary expansion subsidizing operators
- ⚠️ Bootstrap economics — validators must be motivated by priority-tip flow alone or by sponsor-deployment funding per `Improvements.md §5.7` sponsor_declaration field

**Failure mode prevented by `Improvements.md §5.7` validation.** With `block_subsidy ≈ 0` and `subsidy_pool_initial = 0`, the deployment MUST EITHER have non-zero base/priority fee floor OR declare sponsor-funded validators in the manifest. The genesis validation rule rejects "zero subsidy + zero fees + no sponsor" — which would be a chain with no validator economics.

### 2.2 Priority tip 100% to K-of-K committee, split 1/K

**Concrete config:**
```
priority_tip_distribution = FLAT_KK    (split priority tips evenly across K signing members)
priority_tip_dust         = creators[0]   (preserves existing dust-handling convention)
priority_tip_burn         = false   (NO burn; NO global pool)
priority_tip_external_tax = 0       (no foundation tax on tips)
```

**Why even split across K, not weighted.** The K-of-K consensus requires every committee member to sign the same digest. If priority tips were weighted (e.g., 50% to proposer, 50% split among signers), the proposer would have stronger incentive to include high-tip txs than other signers — creating asymmetric incentive that could delay Phase-2 signature collection. Even split aligns all K members equally: every member has the same `tip / K` incentive to sign immediately.

**Why no burn, no global pool, no foundation tax.** Three principles:
- **No burn:** users' priority spend goes to the validators who actually do the work, not destroyed
- **No global pool:** avoids centralized capture vector contradicting K-of-K mutual-distrust posture
- **No foundation tax:** foundation captures value via off-protocol services per §9.5, not by protocol-level skim

The priority tip mechanism is pure validator compensation for prioritization service.

**Composition with FLAT distribution.** v1.x already provides FLAT distribution mode (`subsidy_mode = 0 FLAT`) that splits `total_fees + subsidy_this_block` equally to K creators with dust to `creators[0]`. When subsidy ≈ 0, FLAT distribution applied to priority tips = exactly this policy. **No new mechanism needed for the distribution itself — the recommendation is operator policy on the existing FLAT mode.**

### 2.3 Base fee floor + algorithmic adjustment + uncapped priority tip

**Concrete config (requires new mechanism per §5.8):**
```
base_fee_floor           = 1 dust unit (or operator-chosen microscopic value)
base_fee_target_util     = 0.50 (50% block capacity target)
base_fee_adjust_rate     = adaptive (per algorithm; EIP-1559 default = 1/8 per block)
base_fee_burn            = (operator policy: burn vs subsidy-pool vs priority-tip-pool)
priority_tip_max         = UINT64_MAX (uncapped — users bid freely)
```

**Why 50% utilization target.** Lower than EIP-1559's typical 50% but matches the user's specification. The 50% target means blocks operate at half-capacity during normal load, leaving headroom for bursts without immediately raising base fee. Only sustained blocks > 50% trigger algorithmic increase. Sustained blocks < 50% trigger decrease back to floor.

**Why microscopic floor.** Web3 logging, telemetry, IoT data writes are the use cases where base cost matters. A microscopic floor (~1 dust unit) makes per-tx cost negligible at normal load; users with urgency pay via priority tip on top.

**Why uncapped priority tip.** Lets high-frequency actors (HFT, MEV bots, urgent settlements) bid against each other in the priority lane without affecting the base fee. The priority bid is a market-discovered price for next-block inclusion; no protocol-level cap distorts that price discovery.

**This requires a new mechanism** — v1.x's per-tx `fee` field is a single value, not split into base + tip. Adding base-fee + tip semantics requires either:
1. New optional `priority_tip: u64` field on Transaction (Additive)
2. Per-block algorithmic `base_fee` computation (validator state, not per-tx field)
3. Per-deployment genesis-pinned parameters for base-fee algorithm

See `Improvements.md §5.8` for the proposed Additive implementation that fits under no-migrations constraint.

---

## 3. Self-consistent default configuration template

For new v1.0 deployments wanting this three-policy pattern:

```yaml
# Block subsidy (minimal — 1 dust unit; drops inflation while exercising subsidy code path)
block_subsidy:                  1
subsidy_pool_initial:           0
subsidy_mode:                   0    # FLAT (dust goes to creators[0])

# Priority tip distribution (100% to K-of-K committee, even 1/K split)
# Uses existing FLAT mode on fees when subsidy ≈ 0
priority_tip_distribution:      FLAT_KK
priority_tip_dust_target:       creators[0]
priority_tip_burn:              false
priority_tip_external_tax:      0

# Base fee + uncapped priority tip (per §5.8 EIP-1559-style mechanism)
base_fee_floor:                 1    # 1 dust unit; operator-tunable
base_fee_target_utilization:    0.50  # 50% block capacity
base_fee_adjust_rate:           0.125 # 1/8 per block (EIP-1559 default)
base_fee_handling:              priority_pool   # operator choice: burn / subsidy_pool / priority_pool
priority_tip_max:               UINT64_MAX   # uncapped

# Sponsor declaration (§5.7) — required when subsidy + base_fee_floor are minimal
sponsor_declaration:            SOVEREIGN_OPERATOR   # operator attestation for genesis-time economic-config validation
```

**Validation note.** This config requires `Improvements.md §5.7` genesis-time economic-config validation to pass — specifically the `sponsor_declaration` field must be set (since subsidy and base_fee floor are minimal, validator economics depend on priority-tip-flow + sponsor backing).

---

## 4. Composition with chain primitives

| Primitive | Composition |
|---|---|
| v1.x FLAT distribution mode | Already implements the 1/K split for §2.2 (when subsidy ≈ 0, FLAT applied to fees = priority tip distribution) |
| K-of-K consensus | The 1/K even split enables symmetric Phase-2 signing incentive — critical for K-of-K efficiency |
| `manifest.sponsor_declaration` (§5.7 candidate) | Required field when subsidy/base-fee are minimal; documents off-chain validator funding source |
| `Block.base_fee` (§5.8 candidate) | New per-block field for algorithmic base-fee value (EIP-1559-style) |
| `Transaction.priority_tip` (§5.8 candidate) | New optional Transaction field; user bid for next-block inclusion |
| §9.2 DApp-layer pricing | DApps absorb both base fee + priority tip as cost-of-goods; bills aggregate to principal |

---

## 5. When NOT to use this configuration

The three-policy pattern is appropriate for deployments that want:
- Public-interest infrastructure framing (per `MOTIVATION.md`)
- Minimal monetary expansion
- Sponsor-funded or sustained-priority-tip validator economics
- Cheap base layer for telemetry/logging/Web3-logging workloads

It is NOT appropriate for:
- Deployments that need permanent inflation to fund validators with no sponsor backing
- Pure permissionless deployments without organized sponsor + insufficient priority-tip volume to fund validators
- Deployments wanting traditional fee-market economics (high base fee + small priority tip)

For those cases, see `WHITEPAPER-v1.x.md §8.2-8.4` for the broader range of subsidy/fee configurations the v1.x mechanism supports.

---

## 6. Why this matters for v1.0 launch

Per `dlt-no-migrations-constraint`, the economic configuration is **immutable at genesis**. Operators choosing the configuration at genesis are locked in for the chain's lifetime. The three-policy pattern is a recommended self-consistent default; operators can choose otherwise, but the choice must pass `Improvements.md §5.7` genesis-time validation.

If `§5.8` EIP-1559-style mechanism is shipped in v1.0 (recommended; classified Additive), the three-policy pattern is directly configurable at genesis. If §5.8 ships post-v1.0 as Additive, deployments wanting this pattern must either:
- Wait for v1.1 release with §5.8 mechanism
- Use v1.x's simpler per-tx fee mechanism with operator-side base-fee equivalent (off-chain rate-limiting + fee-suggestion oracle)

The recommended path: ship §5.8 in v1.0 to make this three-policy pattern available from mainnet day 1.

---

*End of economics configuration guidance.*
