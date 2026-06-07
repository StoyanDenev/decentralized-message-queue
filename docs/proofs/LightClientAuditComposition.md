# LightClientAuditComposition — composite one-shot trust-minimized node audit (`determ-light audit`)

This document proves the soundness of the `determ-light audit` subcommand (`light/main.cpp::cmd_audit`, `:5518`, dispatched `:5664`): a **composite, one-shot, trust-minimized node audit** that an operator runs against a single (potentially malicious) daemon to obtain, in one invocation, a PASS/FAIL verdict over two independently-proved trust-minimized reads — CHAIN (genesis-pinned committee-signed chain continuity to head) and SUPPLY (A1 unitary-supply conservation against that same signed head).

The proof exists because the audit is **pure orchestration**. It introduces *no new verification logic*: it calls two already-verified primitives in sequence, conjoins their verdicts, and maps the conjunction to a process exit code. Its soundness is therefore *exactly* the conjunction of its components' soundness — there is nothing cryptographic to prove anew, only that the orchestration faithfully (a) reduces each component to its existing soundness theorem, (b) never manufactures a PASS that a component did not produce, (c) fails closed on every error/exception path, and (d) handles the CHAIN→SUPPLY short-circuit (SKIP) and the pre-S-033 head honestly. This is the same posture `LightClientCompositionMap.md` takes for the family lattice (a coherence artifact over proved nodes), specialized to the single new orchestration command.

**A note on what "composite" means here.** Unlike `read_account_trustless` (which composes *primitives* — genesis anchor + walk + state-proof — into one new theorem `T-L4`), `audit` composes two *commands*, each of which is *itself* a fully-proved composite. CHAIN is the `verify-chain` flow (`verify_chain_to_head`, backed by `LightClientThreatModel.md` T-L1 + T-L2 + the chain-continuity walk, and the chain-level `Safety.md` §7 T-1.2 composition); SUPPLY is the `supply-trustless` flow (`cmd_supply_trustless`, backed by `SupplyProofSoundness.md` SU-1..SU-4 / SU-E). The audit adds a thin conjunction layer on top. Every theorem this document states (AC-1..AC-4, AC-E) is a *composition* statement that reduces to those two component results plus inspection of the orchestration code; none is a fresh cryptographic reduction.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1), **A3** = SHA-256 preimage / second-preimage resistance (§2.1), **A4** = CSPRNG uniform sampling (§2.3). The audit reduces to **A1 + A2** only (A3 inherited only via T-L1's genesis-anchor Case 2; A4 not used — consistent with `LightClientCompositionMap.md §2.1`). As in `SupplyProofSoundness.md`, the symbol "A1" is overloaded: **assumption A1** = Ed25519 EUF-CMA, whereas the **A1 unitary-supply invariant** is the accounting identity `live_total_supply == expected_total` (`AccountStateInvariants.md` I-6 / `EconomicSoundness.md` T-12). This document writes "assumption A1" for the signature reduction and "the A1 supply identity" for the accounting invariant.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (assumption labels), §2.1 (A2/A3), §2.2 (assumption A1) — the audit reduces to assumption A1 + A2; `LightClientThreatModel.md` (the `A_daemon` malicious-daemon model and the **T-L1** genesis anchor, **T-L2** committee-sig head trust, **T-L4** composite read, and **L-6** fail-closed-exit lemma the audit inherits) — `verify_chain_to_head` *is* the `verify-chain` composite of its §1 / §5; `Safety.md` (FA1) **§7 T-1.2** (the light-client safety composition + **Corollary T-1.2.1** fail-closed exit) — the chain-level result CHAIN reduces to; `SupplyProofSoundness.md` (**SU-1** committee-anchored root, **SU-2** `k:c:` Merkle inclusion, **SU-3** A1-identity recompute, **SU-4** `leaf_count` root-wrapper binding, **Corollary SU-E** end-to-end supply read) — the component SUPPLY reduces to; `StateRootAnchorSoundness.md` (F6) (**SR-1** the per-height committee-anchored `state_root` sub-lemma SU-1 and the head-anchoring consume; **SR-5** pre-S-033 vacuity honesty) — the basis for the pre-S-033 head-state-root reporting; `LightClientCompositionMap.md` (the family lattice + the four consolidated shared limitations §6.1–§6.4) — this audit is a new consumer of the same lattice nodes; `EconomicSoundness.md` (FA11) T-12 + `AccountStateInvariants.md` (FA-Apply-1) I-6 (the A1 supply identity SUPPLY's SU-3 re-checks); `docs/SECURITY.md §S-033 + §S-038 + §S-040` for the closure narratives the components inherit.

---

## 1. Scope

### 1.1 In scope

The `determ-light audit --rpc-port <N> --genesis <file> [--json]` composite command (`light/main.cpp::cmd_audit`, `:5518`). Its control flow, read directly off source:

1. **Argument parse + validation.** `--rpc-port` and `--genesis` are required; `--json` is optional. Missing required args → `return 1` with a diagnostic (`:5533-5536`). An unknown arg → `return 1` (`:5528-5531`).

2. **CHAIN check (`:5542-5569`).** In a `try` block: load the operator's genesis (`load_genesis`), build the genesis-seeded committee (`build_genesis_committee`), open the RPC, run `anchor_genesis(rpc, genesis)` (T-L1) and `verify_chain_to_head(rpc, committee_seed, gh)` (T-L2 + continuity, end-to-end from block 0). On success, capture `vc.head_state_root` (the tip's `state_root`, possibly empty pre-S-033) and a human detail string (`height`, headers verified, sig-sets verified); set `ok = true`. Any thrown `std::exception` is caught (`:5561-5563`); `ok` stays `false` and `detail = e.what()`. The verdict `"PASS"`/`"FAIL"` is pushed to `checks[0]` and `passed`/`failed` incremented.

3. **SUPPLY check (`:5571-5601`).** **Attempted only if `checks[0].verdict == "PASS"`** (`:5575`). When attempted, it synthesizes the argv `{--rpc-port N, --genesis file}` and invokes the already-tested `cmd_supply_trustless(...)` (`:5591`), capturing its integer return code `rc`. `rc == 0` (the supply-trustless `CONSERVED` exit) → SUPPLY `"PASS"`; any non-zero `rc` (VIOLATED→2, UNVERIFIABLE→3, transport/parse fault→1) → SUPPLY `"FAIL"` with a detail recording the exit code (`:5593-5597`). If CHAIN did **not** pass, SUPPLY is pushed as `"SKIP"` with detail `"CHAIN failed — not attempted"` and `skipped` is incremented (`:5598-5601`) — **never PASS, never silent**.

4. **`--json` streambuf redirect (`:5580-5592`).** In `--json` mode the sub-command's human stdout output is captured into a local `std::ostringstream sink` by swapping `std::cout`'s streambuf to `sink.rdbuf()`, so only the aggregate JSON reaches the real stdout. The swap is guarded by a RAII `RdbufGuard` *declared after* `sink` (so on stack unwind the guard's destructor runs first, restoring `cout`, and only then is `sink` destroyed — `cout` is never left pointing at a freed buffer). After the call, `cout` is restored explicitly and `guard.prev` nulled (`:5592`).

5. **Aggregate verdict + exit (`:5603-5636`).** `overall = (failed == 0)`. In `--json` mode an aggregate object `{audit, passed, failed, skipped, head_state_root, checks[]}` is emitted; otherwise a human summary table + `head_state_root` line (printed as `(pre-S-033 / not populated)` when empty). The process **`return overall ? 0 : 1`** (`:5636`).

### 1.2 The two components (each fully proved elsewhere)

| Component | Implementation | Backing proof | What it establishes |
|---|---|---|---|
| **CHAIN** | `anchor_genesis` (`light/trustless_read.cpp:52-79`) + `verify_chain_to_head` (`:81-186`), the `verify-chain` flow | `LightClientThreatModel.md` **T-L1** (genesis anchor) + **T-L2** (per-block committee sigs) + chain-continuity walk; `Safety.md` **§7 T-1.2** (the chain-level light-client safety composition) | The served chain's block 0 byte-equals the operator's pinned genesis, AND every block from genesis to head carries a valid K-of-K (MD) / `⌈2K/3⌉`-of-`k_bft` (BFT) committee signature set over its digest, AND the prev_hash links are continuous — i.e. a genuinely-continuous, committee-signed chain anchored to the pinned genesis. |
| **SUPPLY** | `cmd_supply_trustless` (`light/main.cpp:4268-4633`) | `SupplyProofSoundness.md` **SU-1/SU-2/SU-3/SU-4** + Corollary **SU-E** | The five A1 supply counters (`genesis_total`, `accumulated_subsidy/inbound/slashed/outbound`) are each committee-committed under a single committee-anchored `state_root`, and their closed-form A1 identity `expected_total` is internally consistent (and matches the daemon's claimed `total_supply` when supplied) — the A1 unitary-supply conservation read. |

The audit's *only* additions over these two are: the conjunction (`failed == 0`), the CHAIN→SUPPLY short-circuit (SKIP), the head-state-root capture/report, and the `--json` streambuf relocation. §3 proves each of these adds no trust surface.

### 1.3 Out of scope (intentional — the audit's coverage boundary)

- **Per-account / per-DApp / per-receipt / per-merge / per-param membership.** The audit covers chain continuity + supply *only*. It does **not** verify any individual account balance/nonce (`balance-trustless` / `account-history` / `verify-account`), DApp registration (`verify-dapp-registration`), tx inclusion (`verify-tx-inclusion`), cross-shard receipt inclusion (`verify-receipt-inclusion`), merge state (`verify-merge-state`), or param change/value (`verify-param-change` / `verify-param-value`). Each of those is a *separate* `determ-light` subcommand with its own soundness proof (`AccountHistorySoundness.md`, `TxInclusionProofSoundness.md`, the F-track verifiers). The audit is a *node-health* composite, not a full state membership audit. §findings F-A1 states this honestly.
- **The component reads' own out-of-scope adversaries + UNVERIFIABLE conditions.** The audit inherits, verbatim, every out-of-scope adversary of `LightClientThreatModel.md §2.2` (`A_crypto`, `A_local`, `A_net`, `A_genesis`) and every UNVERIFIABLE condition of `SupplyProofSoundness.md` (e.g. a daemon refusing a `c:` state-proof, a split-root read, a `chain_summary`-vs-proof mismatch). The audit does not weaken or strengthen these; it surfaces them as a SUPPLY=FAIL.
- **Multi-peer / persistence / poll loop.** As every other light-client command, the audit talks to ONE daemon in ONE shot with no persistence (`LightClientCompositionMap.md §6.1`). A truncated-tip or stalling daemon is an *availability* failure surfaced as fail-closed, not a soundness break.
- **Committee rotation.** CHAIN's `verify_chain_to_head` seeds the committee map only from genesis `initial_creators` and does **not** thread mid-chain REGISTER/DEREGISTER (`light/trustless_read.hpp:70-75`); a header signed by a non-`K_0` creator fails closed. This is the standard static-`K_0` limitation (`LightClientCompositionMap.md §6.2`); §findings F-A3 records its effect on audit coverage.

---

## 2. Threat model

The adversary is `A_daemon`, the **malicious daemon** of `LightClientThreatModel.md §2.1`: the single RPC endpoint the audit talks to is fully adversary-controlled and may return arbitrary JSON (forged headers, forged block bodies, forged state-proofs, forged supply replies), drop/stall/mutate responses adaptively within and across invocations, and observe cleartext RPC. Out of scope identically to that document §2.2: `A_crypto` (the proof rests on assumption A1 + A2 being infeasible), `A_local` (operator-machine compromise), `A_net` (transport MITM — observationally equivalent to `A_daemon`), `A_genesis` (tampered pinned `genesis.json`).

**Security goal.** Under `A_daemon`, an honest operator running `determ-light audit` never sees an `AUDIT: PASS` (process exit 0) unless **both** (i) the chain the daemon serves is genuinely continuous and committee-signed from the operator's pinned genesis to head (CHAIN soundness) **and** (ii) the A1 supply counters are committee-committed and conserved against that same signed head (SUPPLY soundness) — except with the negligible composition probability of §AC-E. The negation form is **fail-closed**: any detected inconsistency, component error, UNVERIFIABLE verdict, or thrown exception yields `AUDIT: FAIL` (exit 1), never a false PASS. This is the audit-level instantiation of `LightClientThreatModel.md §2.3` ("never acts on inconsistent data") + L-6 (fail-closed exit), conjoined across the two components.

---

## 3. Soundness theorems

Throughout, let `CHAIN ∈ {PASS, FAIL}` and `SUPPLY ∈ {PASS, FAIL, SKIP}` be the two component verdicts the audit records (`checks[0]`, `checks[1]`), and `AUDIT ∈ {PASS, FAIL}` the aggregate verdict (`overall`, exit code `0`/`1`). Bounds follow the `Preliminaries.md §2.0` labels (assumption A1, A2 ≈ `2⁻¹²⁸`).

### 3.1 AC-1 (composite soundness)

**Statement.** Under `A_daemon` + assumption A1 + A2, `AUDIT = PASS` (exit 0) implies the conjunction

> **(CHAIN soundness)** the daemon's served chain is genuinely continuous and every block from the genesis-pinned anchor to head carries a valid committee signature set — reducing to `verify_chain_to_head`'s composition of `LightClientThreatModel.md` **T-L1** (genesis anchor, assumption A2/A3) + **T-L2** (per-block K-of-K committee sigs, assumption A1) + the chain-continuity walk, i.e. the **FA1 light-client safety result `Safety.md` §7 T-1.2** under preconditions {assumption A1, A2} ;

> **∧ (SUPPLY soundness)** the five A1 supply counters are committee-committed under a single committee-anchored `state_root` and satisfy the closed-form A1 supply identity — reducing to `SupplyProofSoundness.md` **SU-1 + SU-2 + SU-3 + SU-4** (Corollary **SU-E**) under {assumption A1, A2}.

The audit adds **no new verification logic**, so its soundness is *exactly* the conjunction of the two component soundness results.

**Proof.** `AUDIT = PASS` ⟺ `overall = (failed == 0)` is true (`:5603`, `:5636`). `failed` is incremented at exactly two sites: the CHAIN block (`:5568`, incremented iff `ok == false`) and the SUPPLY block (`:5597`, incremented iff `rc != 0`). A SKIP increments `skipped`, never `failed` (`:5600`). Therefore `failed == 0` requires:

1. **CHAIN = PASS.** `ok == true` (`:5568`), which holds iff the entire CHAIN `try` block (`:5549-5560`) completed without throwing: `anchor_genesis` returned (no genesis mismatch) and `verify_chain_to_head` returned a `VerifiedChain` (no continuity break, no committee-sig failure, no malformed header). By construction these are precisely the success conditions of T-L1 (genesis byte-equality) and T-L2 + continuity (every block's committee sigs verify under the genesis-seeded `K_0`, and every prev_hash link closes) — i.e. the `verify-chain` composite of `LightClientThreatModel.md §1`/§5 and the `Safety.md` §7 T-1.2 light-client safety composition. By T-L1 + T-L2, `A_daemon` cannot make CHAIN = PASS on a chain whose genesis ≠ the pinned one (assumption A2, `≤ 2⁻¹²⁸`) or which contains a block lacking a valid committee signature set (assumption A1, `≤ K · 2⁻¹²⁸` per block) except with the bound of §AC-E. *The audit calls the same `verify_chain_to_head` helper `cmd_verify_chain` calls* — the source comment at `:5542-5544` notes the direct helper call is used (rather than the `cmd_verify_chain` wrapper) only so the audit can additionally *read* `vc.head_state_root` for the report; the verification performed is byte-identical.

2. **SUPPLY = PASS.** Because CHAIN = PASS (step 1), the SUPPLY branch is taken (`:5575`), not the SKIP branch. SUPPLY = PASS iff `rc == 0` (`:5593`), and `cmd_supply_trustless` returns `0` *only* on its `CONSERVED` verdict (`:5572-5574`, `:5626-5628`: UNVERIFIABLE→3, VIOLATED→2, exception→1, CONSERVED→0). CONSERVED is exactly the conclusion of `SupplyProofSoundness.md` Corollary SU-E: all five counters Merkle-verified against a single committee-anchored root (SU-2 ×5, SU-4), that root committee-anchored to the genesis-pinned chain (SU-1), and the closed-form A1 identity recomputed from the committed values consistent (SU-3, including the `claimed_total == expected_total` cross-check when `total_supply` is supplied, `:4557-4574`). By SU-E, `A_daemon` cannot make `cmd_supply_trustless` return 0 on a chain whose committed counters are not conserved except with the SU-E bound.

The conjunction of (1) and (2) is the statement. The audit's contribution is solely the boolean `failed == 0`; it performs no signature check, no hash check, no Merkle walk of its own. Hence `Pr[AUDIT = PASS ∧ ¬(CHAIN soundness ∧ SUPPLY soundness)] ≤ Pr[T-L1/T-L2 broken] + Pr[SU-E broken]`, bounded in §AC-E.   ∎

**Remark (no double-counting of the head anchor).** Both CHAIN and SUPPLY independently anchor genesis and walk/committee-verify the header chain (SUPPLY re-runs `anchor_genesis` + `verify_chain_to_head` internally at `light/main.cpp:4314-4318`). This is redundant work, not a soundness gap: the two reads are *each* sound standalone, and the conjunction is sound because each conjunct is. The redundancy costs O(height) extra sig-verifies (the no-persistence limitation, `LightClientCompositionMap.md §6.1`) but never weakens the verdict.

### 3.2 AC-2 (no added trust surface — orchestration only)

**Statement.** The audit is pure orchestration: (a) the exit code faithfully reflects the recorded component verdicts (`exit 0 ⟺ failed == 0 ⟺ CHAIN = PASS ∧ SUPPLY ∈ {PASS}` with no SKIP-as-pass), and (b) the `std::cout` **and** `std::cerr` streambuf redirects used to capture sub-command output in `--json` mode cannot affect any verdict — they only relocate output bytes and are RAII-restored even under exception.

**Proof of (a) — faithful exit code.** The exit code is computed *only* from `passed`/`failed`/`skipped`, which are incremented *only* at the four sites enumerated in AC-1's proof, each gated on a component verdict (`ok` for CHAIN, `rc == 0` for SUPPLY, the SKIP branch for the short-circuit). There is no code path that sets `overall = true` other than `failed == 0` (`:5603`), and no path that returns `0` other than `overall == true` (`:5636`). The verdict strings pushed to `checks[]` are the same booleans, stringified for display; the display table (`:5619-5635`) and the JSON object (`:5605-5618`) are *read-only* over `checks`/`passed`/`failed`/`skipped` and `head_state_root` — they emit but never mutate the verdict. Therefore the exit code is a faithful function of the component verdicts; the orchestration introduces no path to a PASS the components did not jointly produce.

**Proof of (b) — the streambuf redirects are verdict-neutral and exception-safe.** In `--json` mode the SUPPLY block swaps BOTH `std::cout`'s and `std::cerr`'s *underlying streambufs* to a single local `std::ostringstream sink` for the duration of the `cmd_supply_trustless` call, then restores them (so only the audit's own aggregate JSON reaches stdout — the sub-command's human stdout AND its failure-diagnostic stderr are absorbed, and the failure reason is still surfaced in the JSON `detail` field). Three facts make this verdict-neutral:

1. **It relocates bytes, not values.** `cmd_supply_trustless` computes its verdict entirely from RPC replies, hash recomputations, and committee-sig checks and returns it as an *integer return code* (`rc`). The streambuf swaps affect only where the sub-command's *text output* lands (the `sink` vs the terminal); they do not touch `rc`, the RPC socket, the genesis bytes, the committee map, or any hash. A redirected `cout`/`cerr` cannot change which integer `cmd_supply_trustless` returns.

2. **It is active only in `--json` mode** (`if (json_out) { guard.out_prev = std::cout.rdbuf(sink.rdbuf()); guard.err_prev = std::cerr.rdbuf(sink.rdbuf()); }`). In human mode both streams are untouched and the sub-command prints its `--- SUPPLY ---` section inline. In neither mode does a redirect feed back into the verdict.

3. **They are RAII-restored under all control flow, including exceptions.** The `RdbufGuard` holds two saved pointers (`out_prev`, `err_prev`) and restores each stream in its destructor iff the corresponding pointer is non-null. It is *declared after* `sink`, so during stack unwinding the guard destructor (restoring `cout` and `cerr`) runs *before* `sink`'s destructor (freeing the buffer) — neither stream is ever left pointing at a freed `ostringstream`. On the normal path both streambufs are *also* restored explicitly immediately after the call and the saved pointers nulled, so the destructor is then a no-op. Either way `cout` is valid for the aggregate-JSON emission. (`cmd_supply_trustless` itself catches its own exceptions and returns `1` rather than propagating — `light/main.cpp` SUPPLY-block `try/catch` — so in practice the unwind path is not exercised by the sub-command; the guard is defense-in-depth for any future throw.)

Hence the redirect is a presentational mechanism with no verdict pathway; AC-2 holds.   ∎

**Remark (why AC-2 matters).** AC-2 is the formal statement that "the audit is a thin shell." It is what lets AC-1 reduce the audit's soundness to the two component proofs without re-examining the orchestration for hidden trust. A reviewer auditing soundness checks the two component proofs (T-L1/T-L2 + SU-E) and then confirms, via AC-2, that the shell neither adds nor subtracts from their verdicts.

### 3.3 AC-3 (fail-closed)

**Statement.** Any component error, UNVERIFIABLE verdict, or thrown exception yields `AUDIT = FAIL` (exit 1), never a false PASS.

**Proof.** Enumerate the failure pathways:

- **CHAIN throws.** Any inconsistency `verify_chain_to_head`/`anchor_genesis` detects throws `std::runtime_error` (genesis mismatch, prev_hash break, committee-sig failure, malformed header — `LightClientThreatModel.md` L-6, the per-surface fail-closed lemma). The audit's CHAIN `try`/`catch` (`:5549-5563`) catches *every* `std::exception`, leaves `ok = false`, records `detail = e.what()`, and increments `failed` (`:5568`). `failed > 0` ⟹ `overall = false` ⟹ exit 1.

- **SUPPLY non-zero (UNVERIFIABLE / VIOLATED / fault).** `cmd_supply_trustless` returns 3 (UNVERIFIABLE — e.g. a refused `c:` proof, a split-root read, a `chain_summary`-vs-proof value-hash mismatch), 2 (VIOLATED — the recomputed A1 identity fails, or claimed `total_supply ≠ expected_total`), or 1 (transport/parse fault / caught exception). Every non-zero `rc` maps to SUPPLY = `"FAIL"` and increments `failed` (`:5593-5597`). `failed > 0` ⟹ exit 1. Note in particular that **UNVERIFIABLE never becomes PASS** — a daemon that *refuses* to let the supply be verified yields FAIL, not a silent pass.

- **SUPPLY itself throws into the audit.** `cmd_supply_trustless` catches its own exceptions (`:4629-4632`, returning 1), so the audit's `rc` capture (`:5591`) sees `rc == 1` → FAIL. Even were a future exception to escape, the audit invokes the sub-command outside any swallowing `try` at that level, so an escaped throw propagates to `main`'s top-level `catch` (`light/main.cpp:5690-5693`, `return 2`) — a non-zero exit, still not a PASS. The RAII guard (AC-2(b)) ensures `cout` is restored on that unwind.

- **Argument / precondition faults.** Missing `--rpc-port`/`--genesis` or an unknown arg → `return 1` before any check runs (`:5528-5536`).

In every pathway the result is a non-zero exit and no `AUDIT: PASS`. There is no code path that emits `overall = true` while any component is in error: `overall` is `failed == 0`, and each error path increments `failed` (or returns early non-zero). AC-3 holds.   ∎

### 3.4 AC-4 (SKIP semantics)

**Statement.** (i) A CHAIN failure short-circuits SUPPLY to **SKIP** — not PASS, not silent — and (ii) a pre-S-033 chain (empty head `state_root`) is **reported, not failed**, by the audit's head-state-root line. Neither path can mask a real failure nor manufacture a PASS.

**Proof of (i) — CHAIN failure ⟹ SUPPLY = SKIP, soundly.** The SUPPLY check is gated on `checks[0].verdict == "PASS"` (`:5575`). If CHAIN failed, the `else` branch (`:5598-5601`) pushes SUPPLY = `"SKIP"` with detail `"CHAIN failed — not attempted"` and increments `skipped` (not `failed`, not `passed`). Two consequences:

- **SKIP is not PASS.** `overall = (failed == 0)`. A SKIP leaves `failed` unchanged, but the CHAIN failure that *caused* the skip already incremented `failed` to ≥ 1 (AC-3). So `overall = false` and the audit exits 1 regardless of the skipped SUPPLY. A skip can never turn a failed CHAIN into an `AUDIT: PASS`.

- **SKIP is not silent.** The SKIP verdict + its reason are recorded in `checks[1]` and surfaced in *both* output modes — the JSON `checks[]` array (`:5612-5617`) and the human summary table (`:5621-5627`). The operator sees `SUPPLY  SKIP  (CHAIN failed — not attempted)`, never a missing or implied-pass row.

The short-circuit is *sound by design*: SUPPLY's own soundness (SU-1) requires a committee-anchored head `state_root`, which it obtains by re-running `verify_chain_to_head` internally (`light/main.cpp:4318`). If CHAIN already failed, that internal re-run would fail too — so running SUPPLY would at best reproduce the failure and at worst waste the round-trips. Skipping it is the honest choice: the audit reports "could not get to SUPPLY because the chain itself didn't verify," not a fabricated supply verdict. SUPPLY is therefore **attempted only if CHAIN passes; on CHAIN failure SUPPLY is SKIP, never PASS**.

**Proof of (ii) — pre-S-033 head reported, not failed.** A chain that has not activated S-033 + S-038 carries an empty `state_root` on its head header (`StateRootAnchorSoundness.md` SR-5; `verify_block_sigs` leaves `state_root_hex` empty when the field is zero). The audit captures this as `head_state_root = vc.head_state_root` (`:5556`), which may be `""`. The CHAIN check itself does **not** fail on an empty head `state_root` — `verify_chain_to_head` validates genesis + continuity + committee sigs, none of which require a non-zero `state_root`; a pre-S-033 chain with valid sigs yields CHAIN = PASS. The empty root is *reported*: the human path prints `head state_root: (pre-S-033 / not populated)` (`:5628-5631`) and the JSON path emits `"head_state_root": ""` (`:5611`). Two soundness points:

- **The report does not manufacture a PASS.** It is a presentational field, read-only over `head_state_root` (AC-2(a)); it does not touch `passed`/`failed`. Reporting an empty root cannot flip the verdict.
- **It does not mask a SUPPLY failure.** On a pre-S-033 chain, *if* CHAIN passes, SUPPLY is still attempted (CHAIN = PASS), and `cmd_supply_trustless` itself throws `"chain has not activated state_root (S-033)"` when `vc.head_state_root.empty()` (`light/main.cpp:4319-4324`), returning 1 → SUPPLY = FAIL → `AUDIT: FAIL`. So a pre-S-033 chain does *not* yield a misleading PASS: CHAIN may pass (the chain is genuinely a valid pre-S-033 chain) but SUPPLY fails closed because there is no committed state to anchor the counter proofs against. The empty-root *report* is the honest disclosure of *why* SUPPLY failed, consistent with SR-5's "report the absence rather than emit a meaningless root."

Hence neither SKIP nor the pre-S-033 report can mask a real failure or manufacture a PASS. AC-4 holds.   ∎

### 3.5 AC-E (composition error bound)

**Statement.** The audit's soundness error is bounded by the **maximum of its two components' bounds** — it adds no independent cryptographic term:

$$
\Pr[\text{AUDIT} = \text{PASS} \ \wedge\ \neg(\text{CHAIN sound} \wedge \text{SUPPLY sound})]
\;\le\; \Pr[\text{CHAIN unsound}] + \Pr[\text{SUPPLY unsound}]
\;\le\; 2 \cdot \max\big(\,\varepsilon_{\text{CHAIN}},\ \varepsilon_{\text{SUPPLY}}\,\big),
$$

which for practical chains is the **`2⁻⁹²`-class** bound the cited proofs use.

**Derivation.** `AUDIT = PASS` requires CHAIN = PASS *and* SUPPLY = PASS (AC-1). The event "AUDIT passes yet a component is unsound" is contained in "(CHAIN passes yet CHAIN unsound) ∨ (SUPPLY passes yet SUPPLY unsound)"; by the union bound it is `≤ Pr[CHAIN unsound] + Pr[SUPPLY unsound]`. The component bounds, taken from the cited proofs:

- **εCHAIN.** `verify_chain_to_head` is the `verify-chain` composite; its per-invocation soundness is the T-L1 + T-L2 + continuity union over the walk: `≤ (vc.height) · K · 2⁻¹²⁸ + 2⁻¹²⁸` (the `Safety.md` §7 T-1.2 / `LightClientThreatModel.md` T-L2 cumulative-over-blocks bound). For practical chains (`vc.height ≤ 2³²`, `K ≤ 16`) this is `≤ 2⁻⁹²`, matching the T-L4 dominant term.
- **εSUPPLY.** Corollary SU-E: `≤ (vc.height + 2) · K · 2⁻¹²⁸ + 5 · log₂(n) · 2⁻¹²⁸ ≤ 2⁻⁹²` for `vc.height ≤ 2³²`, `K ≤ 16`, `n ≤ 2⁶⁴` (`SupplyProofSoundness.md §4.5`).

Both are dominated by the same `≤ 2⁻⁹²`-class header-walk term (the audit's two components walk the *same* header chain, so εCHAIN and εSUPPLY share their dominant factor; the supply read adds only the small `5 · log₂(n)` Merkle term). Therefore

$$
\Pr[\text{AUDIT falsely PASS}] \;\le\; \varepsilon_{\text{CHAIN}} + \varepsilon_{\text{SUPPLY}} \;\le\; 2 \cdot \max(\varepsilon_{\text{CHAIN}}, \varepsilon_{\text{SUPPLY}}) \;\le\; 2^{-91},
$$

i.e. the audit's bound is, up to the factor-of-2 union over two reads, exactly the `2⁻⁹²`-class bound of the cited proofs. The audit contributes **no new cryptographic term** — consistent with AC-2 (orchestration only): the streambuf relocation, the conjunction, and the SKIP logic are all probability-1 deterministic operations.   ∎

---

## 4. Composition with companion proofs

### 4.1 `LightClientThreatModel.md` + `Safety.md` §7 — the CHAIN conjunct

CHAIN *is* the `verify-chain` flow under `A_daemon`. T-L1 (genesis anchor, assumption A2/A3) + T-L2 (per-block K-of-K committee sigs, assumption A1) + the prev_hash-continuity walk compose into "genuinely-continuous, committee-signed chain from the pinned genesis," which `Safety.md` §7 packages as the light-client safety composition **T-1.2** (and **Corollary T-1.2.1** = fail-closed exit, which AC-3 instantiates for the CHAIN block). The audit consumes T-1.2 as a black box: it calls `verify_chain_to_head` and treats its non-throwing return as CHAIN = PASS. AC-1 does not re-prove T-1.2; it cites it.

### 4.2 `SupplyProofSoundness.md` — the SUPPLY conjunct

SUPPLY *is* `cmd_supply_trustless`, whose soundness is `SupplyProofSoundness.md` Corollary SU-E (SU-1 committee-anchored root + SU-2 `k:c:` Merkle inclusion ×5 + SU-3 A1-identity recompute + SU-4 `leaf_count` root-wrapper binding). The audit maps SU-E's `CONSERVED` verdict (exit 0) to SUPPLY = PASS and SU-E's UNVERIFIABLE/VIOLATED verdicts (exit 3/2) to SUPPLY = FAIL. SU-3's cross-counter A1-identity recompute is *the* property that makes SUPPLY a meaningful "supply conserved" check rather than five disjoint leaf reads — and the audit surfaces it as the single SUPPLY verdict. The audit inherits SU-E's bound (§AC-E) and its UNVERIFIABLE conditions (§findings F-A2).

### 4.3 `StateRootAnchorSoundness.md` — the head-state-root report (SR-5)

The audit's `head_state_root` capture/report (AC-4(ii)) rests on `StateRootAnchorSoundness.md` SR-1 (a committee-verified head `state_root` is committee-anchored via the transitive-forward `block_hash(h)=prev_hash(h+1)∈digest(h+1)` link) and SR-5 (pre-S-033 vacuity honesty — report the absence of a `state_root` rather than emit a meaningless zero). The audit's `(pre-S-033 / not populated)` line is the audit-level instance of SR-5's disclosure discipline. The audit does not itself *verify* the head root against a successor (it only reports the field captured by `verify_chain_to_head`); the SUPPLY component is what consumes the committee-anchored root for the counter proofs (SU-1), and SUPPLY fails closed on an empty one (AC-4(ii)).

### 4.4 `LightClientCompositionMap.md` — a new lattice consumer

The audit is a new operator-facing consumer of two existing lattice nodes (the `verify-chain` / T-L2 node and the `supply-trustless` / SU-E node). It introduces no new lattice node and no new edge into the {assumption A1, A2} spine — it sits *above* both nodes as a conjunction. The four consolidated shared limitations of `LightClientCompositionMap.md §6` (single-daemon, static `K_0`, head-only state-proof RPC, pre-S-033 vacuity) all apply to the audit verbatim, inherited through its two components; §findings restates the load-bearing ones.

---

## 5. Findings (honest limitations)

These limitations are stated honestly so an operator knows exactly what an `AUDIT: PASS` does and does not assert. None undermines the per-invocation soundness of AC-1; all are coverage/scope statements or inherited component limitations.

### F-A1 The audit covers chain + supply ONLY — not per-account / DApp / receipt / merge / param membership

An `AUDIT: PASS` asserts (CHAIN) the chain is genuinely continuous + committee-signed from the pinned genesis to head, and (SUPPLY) the A1 supply counters are committee-committed + conserved. It does **not** assert anything about any individual account's balance/nonce, any DApp registration, any transaction's inclusion, any cross-shard receipt, any merge-state record, or any parameter value. Each of those has its **own** `determ-light verify-*` subcommand with its own soundness proof:

| What audit does NOT cover | Dedicated command | Proof |
|---|---|---|
| Per-account balance/nonce point or trajectory | `balance-trustless` / `nonce-trustless` / `account-history` / `verify-account` | `LightClientThreatModel.md` T-L4 / `AccountHistorySoundness.md` AH-1..AH-4 |
| Transaction inclusion in a block | `verify-tx-inclusion` | `TxInclusionProofSoundness.md` TI-1..TI-4 |
| Cross-shard receipt inclusion | `verify-receipt-inclusion` | (F-track receipt-inclusion proof) |
| Merge-state record | `verify-merge-state` | (F-track merge proof) |
| Parameter change / value | `verify-param-change` / `verify-param-value` | (F-track param proof) |
| DApp registration | `verify-dapp-registration` | (F-track DApp proof) |

The audit is deliberately a **node-health composite** (is this daemon serving a real, committee-signed, supply-consistent chain?), not a full state-membership audit. An operator wanting membership assurances runs the relevant `verify-*` command separately.

### F-A2 SUPPLY inherits `SupplyProofSoundness.md`'s own UNVERIFIABLE conditions

The SUPPLY check is exactly `cmd_supply_trustless`, so it inherits every UNVERIFIABLE condition of `SupplyProofSoundness.md` verbatim. A daemon can drive SUPPLY to FAIL-via-UNVERIFIABLE (exit 3) by, e.g., refusing a `c:` state-proof for a counter, serving a split-root read (different `state_root` per counter), or returning a `chain_summary` counter whose `SHA256(u64_be(value))` does not match the proof's committed `value_hash`. These are **not** false-PASS risks (UNVERIFIABLE → FAIL by AC-3), but they mean an `AUDIT: PASS` is *conditional* on the daemon being willing and able to serve verifiable `c:` proofs — a daemon that simply *won't* prove its supply yields FAIL, not a downgrade. Additionally, SUPPLY's SU-3 checks only the *counter-identity* `expected_total = genesis_total + Σsubsidy + Σinbound − Σslashed − Σoutbound`; it does **not** confirm this equals `live_total_supply()` (the sum over every `a:`/`s:` leaf), because the audit does not enumerate the account set (`SupplyProofSoundness.md §6.1`). A PASS asserts the *counter half* of the A1 identity is committee-committed and internally consistent, not the full live-supply equation (which is the chain's own apply-tail guarantee, enforced on full nodes).

### F-A3 CHAIN's mid-chain REGISTER/DEREGISTER coverage is bounded by `verify_chain_to_head`'s committee-seed limitation

CHAIN's `verify_chain_to_head` seeds its committee map *only* from genesis `initial_creators` via `build_genesis_committee` and does **not** thread mid-chain REGISTER/DEREGISTER (`light/trustless_read.hpp:70-75`; `LightClientCompositionMap.md §6.2`). On a chain whose committee rotated post-genesis, the walk **fails closed** at the first block signed by a creator outside `K_0` (`"creator '<domain>' is not in the supplied committee"`), yielding CHAIN = FAIL (and hence SUPPLY = SKIP, AUDIT = FAIL). This is a *safe* failure — the audit never accepts an under-verified block — but it means the audit is sound **out of the box only for committee-stable ranges**: on a rotated chain, an honest daemon serving a genuinely-valid rotated chain still produces `AUDIT: FAIL` unless the operator pre-populates the committee seed with every encountered creator. This is the standard static-`K_0` light-client limitation, applied to the audit's CHAIN conjunct; it is a coverage boundary, not a soundness break (it can only cause a false FAIL, never a false PASS).

### F-A4 Single-daemon, no persistence (inherited)

The audit talks to ONE daemon in ONE shot. A truncated-tip or stalling daemon is detected only as fail-closed (an *availability* failure surfaced as FAIL), not as "this daemon is wrong; daemon-B is right" (`LightClientThreatModel.md` F-4 / `LightClientCompositionMap.md §6.1`). Each invocation re-anchors from genesis and re-walks the chain twice (once for CHAIN, once inside SUPPLY) — O(height) sig-verifies, no caching. Neither affects soundness; both are the medium-tier scope the light-client family declares.

---

## 6. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Component | File:lines | Role |
|---|---|---|---|
| AC-1 | `cmd_audit` aggregate verdict | `light/main.cpp:5603, :5636` | `overall = (failed == 0)`; `return overall ? 0 : 1`. |
| AC-1 (CHAIN) | CHAIN block | `light/main.cpp:5542-5569` | `anchor_genesis` (T-L1) + `verify_chain_to_head` (T-L2 + continuity); captures `vc.head_state_root`. |
| AC-1 (CHAIN) | `verify_chain_to_head` | `light/trustless_read.cpp:81-186` | The `verify-chain` composite the audit calls directly (so it can also read the head `state_root` for the report). |
| AC-1 (CHAIN) | `anchor_genesis` | `light/trustless_read.cpp:52-79` | T-L1 genesis pin (`compute_genesis_hash` byte-compare). |
| AC-1 (SUPPLY) | SUPPLY block | `light/main.cpp:5571-5601` | Invokes `cmd_supply_trustless`; `rc == 0` → PASS, non-zero → FAIL, CHAIN-fail → SKIP. |
| AC-1 (SUPPLY) | `cmd_supply_trustless` | `light/main.cpp:4268-4633` | SU-E supply read; exit 0=CONSERVED, 2=VIOLATED, 3=UNVERIFIABLE, 1=fault (`:4622-4632`). |
| AC-2(a) | exit-code path | `light/main.cpp:5603, :5636` | Exit code is a pure function of `passed`/`failed`/`skipped`. |
| AC-2(b) | `RdbufGuard` + `sink` | `light/main.cpp:5580-5592` | RAII streambuf relocation in `--json` mode; guard declared after `sink` for unwind-safe restore. |
| AC-3 | CHAIN `try`/`catch` | `light/main.cpp:5549-5568` | Catches every `std::exception` → CHAIN = FAIL → exit 1. |
| AC-3 | SUPPLY non-zero → FAIL | `light/main.cpp:5593-5597` | UNVERIFIABLE/VIOLATED/fault all increment `failed`. |
| AC-3 | top-level catch | `light/main.cpp:5690-5693` | An escaped throw → `return 2` (non-zero, never PASS). |
| AC-4(i) | SKIP branch | `light/main.cpp:5575, :5598-5601` | CHAIN-fail short-circuits SUPPLY to SKIP (increments `skipped`, not `failed`). |
| AC-4(ii) | head-state-root report | `light/main.cpp:5556, :5611, :5628-5631` | Captures + reports `head_state_root`; `(pre-S-033 / not populated)` when empty. |
| AC-4(ii) | SUPPLY pre-S-033 throw | `light/main.cpp:4319-4324` | `cmd_supply_trustless` throws `"chain has not activated state_root (S-033)"` on empty head root → SUPPLY = FAIL. |
| AC-E | (no new term) | — | Bound = `εCHAIN + εSUPPLY ≤ 2·max(·) ≤ 2⁻⁹¹`; cited from the component proofs. |
| — | dispatcher | `light/main.cpp:5664` | `if (cmd == "audit") return cmd_audit(...)`. |

**Tests** (the audit composes already-tested primitives; an end-to-end audit script exercises the conjunction + SKIP + pre-S-033 paths):

| Test | Coverage |
|---|---|
| `tools/test_light_verify_chain.sh` | CHAIN conjunct (T-L2 composite; bad block at height N → FAIL). |
| `tools/test_light_supply_trustless.sh` | SUPPLY conjunct (SU-E; tampered counter → UNVERIFIABLE). |
| `tools/test_light_genesis_anchor.sh` | T-L1 (wrong `--genesis` → CHAIN fails → AUDIT FAIL). |
| `tools/test_light_audit.sh` | AC-1..AC-4 end-to-end — happy path PASS; CHAIN-fail → SUPPLY SKIP + AUDIT FAIL; pre-S-033 chain → head reported + SUPPLY FAIL; `--json` aggregate shape. |

---

## 7. Status

- **Implementation.** `determ-light audit` shipped in `light/main.cpp::cmd_audit` (`:5518`, dispatched `:5664`). Composes `anchor_genesis` + `verify_chain_to_head` (CHAIN) and `cmd_supply_trustless` (SUPPLY), conjoins via `failed == 0`, exits `0`/`1`.
- **Proof.** Complete (this document). AC-1 (composite soundness = conjunction of CHAIN + SUPPLY, reducing to T-L1/T-L2 + `Safety.md` §7 T-1.2 and `SupplyProofSoundness.md` SU-E, under assumption A1 + A2); AC-2 (no added trust surface — orchestration only; faithful exit code + verdict-neutral, RAII-restored streambuf redirect); AC-3 (fail-closed — every error/UNVERIFIABLE/exception → AUDIT FAIL, never a false PASS); AC-4 (SKIP semantics — CHAIN-fail short-circuits SUPPLY to SKIP not PASS not silent; pre-S-033 head reported not failed; neither masks a failure nor manufactures a PASS). Composition bound AC-E (`≤ 2·max(εCHAIN, εSUPPLY)`, the `2⁻⁹²`-class bound; no new cryptographic term).
- **Cryptographic assumptions used.** assumption A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision resistance); A3 inherited only via T-L1's genesis-anchor Case 2; A4 not used. Per `Preliminaries.md §2.0`.
- **Adversary model.** `A_daemon` (malicious single daemon). Out of scope: `A_crypto`, `A_local`, `A_net`, `A_genesis` (inherited from `LightClientThreatModel.md §2.2`).
- **Composes with.** `LightClientThreatModel.md` (T-L1/T-L2/L-6 + `A_daemon`), `Safety.md` (§7 T-1.2 + Corollary T-1.2.1), `SupplyProofSoundness.md` (SU-1/SU-2/SU-3/SU-4/SU-E), `StateRootAnchorSoundness.md` (SR-1/SR-5 — the head-root report basis), `LightClientCompositionMap.md` (the family lattice + §6 shared limitations), `EconomicSoundness.md` T-12 + `AccountStateInvariants.md` I-6 (the A1 supply identity SUPPLY's SU-3 re-checks).
- **Known limitations (§findings).** F-A1 (covers chain + supply only — not per-account/DApp/receipt/merge/param membership, each with its own `verify-*` command); F-A2 (SUPPLY inherits `SupplyProofSoundness.md`'s UNVERIFIABLE conditions + the counter-vs-live-supply boundary); F-A3 (CHAIN's mid-chain REGISTER/DEREGISTER coverage bounded by `verify_chain_to_head`'s genesis-only committee-seed limitation — can cause a false FAIL on a rotated chain, never a false PASS); F-A4 (single-daemon, no persistence — inherited). None undermines the per-invocation soundness of AC-1.
- **The orchestration-only posture (load-bearing).** The audit adds NO new verification logic. AC-2 formalizes that its exit code is a faithful function of the two component verdicts and that the `--json` streambuf redirect only relocates output bytes (RAII-restored, even under exception) and cannot touch any verdict. Soundness is therefore *exactly* the conjunction of CHAIN (T-L1/T-L2/T-1.2) and SUPPLY (SU-E) — there is nothing cryptographic to prove anew, which is precisely why AC-E carries no independent term.

---
