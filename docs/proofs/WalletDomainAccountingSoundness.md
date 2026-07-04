# WalletDomainAccountingSoundness — per-domain tx-flow accounting soundness (`determ-wallet account-accounting`)

Status: SHIPPED (R57) — soundness of the `determ-wallet` per-domain accounting read.

This document formalizes the design contract of the **`account-accounting` subcommand** of the `determ-wallet` binary (R57). The subcommand is a **read-only client-side accounting tool**: it walks the chain via the `block` RPC, classifies each included transaction's effect on a single target domain `D`, tallies the per-category flows, and cross-checks the summed **tx-flow net** against the **authoritative balance** obtained from the `balance` / `stake_info` RPCs. It **does not re-derive** the consensus balance — the authoritative figure is the daemon's (or, for a trust-minimized read, the light client's), and the tally is *bookkeeping over transaction fields*, surfaced alongside a residual `non_tx_delta` that isolates exactly what the domain's own transactions explain from what they do not.

The claim worth proving — and the reason this proof exists — is **not** cryptographic (the command introduces no new primitive and re-derives no committed state). It is a **classification-correctness + accounting-identity** contract:

> Each accounting category the command reports corresponds *exactly* to the balance effect the chain's own apply layer (`src/chain/chain.cpp` `apply_transactions`) produces for that transaction type and role; the reported `tx_flow_net` is an exact sum of transaction fields for the included transactions; and the reconciliation identity `authoritative_balance = genesis_opening + tx_flow_net + non_tx_income` holds by summation over the walked range, with the residual `non_tx_delta := authoritative_balance − tx_flow_net` being a *diagnostic surface* (block-creator income, first-register NEF credits, inbound cross-shard receipts, and assume-applied over-counts), **not** an error.

The proof is deliberately honest about four non-claims (§2.4, WA-5): it is **not** a consensus-balance re-derivation; it is **assume-applied** (an included-but-skipped transaction or a failed UNSTAKE is absorbed into `non_tx_delta`); it is a **single-shard view** (cross-shard credits arrive as receipts on the *destination* shard, outside this walk); and subsidy / fee / NEF income is **intentionally not reconstructed** (it lives in `non_tx_delta`; `blocks_produced` is the informational hook). For a plain user domain — never a block creator, all its transactions applied, single shard — `non_tx_delta` collapses to `genesis_opening` and the identity closes exactly (WA-3).

**Companion documents.** `AccountHistorySoundness.md` (the closest sibling — the `determ-light account-history` trajectory read; this document is its *tx-flow-accounting* analog, one axis over: `account-history` proves the *committed* `(balance, nonce)` at sampled heights, `account-accounting` explains *how the balance got there* from the domain's own tx flow, and both share the sample-vs-complete honesty discipline); `OperatorToolingReadOnly.md` (the read-only meta-proof whose RPC read/mutate partition — §2.2 / §2.3 — this command composes: it issues only `block` / `status` / `balance` / `stake_info` reads, never one of the six mutating verbs); `SupplyProofSoundness.md` (the `c:`-counter read whose SU-3 *cross-counter identity recompute* is the structural cousin of WA-3's reconciliation identity — both let a client recompute a closed-form accounting relation over values it does not re-derive from scratch); `S033StateRootNamespaceCoverage.md` (the `a:`-namespace balance encoding the authoritative RPC exposes); `EconomicSoundness.md` (FA11 / T-12, the chain-side A1 unitary-supply identity that makes the block-level subsidy+fee distribution a *conserved transfer*, not a mint the tally must chase); `AccountStateInvariants.md` (FA-Apply-1 — the per-account apply invariants each per-tx effect obeys). Wallet command + test: `determ-wallet account-accounting` and `tools/test_wallet_account_accounting.sh` (both landing in parallel with this proof).

---

## 1. Scope

### 1.1 In scope

The `determ-wallet account-accounting` subcommand, which for a target domain `D` over a walked block range `[0, head]`:

1. **Walks the chain** by issuing `block` RPC reads (`Node::rpc_block`, `src/node/node.cpp`) for each block index in `[0, head]`, obtaining the full block body (transactions + creators + block-level fields).
2. **Classifies each included transaction's effect on `D`** by transaction type and `D`'s role (`from == D` sender, `to == D` receiver), per the per-tx effect table of §3 read off `src/chain/chain.cpp` `apply_transactions`.
3. **Tallies the seven accounting quantities** of §3.2 (`credits_received`, `debits_sent`, `staked`, `unstaked`, `fees_paid`, `blocks_produced`, and the derived `tx_flow_net`). (`dapp_spend` was removed in the R61 shrink — WA-2.)
4. **Fetches the authoritative balance** via the `balance` RPC (`Node::rpc_balance`, `src/node/node.cpp`) and the locked-stake figure via `stake_info` — the values consensus actually holds for `D`.
5. **Reports** `tx_flow_net` exactly (a pure summation of tx fields) and surfaces the residual `non_tx_delta := authoritative_balance − tx_flow_net`, so a reader sees precisely what `D`'s own transactions explain versus what they do not.

The command is a **client-side accounting view**, not a verifier of the chain's arithmetic: it consumes the authoritative balance as ground truth and explains as much of it as the domain's own transaction flow accounts for.

### 1.2 Out of scope (intentional — the four non-claims, formalized in WA-5)

- **Consensus-balance re-derivation.** The command does **not** recompute `D`'s balance from the chain; the authoritative figure is the RPC's (`rpc_balance` → `chain_.balance_lockfree(domain)`, `src/node/node.cpp`). The tally is bookkeeping over tx flows. (WA-5 (1).)
- **Apply-exactness of every included tx.** The tally is **assume-applied** — each included transaction is counted as if it applied as signed. Two documented cases violate this and are absorbed into `non_tx_delta`: an included transaction skipped at apply for insufficient balance (`continue` in the `apply_transactions` switch), and a failed UNSTAKE whose fee is refunded (net-zero, not the net `−fee` the naive tally would assign). (WA-5 (2), WA-2.)
- **Single-shard view.** The tool walks one shard's blocks and holds no shard geometry, so it credits `to` for every same-shard-looking `TRANSFER`. On a **single-shard chain** (`shard_count ≤ 1`, the default) this is exact — there are no cross-shard transfers. On a **multi-shard chain** it is **out of scope**: a cross-shard `TRANSFER`'s recipient credit is actually delivered off-shard (`b.inbound_receipts` on the destination shard), so the tool would credit a recipient on the wrong shard. The command does not claim multi-shard correctness; run it per-shard against each shard's own daemon. (WA-5 (3).) *(The R61 shrink already removed the DAPP_CALL credit and `dapp_spend`, so this single-shard-scope caveat is the only receiver-side limitation that remains.)*
- **Subsidy / fee / NEF income reconstruction.** Block-creator income (subsidy + fee distribution), first-register negative-entry-fee (NEF) credits, and inbound cross-shard receipts are **intentionally not reconstructed** by the tally; they compose `non_tx_delta`. `blocks_produced` is the informational hook that explains the creator-income portion. (WA-5 (4), WA-4.)

---

## 2. Contract model

### 2.1 The accounting object

Fix a target domain `D` and a walk over block range `[0, head]`. Let `T_D` denote the set of transactions in walked blocks with `D` in the `from` or `to` role, and let `C_D` denote the set of walked blocks with `D ∈ block.creators`. The command computes the eight quantities of §3.2 by summing transaction fields over `T_D` and counting over `C_D`, and fetches the authoritative balance `authoritative_balance` via the `balance` RPC.

### 2.2 The soundness predicates

Three predicates constitute the contract:

- **P1 (classification correctness, WA-1).** For each transaction `tx ∈ T_D` and each accounting category, `tx` is placed in the category whose definition matches the balance effect `apply_transactions` produces for `tx`'s type and `D`'s role.
- **P2 (tx-flow-net soundness, WA-2).** `tx_flow_net` equals the exact signed sum of `D`'s transaction-field flows over `T_D` under the assume-applied premise, with the two premise-violating cases (§1.2) isolated into `non_tx_delta`.
- **P3 (reconciliation identity, WA-3).** `authoritative_balance = genesis_opening + tx_flow_net + non_tx_income`, where `non_tx_income` aggregates block-creator income, NEF credits, inbound cross-shard receipts, and the assume-applied over-count correction; equivalently `non_tx_delta := authoritative_balance − tx_flow_net = genesis_opening + non_tx_income'` where `non_tx_income'` is the non-genesis part.

### 2.3 Trust model (read-only, no re-derivation)

The command is **read-only** in the sense of `OperatorToolingReadOnly.md` §2.3: the set of RPC methods it reaches — `block`, `status` (head discovery), `balance`, `stake_info` — is a subset of the daemon's *read* partition (`OperatorToolingReadOnly.md` §2.2 enumerates the six *mutating* methods; `account-accounting` invokes none of them). It appends no transaction, stages no evidence, and mutates no state. Its correctness rests on **no cryptographic assumption of its own**: the authoritative balance is the RPC's (a daemon that lies about it is a daemon-trust question orthogonal to this contract — for a trust-minimized authoritative read the operator uses the `determ-light` balance-trustless path of `AccountHistorySoundness.md` AH-1, which this command is agnostic to), and the tally is a deterministic function of the walked block bodies.

### 2.4 The four non-claims (the honesty core)

Restated compactly (proved in WA-5):

1. **Not a consensus re-derivation** — authoritative balance is the RPC's; the tally is tx-flow bookkeeping.
2. **Assume-applied** — an insufficient-balance apply-skip or a failed UNSTAKE fee-refund is absorbed into `non_tx_delta`, not modeled by the tally.
3. **Single-shard view** — cross-shard credits arrive as receipts on the destination shard, outside this walk.
4. **Subsidy/fee/NEF not reconstructed** — creator income + NEF + receipts live in `non_tx_delta`; `blocks_produced` is the informational hook.

For a plain user domain (never a creator, all txs applied, single shard), `non_tx_delta == genesis_opening` and the identity closes exactly (WA-3).

---

## 3. Per-transaction effect on a domain (read off `apply_transactions`)

The following per-type effects are verified byte-for-byte against `src/chain/chain.cpp` `apply_transactions` (each `case TxType::…` of the tx switch, plus the block-level distribution tail). They are the ground truth WA-1 maps each accounting category onto. Cited by file, no line numbers per repo citation discipline.

### 3.1 Per-type / per-role effect table

| TxType | Role | Balance effect in `apply_transactions` (`src/chain/chain.cpp`) | Accounting category |
|---|---|---|---|
| TRANSFER | `from == D` | `sender.balance -= (amount + fee)`. Same-shard: `to` credited `+= amount`. Cross-shard: `to` credited on the **other** shard via a receipt (`block_outbound += amount`), not in this block. | `debits_sent += amount`; `fees_paid += fee` |
| TRANSFER | `to == D` (same-shard) | `accounts_[to].balance += amount` (overflow-checked). | `credits_received += amount` |
| STAKE | `from == D` | `sender.balance -= (amount + fee)`; `stakes_[from].locked += amount`. | `staked += amount`; `fees_paid += fee` |
| UNSTAKE | `from == D` | On success: fee charged (`charge_fee`), then `sender.balance += amount`, `locked -= amount` (net `+amount − fee`). On FAILURE (too-early: `height < unlock_height`, or `locked < amount`): fee is REFUNDED (`sender.balance += fee; total_fees -= fee`) → net 0. | `unstaked += amount`; `fees_paid += fee` (see WA-2 refund caveat) |
| REGISTER | `from == D` | `charge_fee(sender, fee)` → `sender.balance -= fee`. FIRST-time registration may additionally CREDIT a negative-entry-fee = half the Zeroth-pool balance (`accounts_[from].balance += nef`), not visible from the tx itself. | `fees_paid += fee` (NEF → `non_tx_delta`) |
| DEREGISTER | `from == D` | `charge_fee(sender, fee)` → `sender.balance -= fee`. | `fees_paid += fee` |
| PARAM_CHANGE | `from == D` | `charge_fee(sender, fee)` → `sender.balance -= fee`. | `fees_paid += fee` |
| MERGE_EVENT | `from == D` | `charge_fee(sender, fee)` → `sender.balance -= fee`. | `fees_paid += fee` |
| DAPP_CALL | `from == D` | chain (active DApp): `sender.balance -= (amount + fee)`; or (no-op) charges fee only. | `fees_paid += fee` only — the **amount is NOT tallied** (R61 shrink; folds into `non_tx_delta`). |
| DAPP_CALL | `to == D` | `accounts_[to].balance += amount` (active DApp). | **not tallied** (R61 shrink; the wallet can't confirm the DApp was active — folds into `non_tx_delta`). |
| (block-level, non-tx) | `D ∈ block.creators` | `total_distributed = total_fees + subsidy_this_block`; `per_creator = total_distributed / m`; each creator `+= per_creator`; dust `remainder` (`total_distributed % m`) to `creators[0]`. | `blocks_produced += 1` (income → `non_tx_delta`) |

**Verification note.** Every row above was confirmed against `apply_transactions` in `src/chain/chain.cpp`: the TRANSFER same-shard credit / cross-shard `block_outbound` split; the STAKE `locked += amount` with combined `amount + fee` debit; the UNSTAKE success-vs-failure branch with the explicit fee refund on the too-early / insufficient-locked path; the REGISTER first-time NEF hook crediting `pool_balance / 2`; the fee-only `charge_fee` path shared by DEREGISTER / PARAM_CHANGE / MERGE_EVENT; the DAPP_CALL debit/credit mirroring TRANSFER's same-shard leg; and the block-tail even split of `total_fees + subsidy_this_block` across `creators` with dust to `creators[0]`. **No rule in the R57 contract required correction — the table matches the code as written.**

### 3.2 The accounting tally (tx-flow, assume-applied)

Each included transaction is counted as if it applied as signed. The validator gates most failure modes upstream (nonce, signature, structural checks), so under the common case this is exact; the two residual apply-time skips are handled by WA-2.

```
  credits_received = Σ amount over TRANSFER             with to == D (same-shard)
  debits_sent      = Σ amount over TRANSFER            with from == D
  staked           = Σ amount over STAKE              with from == D
  unstaked         = Σ amount over UNSTAKE            with from == D
  fees_paid        = Σ fee    over ALL tx             with from == D
  blocks_produced  = count of walked blocks with D ∈ block.creators   (informational)

  tx_flow_net = credits_received + unstaked
              − debits_sent − staked − fees_paid
```

**Amount source per type.** For TRANSFER (0) and DAPP_CALL (10) the moved principal is the tx's `amount` field. For **STAKE (3) and UNSTAKE (4) the `amount` field is 0** — the principal is carried as an 8-byte little-endian `payload` (`chain.cpp:860-863` / `:875-878` decode `Σ payload[i] << 8·i`). The command decodes `staked`/`unstaked` from `payload` byte-identically, so "Σ amount over STAKE/UNSTAKE" above denotes that decoded payload quantity, not the (zero) `amount` field. Reading `amount` for these types would silently tally 0.

`blocks_produced` is **informational** — it does not enter `tx_flow_net`; it explains (in `non_tx_delta`) the creator-income the tally deliberately does not reconstruct (WA-4).

---

## 4. Soundness theorems

Notation: `D` the target domain; `[0, head]` the walked range; `T_D` the `D`-touching transactions; `C_D` the blocks `D` created; `b_D^auth` the authoritative balance from `rpc_balance`; `genesis_opening` = `D`'s balance in the genesis block-0 `initial_state` (0 if `D` was not funded at genesis); the eight tally quantities of §3.2.

### 4.1 Theorem WA-1 (per-tx classification correctness)

**Statement.** For every transaction `tx ∈ T_D`, the accounting category the command assigns `tx` corresponds exactly to the balance effect `apply_transactions` (`src/chain/chain.cpp`) produces for `tx`'s `TxType` and `D`'s role. Formally: the five flow categories (`credits_received`, `debits_sent`, `staked`, `unstaked`, `fees_paid`) partition the tallied part of each transaction's effect on `D`'s balance and locked-stake into the *same* signed contributions the chain applies, per the §3.1 table (the un-tallied DAPP_CALL amount + cross-shard/DApp inbound land in `non_tx_delta` — R61 shrink, WA-2).

**Proof.** By exhaustive case analysis over `TxType`, each case a direct reading of the corresponding `case TxType::…` in `apply_transactions` (`src/chain/chain.cpp`):

- *TRANSFER, `from == D`.* The chain executes `sender.balance -= (amount + fee)`. The command splits this into `debits_sent += amount` (the principal) and `fees_paid += fee` (the fee), whose sum `amount + fee` equals the chain's debit. Same-shard: the chain credits `to += amount`; if `to == D` this is captured by the receiver branch below (a distinct category). Cross-shard: the chain records `block_outbound += amount` and delivers the credit via a receipt on the destination shard — the command's `debits_sent`/`fees_paid` on the sender side is exact; the receiver-side credit is a non-shard-local effect (WA-5 (3)).
- *TRANSFER, `to == D` (same-shard).* The chain credits `accounts_[to].balance += amount`. The command records `credits_received += amount`. Exact.
- *STAKE, `from == D`.* The chain does `sender.balance -= (amount + fee)` and `stakes_[from].locked += amount`. The command records `staked += amount` (the moved principal) + `fees_paid += fee`, whose sum matches the balance debit; the `+amount` to locked stake is tracked separately (surfaced against `stake_info`), so the balance effect and the stake effect are both accounted.
- *UNSTAKE, `from == D`.* On the success path the chain charges the fee (`charge_fee`) then `sender.balance += amount`, `locked -= amount` — net balance `+amount − fee`. The command records `unstaked += amount` (a positive flow) + `fees_paid += fee`. Their signed contribution to `tx_flow_net` is `+amount − fee`, matching. The failure branch (fee refunded, net 0) is the assume-applied caveat of WA-2.
- *REGISTER, `from == D`.* The chain does `charge_fee(sender, fee)` (`sender.balance -= fee`); the command records `fees_paid += fee`. The first-time NEF credit (`accounts_[from].balance += pool/2`) is a *pool-to-domain transfer not encoded in the tx*, so it is not a category — it flows into `non_tx_delta` (WA-4).
- *DEREGISTER / PARAM_CHANGE / MERGE_EVENT, `from == D`.* Each does `charge_fee(sender, fee)` only. The command records `fees_paid += fee`. Exact.
- *DAPP_CALL, `from == D`.* The chain either debits `sender.balance -= (amount + fee)` (active DApp) or charges the fee only (no-op). The command records **only `fees_paid += fee`** (R61 shrink) — the moved `amount`, applied or not, is not tallied and folds into `non_tx_delta`. Exact: the fee is always charged, so `fees_paid` is correct regardless of the DApp's state.
- *DAPP_CALL, `to == D` (same-shard, active DApp).* The chain credits `accounts_[to].balance += amount` (`D` is the DApp). The command records `credits_received += amount`. Exact on the happy path; the fee-only no-op (V3) and cross-shard (V4) cases are assume-applied artifacts (WA-2).

Every transaction category's signed contribution to `D`'s balance in the tally equals the signed balance mutation `apply_transactions` performs for that type+role. The classification is therefore correct by construction (it *is* the code's case table, transcribed). ∎

**Composition note.** WA-1 is a *faithful transcription* claim, not a cryptographic one — it asserts the command's classifier is the `apply_transactions` switch read as an accounting function. The apply-layer invariants those cases maintain (`AccountStateInvariants.md` FA-Apply-1) are consumed, not re-proved.

### 4.2 Theorem WA-2 (tx-flow-net soundness under assume-applied)

**Statement.** Under the **assume-applied** premise — every included transaction is counted as if it applied as signed — `tx_flow_net` (§3.2) equals the exact signed sum of `D`'s transaction-field flows over `T_D`. The premise is violated in exactly two cases (V1, V2 below), each of which the tally over-counts on the `amount` axis and which are therefore absorbed, by construction, into `non_tx_delta`. In both cases the **fee** side is exact (the chain charges the fee), so the discrepancy is confined to the moved principal.

- **(V1) Insufficient-balance apply-skip.** A TRANSFER / STAKE whose `sender.balance < (amount + fee)` at apply time hits `continue` in `apply_transactions` and mutates nothing (balance and nonce unchanged), yet the tally counts its `amount`/`fee`. (The validator normally rejects these before inclusion; the `continue` is the apply-time safety net.)
- **(V2) Failed UNSTAKE fee-refund.** An UNSTAKE that is too-early (`height < unlock_height`) or under-locked (`locked < amount`) refunds the fee (`sender.balance += fee; total_fees -= fee`) — net balance effect 0 — yet the tally counts `unstaked += amount` and `fees_paid += fee` (a net `+amount − fee` flow instead of 0).

**R61 shrink — why there is no V3/V4.** The R60 audit found two further over-count cases: a `DAPP_CALL` fee-only no-op (inactive/unregistered DApp or bad topic/framing — `chain.cpp` charges only the fee) and a cross-shard receiver credit routed off-shard. Rather than add `dapp_registry_` / shard-geometry state to a read-only wallet tool to *detect* them, R61 **stopped tallying the uncertain quantities entirely**: `dapp_spend` was removed (a `DAPP_CALL` now contributes only its always-charged `fee`), and only **same-shard** `TRANSFER` credits `to` (`type == 0`; the DAPP_CALL receiver credit and the cross-shard receiver credit are no longer tallied). The `DAPP_CALL` moved amount and any cross-shard/DApp inbound now fold into `non_tx_delta` by construction — whether the call applied or not — so no over-count is possible from either path. The tally is thus **provably exact modulo V1/V2 on a single-shard chain** (the default; a multi-shard chain is out of scope — non-claim #3). This is a strict simplification: fewer tallied quantities, a smaller proof, and no dependency on chain state the wallet cannot see.

**Proof.** `tx_flow_net` is defined as a pure signed summation of transaction *fields* over `T_D` — `amount`/`fee` for TRANSFER/DAPP_CALL, and the 8-byte little-endian `payload` quantity for STAKE/UNSTAKE (§3.2 amount-source note) — with fixed signs per category (§3.2). Summation of literal tx fields is exact and deterministic — no chain state is consulted, so the tally is a well-defined function of the walked block bodies alone. Hence *given* that every included tx applied as signed, `tx_flow_net` is the exact net of `D`'s tx-driven balance flow.

The assume-applied premise fails only where `apply_transactions` diverges from "applied as signed":

- (V1): the `sender.balance < cost` guard's `continue` (present in the TRANSFER and STAKE cases of `apply_transactions`) skips the whole tx — no debit, no nonce bump. The tally, seeing the tx included, still adds its fields. The over-count is `+(amount + fee)` for a skipped debit-type tx.
- (V2): the UNSTAKE failure branch refunds the fee and applies no principal movement. The tally's `+amount − fee` over-states the true `0`.

The `DAPP_CALL` amount and cross-shard/DApp receiver credits are **not summed at all** (R61 shrink), so they contribute no term to `tx_flow_net` and cannot over-count — they land wholly in `non_tx_delta`.

Because the reconciliation identity (WA-3) defines `non_tx_delta := b_D^auth − tx_flow_net`, and `b_D^auth` reflects the *true* applied state (no phantom debit for V1, no net movement for V2, no amount move for V3/V4), any over-count in `tx_flow_net` appears as an equal, opposite term in `non_tx_delta`. Thus V1–V4 are **not** silent errors — they are exactly the discrepancies the surfaced `non_tx_delta` is designed to expose. The command does not attempt to *detect* V1–V4 from tx history (each depends on apply-time or off-shard state — `unlock_height`/`locked` for V2, `dapp_registry_`/topic state for V3, shard geometry for V4 — none determinable from the walked block bodies alone); it reports `tx_flow_net` honestly as the assume-applied sum and lets `non_tx_delta` carry the residual. The `--help` non-claims and this theorem enumerate all four so an operator reading `non_tx_delta` knows what it may contain. ∎

**Honesty note.** WA-2 is why the command reports `tx_flow_net` **exactly** (a defensible, reproducible number: "the signed sum of these tx fields") rather than a *claimed* balance: the moment it claimed to reconstruct the applied balance, V1/V2 would make it wrong. By separating the exact tx-flow sum from the RPC-authoritative balance and surfacing their difference, the command is correct-by-construction on both halves.

### 4.3 Theorem WA-3 (the reconciliation identity)

**Statement.** For a walk over `[0, head]`,
```
   authoritative_balance = genesis_opening + tx_flow_net + non_tx_income
```
where `non_tx_income` = block-creator subsidy+fee distribution (`∝ blocks_produced`) + first-register NEF credits + inbound cross-shard receipts − the assume-applied over-count (V1/V2 of WA-2). Equivalently, `non_tx_delta := authoritative_balance − tx_flow_net = genesis_opening + non_tx_income`. For a **plain non-creator single-shard domain with all its transactions applied**, every non-genesis term of `non_tx_income` is zero, so `non_tx_delta == genesis_opening` and the identity closes exactly.

**Proof.** `D`'s authoritative balance at `head` is the accumulation, over the applied history, of every mutation `apply_transactions` performs on `accounts_[D].balance` across blocks `0..head`. Partition those mutations by origin:

1. **Genesis.** Block 0 installs `accounts_[D].balance = initial_balance(D)` from `initial_state` (no tx semantics, no fees) — this is `genesis_opening`.
2. **Tx-driven, applied-as-signed.** For each `tx ∈ T_D` that applied as signed, the balance mutation is exactly the signed contribution WA-1 maps to a tally category. Summing these over the applied subset of `T_D` yields the *applied* tx-flow, which equals `tx_flow_net` minus the WA-2 over-count (V1/V2): `tx_flow_applied = tx_flow_net − overcount`.
3. **Block-creator income.** For each block in `C_D`, the tail distributes `per_creator = (total_fees + subsidy_this_block) / m` to `D` (plus dust to `creators[0]` if `D` is `creators[0]`). Summed over `C_D`, this is the creator-income term, `∝ blocks_produced` but not equal to any tx field.
4. **First-register NEF.** If `D`'s first REGISTER drew the negative-entry-fee, `accounts_[D].balance += pool_balance/2` at that block — a pool-to-`D` transfer not in the tx.
5. **Inbound cross-shard receipts.** If `D` received a cross-shard TRANSFER whose home shard is this walk's shard, the `b.inbound_receipts` loop credited `accounts_[D].balance += amount`. (If `D`'s inbound receipts land on a *different* shard, they are outside this walk — WA-5 (3).)

By conservation, `b_D^auth = genesis_opening + tx_flow_applied + creator_income + nef + inbound_receipts`. Substituting `tx_flow_applied = tx_flow_net − overcount` and collecting the non-tx, non-genesis terms into `non_tx_income := creator_income + nef + inbound_receipts − overcount`:
```
   b_D^auth = genesis_opening + tx_flow_net + non_tx_income.
```
This is the identity. Rearranging, `non_tx_delta = b_D^auth − tx_flow_net = genesis_opening + non_tx_income`.

**Plain-domain closure.** For a domain that is never a block creator (`C_D = ∅` ⇒ `creator_income = 0`), never drew NEF (`nef = 0`), received no cross-shard inbound on this shard (`inbound_receipts = 0`), and all of whose transactions applied as signed (`overcount = 0`), every term of `non_tx_income` vanishes, leaving `non_tx_delta = genesis_opening`. If, additionally, `D` was not funded at genesis (`genesis_opening = 0`), then `non_tx_delta = 0` and `b_D^auth = tx_flow_net` exactly — the tally fully explains the balance. ∎

**Relation to SU-3.** This is the tx-flow analog of `SupplyProofSoundness.md` SU-3: there, a client recomputes the closed-form A1 supply identity over five committed counters it does not re-derive; here, a client recomputes the per-domain balance identity over tx fields it walks, against an authoritative balance it does not re-derive. Both are *publicly-recomputable accounting relations* layered over consensus-authoritative inputs — neither re-runs consensus.

### 4.4 Theorem WA-4 (non_tx_delta interpretation — a diagnostic, not an error)

**Statement.** The residual `non_tx_delta := authoritative_balance − tx_flow_net` is a **diagnostic surface**, enumerating exactly the balance components the domain's own transactions do not explain. It contains, additively:

1. `genesis_opening` — `D`'s genesis funding (0 if unfunded at genesis).
2. **Block-creator income** — `Σ_{blocks ∈ C_D} per_creator (+ dust)` = the subsidy+fee distribution `D` earned as a creator, `∝ blocks_produced`. The `blocks_produced` count is the informational hook that *explains* this term without reconstructing its exact value (which needs each block's `total_fees + subsidy_this_block` and creator-set size `m`).
3. **First-register NEF** — `pool_balance/2` credited on `D`'s first REGISTER, if any.
4. **Inbound cross-shard receipts** — home-shard receipt credits to `D` (WA-5 (3) covers the other-shard case).
5. **Assume-applied over-count correction** — the negative of the V1/V2 over-count (WA-2): a positive `non_tx_delta` contribution offsetting the tally's over-statement.

A non-zero `non_tx_delta` is therefore **expected and informative**, not a fault. A reader interprets it as: "of `D`'s authoritative balance, `tx_flow_net` is explained by `D`'s own transactions; `non_tx_delta` is explained by genesis funding, creator income (`blocks_produced` blocks), NEF, cross-shard receipts, and/or assume-applied skips."

**Proof.** By WA-3, `non_tx_delta = genesis_opening + non_tx_income`, and `non_tx_income = creator_income + nef + inbound_receipts − overcount` by construction. Each summand is a well-defined, non-negative (except the over-count correction) balance component with a distinct origin in `apply_transactions` (genesis install; block-tail creator distribution; REGISTER NEF hook; `inbound_receipts` loop; the V1/V2 skip). The enumeration is exhaustive because every mutation of `accounts_[D].balance` in `apply_transactions` is either (a) a tx-driven mutation captured by `tx_flow_net` (WA-1), or (b) one of the five non-tx / genesis origins above — there is no sixth balance-mutation site for a domain in the apply path. Hence `non_tx_delta` is precisely the sum of the non-`tx_flow_net` origins, and reporting it exposes them as a diagnostic. ∎

**Why intentionally not reconstructed.** Reconstructing `creator_income` exactly would require, per block in `C_D`, the block's `total_fees` (sum over *all* senders' fees, not just `D`'s) and `subsidy_this_block` (subject to E3 lottery draw + E4 pool cap) and `m = |creators|` — a re-derivation of the block-tail distribution the command deliberately avoids (it is consensus arithmetic, WA-5 (4)). Surfacing `blocks_produced` gives the reader the hook to explain the creator-income portion of `non_tx_delta` without the command re-running that distribution.

### 4.5 Theorem WA-5 (trust model / non-claims)

**Statement.** The command satisfies the four non-claims of §1.2 / §2.4, is read-only, and does not re-derive consensus balances.

**Proof.**

- **(1) Not a consensus re-derivation.** The authoritative balance enters via `rpc_balance` (→ `chain_.balance_lockfree(domain)`, `src/node/node.cpp`) and `stake_info`; the command never recomputes `D`'s balance from block application. The tally is a deterministic summation over walked tx fields (WA-2). The two are combined only in the *reported difference* `non_tx_delta`, never by the command asserting a re-derived balance. ∎(1)
- **(2) Assume-applied.** Per WA-2, `tx_flow_net` counts included txs as applied-as-signed; the V1 insufficient-balance apply-skip and V2 failed-UNSTAKE fee-refund are absorbed into `non_tx_delta`. Success-vs-failure of an UNSTAKE is not determinable from tx history (it depends on `unlock_height` + `locked` at apply time), so the command does not attempt to model it — it reports the assume-applied sum and lets the residual carry it. ∎(2)
- **(3) Single-shard view.** The walk covers `D`'s home-shard blocks via the `block` RPC. A cross-shard TRANSFER's credit to `to` is delivered by the `b.inbound_receipts` loop on the *destination* shard's blocks (`apply_transactions`); if `D` is that receiver on another shard, the credit is outside this walk and surfaces (on the shard that holds it) as an inbound-receipt term of that shard's `non_tx_delta`. The command's tally is exact for `D`'s home-shard tx flow and honest about the cross-shard boundary. ∎(3)
- **(4) Subsidy/fee/NEF not reconstructed.** Per WA-4, block-creator income, NEF, and receipts are intentionally left in `non_tx_delta`; `blocks_produced` is the informational hook. Reconstructing them would require re-running the block-tail distribution (`total_fees + subsidy_this_block` split across `m` creators, dust to `creators[0]`) — consensus arithmetic the command declines to duplicate. ∎(4)
- **Read-only.** The command reaches only `block`, `status`, `balance`, `stake_info` — all in the daemon's read partition (`OperatorToolingReadOnly.md` §2.2 enumerates the six mutating methods; none is reached). It appends no tx and stages no evidence. ∎(read-only)
- **No re-derivation of consensus.** Combining (1) + read-only: the authoritative balance is the RPC's; the tally is bookkeeping; the identity (WA-3) is a *recompute of a public accounting relation over consensus-authoritative inputs*, not a re-execution of consensus. ∎

---

## 5. Composition with companion proofs

### 5.1 `AccountHistorySoundness.md` — the sibling read (the closest analog)

`account-accounting` is the **tx-flow-accounting analog** of the `determ-light account-history` trajectory read. `account-history` proves the *committed* `(balance, nonce)` at sampled heights (AH-1 per-point soundness, cryptographic); `account-accounting` explains *how the balance was reached* from the domain's own transaction flow (WA-1..WA-3, accounting). They share the honesty discipline: AH-4 ("the trajectory proves values AT sampled heights, not between") is mirrored by WA-4/WA-5 ("`tx_flow_net` explains the domain's own tx flow, not creator income / NEF / cross-shard / assume-applied skips"). An operator wanting a *trust-minimized* authoritative balance feeds `account-accounting` the light-client balance-trustless figure (AH-1) instead of the daemon's `rpc_balance`; the accounting identity WA-3 is agnostic to which authoritative source is used.

### 5.2 `OperatorToolingReadOnly.md` — the read-only partition

WA-5's read-only claim composes the `OperatorToolingReadOnly.md` RPC read/mutate partition: `account-accounting` reaches only `block` / `status` / `balance` / `stake_info` (§2.5 read subcommand → method map style), none of the six mutating methods of §2.2. The command is read-only by the same definition (§2.3) the `operator_*.sh` family satisfies.

### 5.3 `SupplyProofSoundness.md` — the closed-form-identity cousin

WA-3's reconciliation identity is the per-domain analog of SU-3's cross-counter A1-supply identity: both let a client recompute a closed-form accounting relation (`b_D^auth = genesis_opening + tx_flow_net + non_tx_income` here; `expected_total = genesis_total + Σsubsidy + Σinbound − Σslashed − Σoutbound` there) over values it consumes as authoritative rather than re-derives. SU-3's "does not confirm `live_total_supply()`" boundary is mirrored by WA-4's "does not reconstruct creator income / NEF" boundary — both draw the line at consensus arithmetic they decline to duplicate.

### 5.4 `EconomicSoundness.md` / `AccountStateInvariants.md` — the chain-side inputs consumed

The block-level subsidy+fee distribution WA-1/WA-4 classify is a *conserved transfer* (fees paid by senders + genesis-pinned subsidy → creators), not a mint the tally must chase: `EconomicSoundness.md` T-12 (the A1 unitary-supply identity) proves the distribution conserves supply, so `non_tx_delta`'s creator-income term is bounded and well-defined. `AccountStateInvariants.md` FA-Apply-1 is the per-account invariant each per-tx effect (§3.1) obeys; WA-1 consumes those invariants (transcribing the apply cases) rather than re-proving them.

---

## 6. Known limitations

1. **Creator-income precision (WA-4).** `non_tx_delta` aggregates creator income without decomposing per-block payouts; `blocks_produced` bounds the count of contributing blocks but not the exact per-block `per_creator`. An operator wanting the exact creator-income figure re-derives it from each block's `total_fees + subsidy_this_block` and `|creators|` — outside this command's scope (WA-5 (4)).
2. **UNSTAKE success/failure indeterminacy (WA-2 V2).** The tally cannot tell an applied UNSTAKE from a refunded (failed) one from tx history alone; the difference is absorbed into `non_tx_delta`. A domain with many too-early UNSTAKE attempts will show a `non_tx_delta` inflated by the refunded-fee over-counts.
3. **Cross-shard receiver credits (WA-5 (3)).** If `D` receives cross-shard TRANSFERs whose credits land on a shard other than the one walked, those credits are not in this walk's `tx_flow_net`; they appear in the *destination* shard's accounting. A full cross-shard picture requires running `account-accounting` against each relevant shard's daemon and composing by hand.
4. **Daemon-trust of the authoritative balance.** `rpc_balance` is the *daemon's* figure; a Byzantine daemon lying about it is a daemon-trust question orthogonal to this contract. For a trust-minimized authoritative read, substitute the `determ-light` balance-trustless value (`AccountHistorySoundness.md` AH-1); the identity WA-3 is unchanged.

---

## 7. Implementation cross-references

Per-theorem citation table (files only, no line numbers, per repo citation discipline).

| Theorem | Component | File | Role |
|---|---|---|---|
| WA-1 | per-tx effect table | `src/chain/chain.cpp` | `apply_transactions` tx switch (TRANSFER / STAKE / UNSTAKE / REGISTER / DEREGISTER / PARAM_CHANGE / MERGE_EVENT / DAPP_CALL cases) — the ground-truth effects the classifier transcribes. |
| WA-1 / WA-3 | block-level distribution | `src/chain/chain.cpp` | `apply_transactions` tail: `total_distributed = total_fees + subsidy_this_block`, even split across `creators`, dust to `creators[0]` — the creator-income origin of `non_tx_delta`. |
| WA-3 | genesis install | `src/chain/chain.cpp` | `apply_transactions` block-0 branch: `accounts_[domain].balance = initial_balance` — `genesis_opening`. |
| WA-3 | NEF hook | `src/chain/chain.cpp` | `apply_transactions` REGISTER first-time branch: `accounts_[from].balance += pool/2` — the NEF term of `non_tx_income`. |
| WA-3 / WA-5 | inbound receipts | `src/chain/chain.cpp` | `apply_transactions` `b.inbound_receipts` loop — the cross-shard credit delivered on the destination shard. |
| WA-1..WA-5 | chain walk | `src/node/node.cpp` | `rpc_block` — the `block` RPC the command walks over `[0, head]`. |
| WA-3 / WA-5 | authoritative balance | `src/node/node.cpp` | `rpc_balance` (→ `chain_.balance_lockfree(domain)`) + `stake_info` — the consensus-authoritative figures the tally reconciles against, not re-derived. |

**Command + test.** `determ-wallet account-accounting` (the R57 subcommand) and `tools/test_wallet_account_accounting.sh` — both landing in parallel with this proof.

---

## 8. Status

- **Spec.** Complete (this document).
- **Implementation.** SHIPPED (R57) — `determ-wallet account-accounting`; test `tools/test_wallet_account_accounting.sh`.
- **Proof.** Complete: WA-1 (per-tx classification correctness — the classifier is `apply_transactions` transcribed as an accounting function), WA-2 (tx-flow-net soundness under assume-applied — exact tx-field sum, V1/V2 absorbed into `non_tx_delta`), WA-3 (the reconciliation identity `authoritative_balance = genesis_opening + tx_flow_net + non_tx_income`, closing exactly to `genesis_opening` for a plain non-creator single-shard domain), WA-4 (`non_tx_delta` is a diagnostic surface enumerating genesis / creator-income / NEF / receipts / assume-applied over-count, not an error), WA-5 (the four non-claims + read-only + no consensus re-derivation).
- **Cryptographic assumptions.** None of its own — the command is an accounting view; the authoritative balance is the RPC's (or, optionally, the light-client balance-trustless value of `AccountHistorySoundness.md` AH-1). No new primitive.
- **Verification.** Every per-tx effect in §3.1 was confirmed against `src/chain/chain.cpp` `apply_transactions` (TRANSFER same-shard/cross-shard split, STAKE `locked += amount`, UNSTAKE success-vs-failure fee-refund branch, REGISTER first-time NEF hook, fee-only DEREGISTER/PARAM_CHANGE/MERGE_EVENT, DAPP_CALL debit/credit, block-tail even split + dust to `creators[0]`). **No rule required correction — the R57 contract matches the code as written.**
- **Composes with.** `AccountHistorySoundness.md` (the sibling read — this is its tx-flow-accounting analog); `OperatorToolingReadOnly.md` (the read-only RPC partition WA-5 composes); `SupplyProofSoundness.md` (SU-3, the closed-form-identity cousin of WA-3); `EconomicSoundness.md` T-12 + `AccountStateInvariants.md` FA-Apply-1 (the chain-side inputs the tally consumes, not re-derives).
- **Headline honesty point (WA-3 + WA-4).** The command reports `tx_flow_net` **exactly** (a reproducible signed sum of tx fields) and surfaces `non_tx_delta = authoritative_balance − tx_flow_net` as a **diagnostic**, so a reader sees precisely what a domain's own transactions explain versus what they don't. It is **not** a consensus-balance re-derivation, it is **assume-applied**, it is a **single-shard view**, and it intentionally does **not** reconstruct subsidy/fee/NEF income (that lives in `non_tx_delta`; `blocks_produced` is the informational hook). For a plain user domain the identity closes exactly to `genesis_opening`.
