# FA-Apply — DApp registry lifecycle (DAPP_REGISTER)

This document formalizes the apply-layer state machine governing the v2.18 on-chain DApp registry: the DAPP_REGISTER transaction with `op=0` that creates or updates a `DAppEntry`, and the DAPP_REGISTER with `op=1` that schedules deferred deactivation via `DAPP_GRACE_BLOCKS`. Together these two op-codes define a per-domain three-state machine — `(unregistered, active, deactivating)` — whose transitions must preserve the A1 unitary-supply invariant, must enforce owner-binding immutability for `owner_pubkey` / `registered_at` across updates, must defer deactivation by exactly `DAPP_GRACE_BLOCKS` so that in-flight DAPP_CALL traffic can settle, and must keep each domain's lifecycle independent of any other domain's.

The proof is mechanical: the entire substrate is a single per-tx-type branch in `Chain::apply_transactions` (`src/chain/chain.cpp:1049–1117`) covering both ops, plus the dual-purpose lookup `Chain::dapp(domain)` (`src/chain/chain.cpp:184–188`) consumed at query time by `Chain::dapp_lockfree` + validator + the DAPP_CALL apply branch. The branch uses the same `charge_fee` / `sender.next_nonce++` primitives covered by `AccountStateInvariants.md` (FA-Apply) I-1 + I-2 and by `NonceMonotonicity.md` (FA-Apply-3); the present proof's contribution is to enumerate the legitimate DApp-channel transitions, prove each preserves I-6 (A1 contribution) and the owner-binding by construction (the registry is keyed by `tx.from`, so a non-owner sender literally cannot reach another owner's entry), and pin the deferred-deactivation contract against regression. The strength is consolidation: the lifecycle semantics are scattered across V2-DAPP-DESIGN.md §3 + §4 + §5, the in-code `DAppEntry` struct comments at `include/determ/chain/chain.hpp:46–81`, the DAPP_REGISTER branch comments at `chain.cpp:1040–1117`, and the test commentary in `tools/test_dapp_state_transition.sh`. No single document collects the theorem statements, the owner-binding-by-keying clarification, the `DAPP_GRACE_BLOCKS` rationale, and the test witnesses.

**Companion documents:** `Preliminaries.md` (F0) for notation, the validator predicate V1–V15, and the apply-time guarantees; `AccountStateInvariants.md` (FA-Apply) for invariants I-1 through I-6, especially I-2 (nonce monotonicity gate that precedes every DAPP_REGISTER branch) and I-6 (A1 closure that DAPP_REGISTER's fee debit feeds via `total_fees`); `SnapshotEquivalence.md` (FA-Apply-2) for the L-S0 / L-S1 coverage that includes the `d:` namespace via S-037 closure (the dapp_registry serialize/restore wiring that makes T-D1..T-D7 invariants survive snapshot bootstrap); `NonceMonotonicity.md` (FA-Apply-3) for T-N3 (per-account independence) which extends naturally to per-DApp-domain independence via the same `std::map` keying argument; `StakeLifecycle.md` (FA-Apply-4) for the structural template — both are state-machine proofs over a `(tx.from)`-keyed map where deferred-effect semantics gate certain state transitions on a future block height; `EconomicSoundness.md` (FA11) for the A1 closure under DApp fees; `docs/V2-DAPP-DESIGN.md` §1–§5 for the design intent and the conceptual three-state machine.

---

## 1. Setup

### 1.1 The `DAppEntry` struct

Per `include/determ/chain/chain.hpp:46–81`:

```cpp
struct DAppEntry {
    PubKey                   service_pubkey{};
    std::string              endpoint_url{};
    std::vector<std::string> topics{};
    uint8_t                  retention{0};
    std::vector<uint8_t>     metadata{};
    uint64_t                 registered_at{0};
    uint64_t                 active_from{0};
    uint64_t                 inactive_from{UINT64_MAX};
};
```

`dapp_registry_` is `std::map<std::string, DAppEntry>` (declared at `include/determ/chain/chain.hpp:549`; sibling of `accounts_`, `stakes_`, `registrants_`). The `inactive_from` field is the load-bearing sentinel: it holds `UINT64_MAX` while the DApp is active (newly-created or freshly updated), and is set to a finite value `b.index + DAPP_GRACE_BLOCKS` at the moment `op=1` fires (the "deactivating" state). Post-deactivation queries gate on `inactive_from <= height` rather than on entry deletion — the entry stays in the map. The `registered_at` field is the structural owner-binding anchor: it is written exactly once (at first-time create) and is explicitly preserved across every update by the apply branch's read-then-rewrite pattern (`chain.cpp:1107–1115`).

The companion `DAPP_GRACE_BLOCKS` constant is defined in `include/determ/chain/block.hpp:195` as a compile-time `uint64_t = 100`. The value is genesis-pinned (no PARAM_CHANGE entry maps to it in the A5 whitelist); changing it requires a code release.

There is no `owner_pubkey` field stored on the `DAppEntry`. The owner-binding is structurally encoded in the registry's `std::map` key — `dapp_registry_[tx.from]` — so the "owner pubkey" is the Ed25519 key registered in `registrants_[tx.from].ed_pub` (the Determ identity that owns this DApp). DAPP_REGISTER's V15-precondition is that `tx.from` is in `registrants_`; the validator at `src/node/validator.cpp:805–808` rejects DAPP_REGISTER from a sender not in the registry. Therefore the owner-binding is enforced by composition of two facts: (1) `tx.from` is signature-authenticated by ed25519 EUF-CMA (A1), and (2) `dapp_registry_[tx.from]` is keyed on that authenticated sender. A non-owner cannot reach another sender's DApp entry because the apply branch writes to `dapp_registry_[tx.from]`, where `tx.from` is the sender field of the verified-signed transaction. Section 2's T-D3 and T-D5 formalize this.

### 1.2 The three-state machine

Each Determ domain `d` (i.e., each `tx.from` value that is a registered Determ identity) has its DApp-registry state at every height in one of:

- **`unregistered`** — `dapp_registry_` does not contain `d`.
- **`active`** — `dapp_registry_[d]` exists AND `dapp_registry_[d].inactive_from == UINT64_MAX`.
- **`deactivating`** — `dapp_registry_[d]` exists AND `dapp_registry_[d].inactive_from < UINT64_MAX` AND `current_height < dapp_registry_[d].inactive_from`.
- **`inactive`** — `dapp_registry_[d]` exists AND `current_height >= dapp_registry_[d].inactive_from`.

The legitimate apply-path transitions (each driven by a DAPP_REGISTER tx with `tx.from == d`) are:

```
unregistered  ──DAPP_REGISTER(op=0)──> active     (create — populate all fields)
active        ──DAPP_REGISTER(op=0)──> active     (update — preserve registered_at)
deactivating  ──DAPP_REGISTER(op=0)──> active     (revive — preserve registered_at, clear inactive_from)
inactive      ──DAPP_REGISTER(op=0)──> active     (revive — same as deactivating)
active        ──DAPP_REGISTER(op=1)──> deactivating   (sets inactive_from = height + DAPP_GRACE_BLOCKS)
deactivating  ──DAPP_REGISTER(op=1)──> deactivating   (re-sets inactive_from)
deactivating  ──[height advance]──>     inactive  (purely a function of block height; no apply mutation)
```

The `inactive → deactivating` arc on `op=1` is structurally identical to `active → deactivating` (the apply path rewrites `inactive_from` to `height + DAPP_GRACE_BLOCKS` whether the prior value was `UINT64_MAX` or any other finite value; `op=1` on an `unregistered` domain is a no-op past the fee-charge / nonce-bump because the registry lookup at `chain.cpp:1057` returns `end()`).

### 1.3 The fee-charge convention

DAPP_REGISTER uses the `charge_fee` lambda at `chain.cpp:727–732` exactly as STAKE / DEREGISTER / UNSTAKE / PARAM_CHANGE / MERGE_EVENT do. The fee is consumed before any payload decode or registry mutation; on insufficient balance the entire tx is silently skipped via `continue` with no nonce bump, identical to I-1 (4) and T-K2 of `StakeLifecycle.md`. On any post-charge-fee branch failure (empty payload, unknown op, malformed structure, missing-registry-on-deactivate, etc.) the apply path bumps the nonce and breaks, charging the fee but skipping the mutation — defensive consistency with the validator-side reject so that honest replay stays deterministic even if a malformed tx slips past validation (`chain.cpp:1046–1048` comment).

The fee debit feeds `total_fees` via `charge_fee` (a single `total_fees += fee` accumulation step is in the lambda body), and `total_fees` is distributed to creators at block-tail (`chain.cpp:1287–1304`). The DAPP_REGISTER channel is identical to every other "fee-only debit" channel enumerated in I-5 of `AccountStateInvariants.md` (the third row of the debit table: "Fee-only debit — REGISTER / DEREGISTER / UNSTAKE / PARAM_CHANGE / MERGE_EVENT / DAPP_REGISTER").

---

## 2. Theorems

### T-D1 — First-time registration creates a fresh DAppEntry

**Statement.** For every domain `d` such that `dapp_registry_` does not contain `d` at `state` and every block `B` at height `b.index` containing a DAPP_REGISTER transaction `tx` with `tx.from == d`, `tx.nonce == state.accounts_[d].next_nonce`, `state.accounts_[d].balance ≥ tx.fee`, `state.registrants_[d]` exists, and a well-formed `op=0` payload, apply produces the deltas:

```
Δdapp_registry_[d]               = {service_pubkey, endpoint_url, topics, retention, metadata,
                                     registered_at = b.index,
                                     active_from   = b.index,
                                     inactive_from = UINT64_MAX}
Δaccounts_[d].balance            = −tx.fee
Δaccounts_[d].next_nonce         = +1
Δtotal_fees                      = +tx.fee
```

with no other state mutation. In particular: **NEF is not drained** (the NEF mechanism at `chain.cpp:823–833` is gated by `TxType::REGISTER`, not `TxType::DAPP_REGISTER`; the two registration paths are independent). The A1 unitary-supply invariant holds — DAPP_REGISTER is a fee-only debit channel (per I-5 of `AccountStateInvariants.md`), and `tx.fee` enters `total_fees` for later creator distribution.

*Proof sketch.* By inspection of `chain.cpp:1049–1117`. The nonce gate at line 739 admits the tx (hypothesis). `charge_fee(sender, tx.fee)` at line 1050 succeeds (balance hypothesis); `sender.next_nonce++` at line 1051 bumps the nonce. The payload-non-empty check at line 1053 admits (well-formed op=0 hypothesis). `op = tx.payload[0] = 0` at line 1054 directs control to the create/update branch (line 1064 `if (op != 0) break` does not trip). Lines 1066–1103 decode the payload deterministically: `service_pubkey` (32 bytes), `endpoint_url_len` (1 byte) + `endpoint_url` (utf8), `topic_count` (1 byte, ≤ MAX_DAPP_TOPICS = 32) + per-topic `(len, bytes)`, `retention` (1 byte), `metadata_len` (2 bytes LE, ≤ MAX_DAPP_METADATA = 4096) + `metadata` (bytes). The `__ensure_dapp_registry()` call at line 1106 is the lazy-snapshot hook (Phase 2A/2B atomic-apply mechanism — saves the pre-mutation map for the A9 rollback path). Lines 1107–1112 read-or-default `registered_at`: under the hypothesis `dapp_registry_.find(tx.from) == end()` (first-time), so `e.registered_at = height = b.index`. Lines 1113–1114 set `e.active_from = height` and `e.inactive_from = UINT64_MAX`. Line 1115 commits the entry via `dapp_registry_[tx.from] = std::move(e)`. The four deltas in the statement are exactly the four state writes; no other field is touched. The NEF non-drain follows directly from the apply branch's body containing no reference to `ZEROTH_ADDRESS`, no read or write of `accounts_[ZEROTH_ADDRESS].balance`, and no call to any helper that touches the NEF pool. ∎

**Code witness.** `src/chain/chain.cpp:1049–1117` (DAPP_REGISTER op=0 create branch); `src/chain/chain.cpp:727–732` (`charge_fee` lambda); `include/determ/chain/chain.hpp:46–81` (`DAppEntry` struct); `include/determ/chain/block.hpp:191–195` (`MAX_DAPP_*` caps + `DAPP_GRACE_BLOCKS`); `src/chain/chain.cpp:823–833` (REGISTER's NEF branch — explicitly NOT reached by DAPP_REGISTER).

**Test witness.** `tools/test_dapp_register.sh` (`determ test-dapp-register`) exercises the create scenario with explicit assertions on `service_pubkey`, `endpoint_url`, `topics`, `metadata`, plus `registered_at`. `tools/test_dapp_state_transition.sh` (`determ test-dapp-state-transition`) — 7 assertions in the "Initial registration op=0" block: entry created with all fields preserved + `inactive_from == UINT64_MAX` sentinel + `registered_at == current_height`.

### T-D2 — Update preserves owner-anchor + registered_at; resets inactive_from

**Statement.** For every domain `d` such that `dapp_registry_` contains `d` at `state` (with `dapp_registry_[d].registered_at = R₀`) and every block `B` at height `b.index` containing a DAPP_REGISTER transaction `tx` with `tx.from == d`, `tx.nonce == state.accounts_[d].next_nonce`, `state.accounts_[d].balance ≥ tx.fee`, and a well-formed `op=0` payload, apply produces the deltas:

```
Δdapp_registry_[d].service_pubkey  = payload.service_pubkey
Δdapp_registry_[d].endpoint_url    = payload.endpoint_url
Δdapp_registry_[d].topics          = payload.topics
Δdapp_registry_[d].retention       = payload.retention
Δdapp_registry_[d].metadata        = payload.metadata
Δdapp_registry_[d].registered_at   = 0          (no change — preserved at R₀)
Δdapp_registry_[d].active_from     = b.index   (refreshed)
Δdapp_registry_[d].inactive_from   = UINT64_MAX (reset — re-activates if previously deactivating)
Δaccounts_[d].balance              = −tx.fee
Δaccounts_[d].next_nonce           = +1
Δtotal_fees                        = +tx.fee
```

with no other state mutation. The five mutable payload fields (`service_pubkey`, `endpoint_url`, `topics`, `retention`, `metadata`) are replaced by the new payload's values; the two lifecycle anchors (`registered_at`, `active_from`) follow the asymmetric pattern: `registered_at` is preserved (creation time is immutable), `active_from` is refreshed to the current height (every successful update re-anchors the "currently-active-from" timestamp), `inactive_from` is reset to the active sentinel (a previously-deactivating DApp can be revived by re-issuing op=0).

*Proof sketch.* By inspection of the same branch at `chain.cpp:1049–1117`, under the hypothesis `dapp_registry_.find(tx.from) != end()`. The fee-charge / nonce-bump / payload-decode portion is identical to T-D1. The branching at line 1107 takes the `existing != end()` arm, so line 1109 reads `e.registered_at = existing->second.registered_at = R₀` — the preserve write. Lines 1113–1114 unconditionally set `e.active_from = height` and `e.inactive_from = UINT64_MAX`, equally for first-time and update cases. Line 1115 commits `e` to `dapp_registry_[tx.from]`, replacing the prior entry's mutable fields with the new payload's values while carrying the preserved `registered_at`. The "no other state mutation" claim follows from the same exhaustive enumeration as T-D1. NEF is not touched (same reasoning). ∎

**Code witness.** `src/chain/chain.cpp:1107–1115` (the read-preserve pattern for `registered_at`); `src/chain/chain.cpp:1113–1114` (the active-anchor refresh + inactive-sentinel reset).

**Test witness.** `tools/test_dapp_state_transition.sh` "Update op=0 on same domain" block — 7 assertions: every mutable field replaced (5 assertions: service_pubkey, endpoint_url, topics, retention, metadata) + `registered_at PRESERVED` + `inactive_from stays sentinel`. The assertion text in the test ("registered_at PRESERVED (not refreshed on update)") is the load-bearing pin against regression to "refresh registered_at on every update," which would break the structural owner-anchor invariant.

### T-D3 — Owner-binding by construction (cross-sender update unreachable)

**Statement.** For every pair of distinct Determ domains `d, d'` with `d ≠ d'`, and every block `B` containing a DAPP_REGISTER transaction `tx` with `tx.from == d'` (signed by `d'`, signature-verified under `registrants_[d'].ed_pub`), the apply path does NOT mutate `dapp_registry_[d]`. Equivalently: an attacker controlling identity `d'` cannot modify, deactivate, or revive the DApp owned by `d`, regardless of payload contents or `op` byte value.

*Proof sketch.* By inspection of every dapp-registry-touching write in `chain.cpp:1049–1117`. The DAPP_REGISTER branch performs four `dapp_registry_` accesses, each keyed by `tx.from`:

- Line 1057: `auto it = dapp_registry_.find(tx.from)` (op=1 lookup).
- Line 1060: `dapp_registry_[tx.from].inactive_from = height + DAPP_GRACE_BLOCKS` (op=1 write).
- Line 1107: `auto existing = dapp_registry_.find(tx.from)` (op=0 preserve-or-default lookup).
- Line 1115: `dapp_registry_[tx.from] = std::move(e)` (op=0 commit write).

Every map access uses `tx.from` as the key; no path within the branch reads or writes any `dapp_registry_[X]` for any `X != tx.from`. Under the hypothesis `tx.from == d'`, every access is to `dapp_registry_[d']`. `std::map` access semantics give the standard guarantee: reading or writing `m[k1]` does not modify `m[k2]` for `k1 ≠ k2`. The signature gate upstream (the V4-class signature check at validator-time and the mempool sig-verify post-S-002) ensures `tx.from = d'` can only be set by an actor holding `sk_{d'}`; no attacker without `sk_{d'}` can produce a `DAPP_REGISTER` with `tx.from == d'` that passes V8 / V15. ∎

The structural conclusion is that owner-binding is enforced **by composition**, not by an explicit per-tx authorization check: (1) ed25519 EUF-CMA (A1, Preliminaries §2.2) prevents impersonation of the sender field, and (2) the `dapp_registry_[tx.from]` keying makes the writer's reach exactly the writer's own slot. There is no path in the apply layer that performs `dapp_registry_[some_other_key] = ...`. A regression introducing such a cross-key write (e.g., a hypothetical "DAPP_TRANSFER_OWNERSHIP" tx) would require an explicit new branch; the current DAPP_REGISTER branch cannot reach it.

**Code witness.** All four `dapp_registry_` accesses in `chain.cpp:1049–1117` keyed exclusively by `tx.from`; `src/node/validator.cpp:805–808` (V15-class precondition that `tx.from` must be in `registrants_`); the ed25519 EUF-CMA assumption A1 (Preliminaries §2.2).

**Test witness.** `tools/test_dapp_state_transition.sh` "Independent domain" block — 2 assertions: bob can register a DApp without affecting alice's DApp + alice's deactivated entry preserved after bob's apply. The independence claim is structurally the same as T-D7's per-domain independence (alice's tx does not write bob's slot and vice versa), with T-D3 specifically about the signed-sender direction.

### T-D4 — Deactivation (op=1) sets deferred inactive_from

**Statement.** For every domain `d` such that `dapp_registry_` contains `d` at `state` and every block `B` at height `b.index` containing a DAPP_REGISTER transaction `tx` with `tx.from == d`, `tx.nonce == state.accounts_[d].next_nonce`, `state.accounts_[d].balance ≥ tx.fee`, and `tx.payload` of exact form `[0x01]` (op=1 with no further bytes, per validator gate at `src/node/validator.cpp:813–819`), apply produces the deltas:

```
Δdapp_registry_[d].inactive_from = b.index + DAPP_GRACE_BLOCKS − old_inactive_from
                                  (i.e., inactive_from := b.index + DAPP_GRACE_BLOCKS,
                                   regardless of prior value)
Δdapp_registry_[d].(other fields) = 0  (preserved; only inactive_from is touched)
Δaccounts_[d].balance            = −tx.fee
Δaccounts_[d].next_nonce         = +1
Δtotal_fees                      = +tx.fee
```

with no other state mutation. The entry remains in `dapp_registry_` — deactivation is **deferred**, not immediate deletion. The grace window `[b.index, b.index + DAPP_GRACE_BLOCKS)` allows in-flight DAPP_CALL transactions addressed to `d` to settle (validator + DAPP_CALL apply check `dapp.inactive_from <= height`; pre-deferred-window blocks still pass).

*Proof sketch.* By inspection of `chain.cpp:1049–1063`. The nonce gate at line 739 admits (hypothesis). `charge_fee` at line 1050 succeeds (balance hypothesis); `sender.next_nonce++` at line 1051. Payload non-empty at line 1053 admits (1-byte payload). `op = tx.payload[0] = 1` at line 1054. Line 1055 enters the deactivate branch. Line 1057 reads `auto it = dapp_registry_.find(tx.from)`. Under the hypothesis (registry contains `d`), `it != end()`. Line 1059 `__ensure_dapp_registry()` saves the pre-mutation map for A9 rollback. Lines 1060–1061 write `dapp_registry_[tx.from].inactive_from = height + DAPP_GRACE_BLOCKS`. This is the ONLY field of the entry that is modified — `service_pubkey`, `endpoint_url`, `topics`, `retention`, `metadata`, `registered_at`, `active_from` are all preserved by the targeted `inactive_from` write (the assignment touches one struct member, not the whole entry). Line 1062 `break`s. The four deltas in the statement are exactly the four state writes. ∎

**Code witness.** `src/chain/chain.cpp:1055–1062` (the op=1 deactivate branch); `include/determ/chain/block.hpp:195` (`DAPP_GRACE_BLOCKS = 100`); `src/node/validator.cpp:813–819` (V15-class shape check that op=1 payload is exactly 1 byte).

**Test witness.** `tools/test_dapp_state_transition.sh` "Deactivate op=1" block — 4 assertions: entry persists (deferred via grace window) + `inactive_from` set (no longer sentinel) + `inactive_from > current_height` + prior fields untouched.

### T-D5 — Deactivation by non-owner unreachable (owner-binding for op=1)

**Statement.** For every pair of distinct domains `d, d'` with `d ≠ d'`, no DAPP_REGISTER transaction with `tx.from == d'` (regardless of `op` byte or payload contents) mutates `dapp_registry_[d].inactive_from` or any other field of `dapp_registry_[d]`.

*Proof sketch.* By inclusion: T-D5 is the op=1 special-case of T-D3. The op=1 deactivate branch at `chain.cpp:1057–1062` performs two `dapp_registry_` accesses, both keyed by `tx.from`:

- Line 1057: `auto it = dapp_registry_.find(tx.from)` (lookup).
- Line 1060: `dapp_registry_[tx.from].inactive_from = ...` (write).

Under hypothesis `tx.from = d'`, both accesses are to `dapp_registry_[d']`. The std::map per-key isolation argument from T-D3 applies identically. An attacker cannot signal "deactivate `d`" by signing a DAPP_REGISTER as `d'` because the apply path's deactivate write lands on `dapp_registry_[d']`, not `dapp_registry_[d]`. ∎

**Code witness.** Same as T-D3 (the four `dapp_registry_` accesses keyed by `tx.from`).

**Test witness.** `tools/test_dapp_state_transition.sh` "Independent domain" block — the bob-can-register-without-affecting-alice assertion covers this direction: bob's apply (including any hypothetical bob-issued op=1 tx) cannot reach alice's slot. The structural argument generalizes the test's particular construction.

### T-D6 — Post-deactivation queries skip via `inactive_from <= height` gate

**Statement.** For every domain `d` such that `dapp_registry_` contains `d` with `dapp_registry_[d].inactive_from = I` (finite, i.e., post-op=1), and every height `h ≥ I`, the DAPP_CALL apply path at `chain.cpp:1142` evaluates the predicate `dapp.inactive_from <= height` to true, takes the silent-reject branch (`charge_fee` + `sender.next_nonce++` + `break`), and produces NO credit to `dapp_registry_[d]`'s owner account. Equivalently: a DApp transitions from `deactivating` → `inactive` purely as a function of block height, with no apply-path event required. The entry persists in `dapp_registry_` (per T-D4: deactivation is deferred-then-skipped, not entry-deletion).

*Proof sketch.* By inspection of the DAPP_CALL apply branch at `chain.cpp:1133–1224`. Line 1135 looks up `dapp_registry_.find(tx.to)`. Line 1136 enters the missing-DApp silent-reject if not found. Line 1141 binds `const DAppEntry& dapp = dit->second`. Line 1142 evaluates `if (dapp.inactive_from <= height)`. Under hypothesis `I = dapp.inactive_from`, `h = height`, `h ≥ I`, the predicate is true, so lines 1143–1145 charge the fee + bump the nonce + `break` — short-circuiting the rest of the branch (the credit / topic decode / cross-shard gate are all unreached). The recipient credit at line 1216 (`checked_add_u64(rcv, tx.amount, &rcv)`) is unreached on this branch, so `dapp_registry_[tx.to]`'s owner-account is not credited.

The `Chain::dapp(domain)` accessor at `chain.cpp:184–188` returns the raw entry regardless of activity (per the comment at lines 178–183: "callers gate on inactive_from themselves"). The query-time skip lives in the caller (DAPP_CALL apply, validator V15, RPC handlers), not in the accessor. The entry's persistence in `dapp_registry_` after deactivation is intentional: snapshot serialize/restore (S-037, `SnapshotEquivalence.md` L-S0 row `d:`) preserves it, and a future op=0 can revive it (T-D2's `inactive_from = UINT64_MAX` reset). ∎

**Code witness.** `src/chain/chain.cpp:1142–1146` (DAPP_CALL inactive-gate); `src/chain/chain.cpp:184–188` (`Chain::dapp(domain)` raw accessor); `src/chain/chain.cpp:178–183` (comment explaining the caller-gates pattern).

**Test witness.** `tools/test_dapp_call.sh` (`determ test-dapp-call`) exercises the active-DApp success path (credit applied) and an inactive-DApp variant where the gate fires and credit is skipped. `tools/test_dapp_state_transition.sh` "Deactivate op=1" + "Independent domain" blocks collectively verify the persistence-after-deactivation assertion (the entry stays in the map post-op=1). The end-to-end gossip-driven `tools/test_dapp_e2e.sh` exercises the full lifecycle including the post-grace-window skip.

### T-D7 — Per-domain independence

**Statement.** For every pair of distinct domains `d_1, d_2` (`d_1 ≠ d_2`) and every block `B`, the DApp-registry mutations on `d_1` (any DAPP_REGISTER tx with `tx.from == d_1`) do not read or write `dapp_registry_[d_2]`. Equivalently: one DApp's lifecycle (register → update → deactivate → revive) is fully isolated from another's; no cross-DApp write or read exists in the DAPP_REGISTER apply branch.

*Proof sketch.* Identical to T-D3's structural argument but stated as an independence property across two non-attacking domains rather than as an authorization property against a single attacker. By inspection of `chain.cpp:1049–1117`, every `dapp_registry_` access is keyed by `tx.from`. Under hypothesis `tx.from = d_1`, no access reaches `dapp_registry_[d_2]`. `std::map` per-key isolation (the same red-black-tree argument as T-K7 in `StakeLifecycle.md`) ensures the write to `dapp_registry_[d_1]` does not disturb `dapp_registry_[d_2]`. ∎

**Code witness.** Same as T-D3 (all four `dapp_registry_` accesses keyed by `tx.from`); `include/determ/chain/chain.hpp:549` (`dapp_registry_` map declaration as `std::map<std::string, DAppEntry>`).

**Test witness.** `tools/test_dapp_state_transition.sh` "Independent domain" block — 2 assertions exactly pin this: bob's DAPP_REGISTER does not affect alice's already-registered DApp entry, and alice's deactivated state survives bob's apply. The "Registry size" assertion at the end confirms `dapp_registry_.size() == 2` after both lifecycles, ruling out any shared-slot or collision regression.

### T-D8 — A1 invariance under DAPP_REGISTER apply

**Statement.** For every successful apply of a block `B` containing one or more DAPP_REGISTER transactions, the A1 unitary-balance invariant (`AccountStateInvariants.md` I-6) holds: `live_total_supply(state_{n+1}) == expected_total(state_{n+1})`. Each DAPP_REGISTER tx contributes either (a) `Δaccounts_[d].balance = −tx.fee` plus `Δtotal_fees = +tx.fee` (any branch that reached `charge_fee` and any of break / commit / no-op-past-fee), which is supply-preserving because `total_fees` accumulates into the per-block subsidy + fees distribution at block-tail, OR (b) zero state delta (the insufficient-balance silent-skip via `if (!charge_fee) continue;` at line 1050).

*Proof sketch.* DAPP_REGISTER's only `accounts_` write is the `charge_fee` debit on `sender.balance`, and its only `total_fees` write is the matching `+= fee` inside `charge_fee` (per the `charge_fee` lambda body at `chain.cpp:727–732`). No other `accounts_` field is mutated by the branch; no `stakes_`, `applied_inbound_receipts_`, `abort_records_`, `merge_state_`, or `pending_param_changes_` is touched. Therefore the only contribution to A1's per-block delta from a DAPP_REGISTER tx is `total_fees += tx.fee` (which is later distributed to creators at `chain.cpp:1287–1304`, conserving the value) or zero (insufficient-balance silent-skip).

`dapp_registry_` itself does NOT participate in the A1 equation (`live_total_supply` sums `accounts_[*].balance + stakes_[*].locked`; `dapp_registry_` carries no value-bearing field). The S-033 state-root commitment includes the `d:` namespace (`chain.cpp:312–329`), but state-root is a cryptographic binding, not a value-balance line item. DAPP_REGISTER's effect on the registry is therefore A1-invisible — only the fee debit lands in A1's accounting, and that lands in `total_fees`, identical to every other fee-only-debit channel of FA-Apply I-5.

A1 closure at apply-tail (`chain.cpp:1399`) sums `live_total_supply` and compares against `expected_total`. The DAPP_REGISTER channel's contribution to that sum is the fee, which is captured in `accumulated_subsidy_or_fees` (the apply-tail distribution step writes the per-creator credits into `accounts_`, balancing the `total_fees` accumulator over the block). A1 holds for the block by composition with FA-Apply T-A6 (the per-account I-5 channel enumeration's A1 closure). ∎

**Code witness.** `src/chain/chain.cpp:727–732` (`charge_fee` lambda — the only `accounts_` write in DAPP_REGISTER's branch); `src/chain/chain.cpp:1287–1304` (per-creator fee + subsidy distribution at block-tail); `src/chain/chain.cpp:1399` (A1 closure assertion).

**Test witness.** `tools/test_supply_lifecycle.sh` walks the chain through TRANSFER / STAKE / UNSTAKE / REGISTER / DEREGISTER / equivocation / suspension / cross-shard / subsidy variants and asserts A1 closure block-by-block. While the canonical test does not specifically inject DAPP_REGISTER, the apply-tail A1 assertion at `chain.cpp:1399` fires for every block, including DApp-active blocks exercised by `test_dapp_register.sh` / `test_dapp_state_transition.sh` / `test_dapp_call.sh` / `test_dapp_e2e.sh` / `test_dapp_snapshot.sh`. Any DAPP_REGISTER apply that mishandled the fee debit would throw at apply-tail and the test would fail.

---

## 3. DAPP_GRACE_BLOCKS rationale

The `DAPP_GRACE_BLOCKS = 100` constant (defined at `include/determ/chain/block.hpp:195`) is the load-bearing parameter for the deferred-deactivation semantics in T-D4. Three competing forces are balanced by the choice:

**Why deferral at all (rather than immediate `inactive_from = b.index`)?** A DApp's clients are off-chain consumers that filter the chain for DAPP_CALL txs addressed to the DApp's domain. Multiple DAPP_CALLs may already be in-flight (mempool-resident, gossiping toward a producer) when the operator broadcasts the `op=1` deactivation tx. If `inactive_from` were set to `b.index` (immediate effect at the same block), the next block's validator would reject all in-flight DAPP_CALLs to this DApp (V15-side gate at the validator + the `chain.cpp:1142` apply-side gate), surprising honest senders who could not have observed the deactivation early enough to cancel. The deferral gives clients a known-in-advance window during which the DApp remains addressable; clients running off-chain monitoring (`dapp_subscribe` RPC, or chain replay) see the `op=1` tx in block `b.index` and know they have `DAPP_GRACE_BLOCKS` more blocks to flush any final messages.

**Why 100 blocks specifically?** Block production is targeted at ~1-2 seconds per block for the cluster profile (`docs/PROTOCOL.md` §12.3 timing-profile table), so 100 blocks corresponds to ~100-200 seconds = 1.5-3 minutes. This is short enough that the operator's wind-down is observable to humans within a coffee break, but long enough that a network with end-to-end gossip latency of order 5-10 seconds + producer-inclusion latency of order 5-10 seconds will reliably settle any in-flight DAPP_CALLs that the sender saw the DApp as active at the time of submission. For the global profile (~6-12 second blocks), the window stretches to ~10-20 minutes, which is still a reasonable upper-bound on the in-flight-tx settling time. Genesis-pinned at the build-time constant; not on the A5 PARAM_CHANGE whitelist (per the absence from `Governance.md` FA10's whitelist table) so changing the value requires a coordinated code release.

**What the deferral costs.** Operators of a DApp who want to genuinely deprovision (e.g., remove the endpoint server, take the service offline) must continue to honor DAPP_CALL traffic for ~100 blocks after their `op=1`. The DApp's endpoint must remain reachable for that window, or honest clients will see "active per chain state, unreachable per network." This is the operational cost of the deferral; the alternative (immediate inactive) would shift the cost to honest senders (their in-flight txs land in a chain that has just declared the DApp inactive, producing a silent reject + fee loss). The chosen direction is operator-side cost (keep service running for ~3 minutes after deprovisioning) rather than honest-sender-side cost (silent rejection of legitimately-submitted in-flight messages).

**Composition with the active-on-update reset.** T-D2's `inactive_from = UINT64_MAX` reset on every op=0 update is the dual mechanism: an operator who issued op=1 by mistake (or who changed their mind during the grace window) can revive the DApp instantly by re-issuing op=0. The combination of "deactivation is deferred + activation/reactivation is instant" makes the lifecycle robust against operator-side errors: every wrong move has an immediate undo path through op=0.

---

## 4. NEF pool drain (cross-reference)

The Negative Entry Fee (NEF) is the E1 economic mechanism at `chain.cpp:823–833`, which transfers `pool/2` from `ZEROTH_ADDRESS` to a newly-registering domain at the first-time REGISTER apply. The mechanism is gated by `TxType::REGISTER` and the `first_time_register` flag computed at lines 795–796.

**DAPP_REGISTER does NOT drain the NEF pool.** The DAPP_REGISTER apply branch at `chain.cpp:1049–1117` contains no reference to `ZEROTH_ADDRESS`, no read or write of `accounts_[ZEROTH_ADDRESS].balance`, and no call to any helper that touches the NEF pool. T-D1 explicitly documents this: NEF is on REGISTER (the Determ identity creation), not on DAPP_REGISTER (the application-layer DApp registration). The two registration paths are independent — a domain's first-time REGISTER fires NEF (one-shot, geometric decay of `pool/2` per first-time REGISTER per FA11 T-13), but the same domain's subsequent DAPP_REGISTER does not retrigger the pool. Multiple DAPP_REGISTERs from the same Determ identity (T-D2 updates) similarly do not touch NEF.

**Why the separation matters.** The NEF mechanism's economic invariant (FA11 EconomicSoundness T-13: NEF is supply-neutral, geometric exhaustion of the Zeroth pool, A1 trivially preserved) depends on a one-shot-per-Determ-identity firing. If DAPP_REGISTER also drained NEF, every operator could create N DApps from the same Determ identity to drain the pool N times. The current keying — NEF on REGISTER's `first_time_register == registrants_.find(tx.from) == end()` — guarantees one drain per Determ identity. DAPP_REGISTER's separation from this mechanism preserves the FA11 invariant.

The chain-wide NEF-pool invariants (geometric exhaustion, A1 supply-neutrality, the "Zeroth address is canonical and not synthesizable" property) are covered by `EconomicSoundness.md` (FA11) T-13. The present proof's contribution is the apply-side observation that DAPP_REGISTER does not participate in the NEF channel — it is purely a fee-only-debit channel as enumerated in I-5 of `AccountStateInvariants.md`.

---

## 5. What this doesn't prove

The theorems above target the DAPP_REGISTER apply branch. They do not extend to:

- **DAPP_CALL apply path.** T-D6's cross-reference to the DAPP_CALL apply branch at `chain.cpp:1142` covers only the inactive-gate skip; the broader DAPP_CALL semantics (topic match, ciphertext length validation, debit/credit, S-007 overflow gate at line 1216, single-shard restriction at line 1205, cross-shard rejection) are covered by the v2.19 substrate tests (`tools/test_dapp_call.sh`, `tools/test_dapp_e2e.sh`, `tools/operator_dapp_call_audit.sh`) and the validator V15 checks at `src/node/validator.cpp:896+`. A future companion proof (FA-Apply-6 if shipped) would formalize the DAPP_CALL apply path the way the present proof formalizes DAPP_REGISTER.

- **Snapshot serialize/restore preservation of `dapp_registry_`.** The S-037 closure (per `SnapshotEquivalence.md` L-S0 row `d:` and the in-line citation in `chain.cpp:1647`) added the `dapp_registry` field to the snapshot envelope, the matching serialize loop at `chain.cpp:1653–1669`, and the restore loop at `chain.cpp:1818–1832`. The apply-after-restore equivalence for DApp-active chains is covered by T-S2 of `SnapshotEquivalence.md`, with the dedicated regression `tools/test_dapp_snapshot.sh` (12 assertions). The present proof depends on snapshot-restore equivalence — every theorem T-D1..T-D8 is stated about the chain state after some sequence of applies and inherits the snapshot-restore inheritance automatically — but does not re-derive the L-S0 / L-S1 coverage argument.

- **Cross-shard DApp calls.** V2-DAPP-DESIGN.md §11.7.2 describes the deferred Phase 7.6 work to extend the cross-shard receipt path to carry DAPP_CALL payload bytes across shards. v2.19 ships single-shard only — `chain.cpp:1205` explicitly rejects cross-shard DAPP_CALL at apply-time. The present proof's T-D6 covers only the same-shard inactive-gate behavior. The cross-shard DAPP_CALL semantics + the associated A1 + CrossShardReceipts.md FA7 composition are outside this proof's scope.

- **Wallet-side nonce coordination for DAPP_REGISTER + DAPP_CALL bundles.** The strict-equality nonce gate (`NonceMonotonicity.md` T-N3) applies to DAPP_REGISTER as much as to TRANSFER / STAKE / UNSTAKE / DAPP_CALL. A wallet that batches a DAPP_REGISTER then a follow-up DAPP_CALL in the same block must allocate consecutive nonces. The present proof's T-D7 (per-domain independence) covers cross-domain isolation; intra-domain nonce sequencing is FA-Apply-3's scope.

- **`service_pubkey` cryptographic properties.** The `DAppEntry.service_pubkey` field is recorded by the apply path as opaque 32 bytes; no signature verification or key-validity check is performed at apply time (the validator at `src/node/validator.cpp:828–829` enforces only the 32-byte length). Whether the operator chose a sound libsodium box pubkey is outside the chain's apply scope — the cryptographic property is the responsibility of the off-chain DApp client (which uses the pubkey to encrypt DAPP_CALL payloads via `crypto_box_seal`).

- **DApp economic invariants beyond A1.** T-D8 covers A1 closure under DAPP_REGISTER. Broader DApp economic claims (anti-spam fee adequacy, retention semantics' interaction with operator-policy snapshot pruning, the FA11 NEF supply-neutrality for the dual REGISTER/NEF channel) are outside the apply-layer scope.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Validator predicate V1–V15 + assumption A1 (ed25519 EUF-CMA) that makes the owner-binding-by-`tx.from`-keying argument in T-D3 / T-D5 sound. |
| `AccountStateInvariants.md` (FA-Apply) | I-1 (no underflow), I-2 (nonce monotonicity gate that precedes every DAPP_REGISTER branch), I-5 (DAPP_REGISTER is the "fee-only debit" channel — the third row of the debit table), I-6 (A1 closure). |
| `SnapshotEquivalence.md` (FA-Apply-2) | L-S0 / L-S1 row `d:` (S-037 closure — dapp_registry serialize/restore wiring) + T-S2 apply-after-restore equivalence; carries every T-D theorem through snapshot boundaries. |
| `NonceMonotonicity.md` (FA-Apply-3) | T-N3 per-account independence — the structural template that T-D7 mirrors for per-DApp-domain independence; the strict-equality nonce gate precedes every DAPP_REGISTER apply. |
| `StakeLifecycle.md` (FA-Apply-4) | Closest structural template (both are state-machine proofs over a `(tx.from)`-keyed map with deferred-effect semantics: STAKE's `unlock_height` ≈ DApp's `inactive_from`). |
| `EconomicSoundness.md` (FA11) | A1 closure under DAPP_REGISTER's fee channel (T-D8) + NEF supply-neutrality (T-13, applies to REGISTER only — the separation argument in §4). |
| `docs/SECURITY.md` §S-037 | The closure that wired dapp_registry into snapshot serialize/restore + state-root binding; makes T-D1..T-D8 survive snapshot bootstrap. |
| `docs/V2-DAPP-DESIGN.md` §1–§5 | Conceptual model + design intent for the DApp substrate; section §3 documents the wire format, §4 the registry struct, §5 the apply semantics. |
| `docs/PROTOCOL.md` §3.3 | Apply rules for DAPP_REGISTER + DAPP_CALL. |
| `docs/PROTOCOL.md` §4.1.1 | State-root namespace table including the `d:` namespace. |
| `tools/test_dapp_register.sh` | T-D1 + T-D2 (`determ test-dapp-register` — DAPP_REGISTER apply mechanics). |
| `tools/test_dapp_state_transition.sh` | T-D1 + T-D2 + T-D4 + T-D6 + T-D7 (`determ test-dapp-state-transition` — 22 assertions across five blocks pinning the full lifecycle including update-preserves-registered_at + deactivation-deferral + independent-domain isolation + replay-determinism). |
| `tools/test_dapp_call.sh` | T-D6 (DAPP_CALL apply-side inactive-gate). |
| `tools/test_dapp_e2e.sh` | End-to-end 3-node gossip-driven lifecycle (network surface). |
| `tools/test_dapp_snapshot.sh` | S-037 joint surface — DApp-active chain → snapshot → restore → state-root parity (12 assertions). |
| `tools/operator_dapp_audit.sh`, `tools/operator_dapp_call_audit.sh` | Operator-facing audit tooling. |
| `include/determ/chain/chain.hpp:46–81` | `DAppEntry` struct (service_pubkey, endpoint_url, topics, retention, metadata, registered_at, active_from, inactive_from). |
| `include/determ/chain/chain.hpp:549` | `dapp_registry_` map declaration (`std::map<std::string, DAppEntry>`). |
| `include/determ/chain/block.hpp:113–138` | DAPP_REGISTER enum value + wire format comment. |
| `include/determ/chain/block.hpp:191–195` | `MAX_DAPP_TOPICS`, `MAX_DAPP_TOPIC_LEN`, `MAX_DAPP_ENDPOINT_LEN`, `MAX_DAPP_METADATA`, `DAPP_GRACE_BLOCKS = 100`. |
| `src/chain/chain.cpp:184–188` | `Chain::dapp(domain)` raw accessor (gates moved to caller). |
| `src/chain/chain.cpp:312–329` | `build_state_leaves` `d:` namespace contribution to state_root. |
| `src/chain/chain.cpp:1049–1117` | DAPP_REGISTER apply branch (T-D1 through T-D5 + T-D7). |
| `src/chain/chain.cpp:1133–1224` | DAPP_CALL apply branch (T-D6 cross-reference for the inactive-gate). |
| `src/chain/chain.cpp:1647–1669` | Snapshot serialize loop for `dapp_registry_` (S-037 closure). |
| `src/chain/chain.cpp:1818–1832` | Snapshot restore loop for `dapp_registry_` (S-037 closure). |
| `src/node/validator.cpp:797–895` | V15-class DAPP_REGISTER shape check (validator's upstream rejection — apply-time defenses are belt-and-suspenders). |

---

## 7. Status

All eight theorems (T-D1 through T-D8) are closed in the current codebase:

- **T-D1** (first-time create) closed via the DAPP_REGISTER op=0 branch at `chain.cpp:1049–1117` + the explicit `registered_at = height` write at line 1111 for the first-time case; regression `test_dapp_register.sh` + `test_dapp_state_transition.sh` "Initial registration" block.
- **T-D2** (update preserves registered_at) closed via the read-preserve pattern at `chain.cpp:1107–1112` (read `existing->second.registered_at` if entry exists, override `e.registered_at` with it); regression `test_dapp_state_transition.sh` "Update op=0" block with the explicit "registered_at PRESERVED" assertion.
- **T-D3** (cross-sender update unreachable / owner-binding by construction) closed via the `dapp_registry_[tx.from]` keying of all four `dapp_registry_` accesses in the branch + ed25519 EUF-CMA (A1) preventing sender-field impersonation; regression `test_dapp_state_transition.sh` "Independent domain" block.
- **T-D4** (deferred deactivation) closed via the op=1 branch at `chain.cpp:1057–1062` writing `inactive_from = height + DAPP_GRACE_BLOCKS`; regression `test_dapp_state_transition.sh` "Deactivate op=1" block.
- **T-D5** (deactivation by non-owner unreachable) closed by inclusion: T-D5 is the op=1 special-case of T-D3's structural argument; same regression coverage.
- **T-D6** (post-deactivation queries skip) closed via the DAPP_CALL inactive-gate at `chain.cpp:1142` (the caller-gates-on-inactive_from pattern documented in the `Chain::dapp` accessor's comment); regression `test_dapp_call.sh` + `test_dapp_e2e.sh`.
- **T-D7** (per-domain independence) closed via the same `tx.from` keying as T-D3 + `std::map` per-key isolation; regression `test_dapp_state_transition.sh` "Independent domain" block.
- **T-D8** (A1 invariance) closed via DAPP_REGISTER's restriction to the fee-only-debit channel (no other `accounts_` / `stakes_` write) + the apply-tail A1 closure at `chain.cpp:1399`; regression covered indirectly via every test that includes DAPP_REGISTER and lands the block successfully (any A1 violation would throw at apply-tail before the test PASS message).

No theorem is open or partial. The S-037 closure is the structural dependency that makes the eight theorems survive snapshot bootstrap: without S-037, a DApp-active chain's snapshot would emit empty `dapp_registry_` to the receiver and the S-033 state-root verification gate at `chain.cpp:1430` would reject the next applied block — the theorems would all hold formally on the donor but the receiver couldn't replay them. The S-037 + S-038 pair (one shipped the dapp_registry serialize/restore wiring, the other made the producer populate `body.state_root` so the apply-time gate actually fires on production blocks) is the joint mechanism that makes T-D1..T-D8 transitively true across the snapshot ↔ replay boundary.

The proof's foundation rests on a small set of code primitives: the `charge_fee` lambda, the `dapp_registry_[tx.from]` keying that makes owner-binding structural, the `UINT64_MAX` sentinel on `DAppEntry.inactive_from`, the `DAPP_GRACE_BLOCKS = 100` deferral window, and the strict-equality nonce gate from FA-Apply-3. The breadth of consequences — eight theorems, a fully-pinned four-state machine, a deferred-deactivation UX contract, owner-binding by construction without an explicit per-tx authorization check — is testimony to how few primitives the chain needs to express the DApp lifecycle without adding a smart-contract VM.
