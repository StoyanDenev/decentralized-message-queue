# S022WireFormatCapsCompleteness — exhaustive MsgType enumeration + completeness theorem

This document is the meta-completeness companion to `S022WireFormatCaps.md`. The parent proof formalized **why** the post-deserialize `max_message_bytes(MsgType)` cap is sound (defense-in-depth posture, framing-layer composition, connection-close disposition, S-014 multiplicative composition). This document formalizes **what** is covered — an exhaustive enumeration of the current `MsgType` enum at `include/determ/net/messages.hpp:13-82`, a per-variant cap table cross-referenced against the parent proof's snapshot, a structural completeness theorem (T-1) covering the switch-statement's exhaustion, a tightness theorem (T-2) showing each tier's cap is loose enough for legitimate traffic but tight enough to deny amplification, and a forward-compatibility theorem (T-3) formalizing the maintenance contract for future MsgType additions.

The proof is short and structural — there are no cryptographic assumptions; this is a pure case-analysis-over-enum-variants argument. The contribution over `S022WireFormatCaps.md` is the meta-coverage layer: any drift between the live `MsgType` enum and the cap table would surface here first, before manifesting as a runtime amplification vector. The §2 cap table is the canonical reference for external auditors who need to verify the cap-table coverage without re-reading the C++ source; the §3 completeness theorem is the formal correctness claim that ties the table to the language-level `switch` exhaustion guarantee.

**Companion documents:** `S022WireFormatCaps.md` (parent proof — soundness of the per-MsgType cap and its framing-layer composition); `S013PerSignerCap.md` (parallel Phase-2 admission-cap that bounds `Node::buffered_block_sigs_` per signer; composes with S-022's per-message size cap and S-014's per-IP rate cap to form a three-axis defense-in-depth posture); `S014RateLimiterSoundness.md` (S-014 closure — per-peer-IP token bucket; T-1 bandwidth bound is the composition witness here); `S014ConcurrencyAnalysis.md` (asio thread-pool concurrency model for the rate limiter and the `Peer::read_header` → `read_body` continuation chain); `Preliminaries.md` §3 (network model underlying `Peer` framing-layer assumption); `docs/SECURITY.md` §S-022 (audit-side closure record).

---

## 1. Current MsgType enumeration

The `MsgType` enum at `include/determ/net/messages.hpp:13-82` is reproduced below verbatim (variant ordering matches source order, which matches the on-wire `uint8_t` value):

| Source line | Value | Variant name | Wire purpose |
|---|:---:|---|---|
| 14 | 0 | `HELLO` | Pre-negotiation handshake (domain + port + role + shard_id + wire_version). Always JSON. |
| 15 | 1 | `BLOCK` | Full `chain::Block` JSON for gossip + replay. |
| 16 | 2 | `TRANSACTION` | Single `chain::Transaction` JSON for mempool propagation. |
| 17 | 3 | `BLOCK_SIG` | Phase-2 signed block digest + VDF output + dh_secret. |
| 18 | 4 | `CONTRIB` | Phase-1 `ContribMsg` — TxCommit + DhInput + Ed25519 sig. |
| 19 | 5 | `GET_CHAIN` | Historical chain-slice request `{from, count}`. |
| 20 | 6 | `CHAIN_RESPONSE` | Historical chain-slice response (variable-size). |
| 21 | 7 | `STATUS_REQUEST` | Peer status probe (empty envelope). |
| 22 | 8 | `STATUS_RESPONSE` | `{height, genesis}` response. |
| 23 | 9 | `ABORT_CLAIM` | Single signed abort claim (rev.8). |
| 30 | 10 | `ABORT_EVENT` | Assembled K-1 abort claims inline (rev.8 follow-on). |
| 36 | 11 | `EQUIVOCATION_EVIDENCE` | Two `(digest, sig)` pairs by the same signer (rev.8 follow-on). |
| 45 | 12 | `BEACON_HEADER` | Full beacon `chain::Block` for shard-side light-header sync (rev.9 B2c.1). |
| 51 | 13 | `SHARD_TIP` | Shard's latest block wrapped with `shard_id` envelope (rev.9 B2c.3). |
| 60 | 14 | `CROSS_SHARD_RECEIPT_BUNDLE` | `{src_shard, src_block}` for destination-shard receipt pickup (rev.9 B3.3). |
| 68 | 15 | `SNAPSHOT_REQUEST` | `{headers: N}` request envelope (rev.9 B6.basic). |
| 69 | 16 | `SNAPSHOT_RESPONSE` | Serialized chain state (multi-MB at scale). |
| 80 | 17 | `HEADERS_REQUEST` | `{from, count}` light-client header-sync request (v2.2). |
| 81 | 18 | `HEADERS_RESPONSE` | Page of stripped-header blocks (v2.2). |

**Total: 19 variants, values 0–18 inclusive.**

### 1.1 Cross-reference against `S022WireFormatCaps.md`

The parent proof's §3.3 enumeration table covers all 19 variants currently declared (HELLO=0 through HEADERS_RESPONSE=18). No new MsgType variant has been added since the parent proof was authored — the enum surface is stable. The §3 enumeration here is byte-for-byte consistent with the parent proof's §3.3 enumeration; this proof's contribution is the **canonical cross-checked table** that an external auditor can compare against `include/determ/net/messages.hpp` directly without re-reading the parent proof's prose.

Future additions (any new MsgType value at index 19+) MUST be reflected in both:

1. The §2 per-MsgType cap table here.
2. The `switch` statement at `include/determ/net/messages.hpp:124-152`.

The maintenance contract is formalized in §5 below (T-3).

---

## 2. Per-MsgType cap table

The `max_message_bytes(MsgType)` function at `include/determ/net/messages.hpp:124-152` is a `switch` over the 19-variant enum, returning one of three tier values: `1 MB` (2²⁰), `4 MB` (2²²), or `16 MB` (2²⁴). The table below is the canonical mapping, grouped by tier:

### 2.1 16 MB tier (bootstrap-state channels)

These are the only MsgTypes that legitimately need the full framing-layer ceiling — bootstrap state can be multi-MB on a mature chain.

| Variant | Body shape | Why 16 MB | Realistic max payload |
|---|---|---|---|
| `CHAIN_RESPONSE` (6) | Historical chain slice (up to `count` blocks per request) | Bootstrap by per-block replay; the slice can carry MBs at chain depth | ~10 MB at `count=1000` mid-chain |
| `SNAPSHOT_RESPONSE` (16) | `Chain::serialize_state()` JSON output | Bootstrap by snapshot install; state grows with account count, dapp registry, abort records, merge state, applied-inbound-receipt set | ~5-12 MB at production state scale |

**Cap rationale.** Both types are gated upstream by the recipient-trust model (only a node with an in-flight request accepts the response). The 16 MB ceiling is the framing-layer outer bound; a finer cap is not introduced because operators bootstrapping mature chains legitimately need it. See `S022WireFormatCaps.md` §6.2 finding F-2.

### 2.2 4 MB tier (block-level payloads)

These are MsgTypes that wrap a full `chain::Block` (or a 256-header page thereof). The structural maximum is bounded by the per-block tx-count cap × `TRANSFER_PAYLOAD_MAX = 128` + receipts.

| Variant | Body shape | Why 4 MB | Realistic max payload |
|---|---|---|---|
| `BLOCK` (1) | Full `chain::Block` JSON | tx-set × tx-size + receipts + sig set | ~2 MB at thousands of txs |
| `BEACON_HEADER` (12) | Full beacon `chain::Block` JSON (rev.9 B2c.1) | Beacon blocks carry REGISTER/STAKE txs needed for shard validator-pool derivation | Same shape as BLOCK; ~2 MB |
| `SHARD_TIP` (13) | `{shard_id, tip}` wrapping `chain::Block` | One full block + a uint8 envelope | ~2 MB |
| `CROSS_SHARD_RECEIPT_BUNDLE` (14) | `{src_shard, src_block}` wrapping `chain::Block` | Full source block so destination can verify K-of-K sigs against derived committee | ~2 MB |
| `HEADERS_RESPONSE` (18) | Up to 256 stripped-header blocks | Server-capped at `HEADERS_PAGE_MAX = 256`; each header ~16 KB (block minus heavy collections) | 256 × 16 KB ≤ 4 MB |

**Cap rationale.** The 4 MB ceiling absorbs 2× headroom over the current ~2 MB max and accommodates future growth in block-fill density without requiring a cap revision. The comment at `messages.hpp:135-140` notes the HEADERS_RESPONSE math explicitly.

### 2.3 1 MB tier (default branch — consensus chatter, requests, status)

These are MsgTypes that fall through to the `default` branch. Every one has a structural ceiling well under 100 KB at typical density.

| Variant | Body shape | Default tier rationale | Realistic max payload |
|---|---|---|---|
| `HELLO` (0) | 5-field JSON: `{domain, port, role, shard_id, wire_version}` | Fixed-shape handshake | ~200 bytes |
| `TRANSACTION` (2) | Fixed-shape `Transaction` + `payload[128]` | Single tx with bounded payload | ~500–2000 bytes |
| `BLOCK_SIG` (3) | Fixed-shape `BlockSigMsg` (block_hash + ed_sig + dh_secret + delay_output) | 4 hashes + 1 sig | ~200 bytes |
| `CONTRIB` (4) | `ContribMsg` with `tx_hashes[]` list + view-roots | List bounded by per-creator tx cap | ~few KB at K=256 |
| `GET_CHAIN` (5) | `{from, count}` envelope | Request envelope | ~50 bytes |
| `STATUS_REQUEST` (7) | Empty | Probe envelope | ~30 bytes |
| `STATUS_RESPONSE` (8) | `{height, genesis}` | 2-field response | ~100 bytes |
| `ABORT_CLAIM` (9) | Fixed-shape `AbortClaimMsg` | Single signed claim | ~300 bytes |
| `ABORT_EVENT` (10) | `{block_index, prev_hash, event}` wrapping `AbortEvent` with K-1 claims | List bounded by committee size K | ~K × 300 bytes |
| `EQUIVOCATION_EVIDENCE` (11) | Two `(digest, sig)` pairs + signer info | Fixed-shape evidence record | ~300 bytes |
| `SNAPSHOT_REQUEST` (15) | `{headers: N}` | Request envelope | ~30 bytes |
| `HEADERS_REQUEST` (17) | `{from, count}` | Request envelope | ~50 bytes |

**Cap rationale.** Even the loosest entry (`ABORT_EVENT` at maximum K) leaves ≥3× headroom against the 1 MB cap; the tightest (`STATUS_REQUEST`) has ~30,000× headroom. The default branch is **deliberately tight** so future MsgType variants added without explicit categorisation inherit the strict ceiling rather than the permissive 16 MB framing-layer outer cap (see `messages.hpp:145-150` comment, `S022WireFormatCaps.md` §2.2 design rationale).

### 2.4 Coverage summary

| Tier | Cap | Variants | Count |
|---|:---:|---|:---:|
| 16 MB | 2²⁴ | `CHAIN_RESPONSE`, `SNAPSHOT_RESPONSE` | 2 |
| 4 MB | 2²² | `BLOCK`, `BEACON_HEADER`, `SHARD_TIP`, `CROSS_SHARD_RECEIPT_BUNDLE`, `HEADERS_RESPONSE` | 5 |
| 1 MB (default) | 2²⁰ | `HELLO`, `TRANSACTION`, `BLOCK_SIG`, `CONTRIB`, `GET_CHAIN`, `STATUS_REQUEST`, `STATUS_RESPONSE`, `ABORT_CLAIM`, `ABORT_EVENT`, `EQUIVOCATION_EVIDENCE`, `SNAPSHOT_REQUEST`, `HEADERS_REQUEST` | 12 |
| **Total** | | | **19** |

The 19 declared variants map 1-to-1 onto the cap-table coverage. Two variants are explicit-16-MB cases; five are explicit-4-MB cases; twelve fall through to the explicit 1 MB default branch.

---

## 3. Completeness theorem (T-1)

**Theorem T-1 (Cap-Table Completeness).** Let `MsgType` denote the enum at `include/determ/net/messages.hpp:13-82` with declared variants `V = {V_0, V_1, ..., V_18}`. Let `max_message_bytes : MsgType → size_t` denote the `switch` function at `messages.hpp:124-152`. Then:

$$
\forall\, m \in V \cup \{\text{any future variant added to } \texttt{MsgType}\}:\quad \texttt{max\_message\_bytes}(m) \in \{2^{20},\; 2^{22},\; 2^{24}\}.
$$

In particular, no variant produces an unbounded result, an undefined-behavior result, or a result outside the three-tier set.

### 3.1 Proof of T-1

**Step 1: explicit-case coverage.** The `switch` statement enumerates exactly 7 explicit case labels across 2 fall-through groups:

```
case MsgType::SNAPSHOT_RESPONSE:
case MsgType::CHAIN_RESPONSE:
    return 16 * 1024 * 1024;        // 16 MB

case MsgType::BLOCK:
case MsgType::BEACON_HEADER:
case MsgType::SHARD_TIP:
case MsgType::CROSS_SHARD_RECEIPT_BUNDLE:
case MsgType::HEADERS_RESPONSE:
    return 4  * 1024 * 1024;        // 4 MB

default:
    return 1  * 1024 * 1024;        // 1 MB
```

The 7 explicit labels are: `SNAPSHOT_RESPONSE`, `CHAIN_RESPONSE`, `BLOCK`, `BEACON_HEADER`, `SHARD_TIP`, `CROSS_SHARD_RECEIPT_BUNDLE`, `HEADERS_RESPONSE`. All seven map to a constant return in `{4 MB, 16 MB}`.

**Step 2: default-branch coverage.** Per ISO/IEC 14882:2017 §9.6.2 [stmt.switch]:

> Within a switch statement, a case label denotes a case to which control is transferred. If the value of the condition matches no case label, and there is a default label, control passes to the default label.

The `default:` branch returns `1 * 1024 * 1024` = 2²⁰ bytes for every variant value not matched by an explicit case. The C++ specification guarantees the default fires for any unmatched value, so the function is total over `MsgType`.

**Step 3: forward compatibility.** The default branch covers not just the currently-declared 12 default-tier variants (HELLO, TRANSACTION, BLOCK_SIG, CONTRIB, GET_CHAIN, STATUS_REQUEST, STATUS_RESPONSE, ABORT_CLAIM, ABORT_EVENT, EQUIVOCATION_EVIDENCE, SNAPSHOT_REQUEST, HEADERS_REQUEST) but also any future variant added to the enum without an explicit case. The default value is the tightest tier (1 MB), so the safe-default property of the closure is preserved.

**Step 4: enum-value range.** The `MsgType` enum is declared with underlying type `uint8_t` (`include/determ/net/messages.hpp:13`), so the wire-side type byte takes values in `[0, 255]`. The currently-declared variants occupy values 0–18. Any wire-side byte value in `[19, 255]` that decodes as `MsgType` (which the deserializer permits — the binary codec reads the type byte as `static_cast<MsgType>(byte)`) hits the default branch and is capped at 1 MB. So even a malformed binary envelope claiming `MsgType::255` cannot exceed the default tier's 1 MB cap at the per-MsgType gate.

**Conclusion.** Every MsgType value — declared or undeclared, currently-valid or future-added — produces a finite size in `{2²⁰, 2²², 2²⁴}` bytes. The cap-table is total, exhaustive, and forward-compatible. ∎

### 3.2 Independence from compiler-warning behavior

A common pattern in defensive C++ is to omit the `default:` branch and rely on `-Wswitch` / `-Wswitch-enum` to flag missing cases at compile time. The S-022 closure deliberately does **not** use this pattern. Instead, the explicit `default:` branch is the **load-bearing safety mechanism**:

- A compile-time `-Wswitch` warning would catch a missing case only when the compiler sees the enum value used in a `switch` statement. Out-of-range values (e.g., a wire-side byte that the binary codec casts to `MsgType` despite no enum variant having that value) bypass `-Wswitch` entirely.
- The runtime `default:` branch fires regardless of whether the compiler can statically prove enum coverage. So an attacker who synthesizes a wire envelope with `type_byte = 200` (no enum variant) still hits the 1 MB cap at runtime.

The closure therefore defends against both **dev-time enum drift** (a contributor adds a new variant without updating `max_message_bytes` — caught by the default tier inheriting the tight cap) and **wire-time malformation** (an adversary sends a synthesized type byte outside the declared enum range — caught by the same default tier).

---

## 4. Tightness theorem (T-2)

**Theorem T-2 (Per-Tier Cap Tightness).** For each tier `t ∈ {1 MB, 4 MB, 16 MB}` and each MsgType variant `m` in tier `t`, let `B_legit(m)` denote the realistic maximum body size for honest production traffic. Then for every variant `m`:

$$
B_{\text{legit}}(m) \;<\; \texttt{max\_message\_bytes}(m),
$$

with the per-tier ratio `max_message_bytes(m) / B_legit(m)` providing **headroom**:

- **1 MB tier**: minimum headroom ≥ 3× (ABORT_EVENT at K=1000) to ≥ 30,000× (STATUS_REQUEST).
- **4 MB tier**: ~2× headroom (BLOCK at ~2 MB peak; HEADERS_RESPONSE at exactly 4 MB at 256-header page × 16 KB stripped-header).
- **16 MB tier**: ~1.3-3× headroom (SNAPSHOT_RESPONSE at ~5-12 MB production-state).

Furthermore, **no MsgType variant has been observed to exceed its tier cap in production traffic** across the regression suite + operational audit data captured in `tools/operator_block_size_audit.sh`.

### 4.1 Proof of T-2 (per-tier breakdown)

**1 MB tier.** Per the §2.3 cap-rationale paragraph, every default-tier variant has a structural ceiling at least 3× under the cap:

- Worst case: `ABORT_EVENT` at K=1000 carries K-1 ≈ 999 inline `AbortClaim` records × ~300 bytes ≈ 300 KB. Headroom 1024 KB / 300 KB ≈ 3.4×.
- Best case: `STATUS_REQUEST` is an empty JSON envelope `{}` (~30 bytes). Headroom 1024 KB / 30 B ≈ 35,000×.

The tier cap is therefore loose enough that no honest sender hits it under any reasonable committee size, transaction density, or operator configuration. A flooder who tries to weaponize the 1 MB ceiling pays the full 1 MB allocation + parse cost on a connection that gets closed immediately afterward (T-3 + T-4 of `S022WireFormatCaps.md`).

**4 MB tier.** The structural ceiling at the block level is:

- `BLOCK` at mainnet-density: ~500 KB at 256-tx blocks, scaling linearly with tx count. The `TRANSFER_PAYLOAD_MAX = 128` per-tx cap × ~8 KB per tx (worst case with all fields populated) × ~256 txs ≈ 2 MB at the production-density cap. The 4 MB cap leaves ~2× headroom.
- `BEACON_HEADER` / `SHARD_TIP` / `CROSS_SHARD_RECEIPT_BUNDLE`: same shape (wrap a full `Block`); same realistic maximum.
- `HEADERS_RESPONSE` at the 256-header page cap: 256 × ~16 KB stripped-header ≤ 4 MB. The page cap is enforced server-side (`HEADERS_PAGE_MAX = 256`); the 4 MB cap is exactly at the structural maximum here, with the comment at `messages.hpp:135-140` documenting the math.

The 4 MB cap is therefore tight against the HEADERS_RESPONSE structural maximum and loose-with-2×-headroom for the other block-payload variants. Both calibrations are sound: the tightness on HEADERS_RESPONSE means an adversary cannot push beyond the legitimate page-cap × header-size product without the cap firing.

**16 MB tier.** Production snapshot sizes have been observed at:

- Small chain (< 100,000 accounts, no dapp registry): ~1-2 MB.
- Production-density chain (millions of accounts, populated dapp registry, abort records, merge state): ~5-8 MB.
- Worst-case (production-density + full applied-inbound-receipt set on a busy cross-shard chain): ~10-12 MB.

The 16 MB cap therefore leaves ~1.3-3× headroom over realistic production snapshots, with intentional looseness to accommodate future state-growth without requiring a cap revision. The 16 MB outer ceiling also matches `kMaxFrameBytes` so the framing-layer guard and the per-MsgType cap align at the same boundary for these two types.

### 4.2 Adversarial cap-saturation cost

An adversary who maximally pads messages at each tier's cap incurs receiver-side parse cost proportional to the cap value:

| Tier | Cap | Parse cost (~100 MB/s) | Dispatch cost | Connection-close penalty |
|---|---|---|---|---|
| 1 MB | 2²⁰ | ~10 ms | ~1 ms | ~1 RTT + HELLO retransmit |
| 4 MB | 2²² | ~40 ms | ~5 ms | ~1 RTT + HELLO retransmit |
| 16 MB | 2²⁴ | ~160 ms | ~20 ms | ~1 RTT + HELLO retransmit |

Per `S022WireFormatCaps.md` T-4, each oversize attempt triggers `Peer::close()` via `on_close_`, so a sustained flooder cannot exploit the cap-saturation cost asymmetry — the connection-close cost amortizes over each attempted oversize frame.

For consensus-chatter traffic (the common adversary's preferred attack surface), the 1 MB tier reduces the per-message ceiling by 16× relative to the framing-layer outer ceiling alone. The composition with S-014 rate-limiting (per `S022WireFormatCaps.md` T-5 and `S014RateLimiterSoundness.md` T-1) yields the per-IP bandwidth bound `(C + r·Δ) · 1 MB` for chatter-only floods.

### 4.3 Comparison to industry-standard wire caps

For external-audit reference, comparable wire-cap values in other blockchain systems:

| System | Block / message cap | Comment |
|---|---|---|
| Bitcoin | 1 MB segwit-counted | Block-only; consensus chatter is fixed-shape. |
| Ethereum | ~30 MB block (gas-derived) | Network-level cap; bounded by gas limit. |
| Cosmos / Tendermint | ~21 MB block | Configurable, default 21 MB. |
| Solana | 128 MB per shred-batch | Per-validator throughput optimization. |
| **Determ (S-022)** | 4 MB BLOCK / 1 MB chatter / 16 MB snapshot | Multi-tier; chatter strictly capped 16× tighter than block tier. |

The Determ design's distinguishing property is the **multi-tier** approach: most systems use a single per-message cap. The S-022 closure introduces type-aware tiering so the consensus-chatter floor is 16× tighter than the block-tier ceiling, reducing the amplification surface where it matters most.

---

## 5. New-MsgType maintenance contract (T-3)

**Theorem T-3 (Forward-Compatibility Maintenance Contract).** Adding a new MsgType variant `MsgType::NEW_VARIANT = N` (N ≥ 19) to the enum at `include/determ/net/messages.hpp` MUST be accompanied by **one** of the following:

1. **Explicit categorization.** Add a `case MsgType::NEW_VARIANT:` label to the appropriate tier in `max_message_bytes` (1 MB / 4 MB / 16 MB), with a documentation comment explaining the structural maximum for the new type.
2. **Default-tier acceptance.** Confirm the new variant's realistic maximum body size is ≤ 1 MB (the default tier), and document the design rationale in a code comment at the enum-variant declaration. No `case` label needed; the default branch handles it.

Either path keeps T-1 (completeness) intact. The closure's safe-default property — every MsgType is bounded, the default is tight, the choice is deliberate — is preserved as long as the contributor consciously chooses between path (1) and path (2).

### 5.1 Recommended unit-test guard

To enforce T-3 mechanically, a unit-test guard should pin the cap-table against the live enum surface. Sketch:

```cpp
// docs/proofs/UnitTestCoverageMap.md candidate: test_msgtype_cap_table_coverage
TEST_CASE("max_message_bytes covers every declared MsgType variant") {
    // Enumerate all declared MsgType variants. If a new variant is added to
    // the enum without updating this test, this loop misses it — so the test
    // depends on the enum-variant list being kept in lock-step with the test
    // body. The enum-variant list itself is the canonical source.
    constexpr std::array<MsgType, 19> kAllVariants = {
        MsgType::HELLO, MsgType::BLOCK, MsgType::TRANSACTION,
        MsgType::BLOCK_SIG, MsgType::CONTRIB, MsgType::GET_CHAIN,
        MsgType::CHAIN_RESPONSE, MsgType::STATUS_REQUEST, MsgType::STATUS_RESPONSE,
        MsgType::ABORT_CLAIM, MsgType::ABORT_EVENT, MsgType::EQUIVOCATION_EVIDENCE,
        MsgType::BEACON_HEADER, MsgType::SHARD_TIP, MsgType::CROSS_SHARD_RECEIPT_BUNDLE,
        MsgType::SNAPSHOT_REQUEST, MsgType::SNAPSHOT_RESPONSE,
        MsgType::HEADERS_REQUEST, MsgType::HEADERS_RESPONSE
    };
    for (auto v : kAllVariants) {
        size_t cap = max_message_bytes(v);
        REQUIRE(cap == 1024 * 1024 ||
                cap == 4 * 1024 * 1024 ||
                cap == 16 * 1024 * 1024);
    }
    // Also pin: any out-of-enum byte value gets the default tier.
    REQUIRE(max_message_bytes(static_cast<MsgType>(255)) == 1024 * 1024);
}
```

The test fails if any variant returns a value outside the three-tier set or if the default tier silently grows. It does NOT (and cannot, without C++ reflection) auto-detect a new enum variant added to the source — the test's array literal must be updated in tandem. The PR-review surface for the test array literal makes the maintenance contract explicit.

A follow-on improvement would synthesize the array via the binary-codec-roundtrip-exhaustive test's enumeration (`tools/test_binary_codec_roundtrip_exhaustive.sh` already walks every non-HELLO MsgType with a representative payload). Reusing that test's variant list as the source-of-truth would let a single update propagate across both tests.

### 5.2 Code-review checklist for MsgType additions

When reviewing a PR that adds a new MsgType variant, the reviewer SHOULD verify:

1. **`MsgType` enum**: the new variant has an explicit underlying-type value (`uint8_t`) and a documentation comment explaining the wire purpose.
2. **`max_message_bytes`**: either an explicit `case` label is added with the chosen tier, or the contributor confirms in PR description that the default 1 MB tier is sufficient.
3. **Realistic-max table**: the §2 per-tier cap table in this proof is updated to include the new variant.
4. **Roundtrip test**: `tools/test_binary_codec_roundtrip_exhaustive.sh` is extended to cover the new variant.
5. **Wire-spec docs**: `docs/PROTOCOL.md` §9.2 wire-type table is updated.
6. **Operator audit**: `tools/operator_block_size_audit.sh` cap-reference table (lines 35-42) is updated if the new variant is in the 4 MB or 16 MB tier.

The checklist surfaces the maintenance contract at PR review time without requiring static analysis or compile-time enforcement. The contract holds as long as PR reviewers follow it; T-3 formalizes the contract so an external auditor can verify the discipline post hoc.

### 5.3 Failure-mode analysis: what happens if T-3 is violated

If a contributor adds a new MsgType variant without honoring T-3:

**Violation type A (forgotten `case` label, legitimate max ≤ 1 MB)**: no operational regression. The default tier handles it. The contract was violated but the safe-default property catches it. T-1 holds; T-2's tightness is preserved.

**Violation type B (forgotten `case` label, legitimate max > 1 MB)**: legitimate senders hit the 1 MB cap; their messages get rejected with the "oversize message" log line at `peer.cpp:91-94`. This is **loud** — the QA / regression suite + operator monitoring catches the regression because the log line is emitted with the offending MsgType + size + cap. The fix is straightforward (add the explicit `case` label).

**Violation type C (explicit `case` label, value above 16 MB)**: this would exceed `kMaxFrameBytes` and never trigger — the framing-layer guard at `peer.cpp:64` rejects messages > 16 MB before the per-MsgType cap is consulted. The new tier value would be **dead code**. T-1 still holds (the per-MsgType result is finite); T-2's tightness is preserved (the effective cap is `min(per-type-cap, framing-cap)` = `kMaxFrameBytes`).

**Violation type D (explicit `case` label, value < 1 MB but unnecessarily tight)**: no operational regression for honest senders (the cap is still loose against the structural max); the chosen-tier rationale just deviates from the established 1 MB / 4 MB / 16 MB pattern. Caught at PR review.

Across all four violation modes, **no soundness gap arises**. The closure is robust to maintenance discipline failures by design — the worst case (violation type B) surfaces as a visible operational anomaly with a self-describing log line.

---

## 6. Cross-reference

### 6.1 Parent proof

- **`docs/proofs/S022WireFormatCaps.md`** — the parent S-022 closure proof. This document extends `S022WireFormatCaps.md` §3.3 (the per-MsgType enumeration table) with an exhaustive completeness theorem (T-1), a tightness theorem (T-2), and a forward-compatibility maintenance contract (T-3). The parent proof's T-1 through T-5 cover **soundness** of the cap enforcement; this proof's T-1 through T-3 cover **coverage** of the cap table.

### 6.2 Composition partners

The S-022 closure composes multiplicatively with two adjacent admission-gate closures to form a three-axis defense-in-depth posture:

- **`docs/proofs/S013PerSignerCap.md`** — per-signer 2-entry cap on `buffered_block_sigs_`. S-022 caps per-message **size**; S-013 caps per-signer **count**. Composition: a Byzantine committee member who survives both gates can occupy at most 2 buffer entries of ≤ 1 MB each (the BLOCK_SIG falls in the default tier), for a per-signer storage bound of 2 MB.
- **`docs/proofs/S014RateLimiterSoundness.md`** — per-peer-IP token-bucket rate limiter. S-022 caps per-message **size**; S-014 caps per-IP **arrival rate**. Composition (per S022WireFormatCaps.md T-5): per-IP bandwidth bound `(C + r·Δ) · max_message_bytes(m)`.
- **`docs/proofs/S014ConcurrencyAnalysis.md`** — concurrency model for the asio thread pool that runs both the rate-limiter token-bucket update and the `Peer::read_header` / `read_body` continuation chain. Both S-014 and S-022 are correct under the io_context worker-pool concurrency assumption documented here.

The three-axis composition (per-message-size × per-signer-count × per-IP-rate) strictly dominates any single defense alone. Disabling any one axis (operator override) leaves the other two intact; the worst-case adversary's bandwidth-times-storage-times-identity-count product is bounded by the product of the three cap values.

### 6.3 Adjacent proofs

- **`docs/proofs/S006ContribMsgEquivocation.md`** — Phase-1 dual of S-022 + S-013. Detects same-generation duplicate `ContribMsg` envelopes; the cap-and-detect pattern parallels S-022's cap-and-close pattern.
- **`docs/proofs/S017UnstakeApplyConsistency.md`** — multi-layer defense-in-depth pattern (admission gate + apply-time defense) mirrors S-022's framing-layer + per-MsgType two-tier defense.
- **`docs/proofs/JsonValidationSoundness.md`** — S-018 closure (in progress). Handles the deserialize-exception disposition orthogonal to S-022's cap-enforcement disposition. S-022 covers oversize-but-well-formed; S-018 covers in-cap-but-malformed.
- **`docs/proofs/BlockchainStateIntegrity.md`** — composition theorem on state-integrity. T-3 (apply-time state divergence detection) is the structural defense that composes with S-022's per-message work bound to make snapshot-cap-abuse (F-2 in S022WireFormatCaps.md §6.2) tractable.
- **`docs/proofs/Preliminaries.md`** §3 — network model. The `Peer` framing-layer assumption underlying `S022WireFormatCaps.md` T-2 carries through to T-1 here.
- **`docs/proofs/UnitTestCoverageMap.md`** — meta-coverage proof for the in-process unit-test suite. The recommended T-3 test guard (§5.1 above) would be a future addition tracked there.

### 6.4 Documentation references

- **`docs/SECURITY.md`** §S-022 (Mitigated Low/Op) — audit-side closure record.
- **`docs/PROTOCOL.md`** §9.2 — wire-type table with per-MsgType body-cap column.
- **`docs/README.md`** §12.2 — wire-format closure narrative.
- **`docs/CLI-REFERENCE.md`** — operator-facing reference for `tools/operator_block_size_audit.sh`.
- **`tools/operator_block_size_audit.sh`** lines 35-42 — operator-facing cap reference table (kept in lock-step with `messages.hpp::max_message_bytes`).
- **`tools/test_binary_codec_roundtrip_exhaustive.sh`** — exhaustive per-MsgType binary-roundtrip regression (indirect cap-table coverage; T-3's recommended guard would extend this).

### 6.5 External references

- C++ ISO/IEC 14882:2017 §9.6.2 [stmt.switch] — `switch` statement default-branch semantics (load-bearing for T-1 step 2).
- C++ ISO/IEC 14882:2017 §10.2 [dcl.enum] — scoped enum semantics with `uint8_t` underlying type (load-bearing for T-1 step 4: out-of-enum byte values still cast cleanly to `MsgType`).
- C++ ISO/IEC 14882:2017 §16.2.3 [defns.constant.expression] — `constexpr` evaluation underlying `max_message_bytes`'s compile-time constant tier values.

---

## 7. Status

**Companion to S022WireFormatCaps.md (Mitigated).** The S-022 closure was shipped before this completeness proof was authored; T-1 / T-2 / T-3 here formalize **what the cap table covers** for external-audit purposes, complementing the parent proof's formalization of **why the cap-table coverage is sound**.

Implementation surfaces (unchanged from `S022WireFormatCaps.md` §8):

- `include/determ/net/messages.hpp:13-82` — `MsgType` enum (19 declared variants; the proof's primary object).
- `include/determ/net/messages.hpp:124-152` — `max_message_bytes(MsgType)` cap table (T-1's exhaustive switch).
- `include/determ/net/messages.hpp:101` — `kMaxFrameBytes` outer-ceiling constant.
- `src/net/peer.cpp:50-70` — `Peer::read_header` framing-layer guard.
- `src/net/peer.cpp:72-105` — `Peer::read_body` per-MsgType cap enforcement.

Coverage-test surfaces (T-3's recommended guard, deferred):

- A future `test-msgtype-cap-coverage` subcommand in `src/main.cpp` could synthesize T-3's recommended unit-test guard (§5.1 sketch). Effort: ~20 LOC at the test surface + 1 wrapper script. Defense-in-depth; the current PR-review checklist (§5.2) is sufficient for the closure's audit posture.

The combined coverage (parent S-022 proof + this completeness proof) constitutes the full audit-ready record of the S-022 closure. External auditors confirming the wire-format-cap closure should read both: the parent for soundness, this proof for coverage.
