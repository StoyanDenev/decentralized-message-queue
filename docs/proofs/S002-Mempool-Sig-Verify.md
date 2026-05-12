# S-002 mempool signature verification + the binary-codec dependency

This document records an in-session attempt to close S-002 (mempool accepts unverified signatures, enabling forged-sig DoS amplification) and the latent pre-existing bug it surfaced in `src/net/binary_codec.cpp`. Both findings need to be fixed together; this doc captures the dependency so the next attempt doesn't repeat the discovery cycle.

## 1. The fix attempt

S-002 reports that neither `Node::on_tx` (gossip-path handler) nor `Node::rpc_submit_tx` (client-RPC handler) verifies a transaction's Ed25519 signature before admitting it into the mempool. The full validator's `check_transactions` re-verifies later at block-apply time, but bad-sig transactions in the meantime:

- consume mempool slots
- gossip amplifies them to peers
- producers may include them in tentative blocks, triggering round aborts when the validator rejects the block

The proposed fix: add a per-tx signature verification at admission time. Implementation:

```cpp
bool Node::verify_tx_signature_locked(const chain::Transaction& tx) const {
    // Determine pubkey based on tx.type and tx.from:
    //   REGISTER → first 32 bytes of payload (the new key)
    //   anon TRANSFER → parse_anon_pubkey(tx.from)
    //   else → registry lookup for tx.from
    // Then verify(pk, tx.signing_bytes(), tx.sig).
}
```

Call from both `on_tx` (silent drop on failure) and `rpc_submit_tx` (throw on failure so the client gets feedback).

This was implemented and reverted in-session. The implementation itself is correct — the validator's per-tx check uses the same logic and works. The revert was forced by a latent bug elsewhere.

## 2. The latent bug

`src/net/binary_codec.cpp::encode_tx_frame` writes the canonical transaction fields to a fixed-slot layout at the front of the encoded frame:

```
offset  0..31:  sender_pubkey slot      (right-padded tx.from)
offset 32..39:  amount  (u64 LE)
offset 40..47:  fee     (u64 LE)
offset 48..55:  nonce   (u64 LE)
offset 56..63:  reserved (must be zero)
offset 64..95:  recipient_pubkey slot   (right-padded tx.to)
offset 96..127: payload slot            (first 32 bytes, right-padded)
offset 128:     trailer (type, payload_len, overflow, from, to, sig, hash)
```

`decode_tx_frame` reads the trailer (starting at offset 128) and reconstructs `tx.type`, `tx.payload`, `tx.from`, `tx.to`, `tx.sig`, `tx.hash`. It does **not** read `tx.amount`, `tx.fee`, or `tx.nonce` from the fixed slots at offsets 32–55.

Result: a tx serialized via the binary codec and then deserialized arrives with `amount = 0`, `fee = 0`, `nonce = 0`. Its `signing_bytes()` over those zero values doesn't match the original signing bytes signed by the sender. Sig verification fails.

## 3. Why the existing tests weren't catching this

Without admission-time sig verification, a tx with zero amount/fee/nonce was admitted to the mempool. The producer picked it up. The validator at block-apply would reject the block — except the validator's nonce mismatch check would fire first ("nonce 0 vs expected N"), causing the producer to filter and re-try. In practice the tx would either:

- Get applied with apparent zero amount (B credited with 0)
- Get filtered as nonce-mismatched

Neither case crashes loudly, so the binary-codec bug stayed latent. The bearer test passing in earlier session runs likely benefited from either (a) JSON wire path being negotiated for those connections (the binary codec is only activated when both peers advertise `wire_version >= kWireVersionBinary` in HELLO), or (b) a specific timing where the apparent-zero-amount case happened to net out with the test's specific expectations.

The S-002 fix exposed the bug clearly: with sig-verify on, the post-decode tx fails verification on the gossip path, gets silently dropped, n2/n3 never see the tx, and the test's "all 3 nodes converge" assertion fails.

## 4. The correct fix sequence

Two paired commits, in order:

### 4.1 Fix `decode_tx_frame` to read amount/fee/nonce

In `src/net/binary_codec.cpp::decode_tx_frame`, after the `size_t off = 128;` line, add:

```cpp
// Read amount/fee/nonce from the fixed slots (encoder writes them
// at offsets 32, 40, 48; reserved at 56 must be zero).
tx.amount = le_get_u64(data + 32);
tx.fee    = le_get_u64(data + 40);
tx.nonce  = le_get_u64(data + 48);
uint64_t reserved = le_get_u64(data + 56);
if (reserved != 0)
    throw std::runtime_error("binary_codec: reserved field non-zero");
```

This restores the encoder/decoder round-trip property. Existing tests should pass unchanged — the binary path produces the same tx as the JSON path.

### 4.2 Wire S-002 mempool sig verification

Once 4.1 is in, restore the calls to `verify_tx_signature_locked()`:

- In `on_tx` (gossip): silent drop on failure
- In `rpc_submit_tx` (RPC): throw with diagnostic

The helper `verify_tx_signature_locked()` is already in `src/node/node.cpp` (was left in place during the revert, with a doc-comment pointing here).

### 4.3 New regression test

A focused test that submits a tx with a deliberately-tampered signature should be rejected at RPC submit time (exit code != 0, error message mentions "signature verification failed"). Also: a tampered tx gossiped to peer B should be silently dropped (peer B's mempool stays empty).

## 5. Why this is the right order

Fixing only S-002 (without the binary codec) breaks gossip-propagated valid transactions, as in the failed attempt. Fixing only the binary codec (without S-002) leaves the DoS amplification surface open. Both need to ship together for either to be a real improvement.

The honest framing: S-002 was reported as a 2–3 day cluster of work in `docs/SECURITY.md` §1's "cheapest path to production-ready security posture" — but only because the binary-codec bug was unknown when that estimate was made. With the bug surfaced, the real estimate is closer to half a day:

- 30 lines to fix `decode_tx_frame`
- A regression test that confirms the binary round-trip preserves amount/fee/nonce
- Re-enable the existing `verify_tx_signature_locked()` calls
- A second regression test for the S-002 closure

The work is straightforward; it just needs to happen together rather than as two separate "easy" commits.

## 6. Status

- **S-002**: Open. Implementation prepared (`verify_tx_signature_locked()` exists in node.cpp); call sites reverted pending the binary-codec fix.
- **Binary codec amount/fee/nonce drop**: Pre-existing latent bug, now documented. Tracked as part of S-002 closure.
- **Bearer regression test**: Reverting S-002 calls restores the test to its previous passing/flaking behavior (TIME_WAIT race remains as the dominant intermittent failure source).

## 7. Cross-references

- `docs/SECURITY.md` S-002 — original finding.
- `src/net/binary_codec.cpp::decode_tx_frame` — the bug site.
- `src/node/node.cpp::verify_tx_signature_locked` — the prepared helper, currently unwired.
- `src/node/node.cpp::on_tx`, `Node::rpc_submit_tx` — the admission sites that need to call the helper post-codec-fix.
