#!/usr/bin/env bash
# INGRESS beacon-header gate: committee floor (DECISION-LOG 2026-07-31 Hole 2)
# + cumulative_rand authentication (DECISION-LOG 2026-08-12 Q1).
#
# Node::on_beacon_header's hand-rolled K-of-K loop was vacuous for an empty (or
# shrunken) creators list: size match 0==0, zero loop iterations, 0 != 0 false
# -> ACCEPTED. An untrusted mesh peer could push a creator-less beacon header
# carrying attacker-chosen cumulative_rand into beacon_headers_, which feeds
# shard epoch-committee selection (current_epoch_rand). The fix routes the
# handler through the ONE shared committee-signature core verify_committee_sigs
# (shardtip_verify.cpp — the same core verify_shard_tip_committee_sig_root
# routes through): NON-EMPTY creators + signed_count >= cfg_.k_block_sigs,
# keeping the caller-side signed_count == creators.size() completeness rule.
#
# In-process SHARD-role node harness (K=2) drives on_beacon_header_for_test:
#   EMPTY-COMMITTEE FORGE: creators={} REJECTED (headline falsifier);
#   UNDER-K FORGE:         creators={node0}, fully signed, REJECTED by the
#                          signed_count >= required_k floor;
#   ZERO-SENTINEL FORGE:   3 creators, 2 sign (passes floor), REJECTED by the
#                          retained completeness rule;
#   POSITIVE CONTROL:      honest full K-of-K ACCEPTED (acceptance unchanged).
# Falsify-on-mutant: (a) re-admit the vacuous loop -> EMPTY case flips RED;
# (b) delete the signed_count < required_k arm in the helper -> UNDER-K RED.
#
# Q1 (DECISION-LOG 2026-08-12) — cumulative_rand authentication. The K-of-K
# creator_block_sigs cover compute_block_digest, which excludes cumulative_rand,
# delay_output AND creator_dh_secrets. A MITM could therefore rewrite the
# header's randomness — the value this ingest path exists to deliver into shard
# epoch-committee selection (current_epoch_rand) — with every signature still
# verifying. Step 5 of on_beacon_header now runs the ONE shared validator seam
# BlockValidator::check_header_rand_binding, which re-runs the three apply-path
# gates that bind the field, with NO wire and NO digest change:
#   commit-reveal  SHA256(secret_i || pk_i) == creator_dh_inputs[i]  (digest-
#                  covered) -> the secrets are pinned  [LOAD-BEARING: they are
#                  not digest-covered, so without it delay_output is grindable]
#   check_delay    delay_seed == compute_delay_seed(index, prev_hash, tx_root,
#                  creator_dh_inputs) and delay_output ==
#                  compute_block_rand(delay_seed, secrets) -> output pinned
#   chaining       cumulative_rand == SHA256(prev_rand || delay_output), where
#                  prev_rand is the PREVIOUS TRACKED BEACON HEADER's rand — NOT
#                  chain.head() (that is the shard's own, unrelated chain).
# FIRST-HEADER RULE: the first tracked header is beacon index 1, whose
# predecessor is the beacon GENESIS block, which a shard neither holds nor pins
# (beacon-genesis pinning is the named B2c.5 follow-on) and whose rand is a
# genesis-config-derived hash, not zero. Its prev_rand is therefore unknowable
# here: the first two links still run, only the last is skipped. Residual,
# documented not closed: on that ONE header cumulative_rand stays attacker-
# choosable — but compute_hash covers it and the next genuine header's prev_hash
# is digest-signed, so a tamper makes header 2 fail to chain (bias one epoch,
# then stall — unchanged from before Q1). Closing it needs the B2c.5 pin.
# Q1 arms (all carry UNBROKEN, still-valid K-of-K sigs — that is the point):
#   FIRST RAND-GRIND:  substitute creator_dh_secrets[0], re-derive delay_output
#                      + cumulative_rand -> REJECTED by commit-reveal;
#   FIRST DELAY FORGE: rewrite delay_output alone -> REJECTED by check_delay;
#   POSITIVE #1:       honest first header ACCEPTED;
#   TAMPERED RAND h=2: honest chained header with cumulative_rand flipped ->
#                      REJECTED (the headline falsifier);
#   POSITIVE #2:       the same header untampered ACCEPTED.
# Falsify-on-mutant: (c) delete step 5 of on_beacon_header -> the three Q1
# tamper arms flip RED, both positives + the three Hole-2 arms stay GREEN;
# (d) drop only the check_creator_dh_secrets_with link inside the seam -> ONLY
# the rand-grind arm flips RED.
#
# Run from repo root: bash tools/test_beacon_header_committee.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== beacon-header-committee — on_beacon_header committee floor (Hole 2) ==="
OUT=$($DETERM test-beacon-header-committee 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-beacon-header-committee"; then
  echo ""
  echo "  PASS: beacon-header-committee unit test"
  exit 0
else
  echo ""
  echo "  FAIL: beacon-header-committee had assertion failures"
  exit 1
fi
