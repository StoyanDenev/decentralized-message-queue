#!/usr/bin/env bash
# D2-inc8 — in-process unit test for the canonical binary GenesisConfig
# container (`chain::GenesisConfig::encode` / `decode`, src/chain/genesis.cpp).
#
# The genesis config FILE is at-rest storage, so as of inc8 it is binary-ONLY:
# GenesisConfig::load/save go through the DGC1 container, the node and
# determ-light decode it with no format sniffing and no text fallback, and
# to_json/from_json survive purely as the CLI text VIEW plus the build-time
# authoring shape `genesis-tool build <config.json>` accepts.
#
# THE LOAD-BEARING THEOREM is GB-3, HASH NEUTRALITY:
#
#     compute_genesis_hash(decode(encode(c))) == compute_genesis_hash(c)
#
# The genesis hash is value-derived — a SHA256Builder over parsed FIELDS, never
# over the file bytes — so swapping the container provably cannot move a
# chain's identity. That is what makes this change legal under the
# no-migrations constraint: every genesis_hash an operator has already pinned
# still matches after the file format changes underneath it.
#
# The other falsifier is GB-6, VALIDATION PARITY. decode() must run the SAME
# GenesisConfig::validate() that from_json runs — the shared rule set extracted
# in this increment. Dropping that call would let a binary genesis carry states
# the JSON path rejects (governed-without-keyholders, LOTTERY multiplier < 2,
# subsidy above the S-007 1e18 bound, an out-of-range beacon shard_id), i.e.
# two loaders with two rule sets and a silent divergence between operators who
# authored their genesis differently. GB-6 also pins the canonical-form rules
# the binary container owns and the JSON view cannot have: a region must
# already equal its normalized image (rejected, not silently rewritten) and
# beacon_shard_regions must be strictly ascending by shard_id — so one config
# has exactly one encoding.
#
# Legs:
#   GB-1  information equivalence with the JSON container on a config
#         exercising every encoded field (governed + keyholders, BEACON +
#         shard_regions, CT-disabled, FIPS, custom message, creators with
#         regions, balances, non-zero salt, every scalar off its default).
#   GB-2  encode(decode(x)) == x byte-for-byte — one canonical encoding.
#   GB-3  hash neutrality, on the full config, on the derived genesis BLOCK
#         hash, and on an all-default config (what nearly every deployed
#         genesis actually is).
#   GB-4  exactness BOTH directions: every proper prefix rejected; one
#         trailing byte rejected with a 'trailing byte(s)' diagnostic.
#   GB-5  hostile bytes: every single-byte corruption twice over (^0x01,
#         ^0xFF). Contract is the BF-12 one — decode or throw, never UB —
#         and reaching the end of the sweep IS the assertion. Survivors must
#         still be canonical (encode(decode(t)) == t), so no corrupted input
#         has a second encoding.
#   GB-6  validate() parity + the canonical-form and container rules.
#   GB-7  the at-rest path: save() writes DGC1, load(save(c)) is hash-stable,
#         and a JSON file at the at-rest path is REJECTED (no text fallback).
#
# Run from repo root: bash tools/test_genesis_binary_codec.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== GenesisConfig binary container (DGC1, D2-inc8) ==="
OUT=$($DETERM test-genesis-binary-codec 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: genesis-binary-codec all assertions"; then
  echo ""
  echo "  PASS: genesis-binary-codec unit test"
  exit 0
else
  echo ""
  echo "  FAIL: genesis-binary-codec had assertion failures"
  exit 1
fi
