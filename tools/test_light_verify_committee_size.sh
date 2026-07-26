#!/usr/bin/env bash
# LightVerify LV-1 / LV-2 — determ-light verify_block_sigs must mirror the NODE's
# committee-size mode-eligibility gate (src/node/validator.cpp check_block_sigs):
# an MD block names EXACTLY genesis k_block_sigs creators; a BFT block exactly
# ceil(2K/3); and a BFT block is refused outright when genesis bft_enabled=false.
#
# THE VULN: verify_block_sigs (light/verify.cpp) set its MD quorum floor to the
# block's OWN attacker-controlled creators.size():  required = creators.size().
# The membership loop only proves each listed creator is IN the committee; the
# COUNT was never bound to the chain's required signing-committee size. Because
# genesis permits 1 <= k_block_sigs <= m_creators, the committee POOL the light
# client passes in may be LARGER than k_block_sigs, so a MITM/malicious RPC
# daemon could serve:
#   * (LV-1) an MD block naming a SINGLE committee member (creators=[one] with
#     that member's real signature) -> required=1 -> a 1-of-K quorum downgrade
#     the node itself rejects (its m==k_full eligibility); and
#   * (LV-2) a reduced-quorum ceil(2K/3) BFT block on a chain whose genesis has
#     bft_enabled=false (a mutual-distrust-only chain that never escalates), via
#     the unconditional MD->BFT fallback.
# verify_block_sigs is the sole committee-sig gate under the state-root/inclusion/
# history anchors, so either downgrade lets a MITM forge a committee-attested
# read the user trusts.
#
# THE FIX (client-side; mirrors the node, no consensus/wire change): when the
# caller supplies the genesis k_block_sigs (--k-block-sigs here), enforce the
# node's mode-eligibility on the committee-signed b.consensus_mode:
#   MD  -> creators.size() == k_block_sigs
#   BFT -> bft_enabled AND creators.size() == ceil(2*k_block_sigs/3)
# Any block the node accepted satisfies this, so it rejects no honest block.
#
# Fully OFFLINE + FAST (no daemon): hand-built JSON headers with placeholder sigs.
# The mode-eligibility gate fires BEFORE the signature loop, so no real crypto is
# needed — a mis-sized / bft-disabled header is refused at the gate with a
# specific diagnostic, BEFORE the "signature does NOT verify" a correct-size
# header reaches.
#   NEG-LV1   MD,  1 creator, --k-block-sigs 3            -> FAIL "genesis k_block_sigs=3"
#   NEG-LV2a  BFT, 2 creators, --k-block-sigs 3 --no-bft-enabled -> FAIL "bft_enabled=false"
#   NEG-LV2b  BFT, 1 creator,  --k-block-sigs 3            -> FAIL "escalated committee size"
#   NEG-LV1b  MD, 3 creators + a sentinel slot, --bft --k-block-sigs 3 -> FAIL
#             "sentinel-zero signature in MD mode": with the mode-eligibility gate
#             active the sig semantics follow the committee-signed consensus_mode
#             (MD, K-of-K, no sentinels), so a mis-asserted --bft cannot loosen it.
#   CTRL      MD,  3 creators, --k-block-sigs 3            -> PASSES the gate, reaches
#             the sig check ("signature does NOT verify") — non-vacuity: a
#             correct-size block is NOT refused by the gate.
# Falsify-on-mutant (`if (false && expected_k > 0)`): all three NEG headers fall
# through to the sig check ("does NOT verify"), so every mode-eligibility
# diagnostic disappears and the three NEG asserts flip; the CTRL is unchanged.
#
# NB: this script never prints the raw determ-light output — its reject
# diagnostics begin with "FAIL:" (verify_block_sigs r.detail) and would land in
# run_all's tail-10 window and false-trip its ^\s*FAIL: outcome marker. The greps
# read the captured $OUT inside $(...) (that output is not echoed to the terminal).
#
# Run from repo root: bash tools/test_light_verify_committee_size.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

T=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/determ-light-committee-size.$$")
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass=0; fail=0
assert() { if [ "$1" = "true" ]; then echo "  PASS: $2"; pass=$((pass+1));
           else echo "  FAIL: $2"; fail=$((fail+1)); fi; }

# committee POOL of 3 members m0/m1/m2 (distinct 64-hex ed_pubs). k_block_sigs=3.
cat > "$T/committee.json" <<JSON
[{"domain":"m0","ed_pub":"$(printf '11%.0s' $(seq 1 32))"},
 {"domain":"m1","ed_pub":"$(printf '22%.0s' $(seq 1 32))"},
 {"domain":"m2","ed_pub":"$(printf '33%.0s' $(seq 1 32))"}]
JSON

# Hand-built headers. Placeholder (garbage, non-zero) sigs — the mode-eligibility
# gate fires before sig verification, and a correct-size header then fails the
# sig check ("does NOT verify"), which is exactly the non-vacuity control.
python - "$T" <<'PY'
import json, sys
T = sys.argv[1]
SIG  = '66' * 64  # 64-byte placeholder signature (128 hex)
ZERO = '00' * 64  # sentinel-zero signature (BFT-only slot)
def hdr(mode, creators, proposer='', sigs=None):
    h = dict(index=5, prev_hash='22'*32, state_root='33'*32, tx_root='44'*32,
             timestamp=1000, delay_seed='00'*32, consensus_mode=mode,
             cumulative_rand='55'*32, abort_events=[],
             creators=creators,
             creator_block_sigs=sigs if sigs is not None else [SIG]*len(creators))
    if mode == 1:
        h['bft_proposer'] = proposer or creators[0]
    return {'headers': [h]}
json.dump(hdr(0, ['m0']),                  open(T+'/md1.json',  'w'))  # NEG-LV1
json.dump(hdr(0, ['m0','m1','m2']),        open(T+'/md3.json',  'w'))  # CTRL
json.dump(hdr(1, ['m0','m1'], 'm0'),       open(T+'/bft2.json', 'w'))  # NEG-LV2a
json.dump(hdr(1, ['m0'],      'm0'),       open(T+'/bft1.json', 'w'))  # NEG-LV2b
# NEG-LV1b: an MD block (consensus_mode=0), correct size 3, but with a
# sentinel-zero slot — run under a mis-asserted --bft. The sig semantics must
# follow the committee-signed b.consensus_mode (MD: no sentinels), NOT --bft.
json.dump(hdr(0, ['m0','m1','m2'], sigs=[ZERO, SIG, SIG]),
          open(T+'/md3_sentinel.json', 'w'))
PY

echo "=== NEG-LV1: MD block, 1 creator, --k-block-sigs 3 -> refuse 1-of-K downgrade ==="
OUT=$("$DETERM_LIGHT" verify-block-sigs --header "$T/md1.json" --committee "$T/committee.json" --k-block-sigs 3 2>&1); RC=$?
HIT=$(echo "$OUT" | grep -qiE "genesis k_block_sigs=3" && [ $RC -eq 1 ] && echo true || echo false)
assert "$HIT" "NEG-LV1: MD 1-of-3 refused at the mode-eligibility gate (exit 1, k_block_sigs diagnostic)"

echo "=== NEG-LV2a: BFT block, --no-bft-enabled -> refuse BFT on a MD-only chain ==="
OUT=$("$DETERM_LIGHT" verify-block-sigs --header "$T/bft2.json" --committee "$T/committee.json" --bft --k-block-sigs 3 --no-bft-enabled 2>&1); RC=$?
HIT=$(echo "$OUT" | grep -qiE "bft_enabled=false" && [ $RC -eq 1 ] && echo true || echo false)
assert "$HIT" "NEG-LV2a: a BFT block is refused when genesis bft_enabled=false (exit 1)"

echo "=== NEG-LV2b: BFT block, 1 creator != ceil(2*3/3)=2 -> refuse mismatched quorum ==="
OUT=$("$DETERM_LIGHT" verify-block-sigs --header "$T/bft1.json" --committee "$T/committee.json" --bft --k-block-sigs 3 2>&1); RC=$?
HIT=$(echo "$OUT" | grep -qiE "escalated committee size" && [ $RC -eq 1 ] && echo true || echo false)
assert "$HIT" "NEG-LV2b: a BFT block with the wrong escalated committee size is refused (exit 1)"

echo "=== NEG-LV1b: MD block with a sentinel slot under a mis-asserted --bft -> MD semantics ==="
# expected_k>0 forces the sig semantics to follow the committee-signed
# consensus_mode (MD: sentinel-zero is illegal), so --bft cannot loosen the
# K-of-K quorum to ceil(2K/3). The sentinel at creator[0] must be refused.
OUT=$("$DETERM_LIGHT" verify-block-sigs --header "$T/md3_sentinel.json" --committee "$T/committee.json" --bft --k-block-sigs 3 2>&1); RC=$?
HIT=$(echo "$OUT" | grep -qiE "sentinel-zero signature in MD mode" && [ $RC -eq 1 ] && echo true || echo false)
assert "$HIT" "NEG-LV1b: --bft cannot loosen an MD block's sig semantics when k_block_sigs is enforced"

echo "=== CTRL: MD block, 3 creators == k_block_sigs 3 -> passes gate, reaches sig check ==="
OUT=$("$DETERM_LIGHT" verify-block-sigs --header "$T/md3.json" --committee "$T/committee.json" --k-block-sigs 3 2>&1); RC=$?
NOTRIP=$(echo "$OUT" | grep -qiE "k_block_sigs=|bft_enabled=false|escalated committee size" && echo false || echo true)
REACHED=$(echo "$OUT" | grep -qiE "does NOT verify" && echo true || echo false)
assert "$NOTRIP" "CTRL: a correct-size (3-of-3) MD block is NOT refused by the mode-eligibility gate"
assert "$REACHED" "CTRL: the correct-size block reaches the signature check (non-vacuity)"

echo
echo "  $pass pass / $fail fail"
if [ "$fail" = "0" ]; then
  echo "  PASS: test_light_verify_committee_size"; exit 0
else
  echo "  FAIL: test_light_verify_committee_size"; exit 1
fi
