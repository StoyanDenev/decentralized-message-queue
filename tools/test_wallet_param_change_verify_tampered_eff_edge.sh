#!/usr/bin/env bash
# determ-wallet param-change-verify — TAMPERED-EFFECTIVE-HEIGHT edge.
#
# THE EDGE (not covered by test_wallet_param_change_verify.sh or
# test_wallet_param_change_flow.sh): a governance K-of-K multisig is assembled
# OVER A FIXED effective_height H. The signatures and the keyholder pubkeys are
# pristine and correct. An attacker then mutates ONLY the on-wire
# effective_height field in the assembled PARAM_CHANGE payload — e.g. to pull an
# activation forward or push it back past a review window — WITHOUT re-signing.
#
# Because the validator binds effective_height into the canonical signing
# preimage
#     sig_msg = name_len(u8) | name | value_len(u16 LE) | value | eff(u64 LE)
# (src/node/validator.cpp:693-701), the verifier re-derives sig_msg FROM THE
# PAYLOAD'S OWN (now-mutated) eff bytes, so every otherwise-valid signature
# verifies against the WRONG preimage and becomes INVALID. Correct fail-closed
# behavior: every keyholder INVALID, good_sigs=0 < threshold -> verdict FAIL,
# exit 2. The happy-path control (identical assembly, eff UNTOUCHED) must verify
# PASS exit 0 — proving the tamper, not the harness, is what flips the verdict,
# and that the eff field is genuinely load-bearing in the multisig binding.
#
# This is DISTINCT from the existing verify test's covered modes:
#   * flipsig  — corrupts a signature BYTE (sig itself bad);
#   * wrong-kh — swaps the keyholder PUBKEY set;
#   * dup/oor  — index distinctness / range.
# Here sigs + pubkeys + indices are all correct; only the SIGNED MESSAGE's eff
# field is altered post-signing (governance tx-malleability / preimage binding).
#
# SAFE REFERENCE: an INDEPENDENT Ed25519 implementation (Python pynacl, RFC 8032)
# plays the keyholders and assembles the payload. No hash/sig algorithm is
# reimplemented as the wallet's oracle — the wallet (libsodium) is checked
# against a different standard Ed25519, and the sig_msg layout + eff offset are
# decoded from the AUTHORITATIVE param-change-build payload, not hand-assembled.
#
# FULLY OFFLINE (no cluster). Run from repo root:
#   bash tools/test_wallet_param_change_verify_tampered_eff_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
W="$DETERM_WALLET"
PY=python
if ! $PY -c "import nacl.signing" >/dev/null 2>&1; then
    echo "  SKIP: python pynacl not available (the independent Ed25519 reference)"; exit 0
fi

T=test_wallet_param_change_verify_tampered_eff_edge
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# ── Assembler/reference (Python). Given a sig_count=0 param-change-build payload,
#    K keyholders all sign the canonical sig_msg over the ORIGINAL eff bytes.
#    Then emit TWO assembled tx-jsons:
#      tx_ok.json     — eff UNTOUCHED (control)
#      tx_tamper.json — eff field overwritten with a DIFFERENT u64 (attack)
#    The signatures are IDENTICAL in both files; only tx_tamper's payload header
#    carries a different effective_height. We locate the eff field structurally
#    from the decoded payload, never by a hard-coded offset.
cat > "$T/assemble.py" <<'PY'
import json, struct, sys
import nacl.signing
T, base_payload_hex, k, new_eff = sys.argv[1:5]
k = int(k); new_eff = int(new_eff)
p = bytes.fromhex(base_payload_hex)
off = 0
nlen = p[off]; off += 1
name = p[off:off+nlen]; off += nlen
vlen = p[off] | (p[off+1] << 8); off += 2
value = p[off:off+vlen]; off += vlen
eff_off = off                      # structural offset of the 8-byte eff field
eff = p[off:off+8]; off += 8
# Canonical sig_msg EXACTLY as validator.cpp builds it (original eff).
sig_msg = bytes([nlen]) + name + bytes([vlen & 0xff, (vlen >> 8) & 0xff]) + value + eff
# K deterministic keyholders; ALL sign over the ORIGINAL eff.
sks = [nacl.signing.SigningKey(bytes([7*(i+1) & 0xff]) * 32) for i in range(k)]
pks = [sk.verify_key.encode().hex() for sk in sks]
json.dump(pks, open(f"{T}/kh.json", "w"))
entries = [(i, sks[i].sign(sig_msg).signature) for i in range(k)]
header = p[:off]                   # name_len..sig_count is rebuilt below; use parts
prefix = bytes([nlen]) + name + bytes([vlen & 0xff, (vlen >> 8) & 0xff]) + value + eff
def assemble(prefix_bytes):
    return (prefix_bytes + bytes([len(entries)])
            + b"".join(struct.pack("<H", i) + s for i, s in entries))
# control: original eff
payload_ok = assemble(prefix)
json.dump({"payload": payload_ok.hex(), "name": name.decode(errors="replace")},
          open(f"{T}/tx_ok.json", "w"))
# tamper: same name/value/sigs, eff field overwritten with new_eff (no re-sign)
prefix_tamper = (bytes([nlen]) + name + bytes([vlen & 0xff, (vlen >> 8) & 0xff])
                 + value + struct.pack("<Q", new_eff))
payload_tamper = assemble(prefix_tamper)
json.dump({"payload": payload_tamper.hex(), "name": name.decode(errors="replace")},
          open(f"{T}/tx_tamper.json", "w"))
# echo the two eff values so the harness can assert they actually differ
print("%d %d" % (int.from_bytes(eff, "little"), new_eff))
PY

build_payload() {  # $1=name $2=value-flag-args -> echoes the built payload hex
  "$W" param-change-build $2 --name "$1" --effective-height 100 --nonce 0 \
       --from node1 --out "$T/pcb.json" >/dev/null 2>&1
  $PY -c "import json;print(json.load(open('$T/pcb.json'))['payload'])"
}

K=3
echo "=== 1. assemble a valid 3-of-3 multisig over eff=100, then tamper eff -> 999 ==="
BP=$(build_payload MIN_STAKE "--value 1000")
EFFS=$($PY "$T/assemble.py" "$T" "$BP" "$K" 999)
OLD_EFF=$(echo "$EFFS" | cut -d' ' -f1); NEW_EFF=$(echo "$EFFS" | cut -d' ' -f2)
assert "$([ "$OLD_EFF" = "100" ] && [ "$NEW_EFF" = "999" ] && echo true || echo false)" \
       "eff actually mutated in the tampered payload (100 -> 999)"

echo; echo "=== 2. CONTROL: untouched eff, 3 valid distinct sigs, threshold=3 -> PASS exit 0 ==="
set +e; "$W" param-change-verify --tx-json "$T/tx_ok.json" --keyholders "$T/kh.json" --threshold 3 >/dev/null 2>&1; RC_OK=$?; set -e
assert "$([ $RC_OK -eq 0 ] && echo true || echo false)" "control (eff untouched) -> PASS exit 0"

echo; echo "=== 3. TAMPER: eff field mutated post-signing -> all keyholders INVALID, FAIL exit 2 ==="
set +e; OUT=$("$W" param-change-verify --tx-json "$T/tx_tamper.json" --keyholders "$T/kh.json" --threshold 3 --json 2>/dev/null); RC_T=$?; set -e
GOOD=$(echo "$OUT" | $PY -c "import json,sys;print(json.load(sys.stdin)['good_sigs'])")
NVALID=$(echo "$OUT" | $PY -c "import json,sys;print(sum(1 for s in json.load(sys.stdin)['sigs'] if s['valid']))")
VERDICT=$(echo "$OUT" | $PY -c "import json,sys;print(json.load(sys.stdin)['verdict'])")
TMET=$(echo "$OUT" | $PY -c "import json,sys;print(json.load(sys.stdin)['threshold_met'])")
EFF_SEEN=$(echo "$OUT" | $PY -c "import json,sys;print(json.load(sys.stdin)['effective_height'])")
assert "$([ $RC_T -eq 2 ] && echo true || echo false)"          "tampered eff -> FAIL exit 2"
assert "$([ "$GOOD" = "0" ] && [ "$NVALID" = "0" ] && echo true || echo false)" \
       "tampered eff -> good_sigs=0, ZERO valid sigs (preimage binding)"
assert "$([ "$VERDICT" = "FAIL" ] && [ "$TMET" = "False" ] && echo true || echo false)" \
       "tampered eff -> verdict FAIL, threshold NOT met"
assert "$([ "$EFF_SEEN" = "999" ] && echo true || echo false)" \
       "verifier decodes the MUTATED eff (999) from the payload it verified against"

echo; echo "=== 4. distinctness of layers: control + tamper share IDENTICAL sigs/pubkeys; only eff differs ==="
# Confirm the two payloads differ ONLY in the eff field region (the assertion that
# the verdict flip is attributable to eff alone, not to any sig/pubkey change).
DIFF_ONLY_EFF=$($PY -c "
import json
a=bytes.fromhex(json.load(open('$T/tx_ok.json'))['payload'])
b=bytes.fromhex(json.load(open('$T/tx_tamper.json'))['payload'])
# locate eff: name_len|name|vlen|value, eff is next 8 bytes
off=0; nlen=a[off]; off+=1; off+=nlen; vlen=a[off]|(a[off+1]<<8); off+=2; off+=vlen
diff=[i for i in range(len(a)) if a[i]!=b[i]]
print('yes' if diff and all(off<=i<off+8 for i in diff) else 'no')")
assert "$([ "$DIFF_ONLY_EFF" = "yes" ] && echo true || echo false)" \
       "control vs tamper payloads differ ONLY within the 8-byte eff field"

echo; echo "=== 5. second tamper direction (eff pulled to 0) also fails closed -> exit 2 ==="
$PY "$T/assemble.py" "$T" "$BP" "$K" 0 >/dev/null
set +e; "$W" param-change-verify --tx-json "$T/tx_tamper.json" --keyholders "$T/kh.json" --threshold 3 >/dev/null 2>&1; RC_Z=$?; set -e
assert "$([ $RC_Z -eq 2 ] && echo true || echo false)" "eff pulled to 0 -> FAIL exit 2 (direction-independent)"

echo; echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then echo "  PASS: test_wallet_param_change_verify_tampered_eff_edge"; exit 0
else echo "  FAIL: test_wallet_param_change_verify_tampered_eff_edge"; exit 1; fi
