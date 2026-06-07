#!/usr/bin/env bash
# determ-light committee-diff — property fuzz / reference cross-check.
#
# committee-diff's load-bearing output is the SIGNING-SET verdict (IDENTICAL iff
# the set of (domain, ed_pub) pairs verify_block_sigs uses is unchanged — region/
# stake deltas don't alter it) plus the added / removed / key-rotated / region-
# changed / stake-changed partition. The per-command test (test_light_committee_
# diff.sh) pins a handful of hand-built shapes; this fuzz exercises MANY random
# committee pairs (additions, removals, ed_pub rotations, region/stake changes,
# reordering, uppercase ed_pub) against an INDEPENDENT Python reference of the
# exact partition rule, asserting per scenario that committee-diff's --json
# verdict, the five member lists, and the exit code all match the reference.
#
# Fixed seed -> reproducible. FULLY OFFLINE (no cluster).
# Run from repo root: bash tools/test_light_committee_diff_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi
L="$DETERM_LIGHT"
ITERS="${FUZZ_ITERS:-40}"

T=test_light_committee_diff_fuzz
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# Generate ITERS random (A,B) committee-file pairs + a manifest of the expected
# partition + signing-set verdict, computed by an independent reference.
python - "$T" "$ITERS" <<'PY'
import json, random, sys
T, iters = sys.argv[1], int(sys.argv[2])
random.seed(0xC0FFEE)
def ed():  return ''.join(random.choice('0123456789abcdef') for _ in range(8))
def member(dom):
    return {"domain": dom, "ed_pub": ed(), "region": random.randint(0,3), "stake": random.choice([100,200,500])}
def norm(arr):  # mirror committee-diff: key by domain; lc ed_pub; region as str
    out={}
    for m in arr:
        out[m["domain"]] = (m["ed_pub"].lower(), str(m["region"]), m["stake"])
    return out
manifest=[]
for it in range(iters):
    n = random.randint(1, 7)
    A = [member("n%d" % k) for k in range(n)]
    # Build B by random mutation of A.
    B = [dict(m) for m in A]
    for m in B:
        r = random.random()
        if r < 0.18: m["ed_pub"] = ed()                 # rotate
        elif r < 0.34: m["region"] = (m["region"]+1) % 4 # region change
        elif r < 0.50: m["stake"] = m["stake"] + 50      # stake change
    B = [m for m in B if random.random() > 0.15]         # random removals
    for k in range(n, n + random.randint(0,2)):          # random additions
        B.append(member("n%d" % k))
    # uppercase some ed_pubs on the B side (case-insensitive compare)
    for m in B:
        if random.random() < 0.3: m["ed_pub"] = m["ed_pub"].upper()
    random.shuffle(A); random.shuffle(B)                 # order-independence
    # occasionally wrap one side in {members:[...]}
    a_doc = {"members": A} if random.random() < 0.3 else A
    b_doc = B
    json.dump(a_doc, open("%s/A%d.json" % (T, it), "w"))
    json.dump(b_doc, open("%s/B%d.json" % (T, it), "w"))
    # reference partition
    ma, mb = norm(A), norm(B)
    added   = sorted(d for d in mb if d not in ma)
    removed = sorted(d for d in ma if d not in mb)
    rotated, region_chg, stake_chg = [], [], []
    for d in sorted(ma):
        if d not in mb: continue
        if ma[d][0] != mb[d][0]: rotated.append(d); continue
        if ma[d][1] != mb[d][1]: region_chg.append(d)
        if ma[d][2] != mb[d][2]: stake_chg.append(d)
    signing = "IDENTICAL" if (not added and not removed and not rotated) else "DIFFERS"
    manifest.append({"it": it, "added": added, "removed": removed,
                     "key_rotated": rotated, "region_changed": region_chg,
                     "stake_changed": stake_chg, "signing_set": signing,
                     "exit": 0 if signing == "IDENTICAL" else 2})
json.dump(manifest, open("%s/manifest.json" % T, "w"))
print("generated", iters, "random committee pairs")
PY

echo "=== fuzzing $ITERS random committee pairs against the reference ==="
VERDICT_OK=true; LISTS_OK=true; EXIT_OK=true
N=$(python -c "import json;print(len(json.load(open('$T/manifest.json'))))")
i=0
while [ "$i" -lt "$N" ]; do
  exp=$(python -c "import json;print(json.dumps(json.load(open('$T/manifest.json'))[$i]))")
  set +e
  got=$("$L" committee-diff --a "$T/A$i.json" --b "$T/B$i.json" --json 2>/dev/null); rc=$?
  set -e
  # compare verdict + the five sorted lists + exit code
  python - "$exp" "$got" "$rc" <<'PY' || { echo "    iter $((i)) mismatch"; LISTS_OK=false; }
import json, sys
exp = json.loads(sys.argv[1]); got = json.loads(sys.argv[2]); rc = int(sys.argv[3])
def s(x): return sorted(x)
ok = (got.get("signing_set") == exp["signing_set"]
      and s(got.get("added",[]))         == exp["added"]
      and s(got.get("removed",[]))       == exp["removed"]
      and s(got.get("key_rotated",[]))   == exp["key_rotated"]
      and s(got.get("region_changed",[]))== exp["region_changed"]
      and s(got.get("stake_changed",[])) == exp["stake_changed"]
      and rc == exp["exit"])
sys.exit(0 if ok else 1)
PY
  [ $? -eq 0 ] || { VERDICT_OK=false; EXIT_OK=false; }
  i=$((i + 1))
done

assert "$VERDICT_OK" "signing-set verdict + partition lists match the reference for all $N pairs"
assert "$EXIT_OK"    "exit code (0 IDENTICAL / 2 DIFFERS) matches the reference for all $N pairs"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail  (over $N random committee pairs)"
if [ "$fail_count" = "0" ]; then echo "  PASS: test_light_committee_diff_fuzz"; exit 0
else echo "  FAIL: test_light_committee_diff_fuzz"; exit 1; fi
