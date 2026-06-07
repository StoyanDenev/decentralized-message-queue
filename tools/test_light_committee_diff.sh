#!/usr/bin/env bash
# determ-light committee-diff — offline diff of two committee files.
#
# committee-diff compares two `determ validators --json`-shaped committee
# snapshots (a bare array, or {members:[...]}, of {domain, ed_pub, region,
# stake}) and reports added / removed / key-rotated / region-changed /
# stake-changed / unchanged members. It is the companion to verify-chain-file
# --committee-manifest: the SIGNING-SET verdict (keyed on the (domain, ed_pub)
# pairs verify_block_sigs uses) tells an operator whether ONE --committee covers
# a headers segment spanning the two snapshots, or whether a rotation means they
# must build a manifest. Exit 0 = signing set IDENTICAL, 2 = DIFFERS, 1 = args.
#
# FULLY OFFLINE (no cluster). Run from repo root: bash tools/test_light_committee_diff.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi
L="$DETERM_LIGHT"

T=test_light_committee_diff
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# Baseline committee snapshot (bare array — the validators --json shape).
cat > "$T/A.json" <<'EOF'
[{"domain":"n1","ed_pub":"aa11","region":0,"stake":100},
 {"domain":"n2","ed_pub":"bb22","region":0,"stake":100},
 {"domain":"n3","ed_pub":"cc33","region":1,"stake":200}]
EOF

echo "=== 1. --help exit 0; missing arg exit 1 ==="
"$L" committee-diff --help >/dev/null 2>&1; assert "$([ $? -eq 0 ] && echo true || echo false)" "--help exit 0"
"$L" committee-diff --a "$T/A.json" >/dev/null 2>&1; assert "$([ $? -eq 1 ] && echo true || echo false)" "missing --b exit 1"
"$L" committee-diff --bogus >/dev/null 2>&1; assert "$([ $? -eq 1 ] && echo true || echo false)" "unknown arg exit 1"

echo; echo "=== 2. identical (same file) -> SIGNING IDENTICAL exit 0 ==="
set +e; OUT=$("$L" committee-diff --a "$T/A.json" --b "$T/A.json" 2>&1); RC=$?; set -e
echo "$OUT" | grep -Eq "SIGNING SET: IDENTICAL" && [ $RC -eq 0 ] && assert true "identical -> IDENTICAL exit 0" || assert false "identical -> IDENTICAL exit 0"

echo; echo "=== 3. reordered (same members, different order) -> IDENTICAL exit 0 ==="
cat > "$T/A_reord.json" <<'EOF'
[{"domain":"n3","ed_pub":"cc33","region":1,"stake":200},
 {"domain":"n1","ed_pub":"aa11","region":0,"stake":100},
 {"domain":"n2","ed_pub":"bb22","region":0,"stake":100}]
EOF
set +e; "$L" committee-diff --a "$T/A.json" --b "$T/A_reord.json" >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 0 ] && echo true || echo false)" "reordered -> IDENTICAL exit 0 (order-independent)"

echo; echo "=== 4. {members:[...]} envelope accepted, case-insensitive ed_pub -> IDENTICAL ==="
cat > "$T/A_env.json" <<'EOF'
{"members":[{"domain":"n1","ed_pub":"AA11","region":0,"stake":100},
            {"domain":"n2","ed_pub":"BB22","region":0,"stake":100},
            {"domain":"n3","ed_pub":"CC33","region":1,"stake":200}]}
EOF
set +e; "$L" committee-diff --a "$T/A.json" --b "$T/A_env.json" >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 0 ] && echo true || echo false)" "{members} envelope + uppercase ed_pub -> IDENTICAL exit 0"

echo; echo "=== 5. added + removed + key-rotated -> SIGNING DIFFERS exit 2 ==="
cat > "$T/B.json" <<'EOF'
[{"domain":"n1","ed_pub":"ffff","region":0,"stake":100},
 {"domain":"n3","ed_pub":"cc33","region":1,"stake":200},
 {"domain":"n4","ed_pub":"dddd","region":2,"stake":150}]
EOF
set +e; J=$("$L" committee-diff --a "$T/A.json" --b "$T/B.json" --json 2>/dev/null); RC=$?; set -e
OK=$(echo "$J" | python -c "
import json,sys
d=json.load(sys.stdin)
print('true' if d['signing_set']=='DIFFERS' and d['added']==['n4'] and d['removed']==['n2'] and d['key_rotated']==['n1'] else 'false')")
assert "$OK" "added=n4 removed=n2 rotated=n1, DIFFERS"
assert "$([ $RC -eq 2 ] && echo true || echo false)" "SIGNING DIFFERS -> exit 2"

echo; echo "=== 6. region + stake change only (ed_pub same) -> SIGNING IDENTICAL exit 0 ==="
cat > "$T/A_rs.json" <<'EOF'
[{"domain":"n1","ed_pub":"aa11","region":5,"stake":777},
 {"domain":"n2","ed_pub":"bb22","region":0,"stake":100},
 {"domain":"n3","ed_pub":"cc33","region":1,"stake":200}]
EOF
set +e; J=$("$L" committee-diff --a "$T/A.json" --b "$T/A_rs.json" --json 2>/dev/null); RC=$?; set -e
OK=$(echo "$J" | python -c "
import json,sys
d=json.load(sys.stdin)
print('true' if d['signing_set']=='IDENTICAL' and d['region_changed']==['n1'] and d['stake_changed']==['n1'] and not d['key_rotated'] else 'false')")
assert "$OK" "n1 in BOTH region_changed AND stake_changed; signing IDENTICAL"
assert "$([ $RC -eq 0 ] && echo true || echo false)" "secondary-only change -> exit 0"

echo; echo "=== 7. malformed committee (member missing domain) -> exit 1 ==="
echo '[{"ed_pub":"aa"}]' > "$T/bad.json"
set +e; "$L" committee-diff --a "$T/A.json" --b "$T/bad.json" >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 1 ] && echo true || echo false)" "member missing domain -> exit 1"

echo; echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then echo "  PASS: test_light_committee_diff"; exit 0
else echo "  FAIL: test_light_committee_diff"; exit 1; fi
