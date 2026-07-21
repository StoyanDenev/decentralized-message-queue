#!/usr/bin/env bash
# test_param_change_whitelist_coherence.sh — register claim PCL-1
# (ParamChangeLintSoundness): governance-whitelist source coherence.
#
# The PARAM_CHANGE governance whitelist and the numeric-scalar set are
# duplicated as INDEPENDENT source literals across two binaries that share NO
# runtime object — the wallet links no chain library (TCB separation), so the
# wallet's `kWhitelist` / `kNumericScalars` are hand-maintained mirrors of the
# authoritative validator whitelist (src/node/validator.cpp) and the chain's
# scalar-apply dispatch (src/chain/chain.cpp). Because the literals live in
# different binaries, drift is invisible to every RUNTIME test: adding a name to
# one copy without the others (the register PCL-1 mutation) makes the wallet
# lint silently reject a now-valid governance param, or accept one the chain
# cannot apply. The only observable is SOURCE parity, which this guard pins:
#
#   (1) all `kWhitelist` literals (validator x1 + wallet x2) are set-identical;
#   (2) the wallet `kNumericScalars` set == the chain's parse_u64 dispatch set;
#   (3) every numeric scalar is itself on the whitelist.
#
# Pure awk/grep over source — no node, no build. Runs in the ci_local offline
# doc-guard set (gated on both platforms via .github/workflows/ci.yml) and is
# auto-discovered by a full (non-FAST) tools/run_all.sh; intentionally NOT in the
# FAST=1 regex, like the other offline guards. Emits ok:/drift: per check + a
# single terminal PASS:/FAIL: marker (run_all.sh convention).
set -u
cd "$(dirname "$0")/.."

VAL=src/node/validator.cpp
WAL=wallet/main.cpp
CHN=src/chain/chain.cpp
fail=0
note() { echo "  $1"; }

# Sorted, comma-joined quoted names of the OCC-th `<setname> = { ... };` block
# in a file.  args: <file> <setname> <occurrence>
extract_set() {
  awk -v want="$2" -v occ="$3" '
    $0 ~ ("static const std::set<std::string> " want " *= *\\{") {
      blk++; if (blk == occ) { grab = 1; next }
    }
    grab && /\};/ { grab = 0 }
    grab {
      s = $0
      while (match(s, /"[^"]*"/)) {
        print substr(s, RSTART + 1, RLENGTH - 2)
        s = substr(s, RSTART + RLENGTH)
      }
    }
  ' "$1" | sort | tr '\n' ','
}

# Chain scalar-apply dispatch: names on `name == "X" ... parse_u64` lines.
extract_chain_scalars() {
  grep -E 'name == "[A-Z_]+".*parse_u64' "$CHN" \
    | grep -oE '"[A-Z_]+"' | tr -d '"' | sort | tr '\n' ','
}

blk_count() { grep -cE "static const std::set<std::string> kWhitelist *= *\{" "$1"; }
WL_BLOCKS=$(( $(blk_count "$VAL") + $(blk_count "$WAL") ))
EXPECT_WL_BLOCKS=3
if [ "$WL_BLOCKS" = "$EXPECT_WL_BLOCKS" ]; then
  note "ok: found $WL_BLOCKS kWhitelist source blocks (validator x1 + wallet x2)"
else
  note "drift: expected $EXPECT_WL_BLOCKS kWhitelist blocks, found $WL_BLOCKS"
  note "       (a renamed/deleted copy makes the parity check vacuous)"
  fail=1
fi

WL_VAL=$(extract_set "$VAL" kWhitelist 1)
WL_W1=$(extract_set "$WAL" kWhitelist 1)
WL_W2=$(extract_set "$WAL" kWhitelist 2)
if [ -n "$WL_VAL" ] && [ "$WL_W1" = "$WL_VAL" ] && [ "$WL_W2" = "$WL_VAL" ]; then
  note "ok: all 3 kWhitelist sets identical [$WL_VAL]"
else
  note "drift: kWhitelist sets differ —"
  note "         validator: [$WL_VAL]"
  note "         wallet#1 : [$WL_W1]"
  note "         wallet#2 : [$WL_W2]"
  fail=1
fi

NS_WAL=$(extract_set "$WAL" kNumericScalars 1)
NS_CHN=$(extract_chain_scalars)
if [ -n "$NS_WAL" ] && [ "$NS_WAL" = "$NS_CHN" ]; then
  note "ok: wallet kNumericScalars == chain parse_u64 dispatch [$NS_WAL]"
else
  note "drift: numeric-scalar set — wallet [$NS_WAL] != chain [$NS_CHN]"
  fail=1
fi

miss=""
IFS=',' read -ra scal <<< "$NS_WAL"
for s in "${scal[@]}"; do
  [ -z "$s" ] && continue
  case ",$WL_VAL" in *",$s,"*) : ;; *) miss="$miss $s" ;; esac
done
if [ -z "$miss" ]; then
  note "ok: every numeric scalar is on the whitelist"
else
  note "drift: numeric scalar(s) not on the whitelist:$miss"
  fail=1
fi

echo
if [ "$fail" = 0 ]; then
  echo "  PASS: test_param_change_whitelist_coherence"
else
  echo "  FAIL: test_param_change_whitelist_coherence"
fi
exit $fail
