#!/usr/bin/env bash
# test_wallet_accounting_credit_gate_source.sh — STATIC source guard for the
# wallet receiver-credit gate (register WA-2 / WalletAccountingCreditGate).
#
# The wallet's tx tally credits a receiver's running balance in exactly one place
# (wallet/main.cpp):
#     if (to_hit && t == 0) {
#         tit->second.credits += amt;
#         tit->second.txs_recv++;
#     }
# The gate condition `to_hit && t == 0` is a CORRECTNESS invariant: only a
# same-shard TRANSFER (tx type 0) whose recipient is the tracked account may add
# to `credits`. DAPP_CALL (10) moves that the wallet cannot confirm, and
# cross-shard receiver credits, must NOT be tallied — they fold into
# non_tx_delta instead (see the block comment above the gate). A wallet that
# credits the wrong tx types reports a balance that silently disagrees with the
# chain's authoritative per-domain balance.
#
# THE GAP this closes: the tally is wallet-internal arithmetic with no on-chain
# cross-check, and no unit test drives a DAPP_CALL / cross-shard receiver through
# it and asserts the credit is withheld. A widened gate —
#     if (to_hit && (t == 0 || t == 10)) {   // now also credits DAPP_CALL
# — passes every existing wallet test (all of which use plain TRANSFERs) while
# double-counting DApp-call amounts that already folded into non_tx_delta,
# breaking the "provably-exact tally" property the comment claims. This is the
# accounting-invariant class: a single governing predicate with no gate pinning
# its exact shape.
#
# This guard pins, at the PRODUCTION source, that:
#   (a) `credits +=` appears in exactly ONE place (non-vacuity — a second credit
#       site, or a rename of the one that exists, flips the count), and
#   (b) the governing `if (...)` condition is EXACTLY `to_hit && t == 0`
#       (whitespace-normalised) — no widening, no extra tx types.
#
# Pure read-only awk over one .cpp file. No build, no node, never SKIPs.
# `SELFTEST=1 bash tools/test_wallet_accounting_credit_gate_source.sh` drives a
# coherent and a widened-gate snippet through the SAME extractor to prove it is
# live. Exit 0 = the credit gate is exact; exit 1 = drift.
set -u
cd "$(dirname "$0")/.."

WALLET_FILE=wallet/main.cpp
EXPECT_CREDIT_SITES=1
EXPECT_COND="to_hit&&t==0"

# extract_gate <file>
# Prints "<sites>|<normalized-condition-of-the-last-credit-site>". Tracks the
# most recent `if (...) {` line; on a `credits +=` site, emits that condition.
extract_gate() {
  awk '
    {
      line = $0; sub(/\/\/.*/, "", line)
      if (line ~ /^[ \t]*if[ \t]*\(/) last_if = line
      if (line ~ /credits[ \t]*\+=/) {
        sites++
        cond = last_if
        sub(/^[ \t]*if[ \t]*\(/, "", cond)      # drop leading `if (`
        sub(/\)[ \t]*\{[ \t\r]*$/, "", cond)    # drop trailing `) {`
        gsub(/[ \t\r]+/, "", cond)              # strip all whitespace
        last_cond = cond
      }
    }
    END { printf "%d|%s\n", sites, last_cond }
  ' "$1"
}

# ── SELFTEST: the extractor + the drift rule are live ────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: wallet credit-gate source extractor ==="
  ST_FAIL=0
  GOOD=$(extract_gate /dev/stdin <<'EOF'
                if (to_hit && t == 0) {
                    tit->second.credits += amt;
                    tit->second.txs_recv++;
                }
EOF
)
  BAD=$(extract_gate /dev/stdin <<'EOF'
                if (to_hit && (t == 0 || t == 10)) {
                    tit->second.credits += amt;
                    tit->second.txs_recv++;
                }
EOF
)
  if [ "$GOOD" = "1|$EXPECT_COND" ]; then
    echo "  ok:  a coherent gate extracts as sites=1 cond=[$EXPECT_COND] [$GOOD]"
  else
    echo "  bad: coherent copy mis-extracted [$GOOD] (extractor wrong)" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  case "$BAD" in
    1\|$EXPECT_COND) echo "  bad: widened-gate mutant NOT flagged [$BAD]" >&2; ST_FAIL=$((ST_FAIL + 1)) ;;
    1\|*)            echo "  ok:  a widened DAPP_CALL-crediting gate is flagged (cond drift) [$BAD]" ;;
    *)               echo "  bad: unexpected extraction [$BAD]" >&2; ST_FAIL=$((ST_FAIL + 1)) ;;
  esac
  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_wallet_accounting_credit_gate_source SELFTEST (extractor flags a widened credit gate)"
    exit 0
  else
    echo "  FAIL: test_wallet_accounting_credit_gate_source SELFTEST ($ST_FAIL self-test failure(s))"
    exit 1
  fi
fi

# ── MAIN: pin the live production credit gate ─────────────────────────────────────
VIOL=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOL=$((VIOL + 1)); }

GATE=$(extract_gate "$WALLET_FILE")
SITES=${GATE%%|*}
COND=${GATE#*|}

if [ "$SITES" -eq "$EXPECT_CREDIT_SITES" ]; then
  ok "wallet credits a receiver in exactly $EXPECT_CREDIT_SITES place (non-vacuity anchor holds)"
else
  bad "wallet has $SITES 'credits +=' sites, expected $EXPECT_CREDIT_SITES (anchor drift / extra credit path)"
fi

if [ "$COND" = "$EXPECT_COND" ]; then
  ok "the credit gate is exactly '$EXPECT_COND' (only same-shard TRANSFER credits the receiver)"
else
  bad "the credit gate is '$COND', expected '$EXPECT_COND' — it may credit tx types the wallet cannot confirm (over-count)"
fi

echo ""
if [ "$VIOL" -eq 0 ]; then
  echo "  PASS: test_wallet_accounting_credit_gate_source (the wallet receiver-credit gate is exact — only same-shard TRANSFER is tallied)"
  exit 0
else
  echo "  FAIL: test_wallet_accounting_credit_gate_source ($VIOL violation(s) — the wallet credit gate has drifted)"
  exit 1
fi
