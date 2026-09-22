#!/usr/bin/env python3
"""Isolated C99 mutation gate; invoked only by tools/ci_local.sh --c99-mutants.

Every case compiles and runs via ci_local in a temporary source snapshot. A
configuration, compilation, launch, or timeout failure is an infrastructure
failure, never evidence that a test rejects a mutant.
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


# name, target, repository-relative source, literal old text, literal new text.
# Each replacement must match exactly once in the unmutated source snapshot.
ROOT_RANK = """if(best<0 || n->records[i].candidate.tx_count>n->records[best].candidate.tx_count ||
           (n->records[i].candidate.tx_count==n->records[best].candidate.tx_count &&
            memcmp(n->records[i].header,n->records[best].header,K2_MODEL_HEADER_BYTES)<0)) best=(int)i;"""
TX_OVERRIDES_ROOT_RANK = """int tx_priority=0;
        if(best>=0 && n->records[i].candidate.tx_count && n->records[best].candidate.tx_count) {
            const triple_entry_tx_t *x=&n->records[i].candidate.txs[0], *y=&n->records[best].candidate.txs[0];
            if(x->nonce==y->nonce && !memcmp(x->from,y->from,32)) {
                uint8_t first[32],second[32]; k2_model_tx_id(x,first); k2_model_tx_id(y,second);
                tx_priority=memcmp(first,second,32);
            }
        }
        if(tx_priority<0 || (tx_priority==0 && (best<0 || n->records[i].candidate.tx_count>n->records[best].candidate.tx_count ||
           (n->records[i].candidate.tx_count==n->records[best].candidate.tx_count &&
            memcmp(n->records[i].header,n->records[best].header,K2_MODEL_HEADER_BYTES)<0)))) best=(int)i;"""
REJECT_CONFLICTING_ROOTS = """for(size_t i=0;i<n->record_count;i++) if(n->records[i].valid && !memcmp(n->records[i].candidate.parent,n->config->anchor_id,32))
        for(size_t j=0;j<i;j++) if(n->records[j].valid && !memcmp(n->records[j].candidate.parent,n->config->anchor_id,32))
            for(size_t x=0;x<n->records[i].candidate.tx_count;x++) for(size_t y=0;y<n->records[j].candidate.tx_count;y++) {
                const triple_entry_tx_t *first=&n->records[i].candidate.txs[x], *second=&n->records[j].candidate.txs[y];
                if(first->nonce==second->nonce && !memcmp(first->from,second->from,32)) {
                    uint8_t first_id[32],second_id[32]; k2_model_tx_id(first,first_id); k2_model_tx_id(second,second_id);
                    if(memcmp(first_id,second_id,32)) return K2_MODEL_INVALID;
                }
            }
    /* This model does not select between competing complete histories. */"""
MUTANTS = [
    ('http-body-capacity', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'if (value > limit / 10 || (value == limit / 10 && digit > limit % 10)) return 413;', '/* mutant: unchecked length accumulation */'),
    ('http-header-case', 'test-http-rpc', 'src/rpc/http_rpc_server.c', "if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + ('a' - 'A'));", '/* mutant: case-sensitive header comparison */'),
    ('http-header-name', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'if (len != strlen(expected)) return 0;', 'if (len < strlen(expected)) return 0; name += len - strlen(expected); len = strlen(expected);'),
    ('http-duplicate-length', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'if (seen) return 400;', '/* mutant: accept duplicate length */'),
    ('http-transfer-encoding', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'if (http_field_is(data + pos, colon - pos, "transfer-encoding")) return 400;', '/* mutant: accept transfer encoding with content length */'),
    ('http-decimal-length', 'test-http-rpc', 'src/rpc/http_rpc_server.c', "if (data[i] < '0' || data[i] > '9') return 400;", '/* mutant: accept nondecimal digits */'),
    ('http-reserved-byte', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'const size_t limit = (HTTP_RPC_BUF_SIZE - 1) - header_len;', 'const size_t limit = HTTP_RPC_BUF_SIZE - header_len;'),
    ('http-incomplete-body', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'if (c->rx_len < header_len + content_len) {', 'if (0) {'),
    ('pending-signature', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'if (determ_ed25519_verify(sender, signing, sizeof(signing), tx.sig) != 0)', 'if (0)'),
    ('pending-small-order', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'if (determ_ed25519_point_has_small_order(sender) != 0)', 'if (0)'),
    ('pending-genesis', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'if (memcmp(tx.genesis_hash, pool->genesis_hash, 32) != 0)', 'if (0)'),
    ('pending-source-route', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'tx.shard_id >= pool->routing.shard_count || tx.shard_id != source_shard', 'tx.shard_id >= pool->routing.shard_count'),
    ('pending-destination-route', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'destination_shard != source_shard', '0'),
    ('pending-data-hash', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'if (memcmp(hash, tx.hash, sizeof(hash)) != 0) return PENDING_TRANSFER_ERR_HASH;', '/* mutant: trust advertised hash */'),
    ('pending-canonical-frame', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'written != len || memcmp(canonical, frame, len) != 0', 'written != len'),
    ('pending-core-prefix', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'if (memcmp(tx.sender_pubkey, tx.from, 32) != 0 || memcmp(tx.recipient_pubkey, tx.to, 32) != 0)', 'if (0)'),
    ('pending-conflict-preference', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'int order = memcmp(candidate.hash, incumbent->hash, sizeof(candidate.hash));', 'int order = -memcmp(candidate.hash, incumbent->hash, sizeof(candidate.hash));'),
    ('pending-bucket-isolation', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'else if (at->shard_id == shard_id) { bucket = at; break; }', 'else { bucket = at; break; }'),
    ('pending-owned-frame', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'memcpy(entry->frame, frame, len);', 'memcpy(entry->frame, frame, len - 64);'),
    ('pending-rpc-output-preflight', 'test-rpc-pending-transfer', 'src/rpc/json_rpc.c', 'if (cap < RPC_PENDING_SUBMIT_RESPONSE_LEN) return -1;', '/* mutant: mutate before discovering short response buffer */'),
    ('pending-rpc-request-bound', 'test-rpc-pending-transfer', 'src/rpc/json_rpc.c', 'len > RPC_PENDING_MAX_REQUEST_LEN', 'len > RPC_PENDING_MAX_REQUEST_LEN + 1'),
    ('pending-node-context', 'determ-node', 'src/determ_node.c', 'rcfg.rpc_ctx.pending = have_pending_genesis ? &g_pending : NULL;', 'rcfg.rpc_ctx.pending = NULL;'),
    ("ed25519-sign-small-heap", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "buf = msglen <= sizeof sign_buf - 64u ? sign_buf : (u8 *)malloc(64 + msglen);",
     "buf = (u8 *)malloc(64 + msglen);"),
    ("ed25519-verify-small-heap", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "buf = msglen <= sizeof verify_buf - 64u ? verify_buf : (u8 *)malloc(64 + msglen);",
     "buf = (u8 *)malloc(64 + msglen);"),
    ("ed25519-sign-boundary", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "msglen <= sizeof sign_buf - 64u", "msglen < sizeof sign_buf - 64u"),
    ("ed25519-verify-boundary", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "msglen <= sizeof verify_buf - 64u", "msglen < sizeof verify_buf - 64u"),
    ("ed25519-sign-stack-free", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "if (buf != sign_buf) free(buf);", "free(buf);"),
    ("ed25519-verify-stack-free", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "if (buf != verify_buf) free(buf);", "free(buf);"),
    ("ed25519-sign-length-overflow", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "if (msglen > SIZE_MAX - 64u) return -1;\n\n    determ_sha512(seed, 32, h);",
     "/* mutant: unchecked signing length */\n\n    determ_sha512(seed, 32, h);"),
    ("ed25519-verify-length-overflow", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "if (msglen > SIZE_MAX - 64u) return -1;\n    if (!point_y_is_canonical(pk))",
     "/* mutant: unchecked verification length */\n    if (!point_y_is_canonical(pk))"),
    ("ed25519-sign-buffer-wipe", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "determ_secure_zero(buf, 64 + msglen);", "/* mutant: leave signing buffer uncleansed */"),
    ("recovery-reject-conflicting-roots", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "/* This model does not select between competing complete histories. */", REJECT_CONFLICTING_ROOTS),
    ("recovery-tx-hash-overrides-block", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     ROOT_RANK, TX_OVERRIDES_ROOT_RANK),
    ("recovery-sibling-selected-state", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "*state=n->config->anchor_state;", "*state=n->state;"),
    ("recovery-requeue-anchor-state", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "bool conflict=false; *scratch=n->state;", "bool conflict=false; *scratch=n->config->anchor_state;"),
    ("recovery-message-count", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "n->records[i].candidate.tx_count>n->records[best].candidate.tx_count",
     "n->records[i].candidate.tx_count<n->records[best].candidate.tx_count"),
    ("recovery-header-not-hash", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "memcmp(n->records[i].header,n->records[best].header,K2_MODEL_HEADER_BYTES)<0",
     "memcmp(n->records[i].id,n->records[best].id,32)<0"),
    ("recovery-original-parent", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "for(size_t i=0;i<n->record_count;i++) if(n->records[i].valid && !memcmp(n->records[i].candidate.parent,n->records[best].id,32)) child=(int)i;",
     "for(size_t i=0;i<n->record_count;i++) if(n->records[i].valid && n->records[i].candidate.height==n->records[best].candidate.height+1) child=(int)i;"),
    ("recovery-shared-receipt", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "if(!shared) return false;", "(void)shared;"),
    ("recovery-pair-authority", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "if(!authorized) return false;", "(void)authorized;"),
    ("recovery-requeue-validity", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "if(ledger_apply_tx(scratch,txs[i],0)!=LEDGER_OK)", "if(false)"),
    ("recovery-message-hash-order", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "while(pos && memcmp(ids[pos-1],id,32)>0)", "while(pos && memcmp(ids[pos-1],id,32)<0)"),
    ("recovery-restore-revision", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "w->restoring.generation=next_generation;", "(void)next_generation;"),
    ("recovery-journal-body-binding", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "if(memcmp(header,p,sizeof(header))) return K2_MODEL_INVALID;", "(void)header;"),
    ("recovery-impossible-root", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "if(c->height==n->config->anchor_height+1) return K2_MODEL_INVALID;", "/* mutant: wait for impossible parent */"),
    ("routing-zero-count", "test-shard-routing", "src/ledger/shard_routing.c",
     "if (!out || !salt || shard_count == 0)", "if (!out || !salt)"),
    ("routing-domain", "test-shard-routing", "src/ledger/shard_routing.c",
     'static const char tag[] = "shard-route";', 'static const char tag[] = "shard-routex";'),
    ("routing-salt", "test-shard-routing", "src/ledger/shard_routing.c",
     "determ_sha256_update(&hash, config->salt, sizeof(config->salt));", "/* mutant: omit salt */"),
    ("routing-key-length", "test-shard-routing", "src/ledger/shard_routing.c",
     "pubkey_len != 32", "pubkey_len == 99"),
    ("routing-hash-width", "test-shard-routing", "src/ledger/shard_routing.c",
     "i < 8;", "i < 4;"),
    ("routing-rpc-duplicate-field", "test-rpc-shard-routing", "src/rpc/json_rpc.c",
     "if (seen & bit) return -32600;", "if (0) return -32600;"),
    ("routing-rpc-method-key", "test-rpc-shard-routing", "src/rpc/json_rpc.c",
     "const determ_json_tok_t *method_tok = rpc_method_token(request_json, tokens, (size_t)num_tokens);",
     'const determ_json_tok_t *method_tok = determ_json_find_key(request_json, tokens, (size_t)num_tokens, &tokens[0], "method");'),
    ("routing-rpc-request-bound", "test-rpc-shard-routing", "src/rpc/json_rpc.c",
     "len > RPC_ROUTING_MAX_REQUEST_LEN", "len > RPC_ROUTING_MAX_REQUEST_LEN + 1"),
    ("routing-rpc-error-id", "test-rpc-shard-routing", "src/rpc/json_rpc.c",
     '\n            error == -32602 ? id : "null"', '\n            "null"'),
    ("routing-node-context", "determ-node", "src/determ_node.c",
     "rcfg.rpc_ctx.routing = &routing;", "rcfg.rpc_ctx.routing = NULL;"),
    ("ledger-fee-wrap", "test-triple-entry-ledger", "src/ledger/state.c",
     "if (UINT64_MAX - state->total_fees < tx_fee)", "if (0)"),
    ("ledger-fee-exact-fit", "test-triple-entry-ledger", "src/ledger/state.c",
     "if (UINT64_MAX - state->total_fees < tx_fee)",
     "if (UINT64_MAX - state->total_fees <= tx_fee)"),
    ("ledger-nonce-wrap", "test-triple-entry-ledger", "src/ledger/state.c",
     "sender_nonce == UINT64_MAX || tx_nonce != sender_nonce + 1",
     "tx_nonce != sender_nonce + 1"),
    ("ledger-self-alias", "test-triple-entry-ledger", "src/ledger/state.c",
     "if (sender == receiver)", "if (0)"),
    ("ledger-self-fee", "test-triple-entry-ledger", "src/ledger/state.c",
     "sender_balance -= tx_fee;", "sender_balance -= tx_amount + tx_fee;"),
    ("ledger-self-nonce", "test-triple-entry-ledger", "src/ledger/state.c",
     "memcpy(&sender->nonce, &tx_nonce, sizeof(uint64_t));",
     "/* mutant: leave the self-transfer nonce unchanged */"),
    ("qpc-remainder-overflow", "test-qpc-clock-overflow", "include/determ/time/clock.h",
     "return ns + quotient;", "return ns + (fraction_ticks * scale) / freq;"),
    ("qpc-whole-saturation", "test-qpc-clock-overflow", "include/determ/time/clock.h",
     "if (whole > UINT64_MAX / scale)", "if (false)"),
    ("qpc-fraction-saturation", "test-qpc-clock-overflow", "include/determ/time/clock.h",
     "if (quotient > UINT64_MAX - ns)", "if (false)"),
    ("dda-interval-count", "test-dda", "src/consensus/dda.c",
     "uint64_t average = delta / (tracker->count - 1);",
     "uint64_t average = delta / tracker->count;"),
    ("dda-average-wrap", "test-dda", "src/consensus/dda.c",
     "return average > UINT32_MAX ? UINT32_MAX : (uint32_t)average;",
     "return (uint32_t)average;"),
    ("dda-timestamp-order", "test-dda", "src/consensus/dda.c",
     "if (timestamp_ms <= tracker->block_timestamps[newest_idx])", "if (false)"),
    ("dda-predecessor-work", "test-dda", "src/consensus/dda.c",
     "if (!tracker || !dda_verify_block_iterations(tracker, iterations))", "if (!tracker)"),
    ("dda-work-progress", "test-dda", "src/consensus/dda.c",
     "tracker->current_iterations = iterations;", "/* mutant: stale work state */"),
    ("duel-both-commits", "test-k2-duel-fallback", "src/consensus/duel_state.c",
     "if (!sm->aggregator_commit.present || !sm->contributor_commit.present)", "if (false)"),
    ("duel-reveal-binding", "test-k2-duel-fallback", "src/consensus/duel_state.c",
     "if (!commit->present || !is_valid || memcmp(digest, commit->hash, 32) != 0)",
     "if (!commit->present || !is_valid)"),
    ("duel-commit-deadline", "test-k2-duel-fallback", "src/consensus/duel_state.c",
     "if (attempt_elapsed(sm) >= DUEL_COMMIT_TIMEOUT_NS)\n        return abort_attempt(sm, ERR_EPOCH_SKIPPED_SILENCE);",
     "if (attempt_elapsed(sm) > DUEL_COMMIT_TIMEOUT_NS)\n        return abort_attempt(sm, ERR_EPOCH_SKIPPED_SILENCE);"),
    ("duel-incomplete-timeout", "test-k2-duel-fallback", "src/consensus/duel_state.c",
     "if (attempt_elapsed(sm) < DUEL_REVEAL_WINDOW_NS) return DUEL_SUCCESS;\n        return abort_attempt(sm, ERR_EPOCH_SKIPPED_INCOMPLETE);",
     "if (attempt_elapsed(sm) < DUEL_REVEAL_WINDOW_NS) return DUEL_SUCCESS;\n        return DUEL_SUCCESS;"),
    ("duel-explicit-retry", "test-k2-duel-fallback", "src/consensus/duel_state.c",
     " && sm->state != DUEL_STATE_ABORTED)", ")"),
    ("node-refusal-status", "determ-node", "src/determ_node.c",
     'fprintf(stderr, "Duel output is not a validated block; --data-dir cannot be used with duel modes\\n");\n        return 1;',
     'fprintf(stderr, "Duel output is not a validated block; --data-dir cannot be used with duel modes\\n");\n        return 0;'),
    ("net-timeout-propagation", "test-k2-net-rpc", "src/net/k2_net.c",
     "return status == DUEL_SUCCESS ? 0 : fail_attempt(agg, status);", "return 0;"),
    ("net-premature-deadline-wakeup", "test-k2-net-rpc", "src/net/k2_net.c",
     "return requested < 0 || requested > remaining ? remaining : requested;",
     "return requested < 0 || requested > remaining ? 0 : requested;"),
    ("net-reveal-binding", "test-k2-net-rpc", "src/consensus/duel_state.c",
     "if (!commit->present || !is_valid || memcmp(digest, commit->hash, 32) != 0)",
     "if (!commit->present || !is_valid)"),
    ("net-eof-before-buffered-result", "test-k2-net-rpc", "src/net/k2_net.c",
     "/* READ|EOF can carry the final complete frame followed by FIN. */",
     "if (flags & NET_EV_EOF) return fail_contributor(cont);\n        /* mutant: discard unread final frame on EOF */"),
]


def run_gate(source, build, targets, jobs):
    command = ["bash", str(source / "tools/ci_local.sh"), "--c99",
               "--build-dir", str(build), "--jobs", str(jobs)]
    for target in targets:
        command.extend(["--c99-test", target])
    process = subprocess.Popen(command, cwd=source, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=(os.name == "posix"))
    try:
        output, _ = process.communicate(timeout=300)
    except subprocess.TimeoutExpired as error:
        # On POSIX, kill the wrapper and its compiler/test descendants together.
        # An infrastructure timeout must not leave a listener or mutant running.
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.communicate()
        raise RuntimeError("gate timed out; not a killed mutant") from error
    return process.returncode, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if not MUTANTS:
        raise RuntimeError("no mutation cases configured")
    cases = MUTANTS
    if sys.platform in ("win32", "cygwin", "msys"):
        cases = [case for case in MUTANTS if case[1] not in
                 ("determ-node", "test-k2-net-rpc", "test-rpc-shard-routing",
                  "test-triple-entry-ledger", "test-rpc-pending-transfer", "test-http-rpc")]
        for case in MUTANTS:
            if case not in cases:
                print("PLATFORM-SKIP(mutant): " + case[0] + " (POSIX prototype)", flush=True)
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="determ-c99-mutants-") as temporary:
        work = Path(temporary)
        baseline = work / "baseline"
        baseline.mkdir()
        # Copy current source, including uncommitted fixes. No checkout writes,
        # stale binaries, dependencies, or .git metadata enter this snapshot.
        for name in ("include", "src", "tests", "tools", "third_party",
                     "wallet", "light", "sim", "dapps"):
            src_dir = root / name
            if src_dir.is_dir():
                shutil.copytree(src_dir, baseline / name,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy2(root / "CMakeLists.txt", baseline / "CMakeLists.txt")
        targets = list(dict.fromkeys(case[1] for case in cases))
        print("=== ci_local --c99-mutants: fresh baseline ===", flush=True)
        code, output = run_gate(baseline, work / "baseline-build", targets, args.jobs)
        if code != 0 or "BUILD_OK(c99):" not in output:
            print(output, flush=True)
            raise RuntimeError("baseline must build and pass before mutation")
        for target in targets:
            if "PASS(test): " + target + "\n" not in output:
                raise RuntimeError("baseline did not execute " + target)
        print("PASS: baseline compiled and all selected gates executed", flush=True)
        for number, (name, target, relative, old, new) in enumerate(cases, 1):
            source = work / ("mutant-%02d" % number)
            shutil.copytree(baseline, source)
            path = source / relative
            original = path.read_text()
            if original.count(old) != 1:
                raise RuntimeError("mutation anchor must match once: " + name)
            path.write_text(original.replace(old, new, 1))
            code, output = run_gate(source, work / ("build-%02d" % number),
                                    [target], args.jobs)
            if "BUILD_OK(c99): " + target + "\n" not in output:
                print(output, flush=True)
                raise RuntimeError("mutant failed to build: " + name)
            if code == 0 or "FAIL(test): " + target + " (exit " not in output:
                print(output, flush=True)
                raise RuntimeError("mutant survived or failed outside its gate: " + name)
            print("RED(mutant): %s [%s; fresh build succeeded]" % (name, target), flush=True)
            shutil.rmtree(source)
            shutil.rmtree(work / ("build-%02d" % number))
        print("PASS: %d/%d mutants rejected after successful builds" %
              (len(cases), len(cases)), flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print("FAIL(c99-mutants): " + str(error), file=sys.stderr)
        sys.exit(1)
