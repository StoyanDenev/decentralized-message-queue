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
MUTANTS = [
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
        cases = [case for case in MUTANTS if case[1] not in ("determ-node", "test-k2-net-rpc")]
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
            shutil.copytree(root / name, baseline / name,
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
