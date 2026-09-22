#!/usr/bin/env python3
"""Bounded CLI checks invoked by ci_local's exact determ-node binary."""
import subprocess
import sys
from pathlib import Path


def main():
    binary, build_directory = sys.argv[1:]
    try:
        help_result = subprocess.run([binary, "--help"], capture_output=True,
                                     text=True, timeout=5)
        if help_result.returncode != 0:
            raise AssertionError("--help failed")
        for role in ("--aggregator", "--contributor"):
            destination = Path(build_directory) / ("forbidden-store-" + role[2:])
            result = subprocess.run([binary, role, "--data-dir", str(destination)],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode != 1:
                raise AssertionError(role + " must reject persistence with exit 1")
            if "Duel output is not a validated block" not in result.stderr:
                raise AssertionError(role + " returned an unrelated failure")
            if destination.exists():
                raise AssertionError(role + " created storage before rejection")
    except subprocess.TimeoutExpired:
        print("FAIL(timeout): determ-node CLI", file=sys.stderr)
        return 124
    except OSError as error:
        print("FAIL(launch): " + str(error), file=sys.stderr)
        return 126
    except AssertionError as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1
    print("PASS: node help and both duel persistence refusals")
    return 0


if __name__ == "__main__":
    sys.exit(main())
