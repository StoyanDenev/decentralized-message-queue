#!/usr/bin/env bash
# reap_daemons.sh — force-kill any stray determ-family daemons by IMAGE NAME.
#
# Why this exists: cluster test wrappers boot determ.exe nodes and rely on a
# per-PID `kill $pid` EXIT trap to reap them. On Windows/Git-Bash that is
# unreliable — the captured PID is sometimes the Git-Bash wrapper rather than
# the real determ.exe, and the trap does not fire at all if the test times out
# or is interrupted. Leaked consensus daemons then accumulate across runs,
# saturate the CPU, and can lock build-output binaries.
#
# Reaping by image name catches EVERY instance regardless of how it was spawned
# or re-parented, sidestepping the fragile PID traps entirely. This is a
# belt-and-suspenders cleanup: safe to call anytime, always a no-op if nothing
# is running, always exits 0 so it can be chained before/after any step.
#
# Usage:
#   bash tools/reap_daemons.sh        # reap now
# Recommended call sites: start + end of run_all.sh, each cluster wrapper's
# cleanup(), and between parallel-agent rounds.
set +e

case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*)
    # Windows: kill by image name. MSYS_NO_PATHCONV stops Git-Bash from
    # mangling the /F /IM flags into filesystem paths.
    for img in determ.exe determ-light.exe determ-wallet.exe; do
      MSYS_NO_PATHCONV=1 taskkill /F /IM "$img" >/dev/null 2>&1
    done
    ;;
  *)
    # Linux / macOS: exact-name match so we never hit unrelated processes.
    for name in determ determ-light determ-wallet; do
      pkill -x "$name" >/dev/null 2>&1
    done
    ;;
esac

exit 0
