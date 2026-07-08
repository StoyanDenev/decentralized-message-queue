# Kqueue Reactor Design — the macOS/BSD backend for the net:: seam

**Status: DESIGN-REVIEW-ONLY (owner rule, 2026-07-07).** No implementation may
ship until a macOS/BSD gate (CI runner or hardware) exists —
[MinixTacticalProfile.md](MinixTacticalProfile.md) §4.5/§9. `.github/workflows/ci.yml`
runs only `ubuntu-latest`/`windows-latest`; §6 lists the OS-version-dependent
behaviors that make an ungated implementation unauditable. This is the design
review that doc's §7 step 3 requires. Reference convention: compound section
numbers (§4.3, §4.5, §4.5b/d, §9) and "§7 step N" are MinixTacticalProfile.md
sections; bare §0-§7 are this doc's own.

## 0. Scope — what actually changes

The shipped epoll reactor ([src/net/reactor_event_loop.cpp](../../src/net/reactor_event_loop.cpp),
[src/net/reactor_transport.cpp](../../src/net/reactor_transport.cpp), §4.5d) is the
sibling architecture; kqueue reuses it wholesale. The load-bearing boundary fact:
the transport talks to the loop ONLY through `arm()`/`deregister()`/`post()` plus
the OS-free `kEventRead/kEventWrite/kEventError` mask
([include/determ/net/reactor_event_loop.hpp:50-83](../../include/determ/net/reactor_event_loop.hpp)).
Its own syscalls (`recv`/`send`/`accept`/`connect`/`poll`/`shutdown`) are portable
POSIX, and the file pins that intent explicitly
([src/net/reactor_transport.cpp:37-38](../../src/net/reactor_transport.cpp) — "destined
to be shared verbatim with the kqueue policy"). The kqueue delta is therefore:
(1) a kqueue implementation of the five loop primitives currently inlined in
`reactor_event_loop.cpp` — create, arm, deregister, wait+interpret, wake (the
§4.5 policy split, deferred at ship time per §4.5d); (2) the SIGPIPE policy
(§5 below) — the ONLY transport-TU change; (3) a CMake `elseif(APPLE)`/BSD
source-list branch. Everything else — the resumable op state machine,
`close()`'s abort synthesis, the dtor-deferred `::close(fd)`, the parked sync
half, the tracked connect helpers, `TimerService` (a plain deadline thread; no
kernel timer filter needed) — ports byte-identical.

## 1. Primitive mapping

| epoll (shipped) | kqueue | what the difference costs |
|---|---|---|
| `epoll_create1(EPOLL_CLOEXEC)` ([reactor_event_loop.cpp:41](../../src/net/reactor_event_loop.cpp)) | `kqueue()` + `fcntl(FD_CLOEXEC)` | no flags argument; kqueue fds are additionally not inherited across `fork` — hygiene only, nothing forks on this path |
| ONE registration per fd, mask `EPOLLIN\|EPOLLOUT\|EPOLLONESHOT` ([:21-26](../../src/net/reactor_event_loop.cpp), [:183-186](../../src/net/reactor_event_loop.cpp)) | up to TWO knotes per fd: `(ident=fd, EVFILT_READ)` + `(ident=fd, EVFILT_WRITE)`, each `EV_ADD\|EV_ONESHOT` | the interest UNION becomes a changelist; filter independence changes the one-shot geometry — §1.1 |
| `EPOLL_CTL_ADD` vs `MOD` + the fallback dance ([:174-192](../../src/net/reactor_event_loop.cpp)) | `EV_ADD` is an upsert | the add/mod bookkeeping and the fallback-retry hack DISAPPEAR — kqueue `arm()` is simpler than epoll's |
| `EPOLLONESHOT` DISABLES (registration survives; re-arm = `MOD`) | `EV_ONESHOT` DELETES the knote on delivery; re-arm = fresh `EV_ADD` | `EV_DISPATCH` (disable-not-delete) is the literal `EPOLLONESHOT` analogue but is NOT universally available across BSDs — use `EV_ONESHOT`, which is; the delete-vs-disable difference is absorbed by `EV_ADD`-as-upsert |
| `epoll_event.data.fd` + fd-keyed registry ([:111-124](../../src/net/reactor_event_loop.cpp)) | `kevent.ident` + the SAME registry; **`udata` deliberately UNUSED** | `udata` pointer carriage is the idiomatic kqueue style and would reintroduce exactly the close-races-dispatch UAF the fd-keyed registry-pin design exists to prevent ([reactor_event_loop.hpp:20-28](../../include/determ/net/reactor_event_loop.hpp)); stale-event safety must stay lookup-based |
| `epoll_wait(epfd, evs, 16, -1)` ([:95](../../src/net/reactor_event_loop.cpp)) | `kevent(kq, NULL, 0, evs, 16, NULL)` | `EINTR → continue` ports verbatim ([:96-98](../../src/net/reactor_event_loop.cpp)); see §6(3) for the OS caveat |
| `EPOLLERR\|EPOLLHUP` → error + BOTH readiness bits ([:32-35](../../src/net/reactor_event_loop.cpp)) | `EV_EOF` flag ON the read/write filter entry, `fflags` = socket error | translation becomes per-ENTRY (one kevent = one filter = one readiness bit); `EV_EOF` with `data > 0` still has drainable bytes — deliver `kEventRead` and let `recv` surface the truth (the shipped syscall-surfaces-errno discipline, [reactor_transport.cpp:80-96](../../src/net/reactor_transport.cpp), ports unchanged). CAUTION: `EV_ERROR` on a RETURNED entry is a REGISTRATION error, not a socket error — it must never be dispatched as readiness (§3, §1.1) |
| `eventfd(EFD_SEMAPHORE)` ([:44-61](../../src/net/reactor_event_loop.cpp)) | **NO analogue** | the multi-consumer wake is the one primitive that does not map — §2 |

### 1.1 Independent filters change the one-shot geometry

epoll: one delivery disables the ENTIRE fd — an fd armed read+write that fires
read-only silently drops its write interest until the handler re-arms, which is
why `on_event` unconditionally re-arms the union
([reactor_transport.cpp:145-160](../../src/net/reactor_transport.cpp), via
`update_interest_locked` at [:101-109](../../src/net/reactor_transport.cpp)).
kqueue: the write knote SURVIVES a read delivery. Two consequences:

1. **No lost-interest window** — strictly safer on this axis; the unconditional
   union re-arm stays correct (`EV_ADD` upsert on a live knote is benign).
2. **A stale knote can outlive its op:** an op that completes without re-parking
   leaves its filter armed (`update_interest_locked` returns early at
   `interest == 0`, [reactor_transport.cpp:105](../../src/net/reactor_transport.cpp))
   → at most ONE spurious dispatch (`EV_ONESHOT` self-deletes on fire), absorbed
   by the documented spurious-tolerance contract
   ([reactor_event_loop.hpp:23-27](../../include/determ/net/reactor_event_loop.hpp)).
   But for `EVFILT_WRITE` the spurious fire is near-guaranteed and IMMEDIATE
   (sockets are almost always writable) — one wasted dispatch per completed
   write op, i.e. per gossip message.

**Recommendation:** keep the transport verbatim; put delta-tracking in the loop.
The registry entry grows a last-armed mask — `{shared_ptr<ReactorHandler>, armed}`;
on delivering filter F for an fd, clear F's bit before dispatch; `arm(fd, want)`
issues `EV_ADD` for `want` bits and an ENOENT-tolerant `EV_DELETE` for
`armed & ~want`. This kills the guaranteed-spurious write fire and keeps ALL
kqueue-specific state inside the loop TU (the §4.5 layout rule).

**Changelist batching caveat:** a 2-entry changelist can PARTIALLY apply on
error, and without `EV_RECEIPT` which entry failed is ambiguous (and
OS-dependent — §6(6)). Use `EV_RECEIPT` with a scratch eventlist (per-entry
`EV_ERROR` status without draining pending events) where available, else one
`kevent` call per entry. The failure-tolerance argument is the shipped one
([reactor_event_loop.cpp:186-191](../../src/net/reactor_event_loop.cpp)): an arm
failing after an external close is benign — `close()` already synthesized the
aborts, and the dtor's `::close(fd)` removes any leftover knotes (§3).

## 2. The wake — EFD_SEMAPHORE has no kqueue analogue

What the shipped design gets from `EFD_SEMAPHORE`
([reactor_event_loop.cpp:44-61](../../src/net/reactor_event_loop.cpp), [:131-146](../../src/net/reactor_event_loop.cpp),
[:150-161](../../src/net/reactor_event_loop.cpp)): COUNTING semantics. N pending
units wake up to N threads; each pass-2 pop consumes exactly one unit; a lost
read race is `EAGAIN` → re-enter the wait; `stop()` writes `threads_in_run_ + 1`
units — the §4.5d HIGH-bug-2 lesson (a fixed 64 hangs shutdown on a >64-core
host; each exiting thread consumes exactly one unit). Options:

- **(a) N separate `EVFILT_USER` events, one per `run()` thread.** Needs a
  per-thread ident registration protocol on `run()` entry/exit plus `stop()`
  triggering every live ident; the entry-races-stop window adds lifecycle
  states the shipped design does not have. Most machinery, least parity. Rejected.
- **(b) One `EVFILT_USER` (+`EV_CLEAR`) with a re-trigger chain.** `NOTE_TRIGGER`s
  COALESCE — a triggered-not-yet-retrieved event absorbs further triggers, so N
  `post()`s can produce ONE wakeup, stranding N−1 closures. Fixable: every woken
  thread re-triggers when the queue is non-empty BEFORE running its closure
  (mandatory ordering — a posted closure may never return: RpcServer sessions
  occupy a loop thread for the connection's lifetime,
  [reactor_event_loop.cpp:100-108](../../src/net/reactor_event_loop.cpp)); `stop()`
  becomes a baton chain (each exiting thread re-triggers on the way out — works
  for any N, including >64). Workable, but it REPLACES the shipped counting
  argument with a liveness-chain argument in which EVERY early-return path of
  pass 2 carries a re-trigger obligation; and `EVFILT_USER` availability varies
  by BSD/version (§6(1)).
- **(c) Self-pipe, one byte per wake unit.** `pipe()`; read end registered
  `EVFILT_READ`, DEFAULT level-triggered — the shipped wake registration shape
  ([reactor_event_loop.cpp:51-57](../../src/net/reactor_event_loop.cpp)); both
  ends `O_NONBLOCK`; `post()` writes 1 byte; pass 2 reads 1 byte (race-loss =
  `EAGAIN` = continue, verbatim [:131-146](../../src/net/reactor_event_loop.cpp));
  `stop()` writes `threads_in_run_ + 1` bytes in one `write` (≤ `PIPE_BUF`,
  atomic). Byte count IS the semaphore count — isomorphic to `EFD_SEMAPHORE`.

**Recommendation: (c), the self-pipe.** Zero new liveness reasoning — the
lost-race and the >64-thread `stop()` arguments port line for line; universal
POSIX availability (no §6(1) exposure); and the one semantic deviation is
explicit and bounded: pipe capacity (typically 64 KiB) caps pending wake units
where eventfd counts to 2^64−1 — a `post()` hitting `EAGAIN` implies ≥65,536
undispatched units already queued, far past any recoverable dispatch stall.
Two pipe-specific hazards to pin at implementation time:

- **SIGPIPE on the wake pipe:** writing after the read end closes raises the
  signal, not just an error. The dtor must close the WRITE end FIRST (a racing
  `post()` then gets `EBADF` — the same benign drop already documented at
  [reactor_event_loop.cpp:170-171](../../src/net/reactor_event_loop.cpp)); on
  Apple, `fcntl(F_SETNOSIGPIPE)` on the write end is available belt-and-braces
  (gate-verify — §6).
- macOS has no `pipe2` — `O_CLOEXEC`/`O_NONBLOCK` via two `fcntl` calls after
  `pipe()`. Nothing on this path forks; hygiene only.

## 3. The §4.5 abort contracts on kqueue

**Cross-thread `close()` vs a parked async op — unchanged.** The abort recipe
is entirely transport-side: synthesize both aborted completions under `op_mu_`
with the `active`-flag exactly-once guarantee, post them, `shutdown(SHUT_RDWR)`
([reactor_transport.cpp:162-191](../../src/net/reactor_transport.cpp)) — no epoll
call anywhere in it. The loop-side `deregister` becomes `EV_DELETE` × 2 (read +
write filters), each ENOENT-tolerant (the knote may never have been armed, or
`EV_ONESHOT` already deleted it) — the "idempotent-enough" `EPOLL_CTL_DEL`
posture ([reactor_event_loop.cpp:194-200](../../src/net/reactor_event_loop.cpp)).
Preserve the shipped order: registry erase FIRST, kernel delete second.

**Does `EV_DELETE` introduce a lost-wakeup window `EPOLL_CTL_DEL` does not?**
No. An event another thread has already dequeued is a VALUE COPY in that
thread's local array (`evs[16]`, [reactor_event_loop.cpp:94](../../src/net/reactor_event_loop.cpp));
no delete can retract it — identical to epoll. The stale-dispatch window is
therefore the same, and the same two mechanisms close it: a registry miss
(erased before the kernel delete) drops the event; a reused-fd hit finds the
NEW handler, which tolerates spurious wakeups by contract
([reactor_event_loop.hpp:20-28](../../include/determ/net/reactor_event_loop.hpp)).
Critically, no ABORT can be lost, because the abort path never rides the kernel
queue at all — the synthesized completions are `post()`ed directly.

**Cross-thread `close()` vs a blocked sync write — code unchanged, assumption
unproven.** `shutdown(SHUT_RDWR)` at [reactor_transport.cpp:187](../../src/net/reactor_transport.cpp)
wakes the `poll()` park ([:209-218](../../src/net/reactor_transport.cpp)); POSIX
nominally gives this for free. But "cross-thread close releases blocked I/O" is
exactly the assumption class the IOCP increment FALSIFIED by probe on Windows
(§4.5b deviation 1: raw blocking `send()` was NOT reliably woken by
`closesocket`). Whether macOS/BSD `poll()` wakes promptly with
`POLLHUP`/`POLLIN` on a cross-thread `shutdown` must be PROBED on the gate OS
before the FB71 path is trusted — §6(5), the highest-priority probe.

**kqueue-specific bonus + caveat:** `close(fd)` auto-removes every knote
referencing the descriptor; with the dtor-deferred `::close`
([reactor_transport.cpp:53-60](../../src/net/reactor_transport.cpp)) kernel state
cannot outlive the last `shared_ptr` owner. Caveat: epoll keys registration on
the open file DESCRIPTION (survives `dup`); kqueue keys on the DESCRIPTOR. No
`dup` exists on this path — pin that as a comment so nobody introduces one.

## 4. Two-pass batch dispatch under kevent

The §4.5d HIGH-bug-1 starvation fix is loop-LOCAL ordering — dispatch every
socket event in the batch, then pop at most ONE posted closure, last
([reactor_event_loop.cpp:100-146](../../src/net/reactor_event_loop.cpp)). kevent's
batched return is just an array; the loop imposes its own dispatch order, so
kernel-side return order is irrelevant and the fix ports verbatim. Deltas:

- **One fd can contribute TWO entries per batch** (read knote + write knote)
  where epoll delivers one masked entry. Two `on_event` calls for the same
  connection in one batch are safe: `op_mu_` serializes them, the second sees
  post-first-call op state, and advancing an inactive op is an explicit no-op
  ([reactor_transport.cpp:98](../../src/net/reactor_transport.cpp)). Coalescing
  by ident before dispatch buys nothing correctness needs — skip it.
- **The wake entry stays single:** one pipe-read knote, level-triggered → at
  most one entry per batch, same as the eventfd
  ([reactor_event_loop.cpp:112](../../src/net/reactor_event_loop.cpp)) — the
  `wake = true; handle once, last` structure is preserved. (Option (b)'s
  `EVFILT_USER` would also be a single entry, but its trigger coalescing is
  exactly what breaks one-pop-per-unit accounting — another reason for the pipe.)
- **`EV_ERROR` entries must be filtered in pass 1** before the registry lookup
  — they are registration failures surfacing in the eventlist, not readiness.
  With §1.1's `EV_RECEIPT` discipline they should never appear in the wait
  path; filter defensively anyway.

## 5. SIGPIPE — MSG_NOSIGNAL does not exist on macOS

Send sites in [src/net/reactor_transport.cpp](../../src/net/reactor_transport.cpp)
needing the treatment — these are the ONLY two `send()` calls in the TU (`recv`
needs nothing):

1. [reactor_transport.cpp:69](../../src/net/reactor_transport.cpp) — `advance_locked`'s
   async-half send.
2. [reactor_transport.cpp:203](../../src/net/reactor_transport.cpp) — `write_all`'s
   sync-half send.

Both currently pass a bare `MSG_NOSIGNAL` — on macOS this does not even
compile. Linux and the BSDs have `MSG_NOSIGNAL`; macOS does not, offering
`SO_NOSIGPIPE` instead (OpenBSD has the flag but NOT the sockopt — the sockopt
alone is not the portable answer either). Policy:

- `#ifdef MSG_NOSIGNAL` → keep the per-call flag; `#else` → flags 0 AND
  `setsockopt(SO_NOSIGPIPE)` at fd intake. There is exactly ONE intake point:
  the `ReactorConnection` ctor ([reactor_transport.cpp:47-51](../../src/net/reactor_transport.cpp)),
  which both producers funnel through — accept-produced fds at
  [:293](../../src/net/reactor_transport.cpp), connect-produced at
  [:442](../../src/net/reactor_transport.cpp) — beside the existing
  `set_nonblocking`. Do NOT rely on `SO_NOSIGPIPE` inheriting across `accept()`
  (undocumented); set it per-fd.
- The in-tree precedent [src/net/sync_client.cpp:192-196](../../src/net/sync_client.cpp)
  carries the `#ifdef MSG_NOSIGNAL → else 0` ladder WITHOUT the `SO_NOSIGPIPE`
  half — compile-portable, NOT behavior-portable: on Apple a daemon-side close
  racing a CLI write delivers SIGPIPE and kills the process the ladder's own
  comment promises to keep alive. The kqueue increment must sweep every
  `send()` in the tree (`sync_client.cpp`, `light/`), not just this TU —
  a definition-of-done item (§7(2)), found by this review.
- The §2 wake pipe is covered by the dtor close-order rule (+ Apple
  `F_SETNOSIGPIPE`), not socket options — pipes are not sockets.

## 6. What CANNOT be verified without a gate

Each item is OS/version-dependent behavior that manpages disagree on or leave
ambiguous; none is testable from Linux or Windows. This is why the
design-review-only rule stands — the backend also carries the §9 close-race
correctness surface that "deserves its own stress test... before either is
trusted", which cannot even be RUN today.

1. **`EVFILT_USER` availability/semantics** — FreeBSD (≥8.1) and macOS have it;
   NetBSD only since 10; OpenBSD support is late/version-dependent. Even with
   the pipe recommendation, re-validate the option matrix on the gate OS.
2. **`EV_RECEIPT` availability + error-reporting semantics** (per-entry
   `EV_ERROR` without draining) — differs across BSDs; §1.1's arm-batching
   choice depends on it.
3. **`kevent` EINTR behavior** — return-vs-restart under `SA_RESTART` differs
   per OS; macOS has documented quirks. The shipped `EINTR → continue`
   ([reactor_event_loop.cpp:96-98](../../src/net/reactor_event_loop.cpp)) should
   absorb all variants; only a gate proves it.
4. **`EV_EOF`-with-pending-data drain semantics** — macOS delivers EOF with
   bytes still readable; the recv-surfaces-truth discipline should absorb it
   (short read then 0 → the ECONNRESET path,
   [reactor_transport.cpp:80-87](../../src/net/reactor_transport.cpp)); probe
   required — a wrong short-circuit silently truncates exactly-N reads on
   consensus-carrying frames.
5. **Cross-thread `shutdown()` waking a parked `poll()`** — the FB71 sync-half
   release (§3). The Windows probe precedent says assume nothing. Probe FIRST.
6. **Partial changelist application on registration error** — which entries of
   a multi-entry changelist applied when `kevent` returns −1 is OS-ambiguous.
7. **`O_NONBLOCK` inheritance across `accept()`** — BSDs inherit from the
   listener, Linux does not. The explicit set at
   [reactor_transport.cpp:50](../../src/net/reactor_transport.cpp) makes this
   parity-neutral; "explicit set over inherited state" wants one probe line.
8. **Tree-wide Apple compile** — never attempted; §5's `sync_client.cpp`
   finding is one known instance of a class (bare POSIX-ism in a shared TU)
   that only a real compiler pass enumerates.

## 7. Definition of done (the eventual gated implementation)

1. **Refactor first, on the GATED platforms:** extract the §4.5 reactor policy
   (create/arm/deregister/wait/wake) from `reactor_event_loop.cpp` into
   `detail/epoll_reactor`; re-run the FULL Linux gate (build, `test-net-native`
   22/22, live `test_weak_3node` + `test_multinode` + `test_dapp_subscribe` on
   the reactor-native daemon, `ci_local.sh` FAST + guards) — the split touches
   shipped code and must prove byte-neutral BEFORE any kqueue line exists.
2. `detail/kqueue_reactor` + the §5 SIGPIPE ladder (the only
   `reactor_transport.cpp` diff) + the tree-wide `send()` sweep + the CMake
   APPLE/BSD branch; ratchet extended (kqueue TUs asio-free, OS includes
   confined to `.cpp` per the §4.5 layout rule).
3. The §6 probes as a throwaway harness on the gate OS, run BEFORE trusting
   anything else (the §4.5b probe-first discipline) — §6(5) first.
4. `test-net-native`'s 22 assertions on the kqueue backend (the §4.5d
   genericized body, including BOTH §4.5 abort assertions: cross-thread
   `close()` aborts a parked async read AND a blocked sync write, exactly once).
5. The §9 connect/close churn stress — rapid connect/close cycles hammering the
   `op_mu_` close-race serialization. It does not exist for epoll yet either:
   build once, baseline on epoll (Linux), then run on kqueue. Plus a
   >64-thread `run()`/`stop()` release test (the §4.5d bug-2 class) pinning §2.
6. Live clusters on a kqueue-native daemon: `test_weak_3node` head agreement,
   `test_multinode` height 330+ no fork, `test_dapp_subscribe` 13/13 (FB71
   through the new backend); goldens byte-identical; FAST green.
7. Adversarial review at the shipped increments' standard — the 27-agent §4.5d
   review caught two HIGH loop-orchestration bugs the live clusters missed;
   this backend has the identical blind-spot shape (correct per-fd logic,
   wrong loop-level orchestration).
