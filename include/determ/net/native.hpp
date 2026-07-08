// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// net::Native* — the per-platform backend selector for the minix net seam
// (docs/proofs/MinixTacticalProfile.md §4.5b). The daemon (Node, RpcServer's
// construction site) declares its loop/transport/timers by these aliases and
// constructs them uniformly — NativeEventLoop is default-constructed, and
// NativeTransport/NativeTimer take the loop by reference (both backends ship
// a loop-taking constructor for exactly this) — so swapping a platform's
// backend is a one-line change HERE, not an edit at every declaration.
//
// Current selection:
//   Windows: the native IOCP backend (§4.5b increment 2 — the daemon cutover;
//            no transport library on this platform anymore).
//   POSIX:   the native epoll reactor backend (§4.5 — no transport library
//            here either; the kqueue policy split lands when a BSD/macOS
//            gate exists). The daemon no longer constructs ANY asio type —
//            the Asio* backends survive only for test-net-seam's contract
//            pins until asio is deleted outright (§7 step 4).
//
// This is a SELECTOR, not a seam interface: consumers still program against
// net::EventLoop/Transport/Timer/Connection (transport.hpp etc.) — the
// aliases only pick which concrete backend gets constructed.
#pragma once

#ifdef _WIN32
#include <determ/net/iocp_event_loop.hpp>
#include <determ/net/iocp_timer.hpp>
#include <determ/net/iocp_transport.hpp>

namespace determ::net {
using NativeEventLoop = IocpEventLoop;
using NativeTimer     = IocpTimer;
using NativeTransport = IocpTransport;
} // namespace determ::net

#else
#include <determ/net/reactor_event_loop.hpp>
#include <determ/net/reactor_timer.hpp>
#include <determ/net/reactor_transport.hpp>

namespace determ::net {
using NativeEventLoop = ReactorEventLoop;
using NativeTimer     = ReactorTimer;
using NativeTransport = ReactorTransport;
} // namespace determ::net

#endif
