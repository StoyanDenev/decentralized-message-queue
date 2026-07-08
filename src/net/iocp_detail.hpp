// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// Shared private plumbing for the native IOCP backend (iocp_event_loop.cpp +
// iocp_transport.cpp). Lives under src/net/ — NOT include/ — so <winsock2.h>/
// <windows.h> never enter any other TU's transitive includes (the minix §4.5
// file-layout rule; the public iocp_*.hpp headers carry only void*/uintptr_t
// opaque handles).
#pragma once
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX   // keep windows.h's min/max macros away from std::min
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>

namespace determ::net::detail {

// Every packet that goes through the completion port is one of these. `ov`
// MUST stay the first member: GetQueuedCompletionStatus hands back the
// LPOVERLAPPED, and IocpEventLoop::run() recovers the enclosing op by
// pointer-identity (standard-layout, first member — no offset arithmetic).
//
// Ownership: the op owns itself from the moment it is queued (issued or
// posted) until exactly one of its two function pointers runs — on_complete
// (normal dispatch in run(), which must free it) or on_abandon (the loop
// destructor's drain, which frees WITHOUT invoking any user callback). A
// CancelIoEx'd I/O op still completes through GQCS (with
// ERROR_OPERATION_ABORTED) — never free an op early; the kernel may still be
// writing into its buffers until the completion is dequeued (§4.5 risk 1).
struct OverlappedOp {
    OVERLAPPED ov{};
    void (*on_complete)(OverlappedOp* self, DWORD bytes, DWORD error) = nullptr;
    void (*on_abandon)(OverlappedOp* self) = nullptr;
};

// Completion keys. Socket associations and posted closures use kKeyOp (the
// op's function pointers carry all dispatch information); kKeyStop packets
// (null OVERLAPPED) release one run() thread each.
constexpr ULONG_PTR kKeyOp   = 0;
constexpr ULONG_PTR kKeyStop = 1;

// Process-wide WSAStartup, once. Never calls WSACleanup — process exit
// reclaims (the daemon needs Winsock for its whole lifetime; matches the
// static-init pattern light/rpc_client.cpp uses).
void winsock_init();

} // namespace determ::net::detail

#endif // _WIN32
