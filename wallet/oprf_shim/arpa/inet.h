// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// A2 Phase 6: Windows MSVC portability stub for liboprf.
//
// liboprf's source files #include <arpa/inet.h> for htons/htonl/etc.
// That header doesn't exist on Windows. By placing this stub on the
// include path BEFORE the system headers, the #include resolves here
// and we provide the byte-swap routines via <winsock2.h>.
//
// Unix builds (where <arpa/inet.h> exists in /usr/include) should not
// see this file because the FetchContent + CMake shim only adds this
// shim directory under WIN32.

#pragma once

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  // Do NOT define htonll / ntohll here: liboprf's own utils.c provides
  // them under `#ifndef htonll`. Defining them as static __inline would
  // not trigger the preprocessor guard (it tests for a macro) and would
  // produce duplicate-definition errors at link time. Trust liboprf to
  // supply its 64-bit byte swap.
#else
  // On real Unix, fall through to the system header.
  #include_next <arpa/inet.h>
#endif
