/* Determ C99-native secure zeroization (CRYPTO-C99-SPEC.md). See secure_zero.h.
 *
 * memset through a `volatile` function pointer: the volatile qualifier forces the
 * compiler to treat the indirect call as having observable side effects, so it
 * cannot apply dead-store elimination to the zeroing of a buffer that is about to
 * go out of scope. This is the portable idiom for when memset_s (C11 Annex K),
 * explicit_bzero (BSD/glibc), and SecureZeroMemory (Win32) are not all available;
 * it compiles identically on Linux, Windows (MinGW/MSVC), and the WSL build. */
#include "determ/crypto/secure_zero.h"
#include <string.h>

static void *(*const volatile determ_memset_v)(void *, int, size_t) = memset;

void determ_secure_zero(void *p, size_t len) {
    if (p != NULL && len != 0u) {
        determ_memset_v(p, 0, len);
    }
}
