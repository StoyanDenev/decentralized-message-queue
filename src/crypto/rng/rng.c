/* Determ C99 OS-entropy shim (CRYPTO-C99-SPEC.md §3.15). See rng.h. */
#include "determ/crypto/rng/rng.h"

#ifdef _WIN32

#include <windows.h>
#include <bcrypt.h>

int determ_rng_bytes(uint8_t *buf, size_t n) {
    /* BCryptGenRandom takes a ULONG; chunk for the (theoretical) >2^31 case. */
    while (n) {
        ULONG chunk = (n > 0x7fffffffu) ? 0x7fffffffu : (ULONG)n;
        NTSTATUS st = BCryptGenRandom(NULL, buf, chunk,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(st)) return -1;
        buf += chunk;
        n   -= chunk;
    }
    return 0;
}

#else /* POSIX */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

int determ_rng_bytes(uint8_t *buf, size_t n) {
#if defined(__linux__)
    /* getrandom(2): blocks only until the kernel pool is initialized once at
     * boot; never returns weak bytes. EINTR is retried; any other error falls
     * through to the /dev/urandom path for the REMAINING bytes. */
    while (n) {
        ssize_t got = getrandom(buf, n, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            break; /* e.g. ENOSYS on pre-3.17 kernels -> urandom fallback */
        }
        buf += (size_t)got;
        n   -= (size_t)got;
    }
    if (n == 0) return 0;
#endif
    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) return -1;
        while (n) {
            ssize_t got = read(fd, buf, n);
            if (got < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return -1;
            }
            if (got == 0) { close(fd); return -1; }
            buf += (size_t)got;
            n   -= (size_t)got;
        }
        close(fd);
        return 0;
    }
}

#endif /* _WIN32 / POSIX */
