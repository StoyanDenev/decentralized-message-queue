/* determ-dsso — the DSSO service binary (selftest surface).
 *
 * Every DSSO module registers one `selftest-*` subcommand here; tools/test_*.sh
 * wrappers run them and judge on the single terminal PASS:/FAIL: marker, the same
 * contract the rest of the repository's gates use. Keeping the surface to
 * selftests means this binary has no network listener and no persistent state:
 * an operator deployment composes the modules, and what ships here is the proof
 * that each module behaves as its gate asserts. */
#include <stdio.h>
#include <string.h>

#include "dsso.h"

int dsso_selftest_core(void);

static int usage(void) {
    printf("determ-dsso — DSSO service (Sign-In With Determ), off-chain identity DApp\n\n");
    printf("  determ-dsso selftest-core        status codes + constant-time compare\n");
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    if (!strcmp(argv[1], "selftest-core")) return dsso_selftest_core();
    return usage();
}

int dsso_selftest_core(void) {
    int fail = 0;
    /* A gate's own harness must not be the thing under test: check() only
     * reports, and every assertion below is a property of dsso.c. */
    #define CHECK(cond, msg) do { \
        if (cond) printf("  PASS: %s\n", (msg)); \
        else { printf("  FAIL: %s\n", (msg)); fail++; } } while (0)

    static const uint8_t a[4] = {1, 2, 3, 4};
    static const uint8_t b[4] = {1, 2, 3, 4};
    static const uint8_t c[4] = {1, 2, 3, 5};
    CHECK(dsso_ct_equal(a, b, 4) == 1, "ct_equal: equal spans compare equal");
    CHECK(dsso_ct_equal(a, c, 4) == 0, "ct_equal: a difference in the last byte is caught");
    CHECK(dsso_ct_equal(a, c, 3) == 1, "ct_equal: the compare honours the given length");
    CHECK(dsso_ct_equal(NULL, b, 4) == 0, "ct_equal: a NULL operand is not equal to anything");
    CHECK(dsso_ct_equal(a, b, 0) == 1, "ct_equal: an empty compare is vacuously equal");

    CHECK(DSSO_OK == 0, "status: DSSO_OK is 0 and every failure is negative");
    CHECK(DSSO_E_ARG < 0 && DSSO_E_STATUS < 0 && DSSO_E_ASSURANCE < 0,
          "status: the failure codes a caller switches on are all negative");
    CHECK(!strcmp(dsso_status_name(DSSO_E_TRUST), "DSSO_E_TRUST"),
          "status: a code names itself for operator logs");
    CHECK(!strcmp(dsso_status_name((dsso_status)-999), "DSSO_E_UNKNOWN"),
          "status: an unknown code is named, never dereferenced");

    printf("\n  %s: dsso-core %s\n", fail == 0 ? "PASS" : "FAIL",
           fail == 0 ? "all assertions" : "had failures");
    return fail == 0 ? 0 : 1;
}
