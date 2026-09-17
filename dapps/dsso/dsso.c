#include "dsso.h"

int dsso_ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    if (!a || !b) return 0;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

const char *dsso_status_name(dsso_status s) {
    switch (s) {
        case DSSO_OK:            return "DSSO_OK";
        case DSSO_E_ARG:         return "DSSO_E_ARG";
        case DSSO_E_FORMAT:      return "DSSO_E_FORMAT";
        case DSSO_E_CRYPTO:      return "DSSO_E_CRYPTO";
        case DSSO_E_TRUST:       return "DSSO_E_TRUST";
        case DSSO_E_EXPIRED:     return "DSSO_E_EXPIRED";
        case DSSO_E_REPLAY:      return "DSSO_E_REPLAY";
        case DSSO_E_AUDIENCE:    return "DSSO_E_AUDIENCE";
        case DSSO_E_BINDING:     return "DSSO_E_BINDING";
        case DSSO_E_STATUS:      return "DSSO_E_STATUS";
        case DSSO_E_ASSURANCE:   return "DSSO_E_ASSURANCE";
        case DSSO_E_UNAVAILABLE: return "DSSO_E_UNAVAILABLE";
    }
    return "DSSO_E_UNKNOWN";
}
