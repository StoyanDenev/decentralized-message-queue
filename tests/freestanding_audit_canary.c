/* SPDX-License-Identifier: Apache-2.0
 * Canary for the freestanding audit (tools/check_no_undefined.cmake). It calls
 * an external function and defines writable data on purpose, so the audit must
 * find both here; if it ever reports neither, it cannot fail and the build
 * stops.
 */
extern int determ_audit_canary_external(int value);

int determ_audit_canary_state = 1;

int determ_audit_canary(int value) {
    determ_audit_canary_state += value;
    return determ_audit_canary_external(value) + determ_audit_canary_state;
}
