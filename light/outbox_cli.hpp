#pragma once
// light/outbox_cli.hpp — `determ-light outbox <verb>` and the outbox selftests.
// Exit codes (outbox verbs): 0 ok; 1 error (nothing acknowledged); 3 a slot is
// CORRUPT / a reconcile leg was UNVERIFIABLE; 4 outbox full; 5 locked by
// another process; 6 genesis / sender mismatch; 7 daemon configuration error
// (HMAC auth required, non-Determ daemon).
namespace determ::light {
int cmd_outbox(int argc, char** argv);
int cmd_selftest_outbox_record(int argc, char** argv);
int cmd_selftest_outbox_classify(int argc, char** argv);
int cmd_selftest_outbox_core(int argc, char** argv);
int cmd_selftest_outbox_hint_wait(int argc, char** argv);
} // namespace determ::light
