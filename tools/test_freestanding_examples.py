#!/usr/bin/env python3
"""Bounded educational-example gate, entered through ci_local.sh only.

This is functional, mutation and freestanding-link evidence. Source trace counters
cannot prove that an optimizing compiler preserves constant-time machine code.
All build inputs are snapshotted into a fresh, retained temporary directory. A
failed compilation, launch, signal or timeout never counts as a killed mutant.
The JSON report is a human-readable build report, not a wire/storage/test format.
"""

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INPUTS = (
    "docs/examples/freestanding_core.h",
    "docs/examples/freestanding_core.c",
    "tests/test_freestanding_example.c",
)
STRICT = ["-std=c99", "-pedantic-errors", "-Wall", "-Wextra", "-Werror"]
# All demonstration profiles exclude the host stack-protector runtime. This is
# not a production hardening prescription: a target may supply its own handler.
FREE = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-lto"]
# Each deliberately wrong implementation stays memory-defined on its test
# inputs. Rejection therefore comes from an asserted property, not a crash.
MUTANTS = [
    ("accept-short-header",
     "if (length < FG_HEADER_SIZE) return 0; /* FG_HEADER_CHECK */",
     "if (length < FG_HEADER_SIZE) return 1; /* mutant: accept truncation */"),
    ("accept-oversized-frame",
     "if (available > FG_PAYLOAD_CAP) return 0; /* FG_CAP_CHECK */",
     "if (available > FG_PAYLOAD_CAP) return 1; /* mutant: accept oversize */"),
    ("accept-trailing-byte",
     "if ((size_t)payload_len != available) return 0; /* FG_EXACT_CHECK */",
     "if ((size_t)payload_len > available) return 0; /* mutant: tolerate trailer */"),
    ("wrong-shard-endianness",
     "shard = (uint16_t)(((unsigned int)bytes[6] << 8) |",
     "shard = (uint16_t)(((unsigned int)bytes[6]) |"),
    ("early-exit-comparison",
     "difference |= (unsigned int)(a[i] ^ b[i]); /* FG_EQUAL_REDUCE */",
     "difference |= (unsigned int)(a[i] ^ b[i]);\n"
     "        if (difference != 0U) return 0; /* mutant: secret-dependent exit */"),
    ("wipe-no-op",
     "bytes[i] = 0U; /* FG_WIPE_STORE */",
     "(void)bytes; /* mutant: erase no bytes */"),
]


class GateFailure(Exception):
    pass


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Runner:
    def __init__(self, directory):
        self.directory = directory
        self.commands = []

    def run(self, args, label, *, allow_failure=False, stdin=None, env=None):
        """Always record build status separately from execution status."""
        args = [str(arg) for arg in args]
        log = self.directory / (label + ".log")
        try:
            result = subprocess.run(args, input=stdin, text=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=60,
                                    env=env, cwd=self.directory)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GateFailure("infrastructure failure: " + label + ": " + str(exc)) from exc
        log.write_text(result.stdout)
        self.commands.append({"label": label, "argv": args,
                              "exit_code": result.returncode, "log": str(log)})
        if result.returncode < 0:
            raise GateFailure("signal, not a test rejection: " + label)
        if result.returncode != 0 and not allow_failure:
            raise GateFailure(label + " failed; inspect " + str(log))
        return result


def find_compilers(runner):
    """Do not count Apple's /usr/bin/gcc (Clang) as an independent GCC."""
    candidates = []
    for name in ("clang", "gcc"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        try:
            for prefix in ("gcc", "clang"):
                candidates.extend(sorted(path for path in Path(directory).glob(prefix + "-*")
                                         if re.fullmatch(prefix + r"-[0-9]+(?:\.[0-9]+)*", path.name)))
        except OSError:
            continue
    # Homebrew's versioned GCC can be installed without its prefix in PATH.
    for directory in (Path("/opt/homebrew/bin"), Path("/usr/local/bin")):
        if directory.is_dir():
            candidates.extend(sorted(path for path in directory.glob("gcc-*")
                                     if re.fullmatch(r"gcc-[0-9]+(?:\.[0-9]+)*", path.name)))
    compilers, seen = {}, set()
    for candidate in candidates:
        canonical = candidate.resolve()
        if canonical in seen or not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        seen.add(canonical)
        label = "discover-" + str(len(seen))
        macros = runner.run([candidate, "-dM", "-E", "-x", "c", "-"],
                            label, allow_failure=True, stdin="\n")
        if macros.returncode != 0:
            continue
        kind = ("clang" if "#define __clang__ " in macros.stdout else
                "gcc" if "#define __GNUC__ " in macros.stdout else None)
        if kind is None or kind in compilers:
            continue
        version = runner.run([candidate, "--version"], label + "-version").stdout.strip()
        target = runner.run([candidate, "-dumpmachine"], label + "-target").stdout.strip()
        compilers[kind] = {"path": str(candidate), "version": version, "target": target}
    if not compilers:
        raise GateFailure("neither an actual GCC nor Clang compiler is available")
    return compilers


def audit_undefined(runner, nm, artifact, label):
    # Neither GNU nm -u nor Apple nm -u prints a heading for a single object.
    result = runner.run([nm, "-u", artifact], label)
    if result.stdout.strip():
        raise GateFailure("unexpected external references in " + str(artifact) + ": " + result.stdout)


def build_test(runner, compiler, optimization, core, header_dir, test,
               output, label, *, trace=False, sanitizer=False):
    flags = STRICT + FREE + [optimization]
    if trace:
        flags += ["-DFG_TEST_TRACE"]
    if sanitizer:
        flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                  "-fno-omit-frame-pointer"]
    runner.run([compiler] + flags + ["-I", header_dir, core, test, "-o", output], label)
    if not output.is_file():
        raise GateFailure("successful command produced no executable: " + label)


def check_mutants(runner, profile, compiler, optimization, snapshot, test, report):
    """Functional mutants must fail the same tests that the fresh baseline passes."""
    baseline = profile / "trace-baseline"
    original = (snapshot / "freestanding_core.c").read_text()
    build_test(runner, compiler, optimization, snapshot / "freestanding_core.c",
               snapshot, test, baseline, profile.name + "-trace-build", trace=True)
    runner.run([baseline], profile.name + "-trace-baseline")
    for name, old, new in MUTANTS:
        if original.count(old) != 1:
            raise GateFailure("mutant must have exactly one source match: " + name)
        isolated = profile / ("mutant-" + name)
        isolated.mkdir()
        shutil.copy2(snapshot / "freestanding_core.h", isolated / "freestanding_core.h")
        source = isolated / "freestanding_core.c"
        source.write_text(original.replace(old, new, 1))
        binary = isolated / "test"
        label = profile.name + "-mutant-" + name
        build_test(runner, compiler, optimization, source, isolated, test,
                   binary, label + "-build", trace=True)
        result = runner.run([binary], label + "-run", allow_failure=True)
        # All test assertion failures return exactly 1. Abnormal exits do not
        # establish falsification, even when their status happens to be nonzero.
        if result.returncode != 1:
            raise GateFailure(label + " did not fail an assertion (exit " +
                              str(result.returncode) + ")")
        report.append({"name": name, "build": "PASS", "assertion": "REJECTED",
                       "binary_sha256": digest(binary)})


def sanitizer_profile(runner, profile, compiler, optimization, core, snapshot, test):
    # Probe instrumentation support on a trivial program. Once this succeeds,
    # failure in the real example is a gate failure, never an unsupported skip.
    probe = profile / "sanitizer-probe.c"
    probe.write_text("int main(void) { return 0; }\n")
    executable = profile / "sanitizer-probe"
    flags = STRICT + [optimization, "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    result = runner.run([compiler] + flags + [probe, "-o", executable],
                        profile.name + "-sanitizer-probe-build", allow_failure=True)
    if result.returncode != 0:
        return "NOT VERIFIED: toolchain cannot compile/link the sanitizer probe (see log)"
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    runner.run([executable], profile.name + "-sanitizer-probe-run", env=environment)
    binary = profile / "sanitized-tests"
    build_test(runner, compiler, optimization, core, snapshot, test, binary,
               profile.name + "-sanitizer-build", sanitizer=True)
    runner.run([binary], profile.name + "-sanitizer-run", env=environment)
    return "PASS: hosted ASan+UBSan semantic tests; not exhaustive memory-safety proof"


def run_gate(runner, report):
    if len(MUTANTS) != 6 or len({mutant[0] for mutant in MUTANTS}) != 6:
        raise GateFailure("the six required, distinct mutation cases must be present")
    snapshot = runner.directory / "snapshot"
    snapshot.mkdir()
    report["sources"] = {}
    report["gate_sources"] = {name: digest(ROOT / name) for name in
                              ("tools/ci_local.sh", "tools/test_freestanding_examples.py")}
    for relative in INPUTS:
        source = ROOT / relative
        destination = snapshot / source.name
        shutil.copy2(source, destination)
        report["sources"][relative] = digest(destination)
    core, test = snapshot / "freestanding_core.c", snapshot / "test_freestanding_example.c"
    compilers = find_compilers(runner)
    report["compilers"] = compilers
    report["unavailable_compilers"] = [kind for kind in ("gcc", "clang") if kind not in compilers]
    nm = shutil.which("nm")
    disassembler = shutil.which("objdump")
    if not nm or not disassembler:
        raise GateFailure("nm and objdump are required for retained object evidence")
    report["profiles"] = []
    for kind, details in compilers.items():
        compiler = details["path"]
        for optimization in ("-O2", "-O3"):
            name = kind + optimization
            profile = runner.directory / name
            profile.mkdir()
            entry = {"name": name, "flags": STRICT + FREE + [optimization],
                     "lto": "disabled (-fno-lto)", "mutants": []}
            report["profiles"].append(entry)
            obj, assembly = profile / "core.o", profile / "core.s"
            flags = STRICT + FREE + [optimization, "-I", snapshot]
            runner.run([compiler] + flags + ["-c", core, "-o", obj], name + "-object-build")
            audit_undefined(runner, nm, obj, name + "-object-undefined")
            runner.run([compiler] + flags + ["-S", core, "-o", assembly], name + "-assembly-build")
            disassembly = runner.run([disassembler, "-d", obj], name + "-object-disassembly")
            if not disassembly.stdout.strip():
                raise GateFailure("empty disassembly for " + name)
            runner.run([disassembler, "-r", obj], name + "-object-relocations")
            # Same-translation-unit optimization can see that the caller never
            # reads the key. Preserve this uninstrumented example for human
            # inspection of dead-store elimination, not an assembly-text proxy
            # claiming to prove erasure. This is still not the final target image.
            dead_source = profile / "wipe-dead-caller.c"
            dead_source.write_text('#include "freestanding_core.c"\n'
                                   'void fg_wipe_dead(void)\n{\n'
                                   '    unsigned char key[32];\n'
                                   '    fg_wipe(key, sizeof key);\n}\n')
            dead_obj = profile / "wipe-dead-caller.o"
            dead_asm = profile / "wipe-dead-caller.s"
            runner.run([compiler] + flags + ["-c", dead_source, "-o", dead_obj],
                       name + "-dead-caller-object-build")
            audit_undefined(runner, nm, dead_obj, name + "-dead-caller-undefined")
            runner.run([compiler] + flags + ["-S", dead_source, "-o", dead_asm],
                       name + "-dead-caller-assembly-build")
            runner.run([disassembler, "-d", dead_obj], name + "-dead-caller-disassembly")
            entry["dead_caller"] = {"source_sha256": digest(dead_source),
                                    "object_sha256": digest(dead_obj),
                                    "assembly_sha256": digest(dead_asm),
                                    "inspection": "retained for manual review; not automatically proved"}
            # Relocatable no-runtime linkage audits the resulting object again.
            # It demonstrates zero external references, not a bootable unikernel.
            linked = profile / "freestanding-linked.o"
            linker_flags = ["-nostdlib", "-Wl,-r"]
            if platform.system() == "Linux":
                linker_flags += ["-no-pie"]
            link = runner.run([compiler] + linker_flags + [obj, "-o", linked],
                              name + "-nostdlib-link", allow_failure=True)
            if link.returncode == 0:
                audit_undefined(runner, nm, linked, name + "-linked-undefined")
                entry["nostdlib_link"] = "PASS: relocatable artifact, no unresolved references"
                entry["linked_sha256"] = digest(linked)
            else:
                entry["nostdlib_link"] = "NOT VERIFIED: relocatable link failed (see log; cause not classified)"
            binary = profile / "semantic-tests"
            build_test(runner, compiler, optimization, core, snapshot, test,
                       binary, name + "-semantic-build")
            runner.run([binary], name + "-semantic-run")
            entry["semantic_tests"] = "PASS"
            entry["object_sha256"] = digest(obj)
            entry["assembly_sha256"] = digest(assembly)
            entry["binary_sha256"] = digest(binary)
            check_mutants(runner, profile, compiler, optimization, snapshot, test, entry["mutants"])
            entry["sanitizers"] = sanitizer_profile(runner, profile, compiler,
                                                    optimization, core, snapshot, test)
            print("PASS:", name, "semantics, undefined-symbol audit,",
                  len(entry["mutants"]), "compiled mutants rejected;", entry["sanitizers"], flush=True)
    for kind in report["unavailable_compilers"]:
        print("NOT VERIFIED: compiler unavailable:", kind, flush=True)


def main():
    if os.environ.get("DETERM_FREESTANDING_GATE") != "1":
        print("Use bash tools/ci_local.sh --freestanding-examples", file=sys.stderr)
        return 2
    directory = Path(tempfile.mkdtemp(prefix="determ-freestanding-examples-"))
    runner = Runner(directory)
    report = {"scope": "educational examples only; not production qualification",
              "host": {"system": platform.system(), "release": platform.release(),
                       "machine": platform.machine()},
              "not_verified": ["LTO / whole-program final production image",
                               "machine-code constant-time proof and leakage measurements",
                               "exhaustive/formal whole-program memory-safety verification",
                               "other compiler versions, ISAs, devices, DMA and hypervisors"],
              "artifact_directory": str(directory)}
    print("Artifacts retained:", directory, flush=True)
    try:
        run_gate(runner, report)
        report["status"] = "PASS (bounded scope only)"
        result = 0
    except (GateFailure, OSError) as exc:
        report["status"] = "FAIL"
        report["error"] = str(exc)
        print("FAIL:", exc, file=sys.stderr)
        result = 1
    report["commands"] = runner.commands
    report_path = directory / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print("Report:", report_path, flush=True)
    if result == 0:
        print("NOT VERIFIED: LTO, production image, machine-code constant-time, leakage or whole-system memory safety.")
    return result


if __name__ == "__main__":
    sys.exit(main())
