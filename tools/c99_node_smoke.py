#!/usr/bin/env python3
"""Bounded CLI checks invoked by ci_local's exact determ-node binary."""
import subprocess
import sys
import http.client
import json
import socket
import time
from pathlib import Path


def rpc_query(port, request):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    try:
        connection.request("POST", "/", body=json.dumps(request),
                           headers={"Content-Type": "application/json"})
        reply = connection.getresponse()
        if reply.status != 200:
            raise AssertionError("routing RPC HTTP status " + str(reply.status))
        return json.loads(reply.read())
    finally:
        connection.close()


def check_live_routing(binary, arguments, salt, count, key, expected, pending_fixture=None):
    # Reserve a kernel-selected port. The close/start gap can lose a race; retry
    # only a reported listener startup failure, never a query assertion failure.
    for attempt in range(3):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        command = [binary, "--rpc-port", str(port)] + arguments
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        request = {"jsonrpc": "2.0", "method": "get_shard_for_pubkey",
                   "params": {"pubkey": key}, "id": "node-route"}
        try:
            deadline = time.monotonic() + 5
            retry = False
            while True:
                if process.poll() is not None:
                    _, error = process.communicate()
                    if "Failed to start HTTP JSON-RPC server" in error and attempt < 2:
                        retry = True
                        break
                    raise AssertionError("routing node exited before serving: " + error.strip())
                try:
                    result = rpc_query(port, request)
                    break
                except ConnectionRefusedError:
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(command, 5)
                    time.sleep(0.02)
            if retry:
                continue
            expected_reply = {"jsonrpc": "2.0", "id": "node-route", "result": {
                "scope": "routing-query", "config_source": "local", "consensus_enforced": False,
                "address": "0x" + key.lower(),
                "shard_id": expected, "shard_count": count, "routing_salt": salt}}
            if result != expected_reply:
                raise AssertionError("node routing configuration not reflected in RPC: " + repr(result))
            # Per-request reconfiguration is rejected; subsequent output must
            # retain the fixed startup mapping.
            invalid = dict(request, params={"pubkey": key, "shard_count": 1})
            rejected = rpc_query(port, invalid)
            if rejected.get("error", {}).get("code") != -32602 or "result" in rejected:
                raise AssertionError("routing accepted per-request configuration")
            if rpc_query(port, request) != expected_reply:
                raise AssertionError("routing configuration changed after request")
            pending_list = {"jsonrpc": "2.0", "method": "get_pending_transfers",
                            "params": {"shard_id": expected}, "id": "pending-list"}
            pending = rpc_query(port, pending_list)
            if pending_fixture is None:
                if pending.get("error", {}).get("code") != -32001:
                    raise AssertionError("pending inbox must be disabled by default")
            else:
                data = (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / pending_fixture).read_bytes()
                if len(data) != 397:
                    raise AssertionError("invalid pending test fixture")
                genesis = data[361:393].hex()
                metadata = {"scope": "pending-signature-and-routing", "state_validated": False,
                            "config_source": "local", "genesis_hash": genesis,
                            "routing_salt": salt, "shard_count": count, "shard_id": expected}
                if pending != {"jsonrpc": "2.0", "id": "pending-list", "result": dict(metadata, frames=[])}:
                    raise AssertionError("pending initial configuration mismatch: " + repr(pending))
                submit = {"jsonrpc": "2.0", "method": "submit_pending_transfer",
                          "params": {"frame": data.hex()}, "id": "method"}
                for status in ("inserted", "duplicate"):
                    admitted = rpc_query(port, submit)
                    if admitted != {"jsonrpc": "2.0", "id": "method", "result": dict(
                            metadata, status=status, pending_count=1, hash=data[329:361].hex())}:
                        raise AssertionError("pending submit mismatch: " + repr(admitted))
                # Signed bytes remain canonical through actual HTTP receive/store/list.
                expected_list = {"jsonrpc": "2.0", "id": "pending-list", "result": dict(metadata, frames=[data.hex()])}
                if rpc_query(port, pending_list) != expected_list:
                    raise AssertionError("pending frame/configuration not retained")
                altered = bytearray(data); altered[265] ^= 1
                submit["params"]["frame"] = altered.hex()
                invalid_sig = rpc_query(port, submit)
                if invalid_sig.get("error", {}).get("code") != -32002:
                    raise AssertionError("pending accepted forged duplicate")
                if rpc_query(port, pending_list) != expected_list:
                    raise AssertionError("pending rejection changed stored bytes")
            return
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    raise


def main():
    binary, build_directory = sys.argv[1:]
    try:
        help_result = subprocess.run([binary, "--help"], capture_output=True,
                                     text=True, timeout=5)
        if help_result.returncode != 0:
            raise AssertionError("--help failed")
        for role in ("--aggregator", "--contributor"):
            destination = Path(build_directory) / ("forbidden-store-" + role[2:])
            result = subprocess.run([binary, role, "--data-dir", str(destination)],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode != 1:
                raise AssertionError(role + " must reject persistence with exit 1")
            if "Duel output is not a validated block" not in result.stderr:
                raise AssertionError(role + " returned an unrelated failure")
            if destination.exists():
                raise AssertionError(role + " created storage before rejection")
        for flag, values in (
            ("--routing-shards", [[], ["0"], ["-1"], ["+1"], ["4294967296"],
                                  ["1x"], [" 1"], [""], ["7", "--routing-shards", "3"]]),
            ("--pending-genesis", [[], ["0" * 63], ["0" * 65], ["g" * 64],
                                   ["0" * 64, "--pending-genesis", "f" * 64]]),
            ("--routing-salt", [[], ["0" * 63], ["0" * 65], ["g" * 64],
                                ["0" * 64, "--routing-salt", "f" * 64]]),
        ):
            for value in values:
                result = subprocess.run([binary, flag] + value, capture_output=True,
                                        text=True, timeout=5)
                if result.returncode != 1 or flag + " requires one" not in result.stderr:
                    raise AssertionError("invalid routing flag was not rejected: " + repr([flag] + value))
        no_port = subprocess.run([binary, "--pending-genesis", "0" * 64],
                                 capture_output=True, text=True, timeout=5)
        if no_port.returncode != 1 or "requires an RPC port" not in no_port.stderr:
            raise AssertionError("pending inbox without RPC port was not rejected")
        check_live_routing(binary, [], "0" * 64, 1, "0" * 64, 0)
        ramp_salt = bytes(range(32)).hex()
        check_live_routing(binary, ["--routing-shards", "7", "--routing-salt", ramp_salt],
                           ramp_salt, 7, "0" * 64, 5)
        check_live_routing(binary, ["--routing-shards", "4294967295", "--routing-salt", "F" * 64],
                           "f" * 64, 4294967295, "F" * 64, 1711102701)
        check_live_routing(binary, ["--pending-genesis", "0" * 64], "0" * 64, 1,
                           "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c", 0,
                           "pending_transfer_default.bin")
        check_live_routing(binary, ["--routing-shards", "7", "--routing-salt", ramp_salt,
                                   "--pending-genesis", ramp_salt], ramp_salt, 7,
                           "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c", 6,
                           "pending_transfer_routed.bin")
    except subprocess.TimeoutExpired:
        print("FAIL(timeout): determ-node CLI", file=sys.stderr)
        return 124
    except OSError as error:
        print("FAIL(launch): " + str(error), file=sys.stderr)
        return 126
    except (ValueError, http.client.HTTPException) as error:
        print("FAIL: invalid routing HTTP response: " + str(error), file=sys.stderr)
        return 1
    except AssertionError as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1
    print("PASS: node help, duel persistence refusals, routing/pending flags and live configured RPC")
    return 0


if __name__ == "__main__":
    sys.exit(main())
