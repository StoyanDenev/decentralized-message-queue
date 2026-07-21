#!/usr/bin/env python3
# rpc_tamper_proxy.py — a transparent man-in-the-middle for the determ node's
# newline-delimited JSON RPC, used to gate the light client's value-hash
# cleartext cross-checks against a LYING DAEMON (register claims RP-3 / SU-2).
#
# The determ RPC (src/rpc/rpc.cpp) is synchronous newline-delimited JSON over
# ONE persistent TCP connection: the client writes `{"method":..,"params":..}\n`
# and the node replies `{"result":{..},"error":..}\n`, strictly alternating,
# many pairs per connection. Nothing signs the response (the optional HMAC auth
# covers only the REQUEST), so a reply rewrite is undetectable at the transport
# layer BY DESIGN — which is exactly what makes the test meaningful: a correct
# light client must catch the lie cryptographically (the tampered cleartext no
# longer hashes to the committee-proven value_hash), not via transport.
#
# This proxy relays every request verbatim to the real daemon and every reply
# back UNCHANGED, EXCEPT: for replies to a chosen target method (optionally
# filtered by params), it rewrites ONE named field of the `result` object — a
# daemon lying about a single cleartext value while every other RPC (headers,
# block, committee, the merkle proof) stays honest. With no --method, it is a
# pure pass-through, used to prove the proxy is transparent (the positive
# control) so the tamper leg is not vacuous.
#
# stdlib only (socket, threading, json, argparse) — no third-party dependency;
# 154 tools/*.sh already invoke python3.
#
# Usage:
#   rpc_tamper_proxy.py --listen P --upstream N            # pass-through
#   rpc_tamper_proxy.py --listen P --upstream N \          # RP-3
#       --method account --field registry.registered_at --mode bump
#   rpc_tamper_proxy.py --listen P --upstream N \          # SU-2
#       --method state_proof --match namespace=c,key=genesis_total \
#       --field value_hex --mode flip-hex
#
# --field is a dotted path into `result` (e.g. value_hex, registry.region).
# Modes:
#   flip-hex  flip the last nibble of a hex string (same length, valid hex,
#             guaranteed different value)
#   bump      add 1 to an integer field (guaranteed different value)
#   set       replace with --set VALUE (string) verbatim
# Only the FIRST matching reply is tampered unless --all is given.
import argparse, json, socket, sys, threading

def log(fh, msg):
    if fh:
        fh.write(msg + "\n"); fh.flush()

def params_match(params, want):
    for k, v in want.items():
        if str(params.get(k)) != v:
            return False
    return True

def flip_last_nibble(hexstr):
    if not hexstr:
        return hexstr
    last = hexstr[-1]
    try:
        int(last, 16)
    except ValueError:
        return hexstr
    return hexstr[:-1] + format(int(last, 16) ^ 0x1, "x")

def nav(obj, path):
    # returns (parent_dict, last_key) for a dotted path, or (None, None)
    keys = path.split(".")
    cur = obj
    for k in keys[:-1]:
        if not isinstance(cur, dict) or k not in cur:
            return None, None
        cur = cur[k]
    if not isinstance(cur, dict) or keys[-1] not in cur:
        return None, None
    return cur, keys[-1]

class Proxy:
    def __init__(self, args):
        self.args = args
        self.want = {}
        if args.match:
            for pair in args.match.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    self.want[k.strip()] = v.strip()
        self.tampered = 0
        self.lock = threading.Lock()
        self.logfh = open(args.log, "w") if args.log else None

    def should_tamper(self, req):
        if not self.args.method or req.get("method") != self.args.method:
            return False
        if self.want and not params_match(req.get("params") or {}, self.want):
            return False
        with self.lock:
            if self.tampered and not self.args.all:
                return False
        return True

    def tamper(self, reply):
        result = reply.get("result")
        if not isinstance(result, dict):
            log(self.logfh, "MISS: result not an object: " + json.dumps(reply)[:200])
            return False
        parent, key = nav(result, self.args.field)
        if parent is None:
            log(self.logfh, "MISS: field %r absent: %s"
                % (self.args.field, json.dumps(reply)[:300]))
            return False
        old = parent[key]
        if self.args.mode == "set":
            new = self.args.set
        elif self.args.mode == "bump":
            try:
                new = int(old) + 1
            except (TypeError, ValueError):
                log(self.logfh, "MISS: bump on non-int %r" % (old,)); return False
        else:
            new = flip_last_nibble(str(old))
        if new == old:
            log(self.logfh, "WARN: tamper produced identical value: %r" % (old,))
        parent[key] = new
        with self.lock:
            self.tampered += 1
        log(self.logfh, "TAMPER %s.%s: %r -> %r"
            % (self.args.method, self.args.field, old, new))
        return True

    def handle(self, client):
        try:
            up = socket.create_connection((self.args.upstream_host,
                                           self.args.upstream_port))
        except OSError as e:
            log(self.logfh, "upstream connect failed: %s" % e)
            client.close(); return
        cf = client.makefile("rwb", buffering=0)
        uf = up.makefile("rwb", buffering=0)
        try:
            while True:
                req_line = cf.readline()
                if not req_line:
                    break
                do_tamper = False
                try:
                    do_tamper = self.should_tamper(
                        json.loads(req_line.decode("utf-8")))
                except Exception:
                    pass
                uf.write(req_line)                  # forward request verbatim
                reply_line = uf.readline()          # one reply per request
                if not reply_line:
                    break
                if do_tamper:
                    try:
                        reply = json.loads(reply_line.decode("utf-8"))
                        if self.tamper(reply):
                            reply_line = (json.dumps(reply) + "\n").encode("utf-8")
                    except Exception as e:
                        log(self.logfh, "tamper parse error: %s" % e)
                cf.write(reply_line)                # return (maybe tampered) reply
        finally:
            for s in (client, up):
                try: s.close()
                except OSError: pass

    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.args.listen))
        srv.listen(8)
        print("PROXY-READY %d -> %d" % (self.args.listen, self.args.upstream_port),
              flush=True)                            # readiness marker for the harness
        while True:
            client, _ = srv.accept()
            threading.Thread(target=self.handle, args=(client,),
                             daemon=True).start()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--upstream", dest="upstream_port", type=int, required=True)
    ap.add_argument("--upstream-host", default="127.0.0.1")
    ap.add_argument("--method", default="")
    ap.add_argument("--match", default="")
    ap.add_argument("--field", default="")
    ap.add_argument("--mode", choices=["flip-hex", "bump", "set"], default="flip-hex")
    ap.add_argument("--set", default="")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--log", default="")
    args = ap.parse_args()
    if args.method and not args.field:
        ap.error("--method requires --field")
    Proxy(args).serve()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
