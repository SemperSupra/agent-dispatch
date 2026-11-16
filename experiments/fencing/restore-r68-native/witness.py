#!/usr/bin/env python3
"""R68 synthetic signed witness checking live native etcd state. Never grants dispatch."""
import hashlib
import hmac
import json
import pathlib
import subprocess
import sys

KEYS = ("epoch", "budget", "effect")
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
def no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d: raise ValueError("duplicate receipt field")
        d[k] = v
    return d
def live(ctl):
    out = {}
    for k in KEYS:
        p = subprocess.run([str(ctl), "get", "r68/"+k, "--print-value-only"],
                           capture_output=True, text=True, timeout=8)
        if p.returncode: raise RuntimeError("etcd unavailable")
        out[k] = p.stdout.strip()
    return out
def keyread(p):
    b = p.read_bytes()
    if len(b) != 32: raise ValueError("bad test key")
    return b
def issue(ctl, keyfile, receipt):
    value = live(ctl)
    mac = hmac.new(keyread(keyfile), canonical(value), hashlib.sha256).hexdigest()
    receipt.write_bytes(canonical({"v":1, "state":value, "mac":mac}))
    print('{"r68_witness_issued":"TEST_ONLY","release_gate":"HOLD"}')
    return 0
def check(ctl, keyfile, receipt):
    if not receipt.is_file() or not keyfile.is_file():
        return "HOLD_MISSING_WITNESS_OR_KEY", 45
    try:
        raw = receipt.read_bytes()
        if len(raw) > 4096: raise ValueError("oversize")
        d = json.loads(raw.decode(), object_pairs_hook=no_dupes)
        if (not isinstance(d, dict) or set(d) != {"v","state","mac"} or
            type(d["v"]) is not int or d["v"] != 1 or
            not isinstance(d["state"], dict) or set(d["state"]) != set(KEYS) or
            not all(isinstance(d["state"][k], str) for k in KEYS) or
            not isinstance(d["mac"], str) or len(d["mac"]) != 64):
            raise ValueError("bad receipt")
        expect = hmac.new(keyread(keyfile), canonical(d["state"]), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, d["mac"]): raise ValueError("invalid MAC")
    except (OSError, TypeError, UnicodeError, ValueError):
        return "HOLD_INVALID_WITNESS", 44
    if live(ctl) != d["state"]: return "HOLD_RESTORED_HIGH_WATER_MISMATCH", 42
    return "MATCH_ONLY_HOLD_EXTERNAL_MONOTONIC_ANCHOR_NOT_PROVEN", 43
def main():
    if len(sys.argv) != 5 or sys.argv[1] not in ("issue", "check"): return 64
    _, mode, tool, keyfile, receipt = sys.argv
    ctl, key, rec = pathlib.Path(tool),pathlib.Path(keyfile),pathlib.Path(receipt)
    if mode == "issue": return issue(ctl,key,rec)
    verdict, code = check(ctl,key,rec)
    print(json.dumps({"r68_native_restore_witness":verdict,"test_only":True,
        "real_external_anchor":"NOT_IMPLEMENTED","external_effect_admission":"DENIED"}))
    return code
if __name__ == "__main__":
    try: sys.exit(main())
    except (RuntimeError, subprocess.TimeoutExpired, OSError):
        print('{"r68_native_restore_witness":"HOLD_PROVIDER_UNAVAILABLE"}')
        sys.exit(46)
