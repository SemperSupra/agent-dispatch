#!/usr/bin/env python3
"""HTTP-level synthetic signed-bundle activation and negative qualification.

No real principals, host policy, secrets, remote endpoints or source access.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import urllib.request

ROOT = Path(sys.argv[1])
OUT = Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
START = time.monotonic()
BUNDLE = ROOT / "active.tar.gz"
EVENTS = ROOT / "requests.jsonl"
INPUT = {"principal": "worker-a", "workset_ref": "synthetic:workset-a",
         "delegation": "observe"}
report = {
    "schema_version": 1,
    "source_scope": "synthetic_only_no_private_code_or_live_grants",
    "policy_source_rights": "no_approval_or_effect_authority",
    "native_amd64_or_arm64": __import__("platform").machine(),
    "image_requested": "docker.io/openpolicyagent/opa:1.22.3",
    "signature_key_id_explicit": True,
    "unsigned_delta_allowed": False,
    "stage_results": [],
    "restart_persistence_qualified": False,
    "antirollback_qualified": False,
    "live_github_policy_approval_qualified": False,
    "sidecar_mcp_integration_qualified": False,
    "rootless_quadlet_qualified": False
}

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def decision(inp=INPUT):
    req = urllib.request.Request("http://127.0.0.1:8181/v1/data/authz/allow",
                                 data=json.dumps({"input": inp}).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=3) as rsp:
        result = json.load(rsp)
    return result.get("result") is True

def publish(name):
    src = ROOT / name
    stage = ROOT / ("active." + name + ".stage")
    shutil.copyfile(src, stage)
    os.replace(stage, BUNDLE)
    return digest(src)

def served(h):
    if not EVENTS.exists():
        return False
    for line in EVENTS.read_text().splitlines():
        e = json.loads(line)
        if e["status"] == 200 and e["sha256"] == h:
            return True
    return False

def wait_for(predicate, timeout, what):
    limit = time.monotonic() + timeout
    last = None
    while time.monotonic() < limit:
        try:
            last = predicate()
            if last:
                return (time.monotonic() - START) * 1000.0
        except Exception as e:
            last = str(e)
        time.sleep(0.15)
    raise AssertionError(f"{what} did not pass within {timeout}s; last={last!s}")

def stage(name, filename, expected_decision, negative=False):
    start = time.monotonic()
    h = publish(filename)
    wait_for(lambda: served(h), 30, name + " delivered")
    if negative:
        # Give OPA enough time to attempt activation after delivery and ensure
        # no late activation; this tests *retention of prior decision*, not
        # independent authorization or host-level freshness.
        until = time.monotonic() + 3.5
        while time.monotonic() < until:
            if decision() != expected_decision:
                raise AssertionError(name + ": rejected candidate changed decision")
            time.sleep(0.2)
    else:
        wait_for(lambda: decision() == expected_decision, 30, name + " activated")
    report["stage_results"].append({
        "stage": name, "passed": True, "server_delivered_sha256": h,
        "decision": expected_decision,
        "elapsed_from_publish_ms": round((time.monotonic()-start)*1000, 1),
        "negative_rejected": negative
    })

try:
    wait_for(lambda: decision() is True, 45, "initial signed allow activation")
    if decision({"principal": "worker-b", "workset_ref":"synthetic:workset-a",
                 "delegation": "observe"}):
        raise AssertionError("wrong principal was allowed")
    if decision({"principal": "worker-a", "workset_ref":"synthetic:workset-b",
                 "delegation": "observe"}):
        raise AssertionError("wrong workset was allowed")
    report["stage_results"].append({"stage":"signed_allow_initial",
                                   "passed":True, "decision":True})
    stage("unsigned_snapshot_rejected", "unsigned.tar.gz", True, True)
    stage("signed_deny_revokes", "deny.tar.gz", False)
    stage("tampered_signature_rejected", "tampered.tar.gz", False, True)
    stage("unsigned_delta_rejected", "delta.tar.gz", False, True)
    # Reconfirm activation of an accepted signed snapshot (no host restart).
    stage("signed_allow_reactivated", "allow.tar.gz", True)
    stage("signed_deny_reactivated", "deny.tar.gz", False)
    report["status"] = "PASS_SYNTHETIC_SIGNED_SNAPSHOT_ACTIVATION"
except Exception as e:
    report["status"] = "FAIL"
    report["failure"] = type(e).__name__ + ": " + str(e)[:450]
finally:
    report["elapsed_seconds"] = round(time.monotonic() - START, 3)
    (OUT / "result.json").write_text(json.dumps(report, indent=2,sort_keys=True)+"\n")
    print(json.dumps(report, indent=2,sort_keys=True))
sys.exit(0 if report["status"].startswith("PASS") else 1)
