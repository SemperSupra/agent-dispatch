#!/usr/bin/env python3
"""Synthetic, HTTP-level authz comparison; pure stdlib, no private data.

All platforms use the same principal/resource/operation and initial permit,
wrong-principal deny, subsequent revocation. In OPAL, checks run against the
inline OPA engine; this DOES NOT benchmark Git -> OPAL policy propagation.
"""
import concurrent.futures
import json
import os
import platform
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ENG = sys.argv[1]
ROOT = Path(__file__).resolve().parent
OUT = Path(os.environ.get("RDTE_RESULT", "result.json"))
SAMPLES = int(os.environ.get("RDTE_SAMPLES", "160"))
URLS = {"opa": "http://127.0.0.1:8181", "opal": "http://127.0.0.1:8181",
        "openfga": "http://127.0.0.1:8080", "spicedb": "http://127.0.0.1:8443",
        "casbin": "http://127.0.0.1:8090"}
ROOT_URL = URLS[ENG]
FGA_ID = None
FGA_MODEL = None
SPICE_KEY = "synthetic-test-only-no-privilege"
ALLOW = {"principal": "worker-a", "resource": "workset-a", "action": "observe"}
DENY = {"principal": "worker-b", "resource": "workset-a", "action": "observe"}
record = {"schema_version": 1, "status": "INCOMPLETE", "engine": ENG,
          "architecture": platform.machine(), "runner_os": platform.platform(),
          "samples": SAMPLES, "method": "urllib HTTP request/response, new connection per decision",
          "synthetic_only": True, "persistent_data": False,
          "policy_git_distribution_qualified": False,
          "service_topology": {"opal": ["postgres", "opal-server", "opal-client-with-inline-opa"],
                               "openfga": ["openfga-memory"], "spicedb": ["spicedb-memory"],
                               "opa": ["opa-memory"], "casbin": ["casbin-go-http-adapter"]}[ENG]}

def req(method, path, payload=None, headers=None):
    body = None
    hdr = {"Accept": "application/json"}
    if isinstance(payload, (dict, list)):
        body = json.dumps(payload, separators=(",", ":")).encode()
        hdr["Content-Type"] = "application/json"
    elif payload is not None:
        body = payload if isinstance(payload, bytes) else payload.encode()
        hdr["Content-Type"] = "text/plain"
    if headers:
        hdr.update(headers)
    q = urllib.request.Request(ROOT_URL + path, data=body, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(q, timeout=7) as r:
            raw = r.read(2 * 1024 * 1024)
            if not raw:
                return {}
            try:
                return json.loads(raw)
            except ValueError:
                return {"text": raw.decode(errors="replace")[:500]}
    except urllib.error.HTTPError as e:
        raise RuntimeError("%s %s HTTP %s %s" % (method, path, e.code, e.read(500))) from e

def wait_ready():
    probes = {"opa": "/health", "opal": "/health", "openfga": "/healthz",
              "spicedb": "/openapi.json", "casbin": "/healthz"}
    deadline = time.monotonic() + 150
    started = time.monotonic()
    last = ""
    while time.monotonic() < deadline:
        try:
            req("GET", probes[ENG])
            return round((time.monotonic() - started)*1000, 2)
        except Exception as e:
            last = str(e)[:400]
            time.sleep(1)
    raise RuntimeError("readiness timeout after 150s; last=" + last)

def initialize():
    global FGA_ID, FGA_MODEL
    if ENG in ("opa", "opal"):
        policy = (ROOT / "fixtures" / "policy.rego").read_text()
        req("PUT", "/v1/policies/authz", policy)
    elif ENG == "openfga":
        FGA_ID = req("POST", "/stores", {"name": "synthetic-policy-rdte"})["id"]
        model = {"schema_version": "1.1", "type_definitions": [
            {"type": "user"},
            {"type": "document", "relations": {"viewer": {"this": {}}},
             "metadata": {"relations": {"viewer": {"directly_related_user_types": [{"type": "user"}]}}}}
        ]}
        FGA_MODEL = req("POST", f"/stores/{FGA_ID}/authorization-models", model)["authorization_model_id"]
        req("POST", f"/stores/{FGA_ID}/write", {
            "writes": {"tuple_keys": [{"user": "user:worker-a", "relation": "viewer", "object": "document:workset-a"}]},
            "authorization_model_id": FGA_MODEL
        })
    elif ENG == "spicedb":
        heads = {"Authorization": "Bearer " + SPICE_KEY}
        req("POST", "/v1/schema/write", {"schema": "definition user {}\ndefinition document {\n relation viewer: user\n permission view = viewer\n}"}, heads)
        req("POST", "/v1/relationships/write", {"updates": [{
            "operation": "OPERATION_TOUCH",
            "relationship": {
                "resource": {"objectType": "document", "objectId": "workset-a"},
                "relation": "viewer",
                "subject": {"object": {"objectType": "user", "objectId": "worker-a"}}
            }
        }]}, heads)

def check(q):
    if ENG in ("opa", "opal"):
        return bool(req("POST", "/v1/data/authz/allow", {"input": q}).get("result", False))
    if ENG == "casbin":
        return bool(req("POST", "/v1/check", q)["result"])
    if ENG == "openfga":
        response = req("POST", f"/stores/{FGA_ID}/check", {
            "tuple_key": {"user": "user:" + q["principal"],
                          "relation": "viewer", "object": "document:" + q["resource"]},
            "authorization_model_id": FGA_MODEL
        })
        return bool(response["allowed"])
    heads = {"Authorization": "Bearer " + SPICE_KEY}
    return req("POST", "/v1/permissions/check", {
        "consistency": {"fullyConsistent": True},
        "resource": {"objectType": "document", "objectId": q["resource"]},
        "permission": "view",
        "subject": {"object": {"objectType": "user", "objectId": q["principal"]}}
    }, heads).get("permissionship") == "PERMISSIONSHIP_HAS_PERMISSION"

def revoke():
    if ENG in ("opa", "opal"):
        req("PUT", "/v1/policies/authz", "package authz\nimport rego.v1\ndefault allow := false\n")
    elif ENG == "casbin":
        req("POST", "/v1/revoke", {})
    elif ENG == "openfga":
        req("POST", f"/stores/{FGA_ID}/write", {"deletes": {"tuple_keys": [
            {"user": "user:worker-a", "relation": "viewer", "object": "document:workset-a"}
        ]}, "authorization_model_id": FGA_MODEL})
    else:
        req("POST", "/v1/relationships/write", {"updates": [{
            "operation": "OPERATION_DELETE",
            "relationship": {"resource": {"objectType": "document", "objectId": "workset-a"},
                             "relation": "viewer",
                             "subject": {"object": {"objectType": "user", "objectId": "worker-a"}}}
        }]}, {"Authorization": "Bearer " + SPICE_KEY})

def distribution(values):
    ordered = sorted(values)
    return {
        "count": len(values),
        "p50_ms": round(ordered[len(ordered)//2], 3),
        "p95_ms": round(ordered[min(len(ordered)-1,int(len(ordered)*0.95))], 3),
        "p99_ms": round(ordered[min(len(ordered)-1,int(len(ordered)*0.99))], 3),
        "mean_ms": round(statistics.mean(values), 3),
        "max_ms": round(max(values), 3)
    }

try:
    record["readiness_wait_ms"] = wait_ready()
    started = time.monotonic()
    initialize()
    record["model_setup_ms"] = round((time.monotonic()-started)*1000, 2)
    if check(ALLOW) is not True or check(DENY) is not False:
        raise RuntimeError("positive/negative semantic test failed")
    for _ in range(12):
        if check(ALLOW) is not True:
            raise RuntimeError("warmup unexpectedly denied")
    timings = []
    start = time.monotonic()
    for i in range(SAMPLES):
        q = ALLOW if i%2 == 0 else DENY
        before = time.perf_counter_ns()
        allowed = check(q)
        timings.append((time.perf_counter_ns()-before)/1e6)
        if allowed != (i%2==0):
            raise RuntimeError("authorization mismatch at sample %d" % i)
    record["serial"] = distribution(timings)
    record["serial_rps"] = round(SAMPLES/(time.monotonic()-start),2)
    def concurrent_case(i):
        q = ALLOW if i % 2 == 0 else DENY
        began = time.perf_counter_ns()
        answer = check(q)
        return answer == (i % 2 == 0), (time.perf_counter_ns()-began)/1e6
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(concurrent_case, range(SAMPLES)))
    if not all(ok for ok, _ in results):
        raise RuntimeError("concurrent semantic mismatch")
    record["concurrent_8"] = distribution([v for _,v in results])
    record["concurrent_rps"] = round(SAMPLES/(time.monotonic()-start), 2)
    start = time.monotonic()
    revoke()
    for _ in range(15):
        if not check(ALLOW):
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("revocation did not take effect")
    record["revocation_verified_ms"] = round((time.monotonic()-start)*1000,2)
    record["status"] = "PASS"
except Exception as e:
    record["status"] = "FAIL"
    record["failure"] = f"{type(e).__name__}: {str(e)[:700]}"
finally:
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(record,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(record,indent=2,sort_keys=True))
sys.exit(0 if record["status"] == "PASS" else 1)
