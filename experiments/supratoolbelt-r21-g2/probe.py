#!/usr/bin/env python3
"""Gate G2 public synthetic real gateway + downstream admission fail-closed checks."""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path("jwt-harness/experiments/mcp-jwt-authz").absolute()))
from fixture import call, permitted

ROOT = pathlib.Path("runtime-g2")
OUT = pathlib.Path("runtime-receipts")
INIT = {"protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "m1-g2-adversarial", "version": "1"}}


def count(path):
    try:
        return int(path.read_text())
    except (ValueError, OSError):
        return 0


def events():
    try:
        return len((ROOT / "audit.ndjson").read_text().splitlines())
    except OSError:
        return 0


def state(grant=True, workset=True, malformed=False):
    path = ROOT / "state-alpha.json"
    scratch = ROOT / "state-alpha.pending"
    scratch.write_text("{malformed" if malformed else json.dumps(
        {"grant": grant, "workset_admitted": workset}))
    scratch.replace(path)


def main(phase):
    receipt = {"schema": "m1-g2-joined-synthetic-v1", "phase": phase,
               "scope": "real Agentgateway; mocked downstream current-grant/workset provider and separate same-runner fsync audit process",
               "limitations": ["NOT native Agent Dispatch/WOW workset integration",
                   "NOT live issuer or real OAuth", "NOT independently durable off-node audit",
                   "NOT gateway discovery revocation; upstream invoke-time only",
                   "NOT a replacement for Gate Z or G2 production acceptance"],
               "checks": [], "passed": False}
    def check(name, actual):
        ok = bool(actual)
        receipt["checks"].append({"name": name, "passed": ok})
        if not ok:
            raise AssertionError(name)

    def invoke(token, session, name, payload):
        return call("tools/call", 3, token, session,
                    {"name": name, "arguments": {"text": payload}})

    try:
        tok = (OUT / "old-research.jwt").read_text()
        status, body, session = call("initialize", 1, tok, params=INIT)
        check("signed-research-context-valid", status == 200 and "result" in body)
        check("fixture-initial-zero-or-known", count(ROOT / "effects-alpha.txt") in (0, 2))
        if phase == "baseline":
            status, body, session = invoke(tok, session, "alpha_echo", "first")
            check("allowed-grant-workset-audit-invoke", permitted(status, body, "alpha:first"))
            check("first-side-effect-committed", count(ROOT / "effects-alpha.txt") == 1)
            state(grant=False)
            status, body, session = invoke(tok, session, "alpha_echo", "revoked")
            check("live-grant-revoke-denied-on-unexpired-token",
                  status == 200 and body.get("result", {}).get("isError") is True)
            check("revoke-no-side-effect", count(ROOT / "effects-alpha.txt") == 1)
            state(workset=False)
            status, body, session = invoke(tok, session, "alpha_echo", "workset-deny")
            check("native-workset-mock-denied", status == 200 and body.get("result", {}).get("isError") is True)
            check("workset-deny-no-side-effect", count(ROOT / "effects-alpha.txt") == 1)
            state(malformed=True)
            status, body, session = invoke(tok, session, "alpha_echo", "corrupt")
            check("corrupt-policy-denied", status == 200 and body.get("result", {}).get("isError") is True)
            check("corrupt-policy-no-side-effect", count(ROOT / "effects-alpha.txt") == 1)
            state()
            status, body, session = invoke(tok, session, "alpha_echo", "restored")
            check("restored-current-grants-allowed", permitted(status, body, "alpha:restored"))
            check("restored-side-effect", count(ROOT / "effects-alpha.txt") == 2)
            status, body, session = invoke(tok, session, "beta_echo", "cross")
            check("gateway-direct-cross-belt-denied", not permitted(status, body, "beta:cross"))
            check("cross-belt-never-mutated", count(ROOT / "effects-beta.txt") == 0)
            check("only-allowed-actions-audited", events() == 2)
        elif phase == "audit-outage":
            status, body, session = invoke(tok, session, "alpha_echo", "no-audit")
            check("real-audit-HTTP-outage-denied", status == 200 and body.get("result", {}).get("isError") is True)
            check("audit-outage-no-side-effect", count(ROOT / "effects-alpha.txt") == 2)
            check("audit-outage-no-new-receipt", events() == 2)
        elif phase == "audit-restored":
            status, body, session = invoke(tok, session, "alpha_echo", "audit-restored")
            check("separate-audit-restart-allows", permitted(status, body, "alpha:audit-restored"))
            check("side-effect-count-after-restart", count(ROOT / "effects-alpha.txt") == 3)
            check("audit-events-fsynced", events() == 3)
        receipt["passed"] = all(x["passed"] for x in receipt["checks"])
    except Exception as ex:
        receipt["error"] = repr(ex)[:500]
    OUT.mkdir(exist_ok=True)
    (OUT / ("g2-" + phase + ".json")).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("baseline", "audit-outage", "audit-restored"))
    args = parser.parse_args()
    sys.exit(main(args.phase))
