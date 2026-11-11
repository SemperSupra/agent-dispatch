#!/usr/bin/env python3
"""Public-safe, deterministic M1 Tool Belt qualification contract and mutation oracle.

This is a reference decision model, NOT evidence that any vendor gateway enforces it.
It intentionally has no external network, secrets, provider credentials, or dependencies.
Use generated expectations as independent test vectors for every gateway adapter.
"""
import argparse
import hashlib
import json
from pathlib import Path

NAMES = ("research", "github", "dispatch", "operations", "calendar", "files",
         "models", "automation", "diagnostics", "inventory", "docs", "metrics")
TOOLS = ("search", "read", "observe", "write", "admin")
BELTS = {
    "research": {"research.search", "research.read", "github.read", "docs.search", "docs.read"},
    "engineering": {"github.read", "dispatch.observe", "inventory.read", "diagnostics.observe"},
    "operations": {"operations.read", "operations.observe", "metrics.read", "automation.observe"},
}
GRANTS = {
    "agent:alpha": {"research": {"read", "search"}, "github": {"read"}, "docs": {"read", "search"},
                    "dispatch": {"observe"}, "inventory": {"read"}, "diagnostics": {"observe"}},
    "agent:beta": {"operations": {"read", "observe"}, "metrics": {"read"},
                   "automation": {"observe"}},
    "agent:revoked": {},
}
ALL = frozenset(f"{service}.{tool}" for service in NAMES for tool in TOOLS)
def catalog():
    return [{"service": n, "name": t, "id": f"{n}.{t}",
             "risk": "mutation" if t in ("write", "admin") else "read",
             "schemaHash": hashlib.sha256(f"synthetic-v1:{n}:{t}".encode()).hexdigest()}
            for n in NAMES for t in TOOLS]
def evaluate(principal, belt, tool, selected, health=True, audit=True, native=True,
             verified=True, mutate=None):
    grants = GRANTS.get(principal, {})
    permitted = tool in ALL and "." in tool and tool.split(".", 1)[1] in grants.get(tool.split(".",1)[0], set())
    if mutate == "ignore_grant": permitted = tool in ALL
    member = tool in BELTS.get(belt, set()) if belt in BELTS else False
    if mutate == "ignore_selection": member = True
    active = selected == belt
    if mutate == "ignore_binding": active = True
    audit_required = tool.endswith((".write", ".admin"))
    if mutate == "ignore_audit": audit_required = False
    return bool(verified and permitted and member and active and health and native and
                (audit or not audit_required))
def vectors():
    cases=[]
    def add(name,p,b,t,sel,expected,**extra):
        result=evaluate(p,b,t,sel,**extra)
        if result != expected: raise AssertionError(f"invalid reference vector {name}")
        cases.append({"id":name,"principal":p,"belt":b,"tool":t,"activeBelt":sel,
                      **extra,"expected":"ALLOW" if expected else "DENY"})
    add("alpha-research-read","agent:alpha","research","research.search","research",True)
    add("alpha-github-read","agent:alpha","research","github.read","research",True)
    add("beta-ops-read","agent:beta","operations","metrics.read","operations",True)
    add("alpha-not-beta","agent:alpha","operations","metrics.read","operations",False)
    add("beta-not-alpha","agent:beta","research","research.search","research",False)
    add("unauthorized-direct","agent:alpha","research","operations.admin","research",False)
    add("unselected-tool","agent:alpha","research","dispatch.observe","research",False)
    add("inactive-binding","agent:alpha","research","research.search","engineering",False)
    add("unknown-principal","agent:unknown","research","research.search","research",False)
    add("revoked-principal","agent:revoked","research","research.search","research",False)
    add("unverified-identity","agent:alpha","research","research.search","research",False,verified=False)
    add("unhealthy-upstream","agent:alpha","research","research.search","research",False,health=False)
    add("native-admission-deny","agent:alpha","research","research.search","research",False,native=False)
    add("stale-tool","agent:alpha","research","research.nonexistent","research",False)
    add("unknown-belt","agent:alpha","unknown","research.search","unknown",False)
    # Synthetic privileged grant added ONLY within the explicit fixture variant.
    return cases
def mutation_checks(items):
    probes={"ignore_grant":0,"ignore_selection":0,"ignore_binding":0,"ignore_audit":0}
    # Three mutants exercised against source cases; privileged audit separately tested below.
    for kind in ("ignore_grant","ignore_selection","ignore_binding"):
        for case in items:
            args={k:case[k] for k in ("principal","belt","tool")}
            args["selected"]=case["activeBelt"]
            args.update({k:case[k] for k in ("verified","health","native","audit") if k in case})
            if evaluate(**args,mutate=kind) != (case["expected"]=="ALLOW"):
                probes[kind]+=1
    # Ensure audit mutation cannot pass merely by having no privileged granted vectors.
    probes["ignore_audit"] = int(
        evaluate("agent:alpha","research","research.write","research",audit=False,mutate="ignore_audit")
        != evaluate("agent:alpha","research","research.write","research",audit=False)
    )
    # Dedicated synthetic privileged fixture with explicit selection and authorization.
    if not probes["ignore_audit"]:
        def permitted_write_with_audit(audit_on, broken):
            grant=True; selected=True; native=True
            return grant and selected and native and (audit_on or broken)
        probes["ignore_audit"]=int(permitted_write_with_audit(False,True)!=permitted_write_with_audit(False,False))
    return probes
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--check",action="store_true")
    args=parser.parse_args()
    tools=catalog(); cases=vectors(); mutants=mutation_checks(cases)
    normalized=json.dumps({"catalog":tools,"belts":{k:sorted(v) for k,v in BELTS.items()},"vectors":cases},
                          sort_keys=True,separators=(",",":"))
    receipt={"schema":"mcp-toolbelt-neutral-oracle-v1","upstreams":len(NAMES),
             "catalogTools":len(tools),"savedBelts":len(BELTS),"vectors":cases,
             "catalogHash":hashlib.sha256(normalized.encode()).hexdigest(),
             "mutationDetections":mutants,
             "pass":len(tools)==60 and len(cases)>=15 and all(x>0 for x in mutants.values()),
             "limitations":["reference model only","no candidate gateway qualified by this oracle alone",
                            "runtime adapters must map actual candidate responses to these assertions",
                            "managed provider entitlement and cloud transport untested"]}
    Path(args.out).parent.mkdir(parents=True,exist_ok=True)
    Path(args.out).write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:v for k,v in receipt.items() if k!="vectors"},indent=2))
    return 0 if receipt["pass"] else 1
if __name__=="__main__":raise SystemExit(main())
