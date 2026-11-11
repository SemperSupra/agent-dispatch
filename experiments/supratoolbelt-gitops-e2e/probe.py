#!/usr/bin/env python3
"""Synthetic end-to-end Git snapshot -> signed context -> real gateway -> tools.

Pure-RDTE acceptance: externally validated Go manifest digests are bound into
JWT claims and target-aware CEL. Replacing the static gateway snapshot rejects
old claims without storing server-side active-login state. NOT a real issuer or
native workset authorization/audit system.
"""
import argparse,json,pathlib,sys,time
from urllib.error import HTTPError

sys.path.insert(0,str(pathlib.Path("jwt-harness/experiments/mcp-jwt-authz").absolute()))
import make_issuer
from fixture import call,permitted

ROOT=pathlib.Path("runtime-receipts")
ROOT.mkdir(exist_ok=True)

def read(profile):
    manifest=json.loads((ROOT/f"{profile}.json").read_text())
    rec=json.loads((ROOT/f"{profile}-digest.json").read_text())
    digest=rec["snapshotDigest"]
    assert len(digest)==64 and rec["beltCount"]==2
    return manifest,digest

def token(belt,digest):
    now=int(time.time())
    return make_issuer.sign({"iss":"https://issuer.invalid/m1",
       "aud":"m1-synthetic-client","sub":"alpha","client_id":"synthetic-"+belt,
       "belt":belt,"snapshot":digest,"iat":now,"exp":now+600})

def prepare(profile):
    m,digest=read(profile)
    mapping={name:obj["tools"][0].split("_")[0] for name,obj in m["belts"].items()}
    assert set(mapping)=={"research","engineering"} and set(mapping.values())=={"alpha","beta"}
    for belt in mapping:
        file=ROOT/f"{profile}-{belt}.jwt"
        file.write_text(token(belt,digest));file.chmod(0o600)
    lines=[
      "binds:",
      "- port: 39200",
      "  listeners:",
      "  - routes:",
      "    - matches:",
      "      - path:",
      "          exact: /mcp",
      "      policies:",
      "        mcpAuthentication:",
      "          mode: strict",
      "          issuer: https://issuer.invalid/m1",
      "          audiences: [m1-synthetic-client]",
      "          jwks:",
      "            file: /keys/jwks.json",
      "          resourceMetadata:",
      "            resource: http://127.0.0.1:39200/mcp",
      "            scopesSupported: [read:all]",
      "            bearerMethodsSupported: [header]",
      "        mcpAuthorization:",
      "          rules:",
      f"          - 'jwt.sub == \"alpha\" && jwt.snapshot == \"{digest}\" && mcp.tool.name == \"echo\"'",
      "      backends:",
      "      - mcp:",
      "          targets:"
    ]
    for service,port in (("alpha",39101),("beta",39102)):
        belt=next(b for b,v in mapping.items() if v==service)
        lines.extend([f"          - name: {service}",
                      f"            condition: 'jwt.belt == \"{belt}\"'",
                      "            mcp:",
                      f"              host: http://127.0.0.1:{port}/mcp"])
    (ROOT/f"{profile}-config.yaml").write_text("\n".join(lines)+"\n")
    print(json.dumps({"profile":profile,"snapshot":digest,"validatedBeltMapping":mapping,
      "gatewayConfigWritten":True,"tokenContentsNotPrinted":True}))

def test(profile,previous=None):
    m,digest=read(profile)
    receipt={"schema":"m1-gitops-signed-belt-gateway-e2e-v1","profile":profile,
             "snapshotDigest":digest,"checks":[],"passed":False,
             "limits":["synthetic issuer, not live OAuth delegation",
              "static config reload, not live private-Git reconciler",
              "not native workset authorization, real-time grant revocation or durable audit"]}
    def check(name,ok,details=None):
        receipt["checks"].append({"name":name,"passed":bool(ok),"details":details})
        if not ok:raise AssertionError(name+":"+repr(details)[:200])
    init={"protocolVersion":"2025-06-18","capabilities":{},
          "clientInfo":{"name":"gitops-gateway-qualification","version":"1"}}
    try:
        for belt in ("research","engineering"):
            tok=(ROOT/f"{profile}-{belt}.jwt").read_text()
            expected=m["belts"][belt]["tools"][0]
            other="beta_echo" if expected=="alpha_echo" else "alpha_echo"
            status,body,sess=call("initialize",1,tok,params=init)
            check(profile+"-"+belt+"-jwt-accepted",status==200 and "result" in body,{"http":status})
            status,body,sess=call("tools/list",2,tok,sess)
            names=sorted(x["name"] for x in body.get("result",{}).get("tools",[]))
            check(profile+"-"+belt+"-list-pinned",status==200 and names==[expected],{"names":names})
            status,body,sess=call("tools/call",3,tok,sess,
                                 {"name":expected,"arguments":{"text":"pinned"}})
            check(profile+"-"+belt+"-own-invoke",permitted(status,body,expected.split("_")[0]+":pinned"),{"http":status})
            status,body,sess=call("tools/call",4,tok,sess,
                                 {"name":other,"arguments":{"text":"forbidden"}})
            check(profile+"-"+belt+"-direct-denied",
                  not permitted(status,body,other.split("_")[0]+":forbidden"),{"http":status})
        if previous:
            old,old_digest=read(previous)
            check("revision-really-changed",old_digest!=digest)
            for belt in ("research","engineering"):
                stale=(ROOT/f"{previous}-{belt}.jwt").read_text()
                status,body,sess=call("initialize",20,stale,params=init)
                check("stale-"+belt+"-signed-in",status==200,{"http":status})
                status,body,sess=call("tools/list",21,stale,sess)
                names=[x["name"] for x in body.get("result",{}).get("tools",[])]
                check("stale-"+belt+"-discovery-denied",status==200 and names==[],{"names":names})
                old_tool=old["belts"][belt]["tools"][0]
                status,body,sess=call("tools/call",22,stale,sess,
                  {"name":old_tool,"arguments":{"text":"must-deny"}})
                check("stale-"+belt+"-direct-invoke-denied",
                  not permitted(status,body,old_tool.split("_")[0]+":must-deny"),{"http":status})
        receipt["passed"]=all(x["passed"] for x in receipt["checks"]) and len(receipt["checks"])==(15 if previous else 8)
    except Exception as ex:receipt["failure"]=repr(ex)[:550]
    (ROOT/f"{profile}-e2e-receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["passed"] else 1

def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=["prepare","test"]);p.add_argument("profile",choices=["old","new"])
    p.add_argument("--previous",choices=["old","new"]);a=p.parse_args()
    if a.mode=="prepare":prepare(a.profile);return 0
    return test(a.profile,a.previous)
if __name__=="__main__":sys.exit(main())
