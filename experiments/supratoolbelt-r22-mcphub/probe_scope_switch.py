#!/usr/bin/env python3
"""Real MCPHub group-scope/selection isolation with disposable synthetic principals.
No real OAuth, native workset authority, durable audit, or user identities.
"""
import json,pathlib,sys,time,urllib.request,urllib.error
sys.path.insert(0,"mcphub-harness/experiments/mcp-toolbelt-bakeoff")
from probe_group_crud import api
BASE="http://127.0.0.1:3300"
ROOT=pathlib.Path(".")
tokens=json.loads((ROOT/"synthetic-scope-tokens.json").read_text())
receipt={"schema":"m1-r22-mcphub-live-group-scope-v1","checks":[],"passed":False,
 "candidate":"samanhappy/mcphub@sha256:a6fb457b1218948cc79c9865baa5fa0c7f689f5af50a2369eea249cf5dd508cf",
 "limitations":["synthetic system bearer scopes not OIDC end-user attribution",
                "admin-managed group mutation; end user is not group manager",
                "config file mode and no durable audit, no external clients or workset enforcement"]}
sessions={}
def check(name,ok,detail=None):
 receipt["checks"].append({"name":name,"passed":bool(ok),"detail":detail})
 if not ok:raise AssertionError(name+" "+str(detail)[:180])
def rpc(principal,group,method,i,params=None):
 t=tokens[principal]
 route="/mcp"+("/"+group if group else "")
 h={"Content-Type":"application/json","Accept":"application/json, text/event-stream",
    "MCP-Protocol-Version":"2025-06-18","Authorization":"Bearer "+t}
 key=(principal,route)
 if key in sessions:h["Mcp-Session-Id"]=sessions[key]
 payload={"jsonrpc":"2.0","id":i,"method":method}
 if params is not None:payload["params"]=params
 req=urllib.request.Request(BASE+route,data=json.dumps(payload).encode(),headers=h)
 try:
  with urllib.request.urlopen(req,timeout=15) as r:
   s=r.headers.get("Mcp-Session-Id")
   if s:sessions[key]=s
   raw=r.read(65536).decode()
   if "text/event-stream" in r.headers.get("Content-Type",""):
    events=[v[5:].strip() for v in raw.splitlines() if v.startswith("data:")]
    raw=events[-1] if events else "{}"
   return r.status,json.loads(raw or "{}")
 except urllib.error.HTTPError as e:return e.code,{"error":e.read(500).decode(errors="replace")}
def init(principal,group):
 return rpc(principal,group,"initialize",1,{"protocolVersion":"2025-06-18",
     "capabilities":{},"clientInfo":{"name":"synthetic-"+principal,"version":"1"}})
def listings(principal,group):
 status,result=rpc(principal,group,"tools/list",2)
 return status,sorted(x["name"] for x in result.get("result",{}).get("tools",[]))
def call(principal,group,name,marker):
 status,out=rpc(principal,group,"tools/call",3,
               {"name":name,"arguments":{"text":marker}})
 return status,json.dumps(out)
def own(principal,group,service):
 status,tools=listings(principal,group)
 check(principal+"-discover-"+group,status==200 and len(tools)==1 and
       tools[0].startswith(service+"-"),{"status":status,"tools":tools})
 status,out=call(principal,group,tools[0],principal+"-proof")
 check(principal+"-invoke-"+group,status==200 and service+":"+principal+"-proof" in out,
       {"status":status})
 return tools[0]
def denied(principal,group):
 status,res=rpc(principal,group,"tools/list",27)
 return status in (401,403)
try:
 password=pathlib.Path("synthetic-admin-password.txt").read_text().strip()
 status,res=api("POST","/api/auth/login",{"username":"admin","password":password})
 jwt=res.get("token")
 check("admin-auth",status==200 and bool(jwt),{"http":status})
 for group,upstream in (("alice","alpha"),("bob","beta")):
  s,r=api("POST","/api/groups",{"name":group,"servers":[upstream]},jwt)
  check("created-"+group,s in (200,201) and r.get("success") is True,{"http":s})
 s,r=api("GET","/api/groups",token=jwt)
 groupids={v.get("name"):v.get("id") for v in r.get("data",[])}
 check("saved-groups",s==200 and groupids.get("alice") and groupids.get("bob"))
 for p,g in (("alice","alice"),("bob","bob")):
  status,result=init(p,g)
  check(p+"-initialized",status==200 and "result" in result,{"http":status})
 alpha_name=own("alice","alice","alpha")
 bob_name=own("bob","bob","beta")
 check("alice-cross-group-denied",denied("alice","bob"))
 check("bob-cross-group-denied",denied("bob","alice"))
 for who in ("alice","bob"):
  check(who+"-global-denied",denied(who,""))
  check(who+"-direct-server-denied",denied(who,"alpha"))
 # Critical: privileged ADMIN group mutation is global; while alice's scoped
 # session remains alive, only her group changes from alpha->beta.
 s,r=api("PUT","/api/groups/"+str(groupids["alice"]),{"servers":["beta"]},jwt)
 check("admin-update-alice-belt",s==200 and r.get("success") is True,{"http":s})
 switched=False
 last=None
 for _ in range(30):
  status,tools=listings("alice","alice")
  last={"http":status,"tools":tools}
  if status==200 and len(tools)==1 and tools[0].startswith("beta-"):
   switched=True;break
  time.sleep(.4)
 check("same-session-list-updated",switched,last)
 # Reusing the same MCP session: old alpha tool must not route to upstream.
 status,out=call("alice","alice",alpha_name,"obsolete-access")
 check("stale-tool-direct-invoke-denied","alpha:obsolete-access" not in out,
       {"http":status})
 own("alice","alice","beta")
 own("bob","bob","beta")
 check("alice-remains-isolated",denied("alice","bob"))
 check("bob-remains-isolated",denied("bob","alice"))
 receipt["passed"]=all(x["passed"] for x in receipt["checks"])
except Exception as e:receipt["error"]=repr(e)[:500]
pathlib.Path("m1-r22-scope-switch-receipt.json").write_text(
 json.dumps(receipt,indent=2,sort_keys=True)+"\n")
print(json.dumps(receipt,indent=2,sort_keys=True))
sys.exit(0 if receipt["passed"] else 1)
