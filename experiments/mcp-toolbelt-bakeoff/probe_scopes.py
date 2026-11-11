#!/usr/bin/env python3
"""Actual scope boundary test: each synthetic caller sees only an admitted server."""
import json, urllib.request, urllib.error, pathlib,sys
BASE="http://127.0.0.1:3300/mcp"
tokens=json.loads(pathlib.Path("ephemeral-scope-tokens.json").read_text())
results=[]
def request(token,url,method,index):
  data={"jsonrpc":"2.0","id":index,"method":method}
  if method=="initialize":
    data["params"]={"protocolVersion":"2025-06-18","capabilities":{},
                    "clientInfo":{"name":"bounded-scope-test","version":"1.0"}}
  req=urllib.request.Request(url,data=json.dumps(data).encode(),
      headers={"Authorization":"Bearer "+token,"Content-Type":"application/json",
               "Accept":"application/json, text/event-stream","MCP-Protocol-Version":"2025-06-18"})
  try:
    with urllib.request.urlopen(req,timeout=15) as r:
      payload=json.loads(r.read(65000))
      return r.status, payload
  except urllib.error.HTTPError as e:
    return e.code,{"error":e.read(500).decode(errors="replace")}
for name in ("alpha","beta"):
  t=tokens[name]
  status,init=request(t,BASE+"/"+name,"initialize",1)
  tools_status,listing=request(t,BASE+"/"+name,"tools/list",2)
  tools=[v.get("name","") for v in listing.get("result",{}).get("tools",[])]
  cross_status,_=request(t,BASE+"/"+("beta" if name=="alpha" else "alpha"),"tools/list",3)
  global_status,_=request(t,BASE,"tools/list",4)
  passed=(status==200 and tools_status==200 and len(tools)==1 and
          all(name in x for x in tools) and cross_status in (401,403) and
          global_status in (401,403))
  results.append({"principal":name,"own_status":status,"own_list_status":tools_status,
                  "own_tools":tools,"cross_status":cross_status,
                  "global_status":global_status,"passed":passed})
receipt={"schema":"public-safe-mcphub-principal-scope-v1",
         "passed":all(x["passed"] for x in results),"results":results,
         "limitations":["Synthetic bearer scopes on server-specific endpoint only",
          "No OAuth, interactive belt switching, cross-provider session or audit durability tested"]}
pathlib.Path("scope-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
print(json.dumps(receipt,indent=2))
sys.exit(0 if receipt["passed"] else 1)
