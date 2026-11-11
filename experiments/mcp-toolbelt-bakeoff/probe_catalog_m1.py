#!/usr/bin/env python3
"""Actual MCP 12x5 aggregation assertion against an ephemeral synthetic gateway."""
import hashlib,json,sys,os,urllib.request,urllib.error
from pathlib import Path
NAMES=("research","github","dispatch","operations","calendar","files","models","automation","diagnostics","inventory","docs","metrics")
TOOLS=("search","read","observe","write","admin")
URL=os.getenv("MCP_PROBE_URL","http://127.0.0.1:39200/mcp")
SEPARATOR=os.getenv("MCP_EXPECT_SEPARATOR","_")
TOKEN=os.getenv("MCP_PROBE_TOKEN")
session=None
def call(i,method,params=None):
    global session
    obj={"jsonrpc":"2.0","id":i,"method":method}
    if params is not None:obj["params"]=params
    headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream","MCP-Protocol-Version":"2025-06-18"}
    if session:headers["Mcp-Session-Id"]=session
    if TOKEN:headers["Authorization"]="Bearer "+TOKEN
    req=urllib.request.Request(URL,data=json.dumps(obj).encode(),headers=headers)
    with urllib.request.urlopen(req,timeout=20) as response:
        session=response.headers.get("Mcp-Session-Id") or session
        raw=response.read().decode()
        if "text/event-stream" in response.headers.get("Content-Type",""):
            raw=[x[5:] for x in raw.splitlines() if x.startswith("data:")][-1]
        return json.loads(raw)
def main():
    outcome={"schema":"mcp-m1-12x5-actual-routing-v1","gateway":os.getenv("MCP_GATEWAY","agentgateway-v1.7.0"),"expectedCount":60,
             "successCount":0,"distinctTools":0,"passed":False}
    try:
        init=call(1,"initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"m1-test","version":"1"}})
        if "error" in init:raise ValueError("initialization error")
        inventory=call(2,"tools/list")
        advertised={x["name"]:x for x in inventory["result"]["tools"]}
        expected={service+SEPARATOR+tool for service in NAMES for tool in TOOLS}
        outcome["distinctTools"]=len(advertised)
        outcome["advertisedToolHash"]=hashlib.sha256("\n".join(sorted(advertised)).encode()).hexdigest()
        if len(advertised)!=60 or set(advertised)!=expected:raise AssertionError("discovery mismatch")
        for i,name in enumerate(sorted(expected),10):
            reply=call(i,"tools/call",{"name":name,"arguments":{"text":"qualification"}})
            service,tool=name.rsplit(SEPARATOR,1)
            if reply.get("result",{}).get("isError") or service+":"+tool+":qualification" not in json.dumps(reply):
                raise AssertionError("wrong upstream/operation: "+name)
            outcome["successCount"]+=1
        outcome["passed"]=True
    except Exception as exc:
        outcome["error"]=str(exc)
    Path("m1-runtime-receipt.json").write_text(json.dumps(outcome,indent=2,sort_keys=True)+"\n")
    print(json.dumps(outcome,indent=2,sort_keys=True))
    return 0 if outcome["passed"] else 1
if __name__=="__main__":sys.exit(main())
