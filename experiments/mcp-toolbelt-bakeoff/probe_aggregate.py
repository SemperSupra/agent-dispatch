#!/usr/bin/env python3
"""Probe real MCP gateway merging duplicate-named synthetic upstream tools.

The fixture uses public, read-only echo operations only. It does not qualify AAA.
"""
import json,sys,time,urllib.request,urllib.error,os
URL=os.environ.get("MCP_PROBE_URL","http://127.0.0.1:39200/mcp")
TOKEN=os.environ.get("MCP_PROBE_TOKEN")
SESSION=None
def rpc(i,method,params=None):
    global SESSION
    msg={"jsonrpc":"2.0","id":i,"method":method}
    if params is not None:msg["params"]=params
    headers={"Content-Type":"application/json",
             "Accept":"application/json, text/event-stream",
             "MCP-Protocol-Version":"2025-06-18"}
    if SESSION: headers["Mcp-Session-Id"]=SESSION
    if TOKEN: headers["Authorization"]="Bearer "+TOKEN
    req=urllib.request.Request(URL,data=json.dumps(msg).encode(),headers=headers)
    try:
        r=urllib.request.urlopen(req,timeout=15)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} for {method}: {e.read(4096).decode(errors='replace')}") from e
    with r:
        SESSION=r.headers.get("Mcp-Session-Id") or SESSION
        body=r.read(100000).decode()
        if "text/event-stream" in r.headers.get("Content-Type",""):
            events=[line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
            if not events:raise ValueError("empty SSE: "+body[:400])
            return json.loads(events[-1])
        return json.loads(body)
receipt={"schema":"public-safe-actual-mcp-fanout-v1","target":os.environ.get("MCP_PROBE_TARGET","agentgateway-v1.7.0"),
         "results":[],"passed":False}
try:
    init=rpc(1,"initialize",{"protocolVersion":"2025-06-18",
               "capabilities":{},"clientInfo":{"name":"public-safe-bakeoff","version":"1.0"}})
    receipt["results"].append({"stage":"initialize","result":init})
    time.sleep(0.2)
    retries=int(os.environ.get("MCP_PROBE_DISCOVERY_RETRIES","1"))
    for attempt in range(retries):
        tools=rpc(2+attempt,"tools/list")
        names=[str(t.get("name")) for t in tools.get("result",{}).get("tools",[])]
        if len(names)>=2:break
        if attempt+1<retries:time.sleep(2)
    receipt["results"].append({"stage":"tools/list","attempts":attempt+1,"result":tools})
    if len(names)<2 or len(set(names))!=len(names):raise ValueError("tool aggregation/namespacing failed: "+str(names))
    sources=set()
    for i,name in enumerate(names,1000):
        reply=rpc(i,"tools/call",{"name":name,"arguments":{"text":"qualification"}})
        receipt["results"].append({"stage":"tools/call","tool":name,"result":reply})
        text=json.dumps(reply)
        if "alpha:qualification" in text:sources.add("alpha")
        if "beta:qualification" in text:sources.add("beta")
    if sources!={"alpha","beta"}:raise ValueError("missing provenance for "+str(sources))
    receipt["passed"]=True
except Exception as e:
    receipt["error"]=repr(e)
with open("functional-receipt.json","w") as f:json.dump(receipt,f,indent=2,sort_keys=True)
print(json.dumps(receipt,indent=2))
sys.exit(0 if receipt["passed"] else 1)
