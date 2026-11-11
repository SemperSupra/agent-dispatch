#!/usr/bin/env python3
"""U1: actual Open WebUI admin-managed MCP fixture and native tool discovery.

All identities, source services, and results are synthetic. No LLM provider or
private endpoint and no admission to production is exercised. NEVER print JWTs.
"""
import json,pathlib,secrets,sys,urllib.error,urllib.request,time

HOST="http://127.0.0.1:33080"
ADMIN_EMAIL="rdte-admin@example.com"
TARGET="http://supra-mcp-fixture:39101/mcp"

def request(method,path,body=None,token=None):
    headers={"Accept":"application/json","Content-Type":"application/json"}
    if token: headers["Authorization"]="Bearer "+token
    req=urllib.request.Request(
        HOST+path, method=method, headers=headers,
        data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req,timeout=25) as response:
            raw=response.read(200000).decode()
            return response.status,json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw=e.read(800).decode(errors="replace")
        try: result=json.loads(raw)
        except Exception: result={"error":raw[:160]}
        return e.code,result

def run():
    receipt={"schema":"m1-openwebui-native-mcp-u1-v1",
             "checks":[],"passed":False,"noModelCalls":True,
             "limitations":["one synthetic administrator, not U2 cross-user isolation",
                            "2025 synthetic MCP fixture, no real OAuth",
                            "WebUI rootful Docker synthetic runtime; rootless proven separately",
                            "no model-driven tool execution"]}
    def check(name,success,status=None,details=None):
        receipt["checks"].append({"name":name,"passed":bool(success),
                                  "status":status,"details":details})
        if not success:raise AssertionError(name+":"+str(status)+":"+str(details)[:250])
    try:
        status,anon=request("GET","/api/v1/configs/tool_servers")
        check("anonymous-admin-config-denied",status in (401,403),status)
        status,anon=request("GET","/api/v1/tools/id/server:mcp:supra-fixture/specs")
        check("anonymous-tool-discovery-denied",status in (401,403),status)
        password=secrets.token_urlsafe(28)+"!1aB"
        status,data=request("POST","/api/v1/auths/signup",
                            {"name":"Synthetic RDTE Admin","email":ADMIN_EMAIL,"password":password})
        token=data.get("token")
        check("initial-admin-created",status==200 and isinstance(token,str) and len(token)>20,status)
        connection={"url":TARGET,"path":"/mcp","type":"mcp",
          "auth_type":"none","headers":{},"key":"",
          "config":{},"info":{"id":"supra-fixture","name":"SupraToolbelt Synthetic",
          "description":"Synthetic five-tool MCP fixture only"}}
        status,data=request("POST","/api/v1/configs/tool_servers",
                            {"TOOL_SERVER_CONNECTIONS":[connection]},token)
        entries=data.get("TOOL_SERVER_CONNECTIONS",[])
        check("authenticated-admin-mcp-registration",status==200 and len(entries)==1,status)
        status,data=request("GET","/api/v1/configs/tool_servers",token=token)
        entries=data.get("TOOL_SERVER_CONNECTIONS",[])
        check("registered-server-readback",status==200 and len(entries)==1 and
              entries[0].get("type")=="mcp" and
              (entries[0].get("info") or {}).get("id")=="supra-fixture",status)
        # The actual WebUI native MCP connector and spec converter must fetch 5 tools.
        successful=False
        for attempt in range(1,7):
            status,data=request("GET","/api/v1/tools/id/server:mcp:supra-fixture/specs",token=token)
            specs=data.get("specs",[])
            names=sorted(x.get("name") for x in specs)
            if status==200 and len(names)==5 and set(names)=={"search","read","observe","write","admin"}:
                successful=True;break
            time.sleep(2)
        check("native-mcp-discovery-five-tools",successful,status,{"names":names if status==200 else [],"attempts":attempt})
        status,data=request("GET","/api/v1/tools/",token=token)
        visible={x.get("id") for x in data} if isinstance(data,list) else set()
        check("admin-catalog-visible",status==200 and
              "server:mcp:supra-fixture" in visible,status,{"toolServerFound":"server:mcp:supra-fixture" in visible})
        receipt["passed"]=all(x["passed"] for x in receipt["checks"]) and len(receipt["checks"])==7
    except Exception as e:receipt["failure"]=repr(e)[:550]
    pathlib.Path("openwebui-u1-receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["passed"] else 1
if __name__=="__main__":sys.exit(run())
