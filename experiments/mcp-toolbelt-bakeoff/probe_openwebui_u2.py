#!/usr/bin/env python3
"""Actual Open WebUI U2 multi-user MCP access control, with only synthetic actors.

No model, external credentials, private provider or live internal service.
This tests WebUI's access_grants as an additional UI boundary, NEVER as a
substitute for backend SupraToolbelt/native workset authorization.
"""
import json,pathlib,secrets,sys
from probe_openwebui_u1 import request,ADMIN_EMAIL

def run():
    out={"schema":"m1-openwebui-native-mcp-u2-v1","passed":False,
         "checks":[],"modelCalls":0,"principalCount":3,
         "limitations":["synthetic WebUI accounts and two synthetic MCP targets",
           "WebUI access control, NOT gateway JWT/AAA or delegated human auth",
           "tool discovery rather than model-directed invocation",
           "Docker runner, rootless Open WebUI runtime separately qualified"]}
    def check(name,ok,status=None,detail=None):
        out["checks"].append({"name":name,"passed":bool(ok),
                              "http":status,"detail":detail})
        if not ok:raise AssertionError(f"{name}:{status}:{detail}")
    try:
        adminpw=secrets.token_urlsafe(32)+"A!1"
        code,body=request("POST","/api/v1/auths/signup",
                          {"name":"Synthetic Administrator","email":ADMIN_EMAIL,
                           "password":adminpw})
        admin=body.get("token")
        check("first-admin-created",code==200 and bool(admin),code)
        users={}
        for label in ("research","engineering"):
            password=secrets.token_urlsafe(32)+"A!1"
            code,body=request("POST","/api/v1/auths/add",
                     {"name":f"Synthetic {label.title()}",
                      "email":f"rdte-{label}@example.com",
                      "password":password,"role":"user"},admin)
            token=body.get("token")
            uid=body.get("id")
            check("admin-add-"+label,code==200 and bool(uid),code)
            if not token:
                code,body=request("POST","/api/v1/auths/signin",
                                  {"email":f"rdte-{label}@example.com","password":password})
                token=body.get("token")
            check(label+"-login-token",bool(token),code)
            users[label]={"token":token,"id":uid,"password":password}
        connections=[]
        for label in ("research","engineering"):
            connections.append({
                "url":f"http://supra-mcp-{label}:{39101 if label=='research' else 39102}/mcp",
                "path":"/mcp","type":"mcp","auth_type":"none",
                "headers":{},"key":"",
                "config":{"enable":True,"access_grants":[{
                    "principal_type":"user","principal_id":users[label]["id"],"permission":"read"}]},
                "info":{"id":label,"name":"Synthetic "+label,"description":"U2 fixture only"},
            })
        code,body=request("POST","/api/v1/configs/tool_servers",
                          {"TOOL_SERVER_CONNECTIONS":connections},admin)
        check("admin-assign-disjoint-mcp-grants",code==200 and
              len(body.get("TOOL_SERVER_CONNECTIONS",[]))==2,code)
        for actor in ("research","engineering"):
            token=users[actor]["token"]
            code,body=request("GET","/api/v1/tools/",token=token)
            ids={x.get("id") for x in body} if isinstance(body,list) else set()
            wanted=f"server:mcp:{actor}"
            forbidden="server:mcp:engineering" if actor=="research" else "server:mcp:research"
            check(actor+"-catalog-own-only",code==200 and wanted in ids and forbidden not in ids,
                  code,{"own":wanted in ids,"forbiddenSeen":forbidden in ids})
            code,body=request("GET","/api/v1/tools/id/"+wanted+"/specs",token=token)
            names={x.get("name") for x in body.get("specs",[])}
            check(actor+"-own-five-specs",code==200 and names==
                  {"search","read","observe","write","admin"},code)
            code,body=request("GET","/api/v1/tools/id/"+forbidden+"/specs",token=token)
            check(actor+"-cross-user-mcp-denied",code==404,code)
        # Same user can hold two login tokens; does not create distinct belt grants.
        p=users["research"]
        code,body=request("POST","/api/v1/auths/signin",
                          {"email":"rdte-research@example.com","password":p["password"]})
        token2=body.get("token")
        check("same-user-second-login",code==200 and bool(token2),code)
        code,body=request("GET","/api/v1/tools/id/server:mcp:engineering/specs",token=token2)
        check("second-login-retains-denial",code==404,code)
        out["passed"]=len(out["checks"])==14 and all(x["passed"] for x in out["checks"])
    except Exception as e:out["failure"]=repr(e)[:650]
    pathlib.Path("openwebui-u2-receipt.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(out,indent=2,sort_keys=True))
    return 0 if out["passed"] else 1
if __name__=="__main__":sys.exit(run())
