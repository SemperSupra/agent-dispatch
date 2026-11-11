#!/usr/bin/env python3
"""Public-safe MCPHub group CRUD/invoke test, no credential material in receipts."""
import json,pathlib,sys,time,urllib.request,urllib.error
BASE="http://127.0.0.1:3300"
def api(method,path,body=None,token=None):
 h={"Content-Type":"application/json"}
 if token:h["x-auth-token"]=token
 request=urllib.request.Request(BASE+path,method=method,
       data=json.dumps(body).encode() if body is not None else None,headers=h)
 try:
  with urllib.request.urlopen(request,timeout=12) as r:return r.status,json.load(r)
 except urllib.error.HTTPError as e:
  try:b=json.loads(e.read().decode())
  except Exception:b={}
  return e.code,b
def rpc(route,method,i,token,session=None,params=None):
 obj={"jsonrpc":"2.0","id":i,"method":method}
 if params is not None:obj["params"]=params
 h={"Content-Type":"application/json","Accept":"application/json, text/event-stream",
    "Authorization":"Bearer "+token,"MCP-Protocol-Version":"2025-06-18"}
 if session:h["Mcp-Session-Id"]=session
 req=urllib.request.Request(BASE+route,data=json.dumps(obj).encode(),headers=h)
 with urllib.request.urlopen(req,timeout=12) as r:
  raw=r.read().decode()
  if "text/event-stream" in r.headers.get("Content-Type",""):
   raw=[x[5:] for x in raw.splitlines() if x.startswith("data:")][-1]
  return json.loads(raw),r.headers.get("Mcp-Session-Id") or session
def probe(group,expected,token):
 route="/mcp/"+group
 init={"protocolVersion":"2025-06-18","capabilities":{},
       "clientInfo":{"name":"synthetic-groups","version":"1"}}
 obj,session=rpc(route,"initialize",1,token,params=init)
 if "result" not in obj:raise ValueError("group initialize failed")
 tools=[]
 for k in range(20):
  obj,session=rpc(route,"tools/list",2+k,token,session)
  tools=obj.get("result",{}).get("tools",[])
  if len(tools)==1:break
  time.sleep(.5)
 if len(tools)!=1 or not tools[0]["name"].startswith(expected+"-"):
  raise AssertionError(("selection wrong",group,expected,tools))
 obj,session=rpc(route,"tools/call",50,token,session,
                  {"name":tools[0]["name"],"arguments":{"text":"group-proof"}})
 if expected+":group-proof" not in json.dumps(obj):raise AssertionError("misrouted group invoke")
 return {"group":group,"source":expected,"tool":tools[0]["name"]}
def main():
 out={"schema":"m1-mcphub-group-crud-v1","checks":[],"passed":False}
 def check(name,passed,details=None):
  out["checks"].append({"name":name,"passed":bool(passed),"details":details})
 try:
  password=pathlib.Path("synthetic-admin-password.txt").read_text().strip()
  service_token=pathlib.Path("ephemeral-token.txt").read_text().strip()
  status,result=api("POST","/api/auth/login",{"username":"admin","password":password})
  jwt=result.get("token")
  check("management-login",status==200 and bool(jwt),{"http":status})
  if not jwt:raise RuntimeError("synthetic management login rejected")
  for name,service in (("research","alpha"),("engineering","beta")):
   status,result=api("POST","/api/groups",{"name":name,"servers":[service]},jwt)
   check("create-"+name,status in (200,201) and result.get("success") is True,{"http":status})
  status,result=api("GET","/api/groups",token=jwt)
  groups={x.get("name"):x.get("id") for x in result.get("data",[])}
  names=set(groups)
  check("list-saved",status==200 and {"research","engineering"}<=names and bool(groups.get("research")),{"groups":sorted(names)})
  for name,service in (("research","alpha"),("engineering","beta")):
   try:check("invoke-"+name,True,probe(name,service,service_token))
   except Exception as e:check("invoke-"+name,False,{"reason":repr(e)})
  status,result=api("PUT","/api/groups/"+str(groups["research"]),{"servers":["beta"]},jwt)
  check("update-research",status==200 and result.get("success") is True,{"http":status})
  try:check("updated-route",True,probe("research","beta",service_token))
  except Exception as e:check("updated-route",False,{"reason":repr(e)})
  try:check("unmodified-other-group",True,probe("engineering","beta",service_token))
  except Exception as e:check("unmodified-other-group",False,{"reason":repr(e)})
  status,result=api("DELETE","/api/groups/"+str(groups["research"]),token=jwt)
  check("delete-research",status==200 and result.get("success") is True,{"http":status})
  status,result=api("GET","/api/groups",token=jwt)
  names={x.get("name") for x in result.get("data",[])}
  check("persist-other-delete-one",status==200 and "research" not in names and "engineering" in names,{"groups":sorted(names)})
  out["passed"]=len(out["checks"])==10 and all(x["passed"] for x in out["checks"])
 except Exception as e:out["error"]=repr(e)
 pathlib.Path("group-crud-receipt.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
 print(json.dumps(out,indent=2,sort_keys=True))
 return 0 if out["passed"] else 1
if __name__=="__main__":sys.exit(main())
