#!/usr/bin/env python3
"""Actual MCP 2026-07-28 stateless direct requests, signed synthetic belt claims."""
import json,pathlib,time,urllib.request,urllib.error,sys
import make_issuer
URL="http://127.0.0.1:39200/mcp"
def rpc(method,i,token,params=None,name=None,override=None):
 obj={"jsonrpc":"2.0","id":i,"method":method}
 p=dict(params or {})
 p["_meta"]={"io.modelcontextprotocol/protocolVersion":"2026-07-28",
             "io.modelcontextprotocol/clientCapabilities":{},
             "io.modelcontextprotocol/clientInfo":{"name":"sessionless-qualify","version":"1"}}
 obj["params"]=p
 headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream",
          "Authorization":"Bearer "+token,"Mcp-Protocol-Version":"2026-07-28",
          "Mcp-Method":override or method}
 if name:headers["Mcp-Name"]=name
 req=urllib.request.Request(URL,data=json.dumps(obj).encode(),headers=headers)
 try:
  with urllib.request.urlopen(req,timeout=15) as r:
   body=r.read(250000).decode()
   if "text/event-stream" in r.headers.get("Content-Type",""):
    body=[x[5:] for x in body.splitlines() if x.startswith("data:")][-1]
   return r.status,json.loads(body)
 except urllib.error.HTTPError as e:
  raw=e.read(4096).decode(errors="replace")
  try:body=json.loads(raw)
  except Exception:body={"error":raw[:300]}
  return e.code,body
def signed(belt):
 now=int(time.time())
 return make_issuer.sign({"iss":"https://issuer.invalid/m1",
   "aud":"m1-synthetic-client","sub":"alpha","belt":belt,
   "client_id":"modern-"+belt,"iat":now,"exp":now+600})
def main():
 out={"schema":"m1-sessionless-2026-gateway-v1","checks":[],"passed":False,
      "limitations":["synthetic issuer, legacy 2025 upstream",
                     "no actual ChatGPT/Gemini client or live enterprise policy"]}
 def check(label,ok,details=None):
  out["checks"].append({"name":label,"passed":bool(ok),"details":details})
 try:
  for belt,expected in (("research","alpha_echo"),("engineering","beta_echo"),
                        ("invalid",None)):
   token=signed(belt)
   status,result=rpc("tools/list",1,token)
   names=sorted(x["name"] for x in result.get("result",{}).get("tools",[]))
   check(belt+"-sessionless-list",status==200 and names==([expected] if expected else []),
         {"http":status,"names":names})
   if not expected:continue
   status,result=rpc("tools/call",2,token,
      {"name":expected,"arguments":{"text":"modern"}},name=expected)
   check(belt+"-sessionless-own-call",status==200 and expected.split("_")[0]+":modern" in json.dumps(result),{"http":status})
   other="beta_echo" if expected=="alpha_echo" else "alpha_echo"
   status,result=rpc("tools/call",3,token,
      {"name":other,"arguments":{"text":"forbidden"}},name=other)
   check(belt+"-cross-belt-denied",other.split("_")[0]+":forbidden" not in json.dumps(result),{"http":status})
   status,result=rpc("tools/call",4,token,
      {"name":expected,"arguments":{"text":"mismatch"}},name=other)
   check(belt+"-mismatched-header-denied",expected.split("_")[0]+":mismatch" not in json.dumps(result),{"http":status})
  out["passed"]=len(out["checks"])==9 and all(x["passed"] for x in out["checks"])
 except Exception as e:out["error"]=repr(e)
 pathlib.Path("modern-receipt.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
 print(json.dumps(out,indent=2,sort_keys=True))
 return 0 if out["passed"] else 1
if __name__=="__main__":sys.exit(main())
