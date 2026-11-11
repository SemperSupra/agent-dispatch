#!/usr/bin/env python3
"""Synthetic MCP upstream plus independent JWT/CEL policy negative test."""
import argparse,json,pathlib,sys,urllib.request,urllib.error
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b"ready")
 def do_POST(self):
  q=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))))
  m=q.get("method","")
  if m=="initialize":result={"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":self.server.label,"version":"1"}}
  elif m=="tools/list":result={"tools":[{"name":"echo","description":"public synthetic","inputSchema":{"type":"object","properties":{"text":{"type":"string"}}}}]}
  elif m=="tools/call":result={"content":[{"type":"text","text":self.server.label+":"+str(q.get("params",{}).get("arguments",{}).get("text",""))}],"isError":False}
  elif m.startswith("notifications/"):
   self.send_response(202);self.end_headers();return
  else:result={}
  buf=json.dumps({"jsonrpc":"2.0","id":q.get("id"),"result":result}).encode()
  self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(buf)));self.end_headers();self.wfile.write(buf)
def call(method,i,token=None,session=None,params=None):
 obj={"jsonrpc":"2.0","id":i,"method":method}
 if params is not None:obj["params"]=params
 headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream","MCP-Protocol-Version":"2025-06-18"}
 if token:headers["Authorization"]="Bearer "+token
 if session:headers["Mcp-Session-Id"]=session
 req=urllib.request.Request("http://127.0.0.1:39200/mcp",data=json.dumps(obj).encode(),headers=headers)
 try:
  with urllib.request.urlopen(req,timeout=8) as response:
   body=response.read().decode()
   if "text/event-stream" in response.headers.get("Content-Type",""):
    body=[x[5:] for x in body.splitlines() if x.startswith("data:")][-1]
   return (response.status,json.loads(body),response.headers.get("Mcp-Session-Id") or session)
 except urllib.error.HTTPError as e:
  return (e.code,{"error":e.read(1000).decode(errors="replace")},session)
def permitted(status,body,expected):
 if status!=200:return False
 r=body.get("result",{})
 return not r.get("isError",False) and expected in json.dumps(r)
def main():
 p=argparse.ArgumentParser();p.add_argument("--serve",action="store_true");p.add_argument("--label",default="alpha");p.add_argument("--port",type=int,default=39101);a=p.parse_args()
 if a.serve:
  s=ThreadingHTTPServer(("127.0.0.1",a.port),Handler);s.label=a.label;s.serve_forever();return 0
 out={"schema":"m1-real-jwt-cel-v1","checks":[],"passed":False}
 try:
  def check(name,good,detail=None):
   out["checks"].append({"name":name,"passed":bool(good),"detail":detail})
  init={"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic-auth-test","version":"1"}}
  status,body,_=call("initialize",1,params=init)
  check("anonymous-denied",status in (401,403),{"status":status})
  for subject in ("alpha","beta","revoked"):
   token=pathlib.Path("token-"+subject+".txt").read_text()
   status,body,session=call("initialize",2,token=token,params=init)
   check(subject+"-jwt-accepted",status==200 and "result" in body,{"status":status})
   if status!=200:continue
   status,body,session=call("tools/list",3,token,session)
   names=sorted(t["name"] for t in body.get("result",{}).get("tools",[]))
   expected=[subject+"_echo"] if subject!="revoked" else []
   check(subject+"-discovery-isolated",status==200 and names==expected,{"names":names,"expected":expected})
   if subject in ("alpha","beta"):
    own=subject+"_echo";other=("beta" if subject=="alpha" else "alpha")+"_echo"
    status,body,session=call("tools/call",4,token,session,{"name":own,"arguments":{"text":"check"}})
    check(subject+"-own-call-allowed",permitted(status,body,subject+":check"),{"status":status})
    status,body,session=call("tools/call",5,token,session,{"name":other,"arguments":{"text":"forbidden"}})
    check(subject+"-cross-call-denied",not permitted(status,body,other.split("_")[0]+":forbidden"),{"status":status})
   else:
    status,body,session=call("tools/call",6,token,session,{"name":"alpha_echo","arguments":{"text":"forbidden"}})
    check("revoked-direct-denied",not permitted(status,body,"alpha:forbidden"),{"status":status})
  out["passed"]=len(out["checks"])==12 and all(x["passed"] for x in out["checks"])
 except Exception as e:out["error"]=repr(e)
 pathlib.Path("authz-receipt.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
 print(json.dumps(out,indent=2,sort_keys=True))
 return 0 if out["passed"] else 1
if __name__=="__main__":sys.exit(main())
