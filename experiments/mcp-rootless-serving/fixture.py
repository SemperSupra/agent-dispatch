#!/usr/bin/env python3
"""Synthetic local MCP upstream and actual multi-tool rootless gateway probe."""
import argparse,json,sys,urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
 def log_message(self,*a): pass
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b"healthy")
 def do_POST(self):
  raw=self.rfile.read(min(65536,int(self.headers.get("Content-Length","0"))))
  q=json.loads(raw);m=q.get("method")
  if m=="initialize": result={"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":self.server.label,"version":"1"}}
  elif m=="tools/list":result={"tools":[{"name":"echo","description":"synthetic","inputSchema":{"type":"object","properties":{"text":{"type":"string"}}}}]}
  elif m=="tools/call":result={"content":[{"type":"text","text":self.server.label+":"+q.get("params",{}).get("arguments",{}).get("text","")}],"isError":False}
  else: result={}
  obj=json.dumps({"jsonrpc":"2.0","id":q.get("id"),"result":result}).encode()
  self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(obj)));self.end_headers();self.wfile.write(obj)
def rpc(method,i,session=None,params=None):
 obj={"jsonrpc":"2.0","method":method,"id":i}
 if params is not None:obj["params"]=params
 headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream","MCP-Protocol-Version":"2025-06-18"}
 if session:headers["Mcp-Session-Id"]=session
 req=urllib.request.Request("http://127.0.0.1:39200/mcp",data=json.dumps(obj).encode(),headers=headers)
 with urllib.request.urlopen(req,timeout=8) as r:
  body=r.read().decode()
  if "text/event-stream" in r.headers.get("Content-Type",""):
   body=[x[5:] for x in body.splitlines() if x.startswith("data:")][-1]
  return json.loads(body),r.headers.get("Mcp-Session-Id") or session
def main():
 p=argparse.ArgumentParser();p.add_argument("--serve",action="store_true");p.add_argument("--label",default="alpha");p.add_argument("--port",type=int,default=39101);p.add_argument("--out",default="rootless-serving-receipt.json");a=p.parse_args()
 if a.serve:
  t=ThreadingHTTPServer(("127.0.0.1",a.port),H);t.label=a.label;t.serve_forever()
 else:
  receipt={"schema":"rootless-agentgateway-serving-v1","passed":False,"nameCount":0,"callCount":0}
  try:
   init,session=rpc("initialize",1,params={"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rootless-smoke","version":"1"}})
   tools,session=rpc("tools/list",2,session)
   names=sorted(x["name"] for x in tools["result"]["tools"])
   receipt["nameCount"]=len(names)
   if names!=["alpha_echo","beta_echo"]:raise AssertionError(names)
   for i,name in enumerate(names,3):
    result,session=rpc("tools/call",i,session,{"name":name,"arguments":{"text":"probe"}})
    if name.split("_",1)[0]+":probe" not in json.dumps(result):raise AssertionError(result)
    receipt["callCount"]+=1
   receipt["passed"]=True
  except Exception as ex:receipt["error"]=repr(ex)
  open(a.out,"w").write(json.dumps(receipt,indent=2,sort_keys=True)+"\n");print(json.dumps(receipt,indent=2))
  return 0 if receipt["passed"] else 1
if __name__=="__main__":sys.exit(main())
