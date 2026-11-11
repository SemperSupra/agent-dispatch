#!/usr/bin/env python3
"""One public-safe MCP 2025-06-18 synthetic upstream, five duplicate-named tools."""
import argparse,json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
NAMES=("search","read","observe","write","admin")
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        self.send_response(200 if self.path=="/health" else 405)
        self.end_headers()
    def do_POST(self):
        if self.path!="/mcp":self.send_error(404);return
        try:
            data=json.loads(self.rfile.read(min(int(self.headers.get("Content-Length","0")),65536)))
            method=data.get("method","")
            if method=="initialize":
                result={"protocolVersion":"2025-06-18","capabilities":{"tools":{}},
                        "serverInfo":{"name":self.server.service,"version":"1.0"}}
            elif method=="tools/list":
                result={"tools":[{"name":n,"description":"Synthetic public-safe "+self.server.service+"."+n,
                    "inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}
                    for n in NAMES]}
            elif method=="tools/call":
                name=data.get("params",{}).get("name")
                if name not in NAMES: result={"isError":True,"content":[{"type":"text","text":"unknown"}]}
                else:result={"isError":False,"content":[{"type":"text","text":self.server.service+":"+name+":"+str(data.get("params",{}).get("arguments",{}).get("text",""))}]}
            elif method.startswith("notifications/"):
                self.send_response(202);self.end_headers();return
            else:
                self.reply({"jsonrpc":"2.0","id":data.get("id"),"error":{"code":-32601,"message":"Method not found"}});return
            self.reply({"jsonrpc":"2.0","id":data.get("id"),"result":result})
        except (ValueError,KeyError,TypeError) as e:self.send_error(400)
    def reply(self,obj):
        raw=json.dumps(obj).encode()
        self.send_response(200);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)));self.end_headers();self.wfile.write(raw)
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--service",required=True)
    parser.add_argument("--port",required=True,type=int)
    a=parser.parse_args()
    h=ThreadingHTTPServer(("127.0.0.1",a.port),Handler);h.service=a.service
    h.serve_forever()
if __name__=="__main__":main()
