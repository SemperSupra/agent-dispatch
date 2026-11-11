#!/usr/bin/env python3
"""Disposable public-safe synthetic MCP upstream. No secrets, no real tools."""
import argparse,json
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 404)
        self.end_headers()
        self.wfile.write(b"ready" if self.path == "/health" else b"not found")
    def do_POST(self):
        if self.path != "/mcp": self.send_error(404); return
        data=self.rfile.read(min(int(self.headers.get("Content-Length","0")),65536))
        try: request=json.loads(data)
        except Exception: self.send_error(400); return
        method=request.get("method")
        if method == "initialize":
            value={"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":False}},
                   "serverInfo":{"name":self.server.label,"version":"1.0"}}
        elif method == "tools/list":
            value={"tools":[{"name":"echo","description":"Public synthetic tool for "+self.server.label,
                             "inputSchema":{"type":"object","properties":{"text":{"type":"string"}},
                                            "required":["text"]}}]}
        elif method == "tools/call":
            if request.get("params",{}).get("name")!="echo":
                value={"isError":True,"content":[{"type":"text","text":"unknown synthetic tool"}]}
            else:
                text=str(request.get("params",{}).get("arguments",{}).get("text",""))
                value={"content":[{"type":"text","text":self.server.label+":"+text}],"isError":False}
        elif method.startswith("notifications/"):
            self.send_response(202); self.end_headers();return
        else:
            self._response({"jsonrpc":"2.0","id":request.get("id"),"error":{"code":-32601,"message":"Method not found"}});return
        self._response({"jsonrpc":"2.0","id":request.get("id"),"result":value})
    def _response(self,obj):
        out=json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(out)))
        self.end_headers();self.wfile.write(out)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--port",type=int,required=True)
    p.add_argument("--bind",default="127.0.0.1")
    p.add_argument("--label",choices=["alpha","beta"],required=True)
    a=p.parse_args()
    server=ThreadingHTTPServer((a.bind,a.port),Handler)
    server.label=a.label
    server.serve_forever()
if __name__=="__main__":main()
