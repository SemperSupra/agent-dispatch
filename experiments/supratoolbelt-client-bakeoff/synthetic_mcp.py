#!/usr/bin/env python3
"""Synthetic, no-credentials legacy MCP HTTP fixture for CLI client connectivity.
Exposes a single safe tool; never proxies to real internal infrastructure.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class MCP(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 405)
        self.end_headers()
    def do_POST(self):
        if self.path != "/mcp":
            self.send_error(404);return
        size=min(int(self.headers.get("Content-Length","0")),65536)
        data=json.loads(self.rfile.read(size))
        method=data.get("method","")
        if method.startswith("notifications/"):
            self.send_response(202);self.end_headers();return
        if method=="initialize":
            result={"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"supra-synthetic","version":"1"}}
        elif method=="tools/list":
            result={"tools":[{"name":"ping","description":"Synthetic public-safe ping",
                    "inputSchema":{"type":"object","properties":{}}}]}
        elif method=="tools/call":
            result={"content":[{"type":"text","text":"synthetic:ok"}],"isError":False}
        else:
            self.reply({"jsonrpc":"2.0","id":data.get("id"),"error":{"code":-32601,"message":"Method not found"}});return
        self.reply({"jsonrpc":"2.0","id":data.get("id"),"result":result})
    def reply(self,data):
        b=json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b)))
        self.end_headers()
        self.wfile.write(b)
if __name__=="__main__":
    ThreadingHTTPServer(("127.0.0.1",39200),MCP).serve_forever()
