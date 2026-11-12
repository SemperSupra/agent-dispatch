#!/usr/bin/env python3
"""Disposable synthetic MCP workset/audit downstream boundary, NOT production AAA.

A real gateway fronts this upstream. This process mimics current native workset
admission (file fixture) and independent audit admission (separate HTTP process).
Neither this mock nor its files are Agent Dispatch/WOW or a production audit sink.
"""
import argparse
import json
import os
import pathlib
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path("runtime-g2")
ROOT.mkdir(exist_ok=True)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, obj):
        raw = json.dumps(obj, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path != "/health":
            return self.respond(404, {"error": "not-found"})
        return self.respond(200, {"ready": True})

    def do_POST(self):
        raw = self.rfile.read(min(int(self.headers.get("Content-Length", "0")), 16384))
        if self.server.mode == "audit":
            if self.path != "/append":
                return self.respond(404, {"error": "not-found"})
            try:
                event = json.loads(raw)
                if set(event) != {"service", "action", "decision"}:
                    raise ValueError("bad-event")
                with (ROOT / "audit.ndjson").open("a") as fp:
                    fp.write(json.dumps(event, sort_keys=True) + "\n")
                    fp.flush()
                    os.fsync(fp.fileno())
                return self.respond(200, {"recorded": True})
            except Exception:
                return self.respond(503, {"error": "unavailable"})
        if self.path != "/mcp":
            return self.respond(404, {"error": "not-found"})
        try:
            request = json.loads(raw)
        except ValueError:
            return self.respond(400, {"error": "invalid-json"})
        method = request.get("method", "")
        label = self.server.label
        if method.startswith("notifications/"):
            self.send_response(202)
            self.end_headers()
            return
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "m1-synthetic-" + label, "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "echo", "description": "synthetic guarded action",
                     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]}
        elif method == "tools/call":
            try:
                state = json.loads((ROOT / ("state-" + label + ".json")).read_text())
                admitted = state == {"grant": True, "workset_admitted": True}
            except (OSError, ValueError, TypeError):
                admitted = False
            if admitted and request.get("params", {}).get("name") == "echo":
                event = {"service": label, "action": "echo", "decision": "allow"}
                try:
                    req = urllib.request.Request("http://127.0.0.1:39303/append",
                          data=json.dumps(event).encode(), headers={"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=0.5) as response:
                        admitted = response.status == 200 and json.load(response).get("recorded") is True
                except (urllib.error.URLError, ValueError, TimeoutError, OSError):
                    admitted = False
            else:
                admitted = False
            if admitted:
                count_file = ROOT / ("effects-" + label + ".txt")
                try:
                    count = int(count_file.read_text())
                except (OSError, ValueError):
                    count = 0
                count_file.write_text(str(count + 1))
                payload = str(request.get("params", {}).get("arguments", {}).get("text", ""))
                result = {"content": [{"type": "text", "text": label + ":" + payload}], "isError": False}
            else:
                result = {"content": [{"type": "text", "text": "denied"}], "isError": True}
        else:
            result = {}
        self.respond(200, {"jsonrpc": "2.0", "id": request.get("id"), "result": result})


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", required=True, choices=("audit", "upstream"))
    p.add_argument("--label", default="alpha", choices=("alpha", "beta"))
    p.add_argument("--port", required=True, type=int)
    args = p.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.mode, server.label = args.mode, args.label
    server.serve_forever()


if __name__ == "__main__":
    main()
