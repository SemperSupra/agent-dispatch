#!/usr/bin/env python3
"""Synthetic LOCAL bundle service, no auth/production use, no external egress."""
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import time

ROOT = Path(sys.argv[1])
ACTIVE = ROOT / "active.tar.gz"
EVENTS = ROOT / "requests.jsonl"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/bundle.tar.gz":
            self.send_error(404)
            return
        try:
            blob = ACTIVE.read_bytes()
        except FileNotFoundError:
            self.send_error(503)
            return
        digest = hashlib.sha256(blob).hexdigest()
        etag = '"' + digest + '"'
        status = 304 if self.headers.get("If-None-Match") == etag else 200
        self.send_response(status)
        self.send_header("ETag", etag)
        self.send_header("Cache-Control", "no-store")
        if status == 200:
            self.send_header("Content-Type", "application/vnd.openpolicyagent.bundles")
            self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        if status == 200:
            self.wfile.write(blob)
        event = {"utc": time.time(), "status": status, "sha256": digest,
                 "length": len(blob), "etag_supplied": bool(self.headers.get("If-None-Match"))}
        with EVENTS.open("a") as out:
            out.write(json.dumps(event, sort_keys=True) + "\n")
    def log_message(self, format, *args):
        pass

ThreadingHTTPServer(("127.0.0.1", 8099), Handler).serve_forever()
