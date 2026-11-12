#!/usr/bin/env python3
"""Public-safe synthetic saved-belt state service for independent runner restore.

Intentionally basic local SQLite process. This is NOT the deployed Tool Belt
authority or off-node live database: the transfer boundary is a GitHub artifact.
"""
import json
import os
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = os.environ.get("STATE_DB", "/state/belts.sqlite")

def db():
    conn = sqlite3.connect(DB, timeout=2)
    conn.execute("CREATE TABLE IF NOT EXISTS belt (id TEXT PRIMARY KEY, revision INTEGER NOT NULL, selected TEXT NOT NULL)")
    conn.commit()
    return conn

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def respond(self, code, obj):
        data = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/health":
            return self.respond(200, {"ready": True})
        if url.path != "/belt":
            return self.respond(404, {"error": "route-not-found"})
        ident = urllib.parse.parse_qs(url.query).get("id", [""])[0]
        with db() as conn:
            obj = conn.execute("SELECT id,revision,selected FROM belt WHERE id=?", (ident,)).fetchone()
        return self.respond(200 if obj else 404, {"id": obj[0], "revision": obj[1], "selected": obj[2]} if obj else {"error": "missing"})
    def do_POST(self):
        if self.path != "/belt":
            return self.respond(404, {"error": "route-not-found"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 2 or size > 4096:
                return self.respond(400, {"error": "size"})
            payload = json.loads(self.rfile.read(size))
            if set(payload) != {"id", "expected_revision", "selected"}:
                return self.respond(400, {"error": "unknown-field"})
            ident, expected, selected = payload["id"], payload["expected_revision"], payload["selected"]
            if ident != "research" or selected not in ("alpha", "beta") or type(expected) is not int:
                return self.respond(400, {"error": "invalid-selection"})
            with db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                previous = conn.execute("SELECT revision FROM belt WHERE id=?", (ident,)).fetchone()
                actual = previous[0] if previous else 0
                if actual != expected:
                    return self.respond(409, {"error": "stale-write", "revision": actual})
                if previous:
                    conn.execute("UPDATE belt SET revision=?,selected=? WHERE id=?",
                                 (actual+1, selected, ident))
                else:
                    conn.execute("INSERT INTO belt(id,revision,selected) VALUES (?,?,?)",
                                 (ident, actual+1, selected))
                conn.commit()
                return self.respond(200, {"id": ident, "revision": actual+1, "selected": selected})
        except (ValueError, TypeError, KeyError, sqlite3.Error):
            return self.respond(400, {"error": "invalid-request"})

if __name__ == "__main__":
    db().close()
    ThreadingHTTPServer(("0.0.0.0", 38081), Handler).serve_forever()
