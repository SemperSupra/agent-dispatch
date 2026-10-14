#!/usr/bin/env python3
"""Standalone public synthetic HTTP/job fixture; no private downloader or data.

Only loopback HTTP is used. This proves fixture semantics, never TrueNAS or a
real export. Run in an empty, exclusively owned output directory.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import re
import threading
import urllib.error
import urllib.request
import zipfile


def zip_bytes(name, payload):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        entry = zipfile.ZipInfo(name, date_time=(2000, 1, 1, 0, 0, 0))
        entry.create_system = 3  # Freeze UNIX metadata across Windows/Linux builders.
        entry.external_attr = 0o100644 << 16
        archive.writestr(entry, payload)
    return stream.getvalue()


FILES = {
    "part-001.zip": zip_bytes("alpha.txt", b"synthetic alpha\n"),
    "part-002.bin": b"synthetic non-zip payload\x00\x01\n",
    "part-003.zip": zip_bytes("resume.txt", b"synthetic resume\n" * 16),
}
SENTINEL = b"synthetic retained archive sentinel v1\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inventory():
    return {name: {"bytes": len(data), "sha256": sha(data)}
            for name, data in FILES.items()}


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.calls.append(self.path)
        if self.path in ("/403", "/429"):
            self.send_response(int(self.path[1:]))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        name = self.path.removeprefix("/")
        if name not in FILES:
            self.send_error(404)
            return
        data = FILES[name]
        start = 0
        range_value = self.headers.get("Range")
        if range_value:
            match = re.fullmatch(r"bytes=([0-9]+)-", range_value)
            if not match or int(match[1]) >= len(data):
                self.send_error(416)
                return
            start = int(match[1])
        self.send_response(206 if range_value else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data) - start))
        if range_value:
            self.send_header("Content-Range", f"bytes {start}-{len(data)-1}/{len(data)}")
        self.end_headers()
        if name == "part-003.zip" and not range_value and not self.server.interrupted:
            self.server.interrupted = True
            self.wfile.write(data[:31])
            self.wfile.flush()
            self.close_connection = True
            return
        self.wfile.write(data[start:])


@contextmanager
def fixture_server():
    # No ingress: the server lives only for this one-shot job and binds loopback.
    server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
    server.calls = []
    server.interrupted = False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("fixture cleanup failed")


def download(base, name, output):
    if name not in FILES or not re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", base):
        raise ValueError("synthetic input only")
    destination = output / name
    partial = output / (name + ".part")
    if output.is_symlink() or destination.is_symlink() or partial.is_symlink():
        raise ValueError("unowned path")
    if destination.exists():
        if destination.read_bytes() != FILES[name]:
            raise ValueError("existing content mismatch")
        return "NOOP"
    offset = partial.stat().st_size if partial.exists() else 0
    headers = {"Range": f"bytes={offset}-"} if offset else {}
    request = urllib.request.Request(base + "/" + name, headers=headers)
    # Bypass environment proxy settings for this closed loopback fixture.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=5) as response:
        expected_range = f"bytes {offset}-{len(FILES[name])-1}/{len(FILES[name])}"
        if response.status != (206 if offset else 200):
            raise ValueError("unexpected status")
        if offset and response.headers.get("Content-Range") != expected_range:
            raise ValueError("range mismatch")
        with partial.open("ab" if offset else "xb") as stream:
            while block := response.read(16):
                stream.write(block)
    if partial.stat().st_size != len(FILES[name]):
        return "INTERRUPTED"
    data = partial.read_bytes()
    if data != FILES[name]:
        raise ValueError("integrity mismatch")
    if name.endswith(".zip"):
        with zipfile.ZipFile(partial) as archive:
            if archive.testzip() is not None:
                raise ValueError("CRC mismatch")
    partial.replace(destination)
    return "VERIFIED"


def halt_oracle(base, server, status):
    before = len(server.calls)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    halted = False
    for path in (f"/{status}", "/part-001.zip", "/part-002.bin"):
        try:
            with opener.open(base + path, timeout=5):
                pass
        except urllib.error.HTTPError as exc:
            if exc.code != status:
                raise ValueError("unexpected halt status") from None
            halted = True
            break
    if not halted or server.calls[before:] != [f"/{status}"]:
        raise ValueError("halt did not stop admission")


def run(output, state_dir=None):
    if output.is_symlink():
        raise ValueError("unowned output")
    output.mkdir(parents=True, exist_ok=True)
    state = {"schema": "takeout-synthetic-state/v1", "files": inventory()}
    state_path = None
    if state_dir is not None:
        if state_dir.is_symlink() or state_dir.resolve() == output.resolve():
            raise ValueError("state must be separate and owned")
        state_dir.mkdir(parents=True, exist_ok=True)
        state_path = state_dir / "state.json"
        if state_path.is_symlink():
            raise ValueError("unowned state")
        if state_path.exists() and json.loads(state_path.read_text()) != state:
            raise ValueError("state identity mismatch")
    sentinel = output / "retained-sentinel.txt"
    if sentinel.is_symlink():
        raise ValueError("unowned sentinel")
    if not sentinel.exists():
        with sentinel.open("xb") as stream:
            stream.write(SENTINEL)
    if sentinel.read_bytes() != SENTINEL:
        raise ValueError("sentinel changed")
    outcomes = {}
    with fixture_server() as (base, server):
        for name in FILES:
            outcome = download(base, name, output)
            if outcome == "INTERRUPTED":
                if name != "part-003.zip":
                    raise ValueError("unexpected interruption")
                outcome = download(base, name, output)
                outcomes["range_resume"] = outcome == "VERIFIED"
            outcomes[name] = outcome
        count = len(server.calls)
        for name in FILES:
            if download(base, name, output) != "NOOP":
                raise ValueError("repeat was not NOOP")
        if len(server.calls) != count:
            raise ValueError("NOOP made a request")
        halt_oracle(base, server, 403)
        halt_oracle(base, server, 429)
    if any(output.glob("*.part")):
        raise ValueError("partial residue")
    if state_path is not None and not state_path.exists():
        with state_path.open("x", encoding="utf-8") as stream:
            json.dump(state, stream, sort_keys=True)
    return {"schema": "takeout-synthetic-fixture/v1", "classification": "SUPPORTED",
            "scope": "synthetic-local-http-only", "files": inventory(),
            "outcomes": outcomes, "noop": True, "halt_403": True, "halt_429": True,
            "sentinel_sha256": sha(sentinel.read_bytes()),
            "fixture_server_closed": True, "guest_qualified": False,
            "uid": os.getuid() if hasattr(os, "getuid") else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state", type=Path, help="separate owned temporary state directory")
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.output, args.state), sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"classification": "ORACLE_FAILURE", "guest_qualified": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
