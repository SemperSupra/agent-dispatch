#!/usr/bin/env python3
"""Dependency-free installed TrueNAS middleware DDP health probe."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import socket
import ssl
import struct
import time


class WebSocket:
    def __init__(self, host, port, path="/websocket", timeout=6.0, tls=False):
        raw = socket.create_connection((host, port), timeout=timeout)
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw = context.wrap_socket(raw, server_hostname=host)
        self.sock = raw
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        self.sock.sendall(request)
        head = self._read_until(b"\r\n\r\n", 16384)
        status = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raise RuntimeError(f"websocket handshake failed: {status.decode(errors='replace')}")
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        headers = {}
        for line in head.decode(errors="replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.lower().strip()] = v.strip()
        if headers.get("sec-websocket-accept") != expected:
            raise RuntimeError("websocket accept digest mismatch")

    def _read_exact(self, n):
        parts = []
        while n:
            part = self.sock.recv(n)
            if not part:
                raise EOFError("websocket closed")
            parts.append(part)
            n -= len(part)
        return b"".join(parts)

    def _read_until(self, marker, limit):
        data = bytearray()
        while marker not in data:
            part = self.sock.recv(4096)
            if not part:
                raise EOFError("socket closed during handshake")
            data.extend(part)
            if len(data) > limit:
                raise RuntimeError("handshake exceeded limit")
        return bytes(data)

    def _send_frame(self, opcode, payload):
        mask = os.urandom(4)
        first = 0x80 | opcode
        n = len(payload)
        if n < 126:
            header = bytes([first, 0x80 | n])
        elif n <= 0xFFFF:
            header = bytes([first, 0x80 | 126]) + struct.pack("!H", n)
        else:
            header = bytes([first, 0x80 | 127]) + struct.pack("!Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def send_json(self, obj):
        self._send_frame(0x1, json.dumps(obj, separators=(",", ":")).encode())

    def recv_json(self):
        while True:
            b1, b2 = self._read_exact(2)
            opcode = b1 & 0x0F
            n = b2 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._read_exact(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._read_exact(8))[0]
            masked = bool(b2 & 0x80)
            mask = self._read_exact(4) if masked else b""
            payload = self._read_exact(n)
            if masked:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                raise EOFError("websocket close frame")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode != 0x1:
                continue
            return json.loads(payload.decode())

    def close(self):
        try:
            self._send_frame(0x8, b"")
        except Exception:
            pass
        self.sock.close()


def wait_for(ws, predicate):
    while True:
        message = ws.recv_json()
        if message.get("msg") == "ping":
            response = {"msg": "pong"}
            if "id" in message:
                response["id"] = message["id"]
            ws.send_json(response)
            continue
        if predicate(message):
            return message


def ddp_call(ws, request_id, method, params):
    ws.send_json({"id": request_id, "msg": "method", "method": method, "params": params})
    message = wait_for(ws, lambda m: m.get("msg") == "result" and m.get("id") == request_id)
    if message.get("error") is not None:
        raise RuntimeError(f"{method}: {json.dumps(message['error'], sort_keys=True)}")
    return message.get("result")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=6.0)
    a = p.parse_args()

    password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()
    payload = {
        "schema": "truenas-middleware-ddp-health/v1",
        "oracleSatisfied": False,
        "classification": "ORACLE_FAILURE",
        "transport": "wss" if a.tls else "ws",
    }
    started = time.time()
    ws = None
    try:
        ws = WebSocket(a.host, a.port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise RuntimeError(f"DDP connection failed: {connected!r}")

        auth = ddp_call(
            ws,
            "1",
            "auth.login_ex",
            [{
                "mechanism": "PASSWORD_PLAIN",
                "username": "truenas_admin",
                "password": password,
            }],
        )
        payload["auth_response_type"] = auth.get("response_type") if isinstance(auth, dict) else None
        if payload["auth_response_type"] != "SUCCESS":
            raise RuntimeError(f"authentication did not return SUCCESS: {auth!r}")

        payload["system_version"] = ddp_call(ws, "2", "system.version", [])
        payload["system_info"] = ddp_call(ws, "3", "system.info", [])
        payload["oracleSatisfied"] = True
        payload["classification"] = "SUPPORTED"
        payload["detail"] = "installed TrueNAS middleware authenticated and answered system.version/system.info"
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
    finally:
        if ws is not None:
            ws.close()

    payload["elapsed_seconds"] = round(time.time() - started, 3)
    pathlib.Path(a.out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
