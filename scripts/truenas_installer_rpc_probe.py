#!/usr/bin/env python3
"""Minimal dependency-free JSON-RPC 2.0 client for the TrueNAS installer WebSocket API."""
from __future__ import annotations
import argparse, base64, hashlib, json, os, pathlib, socket, struct, time


class WebSocket:
    def __init__(self, host: str, port: int, path: str = "/ws", timeout: float = 5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
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

    def _read_exact(self, n: int) -> bytes:
        chunks = []
        remaining = n
        while remaining:
            part = self.sock.recv(remaining)
            if not part:
                raise EOFError("websocket closed")
            chunks.append(part)
            remaining -= len(part)
        return b"".join(chunks)

    def _read_until(self, marker: bytes, limit: int) -> bytes:
        data = bytearray()
        while marker not in data:
            part = self.sock.recv(4096)
            if not part:
                raise EOFError("socket closed during handshake")
            data.extend(part)
            if len(data) > limit:
                raise RuntimeError("handshake exceeded limit")
        return bytes(data)

    def _send_frame(self, opcode: int, payload: bytes):
        first = 0x80 | opcode
        mask = os.urandom(4)
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

    def recv_text(self) -> str:
        fragments = []
        while True:
            b1, b2 = self._read_exact(2)
            fin = bool(b1 & 0x80)
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            n = b2 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._read_exact(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if masked else b""
            payload = self._read_exact(n)
            if masked:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                raise EOFError("websocket close frame")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode in (0x1, 0x0):
                fragments.append(payload)
                if fin:
                    return b"".join(fragments).decode()
            elif opcode == 0xA:
                continue
            else:
                raise RuntimeError(f"unexpected websocket opcode {opcode}")

    def call(self, method: str, request_id: int):
        self.send_json({"jsonrpc": "2.0", "id": request_id, "method": method})
        while True:
            response = json.loads(self.recv_text())
            if response.get("id") != request_id:
                continue
            if response.get("error") is not None:
                raise RuntimeError(f"{method}: {json.dumps(response['error'], sort_keys=True)}")
            return response.get("result")

    def close(self):
        try:
            self._send_frame(0x8, b"")
        except Exception:
            pass
        self.sock.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--timeout", type=float, default=6.0)
    a = p.parse_args()
    started = time.time()
    payload = {
        "schema": "truenas-installer-rpc-discovery/v1",
        "endpoint": {"host": a.host, "port": a.port, "path": "/ws"},
        "methods": {},
        "oracleSatisfied": False,
    }
    ws = WebSocket(a.host, a.port, timeout=a.timeout)
    try:
        adopted = ws.call("is_adopted", 1)
        payload["methods"]["is_adopted"] = adopted
        if adopted:
            raise RuntimeError("fresh installer unexpectedly reports adopted=true")
        for i, method in enumerate(
            ("system_info", "list_disks", "list_network_interfaces"), start=2
        ):
            payload["methods"][method] = ws.call(method, i)
        payload["oracleSatisfied"] = True
        payload["classification"] = "SUPPORTED"
        payload["detail"] = "read-only TrueNAS installer JSON-RPC discovery methods answered"
    except Exception as exc:
        payload["classification"] = "ORACLE_FAILURE"
        payload["detail"] = f"{type(exc).__name__}: {exc}"
    finally:
        ws.close()
    payload["elapsed_seconds"] = round(time.time() - started, 3)
    pathlib.Path(a.out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
