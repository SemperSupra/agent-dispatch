import base64
import hashlib
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALL = ROOT / "scripts" / "truenas_installer_rpc_install.py"
MIDDLEWARE = ROOT / "scripts" / "truenas_middleware_ddp_probe.py"


class SyntheticWebSocketPeer:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]

    @staticmethod
    def read_exact(conn, count):
        chunks = []
        while count:
            part = conn.recv(count)
            if not part:
                raise EOFError("peer closed")
            chunks.append(part)
            count -= len(part)
        return b"".join(chunks)

    @classmethod
    def recv_json(cls, conn):
        b1, b2 = cls.read_exact(conn, 2)
        opcode = b1 & 0x0F
        if opcode == 0x8:
            return None
        if opcode != 0x1:
            raise AssertionError(f"unexpected opcode {opcode}")
        if not (b2 & 0x80):
            raise AssertionError("client frame must be masked")
        size = b2 & 0x7F
        if size == 126:
            size = struct.unpack("!H", cls.read_exact(conn, 2))[0]
        elif size == 127:
            size = struct.unpack("!Q", cls.read_exact(conn, 8))[0]
        mask = cls.read_exact(conn, 4)
        payload = cls.read_exact(conn, size)
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return json.loads(payload.decode())

    @staticmethod
    def send_json(conn, value):
        payload = json.dumps(value, separators=(",", ":")).encode()
        if len(payload) < 126:
            header = bytes([0x81, len(payload)])
        else:
            header = bytes([0x81, 126]) + struct.pack("!H", len(payload))
        conn.sendall(header + payload)

    def accept_websocket(self):
        conn, _ = self.listener.accept()
        request = bytearray()
        while b"\r\n\r\n" not in request:
            request.extend(conn.recv(4096))
        headers = {}
        for line in request.decode().split("\r\n")[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower().strip()] = value.strip()
        key = headers["sec-websocket-key"]
        accept = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
        ).decode()
        conn.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        )
        return conn


class FutureTrueNASProtocolTests(unittest.TestCase):
    def test_installer_mutation_is_exact_and_progress_is_retained(self):
        peer = SyntheticWebSocketPeer()
        errors = []
        password = "synthetic-ephemeral-9264"

        def server():
            try:
                with peer.accept_websocket() as conn:
                    expected = [
                        ("is_adopted", False),
                        ("list_disks", [{
                            "name": "vda",
                            "size": 24_000_000_000,
                            "model": "QEMU",
                            "label": "",
                            "removable": False,
                        }]),
                        ("list_network_interfaces", [{"name": "ens3"}]),
                    ]
                    for method, result in expected:
                        req = peer.recv_json(conn)
                        self.assertEqual(req["method"], method)
                        peer.send_json(conn, {
                            "jsonrpc": "2.0",
                            "id": req["id"],
                            "result": result,
                        })

                    req = peer.recv_json(conn)
                    self.assertEqual(req["method"], "install")
                    self.assertIsInstance(req["params"], list)
                    self.assertEqual(len(req["params"]), 1)
                    params = req["params"][0]
                    self.assertEqual(params["disks"], ["vda"])
                    self.assertTrue(params["set_pmbr"])
                    self.assertEqual(params["authentication"]["username"], "truenas_admin")
                    self.assertEqual(params["authentication"]["password"], password)
                    self.assertEqual(
                        params["post_install"]["network_interfaces"],
                        [{"name": "ens3", "ipv4_dhcp": True, "ipv6_auto": True}],
                    )
                    peer.send_json(conn, {
                        "jsonrpc": "2.0",
                        "method": "installation_progress",
                        "params": [{"progress": 0.5, "message": "Installing"}],
                    })
                    peer.send_json(conn, {
                        "jsonrpc": "2.0",
                        "id": req["id"],
                        "result": None,
                    })
            except Exception as exc:
                errors.append(exc)
            finally:
                peer.listener.close()

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            password_file = td / "password"
            password_file.write_text(password, encoding="utf-8")
            out = td / "install.json"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(INSTALL),
                    "--port", str(peer.port),
                    "--password-file", str(password_file),
                    "--out", str(out),
                    "--timeout", "2",
                ],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            receipt = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(receipt["oracleSatisfied"])
            self.assertEqual(receipt["selected_disk"], "vda")
            self.assertEqual(receipt["selected_interface"], "ens3")
            self.assertEqual(receipt["progress"][0]["message"], "Installing")
            self.assertNotIn(password, out.read_text(encoding="utf-8"))
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_installed_middleware_ddp_auth_and_health(self):
        peer = SyntheticWebSocketPeer()
        errors = []
        password = "synthetic-ephemeral-9264"

        def server():
            try:
                with peer.accept_websocket() as conn:
                    msg = peer.recv_json(conn)
                    self.assertEqual(msg, {"msg": "connect", "version": "1", "support": ["1"]})
                    peer.send_json(conn, {"msg": "connected", "session": "synthetic"})

                    msg = peer.recv_json(conn)
                    self.assertEqual(msg["method"], "auth.login_ex")
                    auth = msg["params"][0]
                    self.assertEqual(auth["mechanism"], "PASSWORD_PLAIN")
                    self.assertEqual(auth["username"], "truenas_admin")
                    self.assertEqual(auth["password"], password)
                    peer.send_json(conn, {
                        "id": msg["id"],
                        "msg": "result",
                        "result": {"response_type": "SUCCESS"},
                    })

                    msg = peer.recv_json(conn)
                    self.assertEqual(msg["method"], "system.version")
                    peer.send_json(conn, {
                        "id": msg["id"],
                        "msg": "result",
                        "result": "TrueNAS-26.0.0-BETA.3",
                    })

                    msg = peer.recv_json(conn)
                    self.assertEqual(msg["method"], "system.info")
                    peer.send_json(conn, {
                        "id": msg["id"],
                        "msg": "result",
                        "result": {"version": "TrueNAS-26.0.0-BETA.3"},
                    })
            except Exception as exc:
                errors.append(exc)
            finally:
                peer.listener.close()

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            password_file = td / "password"
            password_file.write_text(password, encoding="utf-8")
            out = td / "middleware.json"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(MIDDLEWARE),
                    "--port", str(peer.port),
                    "--password-file", str(password_file),
                    "--out", str(out),
                    "--timeout", "2",
                ],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            receipt = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(receipt["oracleSatisfied"])
            self.assertEqual(receipt["auth_response_type"], "SUCCESS")
            self.assertEqual(receipt["system_version"], "TrueNAS-26.0.0-BETA.3")
            self.assertNotIn(password, out.read_text(encoding="utf-8"))
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
