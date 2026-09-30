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
POOL = ROOT / "scripts" / "truenas_middleware_pool_probe.py"
LIFECYCLE = ROOT / "scripts" / "truenas_middleware_app_lifecycle_probe.py"


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

    def test_t3_pool_client_waits_for_job_and_proves_membership(self):
        peer = SyntheticWebSocketPeer()
        errors = []
        password = "synthetic-ephemeral-9264"

        def expect_call(conn, method):
            msg = peer.recv_json(conn)
            self.assertEqual(msg["msg"], "method")
            self.assertEqual(msg["method"], method)
            return msg

        def result(conn, msg, value):
            peer.send_json(conn, {"id": msg["id"], "msg": "result", "result": value})

        def server():
            try:
                with peer.accept_websocket() as conn:
                    msg = peer.recv_json(conn)
                    self.assertEqual(msg, {"msg": "connect", "version": "1", "support": ["1"]})
                    peer.send_json(conn, {"msg": "connected", "session": "synthetic"})

                    msg = expect_call(conn, "auth.login_ex")
                    self.assertEqual(msg["params"][0]["password"], password)
                    result(conn, msg, {"response_type": "SUCCESS"})

                    msg = expect_call(conn, "system.version")
                    result(conn, msg, "TrueNAS-26.0.0-BETA.3")

                    msg = expect_call(conn, "boot.get_disks")
                    result(conn, msg, ["vda"])

                    msg = expect_call(conn, "disk.details")
                    self.assertEqual(msg["params"], [])
                    result(conn, msg, {
                        "used": [{"name": "vda", "devname": "vda"}],
                        "unused": [
                            {"name": "vdb", "devname": "vdb", "serial": "RDTE_DATA_0", "size": 8_589_934_592},
                            {"name": "vdc", "devname": "vdc", "serial": "RDTE_DATA_1", "size": 8_589_934_592},
                            {"name": "fd0", "devname": "fd0", "serial": "", "size": 4096},
                        ],
                    })

                    msg = expect_call(conn, "pool.query")
                    self.assertEqual(msg["params"], [[["name", "=", "rdtepool"]]])
                    result(conn, msg, [])

                    msg = expect_call(conn, "pool.create")
                    self.assertEqual(msg["params"], [{
                        "name": "rdtepool",
                        "encryption": False,
                        "allow_duplicate_serials": False,
                        "topology": {
                            "data": [{
                                "type": "MIRROR",
                                "disks": ["vdb", "vdc"],
                            }],
                        },
                    }])
                    result(conn, msg, 42)

                    msg = expect_call(conn, "core.get_jobs")
                    self.assertEqual(msg["params"][0], [["id", "=", 42]])
                    result(conn, msg, {
                        "id": 42,
                        "state": "RUNNING",
                        "progress": {"percent": 50, "description": "Creating pool"},
                    })

                    msg = expect_call(conn, "core.get_jobs")
                    result(conn, msg, {
                        "id": 42,
                        "state": "SUCCESS",
                        "progress": {"percent": 100, "description": "Pool created"},
                        "result": {"id": 7, "name": "rdtepool"},
                    })

                    msg = expect_call(conn, "pool.query")
                    self.assertEqual(msg["params"], [
                        [["name", "=", "rdtepool"]],
                        {"get": True},
                    ])
                    result(conn, msg, {
                        "id": 7,
                        "name": "rdtepool",
                        "guid": "synthetic",
                        "status": "ONLINE",
                        "healthy": True,
                        "path": "/mnt/rdtepool",
                    })

                    msg = expect_call(conn, "pool.get_disks")
                    self.assertEqual(msg["params"], [7])
                    result(conn, msg, ["vdb", "vdc"])
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
            out = td / "pool.json"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(POOL),
                    "--port", str(peer.port),
                    "--password-file", str(password_file),
                    "--out", str(out),
                    "--timeout", "2",
                    "--job-timeout", "8",
                ],
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            receipt = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(receipt["oracleSatisfied"], receipt)
            self.assertEqual(receipt["classification"], "SUPPORTED")
            self.assertEqual(receipt["selected_data_disks"], ["vdb", "vdc"])
            self.assertEqual([d["serial"] for d in receipt["owned_data_disks"]], ["RDTE_DATA_0", "RDTE_DATA_1"])
            self.assertEqual(len(receipt["unused_disks"]), 3)
            self.assertEqual(receipt["pool_disks"], ["vdb", "vdc"])
            self.assertEqual(receipt["job_state"], "SUCCESS")
            self.assertFalse(receipt["create_contract"]["allow_duplicate_serials"])
            self.assertEqual(receipt["pool"]["status"], "ONLINE")
            self.assertTrue(receipt["pool"]["healthy"])
            self.assertNotIn(password, out.read_text(encoding="utf-8"))
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_t3_uses_public_disk_details_not_private_get_unused(self):
        text = POOL.read_text(encoding="utf-8")
        self.assertIn('"disk.details"', text)
        self.assertNotIn('"disk.get_unused"', text)
        self.assertIn('disk_details["unused"]', text)


    def test_t5_lifecycle_contract_is_exact_version_and_digest_pinned(self):
        text = LIFECYCLE.read_text(encoding="utf-8")
        self.assertNotIn("EXPECTED_VERSION =", text)
        self.assertIn('p.add_argument("--expected-version", required=True)', text)
        self.assertIn('"expected_version": a.expected_version', text)
        self.assertIn('APP_NAME = "rdte-t4-probe"', text)
        self.assertIn('APP_IMAGE = "nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10"', text)
        self.assertNotIn('APP_IMAGE = "nginx:1.27-alpine"', text)
        for method in (
            "app.stop",
            "app.start",
            "app.update",
            "app.config",
            "app.redeploy",
            "app.delete",
        ):
            self.assertIn(f'"{method}"', text)
        self.assertIn('"RDTE_GENERATION": "2"', text)
        self.assertIn('"remove_images": True', text)
        self.assertIn('"remove_ix_volumes": True', text)
        self.assertIn('"post_delete_query"', text)
        cp = subprocess.run(
            [sys.executable, "-m", "py_compile", str(LIFECYCLE)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_t5_lifecycle_round_trip(self):
        peer = SyntheticWebSocketPeer()
        errors = []
        password = "synthetic-ephemeral-9264"

        def expect_call(conn, method):
            msg = peer.recv_json(conn)
            self.assertEqual(msg["msg"], "method")
            self.assertEqual(msg["method"], method)
            return msg

        def result(conn, msg, value):
            peer.send_json(conn, {"id": msg["id"], "msg": "result", "result": value})

        def app(state):
            running = state == "RUNNING"
            return {
                "id": "rdte-t4-probe",
                "name": "rdte-t4-probe",
                "state": state,
                "custom_app": True,
                "active_workloads": {
                    "containers": 1 if running else 0,
                    "container_details": [{
                        "id": "synthetic-nginx",
                        "service_name": "web",
                        "image": "nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10",
                        "state": "running",
                    }] if running else [],
                },
            }

        def job_success(conn, job_id, result_value=None):
            msg = expect_call(conn, "core.get_jobs")
            self.assertEqual(msg["params"][0], [["id", "=", job_id]])
            result(conn, msg, {
                "id": job_id,
                "state": "SUCCESS",
                "progress": {"percent": 100, "description": "done"},
                "result": result_value,
            })

        def server():
            try:
                with peer.accept_websocket() as conn:
                    msg = peer.recv_json(conn)
                    self.assertEqual(
                        msg, {"msg": "connect", "version": "1", "support": ["1"]}
                    )
                    peer.send_json(conn, {"msg": "connected", "session": "synthetic"})

                    msg = expect_call(conn, "auth.login_ex")
                    self.assertEqual(msg["params"][0]["password"], password)
                    result(conn, msg, {"response_type": "SUCCESS"})

                    msg = expect_call(conn, "system.version")
                    result(conn, msg, "TrueNAS-26.0.0-BETA.3")

                    msg = expect_call(conn, "app.query")
                    result(conn, msg, app("RUNNING"))

                    msg = expect_call(conn, "app.stop")
                    self.assertEqual(msg["params"], ["rdte-t4-probe"])
                    result(conn, msg, 31)
                    job_success(conn, 31)
                    msg = expect_call(conn, "app.query")
                    result(conn, msg, app("STOPPED"))

                    msg = expect_call(conn, "app.start")
                    self.assertEqual(msg["params"], ["rdte-t4-probe"])
                    result(conn, msg, 32)
                    job_success(conn, 32)
                    msg = expect_call(conn, "app.query")
                    result(conn, msg, app("RUNNING"))

                    msg = expect_call(conn, "app.update")
                    self.assertEqual(msg["params"][0], "rdte-t4-probe")
                    update = msg["params"][1]
                    self.assertEqual(
                        update["custom_compose_config"]["services"]["web"]["image"],
                        "nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10",
                    )
                    self.assertEqual(
                        update["custom_compose_config"]["services"]["web"]["environment"]["RDTE_GENERATION"],
                        "2",
                    )
                    result(conn, msg, 33)
                    job_success(conn, 33)

                    msg = expect_call(conn, "app.config")
                    result(conn, msg, update["custom_compose_config"])

                    msg = expect_call(conn, "app.query")
                    result(conn, msg, app("RUNNING"))

                    msg = expect_call(conn, "app.redeploy")
                    self.assertEqual(msg["params"], ["rdte-t4-probe"])
                    result(conn, msg, 34)
                    job_success(conn, 34)
                    msg = expect_call(conn, "app.query")
                    result(conn, msg, app("RUNNING"))

                    msg = expect_call(conn, "app.stop")
                    result(conn, msg, 35)
                    job_success(conn, 35)
                    msg = expect_call(conn, "app.query")
                    result(conn, msg, app("STOPPED"))

                    msg = expect_call(conn, "app.delete")
                    self.assertEqual(msg["params"][0], "rdte-t4-probe")
                    self.assertEqual(msg["params"][1], {
                        "remove_images": True,
                        "remove_ix_volumes": True,
                        "force_remove_custom_app": False,
                    })
                    result(conn, msg, 36)
                    job_success(conn, 36, True)

                    msg = expect_call(conn, "app.query")
                    self.assertEqual(
                        msg["params"], [[["id", "=", "rdte-t4-probe"]]]
                    )
                    result(conn, msg, [])
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
            out = td / "lifecycle.json"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(LIFECYCLE),
                    "--port", str(peer.port),
                    "--password-file", str(password_file),
                    "--out", str(out),
                    "--expected-version", "TrueNAS-26.0.0-BETA.3",
                    "--timeout", "2",
                    "--job-timeout", "8",
                    "--state-timeout", "8",
                ],
                text=True,
                capture_output=True,
                timeout=20,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            receipt = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(receipt["oracleSatisfied"], receipt)
            self.assertEqual(receipt["classification"], "SUPPORTED")
            self.assertEqual(receipt["system_version"], "TrueNAS-26.0.0-BETA.3")
            self.assertEqual(receipt["app_image"], "nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10")
            self.assertEqual(
                receipt["states"],
                ["RUNNING", "STOPPED", "RUNNING", "RUNNING", "RUNNING", "STOPPED"],
            )
            self.assertEqual(
                receipt["config_after_update"]["services"]["web"]["environment"]["RDTE_GENERATION"],
                "2",
            )
            self.assertEqual(receipt["post_delete_query"], [])
            self.assertNotIn(password, out.read_text(encoding="utf-8"))
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])




if __name__ == "__main__":
    unittest.main()
    unittest.main()
