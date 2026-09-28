import base64
import hashlib
import json
import socket
import struct
import sys
import tempfile
import threading
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PVE = ROOT / "scripts" / "gha_kvm_proxmox_rdte.sh"
TRUENAS = ROOT / "scripts" / "gha_kvm_truenas_rdte.sh"
TRUENAS_RPC = ROOT / "scripts" / "truenas_installer_rpc_probe.py"
WORKFLOW = ROOT / ".github" / "workflows" / "gha-kvm-system-rdte.yml"


class SystemRdteContractTests(unittest.TestCase):
    def test_shell_syntax(self):
        for path in (PVE, TRUENAS):
            cp = subprocess.run(["bash", "-n", str(path)], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, f"{path}: {cp.stderr}")

    def test_common_evidence_contract(self):
        for path in (PVE, TRUENAS):
            text = path.read_text(encoding="utf-8")
            self.assertIn("gha-kvm-system-lab/v1", text)
            self.assertIn("oracleSatisfied", text)
            self.assertIn("classification", text)
            self.assertIn("passwordless sudo KVM boundary", text)
            self.assertIn("SKIPPED_GUARDRAIL", text)
            self.assertIn('rm -rf -- "$STATE_DIR"', text)

    def test_no_private_runner_or_secret_surface(self):
        forbidden = [
            "self-hosted",
            "garm-provider-truenas-private",
            "agent-dispatch-private.git",
            "ghp_",
            "github_pat_",
            "ACTIONS_RUNNER_INPUT_TOKEN",
        ]
        for path in (PVE, TRUENAS):
            text = path.read_text(encoding="utf-8")
            for needle in forbidden:
                self.assertNotIn(needle, text)

    def test_proxmox_is_pinned_and_uses_vendor_auto_install_contract(self):
        text = PVE.read_text(encoding="utf-8")
        self.assertIn("proxmox-ve_9.2-1.iso", text)
        self.assertIn(
            "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c",
            text,
        )
        self.assertIn('mode = "iso"', text)
        self.assertIn('source = "from-dhcp"', text)
        self.assertIn('filesystem = "ext4"', text)
        self.assertIn('disk-list = ["sda"]', text)
        self.assertIn("/api2/json/version", text)
        self.assertNotIn("xdotool", text)

    def test_truenas_is_pinned_and_digest_sidecar_is_required(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn("TrueNAS-26.0.0-BETA.3.iso", text)
        self.assertIn("TrueNAS-26.0.0-BETA.3.iso.sha256", text)
        self.assertIn("RAM_MIB=8192", text)
        self.assertIn("installer-boot", text)
        self.assertIn("installer-rpc", text)
        self.assertIn("truenas_installer_rpc_probe.py", text)
        self.assertNotIn("nightly", text.lower())
        self.assertNotIn("xdotool", text)

    def test_no_literal_escaped_shell_parameter_expansions(self):
        needle = chr(92) + "$" + "{"
        for path in (PVE, TRUENAS):
            self.assertNotIn(needle, path.read_text(encoding="utf-8"))


    def test_truenas_rpc_probe_is_dependency_free_and_read_only(self):
        text = TRUENAS_RPC.read_text(encoding="utf-8")
        for method in ("is_adopted", "system_info", "list_disks", "list_network_interfaces"):
            self.assertIn(method, text)
        self.assertNotIn('"install"', text)
        self.assertNotIn("pip install", text)
        cp = subprocess.run(
            ["python3", "-m", "py_compile", str(TRUENAS_RPC)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_workflow_scopes_heavy_targets(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("fetch-depth: 0", text)
        self.assertIn("needs.changes.outputs.proxmox", text)
        self.assertIn("needs.changes.outputs.truenas", text)
        self.assertIn("DISPATCH_TARGET", text)
        self.assertIn("BEFORE_SHA:", text)
        self.assertIn('git diff --name-only "$BEFORE_SHA" "$AFTER_SHA"', text)
        self.assertIn("scripts/truenas_installer_rpc_probe.py", text)

    def test_truenas_t1_requires_local_rpc_probe(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn("missing TrueNAS installer RPC probe", text)

    def test_truenas_rpc_probe_protocol_round_trip(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        errors = []

        def read_exact(conn, count):
            parts = []
            remaining = count
            while remaining:
                part = conn.recv(remaining)
                if not part:
                    raise EOFError("synthetic websocket peer closed")
                parts.append(part)
                remaining -= len(part)
            return b"".join(parts)

        def recv_json(conn):
            b1, b2 = read_exact(conn, 2)
            opcode = b1 & 0x0F
            if opcode == 0x8:
                return None
            if opcode != 0x1:
                raise AssertionError(f"unexpected client opcode {opcode}")
            masked = bool(b2 & 0x80)
            if not masked:
                raise AssertionError("client websocket frame must be masked")
            size = b2 & 0x7F
            if size == 126:
                size = struct.unpack("!H", read_exact(conn, 2))[0]
            elif size == 127:
                size = struct.unpack("!Q", read_exact(conn, 8))[0]
            mask = read_exact(conn, 4)
            payload = read_exact(conn, size)
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            return json.loads(payload.decode())

        def send_json(conn, value):
            payload = json.dumps(value, separators=(",", ":")).encode()
            if len(payload) < 126:
                header = bytes([0x81, len(payload)])
            else:
                header = bytes([0x81, 126]) + struct.pack("!H", len(payload))
            conn.sendall(header + payload)

        def server():
            try:
                conn, _ = listener.accept()
                with conn:
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
                    answers = [
                        ("is_adopted", False),
                        ("system_info", {"version": "synthetic", "installation_running": False}),
                        ("list_disks", [{"name": "sda", "size": 1024}]),
                        ("list_network_interfaces", [{"name": "eth0"}]),
                    ]
                    for method, result in answers:
                        request_obj = recv_json(conn)
                        if request_obj["method"] != method:
                            raise AssertionError(
                                f"expected {method}, got {request_obj['method']}"
                            )
                        send_json(
                            conn,
                            {
                                "jsonrpc": "2.0",
                                "id": request_obj["id"],
                                "result": result,
                            },
                        )
            except Exception as exc:
                errors.append(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / "rpc.json"
            cp = subprocess.run(
                [
                    sys.executable,
                    str(TRUENAS_RPC),
                    "--port",
                    str(port),
                    "--out",
                    str(out),
                    "--timeout",
                    "2",
                ],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(payload["oracleSatisfied"])
            self.assertEqual(payload["classification"], "SUPPORTED")
            self.assertFalse(payload["methods"]["is_adopted"])
            self.assertEqual(payload["methods"]["system_info"]["version"], "synthetic")
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_truenas_t1_requires_real_rpc_not_hostfwd_tcp(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn("try_rpc_discovery", text)
        self.assertIn("RPC_DISCOVERY_OK", text)
        self.assertIn("installer_rpc_hostfwd_accepted", text)
        self.assertNotIn("RPC_REACHABLE", text)
        self.assertIn("completed vendor WebSocket/JSON-RPC discovery exchange", text)


if __name__ == "__main__":
    unittest.main()
