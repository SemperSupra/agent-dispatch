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
QEMU_TOPOLOGY = ROOT / "scripts" / "gha_qemu_t3_topology_probe.py"
TRUENAS_INSTALL = ROOT / "scripts" / "truenas_installer_rpc_install.py"
TRUENAS_MIDDLEWARE = ROOT / "scripts" / "truenas_middleware_ddp_probe.py"
TRUENAS_POOL = ROOT / "scripts" / "truenas_middleware_pool_probe.py"
TRUENAS_APP = ROOT / "scripts" / "truenas_middleware_app_probe.py"


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

    def test_future_truenas_mutating_clients_compile_and_refuse_ambiguity(self):
        install = TRUENAS_INSTALL.read_text(encoding="utf-8")
        middleware = TRUENAS_MIDDLEWARE.read_text(encoding="utf-8")
        self.assertIn("expected exactly one non-removable disk", install)
        self.assertIn("expected exactly one non-loopback interface", install)
        self.assertIn('"truenas_admin"', install)
        self.assertIn('"auth.login_ex"', middleware)
        self.assertIn('"PASSWORD_PLAIN"', middleware)
        self.assertIn('"system.version"', middleware)
        self.assertIn('"system.info"', middleware)
        for path in (TRUENAS_INSTALL, TRUENAS_MIDDLEWARE):
            cp = subprocess.run(
                ["python3", "-m", "py_compile", str(path)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_truenas_t2_keeps_install_and_middleware_oracles_separate(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn("t0|t1|t2", text)
        self.assertIn("installer_install_completed", text)
        self.assertIn("installed_middleware_authenticated", text)
        self.assertIn("truenas_installer_rpc_install.py", text)
        self.assertIn("truenas_middleware_ddp_probe.py", text)
        self.assertIn('NIC_MAC="52:54:00:54:4e:26"', text)

    def test_truenas_install_rpc_uses_one_positional_object(self):
        text = TRUENAS_INSTALL.read_text(encoding="utf-8")
        self.assertIn('rpc_call(ws, "install", 4, [install_params]', text)

    def test_truenas_t3_real_harness_contract(self):
        text = TRUENAS.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("t0|t1|t2|t3|t4", text)
        self.assertIn('DATA_DISK_SIZE="8G"', text)
        self.assertIn("DATA_DISK_COUNT=2", text)
        self.assertIn('DATA_POOL_NAME="rdtepool"', text)
        self.assertIn('DATA_SERIAL_PREFIX="RDTE_DATA_"', text)
        self.assertEqual(text.count("mac=$NIC_MAC,addr=0x3"), 2)
        self.assertIn("if=none,id=rdteboot", text)
        self.assertIn("id=rdte-boot,addr=0x4,bootindex=1", text)
        self.assertIn("-boot strict=on", text)
        self.assertNotIn("-boot order=c", text)
        self.assertIn("if=none,id=$drive_id", text)
        self.assertIn("pci_slot=$((5 + index))", text)
        self.assertIn(
            "virtio-blk-pci,drive=$drive_id,serial=${DATA_SERIAL_PREFIX}${index},addr=0x${pci_slot}",
            text,
        )
        self.assertIn('--data-serial-prefix "$DATA_SERIAL_PREFIX"', text)
        self.assertIn("data${index}.qcow2", text)
        self.assertIn('"${DATA_DRIVE_ARGS[@]}"', text)
        self.assertIn("truenas_middleware_pool_probe.py", text)
        self.assertIn('"data_pool_created"', text)
        self.assertIn('"data_pool"', text)
        self.assertIn("--rung t4", workflow)
        self.assertIn("scripts/truenas_middleware_pool_probe.py", workflow)
        shell_check = subprocess.run(["bash", "-n", str(TRUENAS)], text=True, capture_output=True)
        self.assertEqual(shell_check.returncode, 0, shell_check.stderr)
        py_check = subprocess.run(["python3", "-m", "py_compile", str(TRUENAS_POOL)], text=True, capture_output=True)
        self.assertEqual(py_check.returncode, 0, py_check.stderr)

    def test_truenas_t4_apps_contract(self):
        text = TRUENAS.read_text(encoding="utf-8")
        app = TRUENAS_APP.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('APP_RESULT_JSON=""', text)
        self.assertIn("apps_runtime_exercised", text)
        self.assertIn("truenas_middleware_app_probe.py", text)
        self.assertIn("docker.update", app)
        self.assertIn("docker.status", app)
        self.assertIn("truenas.entitlements.check", app)
        self.assertIn('"APPS"', app)
        self.assertIn("app.create", app)
        self.assertIn("app.query", app)
        self.assertIn('payload["docker_update_result"]', app)
        self.assertIn('payload["app_create_result"]', app)
        self.assertIn('"nginx:1.27-alpine"', app)
        self.assertIn('"state") == "RUNNING"', app)
        self.assertIn('--rung t4', workflow)
        py = subprocess.run(
            ["python3", "-m", "py_compile", str(TRUENAS_APP)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(py.returncode, 0, py.stderr)

    def test_qemu_t3_topology_is_a_cheap_separate_oracle(self):
        probe = QEMU_TOPOLOGY.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('"rdte-nic"', probe)
        self.assertIn('"rdte-boot"', probe)
        self.assertIn('"bootindex": 1', probe)
        self.assertIn('"RDTE_DATA_0"', probe)
        self.assertIn('"RDTE_DATA_1"', probe)
        self.assertIn('"query-pci"', probe)
        self.assertIn('"qom-get"', probe)
        self.assertIn("qemu-t3-topology:", workflow)
        self.assertIn("needs.changes.outputs.qemu_topology", workflow)
        self.assertNotIn(
            "scripts/gha_qemu_t3_topology_probe.py)",
            workflow.split("truenas=true", 1)[0],
        )
        py = subprocess.run(
            ["python3", "-m", "py_compile", str(QEMU_TOPOLOGY)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(py.returncode, 0, py.stderr)

if __name__ == "__main__":
    unittest.main()
