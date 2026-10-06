#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
import time

from scripts.compute_guest_seed import NONCE_RE, PREFIX, SeedError, validate_token
from scripts.truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for
from scripts.truenas_vm_console_probe import ShellWebSocket

KVM_RE = re.compile(rb"AGENT_DISPATCH_V2_KVM_PRESENT=([01])")
CPU_RE = re.compile(rb"AGENT_DISPATCH_V2_CPU_VMX_SVM=([01])")


def parse_v2_observation(buffer: bytes, nonce: str) -> dict | None:
    validate_token(nonce, NONCE_RE, "nonce")
    nonce_marker = f"{PREFIX}{nonce}".encode("ascii")
    if nonce_marker not in buffer:
        return None
    km = KVM_RE.search(buffer)
    cm = CPU_RE.search(buffer)
    if not km or not cm:
        return None
    kvm = km.group(1) == b"1"
    cpu = cm.group(1) == b"1"
    return {
        "nonce_observed": True,
        "kvm_device_present": kvm,
        "cpu_vmx_or_svm_present": cpu,
        "nested_kvm_observed": kvm and cpu,
        "firecracker_eligible": kvm and cpu,
    }


def observe_v2(
    host: str,
    port: int,
    username: str,
    password: str,
    vm_id: int,
    nonce: str,
    timeout: float,
    tls: bool,
) -> dict:
    validate_token(nonce, NONCE_RE, "nonce")
    receipt = {
        "schema": "truenas-vm-v2-nested-kvm-observation/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "vm_id": vm_id,
        "nested_kvm_observed": False,
        "firecracker_eligible": False,
        "claim_boundary": (
            "observes nested-KVM prerequisites only; Firecracker execution remains authority #277 "
            "and is forbidden unless both /dev/kvm and vmx|svm are observed"
        ),
    }
    ddp = shell = None
    try:
        ddp = WebSocket(host, port, timeout=min(timeout, 8), tls=tls)
        ddp.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ddp, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise RuntimeError(f"DDP connect failed: {connected!r}")
        auth = ddp_call(ddp, "1", "auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": username,
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise RuntimeError(f"authentication failed: {auth!r}")
        token = ddp_call(ddp, "2", "auth.generate_token", [300, {}, False])
        if not isinstance(token, str) or not token:
            raise RuntimeError(f"auth.generate_token returned invalid token: {token!r}")

        shell = ShellWebSocket(host, port, path="/websocket/shell", timeout=min(timeout, 8), tls=tls)
        shell.send_json({"token": token, "options": {"vm_id": vm_id}})
        deadline = time.monotonic() + timeout
        buffer = bytearray()
        while time.monotonic() < deadline:
            _, payload = shell.recv_payload()
            buffer.extend(payload)
            if len(buffer) > 65536:
                del buffer[:-65536]
            observed = parse_v2_observation(bytes(buffer), nonce)
            if observed is not None:
                receipt.update(observed)
                receipt["classification"] = "SUPPORTED"
                receipt["oracleSatisfied"] = True
                receipt["detail"] = (
                    "nested KVM prerequisites observed inside guest"
                    if observed["nested_kvm_observed"]
                    else "guest observation completed; nested KVM prerequisites are not both exposed"
                )
                return receipt
        raise TimeoutError("V2 nested-KVM markers not observed before deadline")
    except Exception as exc:
        receipt["detail"] = f"{type(exc).__name__}: {exc}"
        return receipt
    finally:
        if shell is not None:
            shell.close()
        if ddp is not None:
            ddp.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--username", default="truenas_admin")
    ap.add_argument("--password-file", type=pathlib.Path, required=True)
    ap.add_argument("--vm-id", type=int, required=True)
    ap.add_argument("--nonce", required=True)
    ap.add_argument("--timeout", type=float, default=90)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--out", type=pathlib.Path, required=True)
    a = ap.parse_args()
    try:
        password = a.password_file.read_text(encoding="utf-8").strip()
        result = observe_v2(a.host, a.port, a.username, password, a.vm_id, a.nonce, a.timeout, a.tls)
    except (OSError, SeedError) as exc:
        result = {
            "schema": "truenas-vm-v2-nested-kvm-observation/v1",
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "nested_kvm_observed": False,
            "firecracker_eligible": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
