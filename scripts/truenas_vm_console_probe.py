#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import struct
import time

from scripts.compute_guest_seed import NONCE_RE, PREFIX, SeedError, validate_token
from scripts.truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


class ShellWebSocket(WebSocket):
    def send_binary(self, payload: bytes) -> None:
        self._send_frame(0x2, payload)

    def recv_payload(self) -> tuple[int, bytes]:
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
            if opcode in {0x1, 0x2}:
                return opcode, payload


def nonce_marker(nonce: str) -> bytes:
    validate_token(nonce, NONCE_RE, "nonce")
    return f"{PREFIX}{nonce}".encode("ascii")


def exact_marker(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise SeedError("marker violates exact console-marker contract")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SeedError("marker must be ASCII") from exc
    if any(b < 0x20 or b > 0x7E for b in encoded):
        raise SeedError("marker contains non-printable ASCII")
    return encoded


def _observe_nonce_frames(shell: ShellWebSocket, marker: bytes, timeout: float) -> dict:
    """Observe VM-console frames until the exact marker or the overall deadline.

    The websocket itself intentionally keeps a short socket timeout so a dead
    transport remains responsive.  A quiet guest console can legitimately be
    idle longer than that while firmware/kernel/userspace boots, so per-read
    TimeoutError is transient here; only the caller's overall deadline is an
    oracle failure.
    """
    buffer = bytearray()
    deadline = time.monotonic() + timeout
    connected_shell = False
    idle_read_timeouts = 0
    while time.monotonic() < deadline:
        try:
            opcode, payload = shell.recv_payload()
        except TimeoutError:
            idle_read_timeouts += 1
            continue

        if opcode == 0x1:
            try:
                message = json.loads(payload.decode())
            except Exception:
                message = None
            if isinstance(message, dict) and message.get("msg") == "connected":
                connected_shell = True
            continue

        buffer.extend(payload)
        if len(buffer) > 65536:
            del buffer[:-65536]
        if marker in buffer:
            return {
                "found": True,
                "shell_connected": connected_shell,
                "idle_read_timeouts": idle_read_timeouts,
                "console_tail": bytes(buffer[-4096:]).decode("utf-8", "replace"),
            }

    return {
        "found": False,
        "shell_connected": connected_shell,
        "idle_read_timeouts": idle_read_timeouts,
        "console_tail": bytes(buffer[-4096:]).decode("utf-8", "replace"),
    }


def observe_console_marker(
    host: str,
    port: int,
    password: str,
    vm_id: int,
    marker_text: str,
    timeout: float,
    tls: bool,
    *,
    schema: str = "truenas-vm-console-marker/v1",
    claim_boundary: str = "exact external guest-console marker only",
    success_detail: str = "exact caller-supplied marker observed through supported TrueNAS VM console websocket",
) -> dict:
    marker = exact_marker(marker_text)
    receipt = {
        "schema": schema,
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "vm_id": vm_id,
        "marker": marker.decode(),
        "transport": "wss:/websocket/shell" if tls else "ws:/websocket/shell",
        "claim_boundary": claim_boundary,
    }
    ddp = shell = None
    started = time.monotonic()
    try:
        ddp = WebSocket(host, port, timeout=min(timeout, 8), tls=tls)
        ddp.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ddp, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise RuntimeError(f"DDP connect failed: {connected!r}")
        auth = ddp_call(ddp, "1", "auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": "truenas_admin",
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise RuntimeError(f"authentication failed: {auth!r}")
        token = ddp_call(ddp, "2", "auth.generate_token", [300, {}, False])
        if not isinstance(token, str) or not token:
            raise RuntimeError(f"auth.generate_token returned invalid token: {token!r}")

        shell = ShellWebSocket(host, port, path="/websocket/shell", timeout=min(timeout, 8), tls=tls)
        shell.send_json({"token": token, "options": {"vm_id": vm_id}})
        observed = _observe_nonce_frames(shell, marker, timeout)
        receipt.update({
            "shell_connected": observed["shell_connected"],
            "idle_read_timeouts": observed["idle_read_timeouts"],
            "console_tail": observed["console_tail"],
        })
        if observed["found"]:
            receipt.update({
                "classification": "SUPPORTED",
                "oracleSatisfied": True,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "detail": success_detail,
            })
            return receipt
        raise TimeoutError("exact console marker not observed before console deadline")
    except Exception as exc:
        receipt["detail"] = f"{type(exc).__name__}: {exc}"
        return receipt
    finally:
        if shell is not None:
            shell.close()
        if ddp is not None:
            ddp.close()


def observe_console_nonce(
    host: str,
    port: int,
    password: str,
    vm_id: int,
    nonce: str,
    timeout: float,
    tls: bool,
) -> dict:
    marker = nonce_marker(nonce).decode()
    receipt = observe_console_marker(
        host,
        port,
        password,
        vm_id,
        marker,
        timeout,
        tls,
        schema="truenas-vm-console-nonce/v1",
        claim_boundary="external guest-console nonce only; no nested-KVM or guest capability claim",
        success_detail="exact injected V1 nonce observed through supported TrueNAS VM console websocket",
    )
    receipt["nonce_marker"] = marker
    receipt.pop("marker", None)
    return receipt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--password-file", type=pathlib.Path, required=True)
    ap.add_argument("--vm-id", type=int, required=True)
    ap.add_argument("--nonce", required=True)
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--out", type=pathlib.Path, required=True)
    a = ap.parse_args()
    try:
        password = a.password_file.read_text(encoding="utf-8").strip()
        result = observe_console_nonce(a.host, a.port, password, a.vm_id, a.nonce, a.timeout, a.tls)
    except (OSError, SeedError) as exc:
        result = {
            "schema": "truenas-vm-console-nonce/v1",
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
