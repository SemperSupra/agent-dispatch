"""Bounded same-guest WinInspect client used by WinBot.

This module is the single transport seam for the embedded WinInspect daemon.
It preserves the literal-loopback-only authority boundary established by PR #79
and exposes only thin wrappers over the upstream v0.4.4 RPC contract.

It is not a capability registry, broker, or alternate control plane.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import time
import uuid

WININSPECT_BASELINE_VERSION = "0.4.4"
WININSPECT_PROTOCOL_VERSION = "0.3.0"
WININSPECT_SOURCE_COMMIT = "e11fb014e7fca5ddc6e450975f4db45913b452d3"
WININSPECT_PROJECTION_SHA256 = "4ad5e2c29613c79ebe7f3a46aa6a6b071457d4f93b3b7cb43f86642429118257"

_WININSPECT_DAEMON_DIR = os.environ.get(
    "WINBOT_WININSPECT_DIR",
    os.environ.get("WINBOT_SESSION_ROOT", r"C:\WinBot"),
)
_WININSPECTD_PATH = os.path.join(
    _WININSPECT_DAEMON_DIR, "tools", "wininspect", "wininspectd.exe"
)
_WININSPECT_HOST = os.environ.get("WINBOT_WININSPECT_HOST", "127.0.0.1")
_WININSPECT_PORT = int(os.environ.get("WINBOT_WININSPECT_PORT", "1985"))
_WININSPECT_TIMEOUT = float(os.environ.get("WINBOT_WININSPECT_TIMEOUT", "5.0"))
_LOCAL_WININSPECT_HOSTS = {"127.0.0.1", "::1"}
MAX_MESSAGE_SIZE = 10 * 1024 * 1024

_wininspect_daemon_proc = None


def _wininspect_local_bind() -> str:
    """Resolve the configured local host to an equally bounded loopback bind."""
    return "::1" if _WININSPECT_HOST.lower() == "::1" else "127.0.0.1"


def _wininspect_daemon_args() -> list[str]:
    """Return bounded same-guest daemon launch arguments."""
    return [
        _WININSPECTD_PATH,
        "--headless",
        "--bind",
        _wininspect_local_bind(),
        "--no-discovery",
        "--no-mdns",
    ]


def _wininspect_host_is_local() -> bool:
    """Accept only literal loopback; DNS resolution must not widen authority."""
    return _WININSPECT_HOST.lower() in _LOCAL_WININSPECT_HOSTS


def _wininspect_daemon_ready() -> bool:
    """Check whether the bounded same-guest daemon is accepting TCP."""
    if not _wininspect_host_is_local():
        return False
    try:
        with socket.create_connection(
            (_WININSPECT_HOST, _WININSPECT_PORT), timeout=1.0
        ):
            return True
    except OSError:
        return False


def _ensure_wininspect_daemon() -> bool:
    """Start the bounded same-guest daemon if necessary."""
    global _wininspect_daemon_proc

    if not _wininspect_host_is_local():
        return False
    if _wininspect_daemon_ready():
        return True
    if (
        _wininspect_daemon_proc is not None
        and _wininspect_daemon_proc.poll() is None
    ):
        return True
    if not os.path.exists(_WININSPECTD_PATH):
        return False

    try:
        _wininspect_daemon_proc = subprocess.Popen(
            _wininspect_daemon_args(),
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if _wininspect_daemon_ready():
                return True
            if _wininspect_daemon_proc.poll() is not None:
                return False
            time.sleep(0.25)
        return False
    except Exception:
        return False


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """Receive exactly size bytes or fail closed."""
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("WinInspect connection closed while reading frame")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_frame(sock: socket.socket) -> dict:
    """Read one uncompressed length-prefixed WinInspect JSON frame."""
    header = _recv_exact(sock, 4)
    raw_length = struct.unpack("!I", header)[0]
    length = raw_length & 0x7FFFFFFF
    if length > MAX_MESSAGE_SIZE:
        raise RuntimeError(f"WinInspect frame too large: {length}")
    if raw_length & 0x80000000:
        # WinBot never negotiates compressed responses. Accepting a compressed
        # frame without implementing the upstream zlib framing would create an
        # ambiguous parser path, so fail closed instead.
        raise RuntimeError("Compressed WinInspect frames are not negotiated by WinBot")
    payload = _recv_exact(sock, length)
    return json.loads(payload.decode("utf-8"))


def request(method: str, params: dict | None = None) -> dict:
    """Send one RPC request through the bounded same-guest TCP transport."""
    if not _wininspect_host_is_local():
        raise RuntimeError(
            "Remote WinInspect transport is not authorized by this client; "
            "configure a literal loopback host or add an authenticated remote transport."
        )
    if not _ensure_wininspect_daemon():
        raise RuntimeError("Local WinInspect daemon is not ready")

    request_id = f"winbot-{uuid.uuid4().hex[:12]}"
    rpc_params = dict(params or {})
    # v0.4.4 uses protocol 0.3.0 and accepts a missing version only through
    # its legacy-client compatibility path. Every WinBot request opens a new
    # connection, so bind the first request on every connection explicitly.
    rpc_params.setdefault("protocol_version", WININSPECT_PROTOCOL_VERSION)
    payload = {"id": request_id, "method": method, "params": rpc_params}
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_MESSAGE_SIZE:
        raise RuntimeError(f"WinInspect request too large: {len(data)}")

    with socket.create_connection(
        (_WININSPECT_HOST, _WININSPECT_PORT), timeout=_WININSPECT_TIMEOUT
    ) as sock:
        sock.settimeout(_WININSPECT_TIMEOUT)
        _read_frame(sock)  # daemon hello / handshake frame
        sock.sendall(struct.pack("!I", len(data)) + data)
        response = _read_frame(sock)

    if not response.get("ok"):
        error = response.get("error") or {}
        raise RuntimeError(
            str(error.get("message") or error or "WinInspect request failed")
        )
    return response.get("result") or {}


# Thin v0.4.4 contract wrappers. These intentionally do not reinterpret
# upstream semantics or create a second capability model.

def capabilities() -> dict:
    return request("daemon.capabilities")


def list_windows() -> list:
    result = request("window.listTop")
    return result if isinstance(result, list) else []


def window_info(hwnd: str) -> dict:
    return request("window.getInfo", {"hwnd": hwnd})


def find_windows(title_regex: str = ".*", class_regex: str = ".*") -> list:
    result = request(
        "window.findRegex",
        {"title_regex": title_regex, "class_regex": class_regex},
    )
    return result if isinstance(result, list) else []


def ensure_foreground(hwnd: str) -> dict:
    return request("window.ensureForeground", {"hwnd": hwnd})


def inspect_ui(hwnd: str) -> list:
    result = request("ui.inspect", {"hwnd": hwnd})
    return result if isinstance(result, list) else []


def invoke_ui(hwnd: str, automation_id: str) -> dict:
    return request(
        "ui.invoke",
        {"hwnd": hwnd, "automation_id": automation_id},
    )


_BUTTONS = {"left": 0, "right": 1, "middle": 2}


def mouse_click(x: int, y: int, button: str = "left") -> dict:
    if button not in _BUTTONS:
        raise ValueError(f"unsupported mouse button: {button}")
    return request(
        "input.mouseClick",
        {"x": x, "y": y, "button": _BUTTONS[button]},
    )


def type_text(text: str) -> dict:
    return request("input.text", {"text": text})


def hotkey(keys: str) -> dict:
    return request("input.hotkey", {"keys": keys})
