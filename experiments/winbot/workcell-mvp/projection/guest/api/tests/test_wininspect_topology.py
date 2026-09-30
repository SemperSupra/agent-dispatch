"""Focused tests for the bounded WinInspect same-guest TCP topology."""

import json
import struct

from core import wininspect


def test_embedded_wininspect_launch_is_loopback_only(monkeypatch):
    monkeypatch.setattr(wininspect, "_WININSPECT_HOST", "127.0.0.1")
    args = wininspect._wininspect_daemon_args()

    assert args[0] == wininspect._WININSPECTD_PATH
    assert args[1:] == [
        "--headless",
        "--bind",
        "127.0.0.1",
        "--no-discovery",
        "--no-mdns",
    ]



def test_embedded_wininspect_preserves_ipv6_loopback(monkeypatch):
    monkeypatch.setattr(wininspect, "_WININSPECT_HOST", "::1")
    args = wininspect._wininspect_daemon_args()

    bind_index = args.index("--bind") + 1
    assert args[bind_index] == "::1"


def test_remote_wininspect_host_never_self_launches_local_daemon(monkeypatch):
    monkeypatch.setattr(wininspect, "_WININSPECT_HOST", "192.168.50.25")
    monkeypatch.setattr(wininspect, "_wininspect_daemon_ready", lambda: False)
    monkeypatch.setattr(wininspect, "_wininspect_daemon_proc", None)
    monkeypatch.setattr(wininspect.os.path, "exists", lambda _: True)

    def unexpected_popen(*args, **kwargs):
        raise AssertionError("remote WinInspect configuration must not self-launch a local daemon")

    monkeypatch.setattr(wininspect.subprocess, "Popen", unexpected_popen)

    assert wininspect._ensure_wininspect_daemon() is False


def test_remote_wininspect_host_is_never_probed(monkeypatch):
    monkeypatch.setattr(wininspect, "_WININSPECT_HOST", "192.168.50.25")

    def unexpected_connect(*args, **kwargs):
        raise AssertionError("remote WinInspect host must not be probed by the loopback client")

    monkeypatch.setattr(wininspect.socket, "create_connection", unexpected_connect)

    assert wininspect._wininspect_daemon_ready() is False


def test_remote_wininspect_request_fails_closed_before_socket(monkeypatch):
    monkeypatch.setattr(wininspect, "_WININSPECT_HOST", "192.168.50.25")

    def unexpected_connect(*args, **kwargs):
        raise AssertionError("remote WinInspect request must fail before opening a socket")

    monkeypatch.setattr(wininspect.socket, "create_connection", unexpected_connect)

    try:
        wininspect.request("daemon.capabilities")
    except RuntimeError as exc:
        assert "Remote WinInspect transport is not authorized" in str(exc)
    else:
        raise AssertionError("remote WinInspect request did not fail closed")


def test_remote_wininspect_ignores_stale_local_daemon_process(monkeypatch):
    monkeypatch.setattr(wininspect, "_WININSPECT_HOST", "192.168.50.25")

    class RunningProcess:
        def poll(self):
            return None

    monkeypatch.setattr(wininspect, "_wininspect_daemon_proc", RunningProcess())

    assert wininspect._ensure_wininspect_daemon() is False


def test_localhost_name_is_not_treated_as_loopback_authority(monkeypatch):
    monkeypatch.setattr(wininspect, "_WININSPECT_HOST", "localhost")

    def unexpected_connect(*args, **kwargs):
        raise AssertionError("hostname resolution must not widen literal-loopback authority")

    monkeypatch.setattr(wininspect.socket, "create_connection", unexpected_connect)

    assert wininspect._wininspect_host_is_local() is False
    assert wininspect._wininspect_daemon_ready() is False




def test_v044_baseline_identity_is_pinned():
    assert wininspect.WININSPECT_BASELINE_VERSION == "0.4.4"
    assert wininspect.WININSPECT_PROTOCOL_VERSION == "0.3.0"
    assert wininspect.WININSPECT_SOURCE_COMMIT == "e11fb014e7fca5ddc6e450975f4db45913b452d3"
    assert (
        wininspect.WININSPECT_PROJECTION_SHA256
        == "4ad5e2c29613c79ebe7f3a46aa6a6b071457d4f93b3b7cb43f86642429118257"
    )


def test_v044_semantic_wrappers_use_upstream_rpc_contract(monkeypatch):
    calls = []

    def fake_request(method, params=None):
        calls.append((method, params or {}))
        if method in {"window.listTop", "window.findRegex", "ui.inspect"}:
            return []
        return {"ok": True}

    monkeypatch.setattr(wininspect, "request", fake_request)

    assert wininspect.capabilities() == {"ok": True}
    assert wininspect.list_windows() == []
    assert wininspect.window_info("0x1234") == {"ok": True}
    assert wininspect.find_windows("Notepad.*", ".*") == []
    assert wininspect.ensure_foreground("0x1234") == {"ok": True}
    assert wininspect.inspect_ui("0x1234") == []
    assert wininspect.invoke_ui("0x1234", "saveButton") == {"ok": True}

    assert calls == [
        ("daemon.capabilities", {}),
        ("window.listTop", {}),
        ("window.getInfo", {"hwnd": "0x1234"}),
        ("window.findRegex", {"title_regex": "Notepad.*", "class_regex": ".*"}),
        ("window.ensureForeground", {"hwnd": "0x1234"}),
        ("ui.inspect", {"hwnd": "0x1234"}),
        ("ui.invoke", {"hwnd": "0x1234", "automation_id": "saveButton"}),
    ]


def test_v044_input_wrappers_use_upstream_rpc_contract(monkeypatch):
    calls = []

    def fake_request(method, params=None):
        calls.append((method, params or {}))
        return {"sent": True}

    monkeypatch.setattr(wininspect, "request", fake_request)

    assert wininspect.mouse_click(10, 20, "left") == {"sent": True}
    assert wininspect.mouse_click(30, 40, "right") == {"sent": True}
    assert wininspect.type_text("hello") == {"sent": True}
    assert wininspect.hotkey("ctrl+s") == {"sent": True}

    assert calls == [
        ("input.mouseClick", {"x": 10, "y": 20, "button": 0}),
        ("input.mouseClick", {"x": 30, "y": 40, "button": 1}),
        ("input.text", {"text": "hello"}),
        ("input.hotkey", {"keys": "ctrl+s"}),
    ]


def test_input_wrapper_rejects_unknown_button_before_rpc(monkeypatch):
    def unexpected_request(*args, **kwargs):
        raise AssertionError("invalid button must fail before WinInspect RPC")

    monkeypatch.setattr(wininspect, "request", unexpected_request)

    try:
        wininspect.mouse_click(1, 2, "side")
    except ValueError as exc:
        assert "unsupported mouse button" in str(exc)
    else:
        raise AssertionError("unsupported button was accepted")



def test_each_connection_binds_v044_protocol_version(monkeypatch):
    hello_payload = json.dumps({"type": "hello"}).encode("utf-8")
    response_payload = json.dumps(
        {"ok": True, "result": {"features": ["uia"]}}
    ).encode("utf-8")
    receive_buffer = bytearray(
        struct.pack("!I", len(hello_payload))
        + hello_payload
        + struct.pack("!I", len(response_payload))
        + response_payload
    )

    class FakeSocket:
        def __init__(self):
            self.sent = bytearray()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def settimeout(self, _timeout):
            pass

        def recv(self, size):
            if not receive_buffer:
                return b""
            data = bytes(receive_buffer[:size])
            del receive_buffer[:size]
            return data

        def sendall(self, data):
            self.sent.extend(data)

    fake_socket = FakeSocket()
    monkeypatch.setattr(wininspect, "_ensure_wininspect_daemon", lambda: True)
    monkeypatch.setattr(
        wininspect.socket,
        "create_connection",
        lambda *args, **kwargs: fake_socket,
    )

    result = wininspect.request("daemon.capabilities")
    assert result == {"features": ["uia"]}

    wire_length = struct.unpack("!I", fake_socket.sent[:4])[0]
    request = json.loads(fake_socket.sent[4 : 4 + wire_length].decode("utf-8"))

    assert request["method"] == "daemon.capabilities"
    assert request["params"]["protocol_version"] == "0.3.0"



def test_unnegotiated_compressed_response_fails_closed():
    payload = b"compressed-bytes"
    wire = struct.pack("!I", 0x80000000 | len(payload)) + payload
    receive_buffer = bytearray(wire)

    class FakeSocket:
        def recv(self, size):
            data = bytes(receive_buffer[:size])
            del receive_buffer[:size]
            return data

    try:
        wininspect._read_frame(FakeSocket())
    except RuntimeError as exc:
        assert "Compressed WinInspect frames are not negotiated" in str(exc)
    else:
        raise AssertionError("unnegotiated compressed frame was accepted")
