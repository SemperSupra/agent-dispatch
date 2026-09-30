"""
WinBot VNC Proxy Endpoint
WebSocket bridge between the browser's noVNC client and the guest's
TightVNC server (or any RFB-compatible VNC server on localhost:5900).

This reuses the existing uvicorn process — no separate service needed.
The browser connects via WebSocket to /vnc/connect, and this endpoint
proxies the RFB protocol bytes bidirectionally to the VNC server.

Architecture:
    Browser (noVNC.js) ← WebSocket → FastAPI /vnc/connect → TightVNC (localhost:5900)

Requires:
    - TightVNC server installed and running on the guest (install-tightvnc.ps1)
    - aiohttp Python package (added to requirements.txt)

References:
    - noVNC: https://github.com/novnc/noVNC
    - TightVNC: https://www.tightvnc.com/
    - RFB protocol: https://github.com/rfbproto/rfbproto
"""

import logging
import os
import socket as _socket

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger("winbot.api")

# Default VNC server host and port — TightVNC binds to localhost:5900
_VNC_HOST = "127.0.0.1"
_VNC_PORT = 5900

# Enable/disable the VNC proxy feature
_VNC_ENABLED = True

# API token for WebSocket auth (set by configure_vnc_token during app startup)
# This avoids a circular import with main.py
_VNC_API_TOKEN = os.environ.get("WINBOT_API_TOKEN", "")

router = APIRouter()


def _set_vnc_enabled(enabled: bool) -> None:
    """Allow tests and configuration to toggle VNC proxy availability."""
    global _VNC_ENABLED
    _VNC_ENABLED = enabled


def _set_vnc_target(host: str, port: int) -> None:
    """Allow tests and configuration to override the VNC target."""
    global _VNC_HOST, _VNC_PORT
    _VNC_HOST = host
    _VNC_PORT = port


def configure_vnc_token(token: str) -> None:
    """Set the API token used for WebSocket auth.

    Called from main.py at startup with the resolved API_TOKEN value.
    This avoids a circular import between vnc.py and main.py.
    """
    global _VNC_API_TOKEN
    _VNC_API_TOKEN = token


def _check_ws_auth(websocket: WebSocket) -> bool:
    """Check X-API-Key header during WebSocket handshake.

    FastAPI's HTTP middleware does not apply to WebSocket connections,
    so we must enforce auth here directly.

    Returns True if authenticated, False otherwise (caller should close).
    """
    token = websocket.headers.get("x-api-key", "")
    if not token:
        token = websocket.headers.get("X-API-Key", "")
    if token == _VNC_API_TOKEN:
        return True
    security_log = logging.getLogger("winbot.security")
    security_log.warning(
        "AUTH_FAIL [WS] /vnc/connect (client: %s)",
        websocket.client.host if websocket.client else "unknown"
    )
    return False


@router.websocket("/vnc/connect")
async def vnc_connect(websocket: WebSocket):
    """WebSocket proxy to the guest's VNC server (TightVNC on localhost:5900).

    Accepts an incoming WebSocket connection from the browser's noVNC client
    and creates a passthrough to the local VNC server. Both binary and text
    frames are forwarded bidirectionally.

    The connection lifecycle:
        1. Browser opens WebSocket to ws://<api>:8000/vnc/connect
        2. This handler connects to TightVNC on localhost:5900
        3. RFB handshake bytes flow bidirectionally
        4. On disconnect or error, both sides are cleaned up

    This endpoint requires X-API-Key authentication (enforced by middleware).
    """
    if not _VNC_ENABLED:
        await websocket.close(code=1011, reason="VNC proxy is disabled")
        return

    # Enforce X-API-Key auth (HTTP middleware does not apply to WS)
    if not _check_ws_auth(websocket):
        await websocket.close(code=4001, reason="Authentication required")
        return

    await websocket.accept()

    import asyncio

    try:
        import aiohttp
    except ImportError:
        logger.error("VNC proxy: aiohttp not installed — cannot proxy to VNC server")
        await websocket.send_text('{"error": "VNC proxy unavailable: aiohttp not installed"}')
        await websocket.close()
        return

    try:
        # Connect to the local VNC server via aiohttp's WebSocket client.
        # TightVNC uses raw TCP for RFB, but aiohttp's ws_connect can handle
        # the TCP-level connection if we use an http:// scheme (it falls back
        # to a raw TCP socket when the server doesn't speak HTTP).
        vnc_url = f"http://{_VNC_HOST}:{_VNC_PORT}"

        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(
                vnc_url,
                heartbeat=30.0,
                compress=False,
            ) as vnc_ws:
                logger.info("VNC proxy: connected to %s:%d", _VNC_HOST, _VNC_PORT)

                async def forward_client_to_vnc():
                    """Forward browser WebSocket messages to the VNC server."""
                    try:
                        while True:
                            msg = await websocket.receive()
                            if msg.type == WebSocketDisconnect:
                                break
                            if msg.type == 0:  # Text frame
                                await vnc_ws.send_str(msg.data)
                            elif msg.type == 1:  # Binary frame
                                await vnc_ws.send_bytes(msg.data)
                    except WebSocketDisconnect:
                        pass
                    except Exception as e:
                        logger.debug("VNC proxy: client→vnc error: %s", e)
                    finally:
                        await vnc_ws.close()

                async def forward_vnc_to_client():
                    """Forward VNC server messages back to the browser WebSocket."""
                    try:
                        while True:
                            msg = await vnc_ws.receive()
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                await websocket.send_bytes(msg.data)
                            elif msg.type == aiohttp.WSMsgType.TEXT:
                                await websocket.send_text(msg.data)
                            elif msg.type == aiohttp.WSMsgType.CLOSED:
                                break
                            elif msg.type == aiohttp.WSMsgType.ERROR:
                                logger.error("VNC proxy: server error: %s", vnc_ws.exception())
                                break
                    except Exception as e:
                        logger.debug("VNC proxy: vnc→client error: %s", e)
                    finally:
                        try:
                            await websocket.close()
                        except Exception:
                            pass

                # Run both directions concurrently. When either side closes,
                # the other side's task is also cancelled.
                tasks = [
                    asyncio.create_task(forward_client_to_vnc()),
                    asyncio.create_task(forward_vnc_to_client()),
                ]
                done, pending = await asyncio.wait(
                    tasks,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()

    except (OSError, ConnectionRefusedError):
        logger.warning("VNC proxy: connection refused — is TightVNC running on %s:%d?", _VNC_HOST, _VNC_PORT)
        try:
            await websocket.send_text(
                '{"error": "VNC server not reachable. Install and start TightVNC on the guest."}'
            )
        except Exception:
            pass
        await websocket.close(code=1011)
    except Exception as e:
        logger.error("VNC proxy: unexpected error: %s", e)
        try:
            await websocket.close(code=1011)
        except Exception:
            pass


# ============================================================
# VNC Health Check
# ============================================================

@router.get("/health/vnc")
async def vnc_health():
    """Report VNC subsystem status for the web dashboard badge.

    Checks:
    1. Whether the WebSocket proxy is enabled
    2. Whether TightVNC server is installed (tvnserver.exe exists)
    3. Whether port 5900 is accepting TCP connections

    The web dashboard polls this endpoint to show a green/amber/red
    VNC badge without needing an active noVNC connection.
    """
    result = {
        "proxy_enabled": _VNC_ENABLED,
        "installed": False,
        "port_listening": False,
        "service_running": False,
        "status": "disabled",
    }

    if not _VNC_ENABLED:
        return result

    # Check if tvnserver.exe exists
    import os as _os
    for _path in [
        _os.path.join(_os.environ.get("ProgramFiles", "C:\\Program Files"), "TightVNC", "tvnserver.exe"),
        _os.path.join(_os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "TightVNC", "tvnserver.exe"),
    ]:
        if _os.path.exists(_path):
            result["installed"] = True
            break

    # Check port 5900
    try:
        _sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        _sock.settimeout(2)
        _conn = _sock.connect_ex(("127.0.0.1", 5900))
        if _conn == 0:
            result["port_listening"] = True
        _sock.close()
    except Exception:
        pass

    # Determine overall status
    if result["port_listening"]:
        result["status"] = "ready"
        result["service_running"] = True
    elif result["installed"]:
        result["status"] = "stopped"
    else:
        result["status"] = "not_installed"

    return result
